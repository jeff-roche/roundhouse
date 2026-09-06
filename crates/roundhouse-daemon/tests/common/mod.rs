//! Shared test-only helpers for this crate's integration tests (Phase 7,
//! Task 7): building a real, minimal `SessionActor`/`DaemonResources` pair
//! now that `SessionRegistry::create`/`socket_server::{accept_loop,
//! accept_loop_with, drive_session}` all take a real actor / real daemon
//! resources instead of a bare `workspace_name: String`.
//!
//! `tests/common/mod.rs` (not `tests/common.rs`) is the standard convention
//! for a module shared across multiple integration-test binaries without
//! itself being compiled as its own test binary (Cargo only treats
//! `tests/<name>.rs` files as independent test crates, never files inside a
//! `tests/<name>/` subdirectory).
//!
//! `#![allow(dead_code)]`: each `tests/*.rs` binary compiles this module
//! separately via `mod common;` and uses only the subset of helpers it
//! needs — a helper unused by one particular binary is not dead code in
//! any real sense, just not needed by *that* caller.
#![allow(dead_code)]

use std::path::Path;
use std::sync::Arc;

use roundhouse_core::{OnDegrade, SessionId, SessionSpec, SessionState, TaskRunner, Tier};
use roundhouse_daemon::session_bootstrap::{
    no_policy_rules, BackgroundServices, DaemonResources, PolicyRuleSource,
};
use roundhouse_engine::SessionActor;
use roundhouse_net::proxy::LoopbackProxy;
use roundhouse_policy::engine::PolicyEngine;
use roundhouse_provider::{
    BoxFut, Capabilities, ChatRequest, ChatStream, HttpRequest, HttpResponseStream, HttpTransport,
    ModelId, ModelInfo, Plan, Provider, ProviderError, RequestCtx, TokenCount, TransportError,
};
use roundhouse_sandbox::isolate::BwrapLandlockIsolate;
use roundhouse_sandbox::probe::{MechanismProbeReport, MechanismStatus};
use roundhouse_sandbox::Isolate;

/// One `TaskRunner::bootstrap()` per test *process* — it panics on a second
/// call, and each `tests/*.rs` file is its own process, but a single file
/// can still have multiple `#[tokio::test]`s, hence the `OnceLock` rather
/// than a plain call in each helper.
static RUNNER: std::sync::OnceLock<TaskRunner> = std::sync::OnceLock::new();

pub fn runner() -> &'static TaskRunner {
    RUNNER.get_or_init(TaskRunner::bootstrap)
}

/// A `BwrapLandlockIsolate` that deterministically achieves `Tier::Sandbox`
/// with no real bwrap/landlock syscalls (`test_with_probe`), matching the
/// pattern `roundhouse-engine`'s own integration tests use.
pub fn available_isolate() -> Arc<dyn Isolate> {
    Arc::new(BwrapLandlockIsolate::test_with_probe(
        MechanismProbeReport {
            landlock: MechanismStatus::Available,
            bwrap: MechanismStatus::Available,
            seccomp: MechanismStatus::Available,
            seatbelt: MechanismStatus::Unavailable {
                reason: "n/a".into(),
            },
        },
    ))
}

/// A minimal but fully real `SessionActor` — every mechanism it wraps
/// (isolation, policy, redaction) is real; only the isolate's probe result
/// is faked. Good enough to hand to `SessionRegistry::create` directly in a
/// test that isn't exercising `session_bootstrap::create_real_session`
/// itself.
pub async fn real_actor(dir: &Path) -> Arc<SessionActor> {
    let store = roundhouse_store::open(&dir.join("events.db"))
        .await
        .unwrap();
    let writer = roundhouse_store::spawn_writer(store).await;
    let policy = Arc::new(PolicyEngine::from_rules(vec![]));
    let isolate = available_isolate();
    let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
    let handle = isolate.prepare(&spec).await.unwrap();
    Arc::new(SessionActor::new(
        SessionId::new(),
        writer,
        SessionState::Running,
        runner(),
        policy,
        dir.join("state"),
        dir.join("daemon-binary"),
        isolate,
        handle,
        spec,
        vec![],
    ))
}

/// A `Provider`/`HttpTransport` pair good enough to satisfy
/// `DaemonResources`'s fields for a test that never actually dispatches a
/// chat turn.
pub struct NoopProvider;
impl Provider for NoopProvider {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        Capabilities::default()
    }
    fn resolve(&self, _req: &ChatRequest) -> Result<Plan, ProviderError> {
        unimplemented!("not exercised by these tests")
    }
    fn stream_chat<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<ChatStream, ProviderError>> {
        unimplemented!("not exercised by these tests")
    }
    fn count_tokens<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<TokenCount, ProviderError>> {
        unimplemented!("not exercised by these tests")
    }
    fn list_models<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<Vec<ModelInfo>, ProviderError>> {
        unimplemented!("not exercised by these tests")
    }
}

pub struct NoopTransport;
impl HttpTransport for NoopTransport {
    fn send<'a>(
        &'a self,
        _req: HttpRequest,
    ) -> futures::future::BoxFuture<'a, Result<HttpResponseStream, TransportError>> {
        Box::pin(async { Err(TransportError::Io("NoopTransport never sends".into())) })
    }
}

/// Real `DaemonResources` — a real store, a real (test-probed) isolate, and
/// a real `LoopbackProxy` actually `serve()`d — with no MCP servers and no
/// network allowlist configured, for tests exercising the real
/// `CreateSession` -> `session_bootstrap::create_real_session` path end to
/// end (`socket_server::accept_loop`/`accept_loop_with`, now that they
/// require a real `Arc<DaemonResources>`).
pub async fn real_resources(dir: &Path) -> Arc<DaemonResources> {
    resources_with_isolate(dir, available_isolate()).await
}

/// [`real_resources`], but over a caller-supplied `Provider` — for Phase 7
/// Task 8's `SubmitTurn` tests, which need the daemon's own real
/// `CreateSession` -> `create_real_session` -> `run_agent_loop` path driven
/// by a *scripted* provider rather than [`NoopProvider`]'s
/// `unimplemented!()`. Nothing else about the session is faked: the store,
/// the policy engine, the proxy, the redaction wiring and the `SessionActor`
/// are all the production ones.
pub async fn resources_with_provider(
    dir: &Path,
    provider: Arc<dyn Provider>,
) -> Arc<DaemonResources> {
    resources_with(dir, available_isolate(), provider, no_policy_rules()).await
}

/// [`resources_with_provider`], but over a caller-supplied
/// [`PolicyRuleSource`] as well (Task 8 fix round 1, ruling W1-R118) — for
/// the end-to-end test that needs a real daemon session whose admission
/// gate can actually answer `Allow`, which production's
/// [`no_policy_rules`] never can.
pub async fn resources_with_provider_and_rules(
    dir: &Path,
    provider: Arc<dyn Provider>,
    policy_rules: PolicyRuleSource,
) -> Arc<DaemonResources> {
    resources_with(dir, available_isolate(), provider, policy_rules).await
}

/// [`real_resources`]'s body, factored out (fix round 2, MUST 2) so a test
/// that needs `create_real_session` to fail deterministically and cheaply —
/// proving the per-peer failed-construction limiter actually engages —
/// can supply its own `Isolate` (e.g. one whose `prepare` always errors)
/// instead of the always-succeeding [`available_isolate`].
pub async fn resources_with_isolate(dir: &Path, isolate: Arc<dyn Isolate>) -> Arc<DaemonResources> {
    resources_with(dir, isolate, Arc::new(NoopProvider), no_policy_rules()).await
}

/// The shared body of [`real_resources`]/[`resources_with_isolate`]/
/// [`resources_with_provider`] — the two axes a test may need to vary
/// (which `Isolate`, which `Provider`) in one place, so the other twelve
/// `DaemonResources::new` arguments are constructed identically for all of
/// them.
pub async fn resources_with(
    dir: &Path,
    isolate: Arc<dyn Isolate>,
    provider: Arc<dyn Provider>,
    policy_rules: PolicyRuleSource,
) -> Arc<DaemonResources> {
    let store = roundhouse_store::open(&dir.join("events.db"))
        .await
        .unwrap();
    let proxy = Arc::new(LoopbackProxy::new());
    let proxy_store = roundhouse_store::open(&dir.join("events.db"))
        .await
        .unwrap();
    let proxy_writer = roundhouse_store::spawn_writer(proxy_store).await;
    proxy
        .clone()
        .serve(runner(), proxy_writer.clone())
        .await
        .unwrap();
    Arc::new(DaemonResources::new(
        store,
        isolate,
        proxy,
        dir.join("state"),
        dir.join("daemon-binary"),
        Vec::new(),
        roundhouse_config::NetworkConfig::default(),
        roundhouse_core::OnDegrade::Refuse,
        policy_rules,
        BackgroundServices::default(),
        runner(),
        provider,
        RequestCtx {
            trace_id: None,
            transport: Arc::new(NoopTransport),
            api_key: "test-api-key-not-a-secret".into(),
            credentials: None,
        },
        proxy_writer,
    ))
}
