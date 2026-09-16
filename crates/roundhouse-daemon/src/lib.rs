//! The daemon's library half: the pieces of `round daemon` that are worth
//! testing without spawning the binary.
//!
//! `roundhouse-daemon` was binary-only through Phase 0, when it existed only to
//! prove the full dependency graph links. Phase 1's exit criterion needs the
//! wiring itself under test — an integration test can drive
//! [`demo::run_demo_session`] and [`socket_server::serve`] directly, but
//! it cannot drive a `main`. Hence this lib target; `src/main.rs` is now a thin
//! startup shell over it. See `docs/architecture/02-system-architecture.md` §5.2.
#![forbid(unsafe_code)]

pub mod boot;
/// Phase 1's scripted, single-session exit-criterion fixture. Phase 7 Task 7
/// retires it as BOOT behavior (`main.rs` no longer calls
/// `run_demo_session` — see that file's own module doc) — this module stays
/// `pub`, unconditionally, only because `tests/exit_criterion_demo.rs` (an
/// external integration test, which cannot see a `#[cfg(test)]`-gated item
/// in the library it depends on — `cfg(test)` is local to each compilation
/// unit) drives it directly to prove the demo wiring itself still works,
/// same as Task 21 of Phase 1 originally used it. `real_boot_smoke.rs`
/// separately asserts this module's symbols are absent from `main.rs`'s own
/// source, i.e. from the real boot path.
pub mod demo;
pub mod mcp_config;
pub mod scheduler_driver;
pub mod session_bootstrap;
pub mod session_manager;
pub mod session_registry;
pub mod socket_server;
pub mod sub_agent_host;
pub mod workflow_host;
pub mod workspace_registry;

/// One `TaskRunner::bootstrap()` shared by every `#[cfg(test)] mod tests`
/// in this crate's LIBRARY test binary — `session_registry`'s and
/// `session_bootstrap`'s own test modules both need a `&'static TaskRunner`
/// to build a real `SessionActor`, and `cargo test -p roundhouse-daemon
/// --lib` runs every `#[cfg(test)]` module in this crate inside ONE process.
/// `TaskRunner::bootstrap()` panics on a second call per process (S-LOG-1),
/// so each module having its own independent `static RUNNER` would panic
/// the moment both modules' tests ran in the same test binary — this is the
/// one shared instance both reach for instead.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Arc;

    use roundhouse_bus::local_bus::LocalBus;
    use roundhouse_bus::spawn_tree::SpawnTree;
    use roundhouse_bus::teams::TeamRegistry;
    use roundhouse_core::{OnDegrade, SessionId, SessionSpec, SessionState, Tier};
    use roundhouse_engine::SessionActor;
    use roundhouse_policy::engine::PolicyEngine;
    use roundhouse_sandbox::isolate::BwrapLandlockIsolate;
    use roundhouse_sandbox::probe::{MechanismProbeReport, MechanismStatus};
    use roundhouse_sandbox::Isolate;

    static RUNNER: std::sync::OnceLock<roundhouse_core::TaskRunner> = std::sync::OnceLock::new();

    pub(crate) fn runner() -> &'static roundhouse_core::TaskRunner {
        RUNNER.get_or_init(roundhouse_core::TaskRunner::bootstrap)
    }

    /// The [`MechanismProbeReport`] every test isolate in this module
    /// reports — Landlock/bwrap/seccomp all `Available`, Seatbelt N/A (this
    /// is a Linux dev/CI environment). Shared by [`available_isolate`] and
    /// [`available_isolate_with_real_bwrap`] so the two differ only in
    /// which `bwrap` binary they actually exec.
    fn test_probe_report() -> MechanismProbeReport {
        MechanismProbeReport {
            landlock: MechanismStatus::Available,
            bwrap: MechanismStatus::Available,
            seccomp: MechanismStatus::Available,
            seatbelt: MechanismStatus::Unavailable {
                reason: "n/a".into(),
            },
        }
    }

    /// A `BwrapLandlockIsolate` that deterministically achieves `Tier::Sandbox`
    /// with no real bwrap/landlock syscalls (`test_with_probe`).
    ///
    /// **This isolate cannot actually spawn anything in a dev checkout.**
    /// `test_with_probe`'s `bwrap_path` is the hardcoded production install
    /// path (`/usr/libexec/roundhouse/bwrap`), which nothing in this repo
    /// vendors into a plain `cargo test` checkout — every real spawn attempt
    /// fails closed with `IsolationError::Unsupported` ("No such file or
    /// directory"). Fine for every test that only cares about the
    /// *attestation*/admission machinery around a `Tier::Sandbox` session
    /// (which is most of them), wrong for one that needs a shell command to
    /// actually run — see [`available_isolate_with_real_bwrap`] for that
    /// case. `real_boot_smoke.rs`'s own `--allow-degraded-to none` is the
    /// same gap, worked around a different way.
    pub(crate) fn available_isolate() -> Arc<dyn Isolate> {
        Arc::new(BwrapLandlockIsolate::test_with_probe(test_probe_report()))
    }

    /// [`available_isolate`], but wired to the real system `bwrap` on
    /// `$PATH` via `BwrapLandlockIsolate::test_with_probe_and_bwrap_path` —
    /// that constructor's own doc comment names exactly this need ("spawn a
    /// real process under the real `bwrap` binary on `$PATH` rather than the
    /// production install path baked into `test_with_probe`"). A test that
    /// needs a genuinely running, genuinely killable process — Phase 8 Task
    /// 25.4 Task 4's §8.13 mid-dispatch shell-cancel tests — needs this, not
    /// [`available_isolate`], in a dev checkout with no vendored bwrap.
    pub(crate) fn available_isolate_with_real_bwrap() -> Arc<dyn Isolate> {
        Arc::new(BwrapLandlockIsolate::test_with_probe_and_bwrap_path(
            test_probe_report(),
            std::path::PathBuf::from("bwrap"),
        ))
    }

    /// A minimal but fully real `SessionActor`, constructed with
    /// `initial_state` rather than always `Running` — needed by
    /// `socket_server`'s `spawn_session_reaper` test, which has no other way
    /// to observe a `Closed` actor (nothing in production code transitions
    /// one there yet — see that test's own doc comment).
    pub(crate) async fn real_actor_with_state(
        dir: &std::path::Path,
        initial_state: SessionState,
    ) -> Arc<SessionActor> {
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
            initial_state,
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

    /// [`real_actor_with_state`] with the ordinary `Running` initial state —
    /// what every session actually starts as.
    pub(crate) async fn real_actor(dir: &std::path::Path) -> Arc<SessionActor> {
        real_actor_with_state(dir, SessionState::Running).await
    }

    /// A `Provider` that panics if anything actually asks it for a
    /// completion. Every test using [`daemon_resources`] builds real
    /// sessions but drives no model turn, so a real provider would only add
    /// network dependence to a unit test.
    pub(crate) struct NoopProvider;

    impl roundhouse_provider::Provider for NoopProvider {
        fn capabilities(
            &self,
            _model: &roundhouse_provider::ModelId,
        ) -> roundhouse_provider::Capabilities {
            roundhouse_provider::Capabilities::default()
        }
        fn resolve(
            &self,
            _req: &roundhouse_provider::ChatRequest,
        ) -> Result<roundhouse_provider::Plan, roundhouse_provider::ProviderError> {
            unimplemented!("not exercised by this crate's library tests")
        }
        fn stream_chat<'a>(
            &'a self,
            _req: &'a roundhouse_provider::ChatRequest,
            _ctx: &'a roundhouse_provider::RequestCtx,
        ) -> roundhouse_provider::BoxFut<
            'a,
            Result<roundhouse_provider::ChatStream, roundhouse_provider::ProviderError>,
        > {
            unimplemented!("not exercised by this crate's library tests")
        }
        fn count_tokens<'a>(
            &'a self,
            _req: &'a roundhouse_provider::ChatRequest,
            _ctx: &'a roundhouse_provider::RequestCtx,
        ) -> roundhouse_provider::BoxFut<
            'a,
            Result<roundhouse_provider::TokenCount, roundhouse_provider::ProviderError>,
        > {
            unimplemented!("not exercised by this crate's library tests")
        }
        fn list_models<'a>(
            &'a self,
            _ctx: &'a roundhouse_provider::RequestCtx,
        ) -> roundhouse_provider::BoxFut<
            'a,
            Result<Vec<roundhouse_provider::ModelInfo>, roundhouse_provider::ProviderError>,
        > {
            unimplemented!("not exercised by this crate's library tests")
        }
    }

    struct NoopTransport;

    impl roundhouse_provider::HttpTransport for NoopTransport {
        fn send<'a>(
            &'a self,
            _req: roundhouse_provider::HttpRequest,
        ) -> futures::future::BoxFuture<
            'a,
            Result<roundhouse_provider::HttpResponseStream, roundhouse_provider::TransportError>,
        > {
            Box::pin(async {
                Err(roundhouse_provider::TransportError::Io(
                    "NoopTransport never sends".into(),
                ))
            })
        }
    }

    /// A fully real [`DaemonResources`](crate::session_bootstrap::DaemonResources)
    /// built against `dir`, with a working loopback proxy, an
    /// always-`Tier::Sandbox` isolate, and no network provider.
    ///
    /// Shared by `session_manager`'s and `scheduler_driver`'s test modules —
    /// both need the identical "everything a real session is built from"
    /// fixture, and a second copy of it would be one more thing to keep in
    /// step with `DaemonResources::new`'s many parameters.
    ///
    /// `load_workspace_config` is `false`: these tests supply their own
    /// (empty) MCP/network/policy inputs rather than having session
    /// construction read files out of the workspace under test.
    pub(crate) async fn daemon_resources(
        dir: &std::path::Path,
        workspace_registry: Option<Arc<crate::workspace_registry::WorkspaceRegistry>>,
    ) -> crate::session_bootstrap::DaemonResources {
        daemon_resources_with_rules(
            dir,
            workspace_registry,
            crate::session_bootstrap::no_policy_rules(),
        )
        .await
    }

    /// [`daemon_resources`], but with a caller-supplied rule source — so a
    /// test can build sessions whose OWN `PolicyEngine` admits something.
    /// `no_policy_rules` makes every task `Ask` -> `RequiresApproval`, which
    /// is the right fail-closed default but leaves any test about what
    /// happens AFTER admission with nothing to measure.
    pub(crate) async fn daemon_resources_with_rules(
        dir: &std::path::Path,
        workspace_registry: Option<Arc<crate::workspace_registry::WorkspaceRegistry>>,
        policy_rules: crate::session_bootstrap::PolicyRuleSource,
    ) -> crate::session_bootstrap::DaemonResources {
        daemon_resources_with_rules_and_isolate(
            dir,
            workspace_registry,
            policy_rules,
            available_isolate(),
        )
        .await
    }

    /// [`daemon_resources_with_rules`], but with a real, genuinely-spawning
    /// `bwrap` ([`available_isolate_with_real_bwrap`]) instead of the
    /// production-install-path isolate that cannot spawn anything in a dev
    /// checkout. See that function's own doc comment for why this exists.
    pub(crate) async fn daemon_resources_with_real_bwrap(
        dir: &std::path::Path,
        workspace_registry: Option<Arc<crate::workspace_registry::WorkspaceRegistry>>,
        policy_rules: crate::session_bootstrap::PolicyRuleSource,
    ) -> crate::session_bootstrap::DaemonResources {
        daemon_resources_with_rules_and_isolate(
            dir,
            workspace_registry,
            policy_rules,
            available_isolate_with_real_bwrap(),
        )
        .await
    }

    async fn daemon_resources_with_rules_and_isolate(
        dir: &std::path::Path,
        workspace_registry: Option<Arc<crate::workspace_registry::WorkspaceRegistry>>,
        policy_rules: crate::session_bootstrap::PolicyRuleSource,
        isolate: Arc<dyn Isolate>,
    ) -> crate::session_bootstrap::DaemonResources {
        use roundhouse_net::proxy::LoopbackProxy;

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
        let teams = Arc::new(TeamRegistry::new());
        let bus = Arc::new(LocalBus::new().with_teams(Arc::clone(&teams)));
        crate::session_bootstrap::DaemonResources::new(
            store,
            isolate,
            proxy,
            Arc::new(SpawnTree::new()),
            teams,
            bus,
            dir.join("state"),
            dir.join("daemon-binary"),
            Vec::new(),
            roundhouse_config::NetworkConfig::default(),
            OnDegrade::Refuse,
            policy_rules,
            crate::session_bootstrap::BackgroundServices::default(),
            runner(),
            Arc::new(NoopProvider),
            roundhouse_provider::RequestCtx {
                trace_id: None,
                transport: Arc::new(NoopTransport),
                api_key: "test-api-key-not-a-secret".into(),
                credentials: None,
            },
            proxy_writer,
            workspace_registry,
            false,
        )
    }
}
