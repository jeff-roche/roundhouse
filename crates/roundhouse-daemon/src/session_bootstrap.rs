//! Real per-session construction (Phase 7, Task 7): turns a `CreateSession`
//! handshake into a real, event-sourced [`SessionActor`] backed by real
//! isolation, policy, MCP, redaction, and egress — the machinery Tasks 1-6
//! built and left unreachable from any real call site. Replaces `demo.rs`'s
//! scripted, single-session stand-in as the daemon's actual session-creation
//! path.
//!
//! # What this module decides, and why (see the task report for the full
//! rationale)
//!
//! - **One `PolicyEngine` per session, not one daemon-wide.** `resolved_mcp_servers`,
//!   `attested_tier`, and `home` are all per-session (`SealedContext`'s own
//!   fields), which a single, daemon-wide `PolicyEngine` cannot honestly
//!   produce for more than one concurrently-live session.
//! - **The provider mirrors the actor (CF-9(i)).** `SessionActor::sealed_context()`
//!   and `PolicyEngine::sealed_ctx()` are two independent channels judging
//!   the same session; before this module, nothing installed a real
//!   provider for the second one at all. [`build_sealed_ctx_provider`]
//!   closes over the SAME session-scoped state (`isolate`/`handle` for
//!   attestation, a `resolved_mcp` set updated by the SAME call this
//!   module makes to [`SessionActor::register_mcp`]) so the two channels
//!   read the identical facts rather than merely agreeing by construction
//!   accident.
//! - **Always [`create_session_with_egress`], never the isolation-only
//!   variant** (CF-11(e)) — every real session is expected to be able to
//!   reach the network, and only the `_with_egress` path installs this
//!   session's real `Redactor` and registers it with the daemon's shared
//!   egress proxy.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use roundhouse_core::{
    OnDegrade, SessionId, SessionSpec, SessionState, TaskRunner, Tier, WorkspaceId,
};
use roundhouse_engine::mcp_spawner::{start_session_mcp, StartSessionMcpError};
use roundhouse_engine::{
    create_session_with_egress, effective_tier, CreateSessionError, SessionActor,
};
use roundhouse_mcp::config::McpServerConfig;
use roundhouse_mcp::host::McpHost;
use roundhouse_net::policy::EgressPolicy;
use roundhouse_net::proxy::LoopbackProxy;
use roundhouse_policy::engine::PolicyEngine;
use roundhouse_policy::sealed::SealedContext;
use roundhouse_provider::{Provider, RequestCtx};
use roundhouse_sandbox::{Handle, Isolate};
use roundhouse_store::{spawn_writer, EventWriter, StorePool};

/// Everything a real session is built from, constructed once at daemon boot
/// (`main.rs`) and shared, by `&`, across every `CreateSession` handshake
/// [`crate::socket_server::drive_session`] handles.
pub struct DaemonResources {
    pub store: StorePool,
    pub isolate: Arc<dyn Isolate>,
    pub proxy: Arc<LoopbackProxy>,
    /// Absolute — asserted by `SessionActor::new` itself, which panics on a
    /// non-absolute value (see that constructor's doc comment).
    pub state_dir: PathBuf,
    /// Absolute, same reason.
    pub daemon_binary: PathBuf,
    /// Loaded once at boot via `mcp_config::load_mcp_servers` (CF-11(b)) —
    /// user-global scope only, structurally (ruling W1-R16). Every session
    /// currently gets the SAME configured server list; there is no
    /// per-session MCP config yet.
    pub mcp_configs: Vec<McpServerConfig>,
    /// Loaded once at boot via `roundhouse_config::load_network_config`
    /// (CF-12(c)) — see `main.rs` for the fail-closed decision on a load
    /// error.
    pub network_config: roundhouse_config::NetworkConfig,
    pub runner: &'static TaskRunner,
    pub provider: Arc<dyn Provider>,
    request_ctx: RequestCtx,
    /// CF-12(a): the daemon-wide egress proxy's own `EventWriter` — see
    /// [`register_proxy_secrets`] for why this needs its own, running
    /// redaction bookkeeping rather than a per-session
    /// `wire_redaction_for_session` call.
    proxy_writer: EventWriter,
    proxy_secrets: Mutex<Vec<String>>,
}

impl DaemonResources {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: StorePool,
        isolate: Arc<dyn Isolate>,
        proxy: Arc<LoopbackProxy>,
        state_dir: PathBuf,
        daemon_binary: PathBuf,
        mcp_configs: Vec<McpServerConfig>,
        network_config: roundhouse_config::NetworkConfig,
        runner: &'static TaskRunner,
        provider: Arc<dyn Provider>,
        request_ctx: RequestCtx,
        proxy_writer: EventWriter,
    ) -> Self {
        DaemonResources {
            store,
            isolate,
            proxy,
            state_dir,
            daemon_binary,
            mcp_configs,
            network_config,
            runner,
            provider,
            request_ctx,
            proxy_writer,
            proxy_secrets: Mutex::new(Vec::new()),
        }
    }

    /// `RequestCtx` does not implement `Clone` (its `Arc<dyn HttpTransport>`/
    /// `Arc<dyn CredentialProvider>` fields could, but the type itself opts
    /// out — see its own doc comment), so a fresh, field-wise clone is built
    /// by hand for each session that needs its own `RequestCtx` value (every
    /// session shares the same underlying transport/credentials/api key
    /// today; there is no per-session provider configuration yet).
    fn clone_request_ctx(&self) -> RequestCtx {
        RequestCtx {
            trace_id: self.request_ctx.trace_id.clone(),
            transport: self.request_ctx.transport.clone(),
            api_key: self.request_ctx.api_key.clone(),
            credentials: self.request_ctx.credentials.clone(),
        }
    }
}

/// Everything wrong that can happen constructing a real session.
#[derive(Debug, thiserror::Error)]
pub enum CreateRealSessionError {
    #[error("isolation/egress setup failed: {0}")]
    Session(#[from] CreateSessionError),
    #[error("starting this session's configured MCP servers failed: {0}")]
    Mcp(#[from] StartSessionMcpError),
}

/// The result of successfully constructing a real session: the actor
/// [`crate::session_registry::SessionRegistry::create`] indexes on, and the
/// MCP host (if this session configured any servers) that must be kept
/// alive for at least as long as the actor is — see [`crate::session_registry`]'s
/// `SessionEntry`, which holds both for exactly that reason.
pub struct RealSession {
    pub actor: Arc<SessionActor>,
    pub mcp_host: Option<Arc<McpHost>>,
}

/// Builds one real session end to end: isolation, a per-session
/// `PolicyEngine` with a real, actor-mirroring sealed-context provider,
/// this session's configured MCP servers (if any), redaction, and egress
/// registration — then a real [`SessionActor`] wrapping all of it, with
/// [`SessionActor::register_mcp`] already called (ruling W1-R85).
///
/// `chat_model`/`request_ctx`'s provider stays daemon-wide (there is no
/// per-session provider selection yet); everything else here is genuinely
/// per-session.
pub async fn create_real_session(
    resources: &DaemonResources,
    workspace_name: String,
) -> Result<RealSession, CreateRealSessionError> {
    let session_id = SessionId::new();
    let writer = spawn_writer(resources.store.clone()).await;

    // `ClientRequest::CreateSession` carries no tier/`on_degrade` field (it
    // is `workspace_name` only), so the daemon picks the default policy
    // itself: ask for `Sandbox`, but `AllowDownTo(Tier::None)` rather than
    // `Refuse` — a real host frequently cannot achieve `Sandbox` (bwrap not
    // installed at the production path, no landlock support, a container
    // without the right capabilities), and `Refuse` would mean this daemon
    // creates zero sessions on such a host. `create_session_isolation`
    // already records a real `Degradation` `Note` event whenever the
    // achieved tier falls short (§6.5 rule 3) — that is the honest signal
    // for this, not refusing to start at all.
    let spec = SessionSpec {
        workspace: WorkspaceId::new(),
        name: Some(workspace_name),
        requested_tier: Tier::Sandbox,
        on_degrade: OnDegrade::AllowDownTo(Tier::None),
    };

    let egress_policy = egress_policy_for(resources);
    let request_ctx = resources.clone_request_ctx();

    // Isolation + egress registration + this session's real `Redactor` —
    // CF-11(e): always the `_with_egress` path, never `create_session_isolation`
    // alone, for a session that must be able to reach the network.
    let (handle, _proxy_handle) = create_session_with_egress(
        &writer,
        resources.runner,
        session_id,
        resources.isolate.as_ref(),
        &spec,
        &resources.proxy,
        egress_policy,
        &request_ctx,
        &resources.mcp_configs,
    )
    .await?;

    // CF-12(a): the daemon-wide proxy writer shares no `Redactor` swap
    // boundary with any one session (`LoopbackProxy::serve` runs once, at
    // boot, before any session exists) — refresh it to the UNION of every
    // live secret registered by any session so far, this one included.
    register_proxy_secrets(resources, &request_ctx);

    // The set this session's `PolicyEngine` sealed-context provider reads
    // for `resolved_mcp_servers` — written to, below, by the exact same
    // `SessionMcp::resolved_servers()` call that also feeds
    // `SessionActor::register_mcp` (ruling W1-R85), so the two channels
    // CF-9(i) names can never disagree about WHICH servers resolved, only
    // (in principle) about the narrow window between the two writes.
    let mirrored_mcp_resolved: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::new()));

    let policy = Arc::new(PolicyEngine::from_rules(vec![]).with_sealed_ctx_provider(
        build_sealed_ctx_provider(
            resources.state_dir.clone(),
            resources.daemon_binary.clone(),
            roundhouse_policy::sealed::home_dir(),
            resources.isolate.clone(),
            handle.clone(),
            effective_tier(&spec),
            mirrored_mcp_resolved.clone(),
        ),
    ));

    let (mcp_host, mcp, tool_defs) = if resources.mcp_configs.is_empty() {
        (None, None, Vec::new())
    } else {
        let (host, mcp, tool_defs) = start_session_mcp(
            resources.mcp_configs.clone(),
            session_id,
            resources.runner,
            writer.clone(),
            policy.clone(),
        )
        .await?;
        (Some(host), Some(mcp), tool_defs)
    };

    let actor = Arc::new(SessionActor::new(
        session_id,
        writer,
        SessionState::Running,
        resources.runner,
        policy,
        resources.state_dir.clone(),
        resources.daemon_binary.clone(),
        resources.isolate.clone(),
        handle,
        spec,
        tool_defs,
    ));

    if let Some(mcp) = &mcp {
        // Ruling W1-R85 — the ONLY writer of `mcp_resolved`; skipping this
        // would deny every MCP call in this session (see that method's own
        // doc comment for the full consequence).
        actor.register_mcp(mcp);
        *mirrored_mcp_resolved.write().unwrap() = mcp.resolved_servers().into_iter().collect();
    }

    Ok(RealSession { actor, mcp_host })
}

/// Builds this session's `EgressPolicy` from the daemon's loaded
/// `NetworkConfig` (CF-12(c)) via the same conversion `roundhouse-engine`
/// already exposes for exactly this purpose.
fn egress_policy_for(resources: &DaemonResources) -> EgressPolicy {
    roundhouse_engine::egress_policy_from_allowed_hosts(&resources.network_config.allowed_hosts)
}

/// CF-12(a): keeps the daemon's shared egress-proxy writer's redaction
/// current. `LoopbackProxy::serve` binds and starts accepting connections
/// exactly once, at boot — long before any session (and therefore any
/// live secret) exists — so its `EventWriter` cannot get a fresh,
/// session-scoped `wire_redaction_for_session` call the way each session's
/// OWN writer does via `create_session_with_egress`. Instead this
/// maintains the UNION of every live secret registered by any session so
/// far (`resources.proxy_secrets`) and re-installs the complete set on
/// `resources.proxy_writer` every time a new session's secrets are added —
/// `wire_redaction_for_session`/`EventWriter::set_redactor` REPLACE
/// wholesale (W1-R25), so passing anything less than the full accumulated
/// set here would silently un-redact an earlier session's secrets from the
/// proxy's own event stream.
fn register_proxy_secrets(resources: &DaemonResources, ctx: &RequestCtx) {
    let this_session_secrets = roundhouse_engine::live_secret_values(ctx, &resources.mcp_configs);
    let mut all_secrets = resources.proxy_secrets.lock().unwrap();
    let mut changed = false;
    for secret in this_session_secrets {
        if !all_secrets.contains(&secret) {
            all_secrets.push(secret);
            changed = true;
        }
    }
    if changed {
        roundhouse_engine::wire_redaction_for_session(&resources.proxy_writer, &all_secrets);
    }
}

/// Builds a `PolicyEngine::with_sealed_ctx_provider` closure that reads the
/// SAME facts `SessionActor::sealed_context()` (private to `roundhouse-engine`)
/// reads internally: a live re-attestation on every call (never a cached
/// snapshot — §6.5 rule 4), and `resolved_mcp` — kept in sync with the
/// actor's own, separately-held `mcp_resolved` set by both being written
/// from the identical `SessionMcp::resolved_servers()` call
/// (`create_real_session`, above). CF-9(i): before this, the actor's own
/// channel had a real writer (`register_mcp`) and this one had none at
/// all — the two could only ever "agree" in the sense that both defaulted
/// to empty. This makes them track the same live value instead.
#[allow(clippy::too_many_arguments)]
fn build_sealed_ctx_provider(
    state_dir: PathBuf,
    daemon_binary: PathBuf,
    home: Option<PathBuf>,
    isolate: Arc<dyn Isolate>,
    handle: Handle,
    requested_tier: Tier,
    resolved_mcp: Arc<RwLock<HashSet<String>>>,
) -> Arc<dyn Fn() -> SealedContext + Send + Sync> {
    Arc::new(move || {
        let attestation = isolate.attest(&handle);
        SealedContext {
            state_dir: state_dir.clone(),
            daemon_binary: daemon_binary.clone(),
            resolved_mcp_servers: resolved_mcp
                .read()
                .map(|guard| guard.clone())
                .unwrap_or_default(),
            requested_tier,
            attested_tier: attestation.tier,
            home: home.clone(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use roundhouse_sandbox::isolate::BwrapLandlockIsolate;
    use roundhouse_sandbox::probe::{MechanismProbeReport, MechanismStatus};

    fn available_isolate() -> Arc<dyn Isolate> {
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

    use crate::test_support::runner;

    async fn resources(dir: &std::path::Path) -> DaemonResources {
        let store = roundhouse_store::open(&dir.join("events.db"))
            .await
            .unwrap();
        let proxy = Arc::new(LoopbackProxy::new());
        let proxy_store = roundhouse_store::open(&dir.join("events.db"))
            .await
            .unwrap();
        let proxy_writer = spawn_writer(proxy_store).await;
        proxy
            .clone()
            .serve(runner(), proxy_writer.clone())
            .await
            .unwrap();
        DaemonResources::new(
            store,
            available_isolate(),
            proxy,
            dir.join("state"),
            dir.join("daemon-binary"),
            Vec::new(),
            roundhouse_config::NetworkConfig::default(),
            runner(),
            Arc::new(NoopProvider),
            RequestCtx {
                trace_id: None,
                transport: Arc::new(NoopTransport),
                api_key: "test-api-key-not-a-secret".into(),
                credentials: None,
            },
            proxy_writer,
        )
    }

    /// A `Provider`/`HttpTransport` pair good enough to satisfy
    /// `DaemonResources`'s fields — nothing in this module's own tests
    /// dispatches a chat turn, so neither is ever actually called.
    struct NoopProvider;
    impl Provider for NoopProvider {
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
            unimplemented!("not exercised by this module's tests")
        }
        fn stream_chat<'a>(
            &'a self,
            _req: &'a roundhouse_provider::ChatRequest,
            _ctx: &'a RequestCtx,
        ) -> roundhouse_provider::BoxFut<
            'a,
            Result<roundhouse_provider::ChatStream, roundhouse_provider::ProviderError>,
        > {
            unimplemented!("not exercised by this module's tests")
        }
        fn count_tokens<'a>(
            &'a self,
            _req: &'a roundhouse_provider::ChatRequest,
            _ctx: &'a RequestCtx,
        ) -> roundhouse_provider::BoxFut<
            'a,
            Result<roundhouse_provider::TokenCount, roundhouse_provider::ProviderError>,
        > {
            unimplemented!("not exercised by this module's tests")
        }
        fn list_models<'a>(
            &'a self,
            _ctx: &'a RequestCtx,
        ) -> roundhouse_provider::BoxFut<
            'a,
            Result<Vec<roundhouse_provider::ModelInfo>, roundhouse_provider::ProviderError>,
        > {
            unimplemented!("not exercised by this module's tests")
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

    #[tokio::test]
    async fn create_real_session_builds_an_actor_with_no_mcp_servers_configured() {
        let dir = tempfile::tempdir().unwrap();
        let resources = resources(dir.path()).await;

        let real_session = create_real_session(&resources, "test-workspace".into())
            .await
            .unwrap();

        assert!(real_session.mcp_host.is_none());
        assert_eq!(real_session.actor.state(), SessionState::Running);
    }

    /// `build_sealed_ctx_provider`'s attestation half, proven directly
    /// against the real isolate/handle pair `create_real_session` builds —
    /// this is the exact closure installed on the session's `PolicyEngine`,
    /// constructed the same way, so if this reads the live attestation
    /// correctly, so does the real one.
    #[tokio::test]
    async fn the_sealed_ctx_provider_reads_the_isolates_live_attestation() {
        let dir = tempfile::tempdir().unwrap();
        let isolate = available_isolate();
        let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
        let handle = isolate.prepare(&spec).await.unwrap();
        let expected_tier = isolate.attest(&handle).tier;

        let provider = build_sealed_ctx_provider(
            dir.path().join("state"),
            dir.path().join("daemon-binary"),
            None,
            isolate,
            handle,
            Tier::Sandbox,
            Arc::new(RwLock::new(HashSet::from(["github".to_string()]))),
        );

        let ctx = provider();
        assert_eq!(ctx.attested_tier, expected_tier);
        assert_eq!(ctx.requested_tier, Tier::Sandbox);
        assert!(ctx.resolved_mcp_servers.contains("github"));
    }
}
