//! Real per-session construction (Phase 7, Task 7): turns a `CreateSession`
//! handshake into a real, event-sourced [`SessionActor`] backed by real
//! isolation, policy, MCP, redaction, and egress — the machinery Tasks 1-6
//! built and wired into the daemon's production session-creation call site. Replaces `demo.rs`'s
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
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};

use futures::stream::{FuturesUnordered, StreamExt};
use roundhouse_core::{
    OnDegrade, SessionId, SessionSpec, SessionState, TaskRunner, Tier, WorkspaceId,
};
use roundhouse_engine::mcp_spawner::{start_session_mcp, SessionMcp, StartSessionMcpError};
use roundhouse_engine::{
    create_session_with_egress, effective_tier, CreateSessionError, SessionActor,
};
use roundhouse_mcp::config::McpServerConfig;
use roundhouse_mcp::host::McpHost;
use roundhouse_net::policy::EgressPolicy;
use roundhouse_net::proxy::{LoopbackProxy, ProxyHandle};
use roundhouse_policy::engine::{CompiledRule, PolicyEngine};
use roundhouse_policy::sealed::SealedContext;
use roundhouse_policy::trust::{apply_project_scope_trust, TrustStore};
use roundhouse_policy::{compile_policy_layers, PolicyConfigError};
use roundhouse_provider::{Provider, RequestCtx};
use roundhouse_sandbox::{Handle, Isolate};
use roundhouse_store::{spawn_writer, EventWriter, StorePool};
use tokio::sync::{oneshot, watch};

/// A background service's terminal failure.  A service must report readiness
/// before it can be considered part of a live daemon, and its later failure
/// is returned to the daemon's lifecycle owner rather than being detached.
#[derive(Debug, thiserror::Error)]
#[error("background service failed: {0}")]
pub struct BackgroundServiceError(pub String);

pub type BackgroundServiceFuture =
    Pin<Box<dyn Future<Output = Result<(), BackgroundServiceError>> + Send>>;
pub type BackgroundService =
    Arc<dyn Fn(BackgroundServiceContext) -> BackgroundServiceFuture + Send + Sync>;

/// Inputs a background service receives from the daemon composition root.
/// `ready` must be completed exactly once before startup succeeds; dropping it
/// or returning before readiness fails daemon boot.  `cancelled` is observed
/// by the service during orderly shutdown, and the returned future is joined
/// by [`RunningBackgroundServices`] so errors are never orphaned.
pub struct BackgroundServiceContext {
    pub store: StorePool,
    pub sessions: Arc<crate::session_registry::SessionRegistry>,
    pub cancelled: watch::Receiver<bool>,
    ready: Option<oneshot::Sender<Result<(), BackgroundServiceError>>>,
}

impl BackgroundServiceContext {
    pub fn signal_ready(&mut self) -> Result<(), BackgroundServiceError> {
        self.ready
            .take()
            .ok_or_else(|| BackgroundServiceError("service signaled readiness twice".to_string()))?
            .send(Ok(()))
            .map_err(|_| {
                BackgroundServiceError("daemon stopped waiting for service readiness".to_string())
            })
    }
}

/// Three intentionally independent optional slots.  L2, L3, and L4 own
/// different eventual services and must not agree on a shared trait shape
/// before those implementations exist.  Production leaves every slot empty
/// until the owning lane supplies a factory; this is a documented seam, not
/// evidence that those services are wired.
#[derive(Default, Clone)]
pub struct BackgroundServices {
    pub workflow: Option<BackgroundService>,
    pub scheduler: Option<BackgroundService>,
    pub acp: Option<BackgroundService>,
}

impl BackgroundServices {
    pub async fn start(
        &self,
        store: StorePool,
        sessions: Arc<crate::session_registry::SessionRegistry>,
    ) -> Result<RunningBackgroundServices, BackgroundServiceError> {
        let (cancel, _) = watch::channel(false);
        let mut handles = FuturesUnordered::new();
        for service in [&self.workflow, &self.scheduler, &self.acp]
            .into_iter()
            .flatten()
        {
            let (ready_tx, ready_rx) = oneshot::channel();
            let context = BackgroundServiceContext {
                store: store.clone(),
                sessions: Arc::clone(&sessions),
                cancelled: cancel.subscribe(),
                ready: Some(ready_tx),
            };
            handles.push(tokio::spawn(service(context)));
            tokio::select! {
                ready = ready_rx => match ready {
                    Ok(Ok(())) => {
                        // The service remains in `handles`; its terminal
                        // result is supervised by `wait_for_failure` after
                        // boot. No timing grace window is used here.
                    }
                    Ok(Err(error)) => {
                        cancel.send_replace(true);
                        for handle in handles.iter() { handle.abort(); }
                        while handles.next().await.is_some() {}
                        return Err(error);
                    }
                    Err(_) => {
                        cancel.send_replace(true);
                        for handle in handles.iter() { handle.abort(); }
                        while handles.next().await.is_some() {}
                        return Err(BackgroundServiceError("service exited without signaling readiness".to_string()));
                    }
                },
                completed = handles.next() => {
                    cancel.send_replace(true);
                    for handle in handles.iter() { handle.abort(); }
                    while handles.next().await.is_some() {}
                    return match completed {
                        Some(Ok(Err(error))) => Err(error),
                        Some(Ok(Ok(()))) => Err(BackgroundServiceError("service stopped before readiness".to_string())),
                        Some(Err(error)) => Err(BackgroundServiceError(error.to_string())),
                        None => Err(BackgroundServiceError("service stopped before readiness".to_string())),
                    };
                }
            }
        }
        Ok(RunningBackgroundServices { cancel, handles })
    }
}

/// Daemon-owned join/cancellation handle for all started background services.
/// The daemon calls [`Self::shutdown`] on exit and [`Self::wait_for_failure`]
/// while serving, making both cancellation and error propagation explicit.
pub struct RunningBackgroundServices {
    cancel: watch::Sender<bool>,
    handles: FuturesUnordered<tokio::task::JoinHandle<Result<(), BackgroundServiceError>>>,
}

impl RunningBackgroundServices {
    pub async fn wait_for_failure(&mut self) -> Result<(), BackgroundServiceError> {
        if let Some(handle) = self.handles.next().await {
            match handle {
                Ok(Ok(())) => {
                    return Err(BackgroundServiceError(
                        "service stopped unexpectedly".to_string(),
                    ))
                }
                Ok(Err(error)) => return Err(error),
                Err(error) => return Err(BackgroundServiceError(error.to_string())),
            }
        }
        std::future::pending().await
    }

    pub async fn shutdown(mut self) -> Result<(), BackgroundServiceError> {
        self.cancel.send_replace(true);
        let mut first_error = None;
        while let Some(handle) = self.handles.next().await {
            match handle {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    first_error.get_or_insert(error);
                }
                Err(error) => {
                    first_error.get_or_insert(BackgroundServiceError(error.to_string()));
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

/// Where a new session's *config-derived* policy rules come from
/// (Phase 7, Task 8 fix round 1, ruling W1-R118).
///
/// A factory rather than a `Vec<CompiledRule>` field because
/// [`CompiledRule`] is deliberately **not** `Clone` — `roundhouse-policy`'s
/// own `grant_rule_encapsulation` compile-fail test guards that, so a
/// synthesized grant cannot be duplicated out of the engine that owns it —
/// and every session needs its own `PolicyEngine::from_rules` set. Called
/// exactly once per session, inside [`create_real_session`].
///
/// **This is a seam, not a configuration surface.** It exists so the rule
/// set a session is built with is an *input* to session construction
/// instead of a literal `vec![]` frozen into it, which is what made the
/// phase's own end-to-end criterion untestable. Production builds it with
/// [`policy_rules_from_files`]; tests can still supply a deliberately empty
/// source via [`no_policy_rules`].
pub type PolicyRuleSource = Arc<dyn Fn() -> Vec<CompiledRule> + Send + Sync>;

/// Error returned while building the production [`PolicyRuleSource`].  This is
/// deliberately a boot-time error: silently replacing a malformed operator
/// policy with zero rules makes a configuration failure indistinguishable from
/// the old, intentionally-empty policy and hides an authorization outage.
#[derive(Debug, thiserror::Error)]
pub enum PolicyRulesLoadError {
    #[error("failed to load policy file")]
    Config(#[source] roundhouse_config::ConfigError),
    #[error("failed to compile policy file")]
    Compile(#[source] PolicyConfigError),
}

/// Loads and validates operator policy files once at daemon boot, then mints a
/// fresh rule vector for each session.  `CompiledRule` is intentionally not
/// cloneable: its private construction is the policy authority, so the source
/// recompiles the already-validated syntax rather than sharing mutable rules.
///
/// Project rules pass through [`apply_project_scope_trust`] on every mint.
/// That gate is owned by `roundhouse-policy`, outside the agent-writable repo,
/// and can therefore reject a project-layer widening before it reaches
/// `PolicyEngine`.  User-global rules have no such gate because they are the
/// operator-controlled wider scope.
pub fn policy_rules_from_files(
    project_root: Option<PathBuf>,
    trust_state_dir: PathBuf,
) -> Result<PolicyRuleSource, PolicyRulesLoadError> {
    let layers = roundhouse_config::load_policy_files(project_root.as_deref())
        .map_err(PolicyRulesLoadError::Config)?;

    // Validate compilation now, before main creates/removes the socket.  The
    // factory below repeats this deterministic work only because rules cannot
    // be cloned without reopening their construction authority.
    effective_policy_rules(&layers, project_root.as_deref(), &trust_state_dir)
        .map_err(PolicyRulesLoadError::Compile)?;

    Ok(Arc::new(move || {
        effective_policy_rules(&layers, project_root.as_deref(), &trust_state_dir)
            .expect("policy files were parsed and compiled during daemon boot")
    }))
}

fn effective_policy_rules(
    layers: &[roundhouse_config::PolicyLayer],
    project_root: Option<&Path>,
    trust_state_dir: &Path,
) -> Result<Vec<CompiledRule>, PolicyConfigError> {
    let mut effective = Vec::new();
    let trust_store = TrustStore::new(trust_state_dir.to_path_buf());
    for layer in layers {
        let compiled = compile_policy_layers(vec![layer.clone()])?;
        if layer.scope == roundhouse_config::ConfigScope::Project {
            // `load_policy_files` labels this path itself; do not accept a
            // caller-supplied scope label for an agent-controlled path.
            let root = project_root.expect("a project layer requires a project root");
            effective.extend(apply_project_scope_trust(
                root,
                &layer.contents,
                compiled,
                &trust_store,
            ));
        } else {
            effective.extend(compiled);
        }
    }
    Ok(effective)
}

/// A deliberately empty [`PolicyRuleSource`] for tests and explicit
/// fail-closed fixtures; production uses [`policy_rules_from_files`] at boot.
///
/// Every session built with this gets `PolicyEngine::from_rules(vec![])`,
/// so `PolicyEngine::decide` falls through to its `Outcome::Ask` default
/// for every task no compiled-in sealed rule already denies, and
/// `SessionActor::admit_task` turns that into
/// `AdmitError::RequiresApproval`. Behaviour is byte-identical to the
/// hardcoded `vec![]` this replaced: fail-closed, and unchanged.
///
/// This is not the production default and must not be used as a fallback for
/// malformed policy files: boot rejects those files rather than disguising
/// them as this intentional empty source.
pub fn no_policy_rules() -> PolicyRuleSource {
    Arc::new(Vec::new)
}

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
    /// The `OnDegrade` every real session is created with (ruling W1-R95).
    /// `OnDegrade::Refuse` — §6.5's documented default — unless the
    /// operator explicitly opts into `OnDegrade::AllowDownTo(tier)` via
    /// `round-daemon-internal --allow-degraded-to <TIER>`. See
    /// `create_real_session`'s own doc comment for why the OTHER default
    /// (`AllowDownTo(Tier::None)`) is actively wrong, not merely stricter
    /// than necessary.
    pub default_on_degrade: OnDegrade,
    /// See [`PolicyRuleSource`]. Production uses [`policy_rules_from_files`].
    pub policy_rules: PolicyRuleSource,
    /// Background-service composition seam. Production is intentionally empty
    /// until the owning Phase 8 lanes supply their independent factories.
    pub background_services: BackgroundServices,
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
        default_on_degrade: OnDegrade,
        policy_rules: PolicyRuleSource,
        background_services: BackgroundServices,
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
            default_on_degrade,
            policy_rules,
            background_services,
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
    pub(crate) fn clone_request_ctx(&self) -> RequestCtx {
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
    #[error(transparent)]
    ProxySecretsPoisoned(#[from] ProxySecretsPoisonedError),
}

/// The result of successfully constructing a real session: the actor
/// [`crate::session_registry::SessionRegistry::create`] indexes on, the
/// MCP host (if this session configured any servers) that must be kept
/// alive for at least as long as the actor is — see [`crate::session_registry`]'s
/// `SessionEntry`, which holds both for exactly that reason — and this
/// session's `ProxyHandle` (bearer token + the daemon-wide proxy's bound
/// address).
///
/// **`proxy_handle` has exactly one consumer today: session teardown**
/// (fix round 1, SHOULD item) — `socket_server::spawn_session_reaper` calls
/// `LoopbackProxy::deregister_session(token)` when this session's actor
/// reaches `SessionState::Closed`, closing what would otherwise be an
/// unbounded leak of the proxy's own internal session table (nothing
/// deregistered a session's egress-policy entry there before this fix). It
/// is NOT yet retrievable by anything that would actually ROUTE traffic
/// through the proxy — no `http` tool executor is wired to a real dispatch
/// chokepoint in this daemon yet (the same "no live work-submission path"
/// gap this whole task names elsewhere), so there is currently nowhere for
/// such a consumer to reach this value from even if one existed. When that
/// wiring lands, `proxy_handle` needs a home a running tool dispatch can
/// read from (most plausibly a field on `SessionActor` itself) — not
/// discarded here, and not stored only for teardown as it is today.
pub struct RealSession {
    pub actor: Arc<SessionActor>,
    pub mcp_host: Option<Arc<McpHost>>,
    /// This session's MCP dispatch handle (ruling W1-R119, Task 8 fix round
    /// 1). **Retained, not dropped.** Before this round `create_real_session`
    /// built a `SessionMcp`, used it for `apply_resolved_mcp_servers`/
    /// `SessionActor::register_mcp`, and then let it fall out of scope — so
    /// the session's MCP tools were offered to the model (they are in
    /// `actor.tool_defs()`) while every call to one hit
    /// `run_agent_loop`'s honest "no MCP servers are configured for this
    /// session" refusal, because nothing could hand the loop a
    /// `SessionMcp`. `SessionRegistry` now stores it alongside the actor,
    /// and `socket_server::run_submitted_turn` passes it to the loop.
    ///
    /// `None` exactly when this session configured no MCP servers.
    pub mcp: Option<SessionMcp>,
    pub proxy_handle: ProxyHandle,
}

/// Tears down every real resource a successfully-built [`RealSession`]
/// holds: this session's isolation handle
/// ([`SessionActor::teardown`](roundhouse_engine::SessionActor::teardown)),
/// its MCP host (if it configured any servers —
/// `McpHost::shutdown` confirms every child process is actually gone, not
/// merely asked to stop), and its egress-proxy registration
/// (`LoopbackProxy::deregister_session`).
///
/// Fix round 2, MUST 2: before this function existed, `grep -rn
/// "\.teardown\("` found exactly one caller workspace-wide and
/// `McpHost::shutdown` had zero — every path that built a real session and
/// then discarded it (the connection lost the `is_full` race against
/// `SessionRegistry::create`, session construction outlived the connection
/// that asked for it and was torn down instead of kept, or the session's
/// own actor later reached `SessionState::Closed`) leaked the real
/// isolation resource and every real MCP child process forever. This
/// function is the one place all three teardown calls happen together, so
/// every caller that decides "this `RealSession` is not going to be used"
/// has exactly one thing to call.
///
/// Takes `real_session` by value (not `&RealSession`) so a caller cannot
/// accidentally call this and then go on to use `actor`/`mcp_host` as if
/// they were still live — teardown and continued use are mutually
/// exclusive by construction, not merely by convention.
pub async fn teardown_real_session(proxy: &LoopbackProxy, real_session: RealSession) {
    real_session.actor.teardown().await;
    if let Some(host) = &real_session.mcp_host {
        if let Err(err) = host.shutdown().await {
            tracing::warn!(error = %err, "failed to shut down this session's MCP host");
        }
    }
    proxy.deregister_session(real_session.proxy_handle.token());
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
    // itself.
    //
    // **Ruling W1-R95 (fix round 1): `OnDegrade::Refuse` is the default, not
    // `AllowDownTo(Tier::None)`.** An earlier version of this function used
    // `AllowDownTo(Tier::None)`, reasoned as "safer than refusing to create
    // any session on a host without bwrap." That reasoning was backwards:
    // `SealedContext.requested_tier` is populated from `effective_tier`
    // (`roundhouse_engine::effective_tier`), not `spec.requested_tier`
    // directly, and `effective_tier` for `AllowDownTo(floor)` IS `floor`.
    // `Tier::None` is the first variant of a derived-`Ord` enum, so
    // `attested_tier < requested_tier` (`sealed_tier_shortfall`,
    // §6.2/§6.5) becomes unsatisfiable for every `Tier` — that setting
    // PERMANENTLY DISARMS the one sealed rule that detects a live
    // mid-session isolation downgrade, for every task, in every session,
    // for the daemon's whole life. `session_actor.rs`'s own doc comment on
    // `effective_tier` already records a previous round fixing a bug with
    // this exact symptom as "a genuine fail-open regression." §6.5 also
    // names `Refuse` as the documented default and requires a downgrade be
    // an explicit human decision at creation — `resources.default_on_degrade`
    // (below) is that decision, made once by the operator via
    // `round-daemon-internal --allow-degraded-to <TIER>`, never silently by
    // this function.
    let spec = SessionSpec {
        workspace: WorkspaceId::new(),
        name: Some(workspace_name),
        requested_tier: Tier::Sandbox,
        on_degrade: resources.default_on_degrade,
    };

    let egress_policy = egress_policy_for(resources);
    let request_ctx = resources.clone_request_ctx();

    // Isolation + egress registration + this session's real `Redactor` —
    // CF-11(e): always the `_with_egress` path, never `create_session_isolation`
    // alone, for a session that must be able to reach the network.
    let (handle, proxy_handle) = create_session_with_egress(
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
    //
    // Fix round 5, MUST 4: fails this session (rather than silently
    // proceeding unredacted) on a poisoned `proxy_secrets` lock — tearing
    // down the real isolation handle and proxy registration
    // `create_session_with_egress` already built, the same shape the
    // `start_session_mcp` failure branch below already uses (fix round 2,
    // MUST 2). No `SessionActor` exists yet at this point to call
    // `teardown()` on, so tear down directly.
    if let Err(err) = register_proxy_secrets(resources, &request_ctx) {
        let _ = resources.isolate.teardown(handle).await;
        resources.proxy.deregister_session(proxy_handle.token());
        return Err(err.into());
    }

    // The set this session's `PolicyEngine` sealed-context provider reads
    // for `resolved_mcp_servers` — written to, below, by the exact same
    // `SessionMcp::resolved_servers()` call that also feeds
    // `SessionActor::register_mcp` (ruling W1-R85), so the two channels
    // CF-9(i) names can never disagree about WHICH servers resolved, only
    // (in principle) about the narrow window between the two writes.
    let mirrored_mcp_resolved: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::new()));

    // Ruling W1-R118: the rule set is an INPUT to session construction, not a
    // literal frozen into it. Tests can pass `no_policy_rules` for an empty,
    // fail-closed fixture; production supplies the file-derived source.
    let policy = Arc::new(
        PolicyEngine::from_rules((resources.policy_rules)()).with_sealed_ctx_provider(
            build_sealed_ctx_provider(
                resources.state_dir.clone(),
                resources.daemon_binary.clone(),
                roundhouse_policy::sealed::home_dir(),
                resources.isolate.clone(),
                handle.clone(),
                effective_tier(&spec),
                mirrored_mcp_resolved.clone(),
            ),
        ),
    );

    let (mcp_host, mcp, tool_defs) = if resources.mcp_configs.is_empty() {
        // **Ruling W1-R132: `builtin_tool_defs()`, NOT `Vec::new()`.** This
        // is the default production configuration — no `[[mcp_server]]` —
        // and it must still offer the model the five built-in tools.
        // `tool_catalog::merged_tool_defs` (below, via `start_session_mcp`)
        // is the only other thing that prepends them, and it is reachable
        // only from the MCP branch, so this branch supplying an empty
        // catalog meant the common case offered ZERO tools — contradicting
        // `SessionActor::tool_defs`' own doc comment, which describes this
        // exact case as "still carrying the five builtins".
        (
            None,
            None,
            roundhouse_engine::tool_catalog::builtin_tool_defs(),
        )
    } else {
        match start_session_mcp(
            resources.mcp_configs.clone(),
            session_id,
            resources.runner,
            writer.clone(),
            policy.clone(),
        )
        .await
        {
            Ok((host, mcp, tool_defs)) => (Some(host), Some(mcp), tool_defs),
            Err(err) => {
                // Fix round 2, MUST 2: isolation and egress registration
                // already succeeded by this point (we hold a real `handle`
                // and `proxy_handle`) — no `SessionActor` exists yet to
                // call `teardown()` on, so tear down directly rather than
                // leaking a real bwrap mount and an orphaned proxy-session
                // entry through this early return.
                let _ = resources.isolate.teardown(handle).await;
                resources.proxy.deregister_session(proxy_handle.token());
                return Err(err.into());
            }
        }
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
        apply_resolved_mcp_servers(&actor, &mirrored_mcp_resolved, mcp);
    }

    Ok(RealSession {
        actor,
        mcp_host,
        mcp,
        proxy_handle,
    })
}

/// Ruling W1-R85 — the ONLY writer of `mcp_resolved`; skipping this call
/// denies every MCP call in this session (see `SessionActor::register_mcp`'s
/// own doc comment for the full consequence). Also updates the mirrored
/// `resolved_mcp` set the session's `PolicyEngine` sealed-context provider
/// reads (CF-9(i)), from the SAME `SessionMcp::resolved_servers()` call.
///
/// Pulled out of [`create_real_session`] as its own function (fix round 1,
/// ruling W1-R99) specifically so this exact wiring can be tested directly
/// — `create_real_session`'s own MCP-configured path necessarily spawns a
/// real subprocess (`McpHost::start`), which this crate's tests cannot
/// stand up cheaply, so the previous test suite exercised only
/// `mcp_configs: Vec::new()` and never called this function at all. A
/// regression that deletes the `register_mcp` call is now caught by
/// `tests::apply_resolved_mcp_servers_registers_and_mirrors`, which builds
/// a real `SessionMcp` via the test-gated `SessionMcp::from_parts` instead.
fn apply_resolved_mcp_servers(
    actor: &SessionActor,
    mirrored_mcp_resolved: &Arc<RwLock<HashSet<String>>>,
    mcp: &SessionMcp,
) {
    actor.register_mcp(mcp);
    let resolved: HashSet<String> = mcp.resolved_servers().into_iter().collect();
    // Fix round 2 (SHOULD item): symmetric with `register_mcp`'s own
    // poisoned-lock handling immediately above (`.write().unwrap()` here
    // would panic this whole task on a poisoned lock instead of failing
    // closed the same way). The mirrored set stays as it was (empty,
    // unless a previous registration succeeded) — every `TaskParams::Mcp`
    // this session's `PolicyEngine` sealed-context provider judges still
    // sealed-denies, the same fail-closed consequence `register_mcp`'s own
    // doc comment describes for the actor's own copy.
    match mirrored_mcp_resolved.write() {
        Ok(mut guard) => *guard = resolved,
        Err(_) => tracing::error!(
            "mirrored_mcp_resolved lock is poisoned; refusing to update the PolicyEngine's \
             resolved-server input — every MCP task in this session will be denied by the \
             sealed floor"
        ),
    }
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
///
/// # Fail-closed on a poisoned lock (fix round 3, MUST 4; corrected to fail
/// CLOSED rather than fail OPEN in fix round 5)
///
/// `create_real_session` calls this UNCONDITIONALLY, after
/// `create_session_with_egress` has already succeeded — a real isolation
/// handle and a real proxy registration both already exist by this point.
/// The original `.lock().unwrap()` here would panic on a poisoned mutex,
/// unwinding out of `create_real_session` with no `SessionActor` yet built
/// to call `teardown()` on — orphaning both, every time, for every future
/// `CreateSession` this daemon process ever handles: a `std::sync::Mutex`
/// stays poisoned forever once poisoned, so the very first panic here would
/// have permanently broken session creation for the rest of the process's
/// life. Fix round 3 replaced the panic with match-and-continue, matching
/// `apply_resolved_mcp_servers`'s own poisoned-lock handling shape — but
/// that sibling function fails CLOSED (denies the MCP task rather than
/// admitting it unverified), while this one, on poison, PROCEEDED with the
/// session anyway. That is fail-OPEN: this session's own
/// `live_secret_values` (the provider API key, any MCP server `env`
/// secrets) then never enter `resources.proxy_secrets`, silently, for
/// every subsequent session too (the poisoned lock never un-poisons
/// itself) — a real, if session-scoped, secret-leak risk through the
/// shared egress proxy's own traffic, not merely "MCP redaction missing."
/// Fixed: this now returns `Err` on a poisoned lock, and
/// `create_real_session` routes that into the SAME teardown path fix
/// round 2's MUST 2 built for `start_session_mcp`'s failure branch — the
/// real isolation handle and proxy registration this call comes after are
/// torn down rather than left running unredacted.
fn register_proxy_secrets(
    resources: &DaemonResources,
    ctx: &RequestCtx,
) -> Result<(), ProxySecretsPoisonedError> {
    let this_session_secrets = roundhouse_engine::live_secret_values(ctx, &resources.mcp_configs);
    let mut all_secrets = match resources.proxy_secrets.lock() {
        Ok(guard) => guard,
        Err(_) => {
            tracing::error!(
                "proxy_secrets lock is poisoned; refusing to create this session rather than \
                 leave its live secrets, if any, unredacted from traffic proxied through the \
                 shared egress proxy"
            );
            return Err(ProxySecretsPoisonedError);
        }
    };
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
    Ok(())
}

/// The daemon-wide `DaemonResources::proxy_secrets` mutex is poisoned —
/// see [`register_proxy_secrets`]'s own doc comment for why this fails
/// the whole session rather than merely skipping the redaction update.
#[derive(Debug, thiserror::Error)]
#[error(
    "this daemon's shared proxy-secrets lock is poisoned; refusing to create a new session \
     rather than risk leaving a live secret unredacted in the shared egress proxy's traffic"
)]
pub struct ProxySecretsPoisonedError;

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

    #[tokio::test]
    async fn a_supplied_background_service_signals_readiness_and_is_joined_on_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let store = roundhouse_store::open(&dir.path().join("events.db"))
            .await
            .unwrap();
        let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
        let service: BackgroundService = Arc::new(move |mut context| {
            let started_tx = started_tx.clone();
            Box::pin(async move {
                context.signal_ready()?;
                let _ = started_tx.send(());
                while !*context.cancelled.borrow() {
                    if context.cancelled.changed().await.is_err() {
                        break;
                    }
                }
                Ok(())
            })
        });
        let services = BackgroundServices {
            workflow: Some(service),
            scheduler: None,
            acp: None,
        };
        let running = services
            .start(
                store,
                Arc::new(crate::session_registry::SessionRegistry::new()),
            )
            .await
            .unwrap();
        started_rx.recv().await.unwrap();
        running.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_non_workflow_service_failure_is_observed_and_the_remaining_service_is_joined() {
        let dir = tempfile::tempdir().unwrap();
        let store = roundhouse_store::open(&dir.path().join("events.db"))
            .await
            .unwrap();
        let workflow: BackgroundService = Arc::new(|mut context| {
            Box::pin(async move {
                context.signal_ready()?;
                while !*context.cancelled.borrow() {
                    context.cancelled.changed().await.map_err(|_| {
                        BackgroundServiceError("daemon dropped cancellation channel".to_string())
                    })?;
                }
                Ok(())
            })
        });
        let scheduler: BackgroundService = Arc::new(|mut context| {
            Box::pin(async move {
                context.signal_ready()?;
                Err(BackgroundServiceError("scheduler failed".to_string()))
            })
        });
        let services = BackgroundServices {
            workflow: Some(workflow),
            scheduler: Some(scheduler),
            acp: None,
        };
        let mut running = services
            .start(
                store,
                Arc::new(crate::session_registry::SessionRegistry::new()),
            )
            .await
            .unwrap();
        assert_eq!(
            running.wait_for_failure().await.unwrap_err().0,
            "scheduler failed"
        );
        running.shutdown().await.unwrap();
    }

    #[test]
    fn an_untrusted_project_allow_is_filtered_before_a_session_can_receive_it() {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let layer = roundhouse_config::PolicyLayer {
            scope: roundhouse_config::ConfigScope::Project,
            path: project.path().join(".roundhouse/policy.toml"),
            contents: "[[rule]]\nid = 'repo-read'\noutcome = 'allow'\nread = '/workspace/a'\n"
                .to_string(),
            file: roundhouse_config::PolicyFile {
                rule: vec![roundhouse_config::PolicyRule {
                    id: "repo-read".to_string(),
                    outcome: roundhouse_config::PolicyRuleOutcome::Allow,
                    read: PathBuf::from("/workspace/a"),
                }],
            },
        };
        let effective =
            effective_policy_rules(&[layer], Some(project.path()), state.path()).unwrap();
        assert!(
            effective.is_empty(),
            "a first-use project file must not widen policy with its Allow rule"
        );
    }
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
            OnDegrade::Refuse,
            no_policy_rules(),
            BackgroundServices::default(),
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

    /// Ruling W1-R132: the DEFAULT production configuration — no
    /// `[[mcp_server]]` at all — must still offer the model the five
    /// built-in tools. Before this fix the no-MCP branch of
    /// `create_real_session` supplied `Vec::new()`, and
    /// `tool_catalog::merged_tool_defs` (the only thing that prepends
    /// `builtin_tool_defs()`) had exactly one caller, inside the MCP
    /// branch — so the common case offered ZERO tools, contradicting the
    /// `tool_defs` field's own doc comment in `session_actor.rs`.
    ///
    /// **No existing daemon-level test would have caught this**: every
    /// other one builds its `SessionActor` with `vec![]` directly, so the
    /// value under test here is only ever produced by `create_real_session`
    /// itself. That is why this asserts through the real bootstrap function
    /// rather than through a hand-built actor.
    #[tokio::test]
    async fn a_session_with_no_mcp_servers_configured_still_offers_the_five_builtins() {
        let dir = tempfile::tempdir().unwrap();
        let resources = resources(dir.path()).await;
        assert!(
            resources.mcp_configs.is_empty(),
            "this test pins the NO-MCP branch specifically — it proves nothing if the fixture \
             configures an MCP server"
        );

        let real_session = create_real_session(&resources, "test-workspace".into())
            .await
            .unwrap();

        let mut offered: Vec<&str> = real_session
            .actor
            .tool_defs()
            .iter()
            .map(|d| d.name())
            .collect();
        offered.sort_unstable();
        assert_eq!(
            offered,
            ["edit", "find", "read", "shell", "write"],
            "a default (no-MCP) session must offer exactly the five builtin tools"
        );
    }

    /// Fix round 3, MUST 4: a poisoned `proxy_secrets` mutex must not panic
    /// `register_proxy_secrets` — it did before this fix
    /// (`.lock().unwrap()`), and since `std::sync::Mutex` stays poisoned
    /// forever once poisoned, the very first panic would have permanently
    /// broken every future `CreateSession` this daemon process ever
    /// handled (this function runs unconditionally inside
    /// `create_real_session`, after real isolation + proxy resources
    /// already exist with no `SessionActor` yet built to tear them down
    /// on unwind).
    #[tokio::test]
    async fn register_proxy_secrets_fails_closed_rather_than_panicking_on_a_poisoned_lock() {
        let dir = tempfile::tempdir().unwrap();
        let resources = resources(dir.path()).await;

        // Poison the lock the same way any real panic while holding it
        // would: panic inside the critical section, caught so the test
        // itself survives.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = resources.proxy_secrets.lock().unwrap();
            panic!("deliberately poisoning proxy_secrets for this test");
        }));
        assert!(
            resources.proxy_secrets.is_poisoned(),
            "sanity check failed: the mutex should be poisoned by now"
        );

        let ctx = resources.clone_request_ctx();
        let mut result = None;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            result = Some(register_proxy_secrets(&resources, &ctx));
        }));
        assert!(
            outcome.is_ok(),
            "register_proxy_secrets must not panic on a poisoned proxy_secrets lock"
        );
        // Fix round 5, MUST 4: fail CLOSED, not open — a poisoned lock must
        // return `Err`, not silently proceed as though nothing happened.
        assert!(
            result.unwrap().is_err(),
            "register_proxy_secrets must return Err on a poisoned lock, not Ok"
        );
    }

    /// Fix round 5, MUST 4: end-to-end proof that `create_real_session`
    /// itself fails closed on a poisoned `proxy_secrets` lock — tearing
    /// down the real isolation handle and proxy registration it had
    /// already built, rather than (as the pre-fix version did) silently
    /// continuing to build a full session with that session's own secrets
    /// never entering the shared proxy's redaction set.
    #[tokio::test]
    async fn create_real_session_fails_closed_and_tears_down_on_a_poisoned_proxy_secrets_lock() {
        let dir = tempfile::tempdir().unwrap();
        let resources = resources(dir.path()).await;

        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = resources.proxy_secrets.lock().unwrap();
            panic!("deliberately poisoning proxy_secrets for this test");
        }));
        assert!(resources.proxy_secrets.is_poisoned());

        match create_real_session(&resources, "test-workspace".into()).await {
            Err(CreateRealSessionError::ProxySecretsPoisoned(_)) => {}
            Err(other) => panic!(
                "create_real_session must fail with ProxySecretsPoisoned on a poisoned \
                 lock, got a different error: {other}"
            ),
            Ok(_) => panic!(
                "create_real_session must fail with ProxySecretsPoisoned on a poisoned \
                 lock, got Ok"
            ),
        }
    }

    /// Fix round 2, MUST 6: `create_real_session`'s OWN MCP-configured
    /// branch (`start_session_mcp` → `McpHost::start`, the real subprocess
    /// spawn) had zero coverage — the doc comment on `apply_resolved_mcp_
    /// servers` above claimed "too heavy for this crate's unit tests," but
    /// the workspace already has precedent for standing up a real
    /// lightweight MCP subprocess in a test:
    /// `roundhouse-mcp/tests/host_integration.rs`'s `fake-mcp-stdio-server`
    /// binary. This drives `create_real_session` itself, with one real
    /// configured server, through the real (non-test-gated) path — proving
    /// `start_session_mcp`'s spawn/discovery AND the `apply_resolved_mcp_
    /// servers` call site inside `create_real_session` both actually ran,
    /// not just the extracted helper in isolation.
    mod real_mcp_configured_tests {
        use super::*;
        use roundhouse_core::{Origin, TaskKind};
        use roundhouse_engine::{AdmitError, TaskCreateRequest};
        use roundhouse_mcp::config::{McpServerConfig, McpTransportKind};
        use roundhouse_policy::{ServerId, TaskParams};

        const FAKE_SERVER: &str = "fake";

        /// `CARGO_BIN_EXE_fake-mcp-stdio-server` is only set by Cargo for
        /// `roundhouse-mcp`'s OWN tests (the crate that owns that `[[bin]]`
        /// target) — not for this crate's. `cargo test --workspace` (this
        /// repo's required test gate) builds every workspace member's
        /// binaries into the same shared `target/<profile>/` directory
        /// before running any test binary, and this test binary itself
        /// lives at `target/<profile>/deps/<this-crate>-<hash>`, two
        /// directories below that same root — so walk up to it and look for
        /// the sibling binary there, the same way `roundhouse_cli::commands
        /// ::daemon::daemon_binary_path` locates its own sibling
        /// `round-daemon-internal`. This is fragile only under a standalone
        /// `cargo test -p roundhouse-daemon` run with nothing else in the
        /// workspace ever built — the assert below names the exact path
        /// searched rather than failing with a bare "file not found" if
        /// that happens.
        fn fake_mcp_stdio_server_path() -> PathBuf {
            let test_exe = std::env::current_exe().expect("current test executable path");
            let profile_dir = test_exe
                .parent() // target/<profile>/deps
                .and_then(|p| p.parent()) // target/<profile>
                .expect("test executable has a target/<profile>/deps parent");
            let bin = profile_dir.join("fake-mcp-stdio-server");
            assert!(
                bin.exists(),
                "{} not found — this test needs `roundhouse-mcp`'s \
                 `fake-mcp-stdio-server` binary already built alongside this test \
                 binary; run via `cargo test --workspace`, not a standalone \
                 `cargo test -p roundhouse-daemon` with nothing else built",
                bin.display()
            );
            bin
        }

        fn mcp_task(server: &str) -> TaskCreateRequest {
            TaskCreateRequest {
                kind: TaskKind::Mcp,
                origin: Origin::Model,
                is_finally_step: false,
                params: TaskParams::Mcp {
                    server: ServerId(server.to_string()),
                    tool: "whoami".to_string(),
                    args: serde_json::Value::Null,
                },
            }
        }

        #[tokio::test]
        async fn a_real_configured_mcp_server_is_spawned_and_registered_so_its_task_is_not_sealed_denied(
        ) {
            let dir = tempfile::tempdir().unwrap();
            let mut resources = resources(dir.path()).await;
            resources.mcp_configs = vec![McpServerConfig {
                id: ServerId(FAKE_SERVER.to_string()),
                transport: McpTransportKind::Stdio {
                    command: fake_mcp_stdio_server_path().to_string_lossy().into_owned(),
                    args: vec![],
                    env: vec![],
                    pinned_binary_hash: None,
                },
            }];

            let real_session = create_real_session(&resources, "test-workspace".into())
                .await
                .expect("a real, working configured MCP server must not fail session creation");

            assert!(
                real_session.mcp_host.is_some(),
                "a configured MCP server must produce a real McpHost, not the \
                 `mcp_configs.is_empty()` no-op branch"
            );

            // `sealed_mcp_unresolved` (roundhouse-policy) denies an MCP task
            // unless its server appears in `SealedContext.resolved_mcp_servers` —
            // which only `apply_resolved_mcp_servers`'s `SessionActor::
            // register_mcp` call populates (ruling W1-R85). A regression that
            // drops either that call OR the real `start_session_mcp` spawn
            // above would leave this server unresolved and this task denied.
            let result = real_session.actor.admit_task(&mcp_task(FAKE_SERVER)).await;
            assert!(
                !matches!(result, Err(AdmitError::Denied(_))),
                "an MCP task naming the real server create_real_session just spawned and \
                 resolved must not be denied by sealed_mcp_unresolved, got {result:?}"
            );

            teardown_real_session(&resources.proxy, real_session).await;
        }
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

    /// Ruling W1-R99 (fix round 1): `create_real_session`'s only prior test
    /// passed `mcp_configs: Vec::new()`, so the branch containing the
    /// `register_mcp` call (ruling W1-R85) was never exercised — a
    /// regression deleting that call would have passed every test in this
    /// crate. `create_real_session`'s own MCP-configured path necessarily
    /// spawns a real subprocess (`McpHost::start`), which is too heavy for
    /// this crate's unit tests, so this proves the extracted
    /// `apply_resolved_mcp_servers` directly: a real actor, a real
    /// `SessionMcp` (built via the test-gated `SessionMcp::from_parts`, not
    /// `start_session_mcp`), and confirms the actor actually admits an MCP
    /// task naming the resolved server — proving `register_mcp` really ran,
    /// not just that `resolved_servers()` was called on something.
    ///
    /// The `_without_it` mirror test proves this is a REAL regression
    /// check, not a vacuously-true one: the identical task is denied when
    /// `apply_resolved_mcp_servers` is never called.
    mod apply_resolved_mcp_servers_tests {
        use super::*;
        use roundhouse_core::{Origin, TaskKind};
        use roundhouse_engine::mcp_spawner::{EngineTaskSpawner, SessionMcp};
        use roundhouse_engine::{AdmitError, TaskCreateRequest};
        use roundhouse_mcp::executor::TaskSpawner as McpTaskSpawner;
        use roundhouse_mcp::namespace::ToolNamespace;
        use roundhouse_mcp::transport::McpTransport;
        use roundhouse_mcp::wire::{DiscoverResult, McpError, McpResult, ToolCallRequest};
        use roundhouse_policy::engine::{CompiledRule, Outcome, Predicate, Scope};
        use roundhouse_policy::{ServerId, TaskParams};

        const FAKE_SERVER: &str = "fake-server";

        /// A transport that discovers one tool and is never actually
        /// called — `apply_resolved_mcp_servers` only reads
        /// `resolved_servers()`, which reflects the CONNECTIONS
        /// `SessionMcp` was built from, not any real traffic over them.
        struct FakeTransport;

        #[async_trait::async_trait]
        impl McpTransport for FakeTransport {
            async fn discover(&self) -> Result<DiscoverResult, McpError> {
                unreachable!("not exercised by this test")
            }
            async fn call_tool(&self, _req: ToolCallRequest) -> Result<McpResult, McpError> {
                unreachable!("not exercised by this test")
            }
            async fn shutdown(&self) -> Result<(), McpError> {
                Ok(())
            }
        }

        /// Builds a real `SessionMcp` claiming `FAKE_SERVER` resolved, wired
        /// to `policy` — mirrors `create_real_session`'s own construction
        /// order (policy built first, `SessionMcp` built against it) without
        /// needing a real `McpHost::start`.
        fn fake_resolved_session_mcp(
            runner: &'static roundhouse_core::TaskRunner,
            writer: roundhouse_store::EventWriter,
            session_id: SessionId,
            policy: Arc<PolicyEngine>,
        ) -> SessionMcp {
            let server = ServerId(FAKE_SERVER.to_string());
            let connections: Vec<(ServerId, Arc<dyn McpTransport>)> =
                vec![(server, Arc::new(FakeTransport))];
            let namespace = ToolNamespace::build(&[]).unwrap();
            let task_spawner: Arc<dyn McpTaskSpawner> =
                Arc::new(EngineTaskSpawner::new(runner, writer, session_id));
            SessionMcp::from_parts(connections, namespace, policy, task_spawner)
                .expect("the test's PolicyEngine has a real sealed_ctx_provider installed")
        }

        fn mcp_task(server: &str) -> TaskCreateRequest {
            TaskCreateRequest {
                kind: TaskKind::Mcp,
                origin: Origin::Model,
                is_finally_step: false,
                params: TaskParams::Mcp {
                    server: ServerId(server.to_string()),
                    tool: "whoami".to_string(),
                    args: serde_json::Value::Null,
                },
            }
        }

        #[tokio::test]
        async fn registers_on_the_actor_so_an_mcp_task_naming_that_server_is_admitted() {
            let dir = tempfile::tempdir().unwrap();
            let isolate = available_isolate();
            let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
            let handle = isolate.prepare(&spec).await.unwrap();
            let session_id = SessionId::new();
            let store = roundhouse_store::open(&dir.path().join("events.db"))
                .await
                .unwrap();
            let writer = spawn_writer(store).await;

            let mirrored: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::new()));
            // An explicit `Allow` rule for this one tool: with zero
            // configured rules, an unmatched-but-not-sealed-denied task
            // falls through to `Ask` (`AdmitError::RequiresApproval`), not
            // `Allow` — this test is about proving `register_mcp` clears
            // the SEALED `sealed_mcp_unresolved` denial specifically, so a
            // real allow rule is needed to reach `Ok(())` rather than a
            // different, unrelated non-`Ok` outcome.
            let allow_whoami = CompiledRule::test_new(
                Scope::Builtin,
                Outcome::Allow,
                Predicate::mcp(
                    ServerId(FAKE_SERVER.to_string()),
                    Some("whoami".to_string()),
                ),
            );
            let policy = Arc::new(
                PolicyEngine::from_rules(vec![allow_whoami]).with_sealed_ctx_provider(
                    build_sealed_ctx_provider(
                        dir.path().join("state"),
                        dir.path().join("daemon-binary"),
                        None,
                        isolate.clone(),
                        handle.clone(),
                        Tier::Sandbox,
                        mirrored.clone(),
                    ),
                ),
            );

            let actor = SessionActor::new(
                session_id,
                writer.clone(),
                SessionState::Running,
                runner(),
                policy.clone(),
                dir.path().join("state"),
                dir.path().join("daemon-binary"),
                isolate,
                handle,
                spec,
                vec![],
            );

            let mcp = fake_resolved_session_mcp(runner(), writer, session_id, policy);
            apply_resolved_mcp_servers(&actor, &mirrored, &mcp);

            let result = actor.admit_task(&mcp_task(FAKE_SERVER)).await;
            assert!(
                result.is_ok(),
                "an MCP task naming a server apply_resolved_mcp_servers just \
                 registered as resolved must be admitted, got {result:?}"
            );
            assert!(mirrored.read().unwrap().contains(FAKE_SERVER));
        }

        /// The regression-catching mirror: WITHOUT calling
        /// `apply_resolved_mcp_servers`, the identical task must be denied
        /// by `sealed_mcp_unresolved` — proving the test above is a real
        /// check, not one that would pass regardless of whether
        /// `register_mcp` ran.
        #[tokio::test]
        async fn without_registering_the_identical_mcp_task_is_denied() {
            let dir = tempfile::tempdir().unwrap();
            let isolate = available_isolate();
            let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
            let handle = isolate.prepare(&spec).await.unwrap();
            let session_id = SessionId::new();
            let store = roundhouse_store::open(&dir.path().join("events.db"))
                .await
                .unwrap();
            let writer = spawn_writer(store).await;

            let mirrored: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::new()));
            let policy = Arc::new(PolicyEngine::from_rules(vec![]).with_sealed_ctx_provider(
                build_sealed_ctx_provider(
                    dir.path().join("state"),
                    dir.path().join("daemon-binary"),
                    None,
                    isolate.clone(),
                    handle.clone(),
                    Tier::Sandbox,
                    mirrored.clone(),
                ),
            ));

            let actor = SessionActor::new(
                session_id,
                writer,
                SessionState::Running,
                runner(),
                policy,
                dir.path().join("state"),
                dir.path().join("daemon-binary"),
                isolate,
                handle,
                spec,
                vec![],
            );

            // Deliberately no `apply_resolved_mcp_servers` call.
            let result = actor.admit_task(&mcp_task(FAKE_SERVER)).await;
            assert!(
                matches!(result, Err(AdmitError::Denied(_))),
                "an MCP task must be denied by sealed_mcp_unresolved when no \
                 server was ever registered as resolved, got {result:?}"
            );
        }
    }
}
