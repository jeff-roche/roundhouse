//! The production `roundhouse_mcp::executor::TaskSpawner` — closes the gap
//! `roundhouse-mcp`'s own doc comments flag repeatedly: every task minted
//! through that trait before this module existed came from a test double
//! (`RecordingTaskSpawner`/`NoopTaskSpawner`), so `McpExecutor`/`McpHost`
//! could never actually mint a real, event-sourced task anywhere outside a
//! unit test. `roundhouse-mcp` deliberately never touches
//! `TaskRunner::record_*` directly (see `TaskSpawner`'s own doc comment in
//! `roundhouse_mcp::executor`): those calls need a session's append-only
//! `seq` counter and `schema_v`, both store/engine-owned state that crate
//! has no business holding. This is the engine-side implementation that
//! wraps `TaskRunner` + an `EventWriter` to close that seam for real.
//!
//! **Ordering is the whole point (S-LOG-1).** The entire reason
//! `TaskSpawner` exists instead of a bare `TaskId::new()` is that the
//! minted id must resolve through the real event-sourced task view — a
//! fabricated id is precisely the bug this type closes. So [`spawn_task`]
//! mints the [`roundhouse_core::TaskId`] and then, in the same call,
//! durably appends its `TaskCreated` event *before* returning that id to
//! the caller. If the append fails, the id must never be handed back
//! anyway — see the panic note on [`EngineTaskSpawner`]'s methods below for
//! why a failed append is treated as fatal here, not swallowed.
//!
//! # Every method has a real implementation
//! `TaskSpawner` has four methods (`spawn_task`, `suspend_task`,
//! `record_decision`, `record_terminal`) and all four are implemented here
//! with real, durable behavior — none is a stub or a silent no-op. Every
//! one of them mints exactly one `roundhouse_core` event through `runner`
//! (the same sealed `record_*` constructors `chat.rs`/`session_actor.rs`
//! already use) and appends it through `writer`.
//!
//! # Why every method panics on a failed append instead of returning `Err`
//! None of `TaskSpawner`'s four methods return a `Result` — that's fixed by
//! the trait, defined in `roundhouse-mcp`, which this crate cannot change
//! (a breaking change to it is out of this lane's scope; see
//! `LANE-CONTEXT.md`'s "no edit to `roundhouse-mcp` without a BLOCKED
//! report" rule). So a failed `EventWriter::append` — e.g. the writer task
//! having shut down, or a non-retryable SQLite error — has no channel to
//! propagate through. Swallowing it (`let _ = ...`) would mean
//! `spawn_task` could return a `TaskId` whose `TaskCreated` event never
//! landed: exactly the fabricated-id bug `TaskSpawner` exists to close,
//! now reintroduced one layer down. Panicking instead is the fail-closed
//! choice, consistent with this crate's other "assert or expect on a
//! violated invariant rather than launder it" call sites (e.g.
//! `params_digest`'s `expect("TaskParams serialization cannot fail")` in
//! `roundhouse-mcp`, or `SessionActor::new`'s path-shape asserts).

use async_trait::async_trait;
use roundhouse_core::{
    Origin, PolicyDecision, SessionId, SuspendReason, TaskId, TaskKind, TaskRunner, Timestamp,
};
use roundhouse_mcp::config::McpServerConfig;
use roundhouse_mcp::executor::{
    McpExecutor, TaskInput as McpTaskInput, TaskSpawner, TerminalOutcome,
};
use roundhouse_mcp::host::{McpHost, McpHostError};
use roundhouse_mcp::namespace::ToolNamespace;
use roundhouse_mcp::transport::McpTransport;
use roundhouse_policy::engine::PolicyEngine;
use roundhouse_policy::ServerId;
use roundhouse_provider::ToolDef;
use roundhouse_store::EventWriter;
use std::sync::Arc;

/// `Timestamp` has no `now()` — read the wall clock ourselves and convert.
/// Mirrors the identical helper in `chat.rs`/`session_actor.rs`.
fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

/// Converts `roundhouse-mcp`'s own local `TaskInput` (`Mcp`/`Elicit` — see
/// that type's doc comment for why it can't live in `roundhouse_core`: it
/// carries `roundhouse_policy::ServerId`, and `roundhouse-policy` already
/// depends on `roundhouse-core`, so a core-side variant would be a
/// dependency cycle) into the real, frozen `roundhouse_core::TaskInput`
/// (`Json`/`Text`/`Blob` only, §4.1/§4.5) that `TaskRunner::record_task_created`
/// actually accepts. Both MCP-local variants carry only JSON-serializable
/// fields, so `Json` losslessly represents either one — nothing here is a
/// lossy summary, just a re-encoding into the shape the frozen event log
/// understands.
fn to_core_task_input(input: McpTaskInput) -> roundhouse_core::TaskInput {
    match input {
        McpTaskInput::Mcp { server, tool, args } => {
            roundhouse_core::TaskInput::Json(serde_json::json!({
                "kind": "mcp",
                "server": server.0,
                "tool": tool,
                "args": args,
            }))
        }
        McpTaskInput::Elicit {
            schema,
            question,
            mcp_resume_context,
        } => roundhouse_core::TaskInput::Json(serde_json::json!({
            "kind": "elicit",
            "schema": schema,
            "question": question,
            "mcp_resume_context": mcp_resume_context,
        })),
    }
}

/// The production `TaskSpawner`: one instance per session, wrapping the
/// process-wide `TaskRunner` singleton (`TaskRunner::bootstrap()`, held as a
/// `'static` reference the same way `SessionActor` holds its own — see that
/// struct's `runner` field doc comment) and the session's `EventWriter`.
///
/// `session_id` is stored because three of `TaskSpawner`'s four methods
/// (`suspend_task`/`record_decision`/`record_terminal`) don't receive a
/// session id as an argument — only a bare `TaskId` — but every
/// `roundhouse_core::TaskRunner::record_*` call needs one. Since exactly one
/// `EngineTaskSpawner` is built per session (see
/// `SessionActor`'s construction path), this field is always the right
/// session for every task this spawner ever mints or records against.
/// `spawn_task` itself is handed a `session` argument by its caller too
/// (`McpExecutor` always passes `ctx.session`); that argument is used
/// directly there rather than `self.session_id`, since it is the more
/// faithful read of the trait's own contract — in practice the two always
/// agree for a correctly-constructed spawner.
pub struct EngineTaskSpawner {
    runner: &'static TaskRunner,
    writer: EventWriter,
    session_id: SessionId,
}

impl EngineTaskSpawner {
    pub fn new(runner: &'static TaskRunner, writer: EventWriter, session_id: SessionId) -> Self {
        Self {
            runner,
            writer,
            session_id,
        }
    }
}

#[async_trait]
impl TaskSpawner for EngineTaskSpawner {
    async fn spawn_task(
        &self,
        session: SessionId,
        parent: Option<TaskId>,
        kind: TaskKind,
        origin: Origin,
        input: McpTaskInput,
    ) -> TaskId {
        let task_id = TaskId::new();
        let event = self.runner.record_task_created(
            session,
            0, // ignored — EventWriter::append assigns the real per-session seq
            now_ts(),
            task_id,
            kind,
            parent,
            origin,
            to_core_task_input(input),
            1,
        );
        // S-LOG-1: the id is only returned once its TaskCreated event is
        // durably appended — see this module's doc comment for why a
        // failed append panics here instead of silently handing back an
        // id that resolves to nothing.
        self.writer.append(event).await.expect(
            "EngineTaskSpawner::spawn_task: TaskSpawner::spawn_task has no Result to propagate \
             a store failure through, and returning a TaskId before its TaskCreated event is \
             durably appended would silently reintroduce the fabricated-id bug this type exists \
             to close (S-LOG-1)",
        );
        task_id
    }

    async fn suspend_task(&self, task: TaskId, reason: SuspendReason) {
        let event = self.runner.record_task_suspended(
            self.session_id,
            0, // ignored — EventWriter::append assigns the real per-session seq
            now_ts(),
            task,
            reason,
            1,
        );
        self.writer.append(event).await.expect(
            "EngineTaskSpawner::suspend_task: no Result to propagate a store failure through; \
             see this module's doc comment for why a failed append is treated as fatal here",
        );
    }

    async fn record_decision(&self, task: TaskId, decision: PolicyDecision) {
        let event = self.runner.record_task_decided(
            self.session_id,
            0, // ignored — EventWriter::append assigns the real per-session seq
            now_ts(),
            task,
            decision,
            // `TaskSpawner::record_decision` carries no rule id (mirrors
            // `PolicyDecision` itself, which has no payload on any variant
            // — see `McpExecutor::gate`'s own comment on this).
            None,
            1,
        );
        self.writer.append(event).await.expect(
            "EngineTaskSpawner::record_decision: no Result to propagate a store failure through; \
             see this module's doc comment for why a failed append is treated as fatal here",
        );
    }

    async fn record_terminal(&self, task: TaskId, outcome: TerminalOutcome) {
        let event = match outcome {
            TerminalOutcome::Completed { output, usage } => self.runner.record_task_completed(
                self.session_id,
                0, // ignored — EventWriter::append assigns the real per-session seq
                now_ts(),
                task,
                output,
                usage,
                1,
            ),
            TerminalOutcome::Failed { error, retryable } => self.runner.record_task_failed(
                self.session_id,
                0, // ignored — EventWriter::append assigns the real per-session seq
                now_ts(),
                task,
                error,
                retryable,
                1,
            ),
        };
        self.writer.append(event).await.expect(
            "EngineTaskSpawner::record_terminal: no Result to propagate a store failure through; \
             see this module's doc comment for why a failed append is treated as fatal here",
        );
    }
}

/// Errors from [`start_session_mcp`]: either the supplied `PolicyEngine`
/// has no real sealed-context provider installed
/// ([`StartSessionMcpError::UnconfiguredSealedContext`] — checked BEFORE
/// anything is spawned), `McpHost::start` itself failed (a server refused
/// to spawn, discovery failed, or the discovered tool namespace collided —
/// see [`McpHostError`]), or the discovered tools collided by name with the
/// built-in catalog or each other (Task 1's
/// [`crate::tool_catalog::ToolCatalogError`]).
#[derive(Debug, thiserror::Error)]
pub enum StartSessionMcpError {
    /// Security review fix round 1 (ruling W1-R17): `policy.sealed_ctx()`
    /// still returns `roundhouse_policy::sealed::default_context()`'s
    /// placeholder (`state_dir`/`daemon_binary` empty, not absolute) —
    /// nothing has called `PolicyEngine::with_sealed_ctx_provider` with a
    /// real provider. See this error variant's `Display` message for why
    /// this is checked and refused rather than silently proceeding.
    #[error(
        "PolicyEngine has no real sealed_ctx_provider installed (sealed_ctx() still returns \
         the empty/non-absolute placeholder from roundhouse_policy::sealed::default_context) — \
         refusing to start this session's MCP servers under a policy that cannot resolve real \
         sealed-floor context. Every TaskParams::Mcp would currently be denied by \
         sealed_mcp_unresolved (fail-closed, but a trap: install a real provider via \
         PolicyEngine::with_sealed_ctx_provider(...) rather than swapping in a permissive \
         Policy to work around the denials"
    )]
    UnconfiguredSealedContext,
    #[error(transparent)]
    Host(#[from] McpHostError),
    #[error(transparent)]
    ToolCatalog(#[from] crate::tool_catalog::ToolCatalogError),
}

/// Spawns every configured MCP server for one session through the real
/// task-creation authority (`McpHost::start`, using an [`EngineTaskSpawner`]
/// built here as its `TaskSpawner` — S-LOG-1: the discovery task this mints
/// is queryable, never a bare `TaskId::new()`), and merges the resulting
/// MCP-discovered tools with the built-in catalog (Task 1's
/// [`crate::tool_catalog::merged_tool_defs`]) into the one tool list an
/// `infer` task's `ChatRequest.tools` should draw from.
///
/// **This is the "session creation calls `McpHost::start`" step Task 4's
/// brief describes** — but it is deliberately a free function that runs
/// *before* [`crate::SessionActor::new`], not code inside `new` itself:
/// `McpHost::start` is async and fallible, while `SessionActor::new` is
/// neither (it is a sync, infallible-except-panic constructor — see that
/// function's own doc comment on its fail-closed path asserts). This
/// mirrors the exact precedent already in `session_actor.rs`:
/// `create_session_isolation`/`create_session_with_egress` are async free
/// functions that build a `Handle`/`ProxyHandle` BEFORE `SessionActor::new`
/// is called, rather than `new` doing that work itself. `SessionActor`
/// itself stores the already-merged `Vec<ToolDef>` this function returns —
/// see its `tool_defs` field and constructor parameter of the same name —
/// not the raw `configs`.
///
/// An empty `configs` is a cheap, allocation-light no-op path (no server to
/// spawn, no discovery to await): sessions configured with zero MCP servers
/// — the common case — pay effectively nothing to call this.
///
/// Returns three things, not just the tool list: the started [`McpHost`],
/// because whatever tears a session down needs `host.shutdown()`; a
/// [`SessionMcp`], because that is what [`crate::agent_loop::run_agent_loop`]
/// dispatches through and what [`crate::SessionActor::register_mcp`] takes
/// (fix round D — see [`SessionMcp`]'s own doc comment for why the loop takes
/// the newtype rather than a bare `Arc<McpExecutor>`); and the merged tool
/// list itself.
///
/// # On `policy` (security review fix round 1, ruling W1-R15)
/// An earlier version of this function took `policy: Arc<dyn Policy>` and
/// this doc comment claimed bridging `SessionActor`'s sealed-floor
/// `PolicyEngine` to `McpHost::start`'s `Policy` trait needed new adapter
/// code this task didn't own. **That premise was wrong** — the real
/// `impl crate::Policy for PolicyEngine` already exists
/// (`roundhouse-policy/src/engine.rs`), routes through `decide_sealed()`
/// against `self.sealed_ctx()`, and its own doc comment states the intent
/// outright: "so `PolicyEngine` is a drop-in `Box<dyn Policy>` ... the
/// sealed floor is never bypassable through the trait-object call path
/// either." So `Arc<PolicyEngine>` unsize-coerces to `Arc<dyn Policy>` for
/// free, with zero bridging code.
///
/// Taking the CONCRETE `Arc<PolicyEngine>` here (rather than `Arc<dyn
/// Policy>`) is deliberately the tighter, security-relevant choice, not a
/// typing preference: a permissive `AllowAllPolicy` test double genuinely
/// exists in `roundhouse-mcp`'s own test suite
/// (`tests/host_integration.rs`, `tests/integration.rs`). Declaring this
/// parameter as `Arc<dyn Policy>` would let a future caller pass one of
/// those in without the compiler noticing; declaring it as the concrete
/// `PolicyEngine` type makes doing so a compile error instead.
///
/// The REAL residual gap this function does guard against explicitly: refer
/// to [`StartSessionMcpError::UnconfiguredSealedContext`]. `PolicyEngine`'s
/// `sealed_ctx()` is driven by a caller-installed provider
/// (`with_sealed_ctx_provider`) that nothing in this codebase installs yet
/// — so an un-configured `PolicyEngine` always judges MCP dispatch against
/// `roundhouse_policy::sealed::default_context()`'s empty placeholder
/// (`state_dir`/`daemon_binary` empty, `resolved_mcp_servers` empty). That
/// currently denies every `TaskParams::Mcp` closed via
/// `sealed_mcp_unresolved` — safe, but a trap for whoever wires this up
/// next: seeing 100% of MCP calls denied and reaching for a permissive
/// `Policy` instead of installing a real provider would be exactly the
/// fail-open shortcut this type signature is designed to make impossible.
/// This function instead detects the placeholder up front (the same
/// non-absolute-path shape `SessionActor::new`'s own asserts already treat
/// as invalid) and returns a named, typed error rather than either
/// panicking or silently running every dispatch through a floor that can
/// never resolve any server.
///
/// **What this check does NOT prove (carry-forward CF-8):** `check_sealed_ctx_configured`
/// (below) tests only `state_dir.is_absolute() && daemon_binary.is_absolute()`
/// — it distinguishes "some real provider is installed" from "the
/// untouched `default_context()` placeholder," nothing more. An installed
/// provider that returns an absolute-but-WRONG `state_dir`/`daemon_binary`
/// (a typo, a path from a different session, a stale snapshot) passes this
/// guard exactly as readily as a correct one; there is no cross-check
/// against reality here or anywhere downstream. Read this error variant's
/// own `Display` message ("refusing to start ... under a policy that
/// cannot resolve real sealed-floor context") as "resolves *some* context,"
/// not "resolves the *correct* one."
pub async fn start_session_mcp(
    configs: Vec<McpServerConfig>,
    session_id: SessionId,
    runner: &'static TaskRunner,
    writer: EventWriter,
    policy: Arc<PolicyEngine>,
) -> Result<(Arc<McpHost>, SessionMcp, Vec<ToolDef>), StartSessionMcpError> {
    check_sealed_ctx_configured(&policy)?;
    let spawner: Arc<dyn TaskSpawner> =
        Arc::new(EngineTaskSpawner::new(runner, writer, session_id));
    let host = McpHost::start(configs, session_id, policy, spawner).await?;
    let tool_defs = crate::tool_catalog::merged_tool_defs(host.tool_defs())?;
    let host = Arc::new(host);
    // The one mint that does not go through `SessionMcp::from_parts`:
    // `McpHost::start` was just handed the same concrete `Arc<PolicyEngine>`
    // this function's own signature demands, so the executor it built carries
    // the real sealed floor by construction — the exact property the newtype
    // exists to attest to.
    let mcp = SessionMcp {
        executor: Arc::clone(&host.executor),
    };
    Ok((host, mcp, tool_defs))
}

/// The [`StartSessionMcpError::UnconfiguredSealedContext`] guard, shared by
/// both mints of a [`SessionMcp`] so neither can be the loose one. See that
/// variant's own doc comment (and carry-forward CF-8) for what it does and
/// does not prove.
fn check_sealed_ctx_configured(policy: &PolicyEngine) -> Result<(), StartSessionMcpError> {
    let ctx = policy.sealed_ctx();
    if !ctx.state_dir.is_absolute() || !ctx.daemon_binary.is_absolute() {
        return Err(StartSessionMcpError::UnconfiguredSealedContext);
    }
    Ok(())
}

/// An [`McpExecutor`] that is *proven*, by the type system rather than by a
/// convention one layer up, to have been built against the real
/// `PolicyEngine` sealed floor.
///
/// # Why this type exists (fix round D, ruling W1-R81 finding I4)
///
/// `McpExecutor::gate` is the §6.2 policy gate every MCP dispatch passes
/// through, and it consults an `Arc<dyn Policy>` the executor was
/// constructed with. `McpExecutor::new` is `pub` and takes exactly that
/// trait object, and permissive test doubles that implement it really do
/// exist in this workspace (`AllowAllPolicy` in `roundhouse-mcp`'s
/// `tests/host_integration.rs` and `tests/integration.rs`). Before this
/// type, `agent_loop::run_agent_loop` took a bare
/// `Option<Arc<McpExecutor>>`, so the entire "MCP's gate is not weaker than
/// the built-in arm's" claim rested on [`start_session_mcp`]'s signature
/// **one layer up** — a caller that built its own `McpExecutor` and handed
/// it straight to the loop bypassed the floor with no compiler objection,
/// and every MCP test in this crate did precisely that.
///
/// This is ruling W1-R15's move applied one layer down: both constructors
/// take the CONCRETE `Arc<PolicyEngine>`, so passing an `AllowAllPolicy` (or
/// any other `Arc<dyn Policy>`) is a **compile error** rather than a thing a
/// future caller can quietly do. The field is private and there is no
/// `From`/`Deref` into one.
///
/// # Exactly what each mint attests (ruling W1-R87)
///
/// **In a production build there is one constructor: [`start_session_mcp`].**
/// It is the only one that attests **spawn + discovery** — its executor's
/// `connections` come from `McpHost::start`, which builds them solely from
/// `StartedServer`s, i.e. servers where both `StdioMcpTransport::spawn` and
/// `discover()` succeeded. That is what makes
/// [`crate::SessionActor::register_mcp`]'s use of `resolved_servers()` an
/// honest input to `SealedContext.resolved_mcp_servers`.
///
/// [`SessionMcp::from_parts`] is **caller-trusted and test-gated**
/// (`#[cfg(any(test, feature = "test-util"))]`). It attests the
/// `PolicyEngine` and nothing else: its `connections` are whatever the caller
/// passed, so the server *names* in them are caller-invented. Since
/// `resolved_servers()` is just those keys, an ungated `from_parts` would let
/// a caller name any server "resolved" and thereby disarm
/// `sealed_mcp_unresolved` for the session — CF-8(b)'s bypass shape, which is
/// why production cannot reach it.
///
/// **What NEITHER mint proves** (carry-forward CF-8, unchanged): that the
/// engine's installed `sealed_ctx_provider` returns a *correct* context.
/// `check_sealed_ctx_configured` proves non-default, not correct.
#[derive(Clone)]
pub struct SessionMcp {
    executor: Arc<McpExecutor>,
}

impl SessionMcp {
    /// Builds a `SessionMcp` from caller-supplied transports and an
    /// already-built namespace — the seam this crate's own integration tests
    /// need in order to drive the MCP arm against a scripted transport while
    /// still going through a real `PolicyEngine`.
    ///
    /// # Test-gated, and why (ruling W1-R87)
    ///
    /// **This constructor attests the `PolicyEngine` and nothing else.**
    /// `connections` is whatever the caller passed; nothing on this path
    /// requires a spawn or a `discover()`. `McpExecutor::resolved_servers()`
    /// is just those connection keys, so a caller-invented server name flows
    /// through [`SessionMcp::resolved_servers`] into
    /// [`crate::SessionActor::register_mcp`] and on into
    /// `SealedContext.resolved_mcp_servers`, where it **disarms
    /// `sealed_mcp_unresolved`** for that session. That is carry-forward
    /// CF-8(b)'s bypass shape, so this is gated behind
    /// `#[cfg(any(test, feature = "test-util"))]` and production code cannot
    /// reach it — [`start_session_mcp`] is the only mint a daemon build has,
    /// and it is the only one that attests spawn + discovery.
    ///
    /// `policy` is the concrete `Arc<PolicyEngine>`, never `Arc<dyn Policy>`:
    /// that is the other half of this type's point (see its doc comment). The
    /// `McpExecutor` is constructed HERE from the parts rather than accepted
    /// pre-built, because accepting a pre-built one would let a caller hand
    /// over an executor whose policy is something else entirely while still
    /// passing a real `PolicyEngine` for show.
    #[cfg(any(test, feature = "test-util"))]
    pub fn from_parts(
        connections: Vec<(ServerId, Arc<dyn McpTransport>)>,
        namespace: ToolNamespace,
        policy: Arc<PolicyEngine>,
        task_spawner: Arc<dyn TaskSpawner>,
    ) -> Result<Self, StartSessionMcpError> {
        check_sealed_ctx_configured(&policy)?;
        Ok(SessionMcp {
            executor: Arc::new(McpExecutor::new(
                connections,
                namespace,
                policy,
                task_spawner,
            )),
        })
    }

    /// The underlying executor, for the one caller that dispatches through
    /// it ([`crate::agent_loop::run_agent_loop`]). Returning `&Arc<_>` rather
    /// than a clone keeps this a read-only borrow: a caller can dispatch and
    /// can `Arc::clone` for a spawned task, but cannot mint a `SessionMcp`
    /// around some *other* executor from it.
    pub fn executor(&self) -> &Arc<McpExecutor> {
        &self.executor
    }

    /// The servers that actually completed spawn + discovery — carry-forward
    /// CF-9's accessor, forwarded. This is the honest input
    /// [`crate::SessionActor::register_mcp`] needs for the session's own
    /// `SealedContext.resolved_mcp_servers`.
    pub fn resolved_servers(&self) -> Vec<String> {
        self.executor.resolved_servers()
    }
}
