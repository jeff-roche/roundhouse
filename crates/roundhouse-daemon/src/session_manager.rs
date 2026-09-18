//! Session lifecycle machinery shared by every caller that can construct a
//! real session — today the Unix socket handshake
//! (`socket_server::drive_session`), and, as of Phase 8 Task 4, a headless
//! caller with no connected client at all (a scheduled trigger delivery,
//! landing in a later task).
//!
//! # Why this module exists (Phase 8, Task 4)
//!
//! Before this task, `spawn_session_reaper` lived in `socket_server.rs` and
//! `session_bootstrap::create_real_session` minted its own `SessionId` and
//! hard-coded `SessionSpec { requested_tier: Tier::Sandbox, .. }` internally
//! — both fine when the only caller was a socket connection reacting to a
//! `CreateSession` handshake, but wrong for a caller that needs to decide
//! (and persist) a session's id *before* construction, with no socket
//! client to hand a subscriber channel to at all.
//!
//! This module composes the pieces `session_bootstrap`/`session_registry`
//! already exposed after Task 4's other changes
//! (`session_bootstrap::create_real_session` now takes its `SessionId`/
//! `SessionSpec` as parameters; `SessionRegistry::register_headless` starts
//! a session with zero subscribers directly) into one call,
//! [`create_headless_session`], and re-homes [`spawn_session_reaper`] here
//! verbatim so both the socket path and this one share the exact same
//! teardown-on-`Closed` logic.
//!
//! **Bounded by the same construction timeout as the socket path, but
//! deliberately not by a semaphore (fix round 3).** An earlier version of
//! this module reasoned that bounding construction at all was a socket-path
//! concern — a concurrent-client-load defense specific to a Unix socket
//! accepting arbitrarily many peers at once — and left [`create_headless_session`]
//! unbounded until a real caller existed. That reasoning held for the
//! semaphore (`construction_slots`, a defense against many peers racing
//! `CreateSession` at once — nothing here has that shape; the scheduler's
//! own `MAX_CONCURRENT_DELIVERIES` already bounds concurrent headless
//! construction from the one caller that exists), but not for the timeout:
//! [`create_headless_session`]'s only caller (`scheduler_driver`) originally
//! wrapped the whole call in `tokio::time::timeout`, which drops the losing
//! future mid-`.await` on elapse — and this function awaits repeatedly
//! *after* real resources are already live (isolation `prepare`, egress
//! registration, potentially a real `McpHost::start` subprocess spawn), so
//! every timed-out attempt orphaned whatever it had already built, forever,
//! for as long as the wedged MCP server / hung isolation probe stayed
//! wedged. [`create_headless_session`] now bounds its own construction the
//! same way `socket_server::construct_real_session_bounded` does — see its
//! own doc comment for the full mechanism.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use roundhouse_bus::spawn_tree::SpawnTree;
use roundhouse_core::{SessionId, SessionOutcome, SessionSpec, SessionState};
use roundhouse_engine::SessionActor;
use roundhouse_mcp::host::McpHost;
use roundhouse_net::proxy::LoopbackProxy;
use roundhouse_store::{CloseReceipt, StoreError};

use crate::session_bootstrap::{
    create_real_session, teardown_real_session, CreateRealSessionError, DaemonResources,
    RealSession,
};
use crate::session_registry::SessionRegistry;
use crate::sub_agent_host::SubAgentSessions;

/// Everything that can go wrong building a headless session:
/// [`create_real_session`]'s own errors, plus the one failure mode that is
/// specific to registration (the registry is already at capacity) rather
/// than to construction itself.
///
/// `Session` boxes [`CreateRealSessionError`] rather than embedding it
/// directly (`clippy::result_large_err`) — the same reason
/// `socket_server::ConstructionOutcome::Failed` already boxes this exact
/// type.
#[derive(Debug, thiserror::Error)]
pub enum CreateHeadlessSessionError {
    #[error(transparent)]
    Session(Box<CreateRealSessionError>),
    /// [`SessionRegistry::register_headless`] returned `None` — this
    /// registry is already at `max_sessions`. The real session
    /// [`create_real_session`] had already built (isolation, egress
    /// registration, and any configured MCP servers) is torn down before
    /// this error is returned; nothing is leaked.
    #[error("session registry is full; refusing to register this session")]
    RegistryFull,
    /// Fix round 3: construction (including registration and the reaper
    /// spawn) did not report an outcome within
    /// [`crate::socket_server::SESSION_CONSTRUCTION_TIMEOUT`]. Construction
    /// itself is never cancelled — it keeps running in a detached task and
    /// self-tears-down on completion instead of being leaked. See
    /// [`create_headless_session`]'s own doc comment for the full mechanism,
    /// which mirrors `socket_server::construct_real_session_bounded`.
    #[error("headless session construction did not finish within the timeout")]
    Timeout,
    /// The detached construction task ended (panicked, or was somehow
    /// dropped) without ever reporting an outcome. The same failure mode
    /// `socket_server::ConstructionOutcome::TaskEnded` names for the socket
    /// path.
    #[error("headless session construction task ended unexpectedly before reporting an outcome")]
    TaskEnded,
}

impl CreateHeadlessSessionError {
    /// A static diagnostic category, safe to render into a `tracing` field —
    /// the same discipline (and the same delegation to
    /// [`CreateRealSessionError::kind`]) the socket path already follows,
    /// because a nested config-parser error's `Display` may carry operator-
    /// or repository-supplied text.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Session(inner) => inner.kind(),
            Self::RegistryFull => "session_registry_full",
            Self::Timeout => "session_construction_timeout",
            Self::TaskEnded => "session_construction_task_ended",
        }
    }
}

/// Builds one real session end to end, exactly as
/// `socket_server::construct_real_session_bounded` does for the socket path,
/// and registers it headlessly (zero subscribers, no channel) — for a caller
/// with no connected client to hand a `Receiver` to (Phase 8, Task 4: a
/// scheduled trigger delivery, wired by Phase 8 Task 6).
///
/// Composes three calls that already exist:
/// [`create_real_session`] → [`SessionRegistry::register_headless`] →
/// [`spawn_session_reaper`], tearing down via [`teardown_real_session`] (the
/// same by-value teardown guarantee `socket_server`'s own failure paths use)
/// if registration loses the race against `max_sessions` after construction
/// has already completed — never leaving a half-constructed session or a
/// leaked isolation/MCP/proxy handle behind.
///
/// # Bounded, but never cancelled (fix round 3)
///
/// The whole composition above runs inside its own detached [`tokio::spawn`],
/// racing a [`tokio::sync::oneshot`] receiver — never the construction future
/// itself — against [`crate::socket_server::SESSION_CONSTRUCTION_TIMEOUT`],
/// exactly the shape `socket_server::construct_real_session_bounded` already
/// uses and for the identical reason: a `tokio::time::timeout` wrapped
/// directly around this work would DROP the losing future mid-`.await` on
/// elapse, and this function awaits repeatedly (isolation `prepare`, egress
/// registration, potentially a real `McpHost::start` subprocess spawn, plus
/// registration and the reaper spawn) after real resources are already live
/// — dropping it there orphans whatever it had already built. An earlier
/// version of this module reasoned that no caller needed *any* bound yet and
/// left this uncovered entirely (see this module's own doc comment); the
/// caller that exists now (`scheduler_driver`) is unattended and repeating,
/// so it originally applied `tokio::time::timeout` at its own call site —
/// reproducing exactly the defect `construct_real_session_bounded`'s doc
/// comment already explains for the socket path, once per scheduler tick for
/// as long as the wedged MCP server or hung isolation probe stayed wedged.
/// The fix is the same one `construct_real_session_bounded` already applies:
/// never cancel construction, only stop *waiting* on it, and let it
/// self-tear-down on late completion (below).
///
/// The `Duration` is reused, not re-chosen — it bounds the identical work in
/// both callers, so a second number here would be two answers to one
/// question.
///
/// **Deliberately still no semaphore.** `construct_real_session_bounded`
/// pairs its timeout with a `construction_slots` semaphore because a Unix
/// socket can have arbitrarily many peers racing `CreateSession` at once;
/// nothing about that applies here — this function's only caller
/// (`scheduler_driver`) already bounds how many deliveries (and therefore how
/// many concurrent calls into this function) can be in flight at all via its
/// own `MAX_CONCURRENT_DELIVERIES` semaphore, held for a delivery's whole
/// life. Adding a second, independent cap here would be a second answer to a
/// question `scheduler_driver` already owns.
///
/// # Late success after the caller already gave up
///
/// If construction (including registration and the reaper spawn) finishes
/// only after this function has already returned
/// [`CreateHeadlessSessionError::Timeout`] to its caller, the detached task
/// notices its `oneshot::Sender::send` failed (the receiver was dropped or
/// closed) and tears the whole [`HeadlessSession`] down via
/// [`HeadlessSession::teardown`] — the exact sequence a caller would have run
/// itself, just run here instead, so nothing is leaked: not the isolation
/// handle, not the MCP host, not the proxy registration, and not the reaper
/// task ([`HeadlessSession::teardown`] aborts it before anything else, per
/// that method's own doc comment).
///
/// # The send/drop race
///
/// Mirrors `construct_real_session_bounded`'s own such section verbatim:
/// racing `result_rx` via `select!` against a bare `sleep` (rather than
/// putting `result_rx` inside `tokio::time::timeout` directly) keeps
/// `result_rx` alive, borrowed, past the timeout arm. On elapse this
/// explicitly `close()`s the receiver first — so a `send` racing exactly that
/// instant observably fails and the detached task's own self-teardown path
/// fires normally — and only then drains `try_recv()` for a value that may
/// have already landed in the channel's slot in the narrow window before
/// `close()` ran, which `close()` alone would otherwise leave to be silently
/// dropped, unread, the instant this function returns.
pub async fn create_headless_session(
    resources: &Arc<DaemonResources>,
    registry: &Arc<SessionRegistry>,
    session_id: SessionId,
    spec: SessionSpec,
    workspace_root: PathBuf,
    workspace_device: Option<i64>,
    workspace_inode: Option<i64>,
) -> Result<HeadlessSession, CreateHeadlessSessionError> {
    let (result_tx, mut result_rx) = tokio::sync::oneshot::channel();
    let construction_resources = resources.clone();
    let construction_registry = registry.clone();
    tokio::spawn(async move {
        let outcome = build_headless_session(
            &construction_resources,
            &construction_registry,
            session_id,
            spec,
            workspace_root,
            workspace_device,
            workspace_inode,
        )
        .await;
        match outcome {
            Ok(headless) => {
                if let Err(Ok(headless)) = result_tx.send(Ok(headless)) {
                    tracing::warn!(
                        session_id = %session_id,
                        "headless session construction finished after its caller gave up on \
                         the timeout; tearing down the session it built instead of leaking it"
                    );
                    headless
                        .teardown(&construction_registry, &construction_resources.proxy)
                        .await;
                }
            }
            Err(err) => {
                // A construction/registration error either carries no real
                // resource to tear down (`create_real_session`'s own error
                // paths already do that) or has already torn its own down
                // (the `RegistryFull` path, below). Best-effort send — if
                // nobody's listening either, there is nothing further to do
                // with the error but drop it.
                let _ = result_tx.send(Err(err));
            }
        }
    });

    // See this function's own "The send/drop race" doc section: `&mut
    // result_rx` here (not moving it into `tokio::time::timeout`) is what
    // makes the post-elapse `close()`/`try_recv()` below possible at all.
    tokio::select! {
        recv = &mut result_rx => {
            match recv {
                Ok(result) => result,
                Err(_recv_error) => Err(CreateHeadlessSessionError::TaskEnded),
            }
        }
        _ = tokio::time::sleep(crate::socket_server::SESSION_CONSTRUCTION_TIMEOUT) => {
            result_rx.close();
            if let Ok(Ok(headless)) = result_rx.try_recv() {
                tracing::warn!(
                    session_id = %session_id,
                    "headless session construction finished (racing the timeout in the \
                     narrow send/drop window) after its caller already gave up; tearing \
                     down the session it built instead of leaking it"
                );
                headless.teardown(registry, &resources.proxy).await;
            }
            Err(CreateHeadlessSessionError::Timeout)
        }
    }
}

/// The actual construction-and-registration body [`create_headless_session`]
/// races against a timeout, in its own detached task — never awaited
/// directly by that function's caller. See [`create_headless_session`]'s own
/// doc comment for why this split exists.
async fn build_headless_session(
    resources: &Arc<DaemonResources>,
    registry: &Arc<SessionRegistry>,
    session_id: SessionId,
    spec: SessionSpec,
    workspace_root: PathBuf,
    workspace_device: Option<i64>,
    workspace_inode: Option<i64>,
) -> Result<HeadlessSession, CreateHeadlessSessionError> {
    let real_session = create_real_session(
        resources,
        session_id,
        spec,
        workspace_root,
        workspace_device,
        workspace_inode,
    )
    .await
    .map_err(|err| CreateHeadlessSessionError::Session(Box::new(err)))?;

    // Cloned BEFORE the actor/mcp_host/mcp move into `register_headless`
    // below, the same shape `socket_server::drive_session` uses for its own
    // "lost the race against max_sessions" teardown path and its reaper
    // spawn — both the discard-on-full path and a successful reaper spawn
    // need their own independent copies of exactly what they each use,
    // regardless of what the registry does with its own.
    let actor_for_reaper = real_session.actor.clone();
    let mcp_host_for_reaper = real_session.mcp_host.clone();
    let mcp_for_teardown = real_session.mcp.clone();
    let proxy_token_for_reaper = real_session.proxy_handle.token().to_string();
    // A third set, for the handle this function returns — the caller's
    // explicit teardown needs exactly what the reaper needs, and neither may
    // depend on the other still holding its own copy.
    let actor_for_handle = actor_for_reaper.clone();
    let mcp_host_for_handle = mcp_host_for_reaper.clone();
    let proxy_token_for_handle = proxy_token_for_reaper.clone();

    let Some(session_id) =
        registry.register_headless(real_session.actor, real_session.mcp_host, real_session.mcp)
    else {
        tracing::warn!(
            "lost the race against max_sessions after real headless session construction \
             already completed; tearing down rather than leaking the isolation handle/MCP \
             host/proxy registration"
        );
        let discarded = RealSession {
            actor: actor_for_reaper,
            mcp_host: mcp_host_for_reaper,
            mcp: mcp_for_teardown,
            proxy_handle: real_session.proxy_handle,
        };
        teardown_real_session(&resources.proxy, discarded).await;
        return Err(CreateHeadlessSessionError::RegistryFull);
    };

    // Phase 8 Task 25.5 (#62): a headless session is a ROOT session in the
    // spawn-tree sense — the scheduler mints it directly, not another
    // session's `agent` tool call — the same fact `socket_server::
    // drive_session`'s identical call already documents for a socket client.
    // Without this, a workflow's `agent:` step could never spawn a child:
    // `SessionActor::sub_agent_host()` would stay `None` for every headless
    // session, and `dispatch_agent`/`dispatch_agent_for_workflow` refuse with
    // `sub_agent_host_unavailable` when it is.
    crate::sub_agent_host::wire_sub_agent_host(&actor_for_reaper, resources, registry);

    // Shared with the reaper below and carried on the returned
    // `HeadlessSession` (Phase 8, T19a Task 6): this is what makes
    // "exactly one real teardown" structural regardless of which of
    // the two independent routes — this reaper, or whatever this function's
    // caller eventually does with the handle it gets back — observes
    // `Closed` first. See `HeadlessSession::finish_teardown`'s own doc
    // comment.
    let torn_down = Arc::new(AtomicBool::new(false));

    let reaper = spawn_session_reaper(
        registry.clone(),
        session_id,
        actor_for_reaper,
        mcp_host_for_reaper,
        resources.proxy.clone(),
        proxy_token_for_reaper,
        ReapAction::Teardown,
        Arc::clone(&torn_down),
    );

    Ok(HeadlessSession {
        session_id,
        actor: actor_for_handle,
        mcp_host: mcp_host_for_handle,
        proxy_token: proxy_token_for_handle,
        reaper,
        torn_down,
    })
}

/// How long [`HeadlessSession::close_and_teardown`] waits for
/// [`SessionActor::close`] before abandoning it and tearing this session
/// down anyway (Phase 8, T19a Task 5). `SessionActor::close`'s own doc
/// comment is explicit that its `wait_idle` step has no timeout of its own
/// and that a caller needing a bound must apply one itself — this is that
/// bound. Chosen in the same tens-of-seconds range as
/// [`crate::socket_server::SESSION_CONSTRUCTION_TIMEOUT`] (30s) for the same
/// kind of reason: long enough that a legitimate in-flight shell or provider
/// call's own SIGTERM→SIGKILL-then-confirm cancellation sequence has room to
/// unwind normally, short enough that a genuinely wedged close (an
/// unreleased `WorkGuard`, per `close`'s own doc comment) does not block
/// whatever caller is waiting on `close_and_teardown` — a socket connection
/// answering a client's close request among them — indefinitely.
///
/// # This is the OUTERMOST bound of a cascade, not the bound of one session (Phase 8, T19a Task 6)
///
/// Chosen back when [`SessionActor::close`]'s step 4
/// (`sub_agent_host().close_children`) was a no-op default, so this
/// constant bounded exactly the ONE session's own `close()` call it
/// wrapped. That is no longer true for a session with tracked sub-agent
/// children: `close_and_teardown`'s `tokio::time::timeout` wraps
/// `actor.close(outcome)`, and step 4 of THAT call recurses — through
/// `DaemonSubAgentHost::close_children` → `SubAgentSessions::retire_child`
/// → each child's own `close_and_teardown` — into a second, nested
/// `tokio::time::timeout` per child, running entirely inside the first.
///
/// **Nested closes therefore do NOT use this constant.** They use
/// [`nested_close_timeout`], which is strictly smaller and shrinks with
/// tracked depth, precisely so the innermost bound is always the first one
/// to fire. Giving every level the same 30s would make the nested timers
/// dead code: an enclosing timeout created at `t` has deadline `t + 30s`,
/// while a nested one created at `t + ε` (after the enclosing close's
/// `cancel`, `wait_idle` and `children_of` snapshot) has deadline
/// `t + 30s + ε`, so the enclosing timeout always wins and DROPS the nested
/// timer before it can fire. That inverts the severity ordering that makes
/// this bound useful at all: one permanently wedged descendant (the
/// unreleased-`WorkGuard` case) would not be caught at its own level, and
/// instead of "the wedged child is abandoned, its ancestors still write
/// their terminators" the whole cascade would be abandoned at the root —
/// on the socket path, with no forced teardown behind it, retaining the
/// root's isolate, MCP host, registry entry and proxy token for the
/// daemon's life.
///
/// **What 30s actually promises, and what it does not.** It promises that
/// ONE session's own close (a leaf, or a root with no tracked children)
/// cannot block its caller longer than this, and that a root's cascade
/// cannot either. It does **not** promise the whole cascade fits: only
/// designed-in grace periods already make an ordinary serial cascade
/// expensive. Each child's [`HeadlessSession::finish_teardown`] awaits
/// [`McpHost::shutdown`], which walks its stdio transports serially at
/// `roundhouse_mcp`'s own `GRACEFUL_EXIT_TIMEOUT` (3s) per server, and a
/// child holding a SIGTERM-ignoring shell costs about 5.5s inside
/// `roundhouse_sandbox`'s `Child::cancel` (a 5s SIGTERM grace, then up to
/// 25 × 20ms of `wait_for_empty_group` confirmation). Eight direct children
/// with MCP hosts is therefore already around 24s of ordinary, non-wedged
/// serial work inside a 30s budget — and §7.7's `MAX_DEPTH` × `MAX_FAN_OUT`
/// permits thousands of descendants. A cascade over a large tree WILL be
/// abandoned at this bound. What [`nested_close_timeout`]'s per-level step
/// buys is room for only ONE abandoned session per level, not the whole
/// level: the first wedged session encountered along a chain is abandoned
/// at its own level, where its `close_and_teardown` still runs
/// `finish_teardown` — but a later sibling at that same level, or a chain
/// whose earlier steps already spent the slack, is instead dropped by the
/// enclosing bound with no teardown for that descendant. Still a real
/// improvement over giving every level the same bound, which stranded all
/// of them this way.
pub(crate) const SESSION_CLOSE_TIMEOUT: Duration = Duration::from_secs(30);

/// How much smaller each tracked level's close budget is than the level
/// above it (Phase 8, T19a Task 6). See [`nested_close_timeout`].
const NESTED_CLOSE_TIMEOUT_STEP: Duration = Duration::from_secs(5);

/// The floor [`nested_close_timeout`] never returns less than: enough for
/// one child's own designed-in grace periods (`Child::cancel`'s ~5.5s plus
/// an `McpHost::shutdown` walk) to unwind rather than being cut off
/// mid-SIGTERM. Reached exactly at §7.7's `MAX_DEPTH`, so no legitimate
/// tracked depth is ever clamped to it from further down.
const MIN_NESTED_CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

/// The close budget for a tracked sub-agent child at `depth`, applied by
/// `SubAgentSessions`' own retirement path instead of
/// [`SESSION_CLOSE_TIMEOUT`] (Phase 8, T19a Task 6).
///
/// Strictly decreasing in `depth` across §7.7's legitimate range (1 through
/// `MAX_DEPTH` = 4, giving 25s/20s/15s/10s against the root's 30s), which is
/// the whole point: a nested `tokio::time::timeout` is created strictly
/// later than the one enclosing it, so it can only ever fire first if its
/// bound is strictly smaller. With that ordering, a wedged descendant is
/// abandoned at ITS own level — where `close_and_teardown` still runs
/// `finish_teardown` and its ancestors still go on to write their own
/// terminators — instead of stranding the whole cascade at the root.
///
/// A tracked child's depth is `parent depth + 1`, so `depth` is never 0
/// here (`LiveSubAgent::depth`, set by `DaemonSubAgentHost::
/// create_child_session` from what §7.7 admitted the child at); a root
/// session is not tracked in `SubAgentSessions` at all and keeps
/// `SESSION_CLOSE_TIMEOUT`. Depths past `MAX_DEPTH` cannot be admitted, and
/// clamp at [`MIN_NESTED_CLOSE_TIMEOUT`] rather than reaching zero.
pub(crate) fn nested_close_timeout(depth: u8) -> Duration {
    let shrink = NESTED_CLOSE_TIMEOUT_STEP.saturating_mul(u32::from(depth));
    let budget = SESSION_CLOSE_TIMEOUT.saturating_sub(shrink);
    if budget < MIN_NESTED_CLOSE_TIMEOUT {
        MIN_NESTED_CLOSE_TIMEOUT
    } else {
        budget
    }
}

/// Everything [`HeadlessSession::close_and_teardown`] can fail with — either
/// [`SessionActor::close`]'s own [`StoreError`], or that call being
/// abandoned after the close budget it was given elapses. Both are logged at
/// error level by `close_and_teardown` itself before being returned; this
/// type exists so a caller that needs to report the failure onward (a
/// socket connection answering its own client, for one) has something
/// concrete to report.
#[derive(Debug, thiserror::Error)]
pub enum CloseAndTeardownError {
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Carries the budget that actually elapsed, which is
    /// `SESSION_CLOSE_TIMEOUT` for a root close and
    /// `nested_close_timeout`'s smaller, depth-derived value for a tracked
    /// child retired inside a cascade.
    #[error("closing this session did not finish within {0:?}")]
    Timeout(Duration),
}

/// A live headless session, plus everything needed to retire it.
///
/// # Why a headless caller has to retire its own session (Phase 8, Task 6)
///
/// [`spawn_session_reaper`] tears a session down when its actor reaches
/// `SessionState::Closed` — and **nothing in this workspace drives a
/// HEADLESS session's actor there on its own** (see that function's own doc
/// comment: [`SessionActor::close`] exists, but nothing calls it
/// unprompted). For the socket path that is merely latent: a session lives
/// as long as the daemon and there is one per connected client. For a
/// *scheduled* session it is fatal, because
/// the scheduler mints one per delivery: at one delivery a minute a daemon
/// reaches `SessionRegistry`'s `DEFAULT_MAX_SESSIONS` (10,000) in about a
/// week, after which every further delivery fails `RegistryFull` — with ten
/// thousand real isolation handles still held.
///
/// So a headless caller gets this handle and calls [`Self::teardown`] itself
/// the moment its work reaches a terminal outcome, rather than waiting for an
/// event that will never arrive. That is a caller obligation, not an
/// automatic behaviour: a caller whose work is *not* finished — a workflow
/// run parked on a human gate — must keep the session alive, and only the
/// caller knows which it is.
pub struct HeadlessSession {
    session_id: SessionId,
    actor: Arc<SessionActor>,
    mcp_host: Option<Arc<McpHost>>,
    proxy_token: String,
    reaper: tokio::task::JoinHandle<()>,
    /// Claimed exactly once, by whichever of this session's teardown routes
    /// gets there first (Phase 8, T19a Task 6) — see
    /// [`Self::finish_teardown`]'s own doc comment.
    torn_down: Arc<AtomicBool>,
}

impl HeadlessSession {
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// The live `SessionActor` behind this handle — Phase 8 Task 25.3 needs
    /// it to dispatch a workflow run's `tool:`/`agent:` steps for real
    /// (`roundhouse_engine::workflow_dispatch::dispatch_tool_for_workflow`
    /// takes `&SessionActor`, not a `HeadlessSession`), the same accessor
    /// shape `roundhouse-engine`'s own `run_agent_loop` gets via its
    /// `actor: &SessionActor` parameter.
    pub(crate) fn actor(&self) -> &Arc<SessionActor> {
        &self.actor
    }

    /// The egress-proxy bearer token this session was registered under.
    /// Test-only, and only so a test can assert [`Self::teardown`] really
    /// deregisters it — nothing in production needs to read it back, because
    /// `teardown` is the one thing that uses it.
    #[cfg(test)]
    pub(crate) fn proxy_token_for_test(&self) -> &str {
        &self.proxy_token
    }

    /// Retires this session: the exact sequence [`spawn_session_reaper`]
    /// performs on `Closed`, run explicitly instead of on an event that never
    /// comes.
    ///
    /// # The reaper is aborted first, and that ordering is load-bearing
    ///
    /// `SessionActor::teardown`'s own doc says callers "should call this at
    /// most once per actor" — `Isolate::teardown` is not guaranteed
    /// idempotent. Aborting the reaper before tearing down makes "exactly one
    /// teardown" structural rather than relying on the reaper never firing.
    ///
    /// **Aborting is also the only thing that retires that task.** Verified
    /// against the real types rather than assumed: `SessionActor::teardown`
    /// releases the isolation handle and never touches `state_tx`, so the
    /// reaper's `state.changed()` neither resolves (no state transition) nor
    /// errors (the sender lives inside the actor, and the reaper holds its
    /// own `Arc` of it). Tearing a session down out from under the reaper is
    /// therefore safe — no panic and no race, because the reaper simply never
    /// wakes — but it would stay parked for the process's life holding that
    /// `Arc`, which at one session per delivery is a slow leak of exactly the
    /// kind this handle exists to stop. `abort()` on a task parked at an
    /// await point drops it there, releasing the `Arc`.
    pub async fn teardown(self, registry: &SessionRegistry, proxy: &LoopbackProxy) {
        self.reaper.abort();
        self.finish_teardown(registry, proxy).await;
    }

    /// The reaper-safe counterpart to [`Self::teardown`] (Phase 8, T19a Task
    /// 5): the identical resource teardown, except it never aborts this
    /// session's own reaper — it just lets `self` (and therefore
    /// `self.reaper`'s `JoinHandle`) drop normally at the end of the call.
    ///
    /// [`Self::teardown`] and [`Self::close_and_teardown`] both call
    /// `self.reaper.abort()` because whatever calls them runs on some OTHER
    /// task than the reaper's own. [`spawn_session_reaper`]'s
    /// `RetireSubAgent` reap action calls THIS method instead, from inside
    /// the very reaper task whose `JoinHandle` this `HeadlessSession` holds
    /// — `abort()`ing there would cancel the task currently executing this
    /// call at its next await point, truncating whatever teardown steps
    /// below had not yet run. Dropping the handle instead detaches the task
    /// without cancelling it, which is exactly right here: the reaper has
    /// already reached its terminal branch and is on its own way to
    /// returning regardless.
    async fn teardown_from_reaper(self, registry: &SessionRegistry, proxy: &LoopbackProxy) {
        self.finish_teardown(registry, proxy).await;
    }

    /// Replaces this session's reaper with one running a different
    /// [`ReapAction`] (Phase 8, T19a Task 6).
    ///
    /// `DaemonSubAgentHost::create_child_session` is the one caller: every
    /// session [`create_headless_session`] builds — sub-agent children
    /// included — starts with a [`ReapAction::Teardown`] reaper, because
    /// [`create_headless_session`] itself knows nothing about
    /// `SubAgentSessions`. Once (and only once) that caller has recorded the
    /// child in `SubAgentSessions`, it calls this to swap in a
    /// [`ReapAction::RetireSubAgent`] reaper instead — never earlier, or the
    /// replacement could observe `Closed` and reap before there is a
    /// `SubAgentSessions` record for `SubAgentSessions::take_for_reap` to
    /// find, which would silently do nothing and leak the child.
    ///
    /// Aborts the old reaper before spawning the new one, for the same
    /// "exactly one teardown" reason [`Self::teardown`]'s doc comment gives:
    /// leaving both running would let either observe `Closed` and race the
    /// other to retire this session.
    pub(crate) fn rewire_reaper(
        &mut self,
        registry: Arc<SessionRegistry>,
        proxy: Arc<LoopbackProxy>,
        action: ReapAction,
    ) {
        self.reaper.abort();
        self.reaper = spawn_session_reaper(
            registry,
            self.session_id,
            self.actor.clone(),
            self.mcp_host.clone(),
            proxy,
            self.proxy_token.clone(),
            action,
            // The SAME flag this session was constructed with, not a fresh
            // one — see `finish_teardown`'s own doc comment for why reusing
            // it is what makes "exactly one real teardown" hold across the
            // reaper this rewires away from as well as the one it rewires
            // to.
            Arc::clone(&self.torn_down),
        );
    }

    /// Explicitly closes this session through the real, ordered
    /// [`SessionActor::close`] path — bounded by [`SESSION_CLOSE_TIMEOUT`],
    /// since `close`'s own doc comment is explicit that its `wait_idle` step
    /// has no timeout of its own — and then tears the session down
    /// regardless of whether that close succeeded (Phase 8, T19a Task 5) —
    /// the sequence a caller with a connected client (a socket connection
    /// reacting to that client's own close request, among others) drives,
    /// as opposed to a reaper merely reacting to a `Closed` it happened to
    /// observe.
    ///
    /// This is the OUTERMOST form, for a session nothing else's close is
    /// waiting on. A tracked sub-agent child retired from inside an
    /// ancestor's cascade goes through [`Self::close_and_teardown_within`]
    /// with [`nested_close_timeout`]'s smaller, depth-derived budget
    /// instead, so the inner bound fires before the outer one can drop it.
    ///
    /// 1. Abort the reaper. This call is about to durably close and tear the
    ///    session down itself, so the reaper's own redundant reap of the
    ///    same `Closed` transition must never run concurrently with it —
    ///    and, per [`Self::teardown`]'s own doc comment, `abort()` is what
    ///    actually retires that task rather than leaking it. This runs
    ///    BEFORE `close()`, never after: reordering it would reopen exactly
    ///    that window.
    /// 2. [`SessionActor::close`], wrapped in this call's own close budget. A
    ///    failure — a durable store error, or the timeout elapsing — is
    ///    logged at error level and returned to the caller, never panicked
    ///    on: this method's caller decides whether/how to report it onward
    ///    (a socket connection answering its own client, for one).
    /// 3. Tear the session's real resources down regardless of step 2's
    ///    outcome. A `close()` that failed OR was abandoned on timeout
    ///    leaves the actor `Cancelling`, never `Closed` (see `close`'s own
    ///    doc comment) — but it still holds a real isolation handle, MCP
    ///    host and egress token that must not be leaked just because its
    ///    terminator failed to append.
    ///
    /// # An abandoned close may leave the event log without its terminator
    ///
    /// `tokio::time::timeout` DROPS the `close()` call's future on elapse —
    /// this method does not wait for whatever `close()` had in flight to
    /// unwind, it walks away from it. Whatever step `close()` had reached
    /// keeps running independently for as long as its own machinery (e.g. a
    /// writer task blocked on a slow disk) keeps it alive, but nothing here
    /// observes how — or whether — it eventually finishes. If it never
    /// durably appends `SessionClosed`, this session's event log simply ends
    /// without a terminator; the error-level log line this path emits is the
    /// only signal that happened, not a promise that it didn't.
    ///
    /// # Must never be called from inside this session's own reaper task, or from inside this session's own work
    ///
    /// Step 1's `abort()` targets the reaper task; calling this method from
    /// inside it would self-abort the very call in progress. The reaper's
    /// own path is [`Self::teardown_from_reaper`], never this method.
    /// Separately — carried over from [`SessionActor::close`]'s own doc
    /// comment — this session's own `run_agent_loop` (or anything else
    /// holding a `WorkGuard` for it) must never call this method either:
    /// step 2's `wait_idle` would then be waiting on the very guard doing
    /// the waiting, a structural deadlock that [`SESSION_CLOSE_TIMEOUT`]
    /// merely delays rather than prevents — the call would still eventually
    /// report a timeout, but only after burning the full bound for no
    /// reason.
    pub async fn close_and_teardown(
        self,
        outcome: SessionOutcome,
        registry: &SessionRegistry,
        proxy: &LoopbackProxy,
    ) -> Result<CloseReceipt, CloseAndTeardownError> {
        self.close_and_teardown_within(SESSION_CLOSE_TIMEOUT, outcome, registry, proxy)
            .await
    }

    /// [`Self::close_and_teardown`] with an explicit close budget, for a
    /// caller whose close is itself running inside someone else's
    /// (Phase 8, T19a Task 6).
    ///
    /// `budget` MUST be strictly smaller than the bound of every timeout
    /// this call runs inside, or this one is dead code: `tokio::time::
    /// timeout` fixes its deadline when it is created, and a nested timeout
    /// is always created later than the one enclosing it, so an equal bound
    /// always yields the later deadline and is dropped before it can fire.
    /// [`nested_close_timeout`] is what the one production caller —
    /// `SubAgentSessions`' retirement path, driven by
    /// `DaemonSubAgentHost::close_children` — derives that budget from, and
    /// [`SESSION_CLOSE_TIMEOUT`]'s own doc comment carries the full
    /// accounting of what the resulting ordering does and does not promise.
    pub(crate) async fn close_and_teardown_within(
        self,
        budget: Duration,
        outcome: SessionOutcome,
        registry: &SessionRegistry,
        proxy: &LoopbackProxy,
    ) -> Result<CloseReceipt, CloseAndTeardownError> {
        self.reaper.abort();
        let outcome_result = match tokio::time::timeout(budget, self.actor.close(outcome)).await {
            Ok(Ok(receipt)) => Ok(receipt),
            Ok(Err(err)) => {
                tracing::error!(
                    session_id = %self.session_id,
                    error = %err,
                    "failed to durably close this session; tearing it down anyway"
                );
                Err(CloseAndTeardownError::Store(err))
            }
            Err(_elapsed) => {
                tracing::error!(
                    session_id = %self.session_id,
                    timeout = ?budget,
                    "closing this session did not finish within the timeout; tearing it down \
                     anyway — its event log may be left without a SessionClosed terminator"
                );
                Err(CloseAndTeardownError::Timeout(budget))
            }
        };
        self.finish_teardown(registry, proxy).await;
        outcome_result
    }

    /// The resource-teardown tail shared by [`Self::teardown`],
    /// [`Self::teardown_from_reaper`] and [`Self::close_and_teardown`]:
    /// registry bookkeeping, the real isolation handle, any MCP host, and
    /// the egress-proxy token. Deciding what happens to the reaper's own
    /// `JoinHandle` is each caller's own concern, not this one's — see
    /// their own doc comments for why they differ.
    ///
    /// # Exactly one real teardown, however many routes reach this session (Phase 8, T19a Task 6)
    ///
    /// This session can be torn down by more than one independent route at
    /// once: this handle's own owner calling [`Self::teardown`]/
    /// [`Self::close_and_teardown`] is one, and — until this task's reaper
    /// is rewired away from it — the plain [`ReapAction::Teardown`] reaper
    /// [`create_headless_session`] always starts a session with is another,
    /// racing on the SAME `Closed` transition with its own independent
    /// copies of the registry/actor/proxy handles (its `ReapAction::Teardown`
    /// arm does not go through a `HeadlessSession` at all). Ordering
    /// (`DaemonSubAgentHost::create_child_session` rewiring the reaper only
    /// after `SubAgentSessions::insert`) narrows *when* that race is even
    /// possible, but does not make it impossible on its own — the ordering
    /// says nothing about a reaper that was ALREADY armed and watching
    /// before the rewiring race even starts.
    ///
    /// `self.torn_down` is what actually makes it structural:
    /// [`claim_teardown`] lets exactly one caller — whichever of this
    /// method or `spawn_session_reaper`'s `ReapAction::Teardown` arm gets
    /// there first, sharing the SAME flag (see [`build_headless_session`]
    /// and [`Self::rewire_reaper`]) — past this guard. Every later caller,
    /// on any route, returns immediately: no double
    /// [`SessionActor::teardown`] (not guaranteed idempotent), no double MCP
    /// shutdown, no double proxy deregistration. A `ReapAction::RetireSubAgent`
    /// reaper that loses this race still runs its OWN bookkeeping
    /// (`SubAgentSessions::take_for_reap`, `SpawnTree::remove_child`) before
    /// reaching this method — those are unconditional, so a session that
    /// lost the flag race here is still fully un-tracked, just not
    /// re-torn-down.
    ///
    /// # The claimed body must also RUN to completion, not just be claimed
    ///
    /// The flag alone only made teardown exactly-one-CLAIM. Everything after
    /// it used to run inline on the caller's own future, and this method is
    /// reached from places where that future can be dropped underneath it:
    /// [`Self::close_and_teardown`]'s own call to this runs after its inner
    /// timeout, but a session being retired inside an ancestor's cascade is
    /// still inside THAT ancestor's `tokio::time::timeout`, whose elapse
    /// drops the whole nested future — awaits included. A drop landing
    /// between the claim and the end of the body left `torn_down` reading
    /// "done" over a half-unwound isolate, MCP children never shut down and
    /// a still-valid session bearer token registered with
    /// [`LoopbackProxy`]; every other route short-circuits on the claimed
    /// flag, so nothing ever retried it.
    ///
    /// [`release_claimed_resources`] is what closes that: the two
    /// synchronous revocations run before anything can yield, and the two
    /// awaits run in a detached `tokio::spawn` whose `JoinHandle` this call
    /// merely awaits. Dropping this future drops the handle, which does not
    /// cancel the task, so the claim stays true regardless of when the drop
    /// lands. The ordering guarantee this gives up in exchange is that
    /// callers no longer see the isolate torn down synchronously with their
    /// own return if they were dropped — which is exactly the case where
    /// they no longer exist to observe it.
    async fn finish_teardown(&self, registry: &SessionRegistry, proxy: &LoopbackProxy) {
        if !claim_teardown(&self.torn_down) {
            tracing::debug!(
                session_id = %self.session_id,
                "skipping this session's real resource teardown; another route already claimed \
                 it"
            );
            return;
        }
        release_claimed_resources(
            self.session_id,
            registry,
            &self.actor,
            self.mcp_host.as_ref(),
            proxy,
            &self.proxy_token,
        )
        .await;
    }
}

/// Releases one session's real resources once a caller has won
/// [`claim_teardown`]: the registry entry, the egress-proxy token, the real
/// isolation handle and any MCP host (Phase 8, T19a Task 6).
///
/// # Uncancellable by construction
///
/// Both of this session's claiming routes — [`HeadlessSession::
/// finish_teardown`] and `spawn_session_reaper`'s [`ReapAction::Teardown`]
/// arm — can have their future dropped mid-body: the first by an ancestor's
/// close timeout elapsing around a cascade this session is inside of, the
/// second by the `reaper.abort()` [`HeadlessSession::close_and_teardown`]
/// and [`HeadlessSession::teardown`] both run. A drop landing between the
/// claim and the last line would leave the flag claiming a teardown that
/// never happened, and since every other route short-circuits on that flag,
/// nothing would retry it.
///
/// So the body cannot live on the caller's future. The two synchronous
/// revocations run first, before this function can yield at all — and
/// revoking egress before unwinding isolation rather than after is the
/// fail-closed order anyway, since a session whose teardown has started
/// should not still be able to reach the network through a live token. The
/// two awaits then run inside `tokio::spawn`: dropping a `JoinHandle`
/// detaches its task rather than cancelling it, so awaiting the handle here
/// keeps an ordinary caller's "teardown finished when this returned"
/// guarantee while a dropped caller still leaves the work running to
/// completion.
async fn release_claimed_resources(
    session_id: SessionId,
    registry: &SessionRegistry,
    actor: &Arc<SessionActor>,
    mcp_host: Option<&Arc<McpHost>>,
    proxy: &LoopbackProxy,
    proxy_token: &str,
) {
    registry.remove(session_id);
    proxy.deregister_session(proxy_token);

    let actor = Arc::clone(actor);
    let mcp_host = mcp_host.cloned();
    let unwinding = tokio::spawn(async move {
        actor.teardown().await;
        if let Some(host) = mcp_host {
            if let Err(err) = host.shutdown().await {
                tracing::warn!(
                    session_id = %session_id,
                    error = %err,
                    "failed to shut down this session's MCP host"
                );
            }
        }
    });
    if let Err(err) = unwinding.await {
        // Nothing in this crate aborts this handle, so in ordinary
        // operation this is a panic inside the teardown itself. A
        // `JoinError` reporting `is_cancelled()` instead would mean the
        // runtime itself shut down while this task was still running, not
        // a panic — logged the same way here either way.
        tracing::error!(
            session_id = %session_id,
            error = %err,
            "this session's real resource teardown panicked; its isolation handle and any MCP \
             children may be left behind"
        );
    }
}

/// Claims the right to run one session's real resource teardown: `true` only
/// for the first caller to observe `flag` false, atomically marking it done
/// for every caller after that (Phase 8, T19a Task 6). Shared by
/// [`HeadlessSession::finish_teardown`] and `spawn_session_reaper`'s
/// [`ReapAction::Teardown`] arm — the one teardown path that tears real
/// resources down without going through a `HeadlessSession` at all — so
/// "exactly one `Isolate::teardown` per session" holds regardless of which
/// of a session's independent teardown routes gets there first.
fn claim_teardown(flag: &AtomicBool) -> bool {
    !flag.swap(true, Ordering::SeqCst)
}

/// What [`spawn_session_reaper`] does with a session once it observes that
/// session's actor reach `SessionState::Closed` (Phase 8, T19a Task 5).
///
/// A plain headless root session and a tracked sub-agent child need
/// different endings: a root session's reaper is the sole owner of retiring
/// it ([`Self::Teardown`]), but a child tracked in [`SubAgentSessions`] also
/// has a `SpawnTree` edge and a `SubAgentSessions` record that must end
/// alongside it — ending only the session and leaving those behind would
/// hold one of the parent's §7.7 fan-out slots forever.
///
/// `DaemonSubAgentHost::create_child_session` (Phase 8, T19a Task 6) is this
/// variant's production caller: every sub-agent child starts with
/// [`Self::Teardown`] (via [`create_headless_session`], which knows nothing
/// about `SubAgentSessions`) and is rewired to this one — via
/// [`HeadlessSession::rewire_reaper`] — the moment, and never before, it is
/// actually findable in [`SubAgentSessions`]
/// ([`HeadlessSession::rewire_reaper`]'s own doc comment explains why the
/// ordering matters: a `RetireSubAgent` reaper that could observe `Closed`
/// before that record exists would reap nothing and leak the session).
///
/// `pub(crate)` rather than `pub`: nothing outside this crate constructs a
/// `ReapAction` at all, and every caller of `spawn_session_reaper` lives in
/// `roundhouse-daemon`.
pub(crate) enum ReapAction {
    /// Tear this session's own tracked resources down directly: the registry
    /// entry, the real isolation handle, any MCP host, and the egress-proxy
    /// token. What every headless root session's reaper does today.
    Teardown,
    /// This session is a tracked sub-agent child: retiring it ends its
    /// `SubAgentSessions` record and drops its parent's `SpawnTree` edge,
    /// then tears its own resources down via
    /// [`HeadlessSession::teardown_from_reaper`] — never
    /// [`HeadlessSession::teardown`] or [`HeadlessSession::close_and_teardown`],
    /// both of which abort the reaper task that IS the caller here.
    RetireSubAgent {
        sub_agents: Arc<SubAgentSessions>,
        tree: Arc<SpawnTree>,
    },
}

/// The "do-reap-when-the-actor-ends" half of ruling W1-R51 (fix round 1,
/// ruling W1-R99): watches `session_id`'s own `SessionState` for its
/// terminal `Closed` value and calls [`SessionRegistry::remove`] the moment
/// it's observed.
///
/// Spawned once per successfully created session, independent of any one
/// connection's lifetime — it must keep running after the connection that
/// called `CreateSession` (and `drive_session` itself) has returned, since a
/// session's actor can outlive every connection that ever touched it (that
/// is the entire point of `SessionEntry`'s "entry lifetime = actor
/// lifetime" rule this reaper closes the other half of). Relocated here
/// verbatim from `socket_server.rs` (Phase 8, Task 4) so a headless session
/// (no connection at all) is torn down by the exact same mechanism.
///
/// `SessionActor::close` (Phase 8, T19a Task 4) is the one production path
/// that ever drives an actor to `SessionState::Closed` today; before it
/// existed this loop simply never observed that value and sat parked on
/// `state.changed()` for the daemon's whole life, exactly as inert as
/// `remove`'s previous zero-caller state was loud about being unwired. The
/// mechanism itself has been real and wired at every call site that creates
/// a session since this reaper was written, so no further wiring was needed
/// once a real terminal transition existed to observe.
///
/// **Returns the task's `JoinHandle` (Phase 8, Task 6).** A caller that
/// retires its session explicitly — [`HeadlessSession::teardown`] or
/// [`HeadlessSession::close_and_teardown`], because a scheduled run cannot
/// afford to wait for a `Closed` this reaper alone would never even be asked
/// to produce — needs to abort this task rather than leave it parked forever
/// holding an `Arc<SessionActor>`. The socket path ignores the handle, which
/// is exactly the previous behaviour.
///
/// `action` (Phase 8, T19a Task 5) picks what happens once `Closed` is
/// observed — see [`ReapAction`]'s own doc comment for why a plain headless
/// root session and a tracked sub-agent child need different endings.
///
/// `torn_down` (Phase 8, T19a Task 6) is the SAME flag the
/// `HeadlessSession` for this exact session carries — see
/// [`HeadlessSession::finish_teardown`]'s own doc comment for why a shared
/// flag, not spawn-then-rewire ordering alone, is what makes this reap
/// action's own real-resource-teardown work ([`ReapAction::Teardown`]'s arm)
/// safe to race against that handle's independent teardown routes.
pub(crate) fn spawn_session_reaper(
    registry: Arc<SessionRegistry>,
    session_id: SessionId,
    actor: Arc<SessionActor>,
    mcp_host: Option<Arc<McpHost>>,
    proxy: Arc<LoopbackProxy>,
    proxy_token: String,
    action: ReapAction,
    torn_down: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    let mut state = actor.subscribe();
    tokio::spawn(async move {
        loop {
            if *state.borrow() == SessionState::Closed {
                match action {
                    ReapAction::Teardown => {
                        if !claim_teardown(&torn_down) {
                            // Another route (this session's own handle
                            // calling `teardown`/`close_and_teardown`, most
                            // likely) already claimed the real teardown —
                            // see `finish_teardown`'s own doc comment.
                            tracing::debug!(
                                session_id = %session_id,
                                "skipping this session's real resource teardown; another route \
                                 already claimed it"
                            );
                            return;
                        }
                        // Clears the registry's own bookkeeping and revokes
                        // egress first, then tears down the REAL resources
                        // behind them (a real bwrap isolation handle, real
                        // MCP child processes) — clearing bookkeeping alone
                        // would leave those leaked. Shared with
                        // `HeadlessSession::finish_teardown` precisely
                        // because this task is abortable: see
                        // `release_claimed_resources`'s own doc comment for
                        // why a claimed teardown must not live on a
                        // cancellable future.
                        release_claimed_resources(
                            session_id,
                            &registry,
                            &actor,
                            mcp_host.as_ref(),
                            &proxy,
                            &proxy_token,
                        )
                        .await;
                    }
                    ReapAction::RetireSubAgent { sub_agents, tree } => {
                        // Idempotent: a second reap of the same child (there
                        // should never be one, but `take_for_reap` costs
                        // nothing to make safe regardless) finds no record
                        // and does nothing further.
                        if let Some((parent, headless)) = sub_agents.take_for_reap(session_id) {
                            tree.remove_child(parent, session_id);
                            // Never `headless.teardown()`/`close_and_teardown()`
                            // here — both abort the reaper task, which IS the
                            // task currently executing this call. See
                            // `teardown_from_reaper`'s own doc comment.
                            headless.teardown_from_reaper(&registry, &proxy).await;
                        }
                    }
                }
                return;
            }
            if state.changed().await.is_err() {
                // The actor's own `state_tx` sender has been dropped — the
                // actor itself is gone. If that happened through some other
                // path than reaching `Closed`, there is nothing meaningful
                // left to watch; just stop.
                return;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    //! End-to-end proof for [`create_headless_session`] (Phase 8, Task 4):
    //! zero subscribers on the resulting `SessionEntry`, the session is
    //! retrievable via `registry.actor`, and — via
    //! `register_headless_session_is_reaped_once_its_actor_is_closed` below
    //! — the relocated `spawn_session_reaper` still tears down a
    //! headlessly-registered session when its actor reaches
    //! `SessionState::Closed`. This also
    //! exercises `SessionRegistry::register_headless` — its only production
    //! call site is `create_headless_session`, so a regression in either
    //! would only be caught here.
    //!
    //! # Why the reaper test does not go through `create_headless_session`
    //! itself
    //!
    //! `create_real_session` (which `create_headless_session` calls) always
    //! constructs its actor with `SessionState::Running`, and nothing in
    //! this crate closes a headless session it just built until the caller
    //! decides to (there is no scripted end-to-end flow that would call
    //! `SessionActor::close` on one within this module's own tests). So
    //! `register_headless_session_is_reaped_once_its_actor_is_closed` below
    //! builds its actor directly via `real_actor_with_state` and drives a
    //! real `close()` on it itself, through `register_headless` instead of
    //! `create` — proving the SAME relocated reaper function correctly
    //! tears down a session that started life in the registry with zero
    //! subscribers, which is exactly what `create_headless_session` composes
    //! it with.

    use super::*;
    use crate::test_support::{daemon_resources, real_actor_with_state, runner};
    use roundhouse_core::{OnDegrade, Tier, WorkspaceId};
    use roundhouse_net::policy::EgressPolicy;
    use roundhouse_sandbox::{
        Attestation, Child, CommandSpec, Handle, Isolate, IsolationError, ProbeResult,
    };
    use roundhouse_store::spawn_writer;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// The shared `DaemonResources` fixture, with no workspace registry —
    /// this module's tests pass a workspace root directly and never resolve
    /// one by name or id. `Arc`-wrapped because [`create_headless_session`]
    /// (fix round 3) clones it into its own detached construction task,
    /// exactly like its only production caller (`scheduler_driver`) already
    /// holds it.
    async fn resources(dir: &std::path::Path) -> Arc<DaemonResources> {
        Arc::new(daemon_resources(dir, None).await)
    }

    fn test_spec(workspace: WorkspaceId, resources: &DaemonResources) -> SessionSpec {
        SessionSpec {
            workspace,
            name: Some("headless-test-workspace".to_string()),
            requested_tier: Tier::Sandbox,
            on_degrade: resources.default_on_degrade,
            parent: None,
        }
    }

    /// An `Isolate` double that counts its own `teardown` calls — for the
    /// `close_and_teardown`/`ReapAction::RetireSubAgent` tests below, which
    /// need to prove teardown runs exactly once, not merely that it runs.
    /// Never spawns anything for real; these tests never dispatch a shell.
    struct CountingIsolate {
        teardown_calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Isolate for CountingIsolate {
        fn declared(&self) -> Tier {
            Tier::Sandbox
        }

        async fn probe(&self) -> ProbeResult {
            ProbeResult {
                achieved: Tier::Sandbox,
                degradations: vec![],
            }
        }

        async fn prepare(&self, _spec: &SessionSpec) -> Result<Handle, IsolationError> {
            Ok(Handle {
                id: "counting-isolate".into(),
            })
        }

        async fn spawn(&self, _h: &Handle, _cmd: CommandSpec) -> Result<Child, IsolationError> {
            unreachable!("this module's close/reap tests never dispatch a real shell")
        }

        fn attest(&self, _h: &Handle) -> Attestation {
            Attestation {
                tier: Tier::Sandbox,
                digest: "counting-isolate".into(),
                net_enforced: false,
            }
        }

        async fn teardown(&self, _h: Handle) -> Result<(), IsolationError> {
            // A real yield point, modeling a real isolate awaiting unmount
            // I/O — without one, this whole function never actually
            // suspends, so the runtime never gets a chance to poll any
            // OTHER task (e.g. a reaper that should have been aborted but
            // wasn't) before this call returns, which would make a
            // self-abort/double-teardown bug invisible to a caller that
            // only checks `teardown_calls` right after `.await` resolves.
            tokio::task::yield_now().await;
            self.teardown_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// A minimal, real `SessionActor` (state `Running`) over a
    /// caller-supplied `isolate` — unlike `real_actor_with_state`, which is
    /// pinned to this crate's shared `available_isolate()`, so it cannot
    /// observe how many times an actor's isolation handle was torn down.
    async fn actor_with_isolate(
        dir: &std::path::Path,
        isolate: Arc<dyn Isolate>,
    ) -> Arc<SessionActor> {
        let store = roundhouse_store::open(&dir.join("events.db"))
            .await
            .unwrap();
        let writer = roundhouse_store::spawn_writer(store).await;
        actor_with_isolate_and_writer(dir, isolate, writer).await
    }

    /// [`actor_with_isolate`], but over a caller-supplied `writer` — for the
    /// `close_and_teardown` timeout test below, which needs a
    /// `roundhouse_store::test_util`-gated writer rather than an ordinary
    /// one.
    async fn actor_with_isolate_and_writer(
        dir: &std::path::Path,
        isolate: Arc<dyn Isolate>,
        writer: roundhouse_store::EventWriter,
    ) -> Arc<SessionActor> {
        let policy = Arc::new(roundhouse_policy::engine::PolicyEngine::from_rules(vec![]));
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

    /// A real, `serve()`d [`LoopbackProxy`] with one freshly registered
    /// session token — the same fixture shape
    /// `register_headless_session_is_reaped_once_its_actor_is_closed` and
    /// `socket_server`'s own reaper tests already use, factored out here
    /// since this module's Task 5 tests need it twice more.
    async fn real_proxy_with_registered_token(
        dir: &std::path::Path,
    ) -> (Arc<LoopbackProxy>, String) {
        let proxy = Arc::new(LoopbackProxy::new());
        let proxy_store = roundhouse_store::open(&dir.join("proxy-events.db"))
            .await
            .unwrap();
        let proxy_writer = spawn_writer(proxy_store).await;
        proxy.clone().serve(runner(), proxy_writer).await.unwrap();
        let proxy_handle = proxy
            .register_session(
                SessionId::new(),
                EgressPolicy {
                    allowed_hosts: vec![],
                },
            )
            .unwrap();
        let token = proxy_handle.token().to_string();
        (proxy, token)
    }

    #[tokio::test]
    async fn create_headless_session_registers_with_zero_subscribers_and_is_retrievable() {
        let dir = tempfile::tempdir().unwrap();
        let resources = resources(dir.path()).await;
        let registry = Arc::new(SessionRegistry::new());
        let session_id = SessionId::new();
        let spec = test_spec(WorkspaceId::new(), &resources);

        let headless = create_headless_session(
            &resources,
            &registry,
            session_id,
            spec,
            dir.path().to_path_buf(),
            None,
            None,
        )
        .await
        .expect("headless session construction must succeed against a working fixture");

        assert_eq!(
            headless.session_id(),
            session_id,
            "the registry must register the session under the SAME id the caller supplied, \
             not mint a new one"
        );

        let actor = registry
            .actor(session_id)
            .expect("a headlessly-registered session must be retrievable via registry.actor");
        assert_eq!(actor.state(), SessionState::Running);

        assert_eq!(
            registry.subscriber_count_for_test(session_id),
            Some(0),
            "a headlessly-registered session must start with ZERO subscribers, not the \
             creator-subscriber `create` mints — that is the whole point of \
             register_headless over create for a caller with no connection to hand a \
             Receiver to"
        );

        assert!(
            registry.session_mcp(session_id).is_none(),
            "this session configured no MCP servers"
        );

        // A headlessly-registered session must still be a fully ordinary,
        // attachable session afterward (ruling W1-R51's "entry lifetime =
        // actor lifetime" applies identically regardless of which entry
        // point started it there).
        assert!(
            registry.attach(session_id).is_some(),
            "a headlessly-registered session must remain attachable, exactly like a \
             normal session whose one subscriber has detached"
        );

        // Phase 8, Task 6: the caller's own teardown is what actually retires
        // a headless session — `spawn_session_reaper` waits on a `Closed`
        // that nothing in this workspace ever produces, so without this a
        // per-delivery session would live for the daemon's whole life.
        headless.teardown(&registry, &resources.proxy).await;
        assert!(
            registry.actor(session_id).is_none(),
            "HeadlessSession::teardown must remove the session from the registry"
        );
    }

    /// Phase 8 Task 25.5 (#62): a headless session is how the scheduler runs
    /// a workflow, and a workflow `agent:` step spawns through the same
    /// `SubAgentHost` machinery the chat path uses — but until this test's
    /// production code lands, `wire_sub_agent_host` is called only from
    /// `socket_server::drive_session`, so a headless session's `SessionActor`
    /// has none registered and would refuse a spawn with
    /// `sub_agent_host_unavailable`. See `sub_agent_host::wire_sub_agent_host`'s
    /// own doc comment, which named this exact gap.
    #[tokio::test]
    async fn a_headless_session_can_spawn_sub_agents() {
        let dir = tempfile::tempdir().unwrap();
        let resources = resources(dir.path()).await;
        let registry = Arc::new(SessionRegistry::new());
        let session_id = SessionId::new();
        let spec = test_spec(WorkspaceId::new(), &resources);

        let headless = create_headless_session(
            &resources,
            &registry,
            session_id,
            spec,
            dir.path().to_path_buf(),
            None,
            None,
        )
        .await
        .expect("headless session construction must succeed against a working fixture");

        assert!(
            headless.actor().sub_agent_host().is_some(),
            "a headless (scheduled/workflow) session must have a SubAgentHost registered, \
             the same way socket_server::drive_session wires one for a chat session, so an \
             `agent:` workflow step can spawn a real child rather than refusing with \
             sub_agent_host_unavailable"
        );

        headless.teardown(&registry, &resources.proxy).await;
    }

    /// The counterpart to the assertion above: teardown must release the
    /// session's *real* resources too, not just its registry bookkeeping —
    /// the exact defect fix round 2's MUST 2 closed for the reaper path, here
    /// for the explicit one.
    #[tokio::test]
    async fn headless_teardown_deregisters_the_sessions_real_proxy_token() {
        let dir = tempfile::tempdir().unwrap();
        let resources = resources(dir.path()).await;
        let registry = Arc::new(SessionRegistry::new());
        let session_id = SessionId::new();
        let spec = test_spec(WorkspaceId::new(), &resources);

        let headless = create_headless_session(
            &resources,
            &registry,
            session_id,
            spec,
            dir.path().to_path_buf(),
            None,
            None,
        )
        .await
        .expect("headless session construction must succeed against a working fixture");
        let token = headless.proxy_token_for_test().to_string();
        assert!(
            resources.proxy.is_registered(&token),
            "a real session registers a real proxy token; this test proves nothing otherwise"
        );

        headless.teardown(&registry, &resources.proxy).await;

        assert!(
            !resources.proxy.is_registered(&token),
            "teardown must deregister this session's egress-proxy entry, not just drop its \
             registry row"
        );
    }

    /// Proves the relocated [`spawn_session_reaper`] tears down a
    /// headlessly-registered session once its actor reaches
    /// `SessionState::Closed` — the composition [`create_headless_session`]
    /// wires together, exercised directly through `register_headless`.
    ///
    /// Phase 8, T19a Task 5: this now drives a REAL close
    /// ([`SessionActor::close`], landed by Task 4) instead of constructing
    /// an already-`Closed` actor at birth — `close()` is real production
    /// code now, not a gap this test has to work around. Still no
    /// real-clock timing: `close()` itself durably appends the terminator
    /// and publishes `Closed` to the state watch before returning, so the
    /// reaper is already woken (not merely eligible to be) by the time this
    /// test starts polling; `tokio::task::yield_now` only lets that already-
    /// woken task actually run.
    #[tokio::test]
    async fn register_headless_session_is_reaped_once_its_actor_is_closed() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Arc::new(SessionRegistry::new());
        let actor = real_actor_with_state(dir.path(), roundhouse_core::SessionState::Running).await;
        let actor_for_reaper = actor.clone();

        let session_id = registry
            .register_headless(actor.clone(), None, None)
            .expect("registering against a fresh, non-full registry must succeed");
        assert_eq!(registry.subscriber_count_for_test(session_id), Some(0));

        let (proxy, token) = real_proxy_with_registered_token(dir.path()).await;

        spawn_session_reaper(
            registry.clone(),
            session_id,
            actor_for_reaper,
            None,
            proxy.clone(),
            token.clone(),
            ReapAction::Teardown,
            Arc::new(AtomicBool::new(false)),
        );

        actor
            .close(SessionOutcome::Completed)
            .await
            .expect("closing a session with no open tasks and no gate must succeed");

        // `yield_now` lets the reaper task — already woken by `close()`'s
        // own state-watch publish above — actually run before this
        // assertion; no real-clock wait involved.
        for _ in 0..1000 {
            if registry.actor(session_id).is_none() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            registry.actor(session_id).is_none(),
            "spawn_session_reaper must remove a headlessly-registered session's registry \
             entry once its actor reaches SessionState::Closed"
        );
        assert!(
            !proxy.is_registered(&token),
            "the reaper must deregister this session's real proxy token"
        );
    }

    /// [`HeadlessSession::close_and_teardown`] must tear this session's real
    /// isolation handle down exactly once (Phase 8, T19a Task 5) — not zero
    /// times (leaked), and not twice (a double `Isolate::teardown` call,
    /// which that method's own doc comment says is not guaranteed safe).
    /// The double-call hazard this guards against: `close_and_teardown`
    /// aborts this session's reaper BEFORE calling `SessionActor::close`, so
    /// the reaper can never independently observe `Closed` and run its own
    /// teardown concurrently with this call's.
    #[tokio::test]
    async fn close_and_teardown_tears_down_the_real_isolation_handle_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let teardown_calls = Arc::new(AtomicUsize::new(0));
        let isolate: Arc<dyn Isolate> = Arc::new(CountingIsolate {
            teardown_calls: Arc::clone(&teardown_calls),
        });
        let actor = actor_with_isolate(dir.path(), isolate).await;

        let registry = Arc::new(SessionRegistry::new());
        let session_id = registry
            .register_headless(actor.clone(), None, None)
            .expect("registering against a fresh, non-full registry must succeed");

        let (proxy, token) = real_proxy_with_registered_token(dir.path()).await;

        let torn_down = Arc::new(AtomicBool::new(false));
        let reaper = spawn_session_reaper(
            registry.clone(),
            session_id,
            actor.clone(),
            None,
            proxy.clone(),
            token.clone(),
            ReapAction::Teardown,
            Arc::clone(&torn_down),
        );
        let headless = HeadlessSession {
            session_id,
            actor: actor.clone(),
            mcp_host: None,
            proxy_token: token.clone(),
            reaper,
            torn_down,
        };

        assert_eq!(
            teardown_calls.load(Ordering::SeqCst),
            0,
            "sanity: nothing has torn this session's isolation handle down yet"
        );

        let receipt = headless
            .close_and_teardown(SessionOutcome::Completed, &registry, &proxy)
            .await
            .expect("closing a session with no open tasks and no gate must succeed");
        assert_eq!(receipt, roundhouse_store::CloseReceipt::Closed { swept: 0 });

        // `CountingIsolate::teardown` has its own real yield point, so a
        // reaper that was WRONGLY left un-aborted needs the runtime to
        // actually poll it before it can run its own (duplicate) teardown —
        // this bounded drain is what gives it that chance, so this
        // assertion genuinely discriminates "aborted" from "not aborted"
        // rather than passing regardless because nothing ever yielded
        // control back to the scheduler.
        for _ in 0..1000 {
            tokio::task::yield_now().await;
        }

        assert_eq!(
            teardown_calls.load(Ordering::SeqCst),
            1,
            "close_and_teardown must tear this session's real isolation handle down exactly \
             once"
        );
        assert!(
            registry.actor(session_id).is_none(),
            "close_and_teardown must remove the registry entry"
        );
        assert!(
            !proxy.is_registered(&token),
            "close_and_teardown must deregister the real egress token"
        );
    }

    /// **Two independent teardown routes racing the same session tear its
    /// real isolation handle down exactly once** (Phase 8, T19a Task 6, fix
    /// round 1) — the structural guarantee `torn_down`/[`claim_teardown`]
    /// exist for, proven WITHOUT the ordering `DaemonSubAgentHost::
    /// create_child_session` relies on (rewiring only after
    /// `SubAgentSessions::insert`): that ordering narrows *when* a race can
    /// start, but a shared flag is what makes the race itself harmless
    /// however it lands, which is what this test isolates.
    ///
    /// Route A is an extra reaper — independent of the `HeadlessSession`
    /// below, sharing only its `torn_down` flag — modeling the plain
    /// `ReapAction::Teardown` reaper `create_headless_session` always starts
    /// a session with and that stays armed until something rewires or
    /// aborts it. Route B is that `HeadlessSession`'s own explicit
    /// `teardown`, called directly rather than waited on by anything. Both
    /// race the SAME `Closed` transition; only one may win the flag.
    #[tokio::test]
    async fn two_independent_teardown_routes_racing_one_session_tear_it_down_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let teardown_calls = Arc::new(AtomicUsize::new(0));
        let isolate: Arc<dyn Isolate> = Arc::new(CountingIsolate {
            teardown_calls: Arc::clone(&teardown_calls),
        });
        let actor = actor_with_isolate(dir.path(), isolate).await;

        let registry = Arc::new(SessionRegistry::new());
        let session_id = registry
            .register_headless(actor.clone(), None, None)
            .expect("registering against a fresh, non-full registry must succeed");

        let (proxy, token) = real_proxy_with_registered_token(dir.path()).await;
        let torn_down = Arc::new(AtomicBool::new(false));

        // Route A: an extra reaper, independent of `headless` below, sharing
        // only the flag.
        let extra_reaper = spawn_session_reaper(
            registry.clone(),
            session_id,
            actor.clone(),
            None,
            proxy.clone(),
            token.clone(),
            ReapAction::Teardown,
            Arc::clone(&torn_down),
        );

        // Route B: `headless`'s own reaper and explicit teardown — a second,
        // independent handle on the same session, sharing the SAME flag.
        let own_reaper = spawn_session_reaper(
            registry.clone(),
            session_id,
            actor.clone(),
            None,
            proxy.clone(),
            token.clone(),
            ReapAction::Teardown,
            Arc::clone(&torn_down),
        );
        let headless = HeadlessSession {
            session_id,
            actor: actor.clone(),
            mcp_host: None,
            proxy_token: token.clone(),
            reaper: own_reaper,
            torn_down,
        };

        // One real close, observed by both routes at once: Route A's extra
        // reaper independently, and Route B's own explicit teardown below
        // (which aborts only `headless`'s own reaper, never Route A's).
        actor
            .close(SessionOutcome::Completed)
            .await
            .expect("closing a session with no open tasks and no gate must succeed");

        headless.teardown(&registry, &proxy).await;

        // Let Route A's independent reaper actually run its race too.
        // `CountingIsolate::teardown` has its own real yield point, so a
        // reaper that reached the real work needs the runtime to poll it
        // before this assertion could observe a wrongly-doubled count.
        for _ in 0..1000 {
            tokio::task::yield_now().await;
        }
        extra_reaper.abort();

        assert_eq!(
            teardown_calls.load(Ordering::SeqCst),
            1,
            "two independent teardown routes racing the same session must tear its real \
             isolation handle down exactly once, not zero and not twice"
        );
        assert!(registry.actor(session_id).is_none());
        assert!(!proxy.is_registered(&token));
    }

    /// **Nested closes must be bounded strictly more tightly than the close
    /// they run inside**, or their own `tokio::time::timeout` is dead code:
    /// it is created strictly later than the enclosing one, so an equal
    /// bound always yields the later deadline and is dropped, timer
    /// included, before it can fire (Phase 8, T19a Task 6).
    ///
    /// Pinned as a pure relationship between the constants, independent of
    /// any one cascade: `sub_agent_host`'s own
    /// `a_wedged_child_is_abandoned_at_its_own_depth_derived_bound` proves
    /// the retirement path really applies these values to a real wedged
    /// child.
    #[test]
    fn a_nested_close_budget_is_strictly_smaller_at_every_tracked_depth() {
        let mut previous = SESSION_CLOSE_TIMEOUT;
        for depth in 1..=roundhouse_bus::limits::MAX_DEPTH {
            let budget = nested_close_timeout(depth);
            assert!(
                budget < previous,
                "depth {depth}'s close budget ({budget:?}) must be strictly smaller than the \
                 budget of the level enclosing it ({previous:?}), or its timeout can never \
                 fire first"
            );
            assert!(
                budget >= MIN_NESTED_CLOSE_TIMEOUT,
                "depth {depth}'s close budget ({budget:?}) must still leave room for one \
                 child's own designed-in grace periods to unwind"
            );
            previous = budget;
        }
    }

    /// [`HeadlessSession::close_and_teardown`]'s [`SESSION_CLOSE_TIMEOUT`]
    /// bound on a wedged [`SessionActor::close`] (Phase 8, T19a Task 5).
    /// `close()`'s own durable `close_session` append is routed
    /// through a `roundhouse_store::test_util::CloseGate` held open and
    /// never released — the same real, deterministic hang-until-signalled
    /// mechanism `roundhouse-engine`'s own `tests/session_close.rs` uses,
    /// not a real sleep standing in for one. No real time passes either:
    /// `#[tokio::test(start_paused = true)]` plus `tokio::time::advance`
    /// jumps straight past `SESSION_CLOSE_TIMEOUT`.
    #[tokio::test(start_paused = true)]
    async fn close_and_teardown_abandons_a_wedged_close_after_the_timeout_and_tears_down_anyway() {
        let dir = tempfile::tempdir().unwrap();
        let teardown_calls = Arc::new(AtomicUsize::new(0));
        let isolate: Arc<dyn Isolate> = Arc::new(CountingIsolate {
            teardown_calls: Arc::clone(&teardown_calls),
        });

        let store = roundhouse_store::open(&dir.path().join("events.db"))
            .await
            .unwrap();
        let gate = roundhouse_store::test_util::CloseGate::new();
        let writer =
            roundhouse_store::test_util::spawn_gated_writer(store, Arc::clone(&gate)).await;
        let actor = actor_with_isolate_and_writer(dir.path(), isolate, writer).await;

        let registry = Arc::new(SessionRegistry::new());
        let session_id = registry
            .register_headless(actor.clone(), None, None)
            .expect("registering against a fresh, non-full registry must succeed");

        let (proxy, token) = real_proxy_with_registered_token(dir.path()).await;

        let torn_down = Arc::new(AtomicBool::new(false));
        let reaper = spawn_session_reaper(
            registry.clone(),
            session_id,
            actor.clone(),
            None,
            proxy.clone(),
            token.clone(),
            ReapAction::Teardown,
            Arc::clone(&torn_down),
        );
        let headless = HeadlessSession {
            session_id,
            actor: actor.clone(),
            mcp_host: None,
            proxy_token: token.clone(),
            reaper,
            torn_down,
        };

        // Never released for the rest of this test: close_session's own
        // append blocks on this forever, modeling a genuinely wedged close.
        gate.hold().await;

        let closing = {
            let registry = Arc::clone(&registry);
            let proxy = Arc::clone(&proxy);
            tokio::spawn(async move {
                headless
                    .close_and_teardown(SessionOutcome::Completed, &registry, &proxy)
                    .await
            })
        };

        // Deterministic: the paused clock only moves when told to. This
        // jumps straight past SESSION_CLOSE_TIMEOUT without any real time
        // elapsing, driving the runtime through whatever else is ready to
        // run along the way (per `tokio::time::advance`'s own contract).
        tokio::time::advance(SESSION_CLOSE_TIMEOUT + Duration::from_millis(1)).await;

        let result = closing
            .await
            .expect("close_and_teardown's own task must not panic");
        assert!(
            matches!(&result, Err(CloseAndTeardownError::Timeout(_))),
            "an abandoned close must report Timeout, got {result:?}"
        );

        assert_eq!(
            teardown_calls.load(Ordering::SeqCst),
            1,
            "close_and_teardown must tear the real isolation handle down even after abandoning \
             a wedged close"
        );
        assert!(
            registry.actor(session_id).is_none(),
            "close_and_teardown must still remove the registry entry after a timeout"
        );
        assert!(
            !proxy.is_registered(&token),
            "close_and_teardown must still deregister the real egress token after a timeout"
        );
    }

    /// An [`Isolate`] whose `teardown` parks until it is released, so a test
    /// can drop the future awaiting it at a known point rather than guessing
    /// when to.
    struct GatedIsolate {
        started: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
        finished: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        teardown_calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Isolate for GatedIsolate {
        fn declared(&self) -> Tier {
            Tier::Sandbox
        }

        async fn probe(&self) -> ProbeResult {
            ProbeResult {
                achieved: Tier::Sandbox,
                degradations: vec![],
            }
        }

        async fn prepare(&self, _spec: &SessionSpec) -> Result<Handle, IsolationError> {
            Ok(Handle {
                id: "gated-isolate".into(),
            })
        }

        async fn spawn(&self, _h: &Handle, _cmd: CommandSpec) -> Result<Child, IsolationError> {
            unreachable!("this module's close/reap tests never dispatch a real shell")
        }

        fn attest(&self, _h: &Handle) -> Attestation {
            Attestation {
                tier: Tier::Sandbox,
                digest: "gated-isolate".into(),
                net_enforced: false,
            }
        }

        async fn teardown(&self, _h: Handle) -> Result<(), IsolationError> {
            // Both taken before anything is awaited, so no lock is ever held
            // across a suspension point.
            let started = self.started.lock().unwrap().take();
            let release = self.release.lock().unwrap().take();
            if let Some(started) = started {
                let _ = started.send(());
            }
            if let Some(release) = release {
                let _ = release.await;
            }
            self.teardown_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(finished) = self.finished.lock().unwrap().take() {
                let _ = finished.send(());
            }
            Ok(())
        }
    }

    /// **A claimed teardown that is dropped mid-body must still release
    /// everything the claim says it released** (Phase 8, T19a Task 6).
    ///
    /// [`claim_teardown`] only ever made teardown exactly-one-CLAIM. The
    /// body behind it awaits real isolation and MCP work, and
    /// [`HeadlessSession::finish_teardown`] is reached from places whose
    /// future can be dropped underneath it — a descendant being retired
    /// inside an ancestor's cascade sits inside that ancestor's own close
    /// timeout, and `tokio::time::timeout` drops what it bounds. A drop
    /// between the claim and the end of the body used to leave `torn_down`
    /// reading "done" over a half-unwound isolate and a still-registered
    /// egress token, with every other route short-circuiting on the flag, so
    /// nothing retried it.
    ///
    /// The drop here is exact rather than timed: [`GatedIsolate`] signals
    /// when its `teardown` has been entered and then parks, and this test
    /// drops the `finish_teardown` future at precisely that point. Nothing
    /// sleeps; the one `tokio::time::timeout` below is a deterministic
    /// failure bound on a paused clock, not a wait.
    #[tokio::test(start_paused = true)]
    async fn a_dropped_finish_teardown_still_releases_everything_it_claimed() {
        let dir = tempfile::tempdir().unwrap();
        let teardown_calls = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        let isolate: Arc<dyn Isolate> = Arc::new(GatedIsolate {
            started: std::sync::Mutex::new(Some(started_tx)),
            release: std::sync::Mutex::new(Some(release_rx)),
            finished: std::sync::Mutex::new(Some(finished_tx)),
            teardown_calls: Arc::clone(&teardown_calls),
        });

        let actor = actor_with_isolate(dir.path(), isolate).await;
        let registry = Arc::new(SessionRegistry::new());
        let session_id = registry
            .register_headless(actor.clone(), None, None)
            .expect("registering against a fresh, non-full registry must succeed");
        let (proxy, token) = real_proxy_with_registered_token(dir.path()).await;

        let torn_down = Arc::new(AtomicBool::new(false));
        let reaper = spawn_session_reaper(
            registry.clone(),
            session_id,
            actor.clone(),
            None,
            proxy.clone(),
            token.clone(),
            ReapAction::Teardown,
            Arc::clone(&torn_down),
        );
        let headless = HeadlessSession {
            session_id,
            actor: actor.clone(),
            mcp_host: None,
            proxy_token: token.clone(),
            reaper,
            torn_down: Arc::clone(&torn_down),
        };

        let mut tearing_down = Box::pin(headless.finish_teardown(&registry, &proxy));
        tokio::select! {
            _ = &mut tearing_down => panic!(
                "finish_teardown must not resolve while the isolate's own teardown is parked"
            ),
            started = started_rx => started.expect(
                "the isolate's teardown must have been entered before this test drops anything"
            ),
        }

        // The cancellation: the caller awaiting the claimed body goes away
        // with the isolate mid-unwind.
        drop(tearing_down);

        assert!(
            torn_down.load(Ordering::SeqCst),
            "sanity: the teardown really was claimed before the drop"
        );
        assert!(
            registry.actor(session_id).is_none(),
            "a claimed teardown that was dropped must still have removed the registry entry"
        );
        assert!(
            !proxy.is_registered(&token),
            "a claimed teardown that was dropped must still have revoked this session's egress \
             token; leaving it registered hands a session that no longer exists a valid bearer \
             token for the life of the daemon"
        );

        // Releasing the isolate proves the rest of the body outlived the
        // dropped caller rather than being truncated with it.
        release_tx
            .send(())
            .expect("the isolate's teardown must still be parked, not gone");
        tokio::time::timeout(Duration::from_secs(5), finished_rx)
            .await
            .expect(
                "a claimed teardown must run to completion after its caller is dropped; nothing \
                 else will ever retry it, since every other route short-circuits on the claimed \
                 flag",
            )
            .expect("the isolate's teardown must not be dropped mid-way");
        assert_eq!(
            teardown_calls.load(Ordering::SeqCst),
            1,
            "the real isolation handle must be torn down exactly once, by the detached body of \
             the claim the dropped caller made"
        );
    }

    /// A child tracked in [`SubAgentSessions`] whose actor is closed
    /// directly ([`SessionActor::close`]) — never through
    /// `HeadlessSession::close_and_teardown`/`teardown` — must still be
    /// fully retired: its `SubAgentSessions` record and its parent's
    /// `SpawnTree` edge dropped, its registry entry and real isolation
    /// handle/egress token torn down, all by the reaper's own
    /// `ReapAction::RetireSubAgent` dispatch (Phase 8, T19a Task 5).
    ///
    /// This is also the test that proves `HeadlessSession::teardown_from_reaper`
    /// really does drop its own `JoinHandle` rather than abort it: this test
    /// never calls `.abort()` on anything, so the ONLY way every one of the
    /// assertions below can pass is for the reaper's retire-arm dispatch to
    /// run to completion inside its own task — an `abort()` on the reaper's
    /// own handle from inside that same call would cancel it at its next
    /// await point, most likely leaving the registry entry, the isolation
    /// teardown, or the proxy deregistration incomplete.
    #[tokio::test]
    async fn a_sub_agent_child_closed_directly_is_retired_without_the_reaper_aborting_itself() {
        let dir = tempfile::tempdir().unwrap();
        let teardown_calls = Arc::new(AtomicUsize::new(0));
        let isolate: Arc<dyn Isolate> = Arc::new(CountingIsolate {
            teardown_calls: Arc::clone(&teardown_calls),
        });
        let actor = actor_with_isolate(dir.path(), isolate).await;

        let registry = Arc::new(SessionRegistry::new());
        let session_id = registry
            .register_headless(actor.clone(), None, None)
            .expect("registering against a fresh, non-full registry must succeed");

        let (proxy, token) = real_proxy_with_registered_token(dir.path()).await;

        let sub_agents = Arc::new(SubAgentSessions::new());
        let tree = Arc::new(SpawnTree::new());
        let parent = SessionId::new();
        tree.record_child(parent, session_id);

        let torn_down = Arc::new(AtomicBool::new(false));
        let reaper = spawn_session_reaper(
            registry.clone(),
            session_id,
            actor.clone(),
            None,
            proxy.clone(),
            token.clone(),
            ReapAction::RetireSubAgent {
                sub_agents: Arc::clone(&sub_agents),
                tree: Arc::clone(&tree),
            },
            Arc::clone(&torn_down),
        );
        let headless = HeadlessSession {
            session_id,
            actor: actor.clone(),
            mcp_host: None,
            proxy_token: token.clone(),
            reaper,
            torn_down,
        };
        // depth 1: a direct child of `parent` (depth 0), the shallowest a
        // real tracked sub-agent is ever admitted at.
        sub_agents.insert_for_test(session_id, parent, 1, headless);
        assert_eq!(
            tree.direct_children(parent),
            1,
            "sanity: the edge is recorded"
        );

        // Close the actor directly — the ordinary durable-close path, never
        // HeadlessSession::teardown/close_and_teardown. Only the reaper's
        // own observation of Closed drives retirement here.
        actor
            .close(SessionOutcome::Completed)
            .await
            .expect("closing a session with no open tasks and no gate must succeed");

        // No real-clock wait: `close()` already published `Closed` to the
        // state watch above, so the reaper is already woken; `yield_now`
        // just lets it actually run. Polls on the LAST thing this session's
        // teardown does — the real isolation teardown that
        // `release_claimed_resources` runs in its detached task, with no MCP
        // host behind it here — not on `sub_agents.is_empty()`, which goes
        // true the moment `take_for_reap` runs, before
        // `SpawnTree::remove_child` or any real resource release has
        // happened, so it would let this loop break (and the assertions
        // below run) while `teardown_from_reaper` is still genuinely in
        // flight.
        for _ in 0..1000 {
            if teardown_calls.load(Ordering::SeqCst) == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }

        assert!(
            sub_agents.is_empty(),
            "ReapAction::RetireSubAgent must remove this child's SubAgentSessions record once \
             its actor closes on its own"
        );
        assert_eq!(
            tree.direct_children(parent),
            0,
            "ReapAction::RetireSubAgent must drop the parent's SpawnTree edge"
        );
        assert!(
            registry.actor(session_id).is_none(),
            "ReapAction::RetireSubAgent must still remove the registry entry"
        );
        assert!(
            !proxy.is_registered(&token),
            "ReapAction::RetireSubAgent must still deregister the real egress token"
        );
        assert_eq!(
            teardown_calls.load(Ordering::SeqCst),
            1,
            "ReapAction::RetireSubAgent must tear the real isolation handle down exactly once"
        );
    }

    /// **A child spawned during a parent's own close is still retired**
    /// (Phase 8, T19a Task 6) — `DaemonSubAgentHost::
    /// close_children`'s single `children_of(parent)` snapshot could
    /// otherwise miss a child admitted after that snapshot but before the
    /// parent's own close finishes (`wait_idle` does not cover this: a
    /// workflow `agent:` step's spawn, driven from `scheduler_driver`
    /// through `workflow_dispatch::dispatch_agent_for_workflow`, holds no
    /// `WorkGuard` for the parent). `close_children` now re-polls until
    /// `children_of` returns empty, so a child recorded after the first
    /// snapshot is still picked up by a later pass.
    ///
    /// C1's close is gated (real, deterministic, no sleep) so this test
    /// controls exactly when `close_children`'s first pass — which found
    /// only C1 — finishes and re-polls: C2 is inserted into
    /// `SubAgentSessions` while C1's retirement is still blocked on the
    /// gate, i.e. provably before `close_children`'s next
    /// `children_of(parent)` call, which cannot run until C1's
    /// `retire_child` call (awaiting the gated close) returns.
    #[tokio::test]
    async fn a_child_spawned_during_close_children_is_retired_by_a_later_repoll() {
        use crate::sub_agent_host::DaemonSubAgentHost;
        use roundhouse_engine::tools::agent_spawn_tool::SubAgentHost;

        let dir = tempfile::tempdir().unwrap();
        let resources = Arc::new(daemon_resources(dir.path(), None).await);
        let registry = Arc::new(SessionRegistry::new());
        let parent = SessionId::new();

        // C1: a gated close, so its retirement stays in flight for exactly
        // as long as this test wants it to.
        let c1_teardown_calls = Arc::new(AtomicUsize::new(0));
        let c1_isolate: Arc<dyn Isolate> = Arc::new(CountingIsolate {
            teardown_calls: Arc::clone(&c1_teardown_calls),
        });
        let c1_store = roundhouse_store::open(&dir.path().join("c1-events.db"))
            .await
            .unwrap();
        let gate = roundhouse_store::test_util::CloseGate::new();
        let c1_writer =
            roundhouse_store::test_util::spawn_gated_writer(c1_store, Arc::clone(&gate)).await;
        let c1_actor = actor_with_isolate_and_writer(dir.path(), c1_isolate, c1_writer).await;
        let c1_id = registry
            .register_headless(c1_actor.clone(), None, None)
            .expect("registering against a fresh, non-full registry must succeed");
        let c1_proxy_handle = resources
            .proxy
            .register_session(
                c1_id,
                EgressPolicy {
                    allowed_hosts: vec![],
                },
            )
            .unwrap();
        let c1_token = c1_proxy_handle.token().to_string();
        let c1_torn_down = Arc::new(AtomicBool::new(false));
        let c1_reaper = spawn_session_reaper(
            registry.clone(),
            c1_id,
            c1_actor.clone(),
            None,
            resources.proxy.clone(),
            c1_token.clone(),
            ReapAction::Teardown,
            Arc::clone(&c1_torn_down),
        );
        resources.sub_agents.insert_for_test(
            c1_id,
            parent,
            1,
            HeadlessSession {
                session_id: c1_id,
                actor: c1_actor.clone(),
                mcp_host: None,
                proxy_token: c1_token,
                reaper: c1_reaper,
                torn_down: c1_torn_down,
            },
        );
        resources.spawn_tree.record_child(parent, c1_id);

        gate.hold().await;

        let host: Arc<dyn SubAgentHost> = Arc::new(DaemonSubAgentHost::for_root_session(
            Arc::clone(&resources),
            Arc::clone(&registry),
            parent,
        ));
        let closing = {
            let host = Arc::clone(&host);
            tokio::spawn(async move { host.close_children(parent).await })
        };

        // C2: an ordinary, ungated child, inserted only now — strictly after
        // close_children's first snapshot (which could only have found C1)
        // and strictly before its next one (blocked on `gate` until this
        // test releases it below).
        let c2_teardown_calls = Arc::new(AtomicUsize::new(0));
        let c2_isolate: Arc<dyn Isolate> = Arc::new(CountingIsolate {
            teardown_calls: Arc::clone(&c2_teardown_calls),
        });
        let c2_actor = actor_with_isolate(dir.path(), c2_isolate).await;
        let c2_id = registry
            .register_headless(c2_actor.clone(), None, None)
            .expect("registering against a fresh, non-full registry must succeed");
        let c2_proxy_handle = resources
            .proxy
            .register_session(
                c2_id,
                EgressPolicy {
                    allowed_hosts: vec![],
                },
            )
            .unwrap();
        let c2_token = c2_proxy_handle.token().to_string();
        let c2_torn_down = Arc::new(AtomicBool::new(false));
        let c2_reaper = spawn_session_reaper(
            registry.clone(),
            c2_id,
            c2_actor.clone(),
            None,
            resources.proxy.clone(),
            c2_token.clone(),
            ReapAction::Teardown,
            Arc::clone(&c2_torn_down),
        );
        resources.sub_agents.insert_for_test(
            c2_id,
            parent,
            1,
            HeadlessSession {
                session_id: c2_id,
                actor: c2_actor.clone(),
                mcp_host: None,
                proxy_token: c2_token,
                reaper: c2_reaper,
                torn_down: c2_torn_down,
            },
        );
        resources.spawn_tree.record_child(parent, c2_id);

        // Let C1's gated close proceed now that C2 is in place.
        gate.release().await;

        closing
            .await
            .expect("close_children's own task must not panic");

        assert_eq!(
            c1_teardown_calls.load(Ordering::SeqCst),
            1,
            "the child found by the first snapshot must still be retired"
        );
        assert_eq!(
            c2_teardown_calls.load(Ordering::SeqCst),
            1,
            "a child inserted only after the first snapshot must be retired by a later \
             re-poll, not left tracked forever"
        );
        assert!(resources.sub_agents.is_empty());
        assert_eq!(resources.spawn_tree.direct_children(parent), 0);
        assert!(registry.actor(c1_id).is_none());
        assert!(registry.actor(c2_id).is_none());
    }

    #[tokio::test]
    async fn create_headless_session_fails_and_tears_down_when_the_registry_is_full() {
        let dir = tempfile::tempdir().unwrap();
        let resources = resources(dir.path()).await;
        // Zero capacity: `register_headless` must observe the registry as
        // already full and refuse, exactly like `create` does for the
        // socket path.
        let registry = Arc::new(SessionRegistry::with_limits(0, 64));
        let session_id = SessionId::new();
        let spec = test_spec(WorkspaceId::new(), &resources);

        let result = create_headless_session(
            &resources,
            &registry,
            session_id,
            spec,
            dir.path().to_path_buf(),
            None,
            None,
        )
        .await;

        // `HeadlessSession` is deliberately not `Debug` (it holds an actor and
        // a bearer token), so the failure message names the error rather than
        // rendering the whole `Result`.
        let error = result.err();
        assert!(
            matches!(error, Some(CreateHeadlessSessionError::RegistryFull)),
            "a full registry must fail create_headless_session with RegistryFull, got {:?}",
            error.as_ref().map(CreateHeadlessSessionError::kind)
        );
        assert!(
            registry.actor(session_id).is_none(),
            "a registry-full failure must not leave a half-registered session behind"
        );
    }

    /// Fix round 3, focused substitute for exercising
    /// [`create_headless_session`]'s timeout/late-success path end to end:
    /// forcing the real construction pipeline (`create_real_session`, which
    /// goes through isolation/MCP/egress with no injectable delay) to run
    /// slower than [`crate::socket_server::SESSION_CONSTRUCTION_TIMEOUT`]
    /// deterministically would need machinery beyond what this fix round's
    /// scope covers — the standing "no real-clock timing tests" constraint
    /// also rules out just making it slow via a real `sleep`. Per this fix
    /// round's own brief, a focused unit test of just the "late send after
    /// the receiver has been dropped or closed" `oneshot` mechanics —
    /// without a real `SessionActor` — is the acceptable substitute; this is
    /// that test.
    ///
    /// This proves the exact fact [`create_headless_session`]'s detached
    /// construction task relies on for its self-teardown branch: once the
    /// caller-side receiver is gone, `Sender::send` reports failure (rather
    /// than succeeding into a channel nobody will ever read), handing the
    /// value straight back so the sender can tear it down instead of leaking
    /// it. No timer, no sleep, no real elapsed time — the receiver is
    /// dropped by ordinary control flow (`drop(result_rx)`), not by a clock.
    #[tokio::test]
    async fn late_oneshot_send_after_the_receiver_is_dropped_reports_failure_with_the_value() {
        let (result_tx, result_rx) = tokio::sync::oneshot::channel::<u64>();

        // The "caller gave up" moment: drop the receiver, exactly what
        // happens when `create_headless_session`'s `tokio::select!` picks
        // its timeout arm and returns, dropping `result_rx` along with the
        // rest of that stack frame.
        drop(result_rx);

        // The "construction finished after the caller gave up" moment: the
        // detached task's own `send` now runs against a gone receiver.
        let send_result = result_tx.send(42);

        assert_eq!(
            send_result,
            Err(42),
            "sending into a oneshot channel whose receiver has already been dropped must fail \
             and hand the value straight back — this is exactly what \
             `create_headless_session`'s `if let Err(Ok(headless)) = result_tx.send(..)` branch \
             depends on to detect a late success and tear it down instead of leaking it"
        );
    }

    /// The companion mechanic to the test above: the send/drop race window
    /// [`create_headless_session`]'s own doc comment (and
    /// `construct_real_session_bounded`'s, which this mirrors) describes.
    /// Proves `close()` alone does not discard a value that had already
    /// landed in the channel's slot before `close()` ran — `try_recv()`
    /// afterward still drains it, which is exactly why the timeout arm calls
    /// `close()` and only then `try_recv()`, in that order, rather than
    /// dropping the receiver outright (which — as the test above shows —
    /// would make that same `send` fail and the value would be lost with no
    /// way back for whichever call, this one or the sender's, reads it
    /// second).
    #[tokio::test]
    async fn oneshot_try_recv_after_close_still_drains_a_value_that_landed_first() {
        let (result_tx, mut result_rx) = tokio::sync::oneshot::channel::<u64>();

        // Simulates a `send` landing in the narrow window before `close()`
        // runs: the value is sent while the receiver is still fully open.
        result_tx
            .send(7)
            .expect("the receiver has not been touched yet");

        // Now the timeout arm's own sequence: close, then drain.
        result_rx.close();
        let drained = result_rx.try_recv();

        assert_eq!(
            drained,
            Ok(7),
            "try_recv() after close() must still return a value that had already landed \
             before close() ran — otherwise the timeout arm would silently drop a `HeadlessSession` \
             that finished constructing in that narrow window, leaking its isolation handle/MCP \
             host/proxy registration"
        );
    }
}
