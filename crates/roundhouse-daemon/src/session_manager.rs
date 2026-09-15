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
use std::sync::Arc;

use roundhouse_core::{SessionId, SessionSpec, SessionState};
use roundhouse_engine::SessionActor;
use roundhouse_mcp::host::McpHost;
use roundhouse_net::proxy::LoopbackProxy;

use crate::session_bootstrap::{
    create_real_session, teardown_real_session, CreateRealSessionError, DaemonResources,
    RealSession,
};
use crate::session_registry::SessionRegistry;

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
    resources: &DaemonResources,
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

    let reaper = spawn_session_reaper(
        registry.clone(),
        session_id,
        actor_for_reaper,
        mcp_host_for_reaper,
        resources.proxy.clone(),
        proxy_token_for_reaper,
    );

    Ok(HeadlessSession {
        session_id,
        actor: actor_for_handle,
        mcp_host: mcp_host_for_handle,
        proxy_token: proxy_token_for_handle,
        reaper,
    })
}

/// A live headless session, plus everything needed to retire it.
///
/// # Why a headless caller has to retire its own session (Phase 8, Task 6)
///
/// [`spawn_session_reaper`] tears a session down when its actor reaches
/// `SessionState::Closed` — and **nothing in this workspace ever drives an
/// actor there** (see that function's own doc comment). For the socket path
/// that is merely latent: a session lives as long as the daemon and there is
/// one per connected client. For a *scheduled* session it is fatal, because
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
}

impl HeadlessSession {
    pub fn session_id(&self) -> SessionId {
        self.session_id
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
        registry.remove(self.session_id);
        self.actor.teardown().await;
        if let Some(host) = &self.mcp_host {
            if let Err(err) = host.shutdown().await {
                tracing::warn!(
                    session_id = %self.session_id,
                    error = %err,
                    "failed to shut down this session's MCP host"
                );
            }
        }
        proxy.deregister_session(&self.proxy_token);
    }
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
/// Nothing in this crate currently drives an actor to `SessionState::Closed`
/// (there is no live work-submission path yet — see `main.rs`'s own module
/// doc comment), so this loop simply never observes that value today and the
/// task sits parked on `state.changed()` for the daemon's whole life,
/// exactly as inert as `remove`'s previous zero-caller state was loud about
/// being unwired. The difference is that the mechanism is now real and
/// wired at every call site that creates a session, so the moment a future
/// task adds a real terminal transition, this reaper closes the loop with no
/// further wiring needed.
///
/// **Returns the task's `JoinHandle` (Phase 8, Task 6).** A caller that
/// retires its session explicitly — [`HeadlessSession::teardown`], because a
/// scheduled run cannot afford to wait for a `Closed` that never arrives —
/// needs to abort this task rather than leave it parked forever holding an
/// `Arc<SessionActor>`. The socket path ignores the handle, which is exactly
/// the previous behaviour.
pub(crate) fn spawn_session_reaper(
    registry: Arc<SessionRegistry>,
    session_id: SessionId,
    actor: Arc<SessionActor>,
    mcp_host: Option<Arc<McpHost>>,
    proxy: Arc<LoopbackProxy>,
    proxy_token: String,
) -> tokio::task::JoinHandle<()> {
    let mut state = actor.subscribe();
    tokio::spawn(async move {
        loop {
            if *state.borrow() == SessionState::Closed {
                registry.remove(session_id);
                // Fix round 2, MUST 2: before this, only the BOOKKEEPING
                // was cleared here (the registry entry, the proxy's
                // session-token map entry) — the REAL resources behind
                // them (a real bwrap isolation handle, real MCP child
                // processes) were never torn down on this path at all.
                actor.teardown().await;
                if let Some(host) = &mcp_host {
                    if let Err(err) = host.shutdown().await {
                        tracing::warn!(
                            session_id = %session_id,
                            error = %err,
                            "failed to shut down this session's MCP host"
                        );
                    }
                }
                proxy.deregister_session(&proxy_token);
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
    //! constructs its actor with `SessionState::Running` — nothing in this
    //! crate drives a real actor to `Closed` yet (see
    //! `spawn_session_reaper`'s own doc comment; this is the same reason
    //! `socket_server`'s pre-relocation reaper tests construct an actor
    //! already `Closed` at birth via `real_actor_with_state`, rather than
    //! transitioning a real one there). This module's reaper test follows
    //! the identical pattern, through `register_headless` instead of
    //! `create` — proving the SAME relocated reaper function correctly
    //! tears down a session that started life in the registry with zero
    //! subscribers, which is exactly what `create_headless_session` composes
    //! it with.

    use super::*;
    use crate::test_support::{daemon_resources, real_actor_with_state, runner};
    use roundhouse_core::{Tier, WorkspaceId};
    use roundhouse_net::policy::EgressPolicy;
    use roundhouse_store::spawn_writer;

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
        }
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
    /// wires together, exercised directly through `register_headless` (see
    /// this module's own doc comment for why `create_headless_session`
    /// itself cannot yet produce a `Closed` actor). No real-clock timing:
    /// the actor is already `Closed` at birth, so the reaper's very first
    /// poll of `state.borrow()` observes it, with no timer or sleep needed
    /// on either side — `tokio::task::yield_now` merely lets the already-
    /// spawned reaper task run before this test asserts on its effect.
    #[tokio::test]
    async fn register_headless_session_is_reaped_once_its_actor_is_closed() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Arc::new(SessionRegistry::new());
        let actor = real_actor_with_state(dir.path(), roundhouse_core::SessionState::Closed).await;
        let actor_for_reaper = actor.clone();

        let session_id = registry
            .register_headless(actor, None, None)
            .expect("registering against a fresh, non-full registry must succeed");
        assert_eq!(registry.subscriber_count_for_test(session_id), Some(0));

        let proxy = Arc::new(LoopbackProxy::new());
        let proxy_store = roundhouse_store::open(&dir.path().join("proxy-events.db"))
            .await
            .unwrap();
        let proxy_writer = spawn_writer(proxy_store).await;
        proxy.clone().serve(runner(), proxy_writer).await.unwrap();
        let proxy_handle = proxy
            .register_session(
                roundhouse_core::SessionId::new(),
                EgressPolicy {
                    allowed_hosts: vec![],
                },
            )
            .unwrap();
        let token = proxy_handle.token().to_string();

        spawn_session_reaper(
            registry.clone(),
            session_id,
            actor_for_reaper,
            None,
            proxy.clone(),
            token.clone(),
        );

        // The reaper's own first poll of `state.borrow()` already observes
        // `Closed` (the actor was constructed that way) — `yield_now` just
        // lets the spawned task actually run at least once before this
        // assertion, with no real-clock wait involved.
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
