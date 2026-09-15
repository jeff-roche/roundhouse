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
//! **Deliberately not bounded by a construction timeout or semaphore.**
//! `socket_server::construct_real_session_bounded` races construction
//! against [`socket_server`]'s own `SESSION_CONSTRUCTION_TIMEOUT` and a
//! `construction_slots` semaphore — a concurrent-client-load defense specific
//! to a Unix socket accepting arbitrarily many peers at once. That is a
//! socket-path concern, not a property of session construction itself; a
//! headless caller (typically one delivery at a time) may need a different
//! policy, or none, and inventing one here — before the caller that actually
//! needs it exists — would be scope creep. See `create_headless_session`'s
//! own doc comment.

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
        }
    }
}

/// Builds one real session end to end, exactly as
/// `socket_server::construct_real_session_bounded` does for the socket path,
/// and registers it headlessly (zero subscribers, no channel) — for a caller
/// with no connected client to hand a `Receiver` to (Phase 8, Task 4: a
/// scheduled trigger delivery, wired by a later task).
///
/// Composes three calls that already exist:
/// [`create_real_session`] → [`SessionRegistry::register_headless`] →
/// [`spawn_session_reaper`], tearing down via [`teardown_real_session`] (the
/// same by-value teardown guarantee `socket_server`'s own failure paths use)
/// if registration loses the race against `max_sessions` after construction
/// has already completed — never leaving a half-constructed session or a
/// leaked isolation/MCP/proxy handle behind.
///
/// # No construction timeout or semaphore here, deliberately
///
/// `socket_server::construct_real_session_bounded` bounds construction
/// against a wedged MCP server or isolation probe specifically because a
/// Unix socket can have arbitrarily many peers racing `CreateSession`
/// concurrently — the timeout/semaphore pair defends against that shared
/// resource being exhausted by concurrent client load. Nothing about that
/// applies here yet: this function's only caller composes it directly, with
/// none of the socket path's concurrency. Bounding headless construction is
/// a real question for whichever future task actually drives concurrent
/// headless sessions, not one this task should preempt by copying a policy
/// that was tuned for a different problem.
pub async fn create_headless_session(
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
    /// one by name or id.
    async fn resources(dir: &std::path::Path) -> DaemonResources {
        daemon_resources(dir, None).await
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
}
