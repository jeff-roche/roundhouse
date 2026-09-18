//! The daemon-owned half of the `agent` tool (Phase 8, L5): the thing that
//! turns `roundhouse-engine`'s spawn decision into a real child session.
//!
//! `roundhouse-engine` owns the ordering contract (reserve → admit → create →
//! commit, release on every failure edge — see
//! `roundhouse_engine::tools::agent_spawn_tool`) but cannot own the *create*
//! step: [`create_headless_session`], [`SessionRegistry`] and
//! [`HeadlessSession`] all live here, and nothing may depend on this crate.
//! So the engine names a trait and this module implements it — the same
//! bridge shape [`crate::workflow_host::WorkflowSessionTree`] already uses to
//! implement `roundhouse-flow`'s `SessionTree` over the same shared
//! `SpawnTree`.
//!
//! # Where a live sub-agent lives
//!
//! [`SubAgentSessions`] (one per daemon, on
//! [`DaemonResources::sub_agents`](crate::session_bootstrap::DaemonResources))
//! owns every [`HeadlessSession`] this daemon spawned as a sub-agent, keyed by
//! the CHILD's session id, alongside the parent it belongs to and the depth
//! §7.7 admitted it at. Two reasons it has to exist at all:
//!
//! 1. [`HeadlessSession`] is a live handle to a real isolation mount, a real
//!    proxy registration and possibly a real MCP subprocess. Dropping it on
//!    the floor leaks all three. Something must hold it.
//! 2. Retiring a sub-agent needs to know which parent's `SpawnTree` edge to
//!    remove, and `SpawnTree` indexes parent → children only. This is the
//!    child → parent direction, and it is what the two ways to end a
//!    tracked sub-agent both read: [`SubAgentSessions::retire_child`], which
//!    drops the edge and tears the session down itself, and
//!    [`SubAgentSessions::take_for_reap`], which hands both back to a caller
//!    (`spawn_session_reaper`'s `RetireSubAgent` reap action) that must do
//!    so itself.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use roundhouse_bus::spawn_tree::SpawnTree;
use roundhouse_bus::teams::TeamRegistry;
use roundhouse_core::{SessionId, SessionOutcome, TeamId, Timestamp};
use roundhouse_engine::agent_spawn::Budget;
use roundhouse_engine::tools::agent_spawn_tool::{
    ChildSessionError, ChildSessionRequest, SubAgentHost,
};
use roundhouse_engine::SessionActor;
use roundhouse_net::proxy::LoopbackProxy;
use tracing::Instrument;

use crate::session_bootstrap::DaemonResources;
use crate::session_manager::{
    create_headless_session, nested_close_timeout, HeadlessSession, ReapAction,
};
use crate::session_registry::SessionRegistry;

/// The token ceiling a session starts with.
///
/// **There is no real per-session token budget in this workspace yet** —
/// nothing meters a session's spend against one, and no config supplies one.
/// `agent_spawn`'s §7.7 transfer arithmetic is real and enforced *between*
/// sub-agents of one parent (a parent that gives away N tokens has N fewer to
/// give the next child, and a request larger than what is left is refused),
/// but the ceiling it starts from is unbounded. Seeding a made-up finite
/// number here would look like a policy decision nobody made; `u64::MAX` is
/// honest about the ledger being open at the top. Replace this the moment a
/// real budget source exists.
const UNMETERED_SESSION_BUDGET: u64 = u64::MAX;

/// How far up a session's tracked parent chain
/// [`DaemonSubAgentHost::ancestors_of`] is willing to walk before treating
/// the chain as corrupted and giving up (Phase 8, T19a Task 6). One more
/// than §7.7's own `MAX_DEPTH`: no LEGITIMATE tracked chain is ever longer
/// than that, so reaching this bound is itself the signal that the tracked
/// parent links have gone circular rather than proof that a real chain is
/// simply long.
const MAX_ANCESTOR_WALK: usize = roundhouse_bus::limits::MAX_DEPTH as usize + 1;

/// One live sub-agent session, plus the facts needed to retire it and to
/// remove its spawn-tree edge.
pub struct LiveSubAgent {
    /// The session that spawned this one — the `SpawnTree` key whose
    /// direct-child list holds this child.
    pub parent: SessionId,
    /// The depth §7.7 admitted this child at (`parent depth + 1`).
    pub depth: u8,
    session: HeadlessSession,
}

impl LiveSubAgent {
    /// Retires the child session: [`HeadlessSession::close_and_teardown`]'s
    /// exact sequence (abort the reaper, durably close the child's own event
    /// log with `outcome`, then deregister, tear down isolation, shut down
    /// MCP, deregister the egress token) — Phase 8, T19a Task 6. Before this
    /// task this called the durably-silent [`HeadlessSession::teardown`]
    /// instead, which is exactly the gap
    /// `workflow_host::reconcile_spawn_tree`'s own "KNOWN GAP" section
    /// documented: nothing ever wrote the terminal event boot recovery's
    /// filter was already looking for.
    ///
    /// A close failure (a durable store error, or `close_and_teardown`'s own
    /// timeout) is already logged at error level by `close_and_teardown`
    /// itself; this method has nothing further to add and does not
    /// propagate it — a caller freeing a fan-out slot has no way to report
    /// a per-child close failure onward either.
    ///
    /// # Why the bound comes from this child's own depth
    ///
    /// Through [`crate::session_manager::HeadlessSession::
    /// close_and_teardown_within`] with [`nested_close_timeout`]'s
    /// depth-derived budget, never the plain `close_and_teardown`'s
    /// outermost `SESSION_CLOSE_TIMEOUT`. A retirement driven by
    /// [`DaemonSubAgentHost::close_children`] runs INSIDE an ancestor's own
    /// close timeout, and a nested `tokio::time::timeout` created later with
    /// an equal bound can never fire first — it is dropped, timer and all,
    /// when the enclosing one elapses. A strictly smaller bound per level is
    /// what makes a wedged descendant get abandoned at its own level, where
    /// this call still runs the child's real teardown, rather than
    /// stranding the whole cascade at the root. `SESSION_CLOSE_TIMEOUT`'s
    /// own doc comment carries the full accounting.
    ///
    /// Module-private, and it does not touch the spawn tree, because it is
    /// only half of ending a sub-agent — [`SubAgentSessions::retire_child`]
    /// is the whole of it and the only way in from outside. The one other
    /// caller is `DaemonSubAgentHost::create_child_session`'s compensation
    /// for a session that was built but never tracked: that child has no
    /// committed edge to drop (the engine still owns its reservation), so
    /// closing and tearing down really is all of it there.
    async fn retire(
        self,
        outcome: SessionOutcome,
        registry: &SessionRegistry,
        proxy: &LoopbackProxy,
    ) {
        let _ = self
            .session
            .close_and_teardown_within(nested_close_timeout(self.depth), outcome, registry, proxy)
            .await;
    }
}

/// Every live sub-agent session this daemon owns, keyed by CHILD session id.
///
/// This is the `child -> parent` tracking structure the spawn path maintains;
/// see this module's own doc comment for why it exists and what deliberately
/// is not built on it yet.
#[derive(Default)]
pub struct SubAgentSessions {
    live: Mutex<HashMap<SessionId, LiveSubAgent>>,
}

impl SubAgentSessions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a newly created sub-agent and takes ownership of its live
    /// session handle.
    ///
    /// A poisoned lock tears the session down rather than leaking it, and
    /// reports failure — the caller's compensation (releasing the spawn-tree
    /// reservation, refunding the budget) then runs as it would for any other
    /// creation failure.
    fn insert(&self, child: SessionId, record: LiveSubAgent) -> Result<(), LiveSubAgent> {
        match self.live.lock() {
            Ok(mut guard) => {
                guard.insert(child, record);
                Ok(())
            }
            Err(_) => Err(record),
        }
    }

    /// The parent of `child`, if `child` is a live sub-agent of this daemon.
    pub fn parent_of(&self, child: SessionId) -> Option<SessionId> {
        self.live
            .lock()
            .ok()
            .and_then(|guard| guard.get(&child).map(|record| record.parent))
    }

    /// Every live sub-agent tracked here whose recorded parent is `parent` —
    /// the direct-child view of this module's `child -> parent` map, in the
    /// other direction from [`Self::parent_of`] (Phase 8, T19a Task 6).
    ///
    /// A snapshot `Vec`, not a live view: `DaemonSubAgentHost::close_children`
    /// retires each one in turn, and retiring a child awaits real teardown
    /// work — holding `self.live`'s lock across that would block every other
    /// caller of this map for as long as one child's isolation/MCP/proxy
    /// teardown takes.
    pub(crate) fn children_of(&self, parent: SessionId) -> Vec<SessionId> {
        self.live
            .lock()
            .map(|guard| {
                guard
                    .iter()
                    .filter(|(_, record)| record.parent == parent)
                    .map(|(child, _)| *child)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Rewires `child`'s reaper to [`ReapAction::RetireSubAgent`] — a no-op
    /// if `child` is not (or is no longer) tracked here (Phase 8, T19a Task
    /// 6). See [`crate::session_manager::HeadlessSession::rewire_reaper`]'s
    /// own doc comment for why `DaemonSubAgentHost::create_child_session`
    /// must call this only AFTER [`Self::insert`] has already recorded
    /// `child`, never before.
    pub(crate) fn rewire_reaper_for_retirement(
        &self,
        child: SessionId,
        registry: Arc<SessionRegistry>,
        proxy: Arc<LoopbackProxy>,
        sub_agents: Arc<SubAgentSessions>,
        tree: Arc<SpawnTree>,
    ) {
        if let Ok(mut guard) = self.live.lock() {
            if let Some(record) = guard.get_mut(&child) {
                record.session.rewire_reaper(
                    registry,
                    proxy,
                    ReapAction::RetireSubAgent { sub_agents, tree },
                );
            }
        }
    }

    /// Removes `child`'s record and hands back everything needed to retire it
    /// and to drop its spawn-tree edge.
    ///
    /// **Module-private on purpose.** A caller holding a [`LiveSubAgent`] it
    /// took out of this map owns a live session *and* a spawn-tree edge, and
    /// handing that pair out is how one of them gets forgotten. There are
    /// two public ways to end a tracked sub-agent, and both go through this:
    /// [`Self::retire_child`], which drops the edge and tears the session
    /// down itself in one call, and [`Self::take_for_reap`], which hands
    /// both back to a caller that commits to doing so itself.
    fn take(&self, child: SessionId) -> Option<LiveSubAgent> {
        self.live.lock().ok()?.remove(&child)
    }

    /// Removes `child`'s record and hands back its parent id and its live
    /// session handle — the edge and the session `Self::retire_child` would
    /// otherwise drop/tear down itself (Phase 8, T19a Task 5).
    ///
    /// **The caller MUST call [`SpawnTree::remove_child`] with the returned
    /// parent id and `child`, and MUST retire the returned
    /// [`HeadlessSession`] itself** (via
    /// [`crate::session_manager::HeadlessSession::teardown_from_reaper`], or
    /// whichever of that type's teardown paths fits the caller's own
    /// situation) — this method does neither. Use it instead of
    /// [`Self::retire_child`] only when the caller cannot safely go through
    /// [`crate::session_manager::HeadlessSession::teardown`]/
    /// [`crate::session_manager::HeadlessSession::close_and_teardown`] —
    /// today, `spawn_session_reaper`'s `RetireSubAgent` reap action, which
    /// runs from inside the very reaper task the returned session's own
    /// `JoinHandle` identifies, and for which both of those methods would
    /// self-abort.
    ///
    /// Idempotent for the same reason the private `take` it is built on is:
    /// a second call for an already-taken child finds no record and returns
    /// `None`.
    pub(crate) fn take_for_reap(
        &self,
        child: SessionId,
    ) -> Option<(SessionId, crate::session_manager::HeadlessSession)> {
        self.take(child)
            .map(|record| (record.parent, record.session))
    }

    /// Ends one live sub-agent: drops its parent's spawn-tree edge and tears
    /// the session down. Returns whether there was a live sub-agent to end.
    ///
    /// This is the sub-agent half of removal-on-termination, and the whole
    /// reason it is one method rather than three calls at a call site: a
    /// child that stops running without its edge being dropped holds one of
    /// its parent's eight §7.7 fan-out slots for the life of the daemon
    /// process. Taking the record, freeing the slot and retiring the session
    /// are one indivisible act, so the only way to do any of them is to do
    /// all three.
    ///
    /// The slot is freed **before** teardown rather than after: teardown
    /// awaits real isolation/MCP/proxy work, and the parent's ceiling should
    /// reflect "this child is finished", not "this child's mount has been
    /// unwound".
    ///
    /// Idempotent, because the map is the authority: a second call for the
    /// same child finds no record, returns `false`, and touches neither the
    /// tree nor the registry. So a duplicate termination signal cannot free a
    /// slot one of the child's live *siblings* is still holding, and cannot
    /// run [`HeadlessSession::close_and_teardown`] twice for one session —
    /// which would double-run [`SessionActor::close`](roundhouse_engine::SessionActor::close)
    /// (harmless — its own `close_lock`/`AlreadyClosed` short-circuit makes a
    /// second call a safe no-op) and, worse, double-run the real isolation
    /// teardown behind it, which is not guaranteed idempotent.
    ///
    /// # `outcome` and its terminal `SessionClosed`
    ///
    /// Phase 8, T19a Task 6: retiring a child now durably closes it — via
    /// [`HeadlessSession::close_and_teardown`] and, underneath that,
    /// [`SessionActor::close`](roundhouse_engine::SessionActor::close) —
    /// with `outcome` as the terminator's own recorded outcome, before
    /// tearing its real resources down. This is the terminal
    /// `SessionClosed` `workflow_host::reconcile_spawn_tree`'s own boot-time
    /// filter was already looking for and, before this task, nothing ever
    /// wrote. Two production paths reach it: `scheduler_driver::
    /// DeliveryExecutor::drive_workflow_agent_child`, which retires a
    /// workflow `agent:` step's child on every path driving it can finish —
    /// success, loop error, timeout, or a vanished session — mapping which
    /// one onto the terminator's own outcome (Phase 8, T19a Task 7) rather
    /// than passing the same value unconditionally; and `DaemonSubAgentHost::
    /// close_children`, which retires a closing session's own tracked
    /// children as one step of that session's own close. A tracked child
    /// whose own actor reaches `Closed` through neither of those two is
    /// retired by a separate path that does **not** call this method:
    /// `spawn_session_reaper`'s `RetireSubAgent` reap action (see
    /// `create_child_session`'s reaper wiring) runs `SubAgentSessions::
    /// take_for_reap` → `SpawnTree::remove_child` →
    /// `HeadlessSession::teardown_from_reaper` directly, never `retire_child`
    /// — this method goes through `HeadlessSession::close_and_teardown`,
    /// which aborts the reaper precisely to avoid a double teardown, so the
    /// reaper task cannot safely call back into the method that would abort
    /// it.
    pub async fn retire_child(
        &self,
        child: SessionId,
        outcome: SessionOutcome,
        tree: &SpawnTree,
        registry: &SessionRegistry,
        proxy: &LoopbackProxy,
    ) -> bool {
        let Some(record) = self.take(child) else {
            return false;
        };
        tree.remove_child(record.parent, child);
        record.retire(outcome, registry, proxy).await;
        true
    }

    /// How many live sub-agent sessions this daemon is holding.
    pub fn len(&self) -> usize {
        self.live.lock().map(|guard| guard.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Test-only direct insertion (Phase 8, T19a Task 5). The real path that
    /// populates this map is `DaemonSubAgentHost::create_child_session`,
    /// which (Phase 8, T19a Task 6) rewires each child's reaper from
    /// `ReapAction::Teardown` to `ReapAction::RetireSubAgent` once it is
    /// recorded here — this lets `spawn_session_reaper`'s own
    /// `RetireSubAgent` tests, in `session_manager`'s test module, exercise
    /// a tracked sub-agent record directly, without going through a real
    /// `create_child_session` call (isolation, egress registration, and a
    /// durable `SessionCreated` append) to get one.
    #[cfg(test)]
    pub(crate) fn insert_for_test(
        &self,
        child: SessionId,
        parent: SessionId,
        depth: u8,
        session: crate::session_manager::HeadlessSession,
    ) {
        if self
            .insert(
                child,
                LiveSubAgent {
                    parent,
                    depth,
                    session,
                },
            )
            .is_err()
        {
            panic!("the live-sub-agent map's lock is not poisoned in tests");
        }
    }
}

/// The real [`SubAgentHost`] for one session.
///
/// One instance per session, registered on that session's `SessionActor` by
/// [`wire_sub_agent_host`]. The shared state it reaches — the spawn tree, the
/// team registry, the live-sub-agent map — all lives on [`DaemonResources`],
/// so a host is a thin per-session view over daemon-wide owners, never a
/// second copy of any of them.
pub struct DaemonSubAgentHost {
    resources: Arc<DaemonResources>,
    registry: Arc<SessionRegistry>,
    /// The session this host serves — the one it was registered on. Used as
    /// the parent of everything it creates, and asserted against the engine's
    /// own idea of the parent so a mis-registration is loud rather than a
    /// silent cross-session spend.
    session: SessionId,
    depth: u8,
    /// The team this session belongs to. Always `None` today: nothing in this
    /// daemon joins a session to a team (`TeamRegistry::join` and the
    /// `team_create` tool have no production caller yet), and inventing a team
    /// here would let `agent_spawn`'s membership fence pass on a team the
    /// parent never joined.
    ///
    /// **This field must be wired before `team_create` becomes
    /// model-reachable.** The moment a model can put its session on a team,
    /// a host still reporting `None` silently skips `agent_spawn`'s two team
    /// fences (§7.5's membership check and its role clamp) for every spawn —
    /// a real authorization gap, not merely a missing feature. Whoever makes
    /// `team_create` reachable owns setting this.
    team: Option<TeamId>,
    budget: Arc<Mutex<Budget>>,
}

impl DaemonSubAgentHost {
    /// A host for a **root** session: depth 0 and the unmetered starting
    /// budget. Only a session with no parent may start from
    /// [`UNMETERED_SESSION_BUDGET`] — a spawned child starts from what its
    /// parent actually transferred, via [`Self::for_child`].
    pub fn for_root_session(
        resources: Arc<DaemonResources>,
        registry: Arc<SessionRegistry>,
        session: SessionId,
    ) -> Self {
        Self::new(
            resources,
            registry,
            session,
            0,
            Budget {
                remaining_tokens: UNMETERED_SESSION_BUDGET,
            },
        )
    }

    /// A host for a **spawned child**: the depth §7.7 admitted it at, and the
    /// budget `agent_spawn` actually moved into it.
    ///
    /// Both values come from the same `ChildSessionRequest` and are threaded
    /// for the same reason — §7.7's limits have to hold at every level of the
    /// tree, not just the first. A child seeded with the root default would
    /// hand its own sub-agents a pool nobody granted it.
    pub fn for_child(
        resources: Arc<DaemonResources>,
        registry: Arc<SessionRegistry>,
        child: SessionId,
        depth: u8,
        budget: Budget,
    ) -> Self {
        Self::new(resources, registry, child, depth, budget)
    }

    /// Private: the two public constructors above exist so that "unmetered is
    /// for roots only" is structural rather than a rule every call site has
    /// to remember.
    fn new(
        resources: Arc<DaemonResources>,
        registry: Arc<SessionRegistry>,
        session: SessionId,
        depth: u8,
        budget: Budget,
    ) -> Self {
        DaemonSubAgentHost {
            resources,
            registry,
            session,
            depth,
            team: None,
            budget: Arc::new(Mutex::new(budget)),
        }
    }
}

#[async_trait::async_trait]
impl SubAgentHost for DaemonSubAgentHost {
    fn spawn_tree(&self) -> &Arc<SpawnTree> {
        &self.resources.spawn_tree
    }

    fn teams(&self) -> &TeamRegistry {
        &self.resources.teams
    }

    fn budget(&self) -> Arc<Mutex<Budget>> {
        Arc::clone(&self.budget)
    }

    fn depth(&self) -> u8 {
        self.depth
    }

    fn team(&self) -> Option<TeamId> {
        self.team
    }

    async fn create_child_session(
        &self,
        req: ChildSessionRequest,
    ) -> Result<(), ChildSessionError> {
        // A host serves exactly one session; being asked to parent a child for
        // a different one means it was registered on the wrong actor, which
        // would spend this session's budget on another session's behalf.
        if req.parent != self.session {
            return Err(ChildSessionError {
                category: "sub_agent_host_mismatch",
                detail: format!(
                    "a sub-agent host for session {} was asked to parent a child of {}",
                    self.session, req.parent
                ),
            });
        }

        let spec = req.spec.clone();
        let headless = create_headless_session(
            &self.resources,
            &self.registry,
            req.child,
            // The original spec moves in here; the `spec` clone taken above
            // is the copy kept back for the durable `SessionCreated` below.
            req.spec,
            req.workspace_root,
            req.workspace_identity.map(|(device, _)| device),
            req.workspace_identity.map(|(_, inode)| inode),
        )
        .await
        .map_err(|err| ChildSessionError {
            category: err.kind(),
            detail: err.to_string(),
        })?;

        // The durable spawn-tree edge (§7.1 decision 4 wants one authority;
        // the in-memory `SpawnTree` dies with the process, this does not).
        // Written through `TaskRunner::record_session_created` +
        // `append_event_in_transaction`, exactly as
        // `WorkflowSessionTree::persist_child_session` writes a `call:`
        // child's — the two must be indistinguishable to whatever reads them
        // back at boot.
        if let Err(err) = self.persist_session_created(req.child, spec).await {
            // The session is real and running by this point; nothing else has
            // a handle on it, so it must be retired here rather than left for
            // the caller (which has none).
            headless
                .teardown(&self.registry, &self.resources.proxy)
                .await;
            return Err(err);
        }

        let record = LiveSubAgent {
            parent: req.parent,
            depth: req.depth,
            session: headless,
        };
        if let Err(orphan) = self.resources.sub_agents.insert(req.child, record) {
            orphan
                .retire(
                    SessionOutcome::Cancelled,
                    &self.registry,
                    &self.resources.proxy,
                )
                .await;
            return Err(ChildSessionError {
                category: "sub_agent_registry_unavailable",
                detail: "the live sub-agent map's lock is poisoned".to_string(),
            });
        }

        // Only NOW — after `insert` above has made this child findable in
        // `SubAgentSessions` — does it get a `RetireSubAgent` reaper instead
        // of the plain `ReapAction::Teardown` one `create_headless_session`
        // always starts a session with (Phase 8, T19a Task 6). Narrows,
        // rather than alone closes, the window this matters in: the
        // ORIGINAL `ReapAction::Teardown` reaper started inside
        // `create_headless_session` stays armed and independently watching
        // this exact session across the whole `persist_session_created`
        // await above, sharing this session's `HeadlessSession::torn_down`
        // flag — so even if that reaper fires before this line runs, it is
        // `finish_teardown`'s shared flag, not this
        // ordering, that stops it from tearing the real resources down
        // twice, and the `RetireSubAgent` reaper rewired in here still
        // finds (and correctly un-tracks) the child the moment it is
        // spawned, because `insert` already ran by construction. See
        // `HeadlessSession::finish_teardown`'s own doc comment for the full
        // argument.
        self.resources.sub_agents.rewire_reaper_for_retirement(
            req.child,
            Arc::clone(&self.registry),
            Arc::clone(&self.resources.proxy),
            Arc::clone(&self.resources.sub_agents),
            Arc::clone(&self.resources.spawn_tree),
        );

        // A sub-agent can spawn sub-agents of its own — at one greater depth,
        // and out of the budget it was actually given. Those two facts are
        // what make §7.7's `MAX_DEPTH` and its budget conservation mean
        // anything beyond the first level.
        match self.registry.actor(req.child) {
            Some(actor) => {
                actor.register_sub_agent_host(Arc::new(DaemonSubAgentHost::for_child(
                    Arc::clone(&self.resources),
                    Arc::clone(&self.registry),
                    req.child,
                    req.depth,
                    req.child_budget,
                )));
                // §6.8: "a child session's taint is seeded from its parent's
                // current `TaintSet` at spawn time." A freshly constructed
                // `SessionActor` already starts `Taint::Trusted`, so only
                // the tainted case needs an explicit mark.
                if req.taint.tainted {
                    actor.mark_tainted();
                }
            }
            // `create_headless_session` returned `Ok`, which means it
            // registered this session — so the only way here is the child
            // being retired between that return and this line. Never silent:
            // the spawn still reports success, and the child would be quietly
            // unable to spawn anything itself.
            None => tracing::warn!(
                session_id = %req.child,
                "a just-created sub-agent session was not in the registry; it will be unable \
                 to spawn sub-agents of its own"
            ),
        }

        Ok(())
    }

    /// Retires every session tracked in [`SubAgentSessions`] as a direct
    /// child of `parent`, depth-first, with [`SessionOutcome::Cancelled`]
    /// (Phase 8, T19a Task 6).
    ///
    /// Called by [`SessionActor::close`](roundhouse_engine::SessionActor::close)'s
    /// own step 4, from INSIDE `parent`'s own close — so this must return
    /// without deadlocking against it. It does, structurally: each child in
    /// [`SubAgentSessions::children_of`] is retired via
    /// [`SubAgentSessions::retire_child`], which durably closes that child's
    /// own actor before this call returns — and closing a child that itself
    /// has children recurses into THAT child's own registered host's
    /// `close_children`, driven by that child's own `SessionActor::close`,
    /// never by this method calling itself. This is what makes the walk
    /// depth-first: a child's whole subtree is retired before its next
    /// sibling is even looked at.
    ///
    /// A no-op — logged, never panicking — if `parent` is not the session
    /// this host was registered on: the symmetric fence
    /// [`Self::create_child_session`] applies for the same reason. A
    /// `SubAgentHost` answers for exactly one session; acting on any other
    /// would be a mis-registration bug, not a legitimate call.
    ///
    /// # A single snapshot can miss a child spawned during this very close
    ///
    /// `parent`'s own [`SessionActor::wait_idle`] step (run just before this
    /// one) does not bound every way a NEW child can appear here:
    /// `wait_idle` only waits on `WorkGuard`s, and
    /// `workflow_dispatch::dispatch_agent_for_workflow` —
    /// `scheduler_driver`'s path for a workflow `agent:` step — spawns a
    /// child without holding one. So a child can be admitted into
    /// [`SubAgentSessions`] after this method has already taken its first
    /// [`SubAgentSessions::children_of`] snapshot. This re-polls
    /// `children_of(parent)` — a full pass, retiring everything a pass
    /// finds — until a pass comes back empty, rather than acting on one
    /// snapshot, so a child that shows up mid-close is still retired rather
    /// than left tracked (holding a fan-out slot, its terminator never
    /// written) forever. Bounded to `MAX_FAN_OUT + 1` passes — one more
    /// than the most direct children a real parent can ever hold at once —
    /// so a pathologically fast, repeat spawner cannot wedge this close
    /// indefinitely; still-appearing children after the bound is spent are
    /// logged, not silently dropped.
    ///
    /// # Ancestor/cycle guard
    ///
    /// Ordering makes a cycle unreachable through the cascade itself:
    /// [`SubAgentSessions::retire_child`] `take`s a child's record out of
    /// the map before awaiting its close, so by the time that close
    /// recurses into the child's own `close_children`, the child's own
    /// record is already gone — [`Self::ancestors_of`] finds nothing above
    /// it there (`parent_of` on an already-taken session returns `None`),
    /// and nothing already retired earlier in this same cascade can ever be
    /// found (and therefore retried) again.
    ///
    /// What ordering does NOT cover is a direct
    /// [`SessionActor::close`](roundhouse_engine::SessionActor::close) on a
    /// session that is still fully tracked — nobody has `take`n anything
    /// yet, so a corrupted or cyclic tracked-parent graph could, in
    /// principle, list `parent` itself (or one of ITS OWN still-tracked
    /// ancestors) among what this walk would otherwise retire. Only
    /// `parent`'s own `close_lock` is provably held at this point — by the
    /// very `close()` call this method runs inside of — so re-entering it
    /// via a nested `retire_child(parent, ..)` would be the deadlock.
    /// Rather than pin down exactly which member of a corrupted chain is
    /// unsafe, [`Self::ancestors_of`] refuses `parent`'s WHOLE tracked
    /// ancestor chain as one conservative guard: never retiring one of
    /// `parent`'s own ancestors can never be more wrong than retiring it
    /// would be.
    ///
    /// Recursion depth is bounded independently of `ancestors_of`'s own
    /// (upward-only) walk: §7.7's `MAX_DEPTH` bounds how deep a LEGITIMATE
    /// tracked tree can ever be, and take-before-recurse (above) means this
    /// cascade can never revisit a session it has already retired — so even
    /// a corrupted graph can at worst make this walk visit each
    /// currently-tracked session once before running out of un-retired
    /// children to find.
    ///
    /// # The enclosing timeout bounds the WHOLE cascade this method drives, not one session
    ///
    /// This always runs inside some caller's `tokio::time::timeout` around
    /// `parent`'s own close, and which one depends on how `parent` was
    /// created:
    ///
    /// - A headless session (a scheduled delivery, a workflow `agent:`
    ///   step's child) is closed through
    ///   `HeadlessSession::close_and_teardown`, wrapped in
    ///   `session_manager`'s `SESSION_CLOSE_TIMEOUT`.
    /// - A session a client created over the socket has no `HeadlessSession`
    ///   at all — `socket_server::drive_session`'s `CreateSession` branch
    ///   spawns the reaper and discards the handle — so its close is wrapped
    ///   in `socket_server`'s own `CLOSE_SESSION_TIMEOUT` instead. Same
    ///   value as `SESSION_CLOSE_TIMEOUT` today, which is exactly why the
    ///   two have to be named separately rather than assumed to be one.
    ///
    /// The practical consequence here: if that enclosing timeout elapses
    /// while this method is mid-cascade, whatever child `retire_child`
    /// already `take`n out of `SubAgentSessions` but not yet finished
    /// retiring is abandoned with its reaper already aborted and its record
    /// already gone — nothing will ever retire it again.
    ///
    /// Each child's own nested close is bounded by
    /// `session_manager::nested_close_timeout`'s depth-derived budget,
    /// strictly smaller than the level above it. Because [`Self::
    /// close_children`] retires children serially, that step buys room for
    /// only the FIRST wedged child at a level: its nested bound fires
    /// before the enclosing one, so it is caught at its own level and still
    /// runs its own teardown. A later sibling at that level, or a chain
    /// whose earlier steps already spent the slack, is instead caught by
    /// the enclosing bound first, with no teardown of its own. What no
    /// ordering here buys is room for the whole cascade: `SESSION_CLOSE_
    /// TIMEOUT`'s own doc comment works through why even a non-wedged
    /// eight-child tree with MCP hosts can exhaust a 30s budget on
    /// designed-in grace periods alone.
    async fn close_children(&self, parent: SessionId) {
        if parent != self.session {
            tracing::error!(
                host_session = %self.session,
                parent = %parent,
                "a SubAgentHost was asked to close children for a session other than the one \
                 it was registered on; refusing rather than acting on a mismatched session"
            );
            return;
        }

        let ancestors = self.ancestors_of(parent);
        // One more pass than the most direct children a real parent can
        // ever hold at once — see this method's own "A single snapshot can
        // miss a child" section for why more than one pass is needed at
        // all, and why this bound rather than an unbounded re-poll.
        let max_passes = roundhouse_bus::limits::MAX_FAN_OUT as usize + 1;
        for _ in 0..max_passes {
            let children = self.resources.sub_agents.children_of(parent);
            if children.is_empty() {
                return;
            }
            for child in children {
                if ancestors.contains(&child) {
                    tracing::error!(
                        parent = %parent,
                        child = %child,
                        "skipping a tracked sub-agent edge that would revisit an ancestor while \
                         cascading a session close; the spawn tree is expected to be acyclic, \
                         so this indicates corrupted tracked state rather than a real spawn \
                         chain"
                    );
                    continue;
                }
                // A span carrying `parent` (and `child`, redundantly with
                // whatever field a failure inside logs under its own name)
                // so an operator reading a failed-close log line emitted
                // underneath — `close_and_teardown`'s own, which otherwise
                // names only the child — can still tie it back to the
                // cascade that caused it.
                let span = tracing::info_span!(
                    "close_children_retire",
                    parent = %parent,
                    child = %child
                );
                self.resources
                    .sub_agents
                    .retire_child(
                        child,
                        SessionOutcome::Cancelled,
                        &self.resources.spawn_tree,
                        &self.registry,
                        &self.resources.proxy,
                    )
                    .instrument(span)
                    .await;
            }
        }

        let still_appearing = self.resources.sub_agents.children_of(parent);
        if !still_appearing.is_empty() {
            tracing::error!(
                parent = %parent,
                remaining = still_appearing.len(),
                max_passes,
                "close_children exhausted its re-poll bound while children kept appearing; \
                 some may be left tracked against this parent"
            );
        }
    }
}

impl DaemonSubAgentHost {
    /// Appends the child's `SessionCreated` event — carrying
    /// `spec.parent = Some(parent)` — in its own immediate transaction.
    async fn persist_session_created(
        &self,
        child: SessionId,
        spec: roundhouse_core::SessionSpec,
    ) -> Result<(), ChildSessionError> {
        let event = self.resources.runner.record_session_created(
            child,
            0, // ignored — the append assigns the real per-session seq
            now_ts(),
            Box::new(spec),
            1,
        );
        let conn = self
            .resources
            .store
            .pool
            .get()
            .await
            .map_err(|err| ChildSessionError {
                category: "store_connection_unavailable",
                detail: err.to_string(),
            })?;
        conn.interact(move |connection| {
            let txn = roundhouse_store::begin_immediate(connection)?;
            // An empty `Redactor`, matching
            // `WorkflowSessionTree::persist_child_session`: a `SessionSpec`
            // carries a workspace id, a generated `agent-xxxxxxxx` handle, a
            // tier and a parent id — no secret values, and no session-scoped
            // redactor exists on this path to consult anyway.
            roundhouse_store::append_event_in_transaction(
                &txn,
                &event,
                &roundhouse_store::redact::Redactor::build(&[]),
            )?;
            txn.commit()?;
            Ok::<(), roundhouse_store::StoreError>(())
        })
        .await
        .map_err(|err| ChildSessionError {
            category: "store_interact_failed",
            detail: err.to_string(),
        })?
        .map_err(|err| ChildSessionError {
            category: "session_created_append_failed",
            detail: err.to_string(),
        })
    }

    /// `parent` and every session above it in [`SubAgentSessions`]' own
    /// tracked `child -> parent` chain, walked upward via
    /// [`SubAgentSessions::parent_of`].
    ///
    /// This is NOT "every session whose `close_lock` is currently held" —
    /// see [`Self::close_children`]'s own "Ancestor/cycle guard" section for
    /// the actual argument. Only `parent`'s own lock is provably held when
    /// `close_children` calls this; the rest of the returned chain is a
    /// cheap, conservative superset `close_children` refuses to revisit
    /// instead of proving exactly which member of a corrupted chain would
    /// be unsafe. In the ordinary cascade this returns just `{parent}`:
    /// `retire_child`'s take-before-recurse already removes each retired
    /// child's own record before its close reaches this method again for
    /// it, so `parent_of(parent)` is already `None` at every nested level.
    /// A longer chain only ever comes back when `close_children` is entered
    /// from a DIRECT `SessionActor::close` on a still-fully-tracked
    /// session, never mid-cascade.
    ///
    /// Bounded by [`MAX_ANCESTOR_WALK`] so a corrupted, circular tracked
    /// parent chain cannot hang this walk itself: `HashSet::insert` returning
    /// `false` (the chain looped back on itself) or the bound being reached
    /// both stop the walk immediately, at which point the set already
    /// contains everything this call needs to refuse.
    fn ancestors_of(&self, parent: SessionId) -> HashSet<SessionId> {
        let mut ancestors = HashSet::new();
        ancestors.insert(parent);
        let mut current = parent;
        for _ in 0..MAX_ANCESTOR_WALK {
            match self.resources.sub_agents.parent_of(current) {
                Some(next) if ancestors.insert(next) => current = next,
                _ => return ancestors,
            }
        }
        tracing::error!(
            session_id = %parent,
            "this session's tracked parent chain did not terminate within {MAX_ANCESTOR_WALK} \
             hops while cascading a session close; treating the spawn tree as corrupted rather \
             than walking it further"
        );
        ancestors
    }
}

/// `Timestamp` has no `now()`. Mirrors the identical helper in
/// `roundhouse-engine`'s `chat.rs`/`agent_loop.rs`.
fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

/// Gives `actor` — a ROOT session — the ability to spawn sub-agents.
///
/// Two production callers: `socket_server::drive_session`, after
/// `SessionRegistry::create` succeeds (a socket client is a human, not
/// somebody else's child), and, as of Phase 8 Task 25.5 (#62),
/// `session_manager::build_headless_session` (the scheduler's path via
/// `create_headless_session`) — a scheduled workflow session is equally a
/// ROOT session in the spawn-tree sense: the scheduler mints it directly,
/// never another session's `agent` tool call. Before #62, only the socket
/// path called this, so a workflow `agent:` step's spawn attempt would refuse
/// with a recorded `sub_agent_host_unavailable`; the daemon's `agent:` step
/// dispatch (`roundhouse-engine`'s `workflow_dispatch::dispatch_agent_for_workflow`)
/// relies on this being wired for both.
///
/// Sub-agent children never come through here — they get their host from
/// [`DaemonSubAgentHost::create_child_session`], the only caller that knows a
/// child's real depth and transferred budget.
pub fn wire_sub_agent_host(
    actor: &SessionActor,
    resources: &Arc<DaemonResources>,
    registry: &Arc<SessionRegistry>,
) {
    actor.register_sub_agent_host(Arc::new(DaemonSubAgentHost::for_root_session(
        Arc::clone(resources),
        Arc::clone(registry),
        actor.session_id(),
    )));
}

#[cfg(test)]
mod tests {
    //! End-to-end proof for the daemon half of the `agent` tool: a real
    //! `SessionActor` dispatching a real `agent` tool call through
    //! `roundhouse-engine`'s real dispatcher into this module's real host,
    //! producing a real registered child session with a durable parent edge.
    //!
    //! The provider round-trip is deliberately not part of this: proving the
    //! model can *reach* the dispatcher is `roundhouse-engine`'s
    //! `tests/agent_tool_spawn.rs`, which drives `run_agent_loop` with a
    //! scripted provider. These tests start one step later, at the same
    //! `dispatch_agent` entry point that loop calls, so the daemon half is
    //! covered without a second scripted provider.

    use super::*;
    use crate::session_bootstrap::DaemonResources;
    use crate::test_support::{
        available_isolate, daemon_resources, daemon_resources_with_rules, runner,
    };
    use roundhouse_core::{EventPayload, OnDegrade, SessionSpec, SessionState, TaskId, Tier};
    use roundhouse_engine::tools::agent_spawn_tool::dispatch_agent;
    use roundhouse_policy::engine::{CompiledRule, Outcome, PolicyEngine, Predicate, Scope};

    async fn resources(dir: &std::path::Path) -> Arc<DaemonResources> {
        Arc::new(daemon_resources(dir, None).await)
    }

    /// The `agent`-allowing rule every session built from these resources gets
    /// — including SPAWNED CHILDREN, whose own `PolicyEngine` is built by
    /// `create_real_session` from this same source. Needed by any test that
    /// has to get past a child's own admission gate to reach what happens
    /// after it.
    fn allow_agent_rules() -> crate::session_bootstrap::PolicyRuleSource {
        Arc::new(|| {
            vec![CompiledRule::test_new(
                Scope::Project,
                Outcome::Allow,
                Predicate::agent(None, None, Tier::None),
            )]
        })
    }

    async fn resources_allowing_agent_spawns(dir: &std::path::Path) -> Arc<DaemonResources> {
        Arc::new(daemon_resources_with_rules(dir, None, allow_agent_rules()).await)
    }

    /// A real parent `SessionActor` with an operator rule that allows `agent`
    /// spawns. Without such a rule `PolicyEngine::decide` falls through to
    /// `Ask` and every spawn is refused at admission — correct, and covered by
    /// the engine's own suite, but it would test nothing here.
    async fn parent_actor(dir: &std::path::Path) -> Arc<SessionActor> {
        let store = roundhouse_store::open(&dir.join("events.db"))
            .await
            .unwrap();
        let writer = roundhouse_store::spawn_writer(store).await;
        let policy = Arc::new(PolicyEngine::from_rules(vec![CompiledRule::test_new(
            Scope::Project,
            Outcome::Allow,
            Predicate::agent(None, None, Tier::None),
        )]));
        let isolate = available_isolate();
        let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
        let handle = isolate.prepare(&spec).await.unwrap();
        Arc::new(SessionActor::new_with_workspace_root(
            SessionId::new(),
            writer,
            SessionState::Running,
            runner(),
            policy,
            dir.join("state"),
            dir.join("daemon-binary"),
            dir.canonicalize().unwrap(),
            isolate,
            handle,
            spec,
            roundhouse_engine::tool_catalog::builtin_tool_defs(),
        ))
    }

    fn agent_args() -> serde_json::Value {
        serde_json::json!({
            "prompt": "review the diff",
            "provider": "anthropic",
            "budget_tokens": 250,
        })
    }

    /// Every `SessionCreated` spec recorded against `session`, newest last.
    async fn session_created_specs(
        db_path: &std::path::Path,
        session: SessionId,
    ) -> Vec<SessionSpec> {
        let reopened = roundhouse_store::open(db_path).await.unwrap();
        roundhouse_store::session_events(&reopened, session)
            .await
            .unwrap()
            .into_iter()
            .filter_map(|event| match event.payload {
                EventPayload::SessionCreated { spec, .. } => Some(*spec),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn an_agent_tool_call_creates_a_real_registered_child_with_a_durable_parent_edge() {
        let dir = tempfile::tempdir().unwrap();
        let resources = resources(dir.path()).await;
        let registry = Arc::new(SessionRegistry::new());
        let actor = parent_actor(dir.path()).await;
        let parent = actor.session_id();
        wire_sub_agent_host(&actor, &resources, &registry);

        let host = actor
            .sub_agent_host()
            .expect("the host was just registered");
        let result = dispatch_agent(
            &actor,
            actor.writer(),
            runner(),
            Some(&host),
            &agent_args(),
            TaskId::new(),
        )
        .await;
        assert!(result.is_ok(), "the spawn must succeed, got {result:?}");

        // Exactly one committed spawn-tree edge, no dangling reservation.
        assert_eq!(resources.spawn_tree.direct_children(parent), 1);
        assert_eq!(resources.spawn_tree.reserved_children(parent), 0);

        let child = resources.spawn_tree.descendants(parent)[0];

        // A REAL session: registered, running, retrievable by id.
        let child_actor = registry
            .actor(child)
            .expect("the spawned child must be a real, registered session");
        assert_eq!(child_actor.state(), SessionState::Running);

        // The child -> parent record, and ownership of the live session.
        assert_eq!(resources.sub_agents.parent_of(child), Some(parent));
        assert_eq!(resources.sub_agents.len(), 1);

        // The durable parent edge: a `SessionCreated` on the CHILD's own log
        // whose spec names the parent, which is what boot-time spawn-tree
        // recovery has to be able to read back.
        let specs = session_created_specs(&dir.path().join("events.db"), child).await;
        assert_eq!(specs.len(), 1, "exactly one SessionCreated for the child");
        assert_eq!(specs[0].parent, Some(parent));
        assert_eq!(specs[0].requested_tier, Tier::Sandbox);

        // A sub-agent can spawn sub-agents of its own, one level deeper —
        // which is the only thing that makes MAX_DEPTH mean anything past the
        // first level.
        let child_host = child_actor
            .sub_agent_host()
            .expect("a spawned child must itself be able to spawn");
        assert_eq!(child_host.depth(), 1);

        assert!(
            resources
                .sub_agents
                .retire_child(
                    child,
                    SessionOutcome::Cancelled,
                    &resources.spawn_tree,
                    &registry,
                    &resources.proxy
                )
                .await,
            "the live child must still be tracked"
        );
        assert!(registry.actor(child).is_none());
    }

    /// Phase 8 Task 25.5 (#62): the workflow-facing sibling of
    /// `dispatch_agent` reuses the identical reserve→admit→create→commit
    /// core (`agent_spawn_tool::spawn_child`) with workflow-shaped inputs —
    /// no `provider`/`budget_tokens` JSON to parse, since an `agent:` step's
    /// AST has neither.
    #[tokio::test]
    async fn dispatch_agent_for_workflow_creates_a_real_registered_child() {
        let dir = tempfile::tempdir().unwrap();
        let resources = resources(dir.path()).await;
        let registry = Arc::new(SessionRegistry::new());
        let actor = parent_actor(dir.path()).await;
        let parent = actor.session_id();
        wire_sub_agent_host(&actor, &resources, &registry);

        let host = actor
            .sub_agent_host()
            .expect("the host was just registered");
        let result = roundhouse_engine::workflow_dispatch::dispatch_agent_for_workflow(
            &actor,
            Some(&host),
            serde_json::json!({"prompt": "review the diff"}),
            None,
            250,
        )
        .await
        .expect("dispatch must not error");

        assert!(
            matches!(
                result.result,
                roundhouse_engine::workflow_dispatch::AgentSpawnOutcome::Spawned { .. }
            ),
            "the spawn must succeed, got {:?}",
            result.result
        );
        assert_eq!(
            resources.spawn_tree.direct_children(parent),
            1,
            "exactly one committed spawn-tree edge, no dangling reservation"
        );
        assert_eq!(resources.spawn_tree.reserved_children(parent), 0);

        let child = resources.spawn_tree.descendants(parent)[0];
        let child_actor = registry
            .actor(child)
            .expect("the spawned child must be a real, registered session");
        assert_eq!(child_actor.state(), SessionState::Running);
        assert_eq!(resources.sub_agents.parent_of(child), Some(parent));

        resources
            .sub_agents
            .retire_child(
                child,
                SessionOutcome::Cancelled,
                &resources.spawn_tree,
                &registry,
                &resources.proxy,
            )
            .await;
    }

    #[tokio::test]
    async fn a_second_spawn_draws_from_what_the_first_one_left() {
        let dir = tempfile::tempdir().unwrap();
        let resources = resources(dir.path()).await;
        let registry = Arc::new(SessionRegistry::new());
        let actor = parent_actor(dir.path()).await;
        let parent = actor.session_id();
        wire_sub_agent_host(&actor, &resources, &registry);
        let host = actor.sub_agent_host().unwrap();

        let before = host.budget().lock().unwrap().remaining_tokens;
        for _ in 0..2 {
            dispatch_agent(
                &actor,
                actor.writer(),
                runner(),
                Some(&host),
                &agent_args(),
                TaskId::new(),
            )
            .await
            .expect("both spawns must succeed");
        }

        assert_eq!(resources.spawn_tree.direct_children(parent), 2);
        assert_eq!(resources.sub_agents.len(), 2);
        assert_eq!(
            host.budget().lock().unwrap().remaining_tokens,
            before - 500,
            "§7.7: each transfer is a debit against the SAME session budget, so two \
             spawns cost twice"
        );

        for child in resources.spawn_tree.descendants(parent) {
            assert!(
                resources
                    .sub_agents
                    .retire_child(
                        child,
                        SessionOutcome::Cancelled,
                        &resources.spawn_tree,
                        &registry,
                        &resources.proxy
                    )
                    .await
            );
        }
    }

    /// **Budget conservation past depth 1.** A child's own host must start
    /// from what its parent actually transferred, not from a fresh
    /// [`UNMETERED_SESSION_BUDGET`].
    ///
    /// Asserted behaviourally, not just by reading the field back: the
    /// grandchild request below asks for more than the child was ever given,
    /// and must be refused. Seed the child at the root default instead and
    /// that same request succeeds — a child handing out a pool nobody granted
    /// it, which is the whole failure this threads `child_budget` to prevent.
    #[tokio::test]
    async fn a_child_spawns_out_of_the_budget_it_was_given_not_an_unmetered_pool() {
        let dir = tempfile::tempdir().unwrap();
        let resources = resources_allowing_agent_spawns(dir.path()).await;
        let registry = Arc::new(SessionRegistry::new());
        let actor = parent_actor(dir.path()).await;
        let parent = actor.session_id();
        wire_sub_agent_host(&actor, &resources, &registry);
        let host = actor.sub_agent_host().unwrap();

        // The parent transfers 250 tokens (see `agent_args`).
        dispatch_agent(
            &actor,
            actor.writer(),
            runner(),
            Some(&host),
            &agent_args(),
            TaskId::new(),
        )
        .await
        .expect("the first spawn must succeed");

        let child = resources.spawn_tree.descendants(parent)[0];
        let child_actor = registry.actor(child).unwrap();
        let child_host = child_actor.sub_agent_host().unwrap();

        assert_eq!(
            child_host.budget().lock().unwrap().remaining_tokens,
            250,
            "the child's host must start from the transfer, not the root default"
        );

        // The grandchild asks for more than the child ever had. `agent_spawn`
        // must refuse it, and the refusal must leave no edge behind.
        let grandchild = dispatch_agent(
            &child_actor,
            child_actor.writer(),
            runner(),
            Some(&child_host),
            &serde_json::json!({
                "prompt": "spend what my parent never gave me",
                "provider": "anthropic",
                "budget_tokens": 10_000,
            }),
            TaskId::new(),
        )
        .await;
        assert!(
            grandchild.is_err(),
            "a grandchild may not be granted more than its parent was transferred"
        );
        assert_eq!(resources.spawn_tree.direct_children(child), 0);
        assert_eq!(resources.spawn_tree.reserved_children(child), 0);
        assert_eq!(resources.sub_agents.len(), 1, "no grandchild was created");

        // ... and a grandchild that fits IS admitted, so the refusal above is
        // about the amount, not about children being unable to spawn at all.
        dispatch_agent(
            &child_actor,
            child_actor.writer(),
            runner(),
            Some(&child_host),
            &serde_json::json!({
                "prompt": "spend within my means",
                "provider": "anthropic",
                "budget_tokens": 100,
            }),
            TaskId::new(),
        )
        .await
        .expect("a grandchild within the child's transferred budget must be admitted");
        assert_eq!(resources.spawn_tree.direct_children(child), 1);
        assert_eq!(
            child_host.budget().lock().unwrap().remaining_tokens,
            150,
            "the grandchild's grant is debited from the child, not from thin air"
        );

        for session in resources.spawn_tree.descendants(parent) {
            resources
                .sub_agents
                .retire_child(
                    session,
                    SessionOutcome::Cancelled,
                    &resources.spawn_tree,
                    &registry,
                    &resources.proxy,
                )
                .await;
        }
    }

    /// **The sub-agent half of removal-on-termination**, against the real
    /// ceiling: a parent saturated at `MAX_FAN_OUT` gets a slot back when one
    /// child is retired, can spend it on a new sub-agent, and gets **exactly
    /// one** back however many times it is told the same child ended.
    ///
    /// Every child here is a real, registered session spawned through the
    /// real `agent` dispatcher, because the thing under test is that the
    /// count the ceiling is checked against is the count retirement changes —
    /// a hand-seeded `record_child` would prove that the tree subtracts, which
    /// `SpawnTree`'s own suite already covers, rather than that the spawn path
    /// and the retire path agree on which session is whose child.
    #[tokio::test]
    async fn a_retired_sub_agent_frees_exactly_one_of_its_parents_fan_out_slots() {
        let dir = tempfile::tempdir().unwrap();
        let resources = resources_allowing_agent_spawns(dir.path()).await;
        let registry = Arc::new(SessionRegistry::new());
        let actor = parent_actor(dir.path()).await;
        let parent = actor.session_id();
        wire_sub_agent_host(&actor, &resources, &registry);
        let host = actor.sub_agent_host().unwrap();

        let spawn = |args: serde_json::Value| {
            let actor = Arc::clone(&actor);
            let host = host.clone();
            async move {
                dispatch_agent(
                    &actor,
                    actor.writer(),
                    runner(),
                    Some(&host),
                    &args,
                    TaskId::new(),
                )
                .await
            }
        };

        for _ in 0..roundhouse_bus::limits::MAX_FAN_OUT {
            spawn(agent_args()).await.expect("under the ceiling");
        }
        assert_eq!(
            resources.spawn_tree.direct_children(parent),
            roundhouse_bus::limits::MAX_FAN_OUT
        );
        assert!(
            spawn(agent_args()).await.is_err(),
            "a saturated parent must be refused before the fix is even relevant"
        );

        let retired = resources.spawn_tree.descendants(parent)[0];
        assert!(
            resources
                .sub_agents
                .retire_child(
                    retired,
                    SessionOutcome::Cancelled,
                    &resources.spawn_tree,
                    &registry,
                    &resources.proxy
                )
                .await,
            "retiring a live sub-agent reports that it found one"
        );

        assert_eq!(
            resources.spawn_tree.direct_children(parent),
            roundhouse_bus::limits::MAX_FAN_OUT - 1,
            "the retired child's slot goes back"
        );
        assert!(
            registry.actor(retired).is_none(),
            "and the session really was torn down, not merely unhooked"
        );
        assert_eq!(
            resources.sub_agents.len(),
            (roundhouse_bus::limits::MAX_FAN_OUT - 1) as usize
        );

        spawn(agent_args())
            .await
            .expect("the freed slot is usable: a ninth spawn is admitted");
        assert_eq!(
            resources.spawn_tree.direct_children(parent),
            roundhouse_bus::limits::MAX_FAN_OUT
        );

        // Idempotency: a duplicate termination signal for a child that is
        // already gone must not free a slot one of its live siblings is
        // holding.
        assert!(
            !resources
                .sub_agents
                .retire_child(
                    retired,
                    SessionOutcome::Cancelled,
                    &resources.spawn_tree,
                    &registry,
                    &resources.proxy
                )
                .await,
            "a second retirement finds nothing to retire"
        );
        assert_eq!(
            resources.spawn_tree.direct_children(parent),
            roundhouse_bus::limits::MAX_FAN_OUT,
            "and frees no phantom slot"
        );
        assert!(
            spawn(agent_args()).await.is_err(),
            "so the parent is still saturated"
        );

        for session in resources.spawn_tree.descendants(parent) {
            resources
                .sub_agents
                .retire_child(
                    session,
                    SessionOutcome::Cancelled,
                    &resources.spawn_tree,
                    &registry,
                    &resources.proxy,
                )
                .await;
        }
    }

    /// **The gap `workflow_host::reconcile_spawn_tree`'s own "KNOWN GAP"
    /// section named is closed (Phase 8, T19a Task 6): `retire_child` now
    /// durably closes a retired child** (`HeadlessSession::close_and_teardown`
    /// → `SessionActor::close` → `EventWriter::close_session`), so a single
    /// restart's boot recovery already excludes it — no hand-written
    /// `SessionClosed` needed, because retiring the child is what writes one
    /// now.
    ///
    /// Every session here is real: spawned through the real `agent`
    /// dispatcher, retired through the real `retire_child`, and recovered by
    /// the real `reconcile_spawn_tree` over the real store this daemon wrote.
    #[tokio::test]
    async fn a_retired_sub_agent_child_does_not_reappear_after_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let resources = resources_allowing_agent_spawns(dir.path()).await;
        let registry = Arc::new(SessionRegistry::new());
        let actor = parent_actor(dir.path()).await;
        let parent = actor.session_id();
        wire_sub_agent_host(&actor, &resources, &registry);
        let host = actor.sub_agent_host().unwrap();

        for _ in 0..2 {
            dispatch_agent(
                &actor,
                actor.writer(),
                runner(),
                Some(&host),
                &agent_args(),
                TaskId::new(),
            )
            .await
            .expect("under the ceiling");
        }
        let children = resources.spawn_tree.descendants(parent);
        assert_eq!(children.len(), 2);
        let (retired, live) = (children[0], children[1]);

        assert!(
            resources
                .sub_agents
                .retire_child(
                    retired,
                    SessionOutcome::Cancelled,
                    &resources.spawn_tree,
                    &registry,
                    &resources.proxy
                )
                .await,
            "one child really is retired: in-memory, the slot is already back"
        );
        assert_eq!(resources.spawn_tree.direct_children(parent), 1);

        // The restart: a brand-new tree, rebuilt from durable state alone.
        let after_restart = Arc::new(SpawnTree::new());
        let tree = Arc::clone(&after_restart);
        resources
            .store
            .pool
            .get()
            .await
            .unwrap()
            .interact(move |conn| crate::workflow_host::reconcile_spawn_tree(conn, &tree).unwrap())
            .await
            .unwrap();

        assert_eq!(
            after_restart.descendants(parent),
            vec![live],
            "the retired child's own retire_child call already wrote its SessionClosed; only \
             the still-live child comes back"
        );

        resources
            .sub_agents
            .retire_child(
                live,
                SessionOutcome::Cancelled,
                &resources.spawn_tree,
                &registry,
                &resources.proxy,
            )
            .await;
    }

    /// **Closing a parent cascades**: `SessionActor::close`'s own step 4
    /// (`sub_agent_host().close_children`) reaches every real GRANDCHILD, not
    /// just direct children, and frees every fan-out slot along the way
    /// (Phase 8, T19a Task 6).
    ///
    /// This is a real two-level tree: `parent` spawns `child` through the
    /// real `agent` dispatcher, and `child` — over the same policy that let
    /// `parent` spawn it — spawns `grandchild` the same way. Closing only
    /// `parent` directly (never `child`, never `grandchild`) must still
    /// leave nothing tracked and no slot held anywhere in the tree, because
    /// `DaemonSubAgentHost::close_children` retires `child` through the real
    /// `retire_child` → `close_and_teardown` → `SessionActor::close` chain,
    /// and CLOSING `child` is what recurses into `child`'s own registered
    /// host to retire `grandchild` in turn — never a second, independent
    /// walk over `resources.spawn_tree`.
    #[tokio::test]
    async fn closing_a_parent_closes_its_grandchildren_and_frees_their_slots() {
        let dir = tempfile::tempdir().unwrap();
        let resources = resources_allowing_agent_spawns(dir.path()).await;
        let registry = Arc::new(SessionRegistry::new());
        let actor = parent_actor(dir.path()).await;
        let parent = actor.session_id();
        wire_sub_agent_host(&actor, &resources, &registry);
        let host = actor.sub_agent_host().unwrap();

        dispatch_agent(
            &actor,
            actor.writer(),
            runner(),
            Some(&host),
            &agent_args(),
            TaskId::new(),
        )
        .await
        .expect("the parent must be able to spawn its child");
        let child = resources.spawn_tree.descendants(parent)[0];
        let child_actor = registry
            .actor(child)
            .expect("the child must be a real, registered session");
        let child_host = child_actor
            .sub_agent_host()
            .expect("a spawned child must itself be able to spawn");

        dispatch_agent(
            &child_actor,
            child_actor.writer(),
            runner(),
            Some(&child_host),
            &agent_args(),
            TaskId::new(),
        )
        .await
        .expect("the child must be able to spawn its own grandchild");
        let grandchild = resources.spawn_tree.descendants(child)[0];
        assert!(
            registry.actor(grandchild).is_some(),
            "sanity: the grandchild is a real, registered session before closing anything"
        );

        // Sanity: two tracked sub-agents, one slot held at each level.
        assert_eq!(resources.sub_agents.len(), 2);
        assert_eq!(resources.spawn_tree.direct_children(parent), 1);
        assert_eq!(resources.spawn_tree.direct_children(child), 1);

        actor
            .close(roundhouse_core::SessionOutcome::Completed)
            .await
            .expect("closing a parent with no open tasks and no gate must succeed");

        assert!(
            resources.sub_agents.is_empty(),
            "closing the parent must retire both the child and the grandchild"
        );
        assert_eq!(
            resources.spawn_tree.direct_children(parent),
            0,
            "the child's slot on the parent must be freed"
        );
        assert_eq!(
            resources.spawn_tree.direct_children(child),
            0,
            "the grandchild's slot on the child must be freed too, not just the parent's own"
        );
        assert!(
            registry.actor(child).is_none(),
            "the child's real session must be torn down"
        );
        assert!(
            registry.actor(grandchild).is_none(),
            "the grandchild's real session must be torn down, proving the cascade reached two \
             levels deep, not just the parent's direct children"
        );
        assert_eq!(actor.state(), SessionState::Closed);
    }

    /// **A wedged tracked child is abandoned at ITS OWN depth-derived bound,
    /// not at the bound of whatever close it runs inside** (Phase 8, T19a
    /// Task 6).
    ///
    /// `LiveSubAgent::retire` hands `close_and_teardown_within`
    /// `session_manager::nested_close_timeout(depth)` rather than the
    /// outermost `SESSION_CLOSE_TIMEOUT`, because a nested
    /// `tokio::time::timeout` is always created later than the one enclosing
    /// it and so can only fire first if its bound is strictly smaller. Given
    /// equal bounds the nested timer is dead code — dropped, timer included,
    /// when the enclosing one elapses — and a permanently wedged descendant
    /// would strand the whole cascade instead of only itself.
    ///
    /// The wedge is the real one `SESSION_CLOSE_TIMEOUT`'s own doc comment
    /// names: a `WorkGuard` nothing ever drops, so `SessionActor::close`'s
    /// `wait_idle` step never returns. Both retirements below go through the
    /// real `retire_child` → `close_and_teardown_within` →
    /// `SessionActor::close` chain over real spawned sessions.
    ///
    /// Nothing sleeps and no real time passes: the clock is paused only
    /// AFTER the real spawns (whose own construction bounds should run
    /// against real time), and the elapsed VIRTUAL time across each
    /// retirement is exactly the budget whose timer fired — which is what
    /// distinguishes the depth-1 bound from the depth-2 one, and both from
    /// the root's.
    #[tokio::test]
    async fn a_wedged_child_is_abandoned_at_its_own_depth_derived_bound() {
        let dir = tempfile::tempdir().unwrap();
        let resources = resources_allowing_agent_spawns(dir.path()).await;
        let registry = Arc::new(SessionRegistry::new());
        let actor = parent_actor(dir.path()).await;
        let parent = actor.session_id();
        wire_sub_agent_host(&actor, &resources, &registry);
        let host = actor.sub_agent_host().unwrap();

        dispatch_agent(
            &actor,
            actor.writer(),
            runner(),
            Some(&host),
            &agent_args(),
            TaskId::new(),
        )
        .await
        .expect("the parent must be able to spawn its child");
        let child = resources.spawn_tree.descendants(parent)[0];
        let child_actor = registry.actor(child).expect("a real, registered child");
        let child_host = child_actor
            .sub_agent_host()
            .expect("a spawned child must itself be able to spawn");

        dispatch_agent(
            &child_actor,
            child_actor.writer(),
            runner(),
            Some(&child_host),
            &agent_args(),
            TaskId::new(),
        )
        .await
        .expect("the child must be able to spawn its own grandchild");
        let grandchild = resources.spawn_tree.descendants(child)[0];
        let grandchild_actor = registry
            .actor(grandchild)
            .expect("a real, registered grandchild");

        // Everything real is built; from here the only thing that moves the
        // clock is a close budget's own timer elapsing.
        tokio::time::pause();

        // The wedges: guards nothing ever drops, so neither session's own
        // `close()` can get past `wait_idle`.
        let _child_wedge = child_actor.begin_work();
        let _grandchild_wedge = grandchild_actor.begin_work();

        let started = tokio::time::Instant::now();
        assert!(
            resources
                .sub_agents
                .retire_child(
                    grandchild,
                    SessionOutcome::Cancelled,
                    &resources.spawn_tree,
                    &registry,
                    &resources.proxy
                )
                .await,
            "the wedged grandchild must still be tracked when it is retired"
        );
        let grandchild_elapsed = started.elapsed();
        assert!(
            grandchild_elapsed >= nested_close_timeout(2)
                && grandchild_elapsed < nested_close_timeout(1),
            "a depth-2 child's wedged close must be abandoned at the depth-2 budget ({:?}), \
             strictly before the budget of the level enclosing it ({:?}) — at that enclosing \
             budget this timer could never fire first at all; got {grandchild_elapsed:?}",
            nested_close_timeout(2),
            nested_close_timeout(1)
        );

        let started = tokio::time::Instant::now();
        assert!(
            resources
                .sub_agents
                .retire_child(
                    child,
                    SessionOutcome::Cancelled,
                    &resources.spawn_tree,
                    &registry,
                    &resources.proxy
                )
                .await,
            "the wedged child must still be tracked when it is retired"
        );
        let child_elapsed = started.elapsed();
        assert!(
            child_elapsed >= nested_close_timeout(1)
                && child_elapsed < crate::session_manager::SESSION_CLOSE_TIMEOUT,
            "a depth-1 child's wedged close must be abandoned at the depth-1 budget ({:?}), \
             strictly before the outermost bound its cascade runs inside ({:?}); got \
             {child_elapsed:?}",
            nested_close_timeout(1),
            crate::session_manager::SESSION_CLOSE_TIMEOUT
        );

        // Abandoning the close is not abandoning the session: both wedged
        // sessions are still fully un-tracked and torn down.
        assert!(resources.sub_agents.is_empty());
        assert_eq!(resources.spawn_tree.direct_children(parent), 0);
        assert_eq!(resources.spawn_tree.direct_children(child), 0);
        assert!(registry.actor(child).is_none());
        assert!(registry.actor(grandchild).is_none());
    }

    /// **A duplicate retirement signal for one child never frees a
    /// still-live SIBLING's slot** (Phase 8, T19a Task 6) — the same
    /// invariant `a_retired_sub_agent_frees_exactly_one_of_its_parents_fan_out_slots`
    /// proves against `MAX_FAN_OUT` siblings, isolated here to two, and
    /// against the new `outcome`-carrying `retire_child` signal a real
    /// close now sends.
    #[tokio::test]
    async fn a_duplicate_retirement_signal_never_frees_a_still_live_siblings_slot() {
        let dir = tempfile::tempdir().unwrap();
        let resources = resources_allowing_agent_spawns(dir.path()).await;
        let registry = Arc::new(SessionRegistry::new());
        let actor = parent_actor(dir.path()).await;
        let parent = actor.session_id();
        wire_sub_agent_host(&actor, &resources, &registry);
        let host = actor.sub_agent_host().unwrap();

        for _ in 0..2 {
            dispatch_agent(
                &actor,
                actor.writer(),
                runner(),
                Some(&host),
                &agent_args(),
                TaskId::new(),
            )
            .await
            .expect("under the ceiling");
        }
        let children = resources.spawn_tree.descendants(parent);
        assert_eq!(children.len(), 2);
        let (signaled, sibling) = (children[0], children[1]);

        assert!(
            resources
                .sub_agents
                .retire_child(
                    signaled,
                    SessionOutcome::Cancelled,
                    &resources.spawn_tree,
                    &registry,
                    &resources.proxy
                )
                .await,
            "the first signal finds a live child to retire"
        );
        assert_eq!(resources.spawn_tree.direct_children(parent), 1);
        assert_eq!(
            resources.sub_agents.parent_of(sibling),
            Some(parent),
            "the sibling must still be tracked, untouched"
        );
        assert!(registry.actor(sibling).is_some());

        // The duplicate signal: the same child, retired again.
        assert!(
            !resources
                .sub_agents
                .retire_child(
                    signaled,
                    SessionOutcome::Cancelled,
                    &resources.spawn_tree,
                    &registry,
                    &resources.proxy
                )
                .await,
            "a duplicate signal for an already-retired child finds nothing to retire"
        );
        assert_eq!(
            resources.spawn_tree.direct_children(parent),
            1,
            "the duplicate signal must not free the sibling's slot"
        );
        assert_eq!(
            resources.sub_agents.parent_of(sibling),
            Some(parent),
            "the sibling must still be tracked after the duplicate signal"
        );
        assert!(
            registry.actor(sibling).is_some(),
            "the sibling's real session must still be alive after the duplicate signal"
        );

        resources
            .sub_agents
            .retire_child(
                sibling,
                SessionOutcome::Cancelled,
                &resources.spawn_tree,
                &registry,
                &resources.proxy,
            )
            .await;
    }

    /// **The production reaper-rewiring path itself, not the hand-wired
    /// substitute** (Phase 8, T19a Task 6).
    ///
    /// Every other test in this module that ends a tracked child calls
    /// `retire_child` directly. This one instead spawns a real child through
    /// `create_child_session` (via `dispatch_agent`, exactly like every
    /// other test here) and then ends it by a route OTHER than
    /// `retire_child` — closing the child's own actor directly — so the
    /// only thing that can possibly retire it is the `ReapAction::
    /// RetireSubAgent` reaper `create_child_session` rewired in after
    /// `SubAgentSessions::insert`. `session_manager`'s own
    /// `a_sub_agent_child_closed_directly_is_retired_without_the_reaper_aborting_itself`
    /// proves the reap action's OWN dispatch logic in isolation, hand-wired
    /// via `insert_for_test`; this proves the real wiring that puts a
    /// `RetireSubAgent` reaper on a child in production at all.
    #[tokio::test]
    async fn a_child_closed_directly_is_retired_through_its_production_rewired_reaper() {
        let dir = tempfile::tempdir().unwrap();
        let resources = resources_allowing_agent_spawns(dir.path()).await;
        let registry = Arc::new(SessionRegistry::new());
        let actor = parent_actor(dir.path()).await;
        let parent = actor.session_id();
        wire_sub_agent_host(&actor, &resources, &registry);
        let host = actor.sub_agent_host().unwrap();

        dispatch_agent(
            &actor,
            actor.writer(),
            runner(),
            Some(&host),
            &agent_args(),
            TaskId::new(),
        )
        .await
        .expect("the parent must be able to spawn its child");
        let child = resources.spawn_tree.descendants(parent)[0];
        let child_actor = registry
            .actor(child)
            .expect("the child must be a real, registered session");

        // Close the child directly — never `retire_child`. If the child's
        // reaper is still `ReapAction::Teardown` (the bug this test would
        // catch), this tears down the child's OWN resources but leaves its
        // `SubAgentSessions` record and its parent's `SpawnTree` edge
        // behind forever.
        child_actor
            .close(roundhouse_core::SessionOutcome::Completed)
            .await
            .expect("closing a child with no open tasks and no gate must succeed");

        // No real-clock wait: `close()` already published `Closed` to the
        // state watch above, so the rewired reaper is already woken;
        // `yield_now` just lets it actually run.
        for _ in 0..1000 {
            if resources.sub_agents.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }

        assert!(
            resources.sub_agents.is_empty(),
            "the production-rewired RetireSubAgent reaper must remove this child's \
             SubAgentSessions record once its actor closes on its own"
        );
        assert_eq!(
            resources.spawn_tree.direct_children(parent),
            0,
            "the production-rewired reaper must drop the parent's SpawnTree edge"
        );
        assert!(
            registry.actor(child).is_none(),
            "the production-rewired reaper must still remove the registry entry"
        );
    }

    /// **`close_children`'s symmetric mismatch fence** (Phase 8, T19a Task
    /// 6): `create_child_session` already refuses to
    /// parent a child for a session other than the one it was registered
    /// on (`a_host_registered_on_the_wrong_session_refuses_to_parent_a_child`,
    /// below); `close_children` must refuse the same way for the same
    /// reason — a `SubAgentHost` answers for exactly one session.
    #[tokio::test]
    async fn close_children_refuses_a_session_other_than_the_one_it_serves() {
        let dir = tempfile::tempdir().unwrap();
        let resources = resources_allowing_agent_spawns(dir.path()).await;
        let registry = Arc::new(SessionRegistry::new());

        // Two independent parents, each with their own real child, so a
        // missing guard has something real to wrongly act on.
        let actor_a = parent_actor(dir.path()).await;
        wire_sub_agent_host(&actor_a, &resources, &registry);
        let host_a = actor_a.sub_agent_host().unwrap();
        dispatch_agent(
            &actor_a,
            actor_a.writer(),
            runner(),
            Some(&host_a),
            &agent_args(),
            TaskId::new(),
        )
        .await
        .expect("parent A must be able to spawn its child");

        let actor_b = parent_actor(dir.path()).await;
        let parent_b = actor_b.session_id();
        wire_sub_agent_host(&actor_b, &resources, &registry);
        let host_b = actor_b.sub_agent_host().unwrap();
        dispatch_agent(
            &actor_b,
            actor_b.writer(),
            runner(),
            Some(&host_b),
            &agent_args(),
            TaskId::new(),
        )
        .await
        .expect("parent B must be able to spawn its child");
        let child_b = resources.spawn_tree.descendants(parent_b)[0];

        assert_eq!(resources.sub_agents.len(), 2);

        // Host A is registered on parent A, not parent B — asking it to
        // close parent B's children must refuse rather than reach across
        // and retire a session it does not answer for.
        host_a.close_children(parent_b).await;

        assert_eq!(
            resources.sub_agents.len(),
            2,
            "close_children must refuse a session other than the one this host serves, not \
             act on a mismatched parent"
        );
        assert!(
            registry.actor(child_b).is_some(),
            "parent B's real child must be untouched by parent A's host"
        );
        assert_eq!(resources.spawn_tree.direct_children(parent_b), 1);

        for parent in [actor_a.session_id(), parent_b] {
            for child in resources.spawn_tree.descendants(parent) {
                resources
                    .sub_agents
                    .retire_child(
                        child,
                        SessionOutcome::Cancelled,
                        &resources.spawn_tree,
                        &registry,
                        &resources.proxy,
                    )
                    .await;
            }
        }
    }

    #[tokio::test]
    async fn a_host_registered_on_the_wrong_session_refuses_to_parent_a_child() {
        let dir = tempfile::tempdir().unwrap();
        let resources = resources(dir.path()).await;
        let registry = Arc::new(SessionRegistry::new());
        let actor = parent_actor(dir.path()).await;
        // A host bound to some OTHER session, registered on this actor — the
        // mis-registration that would otherwise spend a stranger's budget and
        // hang the child off a stranger's spawn tree.
        let stranger = SessionId::new();
        actor.register_sub_agent_host(Arc::new(DaemonSubAgentHost::for_root_session(
            Arc::clone(&resources),
            Arc::clone(&registry),
            stranger,
        )));
        let host = actor.sub_agent_host().unwrap();

        let result = dispatch_agent(
            &actor,
            actor.writer(),
            runner(),
            Some(&host),
            &agent_args(),
            TaskId::new(),
        )
        .await;

        assert!(result.is_err(), "a mismatched host must refuse");
        assert!(resources.sub_agents.is_empty());
        assert_eq!(resources.spawn_tree.direct_children(actor.session_id()), 0);
        assert_eq!(
            resources.spawn_tree.reserved_children(actor.session_id()),
            0
        );
    }

    #[tokio::test]
    async fn a_child_that_loses_the_registry_race_leaves_no_edge_and_no_tracked_session() {
        let dir = tempfile::tempdir().unwrap();
        let resources = resources(dir.path()).await;
        // A registry with no room at all: `create_headless_session` builds the
        // real session, fails to register it, tears it down and reports
        // `RegistryFull` — the step-4 failure edge, with a genuinely real
        // failure rather than a fake one.
        let registry = Arc::new(SessionRegistry::with_limits(0, 1));
        let actor = parent_actor(dir.path()).await;
        let parent = actor.session_id();
        wire_sub_agent_host(&actor, &resources, &registry);
        let host = actor.sub_agent_host().unwrap();
        let before = host.budget().lock().unwrap().remaining_tokens;

        let result = dispatch_agent(
            &actor,
            actor.writer(),
            runner(),
            Some(&host),
            &agent_args(),
            TaskId::new(),
        )
        .await;

        assert!(result.is_err());
        assert_eq!(
            resources.spawn_tree.reserved_children(parent),
            0,
            "the reservation must be released when the child could not be created"
        );
        assert_eq!(resources.spawn_tree.direct_children(parent), 0);
        assert!(resources.sub_agents.is_empty());
        assert_eq!(
            host.budget().lock().unwrap().remaining_tokens,
            before,
            "a child that was never created must not cost the parent its tokens"
        );
    }
}
