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
//!    child → parent direction, and it is what
//!    [`SubAgentSessions::retire_child`] — the one way to end a tracked
//!    sub-agent — uses to free the parent's fan-out slot as it tears the
//!    session down.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use roundhouse_bus::spawn_tree::SpawnTree;
use roundhouse_bus::teams::TeamRegistry;
use roundhouse_core::{SessionId, TeamId, Timestamp};
use roundhouse_engine::agent_spawn::Budget;
use roundhouse_engine::tools::agent_spawn_tool::{
    ChildSessionError, ChildSessionRequest, SubAgentHost,
};
use roundhouse_engine::SessionActor;
use roundhouse_net::proxy::LoopbackProxy;

use crate::session_bootstrap::DaemonResources;
use crate::session_manager::{create_headless_session, HeadlessSession};
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
    /// Retires the child session: [`HeadlessSession::teardown`]'s exact
    /// sequence (abort the reaper, deregister, tear down isolation, shut down
    /// MCP, deregister the egress token).
    ///
    /// Module-private, and it does not touch the spawn tree, because it is
    /// only half of ending a sub-agent — [`SubAgentSessions::retire_child`]
    /// is the whole of it and the only way in from outside. The one other
    /// caller is `DaemonSubAgentHost::create_child_session`'s compensation
    /// for a session that was built but never tracked: that child has no
    /// committed edge to drop (the engine still owns its reservation), so
    /// teardown really is all of it there.
    async fn retire(self, registry: &SessionRegistry, proxy: &LoopbackProxy) {
        self.session.teardown(registry, proxy).await;
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

    /// Removes `child`'s record and hands back everything needed to retire it
    /// and to drop its spawn-tree edge.
    ///
    /// **Module-private on purpose.** A caller holding a [`LiveSubAgent`] it
    /// took out of this map owns a live session *and* a spawn-tree edge, and
    /// handing that pair out is how one of them gets forgotten;
    /// [`Self::retire_child`] is the one public way to end a tracked
    /// sub-agent, and it closes both.
    fn take(&self, child: SessionId) -> Option<LiveSubAgent> {
        self.live.lock().ok()?.remove(&child)
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
    /// run [`HeadlessSession::teardown`] twice for one session — which that
    /// method's own doc comment explains is not safe, since
    /// `Isolate::teardown` is not guaranteed idempotent.
    ///
    /// # No production caller yet, and why that is the correct state
    ///
    /// Nothing in this workspace drives a session to `SessionState::Closed`
    /// ([`crate::session_manager::spawn_session_reaper`]'s own doc comment
    /// says so), and the `agent` tool hands the model a child id rather than
    /// running the child to completion — so today's callers are this crate's
    /// tests. That is deliberate rather than an oversight: Phase 8 L5's job
    /// is to wire this bookkeeping at the seam that owns it, so that whatever
    /// later drives a sub-agent to completion inherits a correct slot release
    /// by construction instead of having to remember one.
    pub async fn retire_child(
        &self,
        child: SessionId,
        tree: &SpawnTree,
        registry: &SessionRegistry,
        proxy: &LoopbackProxy,
    ) -> bool {
        let Some(record) = self.take(child) else {
            return false;
        };
        tree.remove_child(record.parent, child);
        record.retire(registry, proxy).await;
        true
    }

    /// How many live sub-agent sessions this daemon is holding.
    pub fn len(&self) -> usize {
        self.live.lock().map(|guard| guard.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
            orphan.retire(&self.registry, &self.resources.proxy).await;
            return Err(ChildSessionError {
                category: "sub_agent_registry_unavailable",
                detail: "the live sub-agent map's lock is poisoned".to_string(),
            });
        }

        // A sub-agent can spawn sub-agents of its own — at one greater depth,
        // and out of the budget it was actually given. Those two facts are
        // what make §7.7's `MAX_DEPTH` and its budget conservation mean
        // anything beyond the first level.
        match self.registry.actor(req.child) {
            Some(actor) => actor.register_sub_agent_host(Arc::new(DaemonSubAgentHost::for_child(
                Arc::clone(&self.resources),
                Arc::clone(&self.registry),
                req.child,
                req.depth,
                req.child_budget,
            ))),
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
                .retire_child(child, &resources.spawn_tree, &registry, &resources.proxy)
                .await,
            "the live child must still be tracked"
        );
        assert!(registry.actor(child).is_none());
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
                    .retire_child(child, &resources.spawn_tree, &registry, &resources.proxy)
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
                .retire_child(session, &resources.spawn_tree, &registry, &resources.proxy)
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
                .retire_child(retired, &resources.spawn_tree, &registry, &resources.proxy)
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
                .retire_child(retired, &resources.spawn_tree, &registry, &resources.proxy)
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
                .retire_child(session, &resources.spawn_tree, &registry, &resources.proxy)
                .await;
        }
    }

    /// **A KNOWN GAP, pinned so that closing it fails this test rather than
    /// going unnoticed** (see `workflow_host::reconcile_spawn_tree`'s own
    /// "KNOWN GAP" section for the full statement).
    ///
    /// `retire_child` ends a sub-agent child entirely in memory: it drops the
    /// map entry, removes the `SpawnTree` edge and tears the session down, and
    /// writes **nothing** durable. Nothing else in this workspace appends
    /// `SessionClosed` or `SessionStateChanged { state: Closed, .. }` either.
    /// So the only durable trace a retired sub-agent leaves is the
    /// `SessionCreated` that spawned it — and boot recovery, reading that,
    /// hands its parent's fan-out slot straight back to it.
    ///
    /// Both halves are asserted, and the second is what makes the first
    /// falsifiable rather than a shrug: the boot-recovery filter for a closed
    /// session **works**, over the same real store, the moment the event
    /// exists. What is missing is a writer, not the filter.
    ///
    /// Every session here is real: spawned through the real `agent`
    /// dispatcher, retired through the real `retire_child`, and recovered by
    /// the real `reconcile_spawn_tree` over the real store this daemon wrote.
    #[tokio::test]
    async fn a_retired_sub_agent_child_reappears_after_a_restart_known_gap() {
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
                .retire_child(retired, &resources.spawn_tree, &registry, &resources.proxy)
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

        let mut recovered = after_restart.descendants(parent);
        recovered.sort_by_key(|session| session.to_string());
        let mut both = vec![retired, live];
        both.sort_by_key(|session| session.to_string());
        assert_eq!(
            recovered, both,
            "THE GAP: the retired child is back, indistinguishable from the live one, \
             because its retirement was never written down anywhere"
        );

        // Now give the retired child the durable end signal this codebase can
        // already express but never writes, and restart again.
        let closed = runner().record_session_closed(
            retired,
            0,
            now_ts(),
            roundhouse_core::SessionOutcome::Completed,
            1,
        );
        resources
            .store
            .pool
            .get()
            .await
            .unwrap()
            .interact(move |conn| {
                let txn = roundhouse_store::begin_immediate(conn).unwrap();
                roundhouse_store::append_event_in_transaction(
                    &txn,
                    &closed,
                    &roundhouse_store::redact::Redactor::build(&[]),
                )
                .unwrap();
                txn.commit().unwrap();
            })
            .await
            .unwrap();

        let after_second_restart = Arc::new(SpawnTree::new());
        let tree = Arc::clone(&after_second_restart);
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
            after_second_restart.descendants(parent),
            vec![live],
            "with the end recorded, only the live child comes back — the filter is \
             there, a writer for it is not"
        );

        for session in resources.spawn_tree.descendants(parent) {
            resources
                .sub_agents
                .retire_child(session, &resources.spawn_tree, &registry, &resources.proxy)
                .await;
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
