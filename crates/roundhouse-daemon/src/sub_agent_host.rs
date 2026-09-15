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
//! 2. Retiring a sub-agent later needs to know which parent's `SpawnTree`
//!    edge to remove, and `SpawnTree` indexes parent → children only. This is
//!    the child → parent direction. Wiring that removal on child termination
//!    is a **separate, later task**; this module deliberately stops at
//!    [`SubAgentSessions::take`], which hands the whole record (parent, depth
//!    and the live session) to whoever adds it.

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
    /// Deliberately does NOT touch the spawn tree: removing the parent→child
    /// edge is the later removal-hook task's decision to make, together with
    /// whatever drives termination, and doing half of it here would leave that
    /// task with a partly-wired path to reason about.
    pub async fn retire(self, registry: &SessionRegistry, proxy: &LoopbackProxy) {
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

    /// Removes `child`'s record and hands the caller everything needed to
    /// retire it and to remove its spawn-tree edge. The entry point the
    /// removal-on-termination hook is meant to build on.
    pub fn take(&self, child: SessionId) -> Option<LiveSubAgent> {
        self.live.lock().ok()?.remove(&child)
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
    /// parent never joined. When team wiring lands, this is the field it sets.
    team: Option<TeamId>,
    budget: Arc<Mutex<Budget>>,
}

impl DaemonSubAgentHost {
    pub fn new(
        resources: Arc<DaemonResources>,
        registry: Arc<SessionRegistry>,
        session: SessionId,
        depth: u8,
    ) -> Self {
        DaemonSubAgentHost {
            resources,
            registry,
            session,
            depth,
            team: None,
            budget: Arc::new(Mutex::new(Budget {
                remaining_tokens: UNMETERED_SESSION_BUDGET,
            })),
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
            spec.clone(),
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

        // A sub-agent can spawn sub-agents of its own, at one greater depth —
        // which is the only thing that makes §7.7's `MAX_DEPTH` mean anything
        // beyond the first level.
        if let Some(actor) = self.registry.actor(req.child) {
            actor.register_sub_agent_host(Arc::new(DaemonSubAgentHost::new(
                Arc::clone(&self.resources),
                Arc::clone(&self.registry),
                req.child,
                req.depth,
            )));
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

/// Gives `actor` the ability to spawn sub-agents.
///
/// Called at every place this daemon finishes building a ROOT session — the
/// socket handshake and the headless (scheduled) path. Sub-agent children get
/// theirs from [`DaemonSubAgentHost::create_child_session`] instead, which is
/// the only caller that knows a child's real depth.
pub fn wire_sub_agent_host(
    actor: &SessionActor,
    resources: &Arc<DaemonResources>,
    registry: &Arc<SessionRegistry>,
) {
    actor.register_sub_agent_host(Arc::new(DaemonSubAgentHost::new(
        Arc::clone(resources),
        Arc::clone(registry),
        actor.session_id(),
        0,
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
    use crate::test_support::{available_isolate, daemon_resources, runner};
    use roundhouse_core::{EventPayload, OnDegrade, SessionSpec, SessionState, TaskId, Tier};
    use roundhouse_engine::tools::agent_spawn_tool::dispatch_agent;
    use roundhouse_policy::engine::{CompiledRule, Outcome, PolicyEngine, Predicate, Scope};

    async fn resources(dir: &std::path::Path) -> Arc<DaemonResources> {
        Arc::new(daemon_resources(dir, None).await)
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

        resources
            .sub_agents
            .take(child)
            .expect("the live child must still be tracked")
            .retire(&registry, &resources.proxy)
            .await;
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
            resources
                .sub_agents
                .take(child)
                .unwrap()
                .retire(&registry, &resources.proxy)
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
        actor.register_sub_agent_host(Arc::new(DaemonSubAgentHost::new(
            Arc::clone(&resources),
            Arc::clone(&registry),
            stranger,
            0,
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
