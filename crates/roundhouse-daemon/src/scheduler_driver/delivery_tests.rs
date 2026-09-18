use super::*;
use crate::session_registry::SessionRegistry;
use crate::test_support::{daemon_resources, daemon_resources_with_rules};
use crate::workspace_registry::{WorkspaceRegistration, WorkspaceRegistry};
use roundhouse_core::{Tier, WorkspaceId};
use roundhouse_flow::durability::{
    checkpoint_step, insert_workflow_run, recover_run, StepDisposition, StepRunState,
    WorkflowStepRun,
};
use roundhouse_flow::exec::run_loop::CrashRecoveryAnswer;
use roundhouse_flow::exec::StepStatus;
use roundhouse_flow::hitl::CrashResolution;
use roundhouse_flow::job::SessionTemplate;
use roundhouse_flow::job_store::register_workflow_file;
use roundhouse_policy::engine::{CompiledRule, Outcome as PolicyOutcome, Predicate, Scope};
use roundhouse_policy::FsOp;
use roundhouse_sched::delivery::DeliveryState;
use roundhouse_sched::store::fetch_delivery;
use roundhouse_store::StorePool;
use std::path::PathBuf;
use std::time::Duration;

/// The one instant every delivery test reckons against.
fn instant() -> DateTime<Utc> {
    DateTime::from_timestamp_nanos(1_700_000_000_000_000_000)
}

fn template() -> SessionTemplate {
    SessionTemplate {
        provider: "test".into(),
        model: "test-model".into(),
        cwd: "/tmp".into(),
        tools: vec![],
        isolation: Tier::Sandbox,
        permission_policy_ref: "default".into(),
    }
}

/// A workflow whose single step completes with no dispatch of any kind.
fn completing_workflow() -> String {
    "name: scheduled\nversion: 1\npermissions:\n  default: deny\n  unattended:\n    \
         escalate: fail\nsteps:\n  - id: result\n    emit: { value: ready }\n"
        .to_string()
}

fn reading_workflow() -> String {
    "name: scheduled-read\nversion: 1\npermissions:\n  default: deny\n  unattended:\n    \
         escalate: fail\nsteps:\n  - id: read_it\n    tool: read\n    with: { path: greeting.txt }\n"
            .to_string()
}

/// A workflow whose step fails: `no_such_fn` is not a function the
/// expression evaluator knows, so the step (and therefore the run) fails
/// — the same fixture `roundhouse-flow`'s own run-loop tests use.
fn failing_workflow() -> String {
    "name: scheduled\nversion: 1\npermissions:\n  default: deny\n  unattended:\n    \
         escalate: fail\nsteps:\n  - id: broken\n    emit: \"${{ no_such_fn(1) }}\"\n"
        .to_string()
}

/// A workflow that registers fine (its top-level document parses) but
/// whose *step graph* is a `needs:` cycle, which only `run_workflow`'s own
/// `parse_phase`/`topological_order` rejects. This is how a test reaches
/// the `Err(RunLoopError)` return from `run_workflow_from_storage` — an
/// infra-level failure calling into flow — as opposed to the ordinary
/// `Ok(RunOutcome::Terminal { state: Failed, .. })` a failing *step*
/// produces.
fn undrivable_workflow() -> String {
    "name: scheduled\nversion: 1\npermissions:\n  default: deny\n  unattended:\n    \
         escalate: fail\nsteps:\n  - id: a\n    needs: [b]\n    emit: { x: 1 }\n  - id: b\n    \
         needs: [a]\n    emit: { y: 2 }\n"
        .to_string()
}

/// A workflow that parks on a human gate — a real, valid non-terminal
/// outcome this driver deliberately does not resolve.
fn parking_workflow() -> String {
    "name: scheduled\nversion: 1\npermissions:\n  default: deny\n  unattended:\n    \
         escalate: fail\nsteps:\n  - id: approve\n    gate:\n      title: approve\n      \
         form: { approved: { type: boolean } }\n      timeout: 1h\n      on_timeout: deny\n"
        .to_string()
}

struct Harness {
    _dir: tempfile::TempDir,
    store: StorePool,
    resources: Arc<DaemonResources>,
    sessions: Arc<SessionRegistry>,
    executor: DeliveryExecutor,
    registry: Arc<InMemoryRunRegistry>,
    stored: StoredBinding,
    delivery: TriggerDelivery,
    workspace_root: PathBuf,
}

impl Harness {
    async fn delivery_row(&self) -> TriggerDelivery {
        let id = self.delivery.delivery_id.clone();
        let conn = self.store.pool.get().await.unwrap();
        conn.interact(move |connection| fetch_delivery(connection, &id).unwrap().unwrap())
            .await
            .unwrap()
    }

    fn active(&self) -> u32 {
        self.registry
            .active_run_count(self.stored.binding.id)
            .unwrap()
    }

    /// Accepts a second occurrence of the same binding, through the real
    /// `accept_occurrence`, and returns the delivery it created.
    async fn accept_another_occurrence(&self, seconds_later: i64) -> TriggerDelivery {
        let stored = self.stored.clone();
        let occurrence = ScheduledOccurrence {
            binding_id: stored.binding.id,
            scheduled_for: instant() + chrono::Duration::seconds(seconds_later),
            is_catch_up: false,
        };
        let fired_at = instant() + chrono::Duration::seconds(seconds_later);
        let registry = Arc::clone(&self.registry);
        let conn = self.store.pool.get().await.unwrap();
        let acceptance = conn
            .interact(move |connection| {
                roundhouse_sched::store::accept_occurrence(
                    connection,
                    &stored,
                    &occurrence,
                    fired_at,
                    registry.as_ref(),
                )
                .unwrap()
            })
            .await
            .unwrap();
        match acceptance {
            roundhouse_sched::store::Acceptance::New {
                delivery: Some(delivery),
                ..
            } => delivery,
            other => panic!("expected a second delivery, got {other:?}"),
        }
    }

    async fn state_of(&self, delivery_id: &str) -> DeliveryState {
        let id = delivery_id.to_string();
        let conn = self.store.pool.get().await.unwrap();
        conn.interact(move |connection| fetch_delivery(connection, &id).unwrap().unwrap().state)
            .await
            .unwrap()
    }

    async fn session_event_count(&self, session_id: SessionId) -> i64 {
        let conn = self.store.pool.get().await.unwrap();
        conn.interact(move |connection| {
            connection
                .query_row(
                    "SELECT COUNT(*) FROM events WHERE session_id = ?1",
                    rusqlite::params![session_id.to_string()],
                    |row| row.get(0),
                )
                .unwrap()
        })
        .await
        .unwrap()
    }

    /// The `SessionOutcome` this session's own `SessionClosed` terminator
    /// carries, or `None` if its log has no terminator at all — the direct
    /// evidence Phase 8, T19a Task 7's `DeliveryExecutor::close_and_retire`/
    /// `release_session` split exists to produce.
    async fn session_close_outcome(&self, session_id: SessionId) -> Option<SessionOutcome> {
        roundhouse_store::session_events(&self.store, session_id)
            .await
            .unwrap()
            .into_iter()
            .find_map(|event| match event.payload {
                EventPayload::SessionClosed { outcome } => Some(outcome),
                _ => None,
            })
    }

    async fn run_state(&self, run_id: RunId) -> RunState {
        let conn = self.store.pool.get().await.unwrap();
        conn.interact(move |connection| recover_run(connection, run_id).unwrap().run.state)
            .await
            .unwrap()
    }

    /// A second [`DeliveryExecutor`], sharing this harness's on-disk
    /// store and [`DaemonResources`] but wired to a **fresh** (empty)
    /// [`InMemoryRunRegistry`] and a fresh (empty) [`SessionRegistry`] —
    /// exactly what a restarted daemon process boots with. Task 7's
    /// recovery tests drive `recover_after_restart` against this, never
    /// `self.executor` (which still holds the charge `accept_occurrence`
    /// made against `self.registry` when the harness set the delivery
    /// up), so a passing assertion proves the *fresh* registry was
    /// correctly re-seeded rather than merely never zeroed.
    fn fresh_executor_after_restart(
        &self,
    ) -> (
        DeliveryExecutor,
        Arc<InMemoryRunRegistry>,
        Arc<SessionRegistry>,
    ) {
        let registry = Arc::new(InMemoryRunRegistry::new());
        let sessions = Arc::new(SessionRegistry::new());
        let executor = DeliveryExecutor::new(
            self.store.clone(),
            Arc::clone(&self.resources),
            Arc::clone(&sessions),
            Arc::clone(&registry),
            Arc::clone(&self.resources.spawn_tree),
            Arc::new(FixedClock(instant())),
        );
        (executor, registry, sessions)
    }

    /// Like [`Self::fresh_executor_after_restart`], but wired to a fresh
    /// [`DaemonResources`] whose `workspace_registry` is `None` —
    /// forcing `DeliveryExecutor::rebuild_and_drive_recovered_run` to
    /// fail with `DeliveryError::NoWorkspaceRegistry` before it builds
    /// anything, standing in for any pre-run infra failure (session
    /// construction, workspace resolution, a store error). Used by the
    /// fix-round-1 regression test pinning that such a failure, reached
    /// only after `control::cancel` already committed `Cancelling`,
    /// must not fail the delivery to a terminal state.
    async fn fresh_executor_after_restart_without_workspace_registry(
        &self,
    ) -> (
        DeliveryExecutor,
        Arc<InMemoryRunRegistry>,
        Arc<SessionRegistry>,
    ) {
        let registry = Arc::new(InMemoryRunRegistry::new());
        let sessions = Arc::new(SessionRegistry::new());
        let resources = Arc::new(daemon_resources(self._dir.path(), None).await);
        let spawn_tree = Arc::clone(&resources.spawn_tree);
        let executor = DeliveryExecutor::new(
            self.store.clone(),
            resources,
            Arc::clone(&sessions),
            Arc::clone(&registry),
            spawn_tree,
            Arc::new(FixedClock(instant())),
        );
        (executor, registry, sessions)
    }

    /// Simulates a previous daemon process that reserved `self.delivery`,
    /// created its `workflow_run` row in `state`, and (for every state
    /// other than a bare reservation) marked the delivery `running` —
    /// then crashed before ever calling `run_workflow_from_storage`
    /// itself. Returns the `RunId`/`SessionId` a recovery test asserts
    /// against.
    ///
    /// This is the harness-level counterpart to
    /// `DeliveryExecutor::run_claimed_delivery`'s own reserve/resolve/
    /// insert-run-row/mark-running sequence, stopped one step short of
    /// actually driving the workflow — precisely the crash window
    /// restart recovery exists to close.
    async fn simulate_running_before_crash_with_state(
        &self,
        run_state: RunState,
    ) -> (RunId, SessionId) {
        let run_id = RunId::new();
        let session_id = SessionId::new();
        let delivery_id = self.delivery.delivery_id.clone();
        let job_id = self.stored.binding.job_id;
        let binding_id = self.stored.binding.id;
        let trigger_event_id = self.delivery.trigger_event_id;
        let workspace_root = self.workspace_root.clone();
        let conn = self.store.pool.get().await.unwrap();
        conn.interact(move |connection| {
            assert!(lease_delivery(
                connection,
                &delivery_id,
                Timestamp::from_unix_nanos(i64::MAX),
                Timestamp::from_unix_nanos(0),
            )
            .unwrap());
            assert!(reserve_delivery(
                connection,
                &delivery_id,
                &run_id.as_uuid().to_string(),
                session_id,
                Timestamp::from_unix_nanos(0),
            )
            .unwrap());
            let resolved = resolve_latest_by_job_id(connection, &workspace_root, job_id)
                .unwrap()
                .expect("the harness always registers the binding's job");
            let version = resolved.job.latest();
            let run = WorkflowRun {
                id: run_id,
                job_id,
                job_version: version.version(),
                content_hash: content_hash(version),
                session_id,
                binding_id: Some(binding_id),
                trigger_event_id: Some(trigger_event_id),
                state: RunState::Running,
                parent_run_id: None,
                forked_from_run_id: None,
                awaiting_until: None,
                checkpoint_ref: None,
                checkpoint_blob_ref: None,
                started_at: Timestamp::from_unix_nanos(0),
                ended_at: None,
                session_depth: Some(0),
                caps: Some(ResourceCaps::default()),
            };
            insert_workflow_run(connection, &run).unwrap();
            assert!(
                mark_delivery_running(connection, &delivery_id, Timestamp::from_unix_nanos(0))
                    .unwrap()
            );
            // The run row was just inserted `Running`; walk it to
            // `run_state` through `transition_is_legal`'s actual matrix
            // rather than writing an illegal hop (`Cancelled` needs two:
            // `Running -> Cancelling -> Cancelled`).
            let now = Timestamp::from_unix_nanos(0);
            match run_state {
                RunState::Running => {}
                RunState::Cancelled => {
                    roundhouse_flow::durability::transition_run(
                        connection,
                        run_id,
                        RunState::Cancelling,
                        now,
                    )
                    .unwrap();
                    roundhouse_flow::durability::transition_run(
                        connection,
                        run_id,
                        RunState::Cancelled,
                        now,
                    )
                    .unwrap();
                }
                other => {
                    roundhouse_flow::durability::transition_run(connection, run_id, other, now)
                        .unwrap();
                }
            }
        })
        .await
        .unwrap();
        (run_id, session_id)
    }

    /// [`Self::simulate_running_before_crash_with_state`] followed by
    /// `request_cancellation`, moving the delivery from `running` to
    /// `cancellation_requested` — the shape a live `CancelPrevious`
    /// admission decision leaves behind when the daemon then crashes
    /// before ever calling `control::cancel` against it.
    async fn simulate_cancellation_requested_before_crash(
        &self,
        run_state: RunState,
    ) -> (RunId, SessionId) {
        let (run_id, session_id) = self
            .simulate_running_before_crash_with_state(run_state)
            .await;
        let delivery_id = self.delivery.delivery_id.clone();
        let conn = self.store.pool.get().await.unwrap();
        let applied = conn
            .interact(move |connection| {
                roundhouse_sched::store::request_cancellation(
                    connection,
                    &delivery_id,
                    DeliveryState::Running,
                    Timestamp::from_unix_nanos(0),
                )
            })
            .await
            .unwrap()
            .unwrap();
        assert!(applied, "the simulated delivery must actually be `running`");
        (run_id, session_id)
    }
}

/// Builds a real workspace, a real registered job, a real `ready`
/// delivery (through `accept_occurrence`, so the admission slot is
/// genuinely charged), and an executor wired to all of it.
async fn harness(workflow_yaml: String) -> Harness {
    harness_with_overlap(workflow_yaml, OverlapPolicy::Skip).await
}

async fn harness_with_overlap(workflow_yaml: String, overlap: OverlapPolicy) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let workspace_root = dir.path().join("workspace");
    std::fs::create_dir(&workspace_root).unwrap();
    let source = workspace_root.join("workflow.yaml");
    std::fs::write(&source, workflow_yaml).unwrap();

    let store = roundhouse_store::open(&dir.path().join("events.db"))
        .await
        .unwrap();
    let workspaces = Arc::new(
        WorkspaceRegistry::open(
            roundhouse_store::open(&dir.path().join("events.db"))
                .await
                .unwrap(),
        )
        .await
        .unwrap(),
    );
    let workspace = workspaces
        .register(WorkspaceRegistration::new(
            "scheduled-workspace",
            workspace_root.clone(),
        ))
        .await
        .unwrap();
    // The canonical root the registry resolved, not the raw tempdir path
    // — `register_workflow_file` canonicalizes both sides and would
    // otherwise reject the source as outside the workspace on a platform
    // whose temp directory is a symlink.
    let workspace_root = workspace.root.clone();
    let source = workspace_root.join("workflow.yaml");

    let job_id = {
        let conn = store.pool.get().await.unwrap();
        let root = workspace_root.clone();
        conn.interact(move |connection| {
            register_workflow_file(connection, &root, &source, template())
                .unwrap()
                .job
                .id()
        })
        .await
        .unwrap()
    };

    let mut binding = Binding::new(
        job_id,
        TriggerSpec::Interval {
            every: Duration::from_secs(60),
            align: false,
            anchor: None,
        },
    );
    binding.overlap = overlap;
    let stored = StoredBinding {
        workspace: workspace.id,
        binding,
    };

    let registry = Arc::new(InMemoryRunRegistry::new());
    let due = vec![(
        stored.clone(),
        ScheduledOccurrence {
            binding_id: stored.binding.id,
            scheduled_for: instant(),
            is_catch_up: false,
        },
    )];
    {
        let conn = store.pool.get().await.unwrap();
        let tick_registry = Arc::clone(&registry);
        conn.interact(move |connection| {
            accept_due_occurrences(connection, &due, instant(), tick_registry.as_ref());
        })
        .await
        .unwrap();
    }
    let delivery = {
        let conn = store.pool.get().await.unwrap();
        conn.interact(|connection| list_ready_deliveries(connection, 10).unwrap())
            .await
            .unwrap()
            .pop()
            .expect("accept_occurrence must have created one ready delivery")
    };
    assert_eq!(
        registry.active_run_count(stored.binding.id).unwrap(),
        1,
        "this harness proves nothing about release unless the slot was really charged"
    );

    let sessions = Arc::new(SessionRegistry::new());
    let resources = Arc::new(daemon_resources(dir.path(), Some(Arc::clone(&workspaces))).await);
    let executor = DeliveryExecutor::new(
        store.clone(),
        Arc::clone(&resources),
        Arc::clone(&sessions),
        Arc::clone(&registry),
        Arc::clone(&resources.spawn_tree),
        Arc::new(FixedClock(instant())),
    );

    Harness {
        _dir: dir,
        store,
        resources,
        sessions,
        executor,
        registry,
        stored,
        delivery,
        workspace_root,
    }
}

/// Task 1 of the sub-agent spawn-tracking plan: `DaemonResources` is now
/// the single, daemon-wide owner of the `SpawnTree`, and
/// `DeliveryExecutor::new` takes it as a parameter instead of minting its
/// own — because the `agent` tool (through `DaemonSubAgentHost`) reads
/// the very same `Arc<SpawnTree>` off `DaemonResources`, and the two must
/// never disagree about a session's recorded children.
///
/// Instance identity (`Arc::ptr_eq`) alone would pass for two separately
/// empty, structurally-equal trees, so this also proves it behaviorally:
/// a child recorded through the `DaemonResources` handle must be visible
/// through the `DeliveryExecutor`-constructed handle.
#[tokio::test]
async fn the_executor_shares_daemon_resources_spawn_tree_rather_than_minting_its_own() {
    let harness = harness(completing_workflow()).await;

    assert!(
        Arc::ptr_eq(&harness.resources.spawn_tree, &harness.executor.spawn_tree),
        "DeliveryExecutor must share DaemonResources' spawn tree rather than construct its \
             own"
    );

    let parent = SessionId::new();
    let child = SessionId::new();
    harness.resources.spawn_tree.record_child(parent, child);
    assert_eq!(
        harness.executor.spawn_tree.direct_children(parent),
        1,
        "a child recorded through DaemonResources' handle must be visible through the \
             DeliveryExecutor's handle — proof of one shared tree, not two structurally-equal \
             ones"
    );
}

#[tokio::test]
async fn a_ready_delivery_runs_its_workflow_and_releases_its_admission_slot() {
    let harness = harness(completing_workflow()).await;

    harness
        .executor
        .claim_and_run(harness.delivery.clone(), harness.stored.clone())
        .await;

    let row = harness.delivery_row().await;
    assert_eq!(
        row.state,
        DeliveryState::Delivered,
        "a completed run must complete its delivery; last_error was {:?}",
        row.last_error
    );
    let run_id = RunId::from_uuid(
        Uuid::parse_str(row.run_id.as_deref().expect("reserve stamps a run id")).unwrap(),
    );
    let session_id = row.session_id.expect("reserve stamps a session id");

    let run = {
        let conn = harness.store.pool.get().await.unwrap();
        conn.interact(move |connection| recover_run(connection, run_id).unwrap().run)
            .await
            .unwrap()
    };
    assert_eq!(run.session_id, session_id);
    assert_eq!(
        run.binding_id,
        Some(harness.stored.binding.id),
        "the run must be attributable back to the binding that scheduled it"
    );
    assert_eq!(
        run.trigger_event_id,
        Some(harness.delivery.trigger_event_id),
        "the run must be attributable back to the occurrence that fired it"
    );
    assert_eq!(
        run.session_depth,
        Some(0),
        "a root run with no recorded depth is inert — admit_call_from_run refuses it"
    );
    assert_eq!(
        run.caps,
        Some(ResourceCaps::default()),
        "a run with no recorded caps is inert — LedgerError::CapsNotRecorded refuses it"
    );
    assert_eq!(run.state, RunState::Completed);

    assert_eq!(
        harness.active(),
        0,
        "a completed delivery must release the admission slot accept_occurrence charged, \
             or this binding never fires again"
    );
    // The session was real: its `SessionCreated` event and the run's own
    // task events are both in its durable log. That log is what makes a
    // scheduled run openable afterwards — it survives the registry entry,
    // which is live-actor bookkeeping, not the session's record.
    assert!(
        harness.session_event_count(session_id).await > 1,
        "the run's task events must reach the session's log, not just its SessionCreated"
    );
    assert!(
        harness.sessions.actor(session_id).is_none(),
        "a terminal delivery must RETIRE its session — spawn_session_reaper waits on a \
             `Closed` nothing produces, so without an explicit teardown a per-delivery \
             session would live for the daemon's whole life and fill max_sessions"
    );
    // Phase 8, T19a Task 7: a completed run's session must carry a real `SessionClosed`
    // terminator, not just be torn down in memory.
    match harness.session_close_outcome(session_id).await {
        Some(SessionOutcome::Completed) => {}
        other => panic!(
            "a completed delivery must close its session with a Completed terminator, got \
                 {other:?}"
        ),
    }
}

#[tokio::test]
async fn a_failing_workflow_fails_its_delivery_and_still_releases_the_slot() {
    let harness = harness(failing_workflow()).await;

    harness
        .executor
        .claim_and_run(harness.delivery.clone(), harness.stored.clone())
        .await;

    let row = harness.delivery_row().await;
    assert_eq!(row.state, DeliveryState::Failed);
    assert!(
        row.last_error.as_deref().is_some_and(|e| !e.is_empty()),
        "a failed delivery must say why, got {:?}",
        row.last_error
    );
    assert_eq!(row.attempts, 1, "fail_delivery counts the attempt");
    assert_eq!(
        harness.active(),
        0,
        "a FAILED run must release its slot too — a held slot wedges the binding shut \
             exactly like the never-released case"
    );
    let session_id = row.session_id.expect("reserve stamps a session id");
    assert!(
        harness.sessions.actor(session_id).is_none(),
        "a FAILED run must retire its session too, or a binding that fails every minute \
             fills max_sessions just as fast as one that succeeds"
    );
    // Phase 8, T19a Task 7: `RunState::Failed` maps to `SessionOutcome::Failed`, carrying
    // the state's own wire name — never a free-text sentence.
    match harness.session_close_outcome(session_id).await {
        Some(SessionOutcome::Failed { reason }) => {
            assert_eq!(reason, RunState::Failed.wire_name());
        }
        other => panic!(
            "a failed delivery must close its session with a Failed terminator naming the \
                 run's own wire name, got {other:?}"
        ),
    }
}

/// A parked run is not terminal. Completing or failing its delivery would
/// be a lie, and releasing its slot would let the same binding start a
/// second run on top of one that is still live.
#[tokio::test]
async fn a_parked_run_leaves_its_delivery_running_and_holds_its_slot() {
    let harness = harness(parking_workflow()).await;

    harness
        .executor
        .claim_and_run(harness.delivery.clone(), harness.stored.clone())
        .await;

    let row = harness.delivery_row().await;
    assert_eq!(
        row.state,
        DeliveryState::Running,
        "a parked run's delivery must stay `running`; last_error was {:?}",
        row.last_error
    );
    assert!(row.last_error.is_none());
    assert_eq!(
        harness.active(),
        1,
        "a parked run is still live, so its admission slot must stay held"
    );
    let session_id = row.session_id.expect("reserve stamps a session id");
    assert!(
        harness.sessions.actor(session_id).is_some(),
        "a parked run's session must NOT be retired — the resume that answers its gate \
             runs in this session"
    );
    // Phase 8, T19a Task 7: a parked run is not terminal, so its session must carry no
    // `SessionClosed` terminator at all.
    assert!(
        harness.session_close_outcome(session_id).await.is_none(),
        "a parked run's session must not be closed — writing a terminator here would make \
             the eventual resume's own appends trip the store's tail guard"
    );
}

/// Losing the `ready -> leased` race is an ordinary no-op: this claimer
/// never owned the delivery, so it must neither touch the row nor release
/// a slot whose real owner will release it.
#[tokio::test]
async fn a_delivery_someone_else_already_leased_is_skipped_without_release() {
    let harness = harness(completing_workflow()).await;

    let id = harness.delivery.delivery_id.clone();
    let conn = harness.store.pool.get().await.unwrap();
    let leased = conn
        .interact(move |connection| {
            roundhouse_sched::store::lease_delivery(
                connection,
                &id,
                Timestamp::from_unix_nanos(i64::MAX),
                Timestamp::from_unix_nanos(0),
            )
            .unwrap()
        })
        .await
        .unwrap();
    assert!(leased);

    harness
        .executor
        .claim_and_run(harness.delivery.clone(), harness.stored.clone())
        .await;

    let row = harness.delivery_row().await;
    assert_eq!(row.state, DeliveryState::Leased);
    assert!(row.run_id.is_none(), "a lost claim must reserve nothing");
    assert_eq!(
        harness.active(),
        1,
        "a claimer that never owned the delivery must not release its slot"
    );
}

/// A delivery whose binding is not in the driver's boot snapshot has no
/// honest `StoredBinding` to run against; leaving it `ready` is what lets
/// a daemon that *does* know the binding pick it up later.
#[tokio::test]
async fn a_delivery_for_an_unknown_binding_is_left_ready() {
    let harness = harness(completing_workflow()).await;

    dispatch_ready_deliveries(&harness.executor, &HashMap::new()).await;

    assert_eq!(harness.delivery_row().await.state, DeliveryState::Ready);
    assert_eq!(harness.active(), 1);
}

/// `run_workflow_from_storage` returning `Err` — an infra-level failure
/// calling into flow, not a workflow whose step failed — must still
/// release everything Task 6 owns: the delivery reaches `failed`, the
/// admission slot is released, and the session is retired.
///
/// The one thing deliberately left alone is the `workflow_run` row, which
/// stays `Running`. `finish_run` is the workspace's only writer of
/// terminal run states and the only thing that discharges ruling P112's
/// "exactly one report on every terminal path"; a driver-side transition
/// would mint a terminal run with no report. That orphan is a known,
/// narrower gap — see this module's own doc comment.
#[tokio::test]
async fn an_undrivable_run_still_fails_its_delivery_and_releases_everything() {
    let harness = harness(undrivable_workflow()).await;

    harness
        .executor
        .claim_and_run(harness.delivery.clone(), harness.stored.clone())
        .await;

    let row = harness.delivery_row().await;
    assert_eq!(
        row.state,
        DeliveryState::Failed,
        "a run the loop refused to drive must still fail its delivery, not strand it"
    );
    assert!(row.last_error.as_deref().is_some_and(|e| !e.is_empty()));
    assert_eq!(
        harness.active(),
        0,
        "the admission slot must be released even when the failure is infra-level"
    );
    let session_id = row.session_id.expect("reserve stamps a session id");
    assert!(
        harness.sessions.actor(session_id).is_none(),
        "the session must be retired even when the failure is infra-level"
    );
    // Phase 8, T19a Task 7: a run loop error never reaches a terminal `RunState` (pinned
    // below: the row is left `Running`), so this must go through
    // `release_session`, not `close_and_retire` — a terminator here would
    // precede whatever a future recovery pass appends to this same
    // `session_id`.
    assert!(
        harness.session_close_outcome(session_id).await.is_none(),
        "a run loop error that never reached a terminal RunState must write no SessionClosed \
             terminator"
    );

    // The narrower gap, pinned so it is a known state rather than a
    // surprise: only the `workflow_run` row is orphaned.
    let run_id = RunId::from_uuid(Uuid::parse_str(row.run_id.as_deref().unwrap()).unwrap());
    let run = {
        let conn = harness.store.pool.get().await.unwrap();
        conn.interact(move |connection| recover_run(connection, run_id).unwrap().run)
            .await
            .unwrap()
    };
    assert_eq!(
        run.state,
        RunState::Running,
        "this driver must not fake a terminal transition on the run row — P112's \
             exactly-one-report invariant belongs to finish_run"
    );
}

/// **`OverlapPolicy::Queue` must actually serialize.** A `QueueAt`
/// decision creates a `ready` delivery exactly like an `Admit` does, so
/// without a gate the queued occurrence is claimed and run immediately,
/// alongside the run it was queued behind — `Queue { depth }` silently
/// becoming `Concurrent { max: depth + 1 }`. This is reachable today:
/// `Webhook`/`Message` triggers default to `Queue { depth: 8 }`.
///
/// The assertion that matters is the negative one: the second delivery
/// must still be `Ready`, with no run row and no leased state, *while the
/// first is running*. "Both eventually complete" would pass even with the
/// policy ignored entirely.
#[tokio::test]
async fn a_queued_delivery_does_not_start_until_its_predecessor_finishes() {
    let harness =
        harness_with_overlap(completing_workflow(), OverlapPolicy::Queue { depth: 4 }).await;
    let first = harness.delivery.clone();
    let second = harness.accept_another_occurrence(60).await;
    let binding_id = harness.stored.binding.id;

    assert_eq!(
        harness.state_of(&second.delivery_id).await,
        DeliveryState::Ready,
        "a QueueAt decision still creates a ready delivery — that is exactly why \
             `is there a ready row` is not the same question as `may it run`"
    );
    assert_eq!(
        harness.active(),
        1,
        "the first occurrence was admitted and holds the active slot"
    );
    assert_eq!(
        harness.registry.queued_count(binding_id).unwrap(),
        1,
        "the second was queued, not admitted"
    );

    // Put the predecessor genuinely in flight — claimed through the real
    // `claim`, not yet run — so this test observes the steady state a
    // queued delivery actually meets (predecessor running, itself
    // `ready`) with no dependence on when a spawned task happens to be
    // scheduled.
    let in_flight = harness
        .executor
        .claim(first.clone(), harness.stored.clone())
        .await
        .expect("the admitted predecessor must be claimable");
    assert_eq!(
        harness.state_of(&first.delivery_id).await,
        DeliveryState::Leased
    );

    // A whole tick's worth of dispatch, with the predecessor still
    // active: the queued delivery must be declined, and — the part that
    // makes this a real assertion — declined *synchronously*, before any
    // task is spawned, so the row is still `Ready` the instant dispatch
    // returns.
    let mut bindings = HashMap::new();
    bindings.insert(binding_id, harness.stored.clone());
    dispatch_ready_deliveries(&harness.executor, &bindings).await;

    assert_eq!(
        harness.state_of(&second.delivery_id).await,
        DeliveryState::Ready,
        "a queued delivery must NOT be claimed while its binding has an active run — \
             this is the whole of OverlapPolicy::Queue"
    );
    assert_eq!(
        harness.registry.queued_count(binding_id).unwrap(),
        1,
        "a declined claim must not consume the queued slot either"
    );
    assert_eq!(harness.active(), 1);

    // Finish the predecessor. Only now is the binding free.
    harness.executor.run_claimed(in_flight).await;
    assert_eq!(
        harness.state_of(&first.delivery_id).await,
        DeliveryState::Delivered
    );
    assert_eq!(harness.active(), 0, "the predecessor released its slot");

    dispatch_ready_deliveries(&harness.executor, &bindings).await;
    for _ in 0..1000 {
        if harness.state_of(&second.delivery_id).await == DeliveryState::Delivered {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        harness.state_of(&second.delivery_id).await,
        DeliveryState::Delivered,
        "once the predecessor is done the queued delivery must actually run"
    );
    assert_eq!(
        harness.registry.queued_count(binding_id).unwrap(),
        0,
        "running the queued delivery must consume its queued slot (note_promoted)"
    );
    assert_eq!(
        harness.active(),
        0,
        "and release the active slot it was promoted into (note_finished) — a promotion \
             that is never released wedges the binding exactly like a missing release"
    );
}

/// The counterpart: the promotion is charged only once the claim is
/// actually won, and only for a queued-origin delivery. An `Admit`-origin
/// delivery already holds an active slot and must not be promoted on top
/// of it.
#[tokio::test]
async fn an_admitted_delivery_is_never_promoted_and_needs_no_predecessor_check() {
    let harness = harness(completing_workflow()).await;
    let binding_id = harness.stored.binding.id;
    assert_eq!(harness.registry.queued_count(binding_id).unwrap(), 0);

    harness
        .executor
        .claim_and_run(harness.delivery.clone(), harness.stored.clone())
        .await;

    assert_eq!(
        harness.delivery_row().await.state,
        DeliveryState::Delivered,
        "an admitted delivery runs even though its own binding shows an active run — \
             that active run IS this delivery"
    );
    assert_eq!(
        harness.registry.queued_count(binding_id).unwrap(),
        0,
        "promoting an admitted delivery would underflow the queued counter"
    );
    assert_eq!(harness.active(), 0);
}

/// Fail-closed on an unreadable admission outcome. With the queue gate in
/// place, "assume not queued" is the fail-*open* direction — it would run
/// a possibly-queued delivery alongside its predecessor — so an outcome
/// that cannot be established declines the claim and leaves the row for a
/// tick that can read it.
#[tokio::test]
async fn a_delivery_whose_admission_outcome_is_unreadable_is_not_claimed() {
    let harness = harness(completing_workflow()).await;

    // Point the delivery at a `trigger_event` row that does not exist, so
    // the outcome lookup legitimately comes back empty.
    let id = harness.delivery.delivery_id.clone();
    let conn = harness.store.pool.get().await.unwrap();
    conn.interact(move |connection| {
        connection
            .execute(
                "UPDATE trigger_delivery SET trigger_event_id = 987654 WHERE delivery_id = ?1",
                rusqlite::params![id],
            )
            .unwrap();
    })
    .await
    .unwrap();

    let mut delivery = harness.delivery.clone();
    delivery.trigger_event_id = 987_654;
    assert!(
        harness
            .executor
            .claim(delivery, harness.stored.clone())
            .await
            .is_none(),
        "an unestablished admission outcome must decline the claim, not guess"
    );
    assert_eq!(
        harness.delivery_row().await.state,
        DeliveryState::Ready,
        "a declined claim must leave the row untouched"
    );
}

/// A per-tick claim limit does not bound concurrency on its own — claims
/// are taken every second and a run can last hours — so the bound lives
/// on a semaphore whose permit is held for the delivery's whole life.
/// With every permit taken, a tick must claim nothing and leave the rows
/// `ready` rather than queue behind them.
#[tokio::test]
async fn dispatch_claims_nothing_once_every_delivery_slot_is_in_use() {
    let harness = harness(completing_workflow()).await;
    let mut bindings = HashMap::new();
    bindings.insert(harness.stored.binding.id, harness.stored.clone());

    let mut held = Vec::new();
    for _ in 0..MAX_CONCURRENT_DELIVERIES {
        held.push(
            Arc::clone(&harness.executor.slots)
                .try_acquire_owned()
                .expect("a fresh executor must start with every slot free"),
        );
    }

    dispatch_ready_deliveries(&harness.executor, &bindings).await;

    assert_eq!(
        harness.delivery_row().await.state,
        DeliveryState::Ready,
        "with no slot free, a ready delivery must be left alone rather than leased and \
             then queued behind a run that may take hours"
    );
    assert_eq!(harness.active(), 1);

    // Freeing a slot lets the very next tick pick the same row up.
    held.pop();
    dispatch_ready_deliveries(&harness.executor, &bindings).await;
    for _ in 0..1000 {
        if harness.delivery_row().await.state == DeliveryState::Delivered {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        harness.delivery_row().await.state,
        DeliveryState::Delivered,
        "a freed slot must let the next tick claim the delivery it had to decline"
    );
}

#[tokio::test]
async fn multiple_deliveries_wait_for_async_work_concurrently_without_holding_store_connections() {
    let mut harness =
        harness_with_overlap(reading_workflow(), OverlapPolicy::Concurrent { max: 3 }).await;
    std::fs::write(harness.workspace_root.join("greeting.txt"), "hello").unwrap();
    let second = harness.accept_another_occurrence(60).await;
    let third = harness.accept_another_occurrence(120).await;
    let deliveries = [
        harness.delivery.delivery_id.clone(),
        second.delivery_id,
        third.delivery_id,
    ];
    let gate = Arc::new(SegmentGapGate::new());
    harness.executor.segment_gap_gate = Some(Arc::clone(&gate));
    let initial_permits = harness.executor.slots.available_permits();
    let mut bindings = HashMap::new();
    bindings.insert(harness.stored.binding.id, harness.stored.clone());

    dispatch_ready_deliveries(&harness.executor, &bindings).await;
    for _ in 0..100_000 {
        if gate.entrants() == 3 {
            break;
        }
        tokio::task::yield_now().await;
    }

    assert_eq!(
        gate.entrants(),
        3,
        "all three admitted deliveries must overlap in the connection-free async segment gap"
    );
    assert_eq!(
        initial_permits - harness.executor.slots.available_permits(),
        3,
        "each overlapping delivery must hold one scheduler permit"
    );
    let pool_status = harness.store.pool.status();
    assert_eq!(
        pool_status.waiting, 0,
        "deliveries waiting on async work must not queue for store connections"
    );
    assert_eq!(
        pool_status.available, pool_status.size,
        "deliveries waiting on async work must return every store connection"
    );

    gate.release(3);
    for _ in 0..100_000 {
        let mut terminal = true;
        for delivery_id in &deliveries {
            terminal &= matches!(
                harness.state_of(delivery_id).await,
                DeliveryState::Delivered | DeliveryState::Failed | DeliveryState::Cancelled
            );
        }
        if terminal {
            break;
        }
        tokio::task::yield_now().await;
    }

    for delivery_id in &deliveries {
        let state = harness.state_of(delivery_id).await;
        assert!(
            matches!(
                state,
                DeliveryState::Delivered | DeliveryState::Failed | DeliveryState::Cancelled
            ),
            "released delivery {delivery_id} must reach a terminal state, got {state:?}"
        );
    }
    for _ in 0..100_000 {
        if harness.executor.slots.available_permits() == initial_permits {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        harness.executor.slots.available_permits(),
        initial_permits,
        "terminal deliveries must return all scheduler permits"
    );
}

/// The failure this driver must survive rather than propagate: the
/// binding's job is not registered in the workspace it names.
#[tokio::test]
async fn an_unresolvable_job_fails_the_delivery_rather_than_the_driver() {
    let mut harness = harness(completing_workflow()).await;
    harness.stored.binding.job_id = JobId::new();

    harness
        .executor
        .claim_and_run(harness.delivery.clone(), harness.stored.clone())
        .await;

    let row = harness.delivery_row().await;
    assert_eq!(
        row.state,
        DeliveryState::Failed,
        "a delivery that can never run must fail rather than sit leased forever"
    );
    assert_eq!(harness.active(), 0);
    assert!(
        harness.workspace_root.is_dir(),
        "the workspace must be untouched by a failed resolution"
    );
    // Phase 8, T19a Task 7: `run_claimed`'s own `Err(DeliveryError)` branch must go
    // through `release_session`, writing no terminator — this failure is
    // reached before any workflow ever ran.
    //
    // Like the redrive-continuation test's first boot,
    // this assertion is vacuous by itself — an unresolvable job fails
    // resolution before `*session` is ever set, so `release_session`
    // receives `None` here too, and `None` can't distinguish
    // `release_session` from `close_and_retire`. Kept as a sanity check on
    // this call site's own behavior, not as independent proof of
    // `release_session`'s no-terminator guarantee; see
    // `release_session_writes_no_terminator_for_a_real_session` in
    // `child_run_tests` for the direct, non-vacuous proof.
    let session_id = row.session_id.expect("reserve stamps a session id");
    assert!(
        harness.session_close_outcome(session_id).await.is_none(),
        "a pre-run infra failure (Err(DeliveryError)) must write no SessionClosed terminator"
    );
}

/// Phase 8 Task 25.4 Task 3: a [`DeliveryExecutor`]/[`HeadlessSession`]
/// pair built directly, bypassing the trigger/binding/run-row machinery
/// [`harness`] sets up — `execute_pending` only ever dispatches through
/// `session.actor()`, and never touches `DeliveryExecutor`'s own
/// `store`/`registry`/`spawn_tree` fields, so none of that machinery is
/// needed to call it directly with a hand-built [`PendingWork`].
///
/// `rules` governs what the session's own `PolicyEngine` admits —
/// `daemon_resources`'s `no_policy_rules()` default makes everything
/// `Ask`/`RequiresApproval`, which is fine for tests that never reach
/// admission (the `Duration::ZERO` guard) but would wrongly refuse ones
/// that need a real dispatch to actually run.
async fn executor_and_session(
    dir: &std::path::Path,
    rules: Vec<CompiledRule>,
) -> (DeliveryExecutor, HeadlessSession) {
    let resources =
        Arc::new(daemon_resources_with_rules(dir, None, Arc::new(move || rules.clone())).await);
    executor_and_session_with_resources(dir, resources).await
}

/// [`executor_and_session`], but wired to
/// [`crate::test_support::daemon_resources_with_real_bwrap`] instead of
/// [`crate::test_support::daemon_resources_with_rules`] — for a test
/// that needs its dispatched `tool: shell` step to actually run as a
/// real, genuinely-killable process, which the latter's
/// production-install-path isolate cannot do in a dev checkout with no
/// vendored `bwrap`. Phase 8 Task 25.4 Task 4's §8.13 mid-dispatch
/// shell-cancel tests need this; every other `executor_and_session` test
/// in this module does not, and stays on the cheaper, always-available
/// isolate.
async fn executor_and_session_with_real_bwrap(
    dir: &std::path::Path,
    rules: Vec<CompiledRule>,
) -> (DeliveryExecutor, HeadlessSession) {
    let resources = Arc::new(
        crate::test_support::daemon_resources_with_real_bwrap(
            dir,
            None,
            Arc::new(move || rules.clone()),
        )
        .await,
    );
    executor_and_session_with_resources(dir, resources).await
}

async fn executor_and_session_with_resources(
    dir: &std::path::Path,
    resources: Arc<DaemonResources>,
) -> (DeliveryExecutor, HeadlessSession) {
    let sessions = Arc::new(SessionRegistry::new());
    let store = roundhouse_store::open(&dir.join("events.db"))
        .await
        .unwrap();
    let executor = DeliveryExecutor::new(
        store,
        Arc::clone(&resources),
        Arc::clone(&sessions),
        Arc::new(InMemoryRunRegistry::new()),
        Arc::clone(&resources.spawn_tree),
        Arc::new(FixedClock(instant())),
    );

    let session_id = SessionId::new();
    let spec = SessionSpec {
        workspace: WorkspaceId::new(),
        name: None,
        requested_tier: Tier::Sandbox,
        on_degrade: resources.default_on_degrade,
        parent: None,
    };
    let session = create_headless_session(
        &resources,
        &sessions,
        session_id,
        spec,
        dir.to_path_buf(),
        None,
        None,
    )
    .await
    .expect("headless session construction must succeed against a working fixture");

    (executor, session)
}

/// A `tool: write` step whose `step_timeout` has already elapsed before
/// dispatch even begins is caught by `execute_pending`'s OUTER
/// `tokio::time::timeout` — the safety net covering the four filesystem
/// kinds, which (unlike `Shell`) have no internal bound of their own.
/// `Duration::from_nanos(1)` rather than `Duration::ZERO` deliberately:
/// this test is about the outer wrap catching a real elapsed deadline,
/// not about the separate zero-guard (covered by
/// `a_zero_step_timeout_is_refused_as_a_named_bug_not_dispatched` below).
///
/// This does not (and cannot, without a fake/slow filesystem hook this
/// codebase does not have) prove the outer wrap fires only once a REAL
/// write is genuinely slow — real filesystem writes to a tmpfs-backed
/// tempdir are far faster than any timeout this test could use without
/// becoming a flaky, real-time-sensitive test. What it proves instead:
/// given a deadline that has unambiguously already passed, dispatch
/// still completes promptly (bounded by the 10s outer guard below) and
/// reports a named timeout failure rather than hanging or silently
/// succeeding — exactly the property the outer wrap exists to
/// guarantee for a tool with no internal bound.
#[tokio::test]
async fn a_filesystem_step_exceeding_step_timeout_is_caught_by_the_outer_safety_net() {
    let dir = tempfile::tempdir().unwrap();
    let workspace_root = dir.path().canonicalize().unwrap();
    let target = workspace_root.join("out.txt");
    let target_str = target.to_string_lossy().to_string();

    let rules = vec![CompiledRule::test_new(
        Scope::Builtin,
        PolicyOutcome::Allow,
        Predicate::FsExact {
            op: FsOp::Write,
            path: target.clone(),
        },
    )];
    let (executor, session) = executor_and_session(&workspace_root, rules).await;

    let pending = PendingWork {
        run_id: RunId::new(),
        session_id: session.session_id(),
        step_id: "write_it".to_string(),
        attempt: 1,
        item_index: None,
        disposition: StepDisposition::Effectful,
        step_timeout: Duration::from_nanos(1),
        kind: PendingKind::Tool {
            tool: "write".to_string(),
            task_kind: TaskKind::Write,
            logged_input: serde_json::json!({ "path": &target_str, "contents": "hello" }),
            dispatch_input: serde_json::json!({ "path": &target_str, "contents": "hello" }),
        },
    };

    let done = tokio::time::timeout(
        Duration::from_secs(10),
        executor.execute_pending(&session, vec![pending]),
    )
    .await
    .expect(
        "execute_pending must not hang past its own outer safety net — if it did, this \
             test's own guard would be the thing failing it",
    );

    assert_eq!(done.len(), 1);
    match &done[0].status {
        WorkStatus::Failed { message } => assert!(
            message.contains("step_timeout"),
            "the outer safety net's failure must name the timeout, not just say \"failed\", \
                 got {message:?}"
        ),
        other => panic!(
            "a step whose step_timeout had already elapsed before dispatch began must \
                 fail, got {other:?}"
        ),
    }

    assert!(
        !target.exists(),
        "the outer timeout drops the dispatch future — the write must never have landed"
    );
}

/// Issue #69 / PR #68 follow-up: unlike the test above (where the deadline
/// has already elapsed before dispatch even begins, so no task is ever
/// minted), this test forces the outer timeout to fire *after*
/// `TaskCreated`/`TaskStarted` are already durably logged — and proves the
/// step's `WorkDone` still carries real task identity and that a genuine
/// terminal `TaskFailed` reaches the event log, rather than the task being
/// abandoned `Running` until the next boot's recovery pass.
///
/// Deterministic without a fake clock or a fake/slow filesystem hook: a
/// `read` against a FIFO with no writer blocks in `open()` forever (it
/// cannot spuriously complete early), so any `step_timeout` generous enough
/// for two local store appends to land — 300ms, matching this module's other
/// real-duration timeout tests — reliably outlives it. This is not a
/// sleep-then-assert race; the read is not "slow," it is unboundedly
/// blocked, so the outer wrap is guaranteed to observe it still in flight.
#[tokio::test]
async fn a_genuine_outer_timeout_still_reports_real_task_identity_and_appends_a_terminal_event() {
    let dir = tempfile::tempdir().unwrap();
    let workspace_root = dir.path().canonicalize().unwrap();
    let fifo_path = workspace_root.join("in.fifo");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo_path)
        .status()
        .expect("mkfifo must be on PATH in this dev/CI environment");
    assert!(status.success(), "mkfifo must succeed against a fresh path");
    let fifo_str = fifo_path.to_string_lossy().to_string();

    let rules = vec![CompiledRule::test_new(
        Scope::Builtin,
        PolicyOutcome::Allow,
        Predicate::FsExact {
            op: FsOp::Read,
            path: fifo_path.clone(),
        },
    )];
    let (executor, session) = executor_and_session(&workspace_root, rules).await;
    let session_id = session.session_id();
    let store = executor.store.clone();

    let pending = PendingWork {
        run_id: RunId::new(),
        session_id,
        step_id: "read_fifo".to_string(),
        attempt: 1,
        item_index: None,
        disposition: StepDisposition::Pure,
        step_timeout: Duration::from_millis(300),
        kind: PendingKind::Tool {
            tool: "read".to_string(),
            task_kind: TaskKind::Read,
            logged_input: serde_json::json!({ "path": &fifo_str }),
            dispatch_input: serde_json::json!({ "path": &fifo_str }),
        },
    };

    let done = tokio::time::timeout(
        Duration::from_secs(10),
        executor.execute_pending(&session, vec![pending]),
    )
    .await
    .expect(
        "execute_pending must not hang past its own outer safety net — if it did, this \
             test's own guard would be the thing failing it",
    );

    assert_eq!(done.len(), 1);
    let done = &done[0];
    match &done.status {
        WorkStatus::Failed { message } => assert!(
            message.contains("step_timeout"),
            "the timeout arm's failure must name the timeout, got {message:?}"
        ),
        other => panic!("an elapsed step_timeout must fail the step, got {other:?}"),
    }

    let task_id = done
        .task_id
        .expect("TaskCreated/TaskStarted were durably logged before the deadline — identity must not be lost");
    assert!(
        done.first_task_seq.is_some(),
        "first_task_seq must accompany a real task_id"
    );
    let last_task_seq = done.last_task_seq.expect(
        "the timeout arm must itself append a real terminal TaskFailed and report its seq, \
             not leave the task non-terminal",
    );

    let events = roundhouse_store::session_events(&store, session_id)
        .await
        .expect("reading back this session's own event log must succeed");
    let terminal = events
        .iter()
        .find(|e| e.task_id == Some(task_id) && e.seq == last_task_seq)
        .unwrap_or_else(|| {
            panic!("the reported last_task_seq must name a real event on task {task_id:?}")
        });
    match &terminal.payload {
        EventPayload::TaskFailed { error, .. } => assert_eq!(
            error.category, "step_timeout",
            "the terminal event's category must identify this as a timeout, not a generic failure"
        ),
        other => panic!("the task's terminal event must be TaskFailed, got {other:?}"),
    }

    // `execute_pending`'s outer timeout only drops the *awaiting* future —
    // the `spawn_blocking` thread underneath, genuinely stuck in the FIFO's
    // `open()` with no writer, keeps running. Left unblocked, this test's
    // `#[tokio::test]` runtime would hang on drop waiting for it. Opening
    // (then immediately closing) the write end is enough to unblock the
    // reader's `open()` and let that thread finish, exactly like the
    // cancel-while-blocked test above.
    tokio::task::spawn_blocking(move || {
        drop(std::fs::OpenOptions::new().write(true).open(&fifo_path));
    })
    .await
    .expect("the unblocking writer thread must not panic");
}

/// Phase 8 Task 25.4 Task 4's filesystem-kinds half: `read`/`write`/
/// `edit`/`find` have no cancellation mechanism of their own (see
/// `DeliveryExecutor::execute_pending`'s own doc comment), so the
/// honest behaviour this task implements is "the in-flight call is
/// allowed to finish, then the result is reported as cancelled if a
/// cancel was observed by the time it completes." This test proves
/// both halves of that sentence, deterministically:
///
/// - **"allowed to finish":** the dispatched `tool: read` targets a
///   named pipe (FIFO) opened for read-only, which — real POSIX FIFO
///   semantics, not a timing hack — blocks inside `open()` until a
///   writer opens the other end. The cancel is sent while that read is
///   *provably* still blocked (nothing has opened the write end yet),
///   so there is no ambiguity about whether the call was genuinely
///   in-flight when the cancel landed — no `tokio::time::sleep`
///   anywhere in this test decides that ordering.
/// - **"reported as cancelled":** once cancelled, the test opens the
///   write end and closes it (EOF), letting the blocked read complete
///   normally with real content — and the returned `WorkStatus` must
///   still be `Cancelled`, not `Completed`, because a cancel was
///   observed by the time the call returned.
#[tokio::test]
async fn a_filesystem_read_blocked_in_flight_when_cancelled_still_completes_and_is_reported_cancelled(
) {
    let dir = tempfile::tempdir().unwrap();
    let workspace_root = dir.path().canonicalize().unwrap();
    let fifo_path = workspace_root.join("in.fifo");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo_path)
        .status()
        .expect("mkfifo must be on PATH in this dev/CI environment");
    assert!(status.success(), "mkfifo must succeed against a fresh path");
    let fifo_str = fifo_path.to_string_lossy().to_string();

    let rules = vec![CompiledRule::test_new(
        Scope::Builtin,
        PolicyOutcome::Allow,
        Predicate::FsExact {
            op: FsOp::Read,
            path: fifo_path.clone(),
        },
    )];
    let (executor, session) = executor_and_session(&workspace_root, rules).await;
    // `Arc`, not a bare value: `execute_pending` needs `&HeadlessSession`
    // from inside the spawned task below, and this test needs its own
    // `session.actor()` handle afterward to send the cancel — an `Arc`
    // clone gives both without `HeadlessSession` needing to be `Clone`.
    let session = Arc::new(session);
    let session_id = session.session_id();
    // Captured before `executor` moves into the spawned task below —
    // needed afterward to poll for admission (see the comment at that
    // poll for why it matters).
    let store = executor.store.clone();

    let pending = PendingWork {
        run_id: RunId::new(),
        session_id,
        step_id: "read_fifo".to_string(),
        attempt: 1,
        item_index: None,
        disposition: StepDisposition::Pure,
        step_timeout: Duration::from_secs(30),
        kind: PendingKind::Tool {
            tool: "read".to_string(),
            task_kind: TaskKind::Read,
            logged_input: serde_json::json!({ "path": &fifo_str }),
            dispatch_input: serde_json::json!({ "path": &fifo_str }),
        },
    };

    let session_for_dispatch = Arc::clone(&session);
    let dispatch = tokio::spawn(async move {
        executor
            .execute_pending(&session_for_dispatch, vec![pending])
            .await
    });

    // Wait for real proof the read has cleared admission and is about
    // to call (or already has called) `open()` on the FIFO — a
    // `TaskStarted` event, appended by `dispatch_tool_for_workflow`
    // only *after* `SessionActor::admit_task` succeeds and *before*
    // `execute_builtin` is ever called. Without this, cancelling too
    // early could win a race against admission itself
    // (`SessionActor::admit_task`'s own allowlist refuses a
    // non-`Created`/`Running` session), which would deny the read
    // before it ever touched the FIFO — leaving nothing to ever open
    // the write end below and hanging this test forever. This is a
    // bounded poll, not a fixed sleep: it does not decide *whether* the
    // property holds, only how promptly the test notices it already
    // does.
    for _ in 0..200 {
        let events = roundhouse_store::session_events(&store, session_id)
            .await
            .expect("reading back this session's own event log must succeed");
        if events
            .iter()
            .any(|e| matches!(e.payload, EventPayload::TaskStarted { .. }))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // The determinism argument proper: by this point `TaskStarted` is
    // durably recorded, so the read is either already blocked in
    // `open()` or is about to call it — and `read_file` never consults
    // the cancel signal at all (see `DeliveryExecutor::execute_pending`'s
    // own doc comment), so cancelling now cannot change whether or when
    // it calls `open()`, only what `execute_pending` reports once that
    // (still-uninterruptible) call eventually returns.
    let runner = crate::test_support::runner();
    session
        .actor()
        .cancel(runner, roundhouse_core::CancelReason::User)
        .await
        .expect("cancelling a healthy actor must succeed");

    // Now let the blocked read actually complete: open the write end,
    // write one line, and close it (EOF) — `spawn_blocking` because
    // opening a FIFO for writing can itself block until a reader's
    // `open()` call happens.
    let fifo_for_write = fifo_path.clone();
    tokio::task::spawn_blocking(move || {
        use std::io::Write;
        let mut writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&fifo_for_write)
            .expect("opening the FIFO for writing must succeed once a reader is waiting");
        writer
            .write_all(b"hello-from-the-fifo\n")
            .expect("writing to the FIFO must succeed");
        // `writer` drops here, closing the write end and sending EOF to
        // the blocked reader.
    })
    .await
    .expect("the writer thread must not panic");

    let done = tokio::time::timeout(Duration::from_secs(10), dispatch)
        .await
        .expect(
            "the read must actually complete once the FIFO's write end closes — if it \
                 didn't, this test's own guard is what's failing it, not the dispatch itself",
        )
        .expect("the execute_pending task must not panic");

    assert_eq!(done.len(), 1);
    match &done[0].status {
        // `interrupting_session_state` must report — and
        // `cancel_reclassification_reason` must name — the real
        // `SessionState::Cancelling` this test's own `cancel()` call above
        // set, not a generic "cancelled" string: the whole point of
        // returning `Option<SessionState>` instead of a bare bool (Phase 8
        // Task 25.4 PR #68 follow-up) was to stop collapsing which state
        // fired into one message.
        WorkStatus::Cancelled { reason } => assert!(
            reason.contains("Cancelling"),
            "a reclassified-cancelled filesystem step's reason must name the actual observed \
                 state (Cancelling), not a generic \"cancelled\" — got {reason:?}"
        ),
        other => panic!(
            "a read cancelled while genuinely blocked in flight, then allowed to run to \
                 completion, must be reported Cancelled — got {other:?}"
        ),
    }
    assert_eq!(
        done[0].output,
        serde_json::Value::Null,
        "a reclassified-cancelled step's output is nulled, matching every other Cancelled/\
             Failed arm — see `work_done_from_dispatch`'s own Err arm for the precedent"
    );
}

/// Phase 8 Task 25.4 PR #68 follow-up (item 3), direct coverage of
/// [`reclassify_if_interrupted`] itself rather than the full
/// `execute_pending` pipeline: `Shell`'s genuinely narrow pre-dispatch
/// window (before `run_isolated_shell_dispatch`'s own `select!` starts —
/// e.g. during `admit_task` or the child pre-spawn) is real but too short
/// to land a cancel inside deterministically without either a sleep-then-
/// assert race this codebase forbids, or new test-only instrumentation in
/// production code. What actually matters — that the shared helper both
/// branches call correctly reclassifies an ordinary failure once the
/// session is observed interrupted, and names the real state rather than a
/// generic "cancelled" — is exactly what this tests, deterministically,
/// against the real function.
#[tokio::test]
async fn reclassify_if_interrupted_overwrites_an_ordinary_failure_and_names_the_real_state() {
    let dir = tempfile::tempdir().unwrap();
    let (_executor, session) = executor_and_session(dir.path(), vec![]).await;
    let runner = crate::test_support::runner();
    session
        .actor()
        .cancel(runner, roundhouse_core::CancelReason::User)
        .await
        .expect("cancelling a healthy actor must succeed");

    // Stands in for what `Shell`'s branch produces today when a cancel
    // lands in that pre-dispatch window: `admit_task` denies admission
    // (`AdmitError::SessionCancelling`), which `dispatch_tool_for_workflow`
    // folds into an ordinary `DispatchOutcome::Failed`, not `Cancelled` —
    // the exact asymmetry this follow-up closes.
    let mut done = WorkDone {
        step_id: "s".to_string(),
        item_index: None,
        status: WorkStatus::Failed {
            message: "admission was denied because the session is cancelling".to_string(),
        },
        output: serde_json::json!({ "should": "be discarded" }),
        output_is_secret_derived: false,
        task_id: Some(TaskId::new()),
        first_task_seq: Some(1),
        last_task_seq: Some(2),
    };

    reclassify_if_interrupted(&mut done, &session);

    match &done.status {
        WorkStatus::Cancelled { reason } => assert!(
            reason.contains("Cancelling"),
            "must name the real observed SessionState, not a generic \"cancelled\" — \
                 got {reason:?}"
        ),
        other => panic!(
            "an ordinary Failed observed under a cancelling session must be reclassified \
                 Cancelled, got {other:?}"
        ),
    }
    assert_eq!(
        done.output,
        serde_json::Value::Null,
        "reclassification must null the output, matching the filesystem-branch precedent"
    );
}

/// The other half of the same follow-up: the guard that stops
/// [`reclassify_if_interrupted`] from ever overwriting a `WorkStatus::
/// Cancelled` a caller already produced — for `Shell`, the real live
/// signal via `ToolDispatchError::ShellSessionCancelled` — with this
/// post-hoc, less specific one. Without this guard, sharing the helper
/// between both branches (this follow-up's own de-duplication) would
/// silently discard the live signal's own reason whenever the session was
/// also still observably interrupted afterward, which — unlike the
/// generic-reason finding above — is not just less informative but
/// actually wrong.
#[tokio::test]
async fn reclassify_if_interrupted_never_overwrites_an_already_cancelled_status() {
    let dir = tempfile::tempdir().unwrap();
    let (_executor, session) = executor_and_session(dir.path(), vec![]).await;
    let runner = crate::test_support::runner();
    session
        .actor()
        .cancel(runner, roundhouse_core::CancelReason::User)
        .await
        .expect("cancelling a healthy actor must succeed");

    let mut done = WorkDone {
        step_id: "s".to_string(),
        item_index: None,
        status: WorkStatus::Cancelled {
            reason: "a real ShellSessionCancelled signal already fired".to_string(),
        },
        output: serde_json::Value::Null,
        output_is_secret_derived: false,
        task_id: Some(TaskId::new()),
        first_task_seq: Some(1),
        last_task_seq: Some(2),
    };

    reclassify_if_interrupted(&mut done, &session);

    match &done.status {
        WorkStatus::Cancelled { reason } => assert_eq!(
            reason, "a real ShellSessionCancelled signal already fired",
            "the post-hoc check must never overwrite a real Cancelled the live signal already \
                 produced, even though the session is also independently observed interrupted"
        ),
        other => panic!("expected the original Cancelled to survive untouched, got {other:?}"),
    }
}

/// The `Duration::ZERO` guard (this task's brief, item 3):
/// `PendingWork::step_timeout`'s own doc names its `unwrap_or_default()`
/// fallback as unreachable through the normal authoring path today —
/// constructed directly here, bypassing that path entirely, to prove
/// `execute_pending` refuses it with a named-bug message rather than
/// silently treating it as either "no timeout" or a legitimate,
/// instantly-elapsed one.
///
/// Uses `TaskKind::Read` under `daemon_resources`'s default
/// `no_policy_rules()` (fail-closed `Ask`) deliberately: the zero guard
/// must fire BEFORE admission is ever attempted, so a rule that would
/// admit this call is not needed — and its absence is itself part of
/// the proof, since an admission attempt against `no_policy_rules()`
/// would refuse for an unrelated reason and could mask a guard that
/// never actually ran.
#[tokio::test]
async fn a_zero_step_timeout_is_refused_as_a_named_bug_not_dispatched() {
    let dir = tempfile::tempdir().unwrap();
    let workspace_root = dir.path().canonicalize().unwrap();
    let (executor, session) = executor_and_session(&workspace_root, vec![]).await;

    let pending = PendingWork {
        run_id: RunId::new(),
        session_id: session.session_id(),
        step_id: "zero_timeout_step".to_string(),
        attempt: 1,
        item_index: None,
        disposition: StepDisposition::Pure,
        step_timeout: Duration::ZERO,
        kind: PendingKind::Tool {
            tool: "read".to_string(),
            task_kind: TaskKind::Read,
            logged_input: serde_json::json!({ "path": "irrelevant" }),
            dispatch_input: serde_json::json!({ "path": "irrelevant" }),
        },
    };

    let done = executor.execute_pending(&session, vec![pending]).await;

    assert_eq!(done.len(), 1);
    match &done[0].status {
        WorkStatus::Failed { message } => assert!(
            message.contains("step_timeout was zero"),
            "must name the zero-step_timeout bug explicitly, not report a generic or \
                 misleadingly-instant timeout, got {message:?}"
        ),
        other => panic!("a zero step_timeout must be refused, not dispatched, got {other:?}"),
    }
    assert!(
        done[0].task_id.is_none(),
        "the zero guard fires before any dispatch is attempted — no task is ever minted, \
             unlike the outer-timeout case above where a task may already be in flight when \
             the deadline is hit"
    );
}

/// **A `map` item's answer must come back under that item's index** (Phase 8
/// Task 25.7 Task 2). `Loop::work_results` is keyed by
/// `(step_id, item_index)`, so a `WorkDone` filed under `None` for a
/// `PendingWork` that carried `Some(i)` answers nothing: the run loop finds
/// the item still unresolved and re-dispatches it on the next wave, forever,
/// until the run's grant is exhausted and it ends `Failed` reporting
/// "admission refused" instead of what really happened.
///
/// Driven through the zero-`step_timeout` refusal because it is the one arm
/// that needs no real tool dispatch, no policy rule and no live child — the
/// echo it exercises is `execute_pending_with_context`'s, which applies to
/// every arm from one place.
#[tokio::test]
async fn a_map_items_answer_carries_its_item_index_back() {
    let dir = tempfile::tempdir().unwrap();
    let workspace_root = dir.path().canonicalize().unwrap();
    let (executor, session) = executor_and_session(&workspace_root, vec![]).await;

    // Two items of the **same** inner step id, which is exactly the shape a
    // bare-`step_id` answer cannot distinguish, with the interesting index
    // neither first nor last within the run (ruling P92's fixture rule).
    let item = |item_index: Option<u32>| PendingWork {
        run_id: RunId::new(),
        session_id: session.session_id(),
        step_id: "build".to_string(),
        attempt: 1,
        item_index,
        disposition: StepDisposition::Pure,
        step_timeout: Duration::ZERO,
        kind: PendingKind::Tool {
            tool: "read".to_string(),
            task_kind: TaskKind::Read,
            logged_input: serde_json::json!({ "path": "irrelevant" }),
            dispatch_input: serde_json::json!({ "path": "irrelevant" }),
        },
    };

    let done = executor
        .execute_pending(&session, vec![item(Some(2)), item(Some(5)), item(None)])
        .await;

    assert_eq!(
        done.iter().map(|d| d.item_index).collect::<Vec<_>>(),
        vec![Some(2), Some(5), None],
        "each answer echoes exactly the index its own `PendingWork` carried, and a top-level \
         step's `None` is still `None`"
    );
}

/// Phase 8 Task 25.4 Task 4, the non-conflation regression this task's
/// own restructuring risks: an ordinary `step_timeout` elapsing — no
/// §8.13 cancel anywhere in this test — must still classify as
/// `WorkStatus::Failed`, never `WorkStatus::Cancelled`. `Shell`'s own
/// `run_isolated_shell_dispatch` returns
/// `ToolDispatchError::ShellCancelled` (the *timeout* variant, distinct
/// from `ShellSessionCancelled`) for exactly this case; this test pins
/// that `dispatch_tool_for_workflow`/`work_done_from_dispatch` keep the
/// two apart rather than treating every `ShellCancelled`-shaped error as
/// a cancel.
#[tokio::test]
async fn a_shell_step_timeout_with_no_cancel_is_reported_failed_not_cancelled() {
    let dir = tempfile::tempdir().unwrap();
    let workspace_root = dir.path().canonicalize().unwrap();
    let program_path = workspace_root.join("sleep_forever.sh");
    std::fs::write(&program_path, "#!/bin/sh\nsleep 30\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&program_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&program_path, perms).unwrap();
    }
    let program_str = program_path.to_string_lossy().to_string();
    let cwd_str = workspace_root.to_string_lossy().to_string();

    let rules = vec![CompiledRule::test_new(
        Scope::Builtin,
        PolicyOutcome::Allow,
        Predicate::program(&program_str),
    )];
    let (executor, session) = executor_and_session_with_real_bwrap(&workspace_root, rules).await;

    let pending = PendingWork {
        run_id: RunId::new(),
        session_id: session.session_id(),
        step_id: "sleepy".to_string(),
        attempt: 1,
        item_index: None,
        disposition: StepDisposition::Effectful,
        step_timeout: Duration::from_millis(200),
        kind: PendingKind::Tool {
            tool: "shell".to_string(),
            task_kind: TaskKind::Shell,
            logged_input: serde_json::json!({ "program": &program_str, "argv": [], "cwd": &cwd_str }),
            dispatch_input: serde_json::json!({ "program": &program_str, "argv": [], "cwd": &cwd_str }),
        },
    };

    let start = std::time::Instant::now();
    let done = tokio::time::timeout(
        Duration::from_secs(10),
        executor.execute_pending(&session, vec![pending]),
    )
    .await
    .expect("a plain timeout, with no cancel involved, must not hang");
    assert!(
        start.elapsed() >= Duration::from_millis(150),
        "a real step_timeout must actually be waited out, not resolved by some earlier, \
             unrelated failure (e.g. isolation spawn) — elapsed {:?}",
        start.elapsed()
    );

    assert_eq!(done.len(), 1);
    match &done[0].status {
        // `dispatch_tool_for_workflow` reports every ordinary
        // `ToolDispatchError` (timeout included) with the same fixed
        // "tool execution failed" message rather than the error's own
        // `Display` — see `record_workflow_task_failed`'s call site for
        // why (the detail is logged via `tracing`, not returned to the
        // step). The property under test is the *status variant*, not
        // this message's text.
        WorkStatus::Failed { message } => assert_eq!(message, "tool execution failed"),
        other => panic!(
            "a step_timeout elapsing with no cancel signal must report Failed, not {other:?}"
        ),
    }
}

/// Phase 8 Task 25.4 Task 4's central required test: cancelling a run
/// while its `tool: shell` step is genuinely mid-dispatch (a real,
/// long-running process, killed by a real cancel) must report that
/// step's `WorkDone` as `Cancelled` rather than `Failed`, the run must
/// end `RunState::Cancelled`, and `finally:` must still run to
/// completion afterward — §8.13's full four clauses, exercised together.
///
/// Drives `DeliveryExecutor::drive_run_to_completion` directly (the same
/// method `run_claimed_delivery` calls), bypassing only the outer
/// trigger/binding/delivery-leasing machinery [`harness`] sets up — this
/// test needs a job registered and a `workflow_run` row, not a
/// `trigger_delivery` to claim, and driving directly is what lets it
/// hold a live handle to `session.actor()` to cancel, which a claim
/// hidden inside `claim_and_run` would not give it.
///
/// Uses [`executor_and_session_with_real_bwrap`]: `Shell`'s own §8.13
/// cancel is observed by `execute_builtin`'s real `tokio::select!`
/// racing the child's real completion against the actor's real
/// `SessionState` watch, so there has to be a real, running child to
/// race against — the always-available isolate cannot spawn one in this
/// dev checkout (see that isolate's own doc comment).
///
/// # Why this cancels through two calls, not one
///
/// §8.13's cancel has two independently-real, currently-unwired-to-each-
/// other mechanisms in this workspace (see `roundhouse_web::interaction`'s
/// own module doc for the fullest statement of this): `control::cancel`
/// marks the `workflow_run` row `Cancelling`, which is what
/// `run_workflow`'s own terminal-state arithmetic
/// (`cancelled || observed == RunState::Cancelling`) reads to decide
/// `RunState::Cancelled` over `RunState::Failed` — and separately,
/// `session.actor().cancel` flips the *session's* `SessionState`, which
/// is the one `execute_pending`'s dispatch (through
/// `dispatch_tool_for_workflow`/`execute_builtin`) actually watches
/// mid-call. Calling only the first would mark the run cancelled but
/// never touch the running shell child; calling only the second would
/// kill the child but leave the row `Running`, so `run_workflow` would
/// report `RunState::Failed` once the killed step's own resumed
/// `WorkStatus::Cancelled` folds into `main_failed`. This task's own
/// scope is the second mechanism (`execute_pending`'s missing
/// mid-dispatch observation); the first already existed. A real,
/// wired-together cancel RPC is future work this test does not claim to
/// provide.
///
/// # Determinism
///
/// The 150ms head start before the cancel fires is the same idiom
/// `roundhouse-engine`'s own
/// `execute_builtin_shell_cancels_when_the_session_leaves_running` uses:
/// it does not decide correctness (the outer 20s `tokio::time::timeout`
/// below is what fails the test if the race ever went the other way and
/// the run hung or ran to completion instead), it only makes the test
/// actually exercise the mid-dispatch path — a `sleep 30` script started
/// microseconds earlier is overwhelmingly certain to still be running
/// 150ms later, and this test also independently confirms the process
/// was really killed via a real OS-level liveness check afterward.
#[tokio::test]
async fn cancelling_mid_shell_dispatch_reports_cancelled_and_still_runs_finally() {
    let dir = tempfile::tempdir().unwrap();
    let workspace_root = dir.path().join("workspace");
    std::fs::create_dir(&workspace_root).unwrap();
    let workspace_root = workspace_root.canonicalize().unwrap();

    let pid_file = workspace_root.join("shell.pid");
    let program_path = workspace_root.join("sleep_and_record_pid.sh");
    std::fs::write(
        &program_path,
        format!("#!/bin/sh\necho $$ > {}\nsleep 30\n", pid_file.display()),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&program_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&program_path, perms).unwrap();
    }
    let program_str = program_path.to_string_lossy().to_string();
    let cwd_str = workspace_root.to_string_lossy().to_string();

    let workflow_yaml = format!(
        "name: scheduled\nversion: 1\npermissions:\n  default: deny\n  unattended:\n    \
             escalate: fail\nsteps:\n  - id: sleepy\n    tool: shell\n    with: {{ program: \
             {prog:?}, argv: [], cwd: {cwd:?} }}\nfinally:\n  - id: cleanup\n    emit: {{ value: \
             cleanup-ran }}\n",
        prog = program_str,
        cwd = cwd_str,
    );
    let source = workspace_root.join("workflow.yaml");
    std::fs::write(&source, &workflow_yaml).unwrap();

    let rules = vec![CompiledRule::test_new(
        Scope::Builtin,
        PolicyOutcome::Allow,
        Predicate::program(&program_str),
    )];
    let (executor, session) = executor_and_session_with_real_bwrap(&workspace_root, rules).await;
    let session_id = session.session_id();

    let job_id = {
        let conn = executor.store.pool.get().await.unwrap();
        let root = workspace_root.clone();
        let source = source.clone();
        conn.interact(move |connection| {
            register_workflow_file(connection, &root, &source, template())
                .unwrap()
                .job
                .id()
        })
        .await
        .unwrap()
    };

    let run_id = RunId::new();
    // The executor's own `FixedClock` reading — not an arbitrary
    // `Timestamp`, and specifically not epoch 0: `started_at` below and
    // every `self.now()` `drive_run_to_completion` reads later must
    // agree, or the finally: phase's own wall-timeout admission check
    // (`admit_spend_during_finally`) sees a run "started" decades ago
    // and refuses it outright before it ever gets a chance to run —
    // exactly the failure this comment is here to prevent regressing to.
    let now = executor.now();
    {
        let conn = executor.store.pool.get().await.unwrap();
        let root = workspace_root.clone();
        conn.interact(move |connection| {
            let resolved = resolve_latest_by_job_id(connection, &root, job_id)
                .unwrap()
                .expect("the job just registered above must resolve");
            let version = resolved.job.latest();
            let run = WorkflowRun {
                id: run_id,
                job_id,
                job_version: version.version(),
                content_hash: content_hash(version),
                session_id,
                binding_id: None,
                trigger_event_id: None,
                state: RunState::Running,
                parent_run_id: None,
                forked_from_run_id: None,
                awaiting_until: None,
                checkpoint_ref: None,
                checkpoint_blob_ref: None,
                started_at: now,
                ended_at: None,
                session_depth: Some(0),
                caps: Some(ResourceCaps::default()),
            };
            insert_workflow_run(connection, &run).unwrap();
        })
        .await
        .unwrap();
    }

    let spec = SessionSpec {
        workspace: WorkspaceId::new(),
        name: None,
        requested_tier: Tier::Sandbox,
        on_degrade: OnDegrade::Refuse,
        parent: None,
    };
    let run_ctx = RunContext {
        inputs: serde_json::Value::Null,
        inputs_secret_derived: false,
        vars: serde_json::Value::Null,
        secrets: HashMap::new(),
        run_id,
        previous_report: None,
        env_allowlist: EnvAllowlist::deny_all(),
        worktree_provider: Some(Arc::new(SandboxWorktreeProvider::new(
            workspace_root.clone(),
        ))),
    };

    let store_for_cancel = executor.store.clone();
    let actor = Arc::clone(session.actor());
    let runner = crate::test_support::runner();
    let canceller = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(150)).await;
        // Leg 1: mark the run's own row `Cancelling` — what
        // `run_workflow`'s terminal-state arithmetic reads.
        let conn = store_for_cancel.pool.get().await.unwrap();
        conn.interact(move |connection| roundhouse_flow::control::cancel(connection, run_id, now))
            .await
            .unwrap()
            .expect("marking a Running run Cancelling must succeed");
        // Leg 2: flip the session actor's own `SessionState` — what
        // `execute_pending`'s in-flight shell dispatch actually watches.
        actor
            .cancel(runner, roundhouse_core::CancelReason::User)
            .await
            .expect("cancelling a healthy actor must succeed");
    });

    let outcome = tokio::time::timeout(
        Duration::from_secs(20),
        executor.drive_run_to_completion(
            run_id,
            session_id,
            &session,
            spec,
            workspace_root.clone(),
            run_ctx,
            now,
            None,
        ),
    )
    .await
    .expect("a cancelled run must not hang past its own outer safety net")
    .expect("drive_run_to_completion's own DeliveryError path must not be reached")
    .expect("run_workflow must not return a RunLoopError for this fixture");

    canceller.await.expect("the canceller task must not panic");

    let (state, steps) = match outcome {
        DrivenRun::Outcome(RunOutcome::Terminal { state, steps, .. }) => (state, steps),
        other => panic!("a cancelled run must reach a terminal outcome, got {other:?}"),
    };
    assert_eq!(
        state,
        RunState::Cancelled,
        "a run cancelled mid-dispatch must end Cancelled, not Failed or Completed"
    );

    let sleepy = steps
        .iter()
        .find(|s| s.step_id == "sleepy")
        .expect("the sleepy step must have an outcome recorded");
    match &sleepy.status {
        StepStatus::Failed { message } => assert!(
            message.to_lowercase().contains("cancel"),
            "the cancelled shell step's own recorded message should name cancellation \
                 (WorkStatus::Cancelled folds into StepStatus::Failed{{message: reason}} — see \
                 that conversion's own doc comment), got {message:?}"
        ),
        other => panic!(
            "the cancelled shell step must be recorded as failed (with a cancellation \
                 reason), got {other:?}"
        ),
    }

    let cleanup = steps
        .iter()
        .find(|s| s.step_id == "cleanup")
        .expect("finally: must still have run and recorded an outcome, even after a cancel");
    assert!(
        matches!(cleanup.status, StepStatus::Completed),
        "finally: must run to completion on a cancelled run (§8.13), got {:?}",
        cleanup.status
    );

    // Confirm the process was actually killed — a real OS-level
    // liveness check, not just trusting the returned status — the same
    // mechanism `execute_builtin_shell_timeout_parameter_is_a_real_process_group_kill`
    // (`roundhouse-engine`) uses.
    for _ in 0..50 {
        if pid_file.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let pid: i32 = std::fs::read_to_string(&pid_file)
        .expect("the dispatched shell must have written its own pid before sleeping")
        .trim()
        .parse()
        .expect("pid file must contain a valid pid");
    let mut confirmed_dead = false;
    for _ in 0..100 {
        let alive = std::process::Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if !alive {
            confirmed_dead = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        confirmed_dead,
        "a shell step cancelled mid-dispatch must have its process actually killed \
             (SIGTERM/SIGKILL), not merely reported as cancelled while still running (pid {pid})"
    );
}

/// Phase 8 Task 25.4 Task 5's daemon-level test: a real park-and-resume
/// cycle for §8.10's `on_crash: ask`, driven through the production
/// segmented loop ([`DeliveryExecutor::drive_run_to_completion`]) rather
/// than through `roundhouse-flow`'s own in-crate stubs.
///
/// # What "the daemon crashed mid-dispatch" is, durably
///
/// Exactly one thing: a `workflow_step_run` row left `running` with
/// `disposition = effectful`. A killed daemon writes nothing else — that
/// is §8.10's whole premise — so seeding that row *is* the crash, not a
/// stand-in for it. `recover_run` reclassifies it `Indeterminate` on the
/// next load, `crash_policy` resolves a `tool: write` step with no
/// declared `on_crash:` to `Ask`, and before this task that combination
/// permanently failed the run.
///
/// # Both legs are real
///
/// The **park** leg runs `drive_run_to_completion` with no resume, and
/// asserts on the durable `workflow_run` row (`awaiting_human`), not just
/// on the returned value. The **resume** leg feeds a real
/// `Resume::CrashRecovery { rerun }` into the same production loop, which
/// re-admits the step, hands it to [`DeliveryExecutor::execute_pending`]
/// as a genuine `AwaitingWork` suspension, and dispatches the `write` for
/// real — proven by the file's contents on disk afterwards, which nothing
/// but a real dispatch could have put there.
#[tokio::test]
async fn a_crash_recovery_park_is_answered_and_the_write_step_really_re_dispatches() {
    let dir = tempfile::tempdir().unwrap();
    let workspace_root = dir.path().canonicalize().unwrap();
    let target = workspace_root.join("shipped.txt");
    let target_str = target.to_string_lossy().to_string();

    let workflow_yaml = format!(
        "name: scheduled\nversion: 1\npermissions:\n  default: deny\n  unattended:\n    \
             escalate: fail\nsteps:\n  - id: ship\n    tool: write\n    with: {{ path: {path:?}, \
             contents: shipped-by-the-rerun }}\n",
        path = target_str,
    );
    let source = workspace_root.join("workflow.yaml");
    std::fs::write(&source, &workflow_yaml).unwrap();

    let rules = vec![CompiledRule::test_new(
        Scope::Builtin,
        PolicyOutcome::Allow,
        Predicate::FsExact {
            op: FsOp::Write,
            path: target.clone(),
        },
    )];
    let (executor, session) = executor_and_session(&workspace_root, rules).await;
    let session_id = session.session_id();

    let job_id = {
        let conn = executor.store.pool.get().await.unwrap();
        let root = workspace_root.clone();
        let source = source.clone();
        conn.interact(move |connection| {
            register_workflow_file(connection, &root, &source, template())
                .unwrap()
                .job
                .id()
        })
        .await
        .unwrap()
    };

    let run_id = RunId::new();
    let now = executor.now();
    {
        let conn = executor.store.pool.get().await.unwrap();
        let root = workspace_root.clone();
        conn.interact(move |connection| {
            let resolved = resolve_latest_by_job_id(connection, &root, job_id)
                .unwrap()
                .expect("the job just registered above must resolve");
            let version = resolved.job.latest();
            insert_workflow_run(
                connection,
                &WorkflowRun {
                    id: run_id,
                    job_id,
                    job_version: version.version(),
                    content_hash: content_hash(version),
                    session_id,
                    binding_id: None,
                    trigger_event_id: None,
                    state: RunState::Running,
                    parent_run_id: None,
                    forked_from_run_id: None,
                    awaiting_until: None,
                    checkpoint_ref: None,
                    checkpoint_blob_ref: None,
                    started_at: now,
                    ended_at: None,
                    session_depth: Some(0),
                    caps: Some(ResourceCaps::default()),
                },
            )
            .unwrap();
            // The crash itself: the row a daemon killed mid-`write`
            // leaves behind.
            checkpoint_step(
                connection,
                &WorkflowStepRun {
                    run_id,
                    step_id: "ship".to_string(),
                    attempt: 1,
                    item_index: None,
                    disposition: StepDisposition::Effectful,
                    state: StepRunState::Running,
                    first_task_seq: None,
                    last_task_seq: None,
                    output: None,
                    error: None,
                },
            )
            .unwrap();
        })
        .await
        .unwrap();
    }

    let spec = SessionSpec {
        workspace: WorkspaceId::new(),
        name: None,
        requested_tier: Tier::Sandbox,
        on_degrade: OnDegrade::Refuse,
        parent: None,
    };
    let run_ctx = RunContext {
        inputs: serde_json::Value::Null,
        inputs_secret_derived: false,
        vars: serde_json::Value::Null,
        secrets: HashMap::new(),
        run_id,
        previous_report: None,
        env_allowlist: EnvAllowlist::deny_all(),
        worktree_provider: Some(Arc::new(SandboxWorktreeProvider::new(
            workspace_root.clone(),
        ))),
    };

    // Leg 1: the restart finds the step `Indeterminate` and parks.
    let parked = executor
        .drive_run_to_completion(
            run_id,
            session_id,
            &session,
            spec.clone(),
            workspace_root.clone(),
            run_ctx.clone(),
            now,
            None,
        )
        .await
        .expect("drive_run_to_completion's own DeliveryError path must not be reached")
        .expect("run_workflow must not return a RunLoopError for this fixture");
    assert!(
        matches!(parked, DrivenRun::Outcome(RunOutcome::Parked(_))),
        "a restart mid-`write` must ask a human rather than failing the run, got {parked:?}"
    );
    assert!(
        !target.exists(),
        "nothing may be dispatched while the run is parked"
    );
    assert!(
        matches!(conclusion_for(&Ok(parked)), RunConclusion::Parked),
        "a crash-recovery park must reach the same delivery conclusion a gate park does — \
             `conclusion_for` is source-agnostic and must stay so"
    );
    {
        let conn = executor.store.pool.get().await.unwrap();
        let row = conn
            .interact(move |connection| recover_run(connection, run_id).unwrap().run)
            .await
            .unwrap();
        assert_eq!(
            row.state,
            RunState::AwaitingHuman,
            "the durable row, not the returned value, is what a restart would read back"
        );
        assert!(
            row.awaiting_until.is_some(),
            "the wait carries an absolute deadline"
        );
    }

    // Leg 2: a human answers `rerun`, and the same production loop
    // re-admits the step and dispatches it for real.
    let resumed = executor
        .drive_run_to_completion(
            run_id,
            session_id,
            &session,
            spec,
            workspace_root.clone(),
            run_ctx,
            executor.now(),
            Some(Resume::CrashRecovery(CrashRecoveryAnswer {
                step_id: "ship".to_string(),
                resolution: CrashResolution::Rerun,
            })),
        )
        .await
        .expect("drive_run_to_completion's own DeliveryError path must not be reached")
        .expect("run_workflow must not return a RunLoopError for this fixture");

    let (state, steps) = match resumed {
        DrivenRun::Outcome(RunOutcome::Terminal { state, steps, .. }) => (state, steps),
        other => panic!("an answered park must drive to a terminal outcome, got {other:?}"),
    };
    assert_eq!(state, RunState::Completed);
    let ship = steps
        .iter()
        .find(|s| s.step_id == "ship")
        .expect("`rerun` re-dispatches the step, so it has an outcome on this drive");
    assert!(
        matches!(ship.status, StepStatus::Completed),
        "the re-dispatched write must have completed, got {:?}",
        ship.status
    );
    assert_eq!(
        std::fs::read_to_string(&target).expect("the re-dispatched write must have run"),
        "shipped-by-the-rerun",
        "only a real dispatch through execute_pending could have written this"
    );
}

/// Task 7's boot-time restart-recovery pass, exercised against the same
/// [`Harness`] scaffolding — but always through a **fresh**
/// [`DeliveryExecutor`]/[`InMemoryRunRegistry`]/[`SessionRegistry`]
/// ([`Harness::fresh_executor_after_restart`]), never `harness.executor`,
/// which still holds whatever charge the harness's own setup made
/// against `harness.registry`. A recovery test that passed against
/// `harness.executor` would prove nothing about re-seeding — the slot
/// would already be there regardless.
///
/// No real-clock timing anywhere: every `boot` is an explicit
/// `DateTime::from_timestamp_nanos` constant.
mod recovery_tests {
    use super::*;

    fn bindings_map(stored: &StoredBinding) -> HashMap<BindingId, StoredBinding> {
        let mut map = HashMap::new();
        map.insert(stored.binding.id, stored.clone());
        map
    }

    /// A `watch::Receiver<bool>` permanently reporting "not cancelled",
    /// for every recovery test below that isn't itself exercising
    /// mid-recovery interruption (Final-review fix round 1, Important 1
    /// part B). The paired `Sender` is dropped immediately — every
    /// caller here only ever peeks `*borrow()`, never awaits `changed()`,
    /// so a receiver whose sender is gone still reads back its initial
    /// `false` value correctly.
    fn never_cancelled() -> tokio::sync::watch::Receiver<bool> {
        tokio::sync::watch::channel(false).1
    }

    // ── Mechanism 1: reclaim expired leases ──────────────────────────

    #[tokio::test]
    async fn an_expired_lease_is_reclaimed_back_to_ready_and_reseeded() {
        let harness = harness(completing_workflow()).await;
        let (fresh, fresh_registry, _sessions) = harness.fresh_executor_after_restart();

        let id = harness.delivery.delivery_id.clone();
        let conn = harness.store.pool.get().await.unwrap();
        conn.interact(move |connection| {
            assert!(lease_delivery(
                connection,
                &id,
                Timestamp::from_unix_nanos(100),
                Timestamp::from_unix_nanos(0),
            )
            .unwrap());
        })
        .await
        .unwrap();
        assert_eq!(
            harness.state_of(&harness.delivery.delivery_id).await,
            DeliveryState::Leased
        );

        let boot = DateTime::from_timestamp_nanos(200); // past the lease's expiry (100)
        recover_after_restart(
            &fresh,
            &bindings_map(&harness.stored),
            boot,
            &never_cancelled(),
        )
        .await;

        assert_eq!(
            harness.state_of(&harness.delivery.delivery_id).await,
            DeliveryState::Ready,
            "an expired lease must be reclaimed back to ready at boot"
        );
        assert_eq!(
            fresh_registry
                .active_run_count(harness.stored.binding.id)
                .unwrap(),
            1,
            "the reclaimed-then-ready delivery must re-seed the fresh registry too, or a \
                 restart would silently stop enforcing OverlapPolicy for its binding"
        );
    }

    /// Final-review fix round 1, Important 1 part B: recovery must be
    /// interruptible by an orderly shutdown, since it can now run
    /// **after** this service is already observed as ready (part A) —
    /// so a shutdown request can arrive mid-recovery, not just before or
    /// after it. `cancelled` is peeked at the top of each mechanism's
    /// own per-row loop; a receiver that already reports `true` before
    /// `recover_after_restart` is even called must stop Mechanism 1
    /// before it processes this expired lease at all — proved by the
    /// lease staying exactly `leased` (not reclaimed to `ready`) and the
    /// registry staying at zero (never re-seeded, since Mechanism 2 also
    /// never runs). No wall-clock timing: `cancelled` is a plain
    /// `watch::Receiver<bool>` set once, synchronously, before the call.
    #[tokio::test]
    async fn recovery_already_cancelled_before_it_starts_does_nothing() {
        let harness = harness(completing_workflow()).await;
        let (fresh, fresh_registry, _sessions) = harness.fresh_executor_after_restart();

        let id = harness.delivery.delivery_id.clone();
        let conn = harness.store.pool.get().await.unwrap();
        conn.interact(move |connection| {
            assert!(lease_delivery(
                connection,
                &id,
                Timestamp::from_unix_nanos(100),
                Timestamp::from_unix_nanos(0),
            )
            .unwrap());
        })
        .await
        .unwrap();
        assert_eq!(
            harness.state_of(&harness.delivery.delivery_id).await,
            DeliveryState::Leased
        );

        let already_cancelled = tokio::sync::watch::channel(true).1;
        let boot = DateTime::from_timestamp_nanos(200); // past the lease's expiry (100)
        recover_after_restart(
            &fresh,
            &bindings_map(&harness.stored),
            boot,
            &already_cancelled,
        )
        .await;

        assert_eq!(
            harness.state_of(&harness.delivery.delivery_id).await,
            DeliveryState::Leased,
            "recovery must not reclaim an expired lease once shutdown has been requested"
        );
        assert_eq!(
            fresh_registry
                .active_run_count(harness.stored.binding.id)
                .unwrap(),
            0,
            "recovery must not re-seed the registry once shutdown has been requested — \
                 Mechanism 2 never got the chance to run"
        );
    }

    #[tokio::test]
    async fn a_lease_that_has_not_yet_expired_is_left_leased_but_still_reseeded() {
        let harness = harness(completing_workflow()).await;
        let (fresh, fresh_registry, _sessions) = harness.fresh_executor_after_restart();

        let id = harness.delivery.delivery_id.clone();
        let conn = harness.store.pool.get().await.unwrap();
        conn.interact(move |connection| {
            assert!(lease_delivery(
                connection,
                &id,
                Timestamp::from_unix_nanos(1_000),
                Timestamp::from_unix_nanos(0),
            )
            .unwrap());
        })
        .await
        .unwrap();

        let boot = DateTime::from_timestamp_nanos(500); // before the lease's expiry (1_000)
        recover_after_restart(
            &fresh,
            &bindings_map(&harness.stored),
            boot,
            &never_cancelled(),
        )
        .await;

        assert_eq!(
            harness.state_of(&harness.delivery.delivery_id).await,
            DeliveryState::Leased,
            "a lease that has not yet expired must not be reclaimed"
        );
        assert_eq!(
            fresh_registry
                .active_run_count(harness.stored.binding.id)
                .unwrap(),
            1,
            "a still-leased delivery holds an admission slot exactly like a ready one and \
                 must be re-seeded too, not only the ones Mechanism 1 actually reclaimed"
        );
    }

    // ── Re-seeding `ready`/`leased` deliveries by admission outcome ──

    #[tokio::test]
    async fn a_queued_ready_delivery_reseeds_the_queued_counter_not_the_active_one() {
        let harness =
            harness_with_overlap(completing_workflow(), OverlapPolicy::Queue { depth: 4 }).await;
        // Second occurrence: `QueueAt`, still `ready`.
        let _second = harness.accept_another_occurrence(60).await;
        let (fresh, fresh_registry, _sessions) = harness.fresh_executor_after_restart();

        recover_after_restart(
            &fresh,
            &bindings_map(&harness.stored),
            DateTime::from_timestamp_nanos(0),
            &never_cancelled(),
        )
        .await;

        assert_eq!(
            fresh_registry
                .active_run_count(harness.stored.binding.id)
                .unwrap(),
            1,
            "the first (Admitted) delivery must reseed the active slot"
        );
        assert_eq!(
            fresh_registry
                .queued_count(harness.stored.binding.id)
                .unwrap(),
            1,
            "the second (QueueAt) delivery must reseed the QUEUED slot, not the active one"
        );
    }

    // ── Mechanism 2: re-drive `reserved`/`running` deliveries ────────

    #[tokio::test]
    async fn a_running_delivery_crashed_mid_run_is_redriven_to_completion() {
        let harness = harness(completing_workflow()).await;
        let (run_id, session_id) = harness
            .simulate_running_before_crash_with_state(RunState::Running)
            .await;
        let (fresh, fresh_registry, fresh_sessions) = harness.fresh_executor_after_restart();
        assert_eq!(
            harness.state_of(&harness.delivery.delivery_id).await,
            DeliveryState::Running
        );

        recover_after_restart(
            &fresh,
            &bindings_map(&harness.stored),
            DateTime::from_timestamp_nanos(0),
            &never_cancelled(),
        )
        .await;

        assert_eq!(
            harness.state_of(&harness.delivery.delivery_id).await,
            DeliveryState::Delivered,
            "a running delivery whose run never actually started (crash right after \
                 mark_delivery_running) must be re-driven to completion, not left stranded"
        );
        assert_eq!(harness.run_state(run_id).await, RunState::Completed);
        assert_eq!(
            fresh_registry
                .active_run_count(harness.stored.binding.id)
                .unwrap(),
            0,
            "a completed re-drive must release the admission slot it re-seeded"
        );
        assert!(
            fresh_sessions.actor(session_id).is_none(),
            "a terminal re-drive must retire the session it rebuilt, exactly like the live \
                 claim path"
        );
    }

    #[tokio::test]
    async fn a_running_delivery_redriven_to_a_failing_step_fails_the_delivery() {
        let harness = harness(failing_workflow()).await;
        let (run_id, _session_id) = harness
            .simulate_running_before_crash_with_state(RunState::Running)
            .await;
        let (fresh, fresh_registry, _sessions) = harness.fresh_executor_after_restart();

        recover_after_restart(
            &fresh,
            &bindings_map(&harness.stored),
            DateTime::from_timestamp_nanos(0),
            &never_cancelled(),
        )
        .await;

        let row = harness.delivery_row().await;
        assert_eq!(row.state, DeliveryState::Failed);
        assert!(row.last_error.as_deref().is_some_and(|e| !e.is_empty()));
        assert_eq!(harness.run_state(run_id).await, RunState::Failed);
        assert_eq!(
            fresh_registry
                .active_run_count(harness.stored.binding.id)
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn a_running_deliverys_run_already_parked_before_the_restart_is_left_alone() {
        let harness = harness(completing_workflow()).await;
        let _ids = harness
            .simulate_running_before_crash_with_state(RunState::AwaitingHuman)
            .await;
        let (fresh, fresh_registry, _sessions) = harness.fresh_executor_after_restart();

        recover_after_restart(
            &fresh,
            &bindings_map(&harness.stored),
            DateTime::from_timestamp_nanos(0),
            &never_cancelled(),
        )
        .await;

        assert_eq!(
            harness.state_of(&harness.delivery.delivery_id).await,
            DeliveryState::Running,
            "a run already parked before the restart must not be driven — no session, no \
                 GateAnswer, nothing to resume it with"
        );
        assert_eq!(
            fresh_registry
                .active_run_count(harness.stored.binding.id)
                .unwrap(),
            1,
            "a parked run is still live: its admission slot must stay held, exactly like \
                 the live claim path's own RunConclusion::Parked"
        );
    }

    #[tokio::test]
    async fn a_running_deliverys_run_that_already_completed_before_the_restart_is_reconciled() {
        let harness = harness(completing_workflow()).await;
        let (run_id, _session_id) = harness
            .simulate_running_before_crash_with_state(RunState::Completed)
            .await;
        let (fresh, fresh_registry, _sessions) = harness.fresh_executor_after_restart();

        recover_after_restart(
            &fresh,
            &bindings_map(&harness.stored),
            DateTime::from_timestamp_nanos(0),
            &never_cancelled(),
        )
        .await;

        assert_eq!(
            harness.delivery_row().await.state,
            DeliveryState::Delivered,
            "a run that finished before the previous process could record it must be \
                 reconciled to Delivered, not left `running` forever"
        );
        assert_eq!(harness.run_state(run_id).await, RunState::Completed);
        assert_eq!(
            fresh_registry
                .active_run_count(harness.stored.binding.id)
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn a_running_delivery_whose_binding_is_no_longer_enabled_is_reseeded_but_left_alone() {
        let harness = harness(completing_workflow()).await;
        let _ids = harness
            .simulate_running_before_crash_with_state(RunState::Running)
            .await;
        let (fresh, fresh_registry, _sessions) = harness.fresh_executor_after_restart();

        // No bindings at all — the binding is treated as disabled/deleted
        // since this delivery started.
        recover_after_restart(
            &fresh,
            &HashMap::new(),
            DateTime::from_timestamp_nanos(0),
            &never_cancelled(),
        )
        .await;

        assert_eq!(
            harness.state_of(&harness.delivery.delivery_id).await,
            DeliveryState::Running,
            "a delivery whose binding no longer resolves must be left exactly as it is"
        );
        assert_eq!(
            fresh_registry
                .active_run_count(harness.stored.binding.id)
                .unwrap(),
            1,
            "the registry slot must still be re-seeded even when recovery cannot proceed \
                 past it — the slot is real regardless of whether this driver can act on it"
        );
    }

    // ── Mechanism 3: finish `cancellation_requested` deliveries ──────

    #[tokio::test]
    async fn a_cancellation_requested_running_delivery_is_cancelled_and_finished() {
        let harness = harness(completing_workflow()).await;
        let (run_id, session_id) = harness
            .simulate_cancellation_requested_before_crash(RunState::Running)
            .await;
        let (fresh, fresh_registry, fresh_sessions) = harness.fresh_executor_after_restart();
        assert_eq!(
            harness.state_of(&harness.delivery.delivery_id).await,
            DeliveryState::CancellationRequested
        );

        recover_after_restart(
            &fresh,
            &bindings_map(&harness.stored),
            DateTime::from_timestamp_nanos(0),
            &never_cancelled(),
        )
        .await;

        assert_eq!(
            harness.state_of(&harness.delivery.delivery_id).await,
            DeliveryState::Cancelled,
            "a cancellation-requested delivery whose run is actually confirmed Cancelled \
                 must finish the cancellation, not stay cancellation_requested forever"
        );
        assert_eq!(harness.run_state(run_id).await, RunState::Cancelled);
        assert_eq!(
            fresh_registry
                .active_run_count(harness.stored.binding.id)
                .unwrap(),
            0,
            "finishing the cancellation must release the admission slot it re-seeded"
        );
        assert!(
            fresh_sessions.actor(session_id).is_none(),
            "a finished cancellation must retire its session"
        );
        // Phase 8, T19a Task 7: `RunState::Cancelled` maps to `SessionOutcome::Cancelled`.
        match harness.session_close_outcome(session_id).await {
            Some(SessionOutcome::Cancelled) => {}
            other => panic!(
                "a delivery whose run reached Cancelled must close its session with a \
                     Cancelled terminator, got {other:?}"
            ),
        }
    }

    #[tokio::test]
    async fn a_cancellation_requested_delivery_already_cancelling_tolerates_not_cancellable() {
        let harness = harness(completing_workflow()).await;
        let (run_id, _session_id) = harness
            .simulate_cancellation_requested_before_crash(RunState::Cancelling)
            .await;
        let (fresh, fresh_registry, _sessions) = harness.fresh_executor_after_restart();

        recover_after_restart(
            &fresh,
            &bindings_map(&harness.stored),
            DateTime::from_timestamp_nanos(0),
            &never_cancelled(),
        )
        .await;

        assert_eq!(
            harness.state_of(&harness.delivery.delivery_id).await,
            DeliveryState::Cancelled,
            "ControlError::NotCancellable (already Cancelling) must be tolerated, not treated \
                 as a fatal error that abandons the row"
        );
        assert_eq!(harness.run_state(run_id).await, RunState::Cancelled);
        assert_eq!(
            fresh_registry
                .active_run_count(harness.stored.binding.id)
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn a_cancellation_requested_parked_run_is_still_cancelled_not_left_stuck() {
        let harness = harness(completing_workflow()).await;
        let (run_id, session_id) = harness
            .simulate_cancellation_requested_before_crash(RunState::AwaitingHuman)
            .await;
        let (fresh, fresh_registry, fresh_sessions) = harness.fresh_executor_after_restart();

        recover_after_restart(
            &fresh,
            &bindings_map(&harness.stored),
            DateTime::from_timestamp_nanos(0),
            &never_cancelled(),
        )
        .await;

        assert_eq!(
            harness.state_of(&harness.delivery.delivery_id).await,
            DeliveryState::Cancelled,
            "unlike Mechanism 2, a parked run here must still be cancelled — a park nobody \
                 will ever un-park is exactly the stuck-forever case this mechanism exists to \
                 close"
        );
        assert_eq!(harness.run_state(run_id).await, RunState::Cancelled);
        assert_eq!(
            fresh_registry
                .active_run_count(harness.stored.binding.id)
                .unwrap(),
            0
        );
        assert!(fresh_sessions.actor(session_id).is_none());
    }

    #[tokio::test]
    async fn a_cancellation_requested_deliverys_run_that_already_completed_is_reconciled() {
        let harness = harness(completing_workflow()).await;
        let (run_id, _session_id) = harness
            .simulate_cancellation_requested_before_crash(RunState::Completed)
            .await;
        let (fresh, fresh_registry, _sessions) = harness.fresh_executor_after_restart();

        recover_after_restart(
            &fresh,
            &bindings_map(&harness.stored),
            DateTime::from_timestamp_nanos(0),
            &never_cancelled(),
        )
        .await;

        assert_eq!(
            harness.delivery_row().await.state,
            DeliveryState::Delivered,
            "a run that raced its own cancellation and completed first must be reconciled \
                 to Delivered — forcing it to `cancelled` would be dishonest"
        );
        assert_eq!(harness.run_state(run_id).await, RunState::Completed);
        assert_eq!(
            fresh_registry
                .active_run_count(harness.stored.binding.id)
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn a_cancellation_requested_deliverys_run_that_already_failed_is_reconciled() {
        let harness = harness(completing_workflow()).await;
        let (run_id, _session_id) = harness
            .simulate_cancellation_requested_before_crash(RunState::Failed)
            .await;
        let (fresh, fresh_registry, _sessions) = harness.fresh_executor_after_restart();

        recover_after_restart(
            &fresh,
            &bindings_map(&harness.stored),
            DateTime::from_timestamp_nanos(0),
            &never_cancelled(),
        )
        .await;

        let row = harness.delivery_row().await;
        assert_eq!(
            row.state,
            DeliveryState::Failed,
            "a run that raced its own cancellation and failed first must be reconciled to \
                 Failed"
        );
        assert!(row.last_error.as_deref().is_some_and(|e| !e.is_empty()));
        assert_eq!(harness.run_state(run_id).await, RunState::Failed);
        assert_eq!(
            fresh_registry
                .active_run_count(harness.stored.binding.id)
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn a_cancellation_requested_delivery_whose_redrive_infra_fails_after_cancel_committed_stays_retryable(
    ) {
        let harness = harness(completing_workflow()).await;
        let (run_id, _session_id) = harness
            .simulate_cancellation_requested_before_crash(RunState::Running)
            .await;
        // `control::cancel` will still succeed (the run row is a real,
        // resolvable `Running` run); only the *redrive* that follows it
        // fails, because this executor's `DaemonResources` has no
        // workspace registry at all.
        let (fresh, fresh_registry, _sessions) = harness
            .fresh_executor_after_restart_without_workspace_registry()
            .await;

        recover_after_restart(
            &fresh,
            &bindings_map(&harness.stored),
            DateTime::from_timestamp_nanos(0),
            &never_cancelled(),
        )
        .await;

        assert_eq!(
            harness.state_of(&harness.delivery.delivery_id).await,
            DeliveryState::CancellationRequested,
            "a pre-run infra failure reached only after control::cancel already committed \
                 Cancelling must not fail the delivery to a terminal state — that would strand \
                 the run at non-terminal Cancelling forever, since every recovery mechanism \
                 lists deliveries by delivery state and a terminal delivery is never revisited"
        );
        assert_eq!(
            harness.run_state(run_id).await,
            RunState::Cancelling,
            "control::cancel must have actually committed before the redrive's infra \
                 failure"
        );
        assert_eq!(
            fresh_registry
                .active_run_count(harness.stored.binding.id)
                .unwrap(),
            1,
            "the registry slot must stay held (not released) so the next boot's Mechanism \
                 3 retries against an already-charged slot, exactly as every other \
                 leave-it-as-it-is path in this mechanism does"
        );
    }

    /// Phase 8, T19a Task 7: `release_session` (no terminator) must not
    /// poison a `session_id` for a LATER, successful redrive.
    ///
    /// The FIRST boot's own "no terminator" assertion
    /// below is vacuous by itself — `rebuild_and_drive_recovered_run`
    /// returns every `DeliveryError` (including `NoWorkspaceRegistry`,
    /// forced here) BEFORE `*session` is ever set, so `release_session`
    /// receives `None` and the `session_id` has zero events at that point;
    /// `None` can never distinguish `release_session` from
    /// `close_and_retire`. (`release_session_writes_no_terminator_for_a_
    /// real_session`, in `child_run_tests`, is the direct, non-vacuous
    /// proof of `release_session`'s own behavior against a real session.)
    /// The SECOND boot below is what this test actually establishes: with a
    /// real workspace registry, redriving the exact same delivery/run/
    /// session must still reach a genuine `Cancelled` terminator — proving
    /// the first (failed) attempt did not leave anything behind that would
    /// make this append fail with `StoreError::SessionClosed`.
    #[tokio::test]
    async fn a_cancellation_requested_delivery_whose_redrive_infra_failed_is_still_redrivable_to_a_real_terminator(
    ) {
        let harness = harness(completing_workflow()).await;
        let (run_id, session_id) = harness
            .simulate_cancellation_requested_before_crash(RunState::Running)
            .await;

        // First boot: the redrive's own infra fails (no workspace
        // registry), after `control::cancel` already committed
        // `Cancelling` — the exact scenario the previous test pins.
        // `release_session` runs here, since this delivery never reached
        // `Ok(DrivenRun::Outcome(RunOutcome::Terminal { .. }))`.
        let (failed_attempt, _registry, _sessions) = harness
            .fresh_executor_after_restart_without_workspace_registry()
            .await;
        recover_after_restart(
            &failed_attempt,
            &bindings_map(&harness.stored),
            DateTime::from_timestamp_nanos(0),
            &never_cancelled(),
        )
        .await;
        // Trivially true here (`session` was `None` throughout — see this
        // test's own doc comment), kept as a sanity check that the fixture
        // still behaves as documented rather than as independent proof.
        assert!(
            harness.session_close_outcome(session_id).await.is_none(),
            "an infra-failed redrive must write no SessionClosed terminator"
        );

        // Second boot: a real, working executor redrives the SAME
        // session_id/run_id to completion.
        let (fresh, fresh_registry, fresh_sessions) = harness.fresh_executor_after_restart();
        recover_after_restart(
            &fresh,
            &bindings_map(&harness.stored),
            DateTime::from_timestamp_nanos(0),
            &never_cancelled(),
        )
        .await;

        assert_eq!(
            harness.state_of(&harness.delivery.delivery_id).await,
            DeliveryState::Cancelled,
            "a later, working redrive of the same delivery must still reach its real \
                 terminal state — the first attempt's release_session must not have tripped \
                 the store's own tail guard"
        );
        assert_eq!(harness.run_state(run_id).await, RunState::Cancelled);
        match harness.session_close_outcome(session_id).await {
            Some(SessionOutcome::Cancelled) => {}
            other => panic!(
                "the later, successful redrive must close the session with a Cancelled \
                     terminator, got {other:?}"
            ),
        }
        assert_eq!(
            fresh_registry
                .active_run_count(harness.stored.binding.id)
                .unwrap(),
            0
        );
        assert!(fresh_sessions.actor(session_id).is_none());
    }

    #[tokio::test]
    async fn a_cancellation_requested_delivery_whose_binding_is_gone_is_reseeded_but_left_alone() {
        let harness = harness(completing_workflow()).await;
        let _ids = harness
            .simulate_cancellation_requested_before_crash(RunState::Running)
            .await;
        let (fresh, fresh_registry, _sessions) = harness.fresh_executor_after_restart();

        recover_after_restart(
            &fresh,
            &HashMap::new(),
            DateTime::from_timestamp_nanos(0),
            &never_cancelled(),
        )
        .await;

        assert_eq!(
            harness.state_of(&harness.delivery.delivery_id).await,
            DeliveryState::CancellationRequested,
            "a delivery whose binding no longer resolves must be left exactly as it is"
        );
        assert_eq!(
            fresh_registry
                .active_run_count(harness.stored.binding.id)
                .unwrap(),
            1,
            "the registry slot must still be re-seeded even when recovery cannot proceed"
        );
    }
}
