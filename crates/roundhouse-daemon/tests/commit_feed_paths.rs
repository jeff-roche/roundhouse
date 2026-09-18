//! Phase 8 Task 21, Task 2: every direct-commit path — one that appends through its own
//! transaction rather than through `spawn_writer` — must notify the shared `CommitFeed`
//! once its transaction commits. Task 1 already covers `spawn_writer`'s own paths
//! (`roundhouse-store`'s `tests/commit_feed.rs`); this file covers the two direct paths
//! reachable from outside `roundhouse-daemon`'s own crate boundary:
//!
//! - `DaemonSubAgentHost::persist_session_created`, reached through the real
//!   `SubAgentHost::create_child_session` entry point (`sub_agent_host.rs`).
//! - `roundhouse-flow`'s `SqliteWorkflowHost::create_child_run`, which drives
//!   `WorkflowSessionTree::persist_child_session`/`persist_parent_call_task` inside one
//!   transaction and calls `register_child` only after that transaction commits
//!   (`workflow_host.rs`).
//!
//! The third direct path, `scheduler_driver.rs`'s private `flush_task_events`, is
//! `pub(crate)` to that crate and has no entry point this external test binary can reach —
//! it is pinned instead by `scheduler_driver::child_run_tests`' own
//! `flush_task_events_wakes_a_watcher_only_after_its_events_commit`, driven directly
//! against the real function with a self-chosen `session_id` (no race to avoid: an
//! ordinary synchronous call inside that test, not a backgrounded task).
//!
//! Both tests here choose their own target session id, rather than driving the fuller
//! `dispatch_agent`/scheduled-run machinery that mints one internally: a `CommitFeed`
//! watch has to be registered BEFORE the append it means to catch (an unwatched `notify()`
//! is a documented no-op — see `CommitFeed::notify`'s own doc comment), and a session id
//! learned only after the fact would always lose that race. Both call directly into the
//! real production implementor (`DaemonSubAgentHost`/`SqliteWorkflowHost` +
//! `WorkflowSessionTree`) at the point each one is handed a caller-chosen id for real, in
//! production too (`agent_spawn_tool::spawn_child`'s own `let child = SessionId::new();`,
//! `roundhouse-flow`'s own child-run construction) — so this is the real entry point, not
//! a reimplementation of it.

mod common;

use std::sync::Arc;
use std::time::Duration;

use roundhouse_bus::spawn_tree::SpawnTree;
use roundhouse_core::{JobId, OnDegrade, SessionId, SessionSpec, TaskId, TaskInput, Tier};
use roundhouse_daemon::session_registry::SessionRegistry;
use roundhouse_daemon::sub_agent_host::wire_sub_agent_host;
use roundhouse_daemon::workflow_host::WorkflowSessionTree;
use roundhouse_engine::agent_spawn::{Budget, TaintSet};
use roundhouse_engine::tools::agent_spawn_tool::ChildSessionRequest;
use roundhouse_engine::SessionActor;
use roundhouse_flow::caps::ResourceCaps;
use roundhouse_flow::durability::{
    insert_workflow_run, open_test_db, ChildCallJoin, StepDisposition, StepRunState,
    WorkflowChildCall, WorkflowRun, WorkflowStepRun,
};
use roundhouse_flow::exec::run_loop::{CalledWorkflow, WorkflowHost};
use roundhouse_flow::exec::RunId;
use roundhouse_flow::production::SqliteWorkflowHost;
use roundhouse_store::CommitFeed;

/// A real, minimal parent `SessionActor` good enough to register a real
/// `DaemonSubAgentHost` on — modelled on `agent_spawn_taint_boundary.rs`'s own
/// `parent_actor`, which this file does not share a module with (it lives in a
/// different `tests/*.rs` binary, so it is its own separate crate).
async fn parent_actor(
    dir: &std::path::Path,
    writer: roundhouse_store::EventWriter,
) -> Arc<SessionActor> {
    let policy = Arc::new(roundhouse_policy::engine::PolicyEngine::from_rules(vec![]));
    let isolate = common::available_isolate();
    let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
    let handle = isolate.prepare(&spec).await.unwrap();
    Arc::new(SessionActor::new_with_workspace_root(
        SessionId::new(),
        writer,
        roundhouse_core::SessionState::Running,
        common::runner(),
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

/// The direct-commit path in `sub_agent_host.rs`: `DaemonSubAgentHost::
/// persist_session_created`, reached through the real `SubAgentHost::create_child_session`
/// trait method — the same method `agent_spawn_tool::dispatch_agent`'s `spawn_child` calls
/// after it mints the child's id, just without going through that dispatcher's own
/// admission/budget machinery, which this path's own notify wiring does not depend on.
#[tokio::test]
async fn sub_agent_create_child_session_notifies_the_childs_own_commit_feed() {
    let dir = tempfile::tempdir().unwrap();
    let resources = common::real_resources(dir.path()).await;
    let registry = Arc::new(SessionRegistry::new());
    let writer = roundhouse_store::spawn_writer(resources.store.clone()).await;
    let actor = parent_actor(dir.path(), writer).await;
    let parent = actor.session_id();
    wire_sub_agent_host(&actor, &resources, &registry);
    let host = actor
        .sub_agent_host()
        .expect("wire_sub_agent_host just registered one");

    // Chosen here, exactly as `agent_spawn_tool::spawn_child` chooses one for a real
    // model-issued spawn — see this file's own module doc for why the watch below must be
    // registered against this id before `create_child_session` runs, not after.
    let child = SessionId::new();
    let commit_feed = resources.store.commit_feed().clone();
    let mut watch = commit_feed.watch(child);
    watch.mark_seen();

    host.create_child_session(ChildSessionRequest {
        parent,
        child,
        depth: 1,
        child_budget: Budget {
            remaining_tokens: 1_000,
        },
        spec: SessionSpec {
            workspace: actor.session_spec().workspace,
            name: None,
            requested_tier: Tier::Sandbox,
            on_degrade: OnDegrade::Refuse,
            parent: Some(parent),
        },
        workspace_root: actor.workspace_root().to_path_buf(),
        workspace_identity: actor.workspace_identity(),
        taint: TaintSet::default(),
    })
    .await
    .expect("a plain child-session request against a freshly wired host must succeed");

    tokio::time::timeout(Duration::from_secs(5), watch.changed())
        .await
        .expect(
            "persist_session_created must notify the child's own commit feed once its \
             SessionCreated transaction commits",
        );
}

fn parent_run(session_id: SessionId) -> WorkflowRun {
    WorkflowRun {
        id: RunId::new(),
        job_id: JobId::new(),
        job_version: 1,
        content_hash: "sha256:parent".into(),
        session_id,
        binding_id: None,
        trigger_event_id: None,
        state: roundhouse_flow::durability::RunState::Running,
        parent_run_id: None,
        forked_from_run_id: None,
        awaiting_until: None,
        checkpoint_ref: None,
        checkpoint_blob_ref: None,
        started_at: roundhouse_core::Timestamp::from_unix_nanos(1),
        ended_at: None,
        session_depth: Some(0),
        caps: Some(ResourceCaps {
            max_tokens: 6_000,
            max_cost_usd: 6_000.0,
            max_tasks: 6_000,
            max_tool_calls: 6_000,
            max_subagents: 6_000,
            max_bytes_written: 6_000,
            max_escalations: 6_000,
            ..ResourceCaps::default()
        }),
    }
}

fn child_run(parent_run_id: RunId, session_id: SessionId) -> WorkflowRun {
    let mut run = parent_run(session_id);
    run.id = RunId::new();
    run.parent_run_id = Some(parent_run_id);
    run.session_depth = Some(1);
    run.content_hash = "sha256:child".into();
    run
}

/// The direct-commit path split across `roundhouse-flow` and `workflow_host.rs`:
/// `SqliteWorkflowHost::create_child_run` persists the child's `SessionCreated` and the
/// parent's `TaskCreated` in one transaction it owns and commits itself, then calls
/// `WorkflowSessionTree::register_child` — which is what actually drains both stashed
/// receipts into `CommitFeed::notify_appended` (Task 2's `pending_notify` hand-off,
/// exercised in isolation by `workflow_host.rs`'s own unit tests). This test proves the
/// hand-off end to end, through the real `WorkflowHost` trait method, not just through
/// `WorkflowSessionTree` directly.
#[tokio::test]
async fn workflow_create_child_run_notifies_both_the_parent_and_child_sessions() {
    let mut conn = open_test_db();
    let parent_session = SessionId::new();
    let parent = parent_run(parent_session);
    let parent_run_id = parent.id;
    insert_workflow_run(&mut conn, &parent).unwrap();

    let child_session = SessionId::new();
    let child = child_run(parent_run_id, child_session);

    let commit_feed = CommitFeed::default();
    let mut parent_watch = commit_feed.watch(parent_session);
    let mut child_watch = commit_feed.watch(child_session);
    parent_watch.mark_seen();
    child_watch.mark_seen();

    let session_tree = WorkflowSessionTree::new(
        Arc::new(SpawnTree::new()),
        common::runner(),
        SessionSpec::test_default(),
        commit_feed,
    );
    let workspace_dir = tempfile::tempdir().unwrap();
    let mut host = SqliteWorkflowHost::with_session_tree(
        workspace_dir.path().to_path_buf(),
        Box::new(session_tree),
    );

    let called = CalledWorkflow {
        job_id: child.job_id,
        job_version: child.job_version,
        content_hash: child.content_hash.clone(),
        session_id: child_session,
    };
    host.reserve_child_session(parent_session, &called)
        .expect("an unreserved fan-out ceiling must admit the first child");

    let parent_step = WorkflowStepRun {
        run_id: parent_run_id,
        step_id: "call_it".into(),
        attempt: 1,
        item_index: None,
        disposition: StepDisposition::Effectful,
        state: StepRunState::Running,
        first_task_seq: None,
        last_task_seq: None,
        output: None,
        error: None,
    };
    let parent_call = WorkflowChildCall {
        child_run_id: child.id,
        parent_run_id,
        parent_step_id: "call_it".into(),
        parent_attempt: 1,
        parent_item_index: None,
        parent_task_id: TaskId::new(),
        join: ChildCallJoin::Pending,
    };

    host.create_child_run(
        &mut conn,
        parent_session,
        &child,
        &called,
        &parent_step,
        &parent_call,
        TaskInput::Text("call it".into()),
    )
    .expect("a well-formed child-run creation against a freshly reserved slot must succeed");

    tokio::time::timeout(Duration::from_secs(5), parent_watch.changed())
        .await
        .expect(
            "create_child_run must notify the parent's own session once its TaskCreated \
             transaction commits",
        );
    tokio::time::timeout(Duration::from_secs(5), child_watch.changed())
        .await
        .expect(
            "create_child_run must notify the child's own session once its SessionCreated \
             transaction commits",
        );
}
