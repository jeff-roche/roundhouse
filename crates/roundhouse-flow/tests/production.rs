use std::collections::HashMap;
use std::fs;
use std::path::Path;

use roundhouse_core::{JobId, SessionId, Tier, Timestamp};
use roundhouse_flow::durability::{insert_workflow_run, open_test_db, RunState, WorkflowRun};
use roundhouse_flow::exec::run_loop::{
    run_workflow, GateAnswer, RunOutcome, SessionTree, WorkflowHostError,
};
use roundhouse_flow::exec::{RunContext, RunId, TaskSink};
use roundhouse_flow::expr::EnvAllowlist;
use roundhouse_flow::job::SessionTemplate;
use roundhouse_flow::job_store::register_workflow;
use roundhouse_flow::parking::park;
use roundhouse_flow::parking::Checkpointer;
use roundhouse_flow::parse::parse_workflow;
use roundhouse_flow::production::run_workflow_from_storage;
use roundhouse_flow::production::{FileCheckpointer, SqliteWorkflowHost};
use rusqlite::{params, Connection};
use serde_json::Value;
use tempfile::tempdir;

#[derive(Default)]
struct Sink;

impl TaskSink for Sink {
    fn emit(
        &mut self,
        _task_id: roundhouse_core::TaskId,
        _parent: Option<roundhouse_core::TaskId>,
        _kind: roundhouse_core::TaskKind,
        _payload: roundhouse_core::EventPayload,
    ) {
    }
}

#[derive(Default)]
struct RecordingSink {
    emitted: Vec<(roundhouse_core::TaskKind, roundhouse_core::EventPayload)>,
}

impl TaskSink for RecordingSink {
    fn emit(
        &mut self,
        _task_id: roundhouse_core::TaskId,
        _parent: Option<roundhouse_core::TaskId>,
        kind: roundhouse_core::TaskKind,
        payload: roundhouse_core::EventPayload,
    ) {
        self.emitted.push((kind, payload));
    }
}

#[derive(Default)]
struct RecordingSessionTree {
    children: HashMap<SessionId, Vec<SessionId>>,
    registered: Vec<(SessionId, SessionId, JobId)>,
}

impl SessionTree for RecordingSessionTree {
    fn reserve_child(
        &mut self,
        parent: SessionId,
        child: SessionId,
    ) -> Result<u32, WorkflowHostError> {
        let children = self.children.entry(parent).or_default();
        let count = u32::try_from(children.len())
            .map_err(|_| WorkflowHostError::ChildCountOverflow { session_id: parent })?;
        if !children.contains(&child) {
            children.push(child);
            children.pop();
        }
        Ok(count)
    }

    fn release_child(&mut self, _parent: SessionId, _child: SessionId) {}

    fn persist_child_session(
        &mut self,
        _txn: &rusqlite::Transaction<'_>,
        _child: &WorkflowRun,
    ) -> Result<(), WorkflowHostError> {
        Ok(())
    }

    fn register_child(
        &mut self,
        parent: SessionId,
        child: SessionId,
        job_id: JobId,
    ) -> Result<(), WorkflowHostError> {
        self.children.entry(parent).or_default().push(child);
        self.registered.push((parent, child, job_id));
        Ok(())
    }

    fn direct_children(&mut self, parent: SessionId) -> Result<u32, WorkflowHostError> {
        self.children.get(&parent).map_or(Ok(0), |children| {
            u32::try_from(children.len())
                .map_err(|_| WorkflowHostError::ChildCountOverflow { session_id: parent })
        })
    }
}

fn template() -> SessionTemplate {
    SessionTemplate {
        provider: "test".into(),
        model: "test-model".into(),
        cwd: "/tmp".into(),
        tools: vec![],
        isolation: Tier::Worktree,
        permission_policy_ref: "default".into(),
    }
}

fn workflow(name: &str) -> String {
    format!(
        "name: {name}\nversion: 1\npermissions:\n  default: deny\n  unattended:\n    escalate: fail\nsteps:\n  - id: result\n    emit: {{ value: ready }}\n"
    )
}

fn call_workflow() -> String {
    "name: parent\nversion: 1\npermissions:\n  default: deny\n  unattended:\n    escalate: fail\nsteps:\n  - id: child\n    call: child\n"
        .to_string()
}

fn gated_workflow() -> String {
    "name: parked\nversion: 1\npermissions:\n  default: deny\n  unattended:\n    escalate: fail\nsteps:\n  - id: approve\n    gate:\n      title: approve\n      form: { approved: { type: boolean } }\n      timeout: 1h\n      on_timeout: deny\n  - id: finished\n    needs: [approve]\n    emit: { value: finished }\n"
        .to_string()
}

fn seed_run(conn: &mut Connection, job_id: JobId, session_id: SessionId) -> RunId {
    let id = RunId::new();
    insert_workflow_run(
        conn,
        &WorkflowRun {
            id,
            job_id,
            job_version: 1,
            content_hash: "sha256:test".into(),
            session_id,
            binding_id: None,
            trigger_event_id: None,
            state: RunState::Running,
            parent_run_id: None,
            forked_from_run_id: None,
            awaiting_until: None,
            checkpoint_ref: None,
            checkpoint_blob_ref: None,
            started_at: Timestamp::from_unix_nanos(0),
            ended_at: None,
            session_depth: Some(0),
            caps: Some(Default::default()),
        },
    )
    .expect("seed workflow run");
    id
}

fn open_file_db(path: &Path) -> Connection {
    let mut conn = Connection::open(path).expect("open workflow database");
    roundhouse_store::migrations()
        .to_latest(&mut conn)
        .expect("apply workflow migrations");
    conn
}

fn context(run_id: RunId) -> RunContext {
    RunContext {
        inputs: Value::Object(Default::default()),
        vars: Value::Object(Default::default()),
        secrets: Default::default(),
        run_id,
        previous_report: None,
        env_allowlist: EnvAllowlist::deny_all(),
        worktree_provider: None,
    }
}

#[test]
fn file_checkpointer_prepares_a_content_addressed_checkpoint_artifact() {
    let workspace = tempdir().expect("workspace");
    let state = tempdir().expect("state");
    fs::write(workspace.path().join("source.txt"), "checkpoint me").expect("source");
    let mut checkpointer = FileCheckpointer::new(workspace.path(), state.path());

    let artifact = checkpointer
        .checkpoint_artifact(SessionId::new(), RunId::new(), "test")
        .expect("checkpoint artifact");
    assert!(artifact.blob_ref.is_some());
    assert_eq!(artifact.restore_ref.0.len(), 64);
}

#[test]
fn checkpoint_preparation_rejects_state_storage_inside_the_workspace() {
    let workspace = tempdir().expect("workspace");
    let state = workspace.path().join(".roundhouse-checkpoints");
    fs::write(workspace.path().join("source.txt"), "checkpoint me").expect("source");
    let mut checkpointer = FileCheckpointer::new(workspace.path(), state);

    checkpointer
        .checkpoint_artifact(SessionId::new(), RunId::new(), "test")
        .expect_err("checkpoint storage inside the workspace must be rejected");
}

#[test]
fn checkpoint_preparation_keeps_only_the_content_addressed_blob() {
    let workspace = tempdir().expect("workspace");
    let state = tempdir().expect("state");
    fs::write(workspace.path().join("source.txt"), "checkpoint me").expect("source");
    let mut checkpointer = FileCheckpointer::new(workspace.path(), state.path());

    let artifact = checkpointer
        .checkpoint_artifact(SessionId::new(), RunId::new(), "test")
        .expect("checkpoint artifact");

    assert!(artifact.blob_ref.is_some());
    assert!(
        fs::read_dir(state.path())
            .expect("state directory")
            .all(|entry| entry.expect("state entry").file_name() == "blobs"),
        "a prepared checkpoint must retain only content-addressed blobs"
    );
}

#[test]
fn restore_blob_validates_every_file_before_changing_the_workspace() {
    let workspace = tempdir().expect("workspace");
    let state = tempdir().expect("state");
    let first = workspace.path().join("first.txt");
    let second = workspace.path().join("second.txt");
    fs::write(&first, "snapshot first").expect("first snapshot");
    fs::write(&second, "snapshot second").expect("second snapshot");
    let session_id = SessionId::new();
    let mut checkpointer = FileCheckpointer::new(workspace.path(), state.path());
    let run_id = RunId::new();
    let artifact = checkpointer
        .checkpoint_artifact(session_id, run_id, "test")
        .expect("checkpoint artifact");
    let blob_ref = artifact.blob_ref.expect("blob checkpoint");

    fs::write(&first, "workspace first").expect("mutate first");
    fs::write(&second, "workspace second").expect("mutate second");
    let blob_path = state
        .path()
        .join("blobs")
        .join(&blob_ref.hash.as_str()[..2])
        .join(blob_ref.hash.as_str());
    let mut archive: serde_json::Value =
        serde_json::from_slice(&fs::read(&blob_path).expect("archive bytes"))
            .expect("archive json");
    archive["manifest"]["files"][1]["length"] = serde_json::json!(999);
    let tampered = serde_json::to_vec(&archive).expect("tampered archive");
    let tampered_ref = roundhouse_store::blobs::write_blob(state.path(), &tampered, None)
        .expect("write tampered blob");

    checkpointer
        .restore_blob(session_id, run_id, &tampered_ref)
        .expect_err("a malformed archive must be refused before restoration");

    assert_eq!(
        fs::read_to_string(&first).expect("first remains"),
        "workspace first"
    );
    assert_eq!(
        fs::read_to_string(&second).expect("second remains"),
        "workspace second"
    );
}

#[test]
fn restore_blob_replaces_the_workspace_with_the_checkpoint_contents() {
    let workspace = tempdir().expect("workspace");
    let state = tempdir().expect("state");
    let retained = workspace.path().join("retained.txt");
    fs::write(&retained, "snapshot").expect("snapshot file");
    let session_id = SessionId::new();
    let run_id = RunId::new();
    let mut checkpointer = FileCheckpointer::new(workspace.path(), state.path());
    let artifact = checkpointer
        .checkpoint_artifact(session_id, run_id, "test")
        .expect("checkpoint artifact");
    fs::write(&retained, "changed").expect("mutate retained file");
    fs::write(workspace.path().join("stale.txt"), "stale").expect("stale file");

    checkpointer
        .restore_blob(
            session_id,
            run_id,
            &artifact.blob_ref.expect("blob checkpoint"),
        )
        .expect("restore checkpoint");

    assert_eq!(
        fs::read_to_string(retained).expect("restored file"),
        "snapshot"
    );
    assert!(
        !workspace.path().join("stale.txt").exists(),
        "a restore must remove files absent from the checkpoint"
    );
}

#[cfg(unix)]
#[test]
fn restore_blob_does_not_follow_a_workspace_symlink_created_after_checkpointing() {
    use std::os::unix::fs::symlink;

    let workspace = tempdir().expect("workspace");
    let state = tempdir().expect("state");
    let outside = tempdir().expect("outside");
    let nested = workspace.path().join("nested");
    fs::create_dir(&nested).expect("nested directory");
    fs::write(nested.join("file.txt"), "snapshot").expect("snapshot file");
    let session_id = SessionId::new();
    let run_id = RunId::new();
    let mut checkpointer = FileCheckpointer::new(workspace.path(), state.path());
    let artifact = checkpointer
        .checkpoint_artifact(session_id, run_id, "test")
        .expect("checkpoint artifact");
    fs::remove_dir_all(&nested).expect("remove nested directory");
    symlink(outside.path(), &nested).expect("replace nested directory with symlink");

    checkpointer
        .restore_blob(
            session_id,
            run_id,
            &artifact.blob_ref.expect("blob checkpoint"),
        )
        .expect("restore checkpoint");

    assert!(
        !outside.path().join("file.txt").exists(),
        "checkpoint extraction must not escape through workspace symlinks"
    );
    assert_eq!(
        fs::read_to_string(nested.join("file.txt")).expect("restored nested file"),
        "snapshot"
    );
}

#[test]
fn production_host_runs_registered_workflow_and_reloads_it_after_restart() {
    let workspace = tempdir().expect("workspace");
    let source = workspace.path().join("workflow.yaml");
    fs::write(&source, workflow("registered")).expect("workflow source");
    let db_path = workspace.path().join("workflow.db");
    let mut conn = open_file_db(&db_path);
    let registered = register_workflow(
        &mut conn,
        workspace.path(),
        &source,
        template(),
        &workflow("registered"),
    )
    .expect("register workflow");
    let root_session = SessionId::new();
    let run_id = seed_run(&mut conn, registered.job.id(), root_session);
    let def = parse_workflow(&workflow("registered")).expect("parse workflow");
    let mut host = SqliteWorkflowHost::with_session_tree(
        workspace.path(),
        Box::new(RecordingSessionTree::default()),
    );
    let mut sink = Sink;

    let outcome = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        context(run_id),
        Timestamp::from_unix_nanos(1),
        None,
    )
    .expect("production host runs workflow");
    assert!(matches!(outcome, RunOutcome::Terminal { .. }));

    let checkpoint = host
        .checkpoint(root_session, RunId::new(), "restart-test")
        .expect("checkpoint persists");
    assert_eq!(checkpoint.0.len(), 64);
    drop(host);
    let restarted = SqliteWorkflowHost::new(workspace.path());
    let resolved = restarted
        .resolve_job(&conn, "registered")
        .expect("resolve after host restart")
        .expect("registered job");
    assert_eq!(resolved.job.id(), registered.job.id());
}

#[test]
fn parked_run_resumes_after_host_restart_from_durable_step_rows() {
    let workspace = tempdir().expect("workspace");
    let state = tempdir().expect("state");
    let source = workspace.path().join("workflow.yaml");
    let yaml = gated_workflow();
    fs::write(&source, &yaml).expect("workflow source");
    let db_path = state.path().join("workflow.db");
    let mut conn = open_file_db(&db_path);
    let registered = register_workflow(&mut conn, workspace.path(), &source, template(), &yaml)
        .expect("register workflow");
    let session_id = SessionId::new();
    let run_id = seed_run(&mut conn, registered.job.id(), session_id);
    conn.execute(
        "UPDATE workflow_run SET content_hash = ?1 WHERE id = ?2",
        params![
            roundhouse_flow::job::content_hash(registered.job.latest()),
            run_id.to_string()
        ],
    )
    .expect("pin registered workflow hash");
    let mut host = SqliteWorkflowHost::with_session_tree(
        workspace.path(),
        Box::new(RecordingSessionTree::default()),
    );
    let mut sink = Sink;

    let parked = run_workflow_from_storage(
        &mut conn,
        run_id,
        &mut sink,
        &mut host,
        context(run_id),
        Timestamp::from_unix_nanos(1),
        None,
    )
    .expect("park workflow");
    let checkpoint = match &parked {
        RunOutcome::Parked(result) => result.checkpoint_ref.clone(),
        other => panic!("expected a park, got {other:?}"),
    };
    assert_eq!(
        roundhouse_flow::durability::recover_run(&conn, run_id)
            .expect("recover parked run")
            .run
            .checkpoint_ref
            .as_deref(),
        Some(checkpoint.0.as_str()),
        "the checkpoint reference must survive independently of the in-memory ParkResult"
    );
    let checkpoint_blob: Option<String> = conn
        .query_row(
            "SELECT checkpoint_blob_ref FROM workflow_run WHERE id = ?1",
            [run_id.to_string()],
            |row| row.get(0),
        )
        .expect("checkpoint blob reference");
    let checkpoint_blob = checkpoint_blob.expect("park records a content-addressed blob");
    let blob_ref_count: i64 = conn
        .query_row(
            "SELECT ref_count FROM blobs WHERE hash = json_extract(?1, '$.hash')",
            [checkpoint_blob],
            |row| row.get(0),
        )
        .expect("indexed checkpoint blob");
    assert_eq!(blob_ref_count, 1);
    assert_eq!(
        roundhouse_flow::durability::recover_run(&conn, run_id)
            .expect("recover parked run")
            .steps
            .len(),
        1,
        "the gate step is durable before the host is dropped"
    );

    fs::write(&source, "name: changed\n").expect("change workspace after checkpoint");
    drop(host);
    drop(conn);
    let mut restarted = SqliteWorkflowHost::new(workspace.path());
    let conn = open_file_db(&db_path);
    restarted
        .restore_run(&conn, run_id)
        .expect("restore checkpoint blob after restart");
    drop(conn);
    let mut conn = open_file_db(&db_path);
    assert_eq!(
        fs::read_to_string(&source).expect("read restored source"),
        yaml
    );
    let mut sink = Sink;
    let resumed = run_workflow_from_storage(
        &mut conn,
        run_id,
        &mut sink,
        &mut restarted,
        context(run_id),
        Timestamp::from_unix_nanos(2),
        Some(GateAnswer {
            step_id: "approve".into(),
            output: serde_json::json!({ "approved": true }),
        }),
    )
    .expect("resume workflow after restart");
    assert!(matches!(resumed, RunOutcome::Terminal { .. }));
    assert_eq!(
        roundhouse_flow::durability::recover_run(&conn, run_id)
            .expect("recover completed run")
            .run
            .state,
        RunState::Completed
    );
    let remaining_refs: i64 = conn
        .query_row("SELECT COALESCE(SUM(ref_count), 0) FROM blobs", [], |row| {
            row.get(0)
        })
        .expect("read checkpoint blob references");
    assert_eq!(
        remaining_refs, 0,
        "resuming a run releases its checkpoint blob"
    );
}

#[test]
fn parking_emits_a_checkpoint_task_to_the_session_log() {
    let workspace = tempdir().expect("workspace");
    let source = workspace.path().join("workflow.yaml");
    let yaml = gated_workflow();
    fs::write(&source, &yaml).expect("workflow source");
    let mut conn = open_test_db();
    let registered = register_workflow(&mut conn, workspace.path(), &source, template(), &yaml)
        .expect("register workflow");
    let run_id = seed_run(&mut conn, registered.job.id(), SessionId::new());
    let def = parse_workflow(&yaml).expect("parse workflow");
    let mut host = SqliteWorkflowHost::with_session_tree(
        workspace.path(),
        Box::new(RecordingSessionTree::default()),
    );
    let mut sink = RecordingSink::default();

    run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        context(run_id),
        Timestamp::from_unix_nanos(1),
        None,
    )
    .expect("park workflow");

    assert!(sink.emitted.iter().any(|(kind, payload)| {
        *kind == roundhouse_core::TaskKind::Checkpoint
            && matches!(
                payload,
                roundhouse_core::EventPayload::TaskCreated {
                    kind: roundhouse_core::TaskKind::Checkpoint,
                    ..
                }
            )
    }));
}

#[test]
fn storage_resume_executes_the_run_version_not_the_latest_registered_version() {
    let workspace = tempdir().expect("workspace");
    let source = workspace.path().join("versioned.yaml");
    let version_one = workflow("version-one");
    let version_two = version_one
        .replace("ready", "newest")
        .replace("version: 1", "version: 2");
    fs::write(&source, &version_one).expect("workflow source");
    let mut conn = open_file_db(&workspace.path().join("workflow.db"));
    let first = register_workflow(
        &mut conn,
        workspace.path(),
        &source,
        template(),
        &version_one,
    )
    .expect("register first version");
    let latest = register_workflow(
        &mut conn,
        workspace.path(),
        &source,
        template(),
        &version_two,
    )
    .expect("register second version");
    assert_eq!(latest.job.latest().version(), 2);

    let run_id = seed_run(&mut conn, first.job.id(), SessionId::new());
    conn.execute(
        "UPDATE workflow_run SET content_hash = ?1 WHERE id = ?2",
        params![
            roundhouse_flow::job::content_hash(first.job.pinned(1).expect("version one")),
            run_id.to_string()
        ],
    )
    .expect("pin version one hash");
    let mut host = SqliteWorkflowHost::with_session_tree(
        workspace.path(),
        Box::new(RecordingSessionTree::default()),
    );
    let mut sink = Sink;

    let RunOutcome::Terminal { steps, .. } = run_workflow_from_storage(
        &mut conn,
        run_id,
        &mut sink,
        &mut host,
        context(run_id),
        Timestamp::from_unix_nanos(1),
        None,
    )
    .expect("run pinned version") else {
        panic!("versioned workflow must terminate");
    };
    assert_eq!(steps[0].output["value"], "ready");
}

#[test]
fn production_host_pins_called_job_and_rejects_the_ninth_direct_child() {
    let workspace = tempdir().expect("workspace");
    let parent_source = workspace.path().join("parent.yaml");
    let child_source = workspace.path().join("child.yaml");
    let parent_yaml = call_workflow();
    let child_yaml = workflow("child");
    fs::write(&parent_source, &parent_yaml).expect("parent source");
    fs::write(&child_source, &child_yaml).expect("child source");
    let mut conn = open_test_db();
    let parent = register_workflow(
        &mut conn,
        workspace.path(),
        &parent_source,
        template(),
        &parent_yaml,
    )
    .expect("register parent");
    let child = register_workflow(
        &mut conn,
        workspace.path(),
        &child_source,
        template(),
        &child_yaml,
    )
    .expect("register child");
    let parent_run = seed_run(&mut conn, parent.job.id(), SessionId::new());
    let def = parse_workflow(&parent_yaml).expect("parse parent");
    let mut host = SqliteWorkflowHost::with_session_tree(
        workspace.path(),
        Box::new(RecordingSessionTree::default()),
    );
    let mut sink = Sink;

    let first = run_workflow(
        &mut conn,
        &def,
        parent_run,
        &mut sink,
        &mut host,
        context(parent_run),
        Timestamp::from_unix_nanos(1),
        None,
    )
    .expect("run parent");
    assert!(matches!(first, RunOutcome::Terminal { .. }));
    let child_row: (String, i64, String) = conn
        .query_row(
            "SELECT job_id, job_version, content_hash FROM workflow_run WHERE parent_run_id = ?1",
            [parent_run.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap_or_else(|error| panic!("child run row: {error}; outcome={first:?}"));
    assert_eq!(child_row.0, child.job.id().to_string());
    assert_eq!(child_row.1, 1);
    assert_eq!(
        child_row.2,
        roundhouse_flow::job::content_hash(child.job.latest())
    );

    // The authoritative session tree includes eight existing agent children;
    // a workflow call is the ninth direct child and must be refused before a
    // workflow_run row is inserted.
    let second_session = SessionId::new();
    let second_parent = seed_run(&mut conn, parent.job.id(), second_session);
    let mut tree = RecordingSessionTree::default();
    for _ in 0..8 {
        tree.children
            .entry(second_session)
            .or_default()
            .push(SessionId::new());
    }
    let mut host = SqliteWorkflowHost::with_session_tree(workspace.path(), Box::new(tree));
    let mut sink = Sink;
    let refused = run_workflow(
        &mut conn,
        &def,
        second_parent,
        &mut sink,
        &mut host,
        context(second_parent),
        Timestamp::from_unix_nanos(2),
        None,
    )
    .expect("fan-out refusal is a workflow failure");
    let RunOutcome::Terminal { state, .. } = refused else {
        panic!("fan-out refusal must finish the parent");
    };
    assert_eq!(state, RunState::Failed);

    let deep_parent = seed_run(&mut conn, parent.job.id(), SessionId::new());
    conn.execute(
        "UPDATE workflow_run SET session_depth = ?1 WHERE id = ?2",
        params![
            i64::from(roundhouse_flow::compose::MAX_CALL_DEPTH),
            deep_parent.to_string()
        ],
    )
    .expect("seed maximum call depth");
    let mut host = SqliteWorkflowHost::with_session_tree(
        workspace.path(),
        Box::new(RecordingSessionTree::default()),
    );
    let mut sink = Sink;
    let refused = run_workflow(
        &mut conn,
        &def,
        deep_parent,
        &mut sink,
        &mut host,
        context(deep_parent),
        Timestamp::from_unix_nanos(3),
        None,
    )
    .expect("depth refusal is a workflow failure");
    let RunOutcome::Terminal { state, .. } = refused else {
        panic!("depth refusal must finish the parent");
    };
    assert_eq!(state, RunState::Failed);
}

#[test]
fn checkpoint_restore_rejects_another_runs_blob_before_changing_the_workspace() {
    let workspace = tempdir().expect("workspace");
    let state = tempdir().expect("state");
    let source = workspace.path().join("source.txt");
    fs::write(&source, "snapshot").expect("source");
    let session_id = SessionId::new();
    let owner_run = RunId::new();
    let mut checkpointer = FileCheckpointer::new(workspace.path(), state.path());
    let artifact = checkpointer
        .checkpoint_artifact(session_id, owner_run, "owner")
        .expect("checkpoint");
    fs::write(&source, "workspace").expect("mutate workspace");

    checkpointer
        .restore_blob(session_id, RunId::new(), &artifact.blob_ref.expect("blob"))
        .expect_err("a checkpoint cannot be restored by another run");

    assert_eq!(
        fs::read_to_string(source).expect("workspace remains"),
        "workspace"
    );
}

#[test]
fn repark_replaces_the_previous_checkpoint_blob_reference() {
    let workspace = tempdir().expect("workspace");
    let state = tempdir().expect("state");
    let source = workspace.path().join("source.txt");
    fs::write(&source, "first checkpoint").expect("source");
    let session_id = SessionId::new();
    let mut conn = open_test_db();
    let run_id = seed_run(&mut conn, JobId::new(), session_id);
    let awaiting = roundhouse_flow::hitl::AwaitingHuman {
        task_id: roundhouse_core::TaskId::new(),
        source: roundhouse_flow::hitl::HumanWaitSource::Elicitation,
        form_schema: serde_json::json!({"type": "object"}),
        timeout_after: None,
        on_timeout: roundhouse_flow::hitl::UncheckedOnTimeout::new(
            roundhouse_flow::parse::types::OnTimeout::Deny,
        ),
    };
    let mut checkpointer = FileCheckpointer::new(workspace.path(), state.path());

    park(
        &mut conn,
        run_id,
        &awaiting,
        false,
        Timestamp::from_unix_nanos(1),
        &mut checkpointer,
    )
    .expect("first park");
    fs::write(&source, "second checkpoint").expect("change source");
    park(
        &mut conn,
        run_id,
        &awaiting,
        false,
        Timestamp::from_unix_nanos(2),
        &mut checkpointer,
    )
    .expect("re-park");

    let references: i64 = conn
        .query_row("SELECT COALESCE(SUM(ref_count), 0) FROM blobs", [], |row| {
            row.get(0)
        })
        .expect("blob references");
    assert_eq!(references, 1);
}

#[test]
fn failed_park_indexes_the_prepared_blob_for_garbage_collection() {
    let workspace = tempdir().expect("workspace");
    let state = tempdir().expect("state");
    fs::write(workspace.path().join("source.txt"), "checkpoint").expect("source");
    let session_id = SessionId::new();
    let mut conn = open_test_db();
    let run_id = seed_run(&mut conn, JobId::new(), session_id);
    let awaiting = roundhouse_flow::hitl::AwaitingHuman {
        task_id: roundhouse_core::TaskId::new(),
        source: roundhouse_flow::hitl::HumanWaitSource::Elicitation,
        form_schema: serde_json::json!({"type": "object"}),
        timeout_after: None,
        on_timeout: roundhouse_flow::hitl::UncheckedOnTimeout::new(
            roundhouse_flow::parse::types::OnTimeout::Deny,
        ),
    };
    let mut checkpointer = FileCheckpointer::with_quota(workspace.path(), state.path(), 0);

    park(
        &mut conn,
        run_id,
        &awaiting,
        false,
        Timestamp::from_unix_nanos(1),
        &mut checkpointer,
    )
    .expect_err("quota rejection must fail the park");

    assert_eq!(
        roundhouse_store::blobs::gc_eligible_blobs(&conn, 1, 0)
            .expect("query eligible blobs")
            .len(),
        1,
        "failed parking must leave the prepared blob indexed with no references"
    );
}
