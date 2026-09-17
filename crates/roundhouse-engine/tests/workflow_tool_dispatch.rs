//! Tests for Phase 8 Task 25.4: lifting the `Read`-only gate to an allowlist
//! and refusing unknown tool names.
//!
//! These tests verify that `dispatch_tool_for_workflow` accepts the five
//! allowlisted kinds (Read, Write, Edit, Find, Shell) and rejects everything else.

use roundhouse_core::{
    EventPayload, OnDegrade, SessionId, SessionState, TaskKind, TaskRunner, Tier,
};
use roundhouse_engine::workflow_dispatch::{dispatch_tool_for_workflow, DispatchOutcome};
use roundhouse_engine::SessionActor;
use roundhouse_policy::engine::{
    CompiledRule, Outcome as PolicyOutcome, PolicyEngine, Predicate, Scope,
};
use roundhouse_policy::FsOp;
use roundhouse_sandbox::{
    Attestation, Child, CommandSpec, Handle, Isolate, IsolationError, ProbeResult,
    Tier as SandboxTier,
};
use roundhouse_store::{open, session_events, spawn_writer, StorePool};
use serde_json::json;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

/// A generous, fixed bound used by every test in this file that is not
/// itself testing `step_timeout` enforcement — long enough that no ordinary
/// dispatch here could plausibly hit it, so it behaves as "no timeout" for
/// every test that doesn't care.
const AMPLE_STEP_TIMEOUT: Duration = Duration::from_secs(30);

/// Single-instance pattern — `TaskRunner::bootstrap()` panics on a second call per process.
static RUNNER: once_cell::sync::Lazy<TaskRunner> =
    once_cell::sync::Lazy::new(TaskRunner::bootstrap);

/// Test isolate whose `spawn` really launches the requested process, copying
/// `agent_loop_dispatch.rs`'s own `TestIsolate` rather than returning
/// `IsolationError::Unsupported`.
///
/// This is what makes `shell_tool_dispatches_through` below able to *prove*
/// rather than assert that control reached `execute_builtin`'s
/// `TaskParams::Shell` arm: that arm is the only code path in
/// `dispatch_tool_for_workflow` that calls `spawn_isolated` at all, so the
/// dispatched script's own stdout appearing in the returned output is
/// evidence no earlier chokepoint (the allowlist gate,
/// `task_params_for_in_workspace`, `admit_task`, `record_task_started`)
/// short-circuited first. An inert isolate would have let the test claim the
/// same thing on the strength of a failure message alone.
///
/// This is a *test* isolate, not isolation: it spawns an ordinary child
/// process with no sandbox. Real isolation wiring for workflow shell steps
/// is Task 2's job, not this test's.
struct TestIsolate;

#[async_trait::async_trait]
impl Isolate for TestIsolate {
    fn declared(&self) -> SandboxTier {
        SandboxTier::Sandbox
    }
    async fn probe(&self) -> ProbeResult {
        ProbeResult {
            achieved: SandboxTier::Sandbox,
            degradations: vec![],
        }
    }
    async fn prepare(
        &self,
        _spec: &roundhouse_core::SessionSpec,
    ) -> Result<Handle, IsolationError> {
        Ok(Handle {
            id: "test-isolate".into(),
        })
    }
    async fn spawn(&self, _handle: &Handle, command: CommandSpec) -> Result<Child, IsolationError> {
        let mut process = tokio::process::Command::new(&command.program);
        process
            .args(&command.argv)
            .current_dir(command.cwd.as_deref().unwrap_or("."))
            .env_clear()
            .envs(command.env)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        #[cfg(unix)]
        process.process_group(0);
        let child = process
            .spawn()
            .map_err(|err| IsolationError::Unsupported(err.to_string()))?;
        let pid = child
            .id()
            .ok_or_else(|| IsolationError::Unsupported("test child has no pid".into()))?;
        Ok(Child::from_process(pid, child))
    }
    fn attest(&self, _handle: &Handle) -> Attestation {
        // Must equal the session's requested tier below: `sealed_tier_shortfall`
        // (`roundhouse_policy::sealed`) denies *every* task, whatever its params,
        // when `attested_tier < requested_tier`.
        Attestation {
            tier: SandboxTier::Sandbox,
            digest: "test".into(),
            net_enforced: false,
        }
    }
    async fn teardown(&self, _handle: Handle) -> Result<(), IsolationError> {
        Ok(())
    }
}

/// Sets up a minimal SessionActor for testing dispatch_tool_for_workflow.
/// Returns (actor, workspace_root_path, db_path) so tests can use the real
/// workspace root and read back the events the dispatch recorded.
async fn setup_actor(
    dir: &TempDir,
    rules: Vec<CompiledRule>,
) -> (Arc<SessionActor>, PathBuf, PathBuf, SessionId) {
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let isolate: Arc<dyn Isolate> = Arc::new(TestIsolate);
    let session_spec =
        roundhouse_core::SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
    let handle = isolate.prepare(&session_spec).await.unwrap();
    let session_id = SessionId::new();

    let workspace_root = dir.path().canonicalize().unwrap();

    let actor = Arc::new(SessionActor::new_with_workspace_root(
        session_id,
        writer,
        SessionState::Running,
        &RUNNER,
        Arc::new(PolicyEngine::from_rules(rules)),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        workspace_root.clone(),
        isolate,
        handle,
        session_spec,
        vec![],
    ));

    (actor, workspace_root, db_path, session_id)
}

/// Writes `contents` to an executable file `name` directly in
/// `workspace_root`, and returns the exact `program` string a shell dispatch
/// of it will be judged and executed under.
///
/// **Why an absolute, workspace-local script instead of a bare `"echo"`:**
/// `resolve_shell_program` (`roundhouse_engine::tool_dispatch`) splits on
/// whether the raw program contains a `/`. A bare name takes the
/// `resolve_bare_program_on_path` branch, whose result is whatever the
/// daemon's own `PATH` happens to resolve to (`/usr/bin/echo` on this
/// machine, something else on the next) — and `Predicate::Shell`'s program
/// comparison in `roundhouse-policy`'s `engine.rs` is an exact string match,
/// so no portable rule can be written against it. A `/`-containing program
/// takes the other branch, which skips `PATH` entirely and returns the
/// canonicalized *parent directory* joined with the *literal* final path
/// component — deliberately not a fully symlink-resolved path, so that
/// `is_interpreter`/`sealed_program`'s basename matching keeps working. This
/// helper reproduces exactly that computation, so the returned string is both
/// what the policy rule matches on and what the isolate is asked to spawn.
fn workspace_program(workspace_root: &Path, name: &str, contents: &str) -> String {
    let script = workspace_root.join(name);
    std::fs::write(&script, contents).unwrap();
    #[cfg(unix)]
    {
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();
    }
    // Mirrors `resolve_shell_program`'s `/`-containing branch: canonical
    // parent + literal file name (never `script.canonicalize()`, which would
    // also resolve the final component and so could disagree).
    script
        .parent()
        .unwrap()
        .canonicalize()
        .unwrap()
        .join(name)
        .to_string_lossy()
        .into_owned()
}

/// Reopens `db_path` and returns the `IsolationAttestation` carried by
/// `task_id`'s own `TaskStarted` event — the only place an attestation is
/// recorded (`dispatch_tool_for_workflow` never writes one to the `tasks`
/// materialized view).
async fn started_isolation(
    db_path: &Path,
    session_id: SessionId,
    task_id: roundhouse_core::TaskId,
) -> roundhouse_core::IsolationAttestation {
    let reopened = open(db_path).await.unwrap();
    session_events(&reopened, session_id)
        .await
        .unwrap()
        .into_iter()
        .find_map(|e| match e.payload {
            EventPayload::TaskStarted { isolation, .. } if e.task_id == Some(task_id) => {
                Some(isolation)
            }
            _ => None,
        })
        .expect("the dispatched task's own TaskStarted event must exist in the session log")
}

/// Panics with `context` naming the actual outcome unless `result` is
/// `DispatchOutcome::Completed` — Phase 8 Task 25.4 Task 4's `DispatchOutcome`
/// three-way replaced the old `Result<Value, String>` this file's
/// `dispatches_through` tests used to `.unwrap_or_else` directly.
fn expect_completed<'a>(result: &'a DispatchOutcome, context: &str) -> &'a serde_json::Value {
    match result {
        DispatchOutcome::Completed(value) => value,
        other => panic!("{context}: {other:?}"),
    }
}

/// Names one stored event's payload variant — shared by every test in this
/// file that asserts on the exact shape of a dispatched task's own event
/// sequence (Phase 8 Task 19 lane B, Task 9).
fn event_kind(payload: &EventPayload) -> &'static str {
    match payload {
        EventPayload::TaskCreated { .. } => "TaskCreated",
        EventPayload::TaskStarted { .. } => "TaskStarted",
        EventPayload::TaskDelta { .. } => "TaskDelta",
        EventPayload::TaskProgress { .. } => "TaskProgress",
        EventPayload::TaskCompleted { .. } => "TaskCompleted",
        EventPayload::TaskFailed { .. } => "TaskFailed",
        _ => "other",
    }
}

/// `write` dispatches through to a real in-workspace execution (Task 2,
/// closing Task 1's own deferred gap — see this file's own
/// `shell_tool_dispatches_through` doc comment for why an out-of-workspace
/// fixture path can never reach `TaskStarted` at all: containment rejects
/// it before admission), and — the point of this test post-Task-2 — keeps
/// the placeholder `IsolationAttestation { tier: Tier::None, .. }`
/// `dispatch_tool_for_workflow` reserves for in-process filesystem builtins.
#[tokio::test]
async fn write_tool_dispatches_through() {
    let dir = TempDir::new().unwrap();
    let target = dir.path().canonicalize().unwrap().join("out.txt");
    let target_str = target.to_string_lossy().to_string();
    let (actor, _workspace_root, db_path, session_id) = setup_actor(
        &dir,
        vec![CompiledRule::test_new(
            Scope::Builtin,
            PolicyOutcome::Allow,
            Predicate::FsExact {
                op: FsOp::Write,
                path: target.clone(),
            },
        )],
    )
    .await;

    let result = dispatch_tool_for_workflow(
        &actor,
        TaskKind::Write,
        json!({ "path": &target_str, "contents": "hello" }),
        json!({ "path": &target_str, "contents": "hello" }),
        AMPLE_STEP_TIMEOUT,
        None,
    )
    .await;

    let dispatch = result.expect("dispatch should succeed");
    expect_completed(
        &dispatch.result,
        "an in-workspace, allowed write must actually run",
    );

    let isolation = started_isolation(&db_path, session_id, dispatch.task_id).await;
    assert_eq!(
        isolation.tier,
        Tier::None,
        "write stays in-process — it must keep the placeholder attestation, not inherit a real \
         one, got {isolation:?}"
    );
}

/// `edit` dispatches through to a real, in-workspace execution and keeps the
/// placeholder `Tier::None` attestation — see `write_tool_dispatches_through`'s
/// doc comment for why an in-workspace fixture is required to reach
/// `TaskStarted` at all.
#[tokio::test]
async fn edit_tool_dispatches_through() {
    let dir = TempDir::new().unwrap();
    let workspace_root = dir.path().canonicalize().unwrap();
    let target = workspace_root.join("edit.txt");
    std::fs::write(&target, "a").unwrap();
    let target_str = target.to_string_lossy().to_string();
    let (actor, _workspace_root, db_path, session_id) = setup_actor(
        &dir,
        vec![CompiledRule::test_new(
            Scope::Builtin,
            PolicyOutcome::Allow,
            Predicate::FsExact {
                op: FsOp::Edit,
                path: target.clone(),
            },
        )],
    )
    .await;

    let result = dispatch_tool_for_workflow(
        &actor,
        TaskKind::Edit,
        json!({ "path": &target_str, "find": "a", "replace": "b" }),
        json!({ "path": &target_str, "find": "a", "replace": "b" }),
        AMPLE_STEP_TIMEOUT,
        None,
    )
    .await;

    let dispatch = result.expect("dispatch should succeed");
    expect_completed(
        &dispatch.result,
        "an in-workspace, allowed edit must actually run",
    );

    let isolation = started_isolation(&db_path, session_id, dispatch.task_id).await;
    assert_eq!(
        isolation.tier,
        Tier::None,
        "edit stays in-process — it must keep the placeholder attestation, not inherit a real \
         one, got {isolation:?}"
    );
}

/// `find` dispatches through to a real, in-workspace execution and keeps the
/// placeholder `Tier::None` attestation — see `write_tool_dispatches_through`'s
/// doc comment for why an in-workspace fixture is required to reach
/// `TaskStarted` at all.
#[tokio::test]
async fn find_tool_dispatches_through() {
    let dir = TempDir::new().unwrap();
    let workspace_root = dir.path().canonicalize().unwrap();
    let (actor, _workspace_root, db_path, session_id) = setup_actor(
        &dir,
        vec![CompiledRule::test_new(
            Scope::Builtin,
            PolicyOutcome::Allow,
            Predicate::FsExact {
                op: FsOp::Find,
                path: workspace_root.clone(),
            },
        )],
    )
    .await;
    let root_str = workspace_root.to_string_lossy().to_string();

    let result = dispatch_tool_for_workflow(
        &actor,
        TaskKind::Find,
        json!({ "root": &root_str, "pattern": "*.txt" }),
        json!({ "root": &root_str, "pattern": "*.txt" }),
        AMPLE_STEP_TIMEOUT,
        None,
    )
    .await;

    let dispatch = result.expect("dispatch should succeed");
    expect_completed(
        &dispatch.result,
        "an in-workspace, allowed find must actually run",
    );

    let isolation = started_isolation(&db_path, session_id, dispatch.task_id).await;
    assert_eq!(
        isolation.tier,
        Tier::None,
        "find stays in-process — it must keep the placeholder attestation, not inherit a real \
         one, got {isolation:?}"
    );
}

/// An authored `tool: shell` step reaches — and runs through —
/// `execute_builtin`'s `TaskParams::Shell` arm.
///
/// The dispatched program is a real, executable script inside this session's
/// own workspace root, named by the absolute path
/// `resolve_shell_program` will produce for it (see [`workspace_program`]),
/// and the one policy rule allows exactly that program string. The
/// assertions below are on the script's own stdout and on the recorded
/// `TaskStarted`/`TaskCompleted` pair: neither is reachable unless every
/// chokepoint between the allowlist gate and `run_isolated_shell_dispatch`'s
/// `spawn_isolated` call was actually cleared. This also asserts the
/// `TaskStarted` event's `IsolationAttestation` is real (`TestIsolate::attest`'s
/// `Tier::Sandbox`, not the `Tier::None` placeholder the fs kinds keep) —
/// Task 2's own exit criterion, distinguishing this kind from
/// `write`/`edit`/`find` (see those tests' own `Tier::None` assertions).
#[tokio::test]
async fn shell_tool_dispatches_through() {
    let dir = TempDir::new().unwrap();
    let workspace_root = dir.path().canonicalize().unwrap();
    let program = workspace_program(
        &workspace_root,
        "echo.sh",
        "#!/bin/sh\necho hello-from-workflow-shell\n",
    );

    let (actor, actor_root, db_path, session_id) = setup_actor(
        &dir,
        vec![CompiledRule::test_new(
            Scope::Builtin,
            PolicyOutcome::Allow,
            Predicate::program(&program),
        )],
    )
    .await;
    // The rule's program string is only meaningful if it was derived against
    // the same root the actor resolves shell dispatches under.
    assert_eq!(actor_root, workspace_root);

    let cwd = workspace_root.to_string_lossy().to_string();
    let dispatch = dispatch_tool_for_workflow(
        &actor,
        TaskKind::Shell,
        json!({ "program": &program, "argv": [], "cwd": &cwd }),
        json!({ "program": &program, "argv": [], "cwd": &cwd }),
        AMPLE_STEP_TIMEOUT,
        None,
    )
    .await
    .expect("dispatch should succeed");

    let output = match dispatch.result {
        DispatchOutcome::Completed(output) => output,
        other => panic!("shell dispatch never reached execute_builtin: {other:?}"),
    };
    let text = output["content"].as_str().unwrap_or_default();
    assert!(
        text.contains("hello-from-workflow-shell"),
        "execute_builtin's shell arm must have run the dispatched program: {text}"
    );
    assert!(
        text.contains("exit_code=Some(0)"),
        "the dispatched program must have run to a clean exit: {text}"
    );

    // The same run, seen from the event log: a shell step that reached
    // `execute_builtin` and returned `Ok` records TaskStarted, then its
    // streamed output (Phase 8 Task 19 lane B, Task 9 — see
    // `shell_tool_dispatch_streams_deltas_and_progress_before_its_terminal_event`
    // below for the dedicated test on this shape), then TaskCompleted — an
    // admission refusal or a pre-admission rejection records TaskFailed (or
    // a denial note) instead.
    let reopened = open(&db_path).await.unwrap();
    let kinds: Vec<&'static str> = session_events(&reopened, session_id)
        .await
        .unwrap()
        .iter()
        .filter(|e| e.task_id == Some(dispatch.task_id))
        .map(|e| event_kind(&e.payload))
        .collect();
    assert_eq!(
        kinds,
        vec![
            "TaskCreated",
            "TaskStarted",
            "TaskDelta",
            "TaskProgress",
            "TaskCompleted"
        ],
        "a shell step that executed and produced real stdout must have the full S-LOG-1 \
         lifecycle recorded, with its output streamed as a delta/progress pair before the \
         terminal event"
    );

    let isolation = started_isolation(&db_path, session_id, dispatch.task_id).await;
    assert_ne!(
        isolation.tier,
        Tier::None,
        "shell crosses the process isolation boundary — its TaskStarted must carry a real \
         attestation, not the fs kinds' Tier::None placeholder, got {isolation:?}"
    );
}

/// Phase 8 Task 19 lane B, Task 9: `dispatch_tool_for_workflow` builds a
/// real `ShellDeltaSink` for `TaskParams::Shell` and threads it into
/// `execute_builtin`, mirroring `agent_loop::dispatch_builtin`'s identical
/// wiring — a dispatched `tool: shell` step's own stdout now streams as
/// real `TaskDelta`/`TaskProgress` events between `TaskStarted` and the
/// terminal event, not just a single buffered string folded into
/// `TaskCompleted.output` at the very end. This is the workflow-path half
/// of the "on both paths" requirement; `agent_loop_dispatch.rs`'s
/// `a_dispatched_shell_tasks_deltas_and_progress_land_between_started_and_its_terminal_event`
/// is the chat-path half.
#[tokio::test]
async fn shell_tool_dispatch_streams_deltas_and_progress_before_its_terminal_event() {
    let dir = TempDir::new().unwrap();
    let workspace_root = dir.path().canonicalize().unwrap();
    let program = workspace_program(
        &workspace_root,
        "echo_streamed.sh",
        "#!/bin/sh\necho hello-from-streamed-shell\n",
    );

    let (actor, actor_root, db_path, session_id) = setup_actor(
        &dir,
        vec![CompiledRule::test_new(
            Scope::Builtin,
            PolicyOutcome::Allow,
            Predicate::program(&program),
        )],
    )
    .await;
    assert_eq!(actor_root, workspace_root);

    let cwd = workspace_root.to_string_lossy().to_string();
    let dispatch = dispatch_tool_for_workflow(
        &actor,
        TaskKind::Shell,
        json!({ "program": &program, "argv": [], "cwd": &cwd }),
        json!({ "program": &program, "argv": [], "cwd": &cwd }),
        AMPLE_STEP_TIMEOUT,
        None,
    )
    .await
    .expect("dispatch should succeed");
    expect_completed(
        &dispatch.result,
        "an allowed shell dispatch with real output must complete",
    );

    let reopened = open(&db_path).await.unwrap();
    let mut task_events: Vec<_> = session_events(&reopened, session_id)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.task_id == Some(dispatch.task_id))
        .collect();
    task_events.sort_by_key(|e| e.seq);

    for pair in task_events.windows(2) {
        assert!(
            pair[0].seq < pair[1].seq,
            "seq must be strictly increasing across one task's own events, got {:?}",
            task_events.iter().map(|e| e.seq).collect::<Vec<_>>()
        );
    }

    let kinds: Vec<&'static str> = task_events.iter().map(|e| event_kind(&e.payload)).collect();
    assert_eq!(kinds.first(), Some(&"TaskCreated"), "got {kinds:?}");
    assert_eq!(kinds.get(1), Some(&"TaskStarted"), "got {kinds:?}");
    assert_eq!(kinds.last(), Some(&"TaskCompleted"), "got {kinds:?}");
    assert!(
        kinds[2..kinds.len() - 1]
            .iter()
            .all(|k| *k == "TaskDelta" || *k == "TaskProgress"),
        "every event between TaskStarted and the terminal event must be a delta or a \
         progress note, got {kinds:?}"
    );
    assert!(
        kinds.contains(&"TaskDelta"),
        "a real shell step with real output must have produced at least one TaskDelta, got \
         {kinds:?}"
    );
    assert!(
        kinds.contains(&"TaskProgress"),
        "a real shell step must have produced at least one TaskProgress, got {kinds:?}"
    );
}

/// Phase 8 Task 19 lane B, Task 9's required ordering test, workflow half: a
/// shell step that has already produced (and streamed) real output, then
/// has its `step_timeout` elapse mid-flight, must still have every
/// delta/progress event it produced commit strictly before its own terminal
/// event. See `run_isolated_shell_dispatch`'s own comment on `completion`
/// for why this is guaranteed regardless of the race's outcome:
/// `ShellDeltaSink` holds a `Clone` of the very same `EventWriter` that
/// records the terminal event, so both enqueue onto the same writer-actor
/// FIFO.
///
/// **Fix round 1, M2:** an earlier version of this test used a fixed-size
/// burst (`yes | head -c 100000`, then `sleep 30`) before the 300ms
/// `step_timeout` elapsed. That whole ~100 KiB write (and its one
/// size-triggered flush) completes in microseconds, so by the time the
/// timeout fired the pump was already idle and blocked on `recv()` — the
/// assertion below was then only ever checking "an already-committed delta
/// precedes the terminal event," true almost by construction, and never
/// entering the window the Global Constraint is actually about (a
/// `flush_stream` future dropped by the outer `select!` after its
/// `send(...).await` returned but before the reply). The dispatched script
/// now runs `yes` alone — the parameter under test is the real 300ms
/// `step_timeout`, not test-side synchronization.
///
/// **Fix round 2, finding 1 residual:** it is the CHILD PROCESS that never
/// stops on its own here, not the delta stream — `drain_to_end` still sends
/// `ShellChunk::Gap(GapReason::Cap)` and drops the delta sender the instant
/// `MAX_SHELL_OUTPUT_BYTES` is reached (measured: a `sh -c yes` child
/// delivers that many bytes through 64 KiB reads in a few milliseconds), so
/// past that cap the pump only outlives it for as long as its own backlog
/// takes to flush (at most the shared 4 MiB in-flight budget, 64 KiB per
/// flush). The 300ms timeout above may therefore land while the pump is
/// still flushing that backlog rather than while a stream is actively
/// arriving — either way, the ordering assertion below holds.
#[tokio::test]
async fn shell_tool_step_timeout_with_prior_output_commits_all_deltas_before_the_terminal_event() {
    let dir = TempDir::new().unwrap();
    let workspace_root = dir.path().canonicalize().unwrap();
    let program = workspace_program(
        &workspace_root,
        "streamed_then_hangs.sh",
        "#!/bin/sh\nyes\n",
    );

    let (actor, actor_root, db_path, session_id) = setup_actor(
        &dir,
        vec![CompiledRule::test_new(
            Scope::Builtin,
            PolicyOutcome::Allow,
            Predicate::program(&program),
        )],
    )
    .await;
    assert_eq!(actor_root, workspace_root);

    let cwd = workspace_root.to_string_lossy().to_string();
    let dispatch = tokio::time::timeout(
        Duration::from_secs(10),
        dispatch_tool_for_workflow(
            &actor,
            TaskKind::Shell,
            json!({ "program": &program, "argv": [], "cwd": &cwd }),
            json!({ "program": &program, "argv": [], "cwd": &cwd }),
            Duration::from_millis(300),
            None,
        ),
    )
    .await
    .expect("dispatch_tool_for_workflow must honor the threaded step_timeout, not hang")
    .expect("a timed-out shell dispatch still records its own lifecycle and returns Ok(..)");

    match &dispatch.result {
        DispatchOutcome::Completed(output) => panic!(
            "a shell step whose command outlives its step_timeout must not report success, got \
             {output:?}"
        ),
        DispatchOutcome::Failed(msg) => {
            assert!(!msg.is_empty(), "a failed dispatch must carry a message")
        }
        DispatchOutcome::Cancelled(reason) => panic!(
            "a step_timeout elapsing alone (no session cancel) must be reported as an ordinary \
             failure, not Cancelled — got Cancelled({reason:?})"
        ),
    }

    let reopened = open(&db_path).await.unwrap();
    let mut task_events: Vec<_> = session_events(&reopened, session_id)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.task_id == Some(dispatch.task_id))
        .collect();
    task_events.sort_by_key(|e| e.seq);

    let terminal = task_events
        .iter()
        .find(|e| matches!(&e.payload, EventPayload::TaskFailed { .. }))
        .expect("a timed-out shell step must record a real TaskFailed terminal event");
    assert_eq!(
        Some(terminal.seq),
        dispatch.last_task_seq,
        "the terminal event found in the log must be the exact seq dispatch_tool_for_workflow \
         itself returned"
    );

    let delta_or_progress_seqs: Vec<u64> = task_events
        .iter()
        .filter(|e| {
            matches!(
                &e.payload,
                EventPayload::TaskDelta { .. } | EventPayload::TaskProgress { .. }
            )
        })
        .map(|e| e.seq)
        .collect();
    assert!(
        !delta_or_progress_seqs.is_empty(),
        "the shell step's own stdout must have produced at least one streamed delta/progress \
         event before the timeout — otherwise this ordering assertion is vacuous"
    );
    let max_delta_seq = *delta_or_progress_seqs.iter().max().unwrap();
    assert!(
        max_delta_seq < terminal.seq,
        "every delta/progress event for a timed-out shell step must commit before its own \
         terminal event — got max delta/progress seq {max_delta_seq}, terminal seq {}",
        terminal.seq
    );
}

/// Phase 8 Task 25.4 Task 3: `dispatch_tool_for_workflow`'s `step_timeout`
/// parameter — sourced by `DeliveryExecutor::execute_pending` from the
/// run's real `PendingWork.step_timeout` — actually bounds a dispatched
/// `tool: shell` step, and an elapsed timeout is a genuine process-group
/// kill, not merely this call returning early.
///
/// The dispatched script records its own pid to a file before sleeping, so
/// the assertion after the call is a real OS-level liveness check
/// (`kill -0`, the same mechanism
/// `shell_task_started_append_failure_cancels_the_pre_spawned_child` above
/// uses), never just trusting that the returned error names cancellation.
#[tokio::test]
async fn shell_tool_step_timeout_elapsing_kills_the_process_and_fails_the_step() {
    let dir = TempDir::new().unwrap();
    let workspace_root = dir.path().canonicalize().unwrap();
    let pid_file = workspace_root.join("shell.pid");
    let program = workspace_program(
        &workspace_root,
        "sleep_and_record_pid.sh",
        &format!("#!/bin/sh\necho $$ > {}\nsleep 30\n", pid_file.display()),
    );

    let (actor, actor_root, _db_path, _session_id) = setup_actor(
        &dir,
        vec![CompiledRule::test_new(
            Scope::Builtin,
            PolicyOutcome::Allow,
            Predicate::program(&program),
        )],
    )
    .await;
    assert_eq!(actor_root, workspace_root);

    let cwd = workspace_root.to_string_lossy().to_string();
    // The dispatch itself is bounded by a short, explicitly authored
    // `step_timeout` (300ms) — the same value production would source from
    // `PendingWork.step_timeout`. The outer 10s `tokio::time::timeout` here
    // is just this test's own "must not hang" guard, not the mechanism
    // under test.
    let dispatch = tokio::time::timeout(
        Duration::from_secs(10),
        dispatch_tool_for_workflow(
            &actor,
            TaskKind::Shell,
            json!({ "program": &program, "argv": [], "cwd": &cwd }),
            json!({ "program": &program, "argv": [], "cwd": &cwd }),
            Duration::from_millis(300),
            None,
        ),
    )
    .await
    .expect("dispatch_tool_for_workflow must honor the threaded step_timeout, not hang")
    .expect("a timed-out shell dispatch still records its own lifecycle and returns Ok(..)");

    match dispatch.result {
        DispatchOutcome::Completed(output) => panic!(
            "a shell step whose command outlives its step_timeout must not report success, got \
             {output:?}"
        ),
        DispatchOutcome::Failed(msg) => {
            assert!(!msg.is_empty(), "a failed dispatch must carry a message")
        }
        // Phase 8 Task 25.4 Task 4: a `step_timeout` elapsing with no
        // session cancel in play is an ordinary failure, never `Cancelled`
        // — `Cancelled` is reserved for §8.13's cooperative cancel
        // (`ToolDispatchError::ShellSessionCancelled`), which this test
        // never triggers.
        DispatchOutcome::Cancelled(reason) => panic!(
            "a step_timeout elapsing alone (no session cancel) must be reported as an ordinary \
             failure, not Cancelled — got Cancelled({reason:?})"
        ),
    }

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

    #[cfg(unix)]
    {
        let mut still_alive = true;
        for _ in 0..100 {
            still_alive = std::process::Command::new("kill")
                .arg("-0")
                .arg(pid.to_string())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|status| status.success())
                .unwrap_or(false);
            if !still_alive {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            !still_alive,
            "a shell step that exceeded its step_timeout must have its process actually \
             killed (SIGTERM/SIGKILL), not merely reported as cancelled while still running \
             (pid {pid})"
        );
    }
}

/// Unsupported tools (Http, Git, Mcp) are rejected with unsupported_workflow_tool.
#[tokio::test]
async fn unsupported_tools_rejected() {
    let dir = TempDir::new().unwrap();
    let (actor, _workspace_root, _db_path, _session_id) = setup_actor(&dir, vec![]).await;

    let result = dispatch_tool_for_workflow(
        &actor,
        TaskKind::Http,
        json!({}),
        json!({}),
        AMPLE_STEP_TIMEOUT,
        None,
    )
    .await;

    let dispatch = result.expect("dispatch should not error");
    match dispatch.result {
        DispatchOutcome::Failed(msg) => {
            assert!(
                msg.contains("not wired yet"),
                "Http should be rejected as unsupported: {msg}"
            );
        }
        other => panic!("Http should be unsupported, got {other:?}"),
    }
}

/// An isolate whose `spawn` records the pre-spawned child's real pid, then
/// immediately closes `store`'s connection pool — a deterministic way to
/// force `dispatch_tool_for_workflow`'s very next store write (the
/// `TaskStarted` append that follows pre-spawn) to fail, with no
/// sleep/timing race involved.
///
/// `StorePool.pool` is public specifically so integration tests can reach
/// into pool internals directly (see that field's own doc comment in
/// `roundhouse-store`'s `pool.rs`), and `deadpool_sqlite::Pool::close`'s own
/// doc guarantees `PoolError::Closed` for every future `.get()` call
/// immediately, not eventually — so closing it synchronously inside `spawn`,
/// before returning the already-real child, is a genuine injection point,
/// not a fabricated one.
struct PoolClosingIsolate {
    store: StorePool,
    spawned_pid: std::sync::Mutex<Option<u32>>,
}

#[async_trait::async_trait]
impl Isolate for PoolClosingIsolate {
    fn declared(&self) -> SandboxTier {
        SandboxTier::Sandbox
    }
    async fn probe(&self) -> ProbeResult {
        ProbeResult {
            achieved: SandboxTier::Sandbox,
            degradations: vec![],
        }
    }
    async fn prepare(
        &self,
        _spec: &roundhouse_core::SessionSpec,
    ) -> Result<Handle, IsolationError> {
        Ok(Handle {
            id: "pool-closing-isolate".into(),
        })
    }
    async fn spawn(&self, _handle: &Handle, command: CommandSpec) -> Result<Child, IsolationError> {
        let mut process = tokio::process::Command::new(&command.program);
        process
            .args(&command.argv)
            .current_dir(command.cwd.as_deref().unwrap_or("."))
            .env_clear()
            .envs(command.env)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        #[cfg(unix)]
        process.process_group(0);
        let child = process
            .spawn()
            .map_err(|err| IsolationError::Unsupported(err.to_string()))?;
        let pid = child
            .id()
            .ok_or_else(|| IsolationError::Unsupported("test child has no pid".into()))?;
        *self.spawned_pid.lock().unwrap() = Some(pid);
        // The injection point: close the pool BEFORE returning the spawned
        // child, so the very next store write (`TaskStarted`'s append, back
        // in `dispatch_tool_for_workflow`) deterministically fails.
        self.store.pool.close();
        Ok(Child::from_process(pid, child))
    }
    fn attest(&self, _handle: &Handle) -> Attestation {
        Attestation {
            tier: SandboxTier::Sandbox,
            digest: "test".into(),
            net_enforced: false,
        }
    }
    async fn teardown(&self, _handle: Handle) -> Result<(), IsolationError> {
        Ok(())
    }
}

/// A `TaskStarted`-append failure after a shell child has been pre-spawned
/// must cancel that child, not orphan it — `dispatch_tool_for_workflow`'s
/// cleanup branch, mirroring `agent_loop::dispatch_builtin`'s identical one
/// (this task's brief, item 3).
///
/// The dispatched program is a long-lived real process (`sleep 30`): if
/// cleanup never ran, it would still be alive well after this test's own
/// call returns, which the final `kill -0` check below would catch.
#[tokio::test]
async fn shell_task_started_append_failure_cancels_the_pre_spawned_child() {
    let dir = TempDir::new().unwrap();
    let workspace_root = dir.path().canonicalize().unwrap();
    let program = workspace_program(&workspace_root, "sleep_long.sh", "#!/bin/sh\nsleep 30\n");

    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store.clone()).await;

    let isolate = Arc::new(PoolClosingIsolate {
        store: store.clone(),
        spawned_pid: std::sync::Mutex::new(None),
    });
    let session_spec =
        roundhouse_core::SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
    let handle = isolate.prepare(&session_spec).await.unwrap();
    let session_id = SessionId::new();

    let rules = vec![CompiledRule::test_new(
        Scope::Builtin,
        PolicyOutcome::Allow,
        Predicate::program(&program),
    )];
    let actor = Arc::new(SessionActor::new_with_workspace_root(
        session_id,
        writer,
        SessionState::Running,
        &RUNNER,
        Arc::new(PolicyEngine::from_rules(rules)),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        workspace_root.clone(),
        isolate.clone() as Arc<dyn Isolate>,
        handle,
        session_spec,
        vec![],
    ));

    let cwd = workspace_root.to_string_lossy().to_string();
    let result = dispatch_tool_for_workflow(
        &actor,
        TaskKind::Shell,
        json!({ "program": &program, "argv": [], "cwd": &cwd }),
        json!({ "program": &program, "argv": [], "cwd": &cwd }),
        AMPLE_STEP_TIMEOUT,
        None,
    )
    .await;

    // The pool closing mid-dispatch means every store write after the
    // pre-spawn fails, including the TaskFailed `dispatch_tool_for_workflow`
    // tries to record on its way out — so the whole call surfaces as `Err`
    // rather than the ordinary `Ok(WorkflowToolDispatch { result: Err(..) })`
    // shape. That's expected: this test's point is the child, not the event
    // log (which the closed pool makes unobservable for this run anyway).
    assert!(
        result.is_err(),
        "a TaskStarted append against a closed pool must surface as an error, not silently \
         succeed"
    );

    let pid =
        isolate.spawned_pid.lock().unwrap().expect(
            "PoolClosingIsolate::spawn must have recorded the pre-spawned child's real pid",
        );

    // By the time `dispatch_tool_for_workflow` returned, it must already
    // have awaited `child.cancel()` in its TaskStarted-append-failure
    // branch — no extra wait is needed here for that to have taken effect.
    #[cfg(unix)]
    {
        let still_alive = std::process::Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        assert!(
            !still_alive,
            "a pre-spawned shell child must be cancelled (SIGTERM/SIGKILL), not orphaned, when \
             the TaskStarted append that follows it fails (pid {pid})"
        );
    }
}
