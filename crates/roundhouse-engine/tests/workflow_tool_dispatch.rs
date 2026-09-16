//! Tests for Phase 8 Task 25.4: lifting the `Read`-only gate to an allowlist
//! and refusing unknown tool names.
//!
//! These tests verify that `dispatch_tool_for_workflow` accepts the five
//! allowlisted kinds (Read, Write, Edit, Find, Shell) and rejects everything else.

use roundhouse_core::{
    EventPayload, OnDegrade, SessionId, SessionState, TaskKind, TaskRunner, Tier,
};
use roundhouse_engine::workflow_dispatch::dispatch_tool_for_workflow;
use roundhouse_engine::SessionActor;
use roundhouse_policy::engine::{
    CompiledRule, Outcome as PolicyOutcome, PolicyEngine, Predicate, Scope,
};
use roundhouse_sandbox::{
    Attestation, Child, CommandSpec, Handle, Isolate, IsolationError, ProbeResult,
    Tier as SandboxTier,
};
use roundhouse_store::{open, session_events, spawn_writer};
use serde_json::json;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;

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

/// `write` dispatches without hitting unsupported_workflow_tool gate.
#[tokio::test]
async fn write_tool_dispatches_through() {
    let dir = TempDir::new().unwrap();
    let (actor, _workspace_root, _db_path, _session_id) = setup_actor(&dir, vec![]).await;

    let result = dispatch_tool_for_workflow(
        &actor,
        TaskKind::Write,
        json!({ "path": "/tmp/test.txt", "content": "hello" }),
        json!({ "path": "/tmp/test.txt", "content": "hello" }),
    )
    .await;

    let dispatch = result.expect("dispatch should succeed");
    // Should not contain "not wired yet" which is the unsupported tool message
    match dispatch.result {
        Ok(_) => {} // Success
        Err(msg) => {
            assert!(
                !msg.contains("not wired yet"),
                "write should be supported, not unsupported_workflow_tool: {msg}"
            );
        }
    }
}

/// `edit` dispatches without hitting unsupported_workflow_tool gate.
#[tokio::test]
async fn edit_tool_dispatches_through() {
    let dir = TempDir::new().unwrap();
    let (actor, _workspace_root, _db_path, _session_id) = setup_actor(&dir, vec![]).await;

    let result = dispatch_tool_for_workflow(
        &actor,
        TaskKind::Edit,
        json!({ "path": "/tmp/test.txt", "action": "replace_all", "old": "a", "new": "b" }),
        json!({ "path": "/tmp/test.txt", "action": "replace_all", "old": "a", "new": "b" }),
    )
    .await;

    let dispatch = result.expect("dispatch should succeed");
    match dispatch.result {
        Ok(_) => {}
        Err(msg) => {
            assert!(
                !msg.contains("not wired yet"),
                "edit should be supported, not unsupported_workflow_tool: {msg}"
            );
        }
    }
}

/// `find` dispatches without hitting unsupported_workflow_tool gate.
#[tokio::test]
async fn find_tool_dispatches_through() {
    let dir = TempDir::new().unwrap();
    let (actor, _workspace_root, _db_path, _session_id) = setup_actor(&dir, vec![]).await;

    let result = dispatch_tool_for_workflow(
        &actor,
        TaskKind::Find,
        json!({ "root": "/tmp", "regex": ".*\\.txt" }),
        json!({ "root": "/tmp", "regex": ".*\\.txt" }),
    )
    .await;

    let dispatch = result.expect("dispatch should succeed");
    match dispatch.result {
        Ok(_) => {}
        Err(msg) => {
            assert!(
                !msg.contains("not wired yet"),
                "find should be supported, not unsupported_workflow_tool: {msg}"
            );
        }
    }
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
/// `spawn_isolated` call was actually cleared.
///
/// What this does *not* cover: the placeholder
/// `IsolationAttestation { tier: Tier::None, .. }` `dispatch_tool_for_workflow`
/// still records for a shell step, and execution under a real sandbox —
/// both are Task 2's, per this phase's task brief.
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
    )
    .await
    .expect("dispatch should succeed");

    let output = dispatch
        .result
        .unwrap_or_else(|msg| panic!("shell dispatch never reached execute_builtin: {msg}"));
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
    // `execute_builtin` and returned `Ok` records TaskStarted then
    // TaskCompleted — an admission refusal or a pre-admission rejection
    // records TaskFailed (or a denial note) instead.
    let reopened = open(&db_path).await.unwrap();
    let kinds: Vec<&'static str> = session_events(&reopened, session_id)
        .await
        .unwrap()
        .iter()
        .filter(|e| e.task_id == Some(dispatch.task_id))
        .map(|e| match e.payload {
            EventPayload::TaskCreated { .. } => "TaskCreated",
            EventPayload::TaskStarted { .. } => "TaskStarted",
            EventPayload::TaskCompleted { .. } => "TaskCompleted",
            EventPayload::TaskFailed { .. } => "TaskFailed",
            _ => "other",
        })
        .collect();
    assert_eq!(
        kinds,
        vec!["TaskCreated", "TaskStarted", "TaskCompleted"],
        "a shell step that executed must have the full S-LOG-1 lifecycle recorded"
    );
}

/// Unsupported tools (Http, Git, Mcp) are rejected with unsupported_workflow_tool.
#[tokio::test]
async fn unsupported_tools_rejected() {
    let dir = TempDir::new().unwrap();
    let (actor, _workspace_root, _db_path, _session_id) = setup_actor(&dir, vec![]).await;

    let result = dispatch_tool_for_workflow(&actor, TaskKind::Http, json!({}), json!({})).await;

    let dispatch = result.expect("dispatch should not error");
    match dispatch.result {
        Ok(_) => panic!("Http should be unsupported"),
        Err(msg) => {
            assert!(
                msg.contains("not wired yet"),
                "Http should be rejected as unsupported: {msg}"
            );
        }
    }
}
