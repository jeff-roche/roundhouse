//! Tests for Phase 8 Task 25.4: lifting the `Read`-only gate to an allowlist
//! and refusing unknown tool names.
//!
//! These tests verify that `dispatch_tool_for_workflow` accepts the five
//! allowlisted kinds (Read, Write, Edit, Find, Shell) and rejects everything else.

use roundhouse_core::{OnDegrade, SessionId, SessionState, TaskKind, TaskRunner, Tier};
use roundhouse_engine::workflow_dispatch::dispatch_tool_for_workflow;
use roundhouse_engine::SessionActor;
use roundhouse_policy::engine::PolicyEngine;
use roundhouse_sandbox::{
    Attestation, Child, CommandSpec, Handle, Isolate, IsolationError, ProbeResult,
    Tier as SandboxTier,
};
use roundhouse_store::{open, spawn_writer};
use serde_json::json;
use std::sync::Arc;
use tempfile::TempDir;

/// Single-instance pattern — `TaskRunner::bootstrap()` panics on a second call per process.
static RUNNER: once_cell::sync::Lazy<TaskRunner> =
    once_cell::sync::Lazy::new(TaskRunner::bootstrap);

/// Minimal test isolate that just satisfies the trait.
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
    async fn spawn(
        &self,
        _handle: &Handle,
        _command: CommandSpec,
    ) -> Result<Child, IsolationError> {
        Err(IsolationError::Unsupported(
            "test isolate never spawns".into(),
        ))
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

/// Sets up a minimal SessionActor for testing dispatch_tool_for_workflow.
async fn setup_actor(dir: &TempDir) -> Arc<SessionActor> {
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let isolate: Arc<dyn Isolate> = Arc::new(TestIsolate);
    let session_spec =
        roundhouse_core::SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
    let handle = isolate.prepare(&session_spec).await.unwrap();
    let session_id = SessionId::new();

    // Empty rules list - this makes PolicyEngine deny everything by default,
    // but our tests don't care about admission (we're testing the dispatch gate).
    // The dispatch gate tests only verify that Write/Edit/Find/Shell pass the
    // unsupported_workflow_tool check; admission happens after that, so tests
    // will fail on other grounds (missing args, etc.) but not on the gate.
    let rules = vec![];

    Arc::new(SessionActor::new_with_workspace_root(
        session_id,
        writer,
        SessionState::Running,
        &RUNNER,
        Arc::new(PolicyEngine::from_rules(rules)),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        dir.path().canonicalize().unwrap(),
        isolate,
        handle,
        session_spec,
        vec![],
    ))
}

/// `write` dispatches without hitting unsupported_workflow_tool gate.
#[tokio::test]
async fn write_tool_dispatches_through() {
    let dir = TempDir::new().unwrap();
    let actor = setup_actor(&dir).await;

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
    let actor = setup_actor(&dir).await;

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
    let actor = setup_actor(&dir).await;

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

/// `shell` dispatches through to execute_builtin without hitting unsupported gate.
#[tokio::test]
async fn shell_tool_dispatches_through() {
    let dir = TempDir::new().unwrap();
    let actor = setup_actor(&dir).await;

    let result = dispatch_tool_for_workflow(
        &actor,
        TaskKind::Shell,
        json!({ "program": "echo", "argv": ["hello"], "cwd": "/tmp" }),
        json!({ "program": "echo", "argv": ["hello"], "cwd": "/tmp" }),
    )
    .await;

    let dispatch = result.expect("dispatch should succeed");
    match dispatch.result {
        Ok(_) => {} // Success or execution output
        Err(msg) => {
            // Should not be "not wired yet" — shell is wired now
            assert!(
                !msg.contains("not wired yet"),
                "shell should be supported, not unsupported_workflow_tool: {msg}"
            );
        }
    }
}

/// Unsupported tools (Http, Git, Mcp) are rejected with unsupported_workflow_tool.
#[tokio::test]
async fn unsupported_tools_rejected() {
    let dir = TempDir::new().unwrap();
    let actor = setup_actor(&dir).await;

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
