//! Tests for Phase 8 Task 25.4: unknown tool name refusal.
//!
//! Tests that an authored `tool: totally-made-up` step gets a distinct
//! "unknown tool" refusal, distinguishable from `bad_tool_arguments` and other
//! categories.

use roundhouse_core::{EventPayload, TaskId, TaskKind};
use roundhouse_flow::exec::{Executor, RunContext, RunId, TaskSink};
use roundhouse_flow::parse::WorkflowDef;
use serde_json::json;

struct MockSink {
    events: Vec<(TaskId, TaskKind, String)>,
}

impl TaskSink for MockSink {
    fn emit(
        &mut self,
        task_id: TaskId,
        _parent: Option<TaskId>,
        kind: TaskKind,
        payload: EventPayload,
    ) {
        let desc = match payload {
            EventPayload::TaskCreated { kind, .. } => format!("TaskCreated({:?})", kind),
            _ => "other".to_string(),
        };
        self.events.push((task_id, kind, desc));
    }
}

/// Verify that an unknown tool name produces a failed outcome with the right message.
#[test]
fn unknown_tool_name_produces_failed_outcome_with_unknown_tool_message() {
    // Create a minimal workflow YAML with an unknown tool
    let yaml = r#"
name: test-workflow
version: 1
permissions:
  default: deny
  unattended:
    escalate: fail
steps:
  - id: unknown_step
    tool: totally-made-up
    with: {}
"#;

    let def: WorkflowDef = serde_yaml::from_str(yaml).expect("workflow should parse");
    let mut sink = MockSink { events: Vec::new() };
    let run_context = RunContext {
        inputs: json!({}),
        vars: json!({}),
        secrets: std::collections::HashMap::new(),
        run_id: RunId::new(),
        previous_report: None,
        env_allowlist: Default::default(),
        worktree_provider: None,
    };

    let mut executor = Executor::new(&def, &mut sink, run_context).expect("executor should build");
    let outcomes = executor
        .run_to_completion()
        .expect("run_to_completion should not fail at the executor level");

    // Should have one outcome for the unknown_step
    assert_eq!(outcomes.len(), 1, "should have one step outcome");

    let outcome = &outcomes[0];
    assert_eq!(outcome.step_id, "unknown_step");

    // The outcome should be Failed
    match &outcome.status {
        roundhouse_flow::exec::StepStatus::Failed { message } => {
            // Message must indicate it's an unknown tool, not a missing argument
            assert!(
                message.contains("unknown") && message.contains("totally-made-up"),
                "error message should mention unknown tool: {message}"
            );
            // Should NOT be a message about missing "program" field (which would
            // indicate it was routed to Shell and failed there)
            assert!(
                !message.contains("program"),
                "error message should not complain about missing program field: {message}"
            );
        }
        _ => {
            panic!(
                "unknown tool step should fail, got status: {:?}",
                outcome.status
            );
        }
    }
}

/// Verify that a known tool like `read` produces a Pending decision, not a Failed one.
/// This test verifies that known tools are not rejected as unknown, by checking
/// that they reach the tool dispatch path (Pending) rather than failing with
/// "unknown tool" message. The stub in run_to_completion then converts Pending
/// to Completed, so this test asserts the tool was recognized by checking that
/// the outcome is Completed (not Failed with unknown tool message).
#[test]
fn known_tool_reaches_pending_not_failed_as_unknown() {
    let yaml = r#"
name: test-workflow
version: 1
permissions:
  default: deny
  unattended:
    escalate: fail
steps:
  - id: read_step
    tool: read
    with: { path: "/tmp/test.txt" }
"#;

    let def: WorkflowDef = serde_yaml::from_str(yaml).expect("workflow should parse");
    let mut sink = MockSink { events: Vec::new() };
    let run_context = RunContext {
        inputs: json!({}),
        vars: json!({}),
        secrets: std::collections::HashMap::new(),
        run_id: RunId::new(),
        previous_report: None,
        env_allowlist: Default::default(),
        worktree_provider: None,
    };

    let mut executor = Executor::new(&def, &mut sink, run_context).expect("executor should build");
    let outcomes = executor
        .run_to_completion()
        .expect("run_to_completion should not fail");

    assert_eq!(outcomes.len(), 1);
    let outcome = &outcomes[0];

    // Known tools should complete (via the Pending->Completed stub path),
    // not fail with "unknown tool"
    match &outcome.status {
        roundhouse_flow::exec::StepStatus::Completed => {
            // Expected: known tool reached Pending, got stubbed to Completed
        }
        roundhouse_flow::exec::StepStatus::Failed { message } => {
            assert!(
                !message.contains("unknown tool"),
                "known tool should not fail with 'unknown tool': {message}"
            );
        }
        roundhouse_flow::exec::StepStatus::Skipped { .. } => {
            panic!("known tool should not be skipped");
        }
    }
}
