use roundhouse_core::TaskId;
use roundhouse_core::TaskKind;
use roundhouse_flow::exec::{Executor, RunContext, StepStatus, TaskSink};
use roundhouse_flow::parse::parse_workflow;
use std::collections::HashMap;

#[derive(Debug, Clone)]
struct RecordedEvent {
    #[allow(dead_code)]
    parent: Option<TaskId>,
    kind: TaskKind,
    payload_json: serde_json::Value,
}

struct RecordingSink(Vec<RecordedEvent>);
impl TaskSink for RecordingSink {
    fn emit(
        &mut self,
        _task_id: TaskId,
        parent: Option<TaskId>,
        kind: roundhouse_core::TaskKind,
        payload: roundhouse_core::EventPayload,
    ) {
        // `EventPayload` derives `Serialize` (Phase 0) but deliberately not
        // `Deserialize` for the type as a whole (S-LOG-1 — see
        // `roundhouse-core`'s `event.rs`); round-tripping through JSON here
        // is only for this test's own assertions, never a construction path.
        let payload_json = serde_json::to_value(&payload).unwrap_or(serde_json::Value::Null);
        self.0.push(RecordedEvent {
            parent,
            kind,
            payload_json,
        });
    }
}

fn run_ctx(inputs: serde_json::Value) -> RunContext {
    RunContext {
        inputs,
        vars: serde_json::json!({}),
        secrets: HashMap::new(),
        run_id: roundhouse_flow::exec::RunId::new(),
    }
}

const SIMPLE_YAML: &str = r#"
name: three-steps
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    tool: shell
    with: { cmd: ["echo", "a"] }
  - id: b
    needs: [a]
    tool: shell
    with: { cmd: ["echo", "b"] }
  - id: c
    tool: shell
    with: { cmd: ["echo", "c"] }
"#;

#[test]
fn steps_execute_in_dependency_order_each_as_its_own_task_subtree() {
    let def = parse_workflow(SIMPLE_YAML).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let run_id = roundhouse_flow::exec::RunId::new();
    let mut exec = Executor::new(&def, run_id, &mut sink, run_ctx(serde_json::json!({})));
    let outcomes = exec.run_to_completion();

    let order: Vec<&str> = outcomes.iter().map(|o| o.step_id.as_str()).collect();
    let pos_a = order.iter().position(|&s| s == "a").unwrap();
    let pos_b = order.iter().position(|&s| s == "b").unwrap();
    assert!(pos_a < pos_b, "b needs a, so a must run first");
    assert!(outcomes
        .iter()
        .all(|o| matches!(o.status, StepStatus::Completed)));
}

#[test]
fn inputs_are_interpolated_for_real_into_a_tools_with_block() {
    // Finding 8's headline assertion: `${{ inputs.repo }}` must resolve to a
    // real value, never `Null`, in the exact field the reference §8.9
    // workflow uses it in (`with.url`).
    let yaml = r#"
name: fetch-prs
version: 1
inputs: { repo: { type: string, required: true } }
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: list_prs
    tool: http
    with: { method: GET, url: "https://api.github.com/repos/${{ inputs.repo }}/pulls?state=open" }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let mut exec = Executor::new(
        &def,
        roundhouse_flow::exec::RunId::new(),
        &mut sink,
        run_ctx(serde_json::json!({"repo": "acme/widgets"})),
    );
    exec.run_to_completion();

    let created = sink
        .0
        .iter()
        .find(|e| matches!(e.kind, TaskKind::Http))
        .expect("http task was emitted");
    let url = created.payload_json["TaskCreated"]["input"]["Json"]["url"]
        .as_str()
        .unwrap();
    assert_eq!(
        url,
        "https://api.github.com/repos/acme/widgets/pulls?state=open"
    );
}

#[test]
fn report_and_emit_steps_are_persisted_through_the_sink_not_just_returned_in_memory() {
    // Finding 2: `dispatch_step`'s Report/Emit arms
    // (`crates/roundhouse-flow/src/exec/mod.rs`) used to build a
    // `StepOutcome` and return it without ever calling `self.sink.emit(..)`
    // — the Runs inbox/audit/fingerprinting have nothing to read as a
    // result. This test drives the real `dispatch_step` call path and
    // asserts a `TaskKind::Report` task (`TaskCreated` + `TaskCompleted`) is
    // actually emitted, carrying the report JSON.
    let yaml = r#"
name: nightly-lint
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: notify
    emit: { notify: [desktop], severity: high }
  - id: final_report
    report: { outcome: "nothing", severity: "low", headline: "clean run", needs_human: false, cost: { usd: 0.0, tokens: 0 } }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let mut exec = Executor::new(
        &def,
        roundhouse_flow::exec::RunId::new(),
        &mut sink,
        run_ctx(serde_json::json!({})),
    );
    exec.run_to_completion();

    let report_events: Vec<_> = sink
        .0
        .iter()
        .filter(|e| matches!(e.kind, TaskKind::Report))
        .collect();
    assert_eq!(
        report_events.len(),
        2,
        "one TaskCreated + one TaskCompleted for the report step"
    );
    let completed = report_events
        .iter()
        .find(|e| e.payload_json.get("TaskCompleted").is_some())
        .expect("TaskCompleted was emitted");
    assert_eq!(
        completed.payload_json["TaskCompleted"]["output"]["Json"]["headline"],
        serde_json::json!("clean run")
    );

    let flow_events: Vec<_> = sink
        .0
        .iter()
        .filter(|e| matches!(e.kind, TaskKind::Flow))
        .collect();
    assert!(
        !flow_events.is_empty(),
        "the emit: step is persisted too, as a Flow-kind task"
    );
}

#[test]
fn a_when_clause_that_fails_to_evaluate_fails_the_step_rather_than_running_it() {
    // Deliberate deviation from the plan's illustrative `unwrap_or(true)`
    // (see the report's "Deviations from the plan text"): a `when:` whose
    // evaluation errors (here, an unknown function) must not be treated as
    // "runs unconditionally" — that is the wrong fail-open default for a
    // codebase whose stated posture elsewhere is fail-closed.
    let yaml = r#"
name: bad-when
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    when: "${{ not_a_real_function(1) }}"
    tool: shell
    with: { cmd: ["echo", "a"] }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let mut exec = Executor::new(
        &def,
        roundhouse_flow::exec::RunId::new(),
        &mut sink,
        run_ctx(serde_json::json!({})),
    );
    let outcomes = exec.run_to_completion();

    assert_eq!(outcomes.len(), 1);
    assert!(
        matches!(&outcomes[0].status, StepStatus::Failed { .. }),
        "expected Failed, got {:?}",
        outcomes[0].status
    );
    assert!(
        sink.0.is_empty(),
        "a step whose `when:` never evaluated must not have dispatched a task"
    );
}

#[test]
fn secrets_are_bound_into_the_expression_context_and_redacted_when_logged() {
    let yaml = r#"
name: uses-secret
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    tool: shell
    with: { cmd: ["echo", "${{ secrets.GH_TOKEN }}"] }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let mut secrets = HashMap::new();
    secrets.insert("GH_TOKEN".to_string(), "sk-super-secret".to_string());
    let ctx = RunContext {
        inputs: serde_json::json!({}),
        vars: serde_json::json!({}),
        secrets,
        run_id: roundhouse_flow::exec::RunId::new(),
    };
    let mut exec = Executor::new(&def, roundhouse_flow::exec::RunId::new(), &mut sink, ctx);
    let outcomes = exec.run_to_completion();

    assert!(matches!(outcomes[0].status, StepStatus::Completed));
    let created = sink
        .0
        .iter()
        .find(|e| matches!(e.kind, TaskKind::Shell))
        .expect("shell task was emitted");
    let logged = created.payload_json["TaskCreated"]["input"]["Json"]["cmd"]
        .as_array()
        .unwrap();
    let logged_str = serde_json::to_string(logged).unwrap();
    assert!(
        !logged_str.contains("sk-super-secret"),
        "the resolved secret value must never appear verbatim in the persisted log: {logged_str}"
    );
    assert!(logged_str.contains("***"));
}
