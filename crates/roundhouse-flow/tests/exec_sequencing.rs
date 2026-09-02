use roundhouse_core::TaskId;
use roundhouse_core::TaskKind;
use roundhouse_flow::exec::{Executor, RunContext, StepStatus, TaskSink};
use roundhouse_flow::parse::{parse_workflow, ParseError};
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
    let mut exec = Executor::new(&def, &mut sink, run_ctx(serde_json::json!({})));
    let outcomes = exec.run_to_completion().unwrap();

    let order: Vec<&str> = outcomes.iter().map(|o| o.step_id.as_str()).collect();
    let pos_a = order.iter().position(|&s| s == "a").unwrap();
    let pos_b = order.iter().position(|&s| s == "b").unwrap();
    assert!(pos_a < pos_b, "b needs a, so a must run first");
    assert!(outcomes
        .iter()
        .all(|o| matches!(o.status, StepStatus::Completed)));
    assert_eq!(
        sink.0
            .iter()
            .filter(|e| matches!(e.kind, TaskKind::Shell))
            .count(),
        3,
        "each of the three steps is its own dispatched task"
    );
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
        &mut sink,
        run_ctx(serde_json::json!({"repo": "acme/widgets"})),
    );
    exec.run_to_completion().unwrap();

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
    let mut exec = Executor::new(&def, &mut sink, run_ctx(serde_json::json!({})));
    exec.run_to_completion().unwrap();

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

// ---- Fix round 1, item 4: `when:` must accept the documented `${{ }}`
// delimited form (docs/architecture/05-scheduling-and-workflows.md §8.9's
// own reference workflow uses `when: "${{ ... }}"` in both of its
// occurrences, never a bare form), and the earlier regression test claiming
// to pin fail-closed `when:` behaviour was green for the wrong reason: it
// used `when: "${{ not_a_real_function(1) }}"`, which died at position 0 on
// the leading `$` — the `${{ }}` delimiters were never stripped before this
// fix, so `eval` (which requires a bare, undelimited expression) saw the
// literal `$` and errored immediately, never reaching the unknown-function
// path the test's name claims to exercise. STANDING.md's "endorsing a test
// means stating its payload" rule (ruling P26) exists because of exactly
// this test. ----

#[test]
fn a_when_clause_in_the_documented_delimited_form_that_fails_to_evaluate_fails_the_step_rather_than_running_it(
) {
    // Payload: `when: "${{ not_a_real_function(1) }}"`. With the delimiter
    // fix in place, this now genuinely reaches `call_function`'s
    // unknown-function path — asserted below by checking the failure
    // message actually names the unknown function, not merely that *some*
    // failure occurred.
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
    let mut exec = Executor::new(&def, &mut sink, run_ctx(serde_json::json!({})));
    let outcomes = exec.run_to_completion().unwrap();

    assert_eq!(outcomes.len(), 1);
    match &outcomes[0].status {
        StepStatus::Failed { message } => {
            assert!(
                message.contains("unknown function"),
                "expected the failure to genuinely reach the unknown-function path, got: {message}"
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert!(
        sink.0.is_empty(),
        "a step whose `when:` never evaluated must not have dispatched a task"
    );
}

#[test]
fn a_when_clause_wrapped_in_the_documented_delimiters_gates_correctly() {
    // Payload: `when: "${{ 1 == 1 }}"` (dispatches) and
    // `when: "${{ 1 == 2 }}"` (skips) — both the exact documented §8.9
    // form. Before this fix, both died with `unexpected token at position
    // 0: '${{ ... }}'` (measured on HEAD), because `when`'s raw,
    // still-delimited text was passed straight to `eval`, which requires a
    // bare expression.
    let yaml = r#"
name: when-gate
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: runs
    when: "${{ 1 == 1 }}"
    tool: shell
    with: { cmd: ["echo", "runs"] }
  - id: skips
    when: "${{ 1 == 2 }}"
    tool: shell
    with: { cmd: ["echo", "skips"] }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let mut exec = Executor::new(&def, &mut sink, run_ctx(serde_json::json!({})));
    let outcomes = exec.run_to_completion().unwrap();

    let runs = outcomes.iter().find(|o| o.step_id == "runs").unwrap();
    assert!(
        matches!(runs.status, StepStatus::Completed),
        "expected Completed, got {:?}",
        runs.status
    );
    let skips = outcomes.iter().find(|o| o.step_id == "skips").unwrap();
    assert!(
        matches!(&skips.status, StepStatus::Skipped { .. }),
        "expected Skipped, got {:?}",
        skips.status
    );
    assert_eq!(
        sink.0
            .iter()
            .filter(|e| matches!(e.kind, TaskKind::Shell))
            .count(),
        1,
        "only the `runs` step's task may reach the sink"
    );
}

#[test]
fn a_bare_when_without_the_required_delimiters_fails_rather_than_silently_evaluating() {
    // §8.9's reference workflow never writes a bare (undelimited) `when:`
    // — both of its occurrences use `${{ }}` — so per ruling P28, only the
    // delimited form is implemented. A bare `when: "1 == 1"` must fail with
    // a message naming the real problem (missing delimiters), not
    // "unexpected character" and not silently evaluate.
    let yaml = r#"
name: bare-when
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    when: "1 == 1"
    tool: shell
    with: { cmd: ["echo", "a"] }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let mut exec = Executor::new(&def, &mut sink, run_ctx(serde_json::json!({})));
    let outcomes = exec.run_to_completion().unwrap();

    match &outcomes[0].status {
        StepStatus::Failed { message } => {
            assert!(
                message.contains("delimit"),
                "expected the error to name the real problem (missing delimiters), got: {message}"
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert!(sink.0.is_empty());
}

// ---- Fix round 1, item 3: `steps.<id>.status` used to have three
// incompatible encodings depending on which path a step failed through, so
// a dependent's own `when: "${{ steps.a.status != 'failed' }}"` could match
// on one failure shape and silently fail to match another. These tests
// drive a real *dependent* step that reads `${{ steps.a.status }}` (via its
// own `emit:` block, resolved through the same `ExprContext`/`interpolate`
// path any real workflow would use), not the in-memory `StepOutcome` enum,
// for each of the three outcome shapes a step can produce. ----

fn status_seen_by_dependent(yaml: &str) -> String {
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let mut exec = Executor::new(&def, &mut sink, run_ctx(serde_json::json!({})));
    exec.run_to_completion().unwrap();

    let flow_event = sink
        .0
        .iter()
        .find(|e| matches!(e.kind, TaskKind::Flow) && e.payload_json.get("TaskCompleted").is_some())
        .expect("dependent's emit: step was persisted");
    flow_event.payload_json["TaskCompleted"]["output"]["Json"]["seen_status"]
        .as_str()
        .expect("seen_status is a string")
        .to_string()
}

#[test]
fn a_dependent_reads_completed_as_the_stable_lowercase_discriminant() {
    let yaml = r#"
name: dep-completed
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
    emit: { seen_status: "${{ steps.a.status }}" }
"#;
    assert_eq!(status_seen_by_dependent(yaml), "completed");
}

#[test]
fn a_dependent_reads_skipped_as_the_stable_lowercase_discriminant() {
    let yaml = r#"
name: dep-skipped
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    when: "${{ 1 == 2 }}"
    tool: shell
    with: { cmd: ["echo", "a"] }
  - id: b
    needs: [a]
    emit: { seen_status: "${{ steps.a.status }}" }
"#;
    assert_eq!(status_seen_by_dependent(yaml), "skipped");
}

#[test]
fn a_dependent_reads_failed_as_the_stable_lowercase_discriminant_after_a_when_eval_error() {
    // This is exactly the S-Imp-3/C-Imp-1 exploit shape: before this fix,
    // this path hard-coded `"status": "failed"` with no message, so it
    // happened to already read "failed" here — but the *sibling* dispatch-
    // failure path (next test) wrote a completely different, Debug-derived
    // shape. Both must now agree.
    let yaml = r#"
name: dep-failed-when
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    when: "${{ nope_fn(1) }}"
    tool: shell
    with: { cmd: ["echo", "a"] }
  - id: b
    needs: [a]
    emit: { seen_status: "${{ steps.a.status }}" }
"#;
    assert_eq!(status_seen_by_dependent(yaml), "failed");
}

#[test]
fn a_dependent_reads_failed_as_the_stable_lowercase_discriminant_after_a_dispatch_error() {
    // This is the exact exploit the fix-1 brief measured: `a`'s `with:`
    // fails to interpolate (a `with:`-level failure, not a `when:`-level
    // one), which used to write `format!("{:?}", outcome.status)` —
    // `Failed { message: "interpolating `with:`: ..." }` — into
    // `steps.a.status`, so `when: "${{ steps.a.status != 'failed' }}"`
    // silently failed to match and a dependent ran anyway. Confirms the
    // fix: this path now writes the same `"failed"` string the when-eval
    // path does.
    let yaml = r#"
name: dep-failed-dispatch
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    tool: shell
    with: { cmd: ["echo", "${{ nope_fn(1) }}"] }
  - id: b
    needs: [a]
    emit: { seen_status: "${{ steps.a.status }}" }
"#;
    assert_eq!(status_seen_by_dependent(yaml), "failed");
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
    let mut exec = Executor::new(&def, &mut sink, ctx);
    let outcomes = exec.run_to_completion().unwrap();

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

// ---- Fix round 1, item 1 (CRITICAL): the `Agent`/`Emit`/`Report` arms must
// redact resolved secrets before they reach the sink, exactly as `Tool`
// already does. The pre-fix defect: `Emit`/`Report` passed `resolved.clone()`
// straight into `TaskInput::Json`/`TaskOutput::Json` with no redaction at
// all — measured on the unfixed code, 4 of 4 emitted payloads across those
// two arms contained the cleartext secret. These tests each assert against
// the actual persisted `EventPayload` JSON reaching `TaskSink::emit`, not
// against any in-memory intermediate value. ----

fn secret_run_ctx(inputs: serde_json::Value, key: &str, value: &str) -> RunContext {
    let mut secrets = HashMap::new();
    secrets.insert(key.to_string(), value.to_string());
    RunContext {
        inputs,
        vars: serde_json::json!({}),
        secrets,
        run_id: roundhouse_flow::exec::RunId::new(),
    }
}

#[test]
fn a_secret_referenced_in_an_agent_prompt_is_redacted_before_it_reaches_the_sink() {
    let yaml = r#"
name: agent-secret
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    agent:
      prompt: "use token ${{ secrets.GH_TOKEN }} to authenticate"
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(serde_json::json!({}), "GH_TOKEN", "sk-super-secret");
    let mut exec = Executor::new(&def, &mut sink, ctx);
    exec.run_to_completion().unwrap();

    let created = sink
        .0
        .iter()
        .find(|e| matches!(e.kind, TaskKind::Agent))
        .expect("agent task was emitted");
    let logged_str = serde_json::to_string(&created.payload_json["TaskCreated"]["input"]).unwrap();
    assert!(
        !logged_str.contains("sk-super-secret"),
        "the resolved secret value must never appear verbatim in the persisted log: {logged_str}"
    );
    assert!(logged_str.contains("***"));
}

#[test]
fn a_secret_referenced_in_emit_is_redacted_in_both_the_created_and_completed_events() {
    // Payload measured to leak, verbatim, on the pre-fix code:
    // `{"TaskCreated":{"input":{"Json":{"body":"token=sk-super-secret",...`
    let yaml = r#"
name: emit-secret
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    emit: { body: "token=${{ secrets.GH_TOKEN }}" }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(serde_json::json!({}), "GH_TOKEN", "sk-super-secret");
    let mut exec = Executor::new(&def, &mut sink, ctx);
    exec.run_to_completion().unwrap();

    let flow_events: Vec<_> = sink
        .0
        .iter()
        .filter(|e| matches!(e.kind, TaskKind::Flow))
        .collect();
    assert_eq!(flow_events.len(), 2, "TaskCreated + TaskCompleted");
    for event in &flow_events {
        let logged_str = serde_json::to_string(&event.payload_json).unwrap();
        assert!(
            !logged_str.contains("sk-super-secret"),
            "the resolved secret value must never appear verbatim in the persisted log \
             (event: {logged_str})"
        );
        assert!(logged_str.contains("***"));
    }
}

#[test]
fn a_secret_referenced_in_report_is_redacted_in_both_the_created_and_completed_events() {
    // §8.8's *mandatory* per-run block — payload measured to leak, verbatim,
    // on the pre-fix code:
    // `{"TaskCreated":{"input":{"Json":{"headline":"key sk-super-secret",...`
    let yaml = r#"
name: report-secret
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    report: { outcome: "ok", severity: "low", headline: "key ${{ secrets.GH_TOKEN }}", needs_human: false, cost: { usd: 0.0, tokens: 0 } }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(serde_json::json!({}), "GH_TOKEN", "sk-super-secret");
    let mut exec = Executor::new(&def, &mut sink, ctx);
    exec.run_to_completion().unwrap();

    let report_events: Vec<_> = sink
        .0
        .iter()
        .filter(|e| matches!(e.kind, TaskKind::Report))
        .collect();
    assert_eq!(report_events.len(), 2, "TaskCreated + TaskCompleted");
    for event in &report_events {
        let logged_str = serde_json::to_string(&event.payload_json).unwrap();
        assert!(
            !logged_str.contains("sk-super-secret"),
            "the resolved secret value must never appear verbatim in the persisted log \
             (event: {logged_str})"
        );
        assert!(logged_str.contains("***"));
    }
}

// ---- Fix round 1, item 6 (ruling P27): a JSON-valued secret must be
// redacted by its component string leaves too, not only by its whole-string
// value — otherwise `${{ json(secrets.GCP_KEY).private_key }}` slips past
// redaction through the arm that *is* redacted. ----

#[test]
fn a_field_extracted_from_a_json_valued_secret_is_still_redacted() {
    let key_material = "-----BEGIN PRIVATE KEY-----AAAABBBB-----END PRIVATE KEY-----";
    let secret_json =
        serde_json::json!({ "private_key": key_material, "client_email": "svc@example.iam" })
            .to_string();
    let yaml = r#"
name: json-secret
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    tool: shell
    with: { cmd: ["auth", "${{ json(secrets.GCP_KEY).private_key }}"] }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(serde_json::json!({}), "GCP_KEY", &secret_json);
    let mut exec = Executor::new(&def, &mut sink, ctx);
    let outcomes = exec.run_to_completion().unwrap();
    assert!(
        matches!(outcomes[0].status, StepStatus::Completed),
        "expected Completed, got {:?}",
        outcomes[0].status
    );

    let created = sink
        .0
        .iter()
        .find(|e| matches!(e.kind, TaskKind::Shell))
        .expect("shell task was emitted");
    let logged_str = serde_json::to_string(&created.payload_json["TaskCreated"]["input"]).unwrap();
    assert!(
        !logged_str.contains(key_material),
        "a field extracted from a JSON-valued secret must be redacted too: {logged_str}"
    );
    assert!(logged_str.contains("***"));
}

// ---- Fix round 1, item 5: `RunContext`'s `Debug` impl must never print
// secret values, mirroring `crate::expr::ExprContext`'s own hand-written
// impl. ----

#[test]
fn run_context_debug_never_prints_secret_values() {
    let ctx = secret_run_ctx(
        serde_json::json!({"repo": "acme/widgets"}),
        "GH_TOKEN",
        "sk-super-secret-marker-value",
    );
    let debug_output = format!("{ctx:?}");
    assert!(
        !debug_output.contains("sk-super-secret-marker-value"),
        "RunContext's Debug impl must never print a secret's value: {debug_output}"
    );
    assert!(
        debug_output.contains("GH_TOKEN"),
        "the secret NAME is not itself sensitive and may appear: {debug_output}"
    );
}

// ---- Fix round 1, item 2: `run_to_completion` must return a run-level
// `Err` for a malformed step graph, not panic — `parse_workflow` never
// builds or checks the graph, so a cycle/unknown-dependency/duplicate-id/
// missing-body workflow parses successfully and used to panic inside
// `run_to_completion`'s `.expect(...)` calls. ----

#[test]
fn a_step_with_no_recognized_body_kind_is_a_run_error_not_a_panic() {
    let yaml = r#"
name: no-body
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let mut exec = Executor::new(&def, &mut sink, run_ctx(serde_json::json!({})));
    let err = exec
        .run_to_completion()
        .expect_err("a step with no recognized body kind must be a run-level error, not a panic");
    assert!(matches!(err, ParseError::InvalidStepBody { .. }));
}

#[test]
fn a_needs_cycle_is_a_run_error_not_a_panic() {
    let yaml = r#"
name: cyclic
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    needs: [b]
    tool: shell
    with: { cmd: ["echo", "a"] }
  - id: b
    needs: [a]
    tool: shell
    with: { cmd: ["echo", "b"] }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let mut exec = Executor::new(&def, &mut sink, run_ctx(serde_json::json!({})));
    let err = exec
        .run_to_completion()
        .expect_err("a needs: cycle must be a run-level error, not a panic");
    assert!(matches!(err, ParseError::StepGraphCycle { .. }));
}

// ---- Fix round 1, item 9: `Executor::new` must use `run_ctx.run_id`, not
// a separately-supplied one — the old two-parameter signature let a caller
// mint one `RunId` for `RunContext` and pass a different one to `new`,
// which is exactly what every test used to do, with nothing detecting the
// divergence. ----

#[test]
fn run_id_bound_into_the_expression_context_is_the_one_from_run_context() {
    let run_id = roundhouse_flow::exec::RunId::new();
    let ctx = RunContext {
        inputs: serde_json::json!({}),
        vars: serde_json::json!({}),
        secrets: HashMap::new(),
        run_id,
    };
    let yaml = r#"
name: run-id-check
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    emit: { seen_run_id: "${{ run.id }}" }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let mut exec = Executor::new(&def, &mut sink, ctx);
    exec.run_to_completion().unwrap();

    let completed = sink
        .0
        .iter()
        .find(|e| matches!(e.kind, TaskKind::Flow) && e.payload_json.get("TaskCompleted").is_some())
        .expect("emit: step was persisted");
    let seen = completed.payload_json["TaskCompleted"]["output"]["Json"]["seen_run_id"]
        .as_str()
        .unwrap();
    assert_eq!(
        seen,
        run_id.to_string(),
        "`${{ run.id }}` must resolve to the same RunId passed in via RunContext"
    );
}
