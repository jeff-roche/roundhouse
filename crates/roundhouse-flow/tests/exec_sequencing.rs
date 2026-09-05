use roundhouse_core::TaskId;
use roundhouse_core::TaskKind;
use roundhouse_flow::exec::{Executor, ExecutorError, RunContext, StepStatus, TaskSink};
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
        previous_report: None,
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
    let mut exec = Executor::new(&def, &mut sink, run_ctx(serde_json::json!({}))).unwrap();
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
    )
    .unwrap();
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
    let mut exec = Executor::new(&def, &mut sink, run_ctx(serde_json::json!({}))).unwrap();
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

// ---- Task 18 (B10): the `report:` arm's promised validator. The landed arm
// carried a comment saying "Task 10 additionally wraps this exact call site
// with a report validator so a malformed report step fails loudly at run time
// rather than persisting garbage; that validator does not exist yet in this
// crate, so it is not called here." It exists now. ----

#[test]
fn a_report_that_fails_validation_fails_the_step_and_persists_nothing() {
    // `outcome: "ok"` is not one of §8.6's five outcomes. Before the
    // validator, this persisted verbatim as a `TaskKind::Report` task's
    // completed output and the inbox had no bucket to sort it into — the
    // "garbage the inbox cannot read back" the validator exists to prevent.
    // The append-only `events` table physically rejects UPDATE/DELETE, so
    // "persist it and fix it later" is not available: refusing to emit is
    // the only correction there is.
    let yaml = r#"
name: bad-report
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: final_report
    report: { outcome: "ok", severity: "low", headline: "clean run", needs_human: false, cost: { usd: 0.0, tokens: 0 } }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let mut exec = Executor::new(&def, &mut sink, run_ctx(serde_json::json!({}))).unwrap();
    let outcomes = exec.run_to_completion().unwrap();

    assert_eq!(outcomes.len(), 1);
    match &outcomes[0].status {
        StepStatus::Failed { message } => {
            assert_eq!(
                message,
                "invalid `report:`: invalid value for field `outcome`: \"ok\""
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert!(
        !sink.0.iter().any(|e| matches!(e.kind, TaskKind::Report)),
        "a report that failed validation must emit neither TaskCreated nor TaskCompleted \
         — the plan's version set the step to Failed and persisted the invalid payload anyway"
    );
}

#[test]
fn a_report_whose_secret_derived_field_survives_redaction_still_validates() {
    // The validator runs against the *redacted* rendering, because that is
    // what is persisted and what the inbox loads back. A secret in a free
    // text field therefore validates as the redaction placeholder — correct,
    // and worth stating because it is surprising.
    let yaml = r#"
name: report-secret-valid
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    report: { outcome: "changed", severity: "low", headline: "key ${{ secrets.GH_TOKEN }}", needs_human: false, cost: { usd: 0.0, tokens: 0 } }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(serde_json::json!({}), "GH_TOKEN", "sk-super-secret");
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().unwrap();
    assert!(matches!(outcomes[0].status, StepStatus::Completed));

    let completed = sink
        .0
        .iter()
        .find(|e| {
            matches!(e.kind, TaskKind::Report) && e.payload_json.get("TaskCompleted").is_some()
        })
        .expect("TaskCompleted was emitted");
    let headline = completed.payload_json["TaskCompleted"]["output"]["Json"]["headline"]
        .as_str()
        .expect("headline is a string");
    assert!(
        !headline.contains("sk-super-secret") && headline.contains("***"),
        "the persisted headline carries the placeholder, not the secret: {headline}"
    );
    let validated = roundhouse_flow::report::validate_report(
        &completed.payload_json["TaskCompleted"]["output"]["Json"],
    )
    .expect("what was persisted is what the inbox can load back");
    assert_eq!(validated.headline, headline);
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
    let mut exec = Executor::new(&def, &mut sink, run_ctx(serde_json::json!({}))).unwrap();
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
    let mut exec = Executor::new(&def, &mut sink, run_ctx(serde_json::json!({}))).unwrap();
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
    let mut exec = Executor::new(&def, &mut sink, run_ctx(serde_json::json!({}))).unwrap();
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
    let mut exec = Executor::new(&def, &mut sink, run_ctx(serde_json::json!({}))).unwrap();
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
        previous_report: None,
    };
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
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
        previous_report: None,
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
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
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
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
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
    //
    // Task 18 (B10) changed this fixture's `outcome` from `"ok"` to
    // `"changed"`. `"ok"` was never one of §8.6's five outcomes; it only
    // reached the sink because nothing validated the report. Now that the
    // arm validates, an invalid report emits no events at all, which would
    // have failed the length assertion below (`0 != 2`); the fixture is
    // corrected so the redaction assertions still run. (Fix round 1, ruling
    // P74: only the `for` loop over `report_events` would have been
    // vacuous — the preceding `assert_eq!(report_events.len(), 2, …)` fails
    // loudly on its own, so leaving `"ok"` in place would not have gone
    // silently green.)
    let yaml = r#"
name: report-secret
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    report: { outcome: "changed", severity: "low", headline: "key ${{ secrets.GH_TOKEN }}", needs_human: false, cost: { usd: 0.0, tokens: 0 } }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(serde_json::json!({}), "GH_TOKEN", "sk-super-secret");
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
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
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
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
    let mut exec = Executor::new(&def, &mut sink, run_ctx(serde_json::json!({}))).unwrap();
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
    let mut exec = Executor::new(&def, &mut sink, run_ctx(serde_json::json!({}))).unwrap();
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
        previous_report: None,
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
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
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

// ---- Fix round 2, item 1: `StepOutcome` derives no `Debug` — the `Emit`/
// `Report` arms deliberately keep `output` unredacted (a dependent step
// must see the real value), so `run_to_completion`'s `Vec<StepOutcome>`
// must never let a derived `Debug` reproduce a resolved secret. ----

#[test]
fn step_outcome_debug_never_prints_a_secrets_resolved_value() {
    // Payload: an `emit:` step whose body resolves a secret to a planted
    // marker value, exactly the shape the reviewer measured leaking through
    // a derived `Debug`: `StepOutcome { ..., output: Object {"body":
    // String("token=sk-MARKER-9999")}, ... }`.
    let yaml = r#"
name: outcome-debug-secret
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
    let ctx = secret_run_ctx(serde_json::json!({}), "GH_TOKEN", "sk-MARKER-9999");
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().unwrap();

    // Sanity: `output` really does carry the unredacted value (that's the
    // whole point of this test — a redacted `output` would make the `Debug`
    // impl trivially safe for the wrong reason).
    assert_eq!(
        outcomes[0].output,
        serde_json::json!({"body": "token=sk-MARKER-9999"}),
        "StepOutcome.output must stay unredacted so a dependent sees the real value"
    );

    let debug_output = format!("{:?}", outcomes[0]);
    assert!(
        !debug_output.contains("sk-MARKER-9999"),
        "StepOutcome's Debug impl must never print a resolved secret's value: {debug_output}"
    );
    assert!(
        debug_output.contains("body"),
        "the output's shape (key list) may still appear: {debug_output}"
    );
}

// ---- Fix round 2, item 2: the echoed `when:`-field text and the
// `steps.<id>.error` field it feeds are each bounded independently. ----

#[test]
fn a_when_evaluation_error_echoes_only_a_bounded_prefix_of_the_offending_field() {
    // Payload: a 2,000-byte bare (non-`${{ }}`-wrapped) `when:` field built
    // from the marker byte `'Z'`. Pre-fix, `NotADelimitedExpression` echoed
    // the whole field verbatim.
    let marker = "Z".repeat(2_000);
    let yaml = format!(
        "name: bare-when-overlong\nversion: 1\ninputs: {{}}\ndefaults: {{ isolation: \
         worktree }}\npermissions: {{ default: deny, unattended: {{ escalate: fail }} \
         }}\nsteps:\n  - id: a\n    when: \"{marker}\"\n    tool: shell\n    with: {{ cmd: \
         [\"echo\", \"a\"] }}\n"
    );
    let def = parse_workflow(&yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let mut exec = Executor::new(&def, &mut sink, run_ctx(serde_json::json!({}))).unwrap();
    let outcomes = exec.run_to_completion().unwrap();
    match &outcomes[0].status {
        StepStatus::Failed { message } => {
            assert!(
                message.len() < 300,
                "the `when:` evaluation error must not echo the full 2,000-byte field: {} bytes \
                 ({message})",
                message.len()
            );
            assert!(
                !message.contains(&marker),
                "the full marker text must not appear verbatim in the error: {message}"
            );
            assert!(
                message.contains("2000 bytes total"),
                "the truncated message should still state the original field length: {message}"
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

#[test]
fn steps_context_error_field_is_bounded_independently_of_the_underlying_message_source() {
    // A source other than `NotADelimitedExpression` (which truncates its
    // own echo): an `UnexpectedToken` from a malformed `with:` expression,
    // whose echoed remainder is not itself bounded by `expr.rs`. This
    // proves `steps_context_entry`'s bound is independent of the source,
    // not merely a side effect of `expr.rs`'s own truncation. Payload:
    // 5,000 `'Q'` bytes of trailing garbage after a valid `1` inside a
    // `${{ }}` block, read back by a dependent's `emit:`.
    let junk = "Q".repeat(5_000);
    let mut yaml = String::from(
        "name: overlong-unexpected-token\nversion: 1\ninputs: {}\ndefaults: { isolation: \
         worktree }\npermissions: { default: deny, unattended: { escalate: fail } \
         }\nsteps:\n  - id: a\n    tool: shell\n    with: { cmd: [\"echo\", \"${{ 1 ",
    );
    yaml.push_str(&junk);
    yaml.push_str(
        " }}\"] }\n  - id: b\n    needs: [a]\n    emit: { seen_error: \"${{ steps.a.error }}\" \
         }\n",
    );
    let def = parse_workflow(&yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let mut exec = Executor::new(&def, &mut sink, run_ctx(serde_json::json!({}))).unwrap();
    exec.run_to_completion().unwrap();

    let flow_event = sink
        .0
        .iter()
        .find(|e| matches!(e.kind, TaskKind::Flow) && e.payload_json.get("TaskCompleted").is_some())
        .expect("dependent's emit: step was persisted");
    let seen_error = flow_event.payload_json["TaskCompleted"]["output"]["Json"]["seen_error"]
        .as_str()
        .expect("seen_error is a string")
        .to_string();
    assert!(
        seen_error.len() < 700,
        "steps.<id>.error must be bounded independently of the underlying message's own \
         length: {} bytes",
        seen_error.len()
    );
    assert!(
        !seen_error.contains(&junk),
        "the full 5,000-byte junk text must not reach a dependent verbatim"
    );
}

// ---- Fix round 2, item 3: a secret this crate cannot safely redact is
// refused at `Executor::new`, not silently left unprotected. ----

#[test]
fn a_secret_shorter_than_the_redaction_floor_is_rejected_at_construction() {
    // Payload: a 7-byte secret value, `"1234567"`. Pre-fix, this reached
    // the log in cleartext with no signal to the operator at all.
    let def = parse_workflow(SIMPLE_YAML).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(serde_json::json!({}), "SHORT", "1234567");
    let err = Executor::new(&def, &mut sink, ctx)
        .err()
        .expect("a 7-byte secret must be refused at construction, not silently unprotected");
    if let ExecutorError::SecretTooShortToRedact { name } = &err {
        assert_eq!(name, "SHORT");
    } else {
        panic!("unexpected ExecutorError variant: {err:?}");
    }
    // Fix round 3: the secret's own byte length is a length oracle on a
    // credential and must appear neither as a field (checked by the
    // destructuring above, which would not compile if `len` still existed)
    // nor in the rendered message.
    let rendered = err.to_string();
    assert!(
        !rendered.contains('7'),
        "the rejection message must not report the secret's actual byte length: {rendered}"
    );
    assert!(
        rendered.contains("SHORT") && rendered.contains('8'),
        "it must still name the secret and the fixed minimum: {rendered}"
    );
}

#[test]
fn a_secret_exactly_at_the_redaction_floor_is_accepted() {
    // Boundary test, the other side of the previous test: exactly 8 bytes
    // (`MIN_REDACTABLE_SECRET_LEN`) must construct successfully.
    let def = parse_workflow(SIMPLE_YAML).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(serde_json::json!({}), "EIGHTBYT", "12345678");
    assert!(
        Executor::new(&def, &mut sink, ctx).is_ok(),
        "an 8-byte secret is exactly at the redactable floor and must be accepted"
    );
}

// ---- No over-redaction of unrelated text. Written for fix round 2's
// key-name gating (ruling P30) and KEPT UNCHANGED through fix round 3's move
// to provenance (ruling P33), which deleted that gating entirely: this is
// P30's original, legitimate concern and it must not regress. Under
// provenance the four GCP public constants pass through because they were
// never derived from a `secrets.*` lookup — they are literal `with:` text —
// and the only remaining needle is the whole secret's own JSON string, which
// none of them contains. The `private_key` half of the test now passes
// because `json(secrets.GCP_KEY).private_key` read the secrets root, not
// because `private_key` is a name anything recognises. ----

#[test]
fn json_secret_leaf_expansion_does_not_corrupt_unrelated_public_constants() {
    // Payload: a GCP-service-account-shaped secret (the exact fields a real
    // key has) alongside a second step whose `with:` contains, verbatim,
    // the four strings security measured corrupted pre-fix.
    let gcp_key = serde_json::json!({
        "type": "service_account",
        "project_id": "my-project-1234",
        "private_key": "-----BEGIN PRIVATE KEY-----AAAABBBB-----END PRIVATE KEY-----",
        "client_email": "svc@example.iam",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    })
    .to_string();

    let yaml = r#"
name: gcp-key-shaped-secret
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: uses_private_key
    tool: shell
    with: { cmd: ["auth", "${{ json(secrets.GCP_KEY).private_key }}"] }
  - id: ordinary_strings
    tool: shell
    with:
      cmd:
        - "this is a service_account for the team"
        - "https://storage.googleapis.com/public-bucket/x"
        - "https://accounts.google.com/o/oauth2/auth"
        - "deploying my-project-1234 to staging"
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(serde_json::json!({}), "GCP_KEY", &gcp_key);
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().unwrap();
    assert!(
        outcomes
            .iter()
            .all(|o| matches!(o.status, StepStatus::Completed)),
        "expected both steps Completed, got {outcomes:?}"
    );

    let shell_events: Vec<_> = sink
        .0
        .iter()
        .filter(|e| matches!(e.kind, TaskKind::Shell))
        .collect();
    assert_eq!(shell_events.len(), 2);

    let private_key_event = shell_events
        .iter()
        .find(|e| e.payload_json["TaskCreated"]["input"]["Json"]["cmd"][0].as_str() == Some("auth"))
        .expect("the private-key step was dispatched");
    let private_key_logged = serde_json::to_string(&private_key_event.payload_json).unwrap();
    assert!(
        !private_key_logged.contains("BEGIN PRIVATE KEY"),
        "the actually-sensitive `private_key` leaf must still be redacted: {private_key_logged}"
    );
    assert!(private_key_logged.contains("***"));

    let ordinary_event = shell_events
        .iter()
        .find(|e| {
            e.payload_json["TaskCreated"]["input"]["Json"]["cmd"][0].as_str()
                == Some("this is a service_account for the team")
        })
        .expect("the ordinary-strings step was dispatched");
    let ordinary_logged = serde_json::to_string(&ordinary_event.payload_json).unwrap();
    for expected in [
        "this is a service_account for the team",
        "https://storage.googleapis.com/public-bucket/x",
        "https://accounts.google.com/o/oauth2/auth",
        "deploying my-project-1234 to staging",
    ] {
        assert!(
            ordinary_logged.contains(expected),
            "ordinary text containing a GCP public constant must survive redaction \
             unmodified: expected {expected:?} in {ordinary_logged}"
        );
    }
}

// ============================================================================
// Fix round 3 (ruling P33): redaction is PROVENANCE-based.
//
// A value is redacted in the logged rendering because of WHERE IT CAME FROM —
// it was computed by reading `secrets.*` — never because of what a JSON key
// it landed under happens to be called, and never because of how long it is.
// The name-based `SENSITIVE_JSON_LEAF_KEYS` expansion is deleted; what stays
// is one bounded backstop, exact-match needles for the whole declared secret
// values, for a credential an author pasted literally into the YAML.
//
// Every test below drives the real public API end to end
// (`parse_workflow` -> `Executor::new` -> `run_to_completion`) and asserts on
// the emitted `EventPayload` and the returned `StepOutcome`, on parsed
// structure rather than serialized JSON text (ruling P29).
// ============================================================================

/// Runs a one-step workflow whose `emit:` body is `{ probe: <field> }` and
/// returns `(logged rendering of probe, real value of probe)` — the logged
/// half read back out of the persisted `EventPayload::TaskCreated`, the real
/// half out of `StepOutcome.output`, which is what a dependent step reads and
/// what Task 8's durability layer hands onward.
///
/// Both halves come from ONE `run_to_completion`, so every test using this
/// helper is inherently a dual-render test: it cannot pass by redacting the
/// dispatched value too.
fn probe_emit(field: &str, secrets: &[(&str, &str)]) -> (serde_json::Value, serde_json::Value) {
    let yaml = format!(
        "name: probe\nversion: 1\ninputs: {{}}\ndefaults: {{ isolation: worktree }}\n\
         permissions: {{ default: deny, unattended: {{ escalate: fail }} }}\n\
         steps:\n  - id: probe\n    emit: {{ probe: \"{field}\" }}\n"
    );
    let def =
        parse_workflow(&yaml).unwrap_or_else(|e| panic!("probe YAML must parse: {e} ({yaml})"));
    let mut sink = RecordingSink(Vec::new());
    let mut secret_map = HashMap::new();
    for (k, v) in secrets {
        secret_map.insert((*k).to_string(), (*v).to_string());
    }
    let ctx = RunContext {
        inputs: serde_json::json!({"clean": "ordinary-input-value"}),
        vars: serde_json::json!({"list": [10, 11, 12]}),
        secrets: secret_map,
        run_id: roundhouse_flow::exec::RunId::new(),
        previous_report: None,
    };
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().unwrap();
    assert!(
        matches!(outcomes[0].status, StepStatus::Completed),
        "probe step must complete, got {:?}",
        outcomes[0].status
    );
    let created = sink
        .0
        .iter()
        .find(|e| matches!(e.kind, TaskKind::Flow) && e.payload_json.get("TaskCreated").is_some())
        .expect("the emit: step was persisted");
    let logged = created.payload_json["TaskCreated"]["input"]["Json"]["probe"].clone();
    let real = outcomes[0].output["probe"].clone();
    (logged, real)
}

fn redacted() -> serde_json::Value {
    serde_json::json!("***")
}

/// The exact 29 credential key names measured leaking in cleartext under the
/// name-list design (fix round 2), plus the camelCase forms whose snake_case
/// spellings were on the list. Under provenance the list is irrelevant — it
/// is kept as a regression corpus, not as a mechanism.
const CREDENTIAL_KEY_NAMES_THE_NAME_LIST_MISSED: &[&str] = &[
    "AccessKeyId",
    "SecretAccessKey",
    "SessionToken",
    "connection_string",
    "ssh_private_key",
    "credentials",
    "credential",
    "auth",
    "authorization",
    "bearer",
    "signature",
    "cert",
    "secret_key",
    "secretKey",
    "session_token",
    "sas_token",
    "aws_secret_access_key",
    "aws_session_token",
    "secret_access_key",
    "pwd",
    "webhook_secret",
    "signing_secret",
    "signing_key",
    "encryption_key",
    "personal_access_token",
    "oauth_token",
    "client_key",
    "client_email",
    "certificate",
];

#[test]
fn every_credential_key_name_the_name_list_missed_is_redacted_by_provenance() {
    // Payload, per row: a JSON-valued secret `{"<key>": "MARKER-<key>-0001"}`
    // and an `emit:` step whose only field is
    // `${{ json(secrets.K).<key> }}`. The marker is never a substring of the
    // whole-secret backstop needle in a way the needle can match (the needle
    // is the entire JSON text), so a pass here is provenance doing the work,
    // not the backstop.
    for key in CREDENTIAL_KEY_NAMES_THE_NAME_LIST_MISSED {
        let marker = format!("MARKER-{key}-0001");
        let secret = serde_json::json!({ *key: marker.clone() }).to_string();
        let (logged, real) = probe_emit(
            &format!("${{{{ json(secrets.K).{key} }}}}"),
            &[("K", &secret)],
        );
        assert_eq!(
            logged,
            redacted(),
            "a credential under the key {key:?} must be redacted in the logged rendering"
        );
        assert_eq!(
            real,
            serde_json::json!(marker),
            "…while the real value still reaches the dispatched step (key {key:?})"
        );
    }
}

#[test]
fn the_key_name_key_alone_is_redacted_by_provenance() {
    // Separated from the table above only because `key` is also the name of
    // the secret binding in some real workflows and reads confusingly inline.
    let secret = serde_json::json!({ "key": "MARKER-bare-key-0002" }).to_string();
    let (logged, real) = probe_emit("${{ json(secrets.K).key }}", &[("K", &secret)]);
    assert_eq!(logged, redacted());
    assert_eq!(real, serde_json::json!("MARKER-bare-key-0002"));
}

#[test]
fn the_camel_case_token_key_names_are_redacted_by_provenance() {
    // `accessToken`/`refreshToken` — the camelCase spellings whose
    // snake_case forms WERE on the deleted name list, which is exactly the
    // shape that makes a name list unbounded.
    for key in ["accessToken", "refreshToken"] {
        let marker = format!("MARKER-{key}-0003");
        let secret = serde_json::json!({ key: marker.clone() }).to_string();
        let (logged, real) = probe_emit(
            &format!("${{{{ json(secrets.K).{key} }}}}"),
            &[("K", &secret)],
        );
        assert_eq!(logged, redacted(), "camelCase key {key:?} must redact");
        assert_eq!(real, serde_json::json!(marker));
    }
}

#[test]
fn the_literal_aws_sts_assume_role_credential_blob_is_redacted_field_by_field() {
    // Payload: the exact, unmodified JSON shape `aws sts assume-role`
    // returns. None of its three field names matched the deleted name list,
    // so all three leaked in cleartext under fix round 2.
    let secret = serde_json::json!({
        "AccessKeyId": "ASIAMARKERAKID0004",
        "SecretAccessKey": "MARKER-SECRET-ACCESS-KEY-0004",
        "SessionToken": "MARKER-SESSION-TOKEN-0004",
    })
    .to_string();
    for (field, expected) in [
        ("AccessKeyId", "ASIAMARKERAKID0004"),
        ("SecretAccessKey", "MARKER-SECRET-ACCESS-KEY-0004"),
        ("SessionToken", "MARKER-SESSION-TOKEN-0004"),
    ] {
        let (logged, real) = probe_emit(
            &format!("${{{{ json(secrets.K).{field} }}}}"),
            &[("K", &secret)],
        );
        assert_eq!(logged, redacted(), "STS field {field:?} must redact");
        assert_eq!(real, serde_json::json!(expected));
    }
}

#[test]
fn a_credential_nested_under_a_non_sensitive_parent_is_redacted() {
    // Payload: `{"Credentials": {"SecretAccessKey": "MARKER-NESTED-0005"}}` —
    // the AWS `assume-role` envelope, where the outer key is not itself
    // credential-shaped.
    let secret =
        serde_json::json!({"Credentials": {"SecretAccessKey": "MARKER-NESTED-0005"}}).to_string();
    let (logged, real) = probe_emit(
        "${{ json(secrets.K).Credentials.SecretAccessKey }}",
        &[("K", &secret)],
    );
    assert_eq!(logged, redacted());
    assert_eq!(real, serde_json::json!("MARKER-NESTED-0005"));
}

#[test]
fn an_array_of_credential_objects_is_redacted_through_the_index() {
    // Payload: the `.dockerconfigjson` shape — an array of objects, reached
    // by index, then by field.
    let secret = serde_json::json!({"auths": [{"password": "MARKER-DOCKERCFG-0006"}]}).to_string();
    let (logged, real) = probe_emit(
        "${{ json(secrets.K).auths[0].password }}",
        &[("K", &secret)],
    );
    assert_eq!(logged, redacted());
    assert_eq!(real, serde_json::json!("MARKER-DOCKERCFG-0006"));
}

#[test]
fn a_top_level_json_array_secret_is_redacted_through_the_index() {
    // Payload: a secret whose whole value is a JSON *array*. The deleted
    // leaf walk dropped these entirely (its `_ => {}` arm had no object key
    // above the leaf to test).
    let secret = serde_json::json!(["MARKER-TOP-ARRAY-0007", "second"]).to_string();
    let (logged, real) = probe_emit("${{ json(secrets.K)[0] }}", &[("K", &secret)]);
    assert_eq!(logged, redacted());
    assert_eq!(real, serde_json::json!("MARKER-TOP-ARRAY-0007"));
}

#[test]
fn a_top_level_bare_string_secret_is_redacted() {
    // Payload: a plain, non-JSON secret value referenced directly. Both
    // provenance and the whole-value backstop cover this one; it is asserted
    // because the brief names it as a shape that must not regress.
    let (logged, real) = probe_emit(
        "${{ secrets.K }}",
        &[("K", "MARKER-BARE-STRING-SECRET-0008")],
    );
    assert_eq!(logged, redacted());
    assert_eq!(real, serde_json::json!("MARKER-BARE-STRING-SECRET-0008"));
}

#[test]
fn a_derived_leaf_shorter_than_the_redaction_floor_is_still_redacted() {
    // The brief's item 3, verbatim: `{"password":"9182","token":"abcdefghij"}`
    // is 44 bytes, so `Executor::new` accepts it, and pre-fix the run emitted
    // `{"cmd":["9182","***"]}` — the 4-byte leaf below
    // `MIN_REDACTABLE_SECRET_LEN` was silently unprotected. Provenance has no
    // length floor at all: a whole substitution is replaced, not a substring
    // searched for.
    let secret = r#"{"password":"9182","token":"abcdefghij"}"#;
    assert_eq!(secret.len(), 40, "the payload's own size, stated");
    let yaml = r#"
name: short-derived-leaf
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    emit:
      cmd:
        - "${{ json(secrets.K).password }}"
        - "${{ json(secrets.K).token }}"
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(serde_json::json!({}), "K", secret);
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().unwrap();

    let created = sink
        .0
        .iter()
        .find(|e| matches!(e.kind, TaskKind::Flow) && e.payload_json.get("TaskCreated").is_some())
        .expect("the emit: step was persisted");
    assert_eq!(
        created.payload_json["TaskCreated"]["input"]["Json"]["cmd"],
        serde_json::json!(["***", "***"]),
        "both leaves redact, including the 4-byte one"
    );
    assert_eq!(
        outcomes[0].output["cmd"],
        serde_json::json!(["9182", "abcdefghij"]),
        "…while the real values still reach the dispatched step"
    );
}

#[test]
fn the_real_value_reaches_dispatch_while_only_the_logged_copy_is_redacted() {
    // The dual-render property, asserted in one test on one run, plus the
    // cross-step propagation that makes it non-trivial.
    //
    // Payload: step `a` emits `{ body: "${{ json(secrets.K).password }}" }`
    // for the secret `{"password":"9182"}`; step `b` reads back
    // `${{ steps.a.output.body }}` (a value that was NEVER a `secrets.*`
    // lookup of its own, and whose text the whole-secret backstop cannot
    // match) and also `${{ steps.a.status }}` (which carries no secret
    // material and must stay readable in the log).
    let yaml = r#"
name: dual-render
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    emit: { body: "${{ json(secrets.K).password }}" }
  - id: b
    needs: [a]
    emit: { relayed: "${{ steps.a.output.body }}", upstream_status: "${{ steps.a.status }}" }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(serde_json::json!({}), "K", r#"{"password":"9182"}"#);
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().unwrap();

    let created: Vec<&serde_json::Value> = sink
        .0
        .iter()
        .filter(|e| matches!(e.kind, TaskKind::Flow) && e.payload_json.get("TaskCreated").is_some())
        .map(|e| &e.payload_json["TaskCreated"]["input"]["Json"])
        .collect();
    assert_eq!(created.len(), 2, "both emit: steps were persisted");

    // Step a: logged redacted, real value intact.
    assert_eq!(created[0]["body"], redacted());
    assert_eq!(outcomes[0].output["body"], serde_json::json!("9182"));

    // Step b: the relayed value is still secret-derived across the step
    // boundary — logged redacted — and STILL reaches dispatch for real. A
    // test asserting only the log would pass if the dispatched value were
    // redacted too, which would break every workflow that legitimately
    // passes a secret from one step to the next.
    assert_eq!(created[1]["relayed"], redacted());
    assert_eq!(outcomes[1].output["relayed"], serde_json::json!("9182"));

    // …and the taint is path-precise, not "the whole upstream step": the
    // upstream step's status is not secret material and stays readable.
    assert_eq!(
        created[1]["upstream_status"],
        serde_json::json!("completed")
    );
    assert_eq!(
        outcomes[1].output["upstream_status"],
        serde_json::json!("completed")
    );
}

#[test]
fn a_clean_step_output_read_by_a_dependent_is_not_redacted() {
    // The other side of cross-step propagation: an upstream step whose
    // output owes nothing to a secret must not be redacted downstream just
    // because the run has secrets bound. Payload: step `a` emits a literal
    // `{"body": "ordinary-upstream-value"}`, step `b` relays it.
    let yaml = r#"
name: clean-relay
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    emit: { body: "ordinary-upstream-value" }
  - id: b
    needs: [a]
    emit: { relayed: "${{ steps.a.output.body }}" }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(serde_json::json!({}), "K", "an-unused-but-declared-secret");
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    exec.run_to_completion().unwrap();

    let created: Vec<&serde_json::Value> = sink
        .0
        .iter()
        .filter(|e| matches!(e.kind, TaskKind::Flow) && e.payload_json.get("TaskCreated").is_some())
        .map(|e| &e.payload_json["TaskCreated"]["input"]["Json"])
        .collect();
    assert_eq!(
        created[1]["relayed"],
        serde_json::json!("ordinary-upstream-value"),
        "a clean upstream output must not be redacted downstream"
    );
}

#[test]
fn reading_the_whole_steps_root_or_a_whole_step_entry_is_redacted_when_it_contains_secret_material()
{
    // A prefix of a secret path still *contains* the secret material, so it
    // is redacted. Payload: step `a` emits a secret-derived body; step `b`
    // interpolates the bare `${{ steps }}` root and the bare
    // `${{ steps.a }}` entry, both of which render the secret as JSON text.
    let yaml = r#"
name: prefix-of-a-secret-path
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    emit: { body: "${{ json(secrets.K).password }}" }
  - id: b
    needs: [a]
    emit: { whole_root: "${{ steps }}", whole_entry: "${{ steps.a }}" }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(serde_json::json!({}), "K", r#"{"password":"9182"}"#);
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().unwrap();

    let created: Vec<&serde_json::Value> = sink
        .0
        .iter()
        .filter(|e| matches!(e.kind, TaskKind::Flow) && e.payload_json.get("TaskCreated").is_some())
        .map(|e| &e.payload_json["TaskCreated"]["input"]["Json"])
        .collect();
    assert_eq!(created[1]["whole_root"], redacted());
    assert_eq!(created[1]["whole_entry"], redacted());
    // The real values still carry the secret, unredacted.
    assert!(outcomes[1].output["whole_entry"]
        .as_str()
        .expect("whole_entry rendered as a string")
        .contains("9182"));
}

/// One row per operation the frozen `${{ }}` grammar can perform — the
/// enumeration the whole correctness argument of provenance-based redaction
/// rests on (ruling P33: "its risk is bounded and enumerable"). A missed
/// propagation path is a credential leak into an append-only table.
///
/// `logged_is_redacted == true` means the logged rendering must be exactly
/// `"***"`; `false` means it must be exactly `real_rendering`.
struct TaintRow {
    operation: &'static str,
    expr: &'static str,
    /// A substring the *real*, dispatched value must still contain — the
    /// other half of the dual-render property, checked on every row.
    real_contains: &'static str,
    logged_is_redacted: bool,
}

/// `secrets.K` for the table below. 66 bytes, so it clears
/// `MIN_REDACTABLE_SECRET_LEN`; `n` is a number so it can be used as an
/// index, and none of its leaves is 8+ bytes of text that the whole-value
/// backstop could match, so every redaction below is provenance's doing.
const TAINT_TABLE_JSON_SECRET: &str =
    r#"{"nested":{"pw":"9182"},"arr":["alpha-marker","beta-marker"],"n":1}"#;
/// `secrets.T` for the table below.
const TAINT_TABLE_STRING_SECRET: &str = "sk-TOKEN-MARKER-0009";

const TAINT_PROPAGATION_TABLE: &[TaintRow] = &[
    TaintRow {
        operation: "string literal",
        expr: "${{ 'plain-literal' }}",
        real_contains: "plain-literal",
        logged_is_redacted: false,
    },
    TaintRow {
        operation: "number literal",
        expr: "${{ 42 }}",
        real_contains: "42",
        logged_is_redacted: false,
    },
    TaintRow {
        operation: "identifier bound by set() (clean root)",
        expr: "${{ inputs.clean }}",
        real_contains: "ordinary-input-value",
        logged_is_redacted: false,
    },
    TaintRow {
        operation: "unbound identifier (resolves to Null)",
        expr: "${{ nosuchroot }}",
        real_contains: "null",
        logged_is_redacted: false,
    },
    TaintRow {
        operation: "identifier bound by set_secret() (bare secret root)",
        expr: "${{ secrets }}",
        real_contains: TAINT_TABLE_STRING_SECRET,
        logged_is_redacted: true,
    },
    TaintRow {
        operation: ".field on a secret root",
        expr: "${{ secrets.T }}",
        real_contains: TAINT_TABLE_STRING_SECRET,
        logged_is_redacted: true,
    },
    TaintRow {
        operation: "chained .field.field through a secret",
        expr: "${{ json(secrets.K).nested.pw }}",
        real_contains: "9182",
        logged_is_redacted: true,
    },
    TaintRow {
        operation: "[idx] on a secret value",
        expr: "${{ json(secrets.K).arr[1] }}",
        real_contains: "beta-marker",
        logged_is_redacted: true,
    },
    TaintRow {
        operation: "[idx] on a CLEAN value with a SECRET index expression",
        expr: "${{ vars.list[json(secrets.K).n] }}",
        real_contains: "11",
        logged_is_redacted: true,
    },
    TaintRow {
        operation: "[idx] on a clean value with a clean index",
        expr: "${{ vars.list[1] }}",
        real_contains: "11",
        logged_is_redacted: false,
    },
    TaintRow {
        operation: "function call: len() over a secret",
        expr: "${{ len(secrets.T) }}",
        real_contains: "20",
        logged_is_redacted: true,
    },
    TaintRow {
        operation: "function call: default() selecting the secret argument",
        expr: "${{ default(secrets.T, 'fallback') }}",
        real_contains: TAINT_TABLE_STRING_SECRET,
        logged_is_redacted: true,
    },
    TaintRow {
        operation: "function call: default() with a secret in a non-first argument",
        expr: "${{ default(nosuchroot, secrets.T) }}",
        real_contains: TAINT_TABLE_STRING_SECRET,
        logged_is_redacted: true,
    },
    TaintRow {
        operation: "function call: contains() reading a secret (boolean oracle)",
        expr: "${{ contains(secrets.T, 'sk-') }}",
        real_contains: "true",
        logged_is_redacted: true,
    },
    TaintRow {
        operation: "function call: slice() over an array literal holding a secret",
        expr: "${{ slice([secrets.T, 'x'], 0, 1) }}",
        real_contains: TAINT_TABLE_STRING_SECRET,
        logged_is_redacted: true,
    },
    TaintRow {
        operation: "function call: flatten() over nested array literals holding a secret",
        expr: "${{ flatten([[secrets.T]]) }}",
        real_contains: TAINT_TABLE_STRING_SECRET,
        logged_is_redacted: true,
    },
    TaintRow {
        operation: "function call: json() parsing a secret",
        expr: "${{ json(secrets.K) }}",
        real_contains: "9182",
        logged_is_redacted: true,
    },
    TaintRow {
        operation: "function call with only clean arguments",
        expr: "${{ len(inputs.clean) }}",
        real_contains: "20",
        logged_is_redacted: false,
    },
    TaintRow {
        operation: "function call: env() — deliberately unchanged, and clean",
        expr: "${{ env('ROUNDHOUSE_FLOW_DEFINITELY_UNSET_VARIABLE_XYZ') }}",
        real_contains: "null",
        logged_is_redacted: false,
    },
    TaintRow {
        operation: "array literal containing a secret",
        expr: "${{ [secrets.T, 'x'] }}",
        real_contains: TAINT_TABLE_STRING_SECRET,
        logged_is_redacted: true,
    },
    TaintRow {
        operation: "array literal with only clean elements",
        expr: "${{ ['x', 'y'] }}",
        real_contains: "\"y\"",
        logged_is_redacted: false,
    },
    TaintRow {
        operation: "comparison with a secret operand (one-bit oracle)",
        expr: "${{ secrets.T == 'nope' }}",
        real_contains: "false",
        logged_is_redacted: true,
    },
    TaintRow {
        operation: "comparison with only clean operands",
        expr: "${{ 1 == 1 }}",
        real_contains: "true",
        logged_is_redacted: false,
    },
    TaintRow {
        operation: "ternary with a secret condition",
        expr: "${{ secrets.T == 'nope' ? 'branch-a' : 'branch-b' }}",
        real_contains: "branch-b",
        logged_is_redacted: true,
    },
    TaintRow {
        operation: "ternary whose SELECTED branch is a secret",
        expr: "${{ 1 == 1 ? secrets.T : 'branch-b' }}",
        real_contains: TAINT_TABLE_STRING_SECRET,
        logged_is_redacted: true,
    },
    TaintRow {
        operation: "ternary whose UNTAKEN branch is a secret (precision, not a leak)",
        expr: "${{ 1 == 1 ? 'branch-a' : secrets.T }}",
        real_contains: "branch-a",
        logged_is_redacted: false,
    },
];

#[test]
fn taint_propagates_through_every_operation_the_evaluator_can_perform() {
    for row in TAINT_PROPAGATION_TABLE {
        let (logged, real) = probe_emit(
            row.expr,
            &[
                ("K", TAINT_TABLE_JSON_SECRET),
                ("T", TAINT_TABLE_STRING_SECRET),
            ],
        );
        let real_str = real.as_str().unwrap_or_else(|| {
            panic!(
                "{}: the probe field interpolates to a string; got {real}",
                row.operation
            )
        });
        assert!(
            real_str.contains(row.real_contains),
            "{}: the REAL dispatched value must be intact and contain {:?}; got {real_str:?} \
             (expr {})",
            row.operation,
            row.real_contains,
            row.expr
        );
        if row.logged_is_redacted {
            assert_eq!(
                logged,
                redacted(),
                "{}: taint must propagate — the logged rendering must be `***` (expr {})",
                row.operation,
                row.expr
            );
        } else {
            assert_eq!(
                logged, real,
                "{}: nothing secret was read, so the logged rendering must equal the real one \
                 (expr {})",
                row.operation, row.expr
            );
        }
    }
}

#[test]
fn the_taint_propagation_table_covers_both_directions() {
    // Guard against a future edit that quietly turns the table into an
    // all-redacted (or all-clean) list, which would still pass the test above
    // while proving nothing about precision.
    let redacting = TAINT_PROPAGATION_TABLE
        .iter()
        .filter(|r| r.logged_is_redacted)
        .count();
    let clean = TAINT_PROPAGATION_TABLE.len() - redacting;
    assert!(
        redacting >= 14 && clean >= 8,
        "the table must exercise both propagation and non-propagation: {redacting} redacting, \
         {clean} clean"
    );
}

#[test]
fn a_credential_pasted_literally_into_the_workflow_yaml_is_still_caught_by_the_bounded_backstop() {
    // The one thing provenance cannot see, and the reason the whole-value
    // needle backstop stays (ruling P33). Payload: a `with:` block containing
    // the secret's exact text as a literal, with no `${{ }}` anywhere — so
    // nothing was derived from `secrets.*` and taint attaches to nothing.
    let literal = "sk-literal-pasted-into-yaml-0010";
    let yaml = r#"
name: literal-paste
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    tool: shell
    with: { cmd: ["echo", "sk-literal-pasted-into-yaml-0010"] }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(serde_json::json!({}), "K", literal);
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    exec.run_to_completion().unwrap();

    let created = sink
        .0
        .iter()
        .find(|e| matches!(e.kind, TaskKind::Shell))
        .expect("shell task was emitted");
    assert_eq!(
        created.payload_json["TaskCreated"]["input"]["Json"]["cmd"],
        serde_json::json!(["echo", "***"]),
        "the exact-match backstop for whole declared secret values must still fire"
    );
}

#[test]
fn step_outcome_debug_bounds_the_status_message_not_only_the_output() {
    // Fix round 3, bundled Minor: `StepOutcome`'s hand-written `Debug`
    // bounded `output` but printed `status` through its derived impl,
    // unbounded — and Task 8's `tracing::debug!(?outcomes)` is the obvious
    // thing to write. Payload: 5,000 `'Q'` bytes of trailing garbage inside a
    // `${{ }}` block in a `with:` field, which produces an `UnexpectedToken`
    // whose echoed remainder `expr.rs`'s own truncation does not touch.
    let junk = "Q".repeat(5_000);
    let mut yaml = String::from(
        "name: overlong-status-message\nversion: 1\ninputs: {}\ndefaults: { isolation: \
         worktree }\npermissions: { default: deny, unattended: { escalate: fail } \
         }\nsteps:\n  - id: a\n    tool: shell\n    with: { cmd: [\"echo\", \"${{ 1 ",
    );
    yaml.push_str(&junk);
    yaml.push_str(" }}\"] }\n");
    let def = parse_workflow(&yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let mut exec = Executor::new(&def, &mut sink, run_ctx(serde_json::json!({}))).unwrap();
    let outcomes = exec.run_to_completion().unwrap();

    let debug_output = format!("{:?}", outcomes[0]);
    assert!(
        debug_output.len() < 700,
        "StepOutcome's Debug must bound `status`'s message, not only `output`: {} bytes",
        debug_output.len()
    );
    assert!(
        !debug_output.contains(&junk),
        "the full 5,000-byte echoed remainder must not reach a caller's `{{:?}}`"
    );
    assert!(
        debug_output.contains("5057 bytes total"),
        "the truncation must still state the original message length: {debug_output}"
    );

    // The same bound applies when a `StepStatus` is printed on its own, not
    // only through `StepOutcome` — `tracing::debug!(?outcome.status)` is just
    // as easy to write.
    let status_debug = format!("{:?}", outcomes[0].status);
    assert!(
        status_debug.len() < 700 && !status_debug.contains(&junk),
        "StepStatus's own Debug must be bounded too: {} bytes",
        status_debug.len()
    );
}

// ---- Fix round 4, item A (ruling P35): provenance's boundary is
// `ExprContext`'s constructors, not the grammar. This test pins the
// documented boundary so a future change to it is a red test rather than a
// stale doc comment. ----

#[test]
fn a_credential_handed_in_as_inputs_or_vars_instead_of_secrets_is_not_tainted_and_logs_in_cleartext(
) {
    // Payload: the two markers ruling P35 records as executed. The run
    // declares NO secrets at all, and instead carries the credentials in
    // `inputs.carried` / `vars.carried`, which `Executor::new` binds through
    // `set_public`. Neither mechanism can see them: provenance because the
    // binding site asserted they are not secret, the whole-secret backstop
    // because there is no declared secret to match.
    let yaml = r#"
name: mis-bound-credential
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    emit: { v: "${{ inputs.carried }}", w: "${{ vars.carried }}" }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = RunContext {
        inputs: serde_json::json!({"carried": "INPUTSCARRIEDSECRET"}),
        vars: serde_json::json!({"carried": "VARSCARRIEDSECRET"}),
        secrets: HashMap::new(),
        run_id: roundhouse_flow::exec::RunId::new(),
        previous_report: None,
    };
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    exec.run_to_completion().unwrap();

    let created = sink
        .0
        .iter()
        .find(|e| matches!(e.kind, TaskKind::Flow) && e.payload_json.get("TaskCreated").is_some())
        .expect("the emit: step was persisted");
    let logged = &created.payload_json["TaskCreated"]["input"]["Json"];
    assert_eq!(
        logged,
        &serde_json::json!({"v": "INPUTSCARRIEDSECRET", "w": "VARSCARRIEDSECRET"}),
        "the documented boundary: a credential bound through a root the caller marked \
         non-secret reaches the log in cleartext"
    );
}

#[test]
fn the_whole_secret_backstop_covers_the_sub_case_where_a_mis_bound_value_equals_a_declared_secret()
{
    // The other half of the same boundary: if the SAME value is also
    // declared under `secrets:`, the exact-match backstop finds it wherever
    // it appears, including where it arrived through `inputs`. That is the
    // only part of the mis-binding shape either mechanism covers, and it does
    // not extend to a value merely *derived* from a mis-bound secret.
    let yaml = r#"
name: mis-bound-but-declared
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    emit: { v: "${{ inputs.carried }}", derived: "${{ slice(inputs.list, 0, 1) }}" }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let mut secrets = HashMap::new();
    secrets.insert("K".to_string(), "INPUTSCARRIEDSECRET".to_string());
    let ctx = RunContext {
        inputs: serde_json::json!({
            "carried": "INPUTSCARRIEDSECRET",
            "list": ["DERIVED-FROM-MISBOUND-0001", "x"],
        }),
        vars: serde_json::json!({}),
        secrets,
        run_id: roundhouse_flow::exec::RunId::new(),
        previous_report: None,
    };
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    exec.run_to_completion().unwrap();

    let created = sink
        .0
        .iter()
        .find(|e| matches!(e.kind, TaskKind::Flow) && e.payload_json.get("TaskCreated").is_some())
        .expect("the emit: step was persisted");
    let logged = &created.payload_json["TaskCreated"]["input"]["Json"];
    assert_eq!(
        logged["v"],
        redacted(),
        "an exact match against a declared secret value IS caught by the backstop"
    );
    assert!(
        logged["derived"]
            .as_str()
            .unwrap()
            .contains("DERIVED-FROM-MISBOUND-0001"),
        "…but a value only *derived* from the mis-bound root is caught by neither \
         mechanism: {}",
        logged["derived"]
    );
}

// ---- Fix round 4, item C: the `when:` gate's one-bit channel, recorded
// rather than closed. ----

#[test]
fn a_when_gate_records_whether_its_condition_read_secret_material() {
    // Payload: step `gated` is gated on `${{ secrets.T == 'nope' }}` — a
    // one-bit oracle on the secret, which decides whether the run emits two
    // events or none. Step `open` is gated on `${{ inputs.go == 'yes' }}`,
    // which reads nothing secret. Both run in one workflow so the flag is
    // shown to be per-step, not per-run.
    let yaml = r#"
name: gate-taint
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: gated
    when: "${{ secrets.T == 'nope' }}"
    emit: { observed: "ran" }
  - id: open
    when: "${{ inputs.go == 'yes' }}"
    emit: { observed: "ran" }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(
        serde_json::json!({"go": "yes"}),
        "T",
        "sk-gate-oracle-secret-0001",
    );
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().unwrap();

    let gated = outcomes.iter().find(|o| o.step_id == "gated").unwrap();
    let open = outcomes.iter().find(|o| o.step_id == "open").unwrap();

    assert!(
        matches!(gated.status, StepStatus::Skipped { .. }),
        "the secret-derived condition is false, so the step is skipped — which is itself \
         the one bit this flag exists to make legible"
    );
    assert!(
        gated.gate_condition_was_secret_derived,
        "a `when:` that read `secrets.*` must be recorded as such on the outcome"
    );
    assert!(
        matches!(open.status, StepStatus::Completed),
        "the clean condition is true, so that step runs"
    );
    assert!(
        !open.gate_condition_was_secret_derived,
        "a `when:` reading only `inputs.*` must not be recorded as secret-derived"
    );
}

#[test]
fn the_when_gates_branch_taken_is_a_one_bit_function_of_the_secret_and_is_observable() {
    // The channel itself, executed, so the accepted-residual comment in
    // `run_to_completion` is backed by a running assertion rather than by
    // prose. Payload: the same workflow run twice against secrets differing
    // only in their first byte (`Asecret-value-0001` vs `Bsecret-value-0001`),
    // gated on `${{ contains(secrets.T, 'A') }}`.
    let yaml = r#"
name: gate-oracle
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: probe
    when: "${{ contains(secrets.T, 'A') }}"
    emit: { observed: "completed" }
"#;
    let def = parse_workflow(yaml).unwrap();

    let mut observed = Vec::new();
    for secret in ["Asecret-value-0001", "Bsecret-value-0001"] {
        let mut sink = RecordingSink(Vec::new());
        let ctx = secret_run_ctx(serde_json::json!({}), "T", secret);
        let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
        let outcomes = exec.run_to_completion().unwrap();
        let emitted = sink
            .0
            .iter()
            .filter(|e| matches!(e.kind, TaskKind::Flow))
            .count();
        observed.push((
            match &outcomes[0].status {
                StepStatus::Completed => "completed",
                StepStatus::Skipped { .. } => "skipped",
                StepStatus::Failed { .. } => "failed",
            },
            emitted,
        ));
    }

    assert_eq!(
        observed,
        vec![("completed", 2), ("skipped", 0)],
        "one bit of the secret selects which fixed discriminant is written, and is \
         observable from the event count alone with no reader step at all — accepted, \
         not closed; see `run_to_completion`'s gate arm"
    );
}

// ---- Fix round 4, item D: the taint bit survives the crate's public
// boundary instead of being consumed inside `run_to_completion`. ----

#[test]
fn a_steps_output_taint_is_readable_on_the_public_step_outcome() {
    // Payload: step `a` emits `{ body: "${{ secrets.T }}" }` (output derived
    // from a secret); step `b` emits a literal `{ body: "ordinary" }` (not).
    // Task 8's durability layer must persist step outputs, and this is the
    // fact it would otherwise have to re-derive — a re-derivation that
    // disagrees with this one is a leak.
    let yaml = r#"
name: outcome-taint
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    emit: { body: "${{ secrets.T }}" }
  - id: b
    emit: { body: "ordinary" }
  - id: c
    tool: shell
    with: { cmd: ["echo", "${{ secrets.T }}"] }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(serde_json::json!({}), "T", "sk-outcome-taint-0002");
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().unwrap();

    let a = outcomes.iter().find(|o| o.step_id == "a").unwrap();
    let b = outcomes.iter().find(|o| o.step_id == "b").unwrap();
    let c = outcomes.iter().find(|o| o.step_id == "c").unwrap();

    assert!(
        a.output_is_secret_derived,
        "`output` really does carry the secret here: {:?}",
        a.output
    );
    assert_eq!(a.output["body"], serde_json::json!("sk-outcome-taint-0002"));
    assert!(!b.output_is_secret_derived);
    assert!(
        !c.output_is_secret_derived,
        "a tool step's `output` is a fixed empty object, so it is not secret-derived \
         even though its `with:` resolved a secret — this flag describes `output`, \
         not the step"
    );
}

// ---- Fix round 4, item E (orchestrator ruling): `interpolate_json` redacts
// per substitution, like `interpolate`, not whole-leaf. ----

#[test]
fn only_the_substitution_is_replaced_in_a_with_field_the_surrounding_url_survives() {
    // The ruling's own payload. Whole-leaf redaction logged this as
    // `{"cmd":["curl","***"]}` — losing the entire URL, including which host
    // was contacted, which is real operational and forensic loss for no
    // security gain, because the substitution is whole-replaced either way.
    let yaml = r#"
name: per-substitution
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: fetch
    tool: shell
    with: { cmd: ["curl", "https://api.example.com/v1?token=${{ secrets.T }}&x=1"] }
  - id: echo
    emit: { cmd: ["curl", "https://api.example.com/v1?token=${{ secrets.T }}&x=1"] }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(serde_json::json!({}), "T", "tok-SECRET-VALUE-12345");
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().unwrap();

    let shell = sink
        .0
        .iter()
        .find(|e| matches!(e.kind, TaskKind::Shell))
        .expect("the tool: step was persisted");
    assert_eq!(
        shell.payload_json["TaskCreated"]["input"]["Json"]["cmd"],
        serde_json::json!(["curl", "https://api.example.com/v1?token=***&x=1"]),
        "the surrounding literal template text survives; only the substitution is `***`"
    );

    // The substitution is still replaced WHOLE — never a substring
    // find-and-replace over the output — and the real value still reaches
    // dispatch, which is what the `emit:` twin shows.
    let emitted = sink
        .0
        .iter()
        .find(|e| matches!(e.kind, TaskKind::Flow) && e.payload_json.get("TaskCreated").is_some())
        .expect("the emit: step was persisted");
    assert_eq!(
        emitted.payload_json["TaskCreated"]["input"]["Json"]["cmd"],
        serde_json::json!(["curl", "https://api.example.com/v1?token=***&x=1"])
    );
    let echo = outcomes.iter().find(|o| o.step_id == "echo").unwrap();
    assert_eq!(
        echo.output["cmd"],
        serde_json::json!([
            "curl",
            "https://api.example.com/v1?token=tok-SECRET-VALUE-12345&x=1"
        ]),
        "…while the unredacted half still carries the real token to dispatch"
    );
}

#[test]
fn a_leaf_built_from_two_substitutions_redacts_only_the_secret_one() {
    // Sharpens the previous test: a single leaf holding one clean and one
    // secret substitution must keep the clean one intact. Payload:
    // `"repo=${{ inputs.repo }} token=${{ secrets.T }} done"`.
    let yaml = r#"
name: mixed-leaf
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    emit: { line: "repo=${{ inputs.repo }} token=${{ secrets.T }} done" }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(
        serde_json::json!({"repo": "acme/widgets"}),
        "T",
        "tok-SECRET-VALUE-67890",
    );
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().unwrap();

    let created = sink
        .0
        .iter()
        .find(|e| matches!(e.kind, TaskKind::Flow) && e.payload_json.get("TaskCreated").is_some())
        .expect("the emit: step was persisted");
    assert_eq!(
        created.payload_json["TaskCreated"]["input"]["Json"]["line"],
        serde_json::json!("repo=acme/widgets token=*** done")
    );
    assert_eq!(
        outcomes[0].output["line"],
        serde_json::json!("repo=acme/widgets token=tok-SECRET-VALUE-67890 done")
    );
}

// ---- Fix round 4, item F: `steps['a']` is a typed failure, not a silent
// `Null` that looks like a successful lookup. ----

#[test]
fn a_string_subscript_on_steps_fails_the_step_instead_of_emitting_null() {
    // Payload: `emit: { probe: "${{ steps['a'].output.sec }}" }` — the exact
    // shape from the security lens's retracted probe. Pre-fix the step
    // completed and emitted the literal string `"null"`, so a wrong result
    // was indistinguishable from a right one.
    let yaml = r#"
name: string-subscript
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    emit: { sec: "${{ secrets.T }}" }
  - id: b
    needs: [a]
    emit: { probe: "${{ steps['a'].output.sec }}" }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(serde_json::json!({}), "T", "sk-subscript-probe-0003");
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().unwrap();

    let b = outcomes.iter().find(|o| o.step_id == "b").unwrap();
    let message = match &b.status {
        StepStatus::Failed { message } => message.clone(),
        other => panic!("expected the step to fail loudly, got {other:?}"),
    };
    assert!(
        message.contains("'a'") && message.contains("`[..]` indexes an array by position"),
        "the failure must name the offending subscript and what to write instead: {message}"
    );
    assert!(
        !message.contains("sk-subscript-probe-0003"),
        "…and must never carry the value the expression was reaching for: {message}"
    );
    // Nothing was emitted for the failed step, so no `"null"` reached the log.
    let flow_created = sink
        .0
        .iter()
        .filter(|e| matches!(e.kind, TaskKind::Flow) && e.payload_json.get("TaskCreated").is_some())
        .count();
    assert_eq!(flow_created, 1, "only step `a` emitted anything");
}

// ---- Fix round 5, item 1: a `when:` that fails to evaluate records the gate
// as secret-derived, because its taint is unknown (ruling P35). ----

#[test]
fn a_when_that_fails_to_evaluate_because_of_the_secrets_content_records_the_gate_as_secret_derived()
{
    // Payload — ONE workflow, two runs differing only in the secret's content:
    //
    //   when: "${{ inputs.arr[json(secrets.K).idx] }}"   inputs.arr = [true, false]
    //
    //   K = `{"idx":0}`               -> subscript 0, `arr[0]` is true -> Completed
    //   K = `{"idx":"not-a-number"}`  -> subscript is a string         -> Failed
    //
    // Nothing but the secret's own content decides which of those happens, so
    // both runs must record the gate as secret-derived. The failing run is the
    // one that used to record `false` — i.e. "this gate read nothing secret" —
    // for exactly the case where the secret decided the outcome.
    let yaml = r#"
name: gate-eval-failure-taint
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: g5
    when: "${{ inputs.arr[json(secrets.K).idx] }}"
    emit: { v: "v" }
"#;
    let def = parse_workflow(yaml).unwrap();

    let mut observed: Vec<(String, bool)> = Vec::new();
    for secret in [r#"{"idx":0}"#, r#"{"idx":"not-a-number"}"#] {
        let mut sink = RecordingSink(Vec::new());
        let ctx = secret_run_ctx(serde_json::json!({"arr": [true, false]}), "K", secret);
        let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
        let outcomes = exec.run_to_completion().unwrap();
        let g5 = outcomes.iter().find(|o| o.step_id == "g5").unwrap();
        let status = match &g5.status {
            StepStatus::Completed => "completed",
            StepStatus::Failed { .. } => "failed",
            StepStatus::Skipped { .. } => "skipped",
        };
        observed.push((status.to_string(), g5.gate_condition_was_secret_derived));
    }

    assert_eq!(
        observed,
        vec![
            ("completed".to_string(), true),
            ("failed".to_string(), true),
        ],
        "the secret's content alone flips this gate between completing and failing to \
         evaluate; both runs must record the gate as secret-derived, and the failing one \
         is the arm that used to report the gate as clean"
    );
}

#[test]
fn a_when_whose_evaluation_fails_records_the_gate_as_secret_derived_even_with_no_secret_in_it() {
    // The other two shapes of an evaluation failure, and the price of the
    // fail-safe default, both asserted so neither can drift silently:
    //
    //   - `when: "${{ nosuchfn(secrets.T) }}"`  — an unknown function applied
    //     to a secret. The gate really is secret-derived; recording `false`
    //     here would have been a straightforward miss.
    //   - `when: "${{ nosuchfn(1) }}"`          — an unknown function applied
    //     to a literal. Nothing secret is involved, and this still records
    //     `true`. That is the accepted cost of the fail-safe default: an
    //     over-redacted log line for a gate that failed for an unrelated
    //     reason, rather than a clean-looking flag on a gate whose taint the
    //     `Err` arm cannot see.
    let yaml = r#"
name: gate-eval-failure-shapes
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: with_secret
    when: "${{ nosuchfn(secrets.T) }}"
    emit: { v: "v" }
  - id: without_secret
    when: "${{ nosuchfn(1) }}"
    emit: { v: "v" }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(serde_json::json!({}), "T", "sk-unknown-fn-probe-0007");
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().unwrap();

    for id in ["with_secret", "without_secret"] {
        let o = outcomes.iter().find(|o| o.step_id == id).unwrap();
        let message = match &o.status {
            StepStatus::Failed { message } => message.clone(),
            other => panic!("expected `{id}` to fail its `when:`, got {other:?}"),
        };
        assert!(
            message.contains("nosuchfn"),
            "the failure really is the unknown-function path, not a delimiter or parse \
             error at position 0: {message}"
        );
        assert!(
            o.gate_condition_was_secret_derived,
            "a `when:` that failed to evaluate has unknown taint, so `{id}` must record \
             the gate as secret-derived"
        );
        assert!(
            !message.contains("sk-unknown-fn-probe-0007"),
            "the failure message still carries source text only: {message}"
        );
    }
}

// ---- Fix round 5, item 3: what per-substitution rendering stopped covering
// incidentally at the P35 boundary. ----

#[test]
fn a_mis_bound_credential_sharing_a_leaf_with_a_secret_is_no_longer_covered_incidentally() {
    // Payload: `emit: { v: "${{ secrets.T }} and ${{ inputs.cred }}", w: "${{ inputs.cred }}" }`
    // with `secrets.T = "sk-colocated-secret-0009"` and the P35-boundary
    // credential handed in through `inputs` as `INPUTS-CARRIED-CREDENTIAL-0009`.
    //
    // `v` logs `"*** and INPUTS-CARRIED-CREDENTIAL-0009"` — fix round 3's
    // whole-leaf redaction would have logged `"***"` and hidden the mis-bound
    // value as a side effect of the secret happening to share the leaf.
    // `w` shows why that is not a new hole: the same value already logged in
    // cleartext whenever it sat in a leaf of its own, in both rounds, so the
    // set of values that can leak is unchanged.
    let yaml = r#"
name: colocated-boundary
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: a
    emit:
      v: "${{ secrets.T }} and ${{ inputs.cred }}"
      w: "${{ inputs.cred }}"
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(
        serde_json::json!({"cred": "INPUTS-CARRIED-CREDENTIAL-0009"}),
        "T",
        "sk-colocated-secret-0009",
    );
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    exec.run_to_completion().unwrap();

    let created = sink
        .0
        .iter()
        .find(|e| e.payload_json.get("TaskCreated").is_some())
        .unwrap();
    let logged = &created.payload_json["TaskCreated"]["input"]["Json"];
    assert_eq!(
        logged["v"],
        serde_json::json!("*** and INPUTS-CARRIED-CREDENTIAL-0009"),
        "only the secret's own substitution is replaced; the co-located P35-boundary \
         value is not covered, where whole-leaf redaction covered it incidentally"
    );
    assert_eq!(
        logged["w"],
        serde_json::json!("INPUTS-CARRIED-CREDENTIAL-0009"),
        "and it already logged in cleartext in its own leaf under both renderings, which \
         is why the leakable set is unchanged"
    );
}
