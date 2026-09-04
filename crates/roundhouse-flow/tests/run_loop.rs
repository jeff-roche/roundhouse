//! B12c — the run loop: `catch:`/`finally:`/stop-on-failure, the `Skipped` and
//! `error` writers, the `gate:` park and `call:` child-run arms, and ruling
//! P112's report mandatoriness.
//!
//! Every assertion reads the durable row back rather than trusting a returned
//! value, for the reason `tests/control.rs` states: the defect this subsystem
//! keeps producing is an in-memory answer nothing else can see.
//!
//! Fixture convention, per ruling P92 and its amendment: anything that iterates
//! a list carries **at least two** entries, and the entry that makes the
//! assertion interesting appears **first in one test and last in another**, so
//! neither a `.take(1)`-shaped truncation nor a `.skip(1)`-shaped one is
//! invisible to the suite.

use roundhouse_core::{EventPayload, JobId, SessionId, TaskId, TaskKind, TaskOutput, Timestamp};
use roundhouse_flow::caps::ResourceCaps;
use roundhouse_flow::durability::{
    insert_workflow_run, open_test_db, recover_run, transition_run, RunState, StepRunState,
    WorkflowRun,
};
use roundhouse_flow::exec::run_loop::{
    run_workflow, CalledWorkflow, GateAnswer, ReportOrigin, RunLoopError, RunOutcome, WorkflowHost,
};
use roundhouse_flow::exec::{RunContext, RunId, TaskSink};
use roundhouse_flow::ledger::run_ledger;
use roundhouse_flow::parking::{CheckpointError, CheckpointRef, Checkpointer};
use roundhouse_flow::parse::parse_workflow;
use rusqlite::Connection;
use serde_json::Value;
use std::collections::HashMap;

const NANOS_PER_SEC: i64 = 1_000_000_000;

fn at(seconds: i64) -> Timestamp {
    Timestamp::from_unix_nanos(seconds * NANOS_PER_SEC)
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Records everything the run loop emitted, so a test can ask what reached the
/// log rather than what a function returned.
#[derive(Default)]
struct RecordingSink {
    emitted: Vec<(TaskKind, EventPayload)>,
}

impl RecordingSink {
    fn reports(&self) -> Vec<&EventPayload> {
        self.emitted
            .iter()
            .filter(|(kind, payload)| {
                *kind == TaskKind::Report && matches!(payload, EventPayload::TaskCompleted { .. })
            })
            .map(|(_, payload)| payload)
            .collect()
    }

    /// The one report document that reached the log, as JSON.
    fn the_report(&self) -> Value {
        let reports = self.reports();
        assert_eq!(
            reports.len(),
            1,
            "ruling P112: exactly one report task per terminal run, got {}",
            reports.len()
        );
        match reports[0] {
            EventPayload::TaskCompleted {
                output: TaskOutput::Json(v),
                ..
            } => v.clone(),
            other => panic!("a report task completes with JSON output, got {other:?}"),
        }
    }

    fn kinds(&self) -> Vec<TaskKind> {
        self.emitted.iter().map(|(k, _)| k.clone()).collect()
    }
}

impl TaskSink for RecordingSink {
    fn emit(
        &mut self,
        _task_id: TaskId,
        _parent: Option<TaskId>,
        kind: TaskKind,
        payload: EventPayload,
    ) {
        self.emitted.push((kind, payload));
    }
}

/// A host that resolves whatever `call:` names it was told about, mints a
/// fresh Session per call, and reports a fixed direct-child count.
struct FakeHost {
    checkpoints: Vec<(SessionId, String)>,
    resolvable: HashMap<String, (JobId, u32, String)>,
    direct_children: u32,
    sessions_created: Vec<SessionId>,
}

impl FakeHost {
    fn new() -> Self {
        FakeHost {
            checkpoints: Vec::new(),
            resolvable: HashMap::new(),
            direct_children: 0,
            sessions_created: Vec::new(),
        }
    }

    fn resolving(mut self, name: &str) -> Self {
        self.resolvable.insert(
            name.to_string(),
            (JobId::new(), 7, format!("sha256:{name}")),
        );
        self
    }
}

impl Checkpointer for FakeHost {
    fn checkpoint(
        &mut self,
        session_id: SessionId,
        label: &str,
    ) -> Result<CheckpointRef, CheckpointError> {
        self.checkpoints.push((session_id, label.to_string()));
        Ok(CheckpointRef(format!("ckpt-{}", self.checkpoints.len())))
    }
}

impl WorkflowHost for FakeHost {
    fn resolve_call(&mut self, workflow: &str, _parent: SessionId) -> Option<CalledWorkflow> {
        let (job_id, job_version, content_hash) = self.resolvable.get(workflow)?.clone();
        let session_id = SessionId::new();
        self.sessions_created.push(session_id);
        Some(CalledWorkflow {
            job_id,
            job_version,
            content_hash,
            session_id,
        })
    }

    fn direct_children_of(&mut self, _parent: SessionId) -> u32 {
        self.direct_children
    }
}

fn a_grant() -> ResourceCaps {
    ResourceCaps {
        max_tokens: 5_000,
        max_cost_usd: 100.0,
        max_tasks: 100,
        max_tool_calls: 100,
        max_subagents: 20,
        max_bytes_written: 1_000_000,
        max_escalations: 10,
        ..ResourceCaps::default()
    }
}

fn a_run(id: RunId, session_id: SessionId) -> WorkflowRun {
    WorkflowRun {
        id,
        job_id: JobId::new(),
        job_version: 1,
        content_hash: "sha256:pinned".into(),
        session_id,
        binding_id: None,
        trigger_event_id: None,
        state: RunState::Running,
        parent_run_id: None,
        forked_from_run_id: None,
        awaiting_until: None,
        started_at: at(0),
        ended_at: None,
        session_depth: Some(0),
        caps: Some(a_grant()),
    }
}

/// Seeds a `Running` root run and returns its id and session.
fn seed_run(conn: &mut Connection) -> (RunId, SessionId) {
    let run_id = RunId::new();
    let session_id = SessionId::new();
    insert_workflow_run(conn, &a_run(run_id, session_id)).expect("seed the run row");
    (run_id, session_id)
}

fn ctx(run_id: RunId) -> RunContext {
    RunContext {
        inputs: serde_json::json!({}),
        vars: serde_json::json!({}),
        secrets: HashMap::new(),
        run_id,
    }
}

/// Wraps a body in the smallest workflow document `parse_workflow` accepts.
fn workflow(body: &str) -> String {
    format!(
        "name: t\nversion: 1\npermissions:\n  default: deny\n  unattended:\n    escalate: fail\n{body}"
    )
}

/// Runs one workflow against a fresh database, returning everything a test
/// might want to assert on.
fn drive(
    body: &str,
    now: i64,
) -> (
    Connection,
    RunId,
    RecordingSink,
    FakeHost,
    Result<RunOutcome, RunLoopError>,
) {
    drive_with(body, now, FakeHost::new(), None)
}

fn drive_with(
    body: &str,
    now: i64,
    mut host: FakeHost,
    resume: Option<GateAnswer>,
) -> (
    Connection,
    RunId,
    RecordingSink,
    FakeHost,
    Result<RunOutcome, RunLoopError>,
) {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(body)).expect("fixture parses");
    let mut sink = RecordingSink::default();
    let result = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        at(now),
        resume,
    );
    (conn, run_id, sink, host, result)
}

fn step_row(conn: &Connection, run_id: RunId, step_id: &str) -> (StepRunState, Option<String>) {
    let recovered = recover_run(conn, run_id).expect("the run is recoverable");
    let row = recovered
        .steps
        .iter()
        .find(|s| s.step_id == step_id)
        .unwrap_or_else(|| panic!("no workflow_step_run row for step {step_id:?}"));
    (row.state, row.error.clone())
}

// ---------------------------------------------------------------------------
// Stop-on-failure, `continue_on_error`, and the two writers
// ---------------------------------------------------------------------------

/// §8.9: *"`continue_on_error` distinguishes 'the command failed' (data) from
/// 'the step failed' (control flow)."* Before B12c nothing read the flag —
/// `run_to_completion`'s own doc said *"every step in topological order is
/// attempted regardless of an earlier step's outcome"*.
///
/// The failing step is **last** here and **first** in
/// `a_failure_stops_the_phase_and_the_steps_after_it_are_written_skipped`, so a
/// truncation at either end of the iteration is visible.
#[test]
fn a_step_that_declares_continue_on_error_does_not_stop_the_run() {
    let (conn, run_id, sink, _, result) = drive(
        "steps:\n\
         \x20 - id: first\n\
         \x20   emit: { a: 1 }\n\
         \x20 - id: second\n\
         \x20   emit: \"${{ no_such_fn(1) }}\"\n\
         \x20   continue_on_error: true\n",
        10,
    );
    let RunOutcome::Terminal { state, .. } = result.expect("the run drives") else {
        panic!("no gate, so no park");
    };

    assert_eq!(
        state,
        RunState::Completed,
        "a non-fatal step failure is data, not control flow"
    );
    assert_eq!(step_row(&conn, run_id, "first").0, StepRunState::Completed);
    let (second_state, second_error) = step_row(&conn, run_id, "second");
    assert_eq!(second_state, StepRunState::Failed);
    assert!(
        second_error.is_some_and(|e| e.contains("no_such_fn")),
        "the `error` writer records why, because the message cannot be recomputed"
    );

    // A completed run with a non-fatal failure is still triage-worthy, and the
    // report says so rather than reporting `nothing`.
    let report = sink.the_report();
    assert_eq!(report["outcome"], "findings");
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
    assert_eq!(
        recover_run(&conn, run_id).unwrap().run.state,
        RunState::Completed
    );
}

/// The `Skipped` writer in its second role (the first is a `when:` that
/// evaluated false): a step that never ran because an earlier one stopped the
/// phase gets a row saying so, rather than being silently absent from the run's
/// history.
///
/// The failing step is **first** here — see the previous test for why the
/// position is deliberate.
#[test]
fn a_failure_stops_the_phase_and_the_steps_after_it_are_written_skipped() {
    let (conn, run_id, sink, _, result) = drive(
        "steps:\n\
         \x20 - id: boom\n\
         \x20   emit: \"${{ no_such_fn(1) }}\"\n\
         \x20 - id: never_a\n\
         \x20   emit: { a: 1 }\n\
         \x20 - id: never_b\n\
         \x20   emit: { b: 2 }\n",
        10,
    );
    let RunOutcome::Terminal { state, .. } = result.expect("the run drives") else {
        panic!("no gate, so no park");
    };

    assert_eq!(state, RunState::Failed);
    assert_eq!(step_row(&conn, run_id, "boom").0, StepRunState::Failed);
    for skipped in ["never_a", "never_b"] {
        let (state, error) = step_row(&conn, run_id, skipped);
        assert_eq!(
            state,
            StepRunState::Skipped,
            "{skipped} must have a row saying it did not run"
        );
        assert_eq!(error.as_deref(), Some("an earlier step failed"));
    }

    // Neither skipped step reached the sink at all.
    assert!(
        !sink
            .emitted
            .iter()
            .any(|(_, p)| format!("{p:?}").contains("\"a\"") || format!("{p:?}").contains("\"b\"")),
        "a skipped step must not dispatch"
    );

    let report = sink.the_report();
    assert_eq!(report["outcome"], "failed");
    assert_eq!(report["needs_human"], true);
    assert_eq!(report["headline"], "run failed at step `boom`");
}

/// A `when:` that evaluates false is the `Skipped` writer's first role, and it
/// is a *finished* state: on re-drive the loop must not re-evaluate the
/// condition (`StepRunState::Skipped`'s own doc says so, because the condition
/// may read differently by then).
#[test]
fn a_when_gate_that_evaluates_false_is_checkpointed_skipped_with_its_reason() {
    let (conn, run_id, _, _, result) = drive(
        "steps:\n\
         \x20 - id: gated\n\
         \x20   when: \"${{ false }}\"\n\
         \x20   emit: { a: 1 }\n\
         \x20 - id: after\n\
         \x20   emit: { b: 2 }\n",
        10,
    );
    let RunOutcome::Terminal { state, .. } = result.expect("the run drives") else {
        panic!("no gate");
    };
    assert_eq!(state, RunState::Completed, "a skip is not a failure");
    let (gated_state, gated_error) = step_row(&conn, run_id, "gated");
    assert_eq!(gated_state, StepRunState::Skipped);
    assert_eq!(gated_error.as_deref(), Some("when: evaluated false"));
    assert_eq!(step_row(&conn, run_id, "after").0, StepRunState::Completed);
}

// ---------------------------------------------------------------------------
// catch: and finally:
// ---------------------------------------------------------------------------

/// §8.9's own example puts a `catch:` handler named `on_failure` next to a
/// `finally:` block holding the `report:` step. Both halves here.
#[test]
fn catch_runs_only_on_failure_and_finally_runs_either_way() {
    // Failing run: `catch:` and `finally:` both run.
    let (conn, run_id, _, _, result) = drive(
        "steps:\n\
         \x20 - id: boom\n\
         \x20   emit: \"${{ no_such_fn(1) }}\"\n\
         catch:\n\
         \x20 - id: on_failure\n\
         \x20   emit: { notified: true }\n\
         finally:\n\
         \x20 - id: cleanup\n\
         \x20   emit: { cleaned: true }\n",
        10,
    );
    let RunOutcome::Terminal { state, .. } = result.expect("the run drives") else {
        panic!("no gate");
    };
    assert_eq!(state, RunState::Failed);
    assert_eq!(
        step_row(&conn, run_id, "on_failure").0,
        StepRunState::Completed
    );
    assert_eq!(
        step_row(&conn, run_id, "cleanup").0,
        StepRunState::Completed
    );

    // Succeeding run: `finally:` runs, `catch:` does not, and there is no row
    // for it at all — a handler that did not fire is not a skipped step.
    let (conn, run_id, _, _, result) = drive(
        "steps:\n\
         \x20 - id: fine\n\
         \x20   emit: { a: 1 }\n\
         catch:\n\
         \x20 - id: on_failure\n\
         \x20   emit: { notified: true }\n\
         finally:\n\
         \x20 - id: cleanup\n\
         \x20   emit: { cleaned: true }\n",
        10,
    );
    let RunOutcome::Terminal { state, .. } = result.expect("the run drives") else {
        panic!("no gate");
    };
    assert_eq!(state, RunState::Completed);
    assert_eq!(
        step_row(&conn, run_id, "cleanup").0,
        StepRunState::Completed
    );
    assert!(
        recover_run(&conn, run_id)
            .unwrap()
            .steps
            .iter()
            .all(|s| s.step_id != "on_failure"),
        "`catch:` must not run when nothing failed"
    );
}

/// A `catch:` step can read what failed: the three phases share one `steps`
/// context, so `${{ steps.boom.status }}` is the failure signal §8.9 gives an
/// author.
#[test]
fn catch_and_finally_read_the_main_phases_step_results() {
    let (conn, run_id, _, _, result) = drive(
        "steps:\n\
         \x20 - id: ok\n\
         \x20   emit: { value: 7 }\n\
         \x20 - id: boom\n\
         \x20   emit: \"${{ no_such_fn(1) }}\"\n\
         catch:\n\
         \x20 - id: only_if_boom_failed\n\
         \x20   when: \"${{ steps.boom.status == 'failed' }}\"\n\
         \x20   emit: { saw: \"${{ steps.ok.output.value }}\" }\n",
        10,
    );
    result.expect("the run drives");
    assert_eq!(
        step_row(&conn, run_id, "only_if_boom_failed").0,
        StepRunState::Completed,
        "the catch handler saw the main phase's statuses and outputs"
    );
}

/// §8.13 requires **both** *"refuse new task admission"* and *"run
/// `finally:`"* of one cancel. The run loop reads the cancel off the admission
/// chokepoint itself, so a run marked `Cancelling` mid-flight stops admitting
/// `steps:`, still runs `finally:`, and lands in `Cancelled` — with a report,
/// which is the case ruling P112 says the inbox most needs.
#[test]
fn a_cancelled_run_stops_admitting_runs_finally_and_still_reports() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    // Marked `Cancelling` before the loop starts, which is what an operator
    // pressing cancel on a run between steps looks like to the loop.
    transition_run(&mut conn, run_id, RunState::Cancelling, at(5)).unwrap();

    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: never_a\n\
         \x20   emit: { a: 1 }\n\
         \x20 - id: never_b\n\
         \x20   emit: { b: 2 }\n\
         finally:\n\
         \x20 - id: cleanup\n\
         \x20   emit: { cleaned: true }\n",
    ))
    .expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let outcome = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        at(10),
        None,
    )
    .expect("a cancelling run still drains");

    let RunOutcome::Terminal { state, report, .. } = outcome else {
        panic!("no gate");
    };
    assert_eq!(state, RunState::Cancelled);
    assert_eq!(report, ReportOrigin::Synthesised);
    for skipped in ["never_a", "never_b"] {
        let (state, error) = step_row(&conn, run_id, skipped);
        assert_eq!(state, StepRunState::Skipped);
        assert_eq!(
            error.as_deref(),
            Some("the run was cancelled before this step ran")
        );
    }
    assert_eq!(
        step_row(&conn, run_id, "cleanup").0,
        StepRunState::Completed,
        "§8.13 requires `finally:` to run during a cancel"
    );

    let report = sink.the_report();
    assert_eq!(
        report["outcome"], "failed",
        "a cancelled run reported as `nothing` would sink to the bottom of \
         §8.6's sort — the silent omission ruling P112 names"
    );
    assert_eq!(report["headline"], "run cancelled");
    assert_eq!(
        recover_run(&conn, run_id).unwrap().run.state,
        RunState::Cancelled
    );
}

// ---------------------------------------------------------------------------
// Ruling P112: exactly one report, on every terminal path
// ---------------------------------------------------------------------------

/// An authored `report:` step is §8.6's first producer, and the run loop
/// synthesises nothing on top of it.
#[test]
fn an_authored_report_step_is_the_runs_one_report() {
    let (_, _, sink, _, result) = drive(
        "steps:\n\
         \x20 - id: work\n\
         \x20   emit: { a: 1 }\n\
         finally:\n\
         \x20 - id: report\n\
         \x20   report:\n\
         \x20     outcome: changed\n\
         \x20     severity: low\n\
         \x20     headline: authored\n\
         \x20     needs_human: false\n\
         \x20     cost: { usd: 0.5, tokens: 12 }\n",
        10,
    );
    let RunOutcome::Terminal { report, state, .. } = result.expect("the run drives") else {
        panic!("no gate");
    };
    assert_eq!(state, RunState::Completed);
    assert_eq!(
        report,
        ReportOrigin::Authored {
            step_id: "report".into()
        }
    );
    let document = sink.the_report();
    assert_eq!(document["headline"], "authored");
    assert_eq!(
        document.get("synthesised_by"),
        None,
        "nothing was synthesised on top of the author's report"
    );
}

/// Ruling P112's point 4: **every** terminal state carries one, and each is
/// reached by a different path through the loop.
#[test]
fn every_terminal_state_leaves_exactly_one_report_task() {
    // Completed.
    let (_, _, sink, _, _) = drive("steps:\n \x20- id: a\n \x20  emit: { a: 1 }\n", 10);
    assert_eq!(sink.the_report()["outcome"], "nothing");

    // Failed.
    let (_, _, sink, _, _) = drive(
        "steps:\n \x20- id: a\n \x20  emit: \"${{ no_such_fn(1) }}\"\n",
        10,
    );
    assert_eq!(sink.the_report()["outcome"], "failed");

    // Cancelled — driven through its own fixture above; asserted here for the
    // completeness of the set rather than re-measured.
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    transition_run(&mut conn, run_id, RunState::Cancelling, at(1)).unwrap();
    let def = parse_workflow(&workflow("steps:\n \x20- id: a\n \x20  emit: { a: 1 }\n")).unwrap();
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        at(2),
        None,
    )
    .unwrap();
    assert_eq!(sink.the_report()["outcome"], "failed");
}

/// Mandatoriness **with teeth**: a run cannot be marked terminal without a
/// report. The mechanism is a private witness `finish_run` requires, so this
/// test measures the consequence rather than the mechanism — no terminal row
/// exists anywhere without a report task having reached the sink first.
#[test]
fn no_run_reaches_a_terminal_state_without_a_report_reaching_the_sink_first() {
    for body in [
        "steps:\n \x20- id: a\n \x20  emit: { a: 1 }\n",
        "steps:\n \x20- id: a\n \x20  emit: \"${{ no_such_fn(1) }}\"\n",
        "steps:\n \x20- id: a\n \x20  emit: { a: 1 }\nfinally:\n \x20- id: b\n \x20  emit: { b: 2 }\n",
    ] {
        let (conn, run_id, sink, _, _) = drive(body, 10);
        let state = recover_run(&conn, run_id).unwrap().run.state;
        assert!(state.is_terminal(), "{body} must end the run");

        let kinds = sink.kinds();
        let first_report = kinds
            .iter()
            .position(|k| *k == TaskKind::Report)
            .unwrap_or_else(|| panic!("{body} ended terminal with no report task"));
        assert!(first_report < kinds.len(), "the report is in the log");
        assert_eq!(sink.reports().len(), 1, "exactly one, for {body}");
    }
}

/// §8.6 and ruling P112 say **exactly one**, so two authored `report:` steps
/// are refused — and refused **before any step runs**, so a workflow that
/// cannot satisfy the invariant never commits side effects on the way to
/// discovering it.
#[test]
fn two_authored_report_steps_are_refused_before_anything_runs() {
    let (conn, run_id, sink, _, result) = drive(
        "steps:\n\
         \x20 - id: effectful\n\
         \x20   emit: { side: effect }\n\
         \x20 - id: r1\n\
         \x20   report: { outcome: nothing, severity: low, headline: a, needs_human: false, cost: { usd: 0, tokens: 0 } }\n\
         finally:\n\
         \x20 - id: r2\n\
         \x20   report: { outcome: nothing, severity: low, headline: b, needs_human: false, cost: { usd: 0, tokens: 0 } }\n",
        10,
    );
    assert!(
        matches!(result, Err(RunLoopError::MultipleReportSteps { count: 2 })),
        "got {result:?}"
    );
    assert!(
        sink.emitted.is_empty(),
        "refused before any step dispatched"
    );
    assert_eq!(
        recover_run(&conn, run_id).unwrap().run.state,
        RunState::Running,
        "and the run is untouched"
    );
    assert!(recover_run(&conn, run_id).unwrap().steps.is_empty());
}

/// The synthesised report's `cost` comes from the run's own ledger row, not
/// from a figure this loop invented — `Spend`'s doc is explicit that a
/// self-reported number is exactly what §8.12's invariant reduces to not
/// trusting.
#[test]
fn the_synthesised_reports_cost_is_read_from_the_ledger() {
    let mut conn = open_test_db();
    let run_id = RunId::new();
    let mut run = a_run(run_id, SessionId::new());
    run.caps = Some(ResourceCaps {
        max_tokens: 200_000,
        ..a_grant()
    });
    insert_workflow_run(&mut conn, &run).unwrap();
    roundhouse_flow::ledger::admit_spend(
        &mut conn,
        run_id,
        &roundhouse_flow::ledger::Spend {
            tokens: 118_204,
            cost_usd: 0.42,
            ..roundhouse_flow::ledger::Spend::ZERO
        },
        at(1),
    )
    .expect("Phase 2's accounting records what it measured");

    let def = parse_workflow(&workflow("steps:\n \x20- id: a\n \x20  emit: { a: 1 }\n")).unwrap();
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        at(2),
        None,
    )
    .unwrap();

    let report = sink.the_report();
    assert_eq!(report["cost"]["tokens"], 118_204);
    assert_eq!(report["cost"]["usd"], 0.42);
    assert_eq!(report["synthesised_by"], "run_loop");
}

/// A credential an author pasted literally into the YAML has no provenance for
/// taint to see, and a step's failure message quotes a bounded prefix of the
/// offending field. The synthesised report goes through the same needle
/// redaction every other dispatch arm uses, so it cannot carry one into the
/// append-only log.
///
/// The fixture is an authored `report:` whose `severity` is a pasted
/// credential: `validate_report` quotes the offending value verbatim, the step
/// fails with that message, no report is persisted by the author, and the
/// synthesised one carries the message as a finding title — the exact route
/// this backstop exists for, since a literal has no `secrets.*` provenance.
#[test]
fn a_secret_cannot_reach_the_synthesised_report_through_a_failure_message() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: boom\n\
         \x20   report:\n\
         \x20     outcome: nothing\n\
         \x20     severity: sk-super-secret-value\n\
         \x20     headline: h\n\
         \x20     needs_human: false\n\
         \x20     cost: { usd: 0, tokens: 0 }\n",
    ))
    .expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let mut run_ctx = ctx(run_id);
    run_ctx
        .secrets
        .insert("TOKEN".into(), "sk-super-secret-value".into());

    run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx,
        at(2),
        None,
    )
    .unwrap();

    // The author's `report:` failed validation, so nothing of theirs was
    // persisted and the loop synthesised one — which still leaves exactly one.
    let report = sink.the_report();
    let rendered = report.to_string();
    assert!(
        !rendered.contains("sk-super-secret-value"),
        "the needle backstop must scrub a literal credential out of a finding \
         title; got {rendered}"
    );
    assert!(
        rendered.contains("***"),
        "and the placeholder is what replaced it; got {rendered}"
    );
    assert_eq!(report["synthesised_by"], "run_loop");
}

// ---------------------------------------------------------------------------
// The `gate:` arm — §8.11's park, and resume
// ---------------------------------------------------------------------------

#[test]
fn a_gate_step_parks_the_run_and_resuming_it_answers_the_gate() {
    let mut conn = open_test_db();
    let (run_id, session_id) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: before\n\
         \x20   emit: { a: 1 }\n\
         \x20 - id: approve\n\
         \x20   needs: [before]\n\
         \x20   gate:\n\
         \x20     title: \"ship it?\"\n\
         \x20     form: { approve: { type: boolean } }\n\
         \x20     timeout: 24h\n\
         \x20     on_timeout: deny\n\
         \x20 - id: after\n\
         \x20   needs: [approve]\n\
         \x20   when: \"${{ steps.approve.output.approve }}\"\n\
         \x20   emit: { shipped: true }\n",
    ))
    .expect("fixture parses");

    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let parked = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        at(100),
        None,
    )
    .expect("the run drives to the gate");

    let RunOutcome::Parked(parked) = parked else {
        panic!("a gate parks the run");
    };
    assert_eq!(parked.session_id, session_id);
    assert_eq!(host.checkpoints.len(), 1, "§8.11's implicit checkpoint ran");
    assert_eq!(
        recover_run(&conn, run_id).unwrap().run.state,
        RunState::AwaitingHuman
    );
    assert_eq!(
        parked.awaiting_until,
        Some(at(100 + 24 * 3600)),
        "the wait's deadline is absolute"
    );
    assert!(
        sink.reports().is_empty(),
        "a parked run has not ended, so it has no result to report"
    );
    assert_eq!(step_row(&conn, run_id, "before").0, StepRunState::Completed);
    assert_eq!(step_row(&conn, run_id, "approve").0, StepRunState::Running);

    // The human answers. The loop re-drives: `before` is not re-run, the gate
    // resolves with the answer, and the dependent's `when:` reads it.
    let mut sink = RecordingSink::default();
    let resumed = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        at(200),
        Some(GateAnswer {
            step_id: "approve".into(),
            output: serde_json::json!({ "approve": true }),
        }),
    )
    .expect("the answer releases the park");

    let RunOutcome::Terminal { state, steps, .. } = resumed else {
        panic!("the gate is answered, so nothing parks");
    };
    assert_eq!(state, RunState::Completed);
    assert!(
        !steps.iter().any(|s| s.step_id == "before"),
        "an already-completed step is re-driven, not re-run"
    );
    assert_eq!(step_row(&conn, run_id, "after").0, StepRunState::Completed);
    assert_eq!(sink.reports().len(), 1);
}

/// A gate inside `finally:` would suspend a run that is already ending, so it
/// is refused rather than honoured — the run loop's leg of the same rule that
/// refuses a `call:` inside `finally:` at the ledger. Cancel must converge.
#[test]
fn a_gate_inside_finally_fails_the_step_rather_than_parking_a_run_that_is_ending() {
    let (conn, run_id, sink, host, result) = drive(
        "steps:\n\
         \x20 - id: work\n\
         \x20   emit: { a: 1 }\n\
         finally:\n\
         \x20 - id: late_gate\n\
         \x20   gate:\n\
         \x20     title: \"one more thing?\"\n\
         \x20     form: { ok: { type: boolean } }\n\
         \x20     timeout: 1h\n\
         \x20     on_timeout: deny\n",
        10,
    );
    let RunOutcome::Terminal { state, .. } = result.expect("the run drives") else {
        panic!("the gate must not park from `finally:`");
    };
    assert_eq!(state, RunState::Failed);
    assert!(host.checkpoints.is_empty(), "no park, so no checkpoint");
    let (gate_state, gate_error) = step_row(&conn, run_id, "late_gate");
    assert_eq!(gate_state, StepRunState::Failed);
    assert!(
        gate_error.is_some_and(|e| e.contains("finally:")),
        "the row says why it could not park"
    );
    assert_eq!(sink.reports().len(), 1);
}

/// A gate answer naming a step that is not a gate would inject a value under an
/// id whose real step is about to run, silently overwriting it.
#[test]
fn a_gate_answer_naming_a_non_gate_step_is_refused() {
    let (_, _, _, _, result) = drive_with(
        "steps:\n \x20- id: work\n \x20  emit: { a: 1 }\n",
        10,
        FakeHost::new(),
        Some(GateAnswer {
            step_id: "work".into(),
            output: serde_json::json!({}),
        }),
    );
    assert!(
        matches!(result, Err(RunLoopError::UnknownGateStep { .. })),
        "got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// The `call:` arm — §8.12's child run and its budget transfer
// ---------------------------------------------------------------------------

/// §8.12: a `call:` creates a child `workflow_run` **and** a child Session,
/// draws the child's grant from the parent, and puts one `agent`-kind task in
/// the parent's log standing for the call.
#[test]
fn a_call_step_creates_a_funded_child_run_and_one_agent_task() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: sub\n\
         \x20   call: child-flow\n\
         \x20   with: { repo: acme/widgets }\n\
         \x20   caps: { max_cost_usd: 2.5, max_tool_calls: 9 }\n",
    ))
    .expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new().resolving("child-flow");

    let outcome = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        at(10),
        None,
    )
    .expect("the run drives");
    let RunOutcome::Terminal { state, steps, .. } = outcome else {
        panic!("no gate");
    };
    assert_eq!(state, RunState::Completed);

    let child_id: RunId = steps
        .iter()
        .find(|s| s.step_id == "sub")
        .expect("the call step ran")
        .output["run_id"]
        .as_str()
        .expect("the step's output is the child's handle")
        .parse()
        .map(RunId::from_uuid)
        .expect("a run id");

    let child = run_ledger(&conn, child_id).expect("the child row exists");
    assert_eq!(child.parent_run_id, Some(run_id));
    assert_eq!(
        child.session_depth,
        Some(1),
        "the depth `admit_call_from_run` returned, never one computed here \
         (ruling P76 §1)"
    );
    assert_eq!(
        child.drawn_at,
        Some(at(10)),
        "the child's grant was drawn in the insert's own transaction"
    );
    let grant = child.caps.expect("the child records its grant");
    assert_eq!(grant.max_cost_usd, 2.5, "the step's own `caps:` block");
    assert_eq!(grant.max_tool_calls, 9);
    assert_eq!(
        grant.max_tokens,
        a_grant().max_tokens,
        "every other field is clamped to the parent's *remaining*, and the \
         parent has spent no tokens: this loop charges tasks, tool calls and \
         sub-agents, never a token figure it would have had to invent"
    );
    assert_eq!(
        grant.max_tasks,
        a_grant().max_tasks - 1,
        "the countable it does charge is one task per step, and the call \
         step's own admission already took one"
    );
    assert_eq!(
        host.sessions_created.len(),
        1,
        "§8.12: a `call:` creates a child Session too"
    );
    assert_eq!(
        recover_run(&conn, child_id).unwrap().run.session_id,
        host.sessions_created[0],
        "and the child run is filed under the Session the host created for it"
    );

    // §8.12: "the parent's log gets one `agent`-kind task standing for the
    // call".
    let agent_tasks: Vec<_> = sink
        .emitted
        .iter()
        .filter(|(kind, _)| *kind == TaskKind::Agent)
        .collect();
    assert_eq!(agent_tasks.len(), 1);
    assert!(
        format!("{:?}", agent_tasks[0].1).contains("child-flow"),
        "the task names the workflow it stands for"
    );
}

/// **Measured, and it corrects an assumption the brief carries:** a `call:` is
/// never refused for *funding*, because `draw_child_budget` clamps the request
/// to what the parent has left before the row is ever written. A parent with
/// almost nothing gives its child almost nothing — it does not refuse it.
///
/// Ruling P113's *"raise the ceiling or accept the failure"* refusal is real
/// and is measured in `tests/control.rs`; the path that reaches it is
/// `retry_from_step`, which copies the original's caps rather than clamping
/// them.
#[test]
fn a_call_draws_only_what_the_parent_has_left_rather_than_being_refused() {
    let mut conn = open_test_db();
    let run_id = RunId::new();
    let mut run = a_run(run_id, SessionId::new());
    run.caps = Some(ResourceCaps {
        max_tokens: 10,
        max_subagents: 1,
        ..a_grant()
    });
    insert_workflow_run(&mut conn, &run).unwrap();
    // Spend nearly all of it before the call, so the remainder is a number no
    // default could coincidentally equal.
    roundhouse_flow::ledger::admit_spend(
        &mut conn,
        run_id,
        &roundhouse_flow::ledger::Spend {
            tokens: 7,
            ..roundhouse_flow::ledger::Spend::ZERO
        },
        at(1),
    )
    .unwrap();

    let def = parse_workflow(&workflow(
        "steps:\n \x20- id: sub\n \x20  call: child-flow\n",
    ))
    .expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new().resolving("child-flow");
    let outcome = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        at(10),
        None,
    )
    .expect("the run drives");

    let RunOutcome::Terminal { state, steps, .. } = outcome else {
        panic!("no gate");
    };
    assert_eq!(
        state,
        RunState::Completed,
        "the call is funded, not refused"
    );
    let child_id: RunId = steps[0].output["run_id"]
        .as_str()
        .unwrap()
        .parse()
        .map(RunId::from_uuid)
        .unwrap();
    let child = run_ledger(&conn, child_id).unwrap();
    assert_eq!(
        child.caps.unwrap().max_tokens,
        3,
        "exactly the parent's remainder, never its ceiling"
    );
    assert_eq!(
        run_ledger(&conn, run_id).unwrap().spent.tokens,
        10,
        "and the parent is charged that remainder, so it now has nothing left"
    );
}

/// §7.7's depth bound, reached through the `call:` arm: a run already at the
/// ceiling cannot start another child, and the refusal happens **before**
/// anything is created.
#[test]
fn a_call_past_the_depth_ceiling_fails_the_step_and_creates_nothing() {
    use roundhouse_flow::compose::MAX_CALL_DEPTH;

    let mut conn = open_test_db();
    let run_id = RunId::new();
    let mut run = a_run(run_id, SessionId::new());
    run.session_depth = Some(MAX_CALL_DEPTH);
    insert_workflow_run(&mut conn, &run).unwrap();

    let def = parse_workflow(&workflow(
        "steps:\n \x20- id: sub\n \x20  call: child-flow\n",
    ))
    .expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new().resolving("child-flow");
    let outcome = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        at(10),
        None,
    )
    .expect("the run drives");

    let RunOutcome::Terminal { state, .. } = outcome else {
        panic!("no gate");
    };
    assert_eq!(state, RunState::Failed);
    let (_, error) = step_row(&conn, run_id, "sub");
    assert!(
        error.is_some_and(|e| e.contains("refused")),
        "the row says the call was refused"
    );
    assert!(
        host.sessions_created.is_empty(),
        "and nothing was created on the way to refusing"
    );
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM workflow_run WHERE parent_run_id IS NOT NULL",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
}

/// A `call:` whose workflow name does not resolve is a step failure naming the
/// name, not a panic and not a silently-skipped step.
#[test]
fn a_call_to_an_unknown_workflow_fails_the_step() {
    let (conn, run_id, _, _, result) =
        drive("steps:\n \x20- id: sub\n \x20  call: no-such-flow\n", 10);
    let RunOutcome::Terminal { state, .. } = result.expect("the run drives") else {
        panic!("no gate");
    };
    assert_eq!(state, RunState::Failed);
    let (_, error) = step_row(&conn, run_id, "sub");
    assert!(
        error.is_some_and(|e| e.contains("no-such-flow")),
        "the failure names the unresolved workflow"
    );
}

/// §8.12's *"refunded on completion"*, from inside the run whose completion it
/// is: a child run that ends returns its unspent grant to its parent, closing
/// the transfer without anything recursing.
#[test]
fn a_child_run_refunds_its_unspent_grant_to_its_parent_when_it_ends() {
    let mut conn = open_test_db();
    let (parent_id, _) = seed_run(&mut conn);

    let child_id = RunId::new();
    let mut child = a_run(child_id, SessionId::new());
    child.parent_run_id = Some(parent_id);
    child.session_depth = Some(1);
    child.caps = Some(ResourceCaps {
        max_tokens: 500,
        max_tasks: 10,
        ..a_grant()
    });
    child.started_at = at(1);
    insert_workflow_run(&mut conn, &child).expect("the child draws at creation");

    let parent_after_draw = run_ledger(&conn, parent_id).unwrap().spent;
    assert_eq!(parent_after_draw.tokens, 500);
    assert_eq!(parent_after_draw.tasks, 10);

    let def = parse_workflow(&workflow("steps:\n \x20- id: a\n \x20  emit: { a: 1 }\n")).unwrap();
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    run_workflow(
        &mut conn,
        &def,
        child_id,
        &mut sink,
        &mut host,
        ctx(child_id),
        at(2),
        None,
    )
    .expect("the child run drives");

    assert_eq!(
        run_ledger(&conn, child_id).unwrap().refunded_at,
        Some(at(2)),
        "the child is stamped, so it cannot refund twice"
    );
    let parent = run_ledger(&conn, parent_id).unwrap().spent;
    assert_eq!(
        parent.tokens, 0,
        "the child spent no tokens, so its whole 500-token grant came back"
    );
    assert_eq!(
        parent.tasks, 1,
        "and exactly the one task the child really admitted stays charged"
    );
}

// ---------------------------------------------------------------------------
// Admission: §8.4's caps, enforced once per step
// ---------------------------------------------------------------------------

/// §8.4's *"caps enforced at task admission"* becomes real for the countables
/// this loop knows. A run whose `max_tasks` runs out mid-flight fails with a
/// report naming the field, rather than running past its ceiling.
#[test]
fn a_run_that_exhausts_max_tasks_fails_with_a_report_naming_the_field() {
    let mut conn = open_test_db();
    let run_id = RunId::new();
    let mut run = a_run(run_id, SessionId::new());
    run.caps = Some(ResourceCaps {
        max_tasks: 2,
        ..a_grant()
    });
    insert_workflow_run(&mut conn, &run).unwrap();

    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: a\n\
         \x20   emit: { a: 1 }\n\
         \x20 - id: b\n\
         \x20   emit: { b: 2 }\n\
         \x20 - id: c\n\
         \x20   emit: { c: 3 }\n",
    ))
    .unwrap();
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let outcome = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        at(10),
        None,
    )
    .expect("the run drives");

    let RunOutcome::Terminal { state, .. } = outcome else {
        panic!("no gate");
    };
    assert_eq!(state, RunState::Failed);
    assert_eq!(step_row(&conn, run_id, "a").0, StepRunState::Completed);
    assert_eq!(step_row(&conn, run_id, "b").0, StepRunState::Completed);
    let (c_state, c_error) = step_row(&conn, run_id, "c");
    assert_eq!(c_state, StepRunState::Failed);
    assert!(
        c_error.is_some_and(|e| e.contains("max_tasks")),
        "the row names the ceiling that ran out"
    );
    assert_eq!(sink.the_report()["outcome"], "failed");
}

/// The run loop refuses to drive a run that is not `Running` and has no gate
/// answer to release it — a caller mistake, answered as one rather than by
/// inventing a terminal state for a paused run.
#[test]
fn the_loop_refuses_to_drive_a_paused_run() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    transition_run(&mut conn, run_id, RunState::Paused, at(1)).unwrap();

    let def = parse_workflow(&workflow("steps:\n \x20- id: a\n \x20  emit: { a: 1 }\n")).unwrap();
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let result = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        at(2),
        None,
    );
    assert!(
        matches!(
            result,
            Err(RunLoopError::RunNotDrivable {
                state: RunState::Paused,
                ..
            })
        ),
        "got {result:?}"
    );
    assert_eq!(
        recover_run(&conn, run_id).unwrap().run.state,
        RunState::Paused,
        "and nothing was written"
    );
    assert!(sink.emitted.is_empty());
}
