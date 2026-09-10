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
    WorkflowHostError,
};
use roundhouse_flow::exec::{RunContext, RunId, StepStatus, TaskSink};
use roundhouse_flow::expr::EnvAllowlist;
use roundhouse_flow::ledger::run_ledger;
use roundhouse_flow::parking::{CheckpointError, CheckpointRef, Checkpointer};
use roundhouse_flow::parse::parse_workflow;
use roundhouse_flow::report::{Cost, Outcome, Report, Severity};
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
    /// The `TaskId` each entry of `emitted` was emitted under, kept in step
    /// with it. Separate rather than a third tuple element so the many
    /// `format!("{:?}", sink.emitted)` leak assertions keep reading as a list
    /// of what was logged.
    task_ids: Vec<TaskId>,
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

    /// The one report document that reached the log, as JSON — and, on the
    /// way, that it reached the log as a **whole task**.
    ///
    /// §4.2's tasks are event-sourced: a `TaskCompleted` with no matching
    /// `TaskCreated` is an orphan completion in a table that physically
    /// rejects `UPDATE`/`DELETE`, and nothing downstream could say what kind
    /// of task completed or when it began. Asserted here, once, rather than in
    /// each of the dozen tests that call this.
    fn the_report(&self) -> Value {
        let created: Vec<TaskId> = self
            .emitted
            .iter()
            .zip(&self.task_ids)
            .filter(|((kind, payload), _)| {
                *kind == TaskKind::Report && matches!(payload, EventPayload::TaskCreated { .. })
            })
            .map(|(_, id)| *id)
            .collect();
        let completed: Vec<TaskId> = self
            .emitted
            .iter()
            .zip(&self.task_ids)
            .filter(|((kind, payload), _)| {
                *kind == TaskKind::Report && matches!(payload, EventPayload::TaskCompleted { .. })
            })
            .map(|(_, id)| *id)
            .collect();
        assert_eq!(
            created, completed,
            "every report task is created and completed, under one id: \
             created {created:?}, completed {completed:?}"
        );

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
        self.task_ids.push(_task_id);
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
    reservations: Vec<SessionId>,
}

impl FakeHost {
    fn new() -> Self {
        FakeHost {
            checkpoints: Vec::new(),
            resolvable: HashMap::new(),
            direct_children: 0,
            sessions_created: Vec::new(),
            reservations: Vec::new(),
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
        _run_id: RunId,
        label: &str,
    ) -> Result<CheckpointRef, CheckpointError> {
        self.checkpoints.push((session_id, label.to_string()));
        Ok(CheckpointRef(format!("ckpt-{}", self.checkpoints.len())))
    }
}

impl WorkflowHost for FakeHost {
    fn resolve_call(
        &mut self,
        _conn: &Connection,
        workflow: &str,
        _parent: SessionId,
    ) -> Result<Option<CalledWorkflow>, WorkflowHostError> {
        let Some((job_id, job_version, content_hash)) = self.resolvable.get(workflow).cloned()
        else {
            return Ok(None);
        };
        let session_id = SessionId::new();
        Ok(Some(CalledWorkflow {
            job_id,
            job_version,
            content_hash,
            session_id,
        }))
    }

    fn reserve_child_session(
        &mut self,
        _parent: SessionId,
        child: &CalledWorkflow,
    ) -> Result<u32, WorkflowHostError> {
        self.reservations.push(child.session_id);
        Ok(self.direct_children)
    }

    fn release_child_session(&mut self, _parent: SessionId, child: &CalledWorkflow) {
        self.reservations
            .retain(|session_id| *session_id != child.session_id);
    }

    fn create_child_run(
        &mut self,
        conn: &mut Connection,
        _parent: SessionId,
        child: &WorkflowRun,
        called: &CalledWorkflow,
    ) -> Result<(), WorkflowHostError> {
        let txn = roundhouse_store::begin_immediate(conn)?;
        if let Err(error) =
            roundhouse_flow::durability::insert_workflow_run_in_transaction(&txn, child)
        {
            self.release_child_session(_parent, called);
            return Err(error.into());
        }
        if let Err(error) = txn.commit() {
            self.release_child_session(_parent, called);
            return Err(error.into());
        }
        self.reservations
            .retain(|session_id| *session_id != child.session_id);
        self.sessions_created.push(child.session_id);
        Ok(())
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
        checkpoint_ref: None,
        checkpoint_blob_ref: None,
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
        previous_report: None,
        env_allowlist: EnvAllowlist::deny_all(),
        worktree_provider: None,
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

/// Like [`drive`], but with a caller-supplied `RunContext::previous_report` —
/// Task 19a's carry-over seed is only reachable at all when the run context
/// actually carries one, which `ctx()`/`drive()` never populate.
fn drive_with_previous_report(
    body: &str,
    previous_report: Report,
) -> (
    Connection,
    RunId,
    RecordingSink,
    Result<RunOutcome, RunLoopError>,
) {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(body)).expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let mut run_ctx = ctx(run_id);
    run_ctx.previous_report = Some(previous_report);
    let result = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx,
        at(10),
        None,
    );
    (conn, run_id, sink, result)
}

/// Writes a finished `Completed` row for `step_id`, so a re-drive skips it —
/// the state a run that was interrupted (or parked) between passes is in.
fn checkpoint_completed(conn: &mut Connection, run_id: RunId, step_id: &str) {
    roundhouse_flow::durability::checkpoint_step(
        conn,
        &roundhouse_flow::durability::WorkflowStepRun {
            run_id,
            step_id: step_id.to_string(),
            attempt: 1,
            item_index: None,
            disposition: roundhouse_flow::durability::StepDisposition::Pure,
            state: StepRunState::Completed,
            first_task_seq: None,
            last_task_seq: None,
            output: None,
            error: None,
        },
    )
    .expect("checkpoint the finished step");
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
         \x20   emit: { shipped: \"${{ steps.before.output.a }}\" }\n",
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
    assert_eq!(
        steps
            .iter()
            .find(|s| s.step_id == "after")
            .expect("the dependent ran")
            .output["shipped"],
        "1",
        "the dependent read `before`'s output back out of the row the first \
         pass checkpointed — which is what makes a park resumable at all"
    );
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
        a_grant().max_tokens / 2,
        "an undeclared field asks for a bounded *share* of what the parent has \
         left, never the remainder (ruling P116 §A) — the parent has spent no \
         tokens, so half of its whole ceiling"
    );
    assert_eq!(
        grant.max_tasks,
        (a_grant().max_tasks - 1) / 2,
        "and half of the tasks it has left: the call step's own admission \
         already took one of the hundred"
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

#[test]
fn a_failed_child_insert_releases_its_uncommitted_child_reservation() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    conn.execute_batch(
        "CREATE TRIGGER reject_child_workflow_run
         BEFORE INSERT ON workflow_run
         WHEN NEW.parent_run_id IS NOT NULL
         BEGIN
             SELECT RAISE(ABORT, 'test child insert failure');
         END;",
    )
    .expect("install child insert failure");
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: sub\n\
         \x20   call: child-flow\n",
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
    .expect("child insertion failure is a workflow failure");
    let RunOutcome::Terminal { steps, .. } = outcome else {
        panic!("child insertion failure must terminate the parent");
    };
    let StepStatus::Failed { message } = &steps[0].status else {
        panic!("the call step must fail");
    };
    assert!(message.contains("could not be funded"));
    assert_eq!(
        host.sessions_created.len(),
        0,
        "a failed transaction cannot leave a runtime child edge"
    );
    assert!(host.reservations.is_empty());
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
///
/// **This test asserted the defect ruling P116 §A names, as correct.** It used
/// to read *"the parent is charged that remainder, so it now has nothing
/// left"* — which is exactly the starvation that stops `finally:` running. The
/// draw is now a bounded share, so the parent keeps a remainder of its own.
#[test]
fn a_call_draws_a_bounded_share_of_what_the_parent_has_left_and_leaves_it_some() {
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
        1,
        "half of the parent's remaining 3, never its ceiling and never the \
         whole remainder"
    );
    assert_eq!(
        run_ledger(&conn, run_id).unwrap().spent.tokens,
        8,
        "and the parent is charged only that share — 7 spent plus the 1 it \
         granted, so it still has 2 tokens of its own to finish with"
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

// ---------------------------------------------------------------------------
// Mutation-sweep round 2: the shapes no fixture above builds
//
// Ruling P113's carry-forward — *"when several guards survive together, look
// for the single state none of the fixtures construct rather than writing a
// test per guard"* — applies twice here. Twenty-five survivors reduced to four
// shapes: **two failing steps in one run** (S1/S4), **a re-drive with more
// than one finished row and rows of every finished kind** (D2/D4/D5/D6/D7/D8/
// Q4/Q5), **a boundary-exact countable ceiling** (A2/A3/A4), and **a child
// whose grant is clamped in a field the default would not clamp** (C7/C8).
// ---------------------------------------------------------------------------

/// **Two failures in one run**, one non-fatal and one fatal, in that order.
/// Every fixture above had exactly one failing step, so a report that listed
/// only the first finding — or headlined the last failure rather than the
/// first — was indistinguishable from a correct one.
#[test]
fn a_report_lists_every_failure_and_headlines_the_first() {
    let (conn, run_id, sink, _, result) = drive(
        "steps:\n\
         \x20 - id: first_failure\n\
         \x20   emit: \"${{ no_such_fn(1) }}\"\n\
         \x20   continue_on_error: true\n\
         \x20 - id: second_failure\n\
         \x20   needs: [first_failure]\n\
         \x20   emit: \"${{ also_missing(2) }}\"\n",
        10,
    );
    let RunOutcome::Terminal { state, .. } = result.expect("the run drives") else {
        panic!("no gate");
    };
    assert_eq!(state, RunState::Failed, "the second failure is fatal");
    assert_eq!(
        step_row(&conn, run_id, "first_failure").0,
        StepRunState::Failed
    );
    assert_eq!(
        step_row(&conn, run_id, "second_failure").0,
        StepRunState::Failed
    );

    let report = sink.the_report();
    let findings = report["findings"].as_array().expect("findings is an array");
    assert_eq!(
        findings.len(),
        2,
        "every failure is a finding, not just the first or the last: {report}"
    );
    assert_eq!(findings[0]["id"], "first_failure");
    assert_eq!(findings[1]["id"], "second_failure");
    assert_eq!(
        report["headline"], "run failed at step `first_failure`",
        "the headline names the first failure — the one that started the trouble"
    );
}

/// A message this crate builds itself, carrying a literal an author typed into
/// the YAML, reaching the synthesised report. Unlike the `report:`-step fixture
/// above — whose message is built from an *already needle-redacted* value by
/// the `Report` dispatch arm — this text is assembled inside the run loop from
/// raw workflow source, so `synthesise_report`'s own redaction is the only
/// thing standing between it and the append-only log.
#[test]
fn the_synthesised_reports_own_redaction_is_what_scrubs_a_message_it_built_itself() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(
        "steps:\n \x20- id: sub\n \x20  call: sk-pasted-into-the-yaml\n",
    ))
    .expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let mut run_ctx = ctx(run_id);
    run_ctx
        .secrets
        .insert("TOKEN".into(), "sk-pasted-into-the-yaml".into());

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

    let rendered = sink.the_report().to_string();
    assert!(
        !rendered.contains("sk-pasted-into-the-yaml"),
        "the run loop's own \"does not resolve to a job\" message quotes the \
         workflow name verbatim; got {rendered}"
    );
    assert!(rendered.contains("***"), "got {rendered}");
}

/// The synthesised report is validated **before** it is emitted, and the check
/// is not unfalsifiable: a hand-edited `spent_cost_usd` of `+inf` — which
/// migration 0008's `CHECK (spent_cost_usd >= 0)` admits and stores (ruling
/// P108 §B) — serialises as JSON `null`, so `cost.usd` is not a number and the
/// report is refused rather than written permanently into a table that
/// physically rejects `UPDATE`/`DELETE`.
#[test]
fn a_synthesised_report_that_would_not_validate_is_refused_rather_than_emitted() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    // `9e999` is stored as `+inf`: the column CHECK sees `>= 0` and passes it.
    conn.execute(
        "UPDATE workflow_run SET spent_cost_usd = 9e999 WHERE id = ?1",
        [run_id.to_string()],
    )
    .expect("the column CHECK admits +inf");

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
        matches!(result, Err(RunLoopError::SynthesisedReportInvalid(_))),
        "got {result:?}"
    );
    assert!(
        sink.reports().is_empty(),
        "and nothing malformed reached the append-only log"
    );
    assert!(
        !recover_run(&conn, run_id).unwrap().run.state.is_terminal(),
        "nor was the run marked terminal without one"
    );
}

/// **The re-drive shape no fixture built**: a resumed run whose history holds
/// *two* completed rows (one carrying secret-derived output), a `Skipped` row,
/// a `Failed` row, and a `map`-item row. Eight guards survived together
/// because every earlier fixture had exactly one finished row, of one kind,
/// with an output nothing read.
#[test]
fn a_re_drive_honours_every_kind_of_finished_row_and_re_runs_the_rest() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: alpha\n\
         \x20   emit: { a: 1 }\n\
         \x20 - id: beta\n\
         \x20   emit: { b: 2 }\n\
         \x20 - id: gamma\n\
         \x20   emit: { c: 3 }\n\
         \x20 - id: delta\n\
         \x20   emit: { d: 4 }\n\
         \x20 - id: reader\n\
         \x20   needs: [alpha, beta, gamma, delta]\n\
         \x20   emit: { saw: \"${{ steps.beta.output.token }}\", from_alpha: \"${{ steps.alpha.output.a }}\" }\n",
    ))
    .expect("fixture parses");

    let finished = |step_id: &str, state: StepRunState, output: Option<(Value, bool)>| {
        roundhouse_flow::durability::WorkflowStepRun {
            run_id,
            step_id: step_id.to_string(),
            attempt: 1,
            item_index: None,
            disposition: roundhouse_flow::durability::StepDisposition::Pure,
            state,
            first_task_seq: None,
            last_task_seq: None,
            output: output.map(|(value, tainted)| {
                roundhouse_flow::durability::StepOutput::from_outcome(
                    &roundhouse_flow::exec::StepOutcome {
                        step_id: step_id.to_string(),
                        output: value,
                        status: roundhouse_flow::exec::StepStatus::Completed,
                        output_is_secret_derived: tainted,
                        gate_condition_was_secret_derived: false,
                    },
                )
            }),
            error: None,
        }
    };
    // Two completed rows, so a `.take(1)`/`.skip(1)` on the finished map is
    // visible from either end; `beta`'s output is secret-derived.
    roundhouse_flow::durability::checkpoint_step(
        &mut conn,
        &finished(
            "alpha",
            StepRunState::Completed,
            Some((serde_json::json!({"a": 1}), false)),
        ),
    )
    .unwrap();
    roundhouse_flow::durability::checkpoint_step(
        &mut conn,
        &finished(
            "beta",
            StepRunState::Completed,
            Some((
                serde_json::json!({"token": "leaf-parsed-out-of-the-secret"}),
                true,
            )),
        ),
    )
    .unwrap();
    // Finished, but not completed: a skip must stay skipped rather than have
    // its `when:` re-evaluated.
    roundhouse_flow::durability::checkpoint_step(
        &mut conn,
        &finished("gamma", StepRunState::Skipped, None),
    )
    .unwrap();
    // Not finished: a failed step re-runs, because §8.10 tier 2 exists to
    // re-decide those rather than inherit them.
    roundhouse_flow::durability::checkpoint_step(
        &mut conn,
        &finished("delta", StepRunState::Failed, None),
    )
    .unwrap();
    // A `map` item's row, which is not a top-level step's however finished it
    // looks: `reader` must still run.
    let mut item_row = finished(
        "reader",
        StepRunState::Completed,
        Some((serde_json::json!({}), false)),
    );
    item_row.item_index = Some(0);
    roundhouse_flow::durability::checkpoint_step(&mut conn, &item_row).unwrap();

    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let mut run_ctx = ctx(run_id);
    // A declared secret that is **not** the value on the row. `beta`'s stored
    // output is a *derived leaf* — the shape the whole-secret needle backstop
    // structurally cannot match (`redact_known_secrets`'s own doc: it matches
    // whole declared values, nothing else) — so the only thing that can keep
    // it out of the log is the taint flag surviving the restart.
    run_ctx.secrets.insert(
        "TOKEN".into(),
        "{\"leaf\":\"sk-the-whole-declared-secret\"}".into(),
    );
    let outcome = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx,
        at(10),
        None,
    )
    .expect("the run re-drives");

    let RunOutcome::Terminal { state, steps, .. } = outcome else {
        panic!("no gate");
    };
    assert_eq!(state, RunState::Completed);
    let ran: Vec<&str> = steps.iter().map(|s| s.step_id.as_str()).collect();
    assert!(
        !ran.contains(&"alpha"),
        "a completed row is not re-run: {ran:?}"
    );
    assert!(!ran.contains(&"beta"), "nor is the second one: {ran:?}");
    assert!(!ran.contains(&"gamma"), "nor is a skipped one: {ran:?}");
    assert!(ran.contains(&"delta"), "a failed row re-runs: {ran:?}");
    assert!(
        ran.contains(&"reader"),
        "a `map` item's row is not a top-level step's: {ran:?}"
    );
    assert_eq!(
        step_row(&conn, run_id, "gamma").0,
        StepRunState::Skipped,
        "and the skip is still a skip"
    );

    // The dependent read both completed outputs back out of the rows, and the
    // taint on `beta`'s survived the restart rather than being re-derived.
    let reader = steps
        .iter()
        .find(|s| s.step_id == "reader")
        .expect("the reader ran");
    assert_eq!(
        reader.output["from_alpha"], "1",
        "a re-driven output is readable"
    );
    assert_eq!(reader.output["saw"], "leaf-parsed-out-of-the-secret");
    let logged = format!("{:?}", sink.emitted);
    assert!(
        !logged.contains("leaf-parsed-out-of-the-secret"),
        "taint recorded on the row must survive the restart, or a value the \
         first pass redacted reaches the log in cleartext on the second — and \
         the needle backstop cannot help, because a derived leaf is not a \
         declared secret: {logged}"
    );
}

/// Taint across a step boundary **within one run**: the run loop keeps its own
/// `secret_derived_steps` fold, so `steps.<id>.output` read by a later step is
/// tainted even though it was never itself a `secrets.*` lookup (ruling P33's
/// property, at this loop's own boundary rather than `run_to_completion`'s).
///
/// Two tainted steps, with the leaf under test relayed from the **first** —
/// `two_secret_derived_steps_are_both_marked_so_neither_end_of_the_projection_can_be_dropped`
/// relays it from the last. Before this round both taint tests had exactly one
/// tainted step, so the projection in `Loop::bind_steps_context` had no
/// cardinality any fixture could hold it to (ruling P116 §D).
#[test]
fn taint_crosses_a_step_boundary_inside_the_run_loop_too() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    // `source` emits a **field of** a JSON secret, not the secret itself, so
    // what crosses the boundary is a derived leaf the whole-secret needle
    // backstop structurally cannot match (`redact_known_secrets`'s own doc:
    // it matches whole declared values and nothing else). Only the taint fold
    // can keep it out of the log, which is what makes this test measure the
    // fold rather than the backstop.
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: source\n\
         \x20   emit: { body: \"${{ json(secrets.TOKEN).inner }}\" }\n\
         \x20 - id: other_source\n\
         \x20   emit: { body: \"${{ json(secrets.TOKEN).other }}\" }\n\
         \x20 - id: sink_step\n\
         \x20   needs: [source, other_source]\n\
         \x20   emit: { relayed: \"${{ steps.source.output.body }}\" }\n",
    ))
    .expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let mut run_ctx = ctx(run_id);
    run_ctx.secrets.insert(
        "TOKEN".into(),
        "{\"inner\":\"derived-leaf-not-a-needle\",\"other\":\"other-derived-leaf\"}".into(),
    );

    let outcome = run_workflow(
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

    // The relay must actually have happened, or "the leaf is not in the log"
    // is true for the uninteresting reason.
    let RunOutcome::Terminal { state, steps, .. } = outcome else {
        panic!("no gate")
    };
    assert_eq!(state, RunState::Completed, "both steps ran: {steps:?}");
    assert_eq!(
        steps
            .iter()
            .find(|s| s.step_id == "sink_step")
            .expect("the relay ran")
            .output["relayed"],
        "derived-leaf-not-a-needle",
        "and it really did relay the leaf, unredacted, for dispatch"
    );

    let logged = format!("{:?}", sink.emitted);
    for leaf in ["derived-leaf-not-a-needle", "other-derived-leaf"] {
        assert!(
            !logged.contains(leaf),
            "a derived leaf must not reach the log in cleartext: {leaf} in {logged}"
        );
    }
}

/// A step's crash disposition is derived from its real kind, not stamped a
/// constant — §8.10 tier 2 reclassifies an `Effectful` step found `Running`
/// after a crash, and every step reading `Pure` would silently re-run
/// side effects.
#[test]
fn each_steps_row_records_the_disposition_its_kind_derives() {
    let (conn, run_id, _, _, _) = drive(
        "steps:\n\
         \x20 - id: safe\n\
         \x20   tool: read\n\
         \x20   with: { path: x }\n\
         \x20 - id: risky\n\
         \x20   tool: shell\n\
         \x20   with: { cmd: [ls] }\n",
        10,
    );
    let recovered = recover_run(&conn, run_id).unwrap();
    let by_id = |id: &str| {
        recovered
            .steps
            .iter()
            .find(|s| s.step_id == id)
            .unwrap()
            .disposition
    };
    assert_eq!(
        by_id("safe"),
        roundhouse_flow::durability::StepDisposition::Pure
    );
    assert_eq!(
        by_id("risky"),
        roundhouse_flow::durability::StepDisposition::Effectful
    );
}

/// **A boundary-exact countable ceiling**, which is the only fixture shape
/// that can tell "charged one" from "charged none" or "charged always". Every
/// earlier fixture had a ceiling roomy enough that any of the three passed.
#[test]
fn the_per_step_charge_is_one_tool_call_for_a_tool_step_and_none_for_the_rest() {
    // A ceiling of zero tool calls: two `emit:` steps must both run, because
    // neither is a `tool:` step.
    let mut conn = open_test_db();
    let run_id = RunId::new();
    let mut run = a_run(run_id, SessionId::new());
    run.caps = Some(ResourceCaps {
        max_tool_calls: 0,
        ..a_grant()
    });
    insert_workflow_run(&mut conn, &run).unwrap();
    let def = parse_workflow(&workflow(
        "steps:\n \x20- id: a\n \x20  emit: { a: 1 }\n \x20- id: b\n \x20  emit: { b: 2 }\n",
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
    .unwrap();
    let RunOutcome::Terminal { state, .. } = outcome else {
        panic!("no gate")
    };
    assert_eq!(
        state,
        RunState::Completed,
        "a non-tool step must not be charged a tool call"
    );

    // A ceiling of exactly one: the first `tool:` step fits and the second
    // does not.
    let mut conn = open_test_db();
    let run_id = RunId::new();
    let mut run = a_run(run_id, SessionId::new());
    run.caps = Some(ResourceCaps {
        max_tool_calls: 1,
        ..a_grant()
    });
    insert_workflow_run(&mut conn, &run).unwrap();
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: a\n\
         \x20   tool: read\n\
         \x20   with: { path: x }\n\
         \x20 - id: b\n\
         \x20   needs: [a]\n\
         \x20   tool: read\n\
         \x20   with: { path: y }\n",
    ))
    .unwrap();
    let mut sink = RecordingSink::default();
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
    .unwrap();
    let RunOutcome::Terminal { state, .. } = outcome else {
        panic!("no gate")
    };
    assert_eq!(state, RunState::Failed);
    assert_eq!(step_row(&conn, run_id, "a").0, StepRunState::Completed);
    let (_, error) = step_row(&conn, run_id, "b");
    assert!(
        error.is_some_and(|e| e.contains("max_tool_calls")),
        "a tool step is charged exactly one tool call"
    );
}

/// The same shape for §7.7's sub-agent countable: a `call:` is a sub-agent
/// spawn by §8.12's own description, so a run with none left cannot make one.
#[test]
fn a_call_is_charged_a_subagent_so_a_run_with_none_left_cannot_make_one() {
    let mut conn = open_test_db();
    let run_id = RunId::new();
    let mut run = a_run(run_id, SessionId::new());
    run.caps = Some(ResourceCaps {
        max_subagents: 0,
        ..a_grant()
    });
    insert_workflow_run(&mut conn, &run).unwrap();

    let def = parse_workflow(&workflow(
        "steps:\n \x20- id: sub\n \x20  call: child-flow\n",
    ))
    .unwrap();
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
    .unwrap();
    let RunOutcome::Terminal { state, .. } = outcome else {
        panic!("no gate")
    };
    assert_eq!(state, RunState::Failed);
    let (_, error) = step_row(&conn, run_id, "sub");
    assert!(
        error.is_some_and(|e| e.contains("max_subagents")),
        "a `call:` must be charged a sub-agent"
    );
    assert!(
        host.sessions_created.is_empty(),
        "and nothing is created for a call admission refused"
    );
}

/// **A child grant clamped in a field the default would not clamp.** Every
/// earlier `call:` fixture had a parent whose remaining ceiling was *below*
/// `ResourceCaps::default()` in every field a test asserted, so asking for the
/// default and asking for the remainder produced the same clamped answer.
/// `max_cost_usd` is the discriminator: the fixture parent grants $100, the
/// default is $10.
///
/// Two runs, not two steps of one: the first child draws the parent's whole
/// remainder, so a second `call:` in the same run is refused by its own
/// sub-agent admission before it can measure anything.
#[test]
fn a_childs_grant_is_a_bounded_share_clamped_and_not_a_default() {
    fn child_grant_for(body: &str) -> ResourceCaps {
        let mut conn = open_test_db();
        let (run_id, _) = seed_run(&mut conn);
        let def = parse_workflow(&workflow(body)).expect("fixture parses");
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
            panic!("no gate")
        };
        assert_eq!(state, RunState::Completed, "the call is funded");
        let id: RunId = steps[0].output["run_id"]
            .as_str()
            .expect("the call step's output is the child's handle")
            .parse()
            .map(RunId::from_uuid)
            .unwrap();
        run_ledger(&conn, id).unwrap().caps.unwrap()
    }

    assert_eq!(
        child_grant_for("steps:\n \x20- id: sub\n \x20  call: child-flow\n").max_cost_usd,
        50.0,
        "with no `caps:` block the child asks for a bounded share of the \
         parent's remainder — half of $100, not the whole $100 and not \
         `ResourceCaps::default()`'s $10"
    );
    assert_eq!(
        child_grant_for(
            "steps:\n \x20- id: sub\n \x20  call: child-flow\n \x20  caps: { max_cost_usd: 500.0 }\n"
        )
        .max_cost_usd,
        100.0,
        "and a step asking for $500 is clamped to the $100 its parent has — \
         never granted the figure it asked for"
    );
}

/// A `call:`'s `with:` block reaches the parent's log through the same needle
/// backstop every other dispatch arm uses, so a credential typed literally
/// into the YAML — which no provenance can see — cannot ride along.
#[test]
fn a_calls_with_block_is_needle_redacted_on_its_way_into_the_parents_log() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: sub\n\
         \x20   call: child-flow\n\
         \x20   with: { token: sk-typed-straight-in }\n",
    ))
    .expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new().resolving("child-flow");
    let mut run_ctx = ctx(run_id);
    run_ctx
        .secrets
        .insert("TOKEN".into(), "sk-typed-straight-in".into());
    run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx,
        at(10),
        None,
    )
    .unwrap();

    let logged = format!("{:?}", sink.emitted);
    assert!(!logged.contains("sk-typed-straight-in"), "got {logged}");
    assert!(logged.contains("***"), "got {logged}");
}

/// A gate answer names one gate, not whichever gate the loop reaches first.
/// With two gates in one run, an answer for the second must not release the
/// first.
#[test]
fn a_gate_answer_releases_only_the_gate_it_names() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: first_gate\n\
         \x20   gate:\n\
         \x20     title: \"first?\"\n\
         \x20     form: { ok: { type: boolean } }\n\
         \x20     timeout: 1h\n\
         \x20     on_timeout: deny\n\
         \x20 - id: second_gate\n\
         \x20   needs: [first_gate]\n\
         \x20   gate:\n\
         \x20     title: \"second?\"\n\
         \x20     form: { ok: { type: boolean } }\n\
         \x20     timeout: 1h\n\
         \x20     on_timeout: deny\n",
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
        Some(GateAnswer {
            step_id: "second_gate".into(),
            output: serde_json::json!({ "ok": true }),
        }),
    )
    .expect("the run drives");

    assert!(
        matches!(outcome, RunOutcome::Parked(_)),
        "the first gate has no answer, so it parks: {outcome:?}"
    );
    assert_eq!(
        step_row(&conn, run_id, "first_gate").0,
        StepRunState::Running,
        "and it is the first gate that is waiting, not the second"
    );
}

/// §8.11's *"an `AwaitingHuman` task with a JSON-Schema form that TUI and web
/// render from the same schema"*: the park puts the form in the log, or nobody
/// is ever asked. The gate's `title:` is interpolated workflow source, so it
/// goes through the same needle backstop as every other value this crate logs.
#[test]
fn a_park_puts_the_redacted_form_in_the_log_so_a_human_can_be_asked() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: approve\n\
         \x20   gate:\n\
         \x20     title: \"ship sk-in-the-prompt-text?\"\n\
         \x20     form: { approve: { type: boolean } }\n\
         \x20     timeout: 1h\n\
         \x20     on_timeout: deny\n",
    ))
    .expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let mut run_ctx = ctx(run_id);
    run_ctx
        .secrets
        .insert("TOKEN".into(), "sk-in-the-prompt-text".into());
    let outcome = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx,
        at(10),
        None,
    )
    .expect("the run parks");
    assert!(matches!(outcome, RunOutcome::Parked(_)));

    let logged = format!("{:?}", sink.emitted);
    assert!(
        logged.contains("awaiting_human"),
        "the form must reach the log, or the human has nothing to answer: {logged}"
    );
    assert!(
        logged.contains("approve"),
        "and it must carry the form's own fields: {logged}"
    );
    assert!(
        !logged.contains("sk-in-the-prompt-text"),
        "a credential pasted into the gate's title must not ride along: {logged}"
    );
    assert!(logged.contains("***"), "got {logged}");
}

/// The door check is not redundant with admission. A run with nothing to
/// admit — no `steps:`, no `finally:` — would otherwise be driven straight to
/// a terminal state, emitting a report for a run an operator had paused.
#[test]
fn a_paused_run_with_nothing_to_admit_is_still_refused_at_the_door() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    roundhouse_flow::control::pause(&mut conn, run_id, at(1)).unwrap();

    let def = parse_workflow(&workflow("steps: []\n")).expect("an empty step list parses");
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
    assert!(
        sink.emitted.is_empty(),
        "no report is written for a run the operator paused"
    );
    assert_eq!(
        recover_run(&conn, run_id).unwrap().run.state,
        RunState::Paused
    );
}

/// `draw_child_run`'s `AlreadySettled` guard, reached from the one shape the
/// invariant makes rare: a child that has already been refunded. Nothing else
/// in the suite constructs a settled run and then asks to draw for it.
#[test]
fn a_settled_child_cannot_be_drawn_for_again() {
    use roundhouse_flow::ledger::{draw_child_run, refund_child_run, LedgerError};

    let mut conn = open_test_db();
    let (parent, _) = seed_run(&mut conn);
    let child_id = RunId::new();
    let mut child = a_run(child_id, SessionId::new());
    child.parent_run_id = Some(parent);
    child.session_depth = Some(1);
    child.caps = Some(ResourceCaps {
        max_tokens: 100,
        ..a_grant()
    });
    child.started_at = at(1);
    insert_workflow_run(&mut conn, &child).expect("the insert draws");
    transition_run(&mut conn, child_id, RunState::Completed, at(2)).unwrap();
    refund_child_run(&mut conn, child_id, at(3)).expect("the draw refunds once");

    let spent_after_refund = run_ledger(&conn, parent).unwrap().spent;
    // Clear the draw stamp so `AlreadyDrawn` cannot be the guard that fires:
    // what is under test is that a **settled** run is refused.
    conn.execute(
        "UPDATE workflow_run SET drawn_at = NULL WHERE id = ?1",
        [child_id.to_string()],
    )
    .unwrap();

    let refused = draw_child_run(&mut conn, child_id, at(4));
    assert!(
        matches!(refused, Err(LedgerError::AlreadySettled { .. })),
        "drawing for a settled run would charge the parent a grant the refund \
         can never give back; got {refused:?}"
    );
    assert_eq!(
        run_ledger(&conn, parent).unwrap().spent,
        spent_after_refund,
        "and the refusal charges nothing on its way to refusing"
    );
}

/// A secret too short for this crate to use as a redaction needle refuses the
/// **run**, by name. Before B12c it was reported as a report-validation
/// failure, which tells an operator nothing about the credential that is
/// actually the problem.
#[test]
fn a_secret_too_short_to_redact_refuses_the_run_and_says_so() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow("steps:\n \x20- id: a\n \x20  emit: { a: 1 }\n")).unwrap();
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let mut run_ctx = ctx(run_id);
    run_ctx.secrets.insert("TINY".into(), "abc".into());

    let result = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx,
        at(2),
        None,
    );
    let Err(RunLoopError::Executor(e)) = result else {
        panic!("a short secret must refuse the run, got {result:?}");
    };
    let rendered = e.to_string();
    assert!(rendered.contains("TINY"), "it names the secret: {rendered}");
    assert!(!rendered.contains("abc"), "and never its value: {rendered}");
    assert!(sink.emitted.is_empty(), "nothing ran");
    assert_eq!(
        recover_run(&conn, run_id).unwrap().run.state,
        RunState::Running,
        "and the run is untouched"
    );
}

// ---------------------------------------------------------------------------
// B12c fix round — ruling P116 §A/§B/§D and ruling P117 §A/§B/§C
// ---------------------------------------------------------------------------

/// **The Critical (ruling P117 §A): a cancel is invisible to the terminal-state
/// computation after the last admission.**
///
/// `run_phase` observes a cancel only at `admit`, and `admit` runs only for
/// steps not already checkpointed. This fixture is that window made
/// deterministic: every `steps:` row is already `Completed`, so nothing admits
/// at all, and `finally:` admits through the §8.13 exemption that
/// deliberately does *not* refuse a `Cancelling` run. The loop therefore saw
/// no cancel anywhere.
///
/// Before the fix this returned `Err("run ... cannot move from Cancelling to
/// Completed")` with the row left `Cancelling` and `ended_at` NULL — and since
/// `finish_run` is the only writer of `Cancelled`/`Failed` in the workspace,
/// **nothing could ever move that row again**, while every retry committed
/// another report into an append-only table.
#[test]
fn a_cancel_after_the_last_admission_still_reaches_a_terminal_state() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: alpha\n\
         \x20   emit: { a: 1 }\n\
         \x20 - id: beta\n\
         \x20   emit: { b: 2 }\n\
         finally:\n\
         \x20 - id: cleanup\n\
         \x20   emit: { cleaned: true }\n",
    ))
    .expect("fixture parses");
    // Two finished rows, so the "nothing admits" condition is reached from a
    // real history rather than an empty workflow.
    for step_id in ["alpha", "beta"] {
        checkpoint_completed(&mut conn, run_id, step_id);
    }
    transition_run(&mut conn, run_id, RunState::Cancelling, at(5)).unwrap();

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
    .expect("a `Cancelling` run must be drivable to a terminal state");

    let RunOutcome::Terminal { state, .. } = outcome else {
        panic!("no gate");
    };
    assert_eq!(
        state,
        RunState::Cancelled,
        "the durable row is the second observer of a cancel, and it is \
         consulted before the terminal state is computed"
    );
    let row = recover_run(&conn, run_id).unwrap().run;
    assert_eq!(row.state, RunState::Cancelled);
    assert!(
        row.ended_at.is_some(),
        "`ended_at` is stamped, so the run does not look live forever"
    );
    assert_eq!(
        step_row(&conn, run_id, "cleanup").0,
        StepRunState::Completed,
        "§8.13's `finally:` still ran — the exemption is why the cancel was \
         invisible in the first place, and it is not what is being changed"
    );

    let report = sink.the_report();
    assert_eq!(
        report["headline"], "run cancelled",
        "and the report the operator reads says what happened, not \
         `run completed: 0 steps`"
    );
    assert_eq!(report["outcome"], "failed");
    assert_eq!(
        report["run_state"], "cancelled",
        "ruling P117 §C: the report carries the run's real terminal state"
    );
}

/// The durable consequence ruling P117 §A names second: **a cancelled child
/// leaks its parent's grant permanently.**
///
/// `refund_child_run` correctly refuses a non-terminal child, so a child that
/// could never reach a terminal state could never return what it drew —
/// §8.12's *"refunded on completion"* defeated by the very action meant to end
/// the run.
///
/// The child here has **nothing** left to admit (an empty `steps:` and no
/// `finally:`), which is ruling P116 §C's variant of the same window: `admit`
/// never runs at all, so the cancel has no in-memory observer whatsoever.
#[test]
fn a_child_cancelled_with_nothing_left_to_admit_refunds_rather_than_leaking_its_grant() {
    let mut conn = open_test_db();
    let (parent_id, _) = seed_run(&mut conn);

    let child_id = RunId::new();
    let mut child = a_run(child_id, SessionId::new());
    child.parent_run_id = Some(parent_id);
    child.session_depth = Some(1);
    child.caps = Some(ResourceCaps {
        max_tokens: 400,
        ..a_grant()
    });
    insert_workflow_run(&mut conn, &child).expect("the child draws its grant at insert");
    assert_eq!(
        run_ledger(&conn, parent_id).unwrap().spent.tokens,
        400,
        "the parent was charged the child's whole grant up front"
    );

    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: alpha\n\
         \x20   emit: { a: 1 }\n\
         \x20 - id: beta\n\
         \x20   emit: { b: 2 }\n",
    ))
    .expect("fixture parses");
    for step_id in ["alpha", "beta"] {
        checkpoint_completed(&mut conn, child_id, step_id);
    }
    transition_run(&mut conn, child_id, RunState::Cancelling, at(5)).unwrap();

    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let outcome = run_workflow(
        &mut conn,
        &def,
        child_id,
        &mut sink,
        &mut host,
        ctx(child_id),
        at(10),
        None,
    )
    .expect("the cancelled child reaches a terminal state");
    let RunOutcome::Terminal { state, .. } = outcome else {
        panic!("no gate");
    };
    assert_eq!(state, RunState::Cancelled);
    assert_eq!(
        recover_run(&conn, child_id).unwrap().run.state,
        RunState::Cancelled
    );
    assert_eq!(
        run_ledger(&conn, parent_id).unwrap().spent.tokens,
        0,
        "and the whole unspent grant went back to the parent, rather than \
         being stranded on a child that could never end"
    );
    assert!(run_ledger(&conn, child_id).unwrap().refunded_at.is_some());
    assert_eq!(
        sink.the_report()["run_state"],
        "cancelled",
        "one report, and it says what the row says"
    );
}

/// **Ruling P116 §B / P117 §B: an authored report must survive a re-drive, and
/// the sink must be the one production has.**
///
/// Every other test in this file builds a fresh `RecordingSink` per
/// `run_workflow` call; the real sink is per **session**, so a second report
/// emitted on a second pass was invisible to the whole suite. This test
/// accumulates one sink across both passes, which is the only shape that can
/// see it.
///
/// Reachable with no crash at all: an authored `report:` ordered before a
/// `gate:`, which the author chooses and stable-Kahn file order permits.
#[test]
fn one_sink_across_two_passes_sees_exactly_one_report_and_it_is_the_authored_one() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: report\n\
         \x20   report:\n\
         \x20     outcome: findings\n\
         \x20     severity: high\n\
         \x20     headline: the author found something\n\
         \x20     needs_human: true\n\
         \x20     cost: { usd: 0.5, tokens: 12 }\n\
         \x20 - id: approve\n\
         \x20   needs: [report]\n\
         \x20   gate:\n\
         \x20     title: \"ok?\"\n\
         \x20     form: { approve: { type: boolean } }\n\
         \x20     timeout: 1h\n\
         \x20     on_timeout: deny\n",
    ))
    .expect("fixture parses");

    // One sink, for both passes — this is the fixture, not an incidental
    // detail.
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();

    let first = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        at(10),
        None,
    )
    .expect("pass one drives");
    assert!(
        matches!(first, RunOutcome::Parked(_)),
        "the gate parks the run after the report step has completed"
    );
    assert_eq!(
        sink.reports().len(),
        0,
        "a parked run is not terminal, so it carries no report at all \
         (`RunOutcome::Parked`'s own doc)"
    );

    let second = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        at(20),
        Some(GateAnswer {
            step_id: "approve".into(),
            output: serde_json::json!({ "approve": true }),
        }),
    )
    .expect("pass two drives");
    let RunOutcome::Terminal { report, state, .. } = second else {
        panic!("the gate was answered, so the run ends");
    };
    assert_eq!(state, RunState::Completed);
    assert_eq!(
        report,
        ReportOrigin::Authored {
            step_id: "report".into()
        },
        "the report step is in `finished_before` on this pass, and the loop \
         still knows the author wrote one"
    );

    // The assertion the fresh-sink-per-call convention could not make.
    let document = sink.the_report();
    assert_eq!(document["headline"], "the author found something");
    assert_eq!(document["needs_human"], true);
    assert_eq!(document["severity"], "high");
    assert_eq!(
        document.get("synthesised_by"),
        None,
        "a synthesised companion would be generic by construction — \
         `outcome: nothing`, `severity: low`, `needs_human: false` — and would \
         sort this run to the BOTTOM of §8.6's order. That is ruling P112's \
         failure reached by ADDING a report, not by omitting one."
    );
}

/// **Ruling P117 §C: the report carries the run's real terminal state.**
///
/// An authored `report:` that completed before a later step failed leaves the
/// inbox a document reading `outcome: changed, needs_human: false` for a
/// `Failed` run — and §8.6's `(needs_human, severity, outcome != nothing)`
/// sort then buries exactly the run ruling P112 exists to surface.
///
/// The author's core judgement is left alone; the loop's fact goes on the
/// extension half.
#[test]
fn an_authored_report_carries_the_terminal_state_of_a_run_that_failed_after_it() {
    let (conn, run_id, sink, _, result) = drive(
        "steps:\n\
         \x20 - id: report\n\
         \x20   report:\n\
         \x20     outcome: changed\n\
         \x20     severity: low\n\
         \x20     headline: all good so far\n\
         \x20     needs_human: false\n\
         \x20     cost: { usd: 0.5, tokens: 12 }\n\
         \x20 - id: boom\n\
         \x20   needs: [report]\n\
         \x20   emit: \"${{ no_such_fn(1) }}\"\n",
        10,
    );
    let RunOutcome::Terminal { state, report, .. } = result.expect("the run drives") else {
        panic!("no gate");
    };
    assert_eq!(state, RunState::Failed);
    assert_eq!(
        report,
        ReportOrigin::Authored {
            step_id: "report".into()
        },
        "the author's report is still the run's one report — an authored \
         `report:` outside `finally:` is not refused"
    );
    assert_eq!(
        recover_run(&conn, run_id).unwrap().run.state,
        RunState::Failed
    );

    let document = sink.the_report();
    assert_eq!(
        document["run_state"], "failed",
        "the one fact a reader cannot recover from the author's core half"
    );
    assert_eq!(
        document["outcome"], "changed",
        "and the author's own judgement is left exactly as written — the \
         annotation is additive, not a rewrite"
    );
    assert_eq!(document["needs_human"], false);
}

/// A `report:` nested inside a `map` would emit one `TaskKind::Report` task
/// **per item**, and `run_workflow`'s §8.6 "exactly one" pre-check
/// structurally cannot see it: it flattens the three phase lists only.
///
/// `gate:` and `call:` already carry this refusal; a report is a property of
/// the run in exactly the same way, which is the argument already written for
/// those two. Two items, and `on_item_error: continue`, so a refusal that
/// fired for only one of them would be visible.
#[test]
fn a_report_step_inside_a_map_is_refused_rather_than_emitting_one_per_item() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: fan\n\
         \x20   map:\n\
         \x20     over: \"${{ inputs.items }}\"\n\
         \x20     as: item\n\
         \x20     on_item_error: continue\n\
         \x20   steps:\n\
         \x20     - id: per_item_report\n\
         \x20       report:\n\
         \x20         outcome: changed\n\
         \x20         severity: low\n\
         \x20         headline: \"per item\"\n\
         \x20         needs_human: false\n\
         \x20         cost: { usd: 0.0, tokens: 0 }\n",
    ))
    .expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let mut run_ctx = ctx(run_id);
    run_ctx.inputs = serde_json::json!({ "items": ["one", "two"] });

    let outcome = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx,
        at(10),
        None,
    )
    .expect("the run drives");
    let RunOutcome::Terminal { steps, .. } = outcome else {
        panic!("no gate");
    };

    let items = steps
        .iter()
        .find(|s| s.step_id == "fan")
        .expect("the map ran")
        .output["items"]
        .as_array()
        .expect("one entry per item")
        .clone();
    assert_eq!(items.len(), 2);
    for item in &items {
        assert_eq!(item["status"], "failed");
        assert!(
            item["error"]
                .as_str()
                .is_some_and(|e| e.contains("cannot run inside a `map`")),
            "every item is refused, not just the first: {item:?}"
        );
    }

    // The invariant the refusal defends: still exactly one report task, and it
    // is the run's, not an item's.
    assert_eq!(sink.reports().len(), 1);
    assert_eq!(
        sink.the_report()["synthesised_by"],
        "run_loop",
        "no `report:` step ran, so the run's one report is the synthesised one"
    );
}

/// **The fixture ruling P116 §A says no test in this file built: a step after a
/// `call:`.**
///
/// With every child drawing its grant at insert (rulings P113/P114) and
/// `Spend::for_grant` charging the parent the whole grant, an uncapped `call:`
/// that asked for the parent's *remainder* took everything — and every step
/// after it, `finally:` included, was refused `CapsExceeded`. §8.13's
/// *"`finally:` runs"* defeated by the budget route the admission exemption
/// does not cover.
#[test]
fn a_step_after_a_call_still_runs_and_so_does_finally() {
    let (conn, run_id, sink, _, result) = drive_with(
        "steps:\n\
         \x20 - id: sub\n\
         \x20   call: child-flow\n\
         \x20 - id: after\n\
         \x20   needs: [sub]\n\
         \x20   emit: { ran: true }\n\
         finally:\n\
         \x20 - id: cleanup\n\
         \x20   emit: { cleaned: true }\n",
        10,
        FakeHost::new().resolving("child-flow"),
        None,
    );
    let RunOutcome::Terminal { state, .. } = result.expect("the run drives") else {
        panic!("no gate");
    };
    assert_eq!(
        state,
        RunState::Completed,
        "an uncapped `call:` does not starve the run that made it"
    );
    assert_eq!(
        step_row(&conn, run_id, "after").0,
        StepRunState::Completed,
        "the step after the `call:` was admitted"
    );
    assert_eq!(
        step_row(&conn, run_id, "cleanup").0,
        StepRunState::Completed,
        "and §8.13's `finally:` ran"
    );
    assert_eq!(sink.the_report()["outcome"], "nothing");
}

/// The taint projection's **cardinality**, which ruling P116 §D found had no
/// mutation and no fixture that could catch one: both existing taint tests had
/// exactly one tainted step, so a `.take(1)` on `Loop::bind_steps_context`'s
/// `secret_derived_steps` iteration was invisible.
///
/// Two secret-derived steps, each producing a **derived leaf** the whole-value
/// needle backstop structurally cannot match. The leaf under test is relayed
/// from the **second** tainted step here and from the **first** in
/// `taint_crosses_a_step_boundary_inside_the_run_loop_too`, so a truncation at
/// either end of the projection leaks a cleartext credential into the log and
/// fails one of the two.
#[test]
fn two_secret_derived_steps_are_both_marked_so_neither_end_of_the_projection_can_be_dropped() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: first_source\n\
         \x20   emit: { body: \"${{ json(secrets.TOKEN).first }}\" }\n\
         \x20 - id: second_source\n\
         \x20   emit: { body: \"${{ json(secrets.TOKEN).second }}\" }\n\
         \x20 - id: sink_step\n\
         \x20   needs: [first_source, second_source]\n\
         \x20   emit: { relayed: \"${{ steps.second_source.output.body }}\" }\n",
    ))
    .expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let mut run_ctx = ctx(run_id);
    run_ctx.secrets.insert(
        "TOKEN".into(),
        "{\"first\":\"first-derived-leaf\",\"second\":\"second-derived-leaf\"}".into(),
    );

    let outcome = run_workflow(
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
    let RunOutcome::Terminal { state, steps, .. } = outcome else {
        panic!("no gate")
    };
    assert_eq!(state, RunState::Completed, "every step ran: {steps:?}");
    assert_eq!(
        steps
            .iter()
            .find(|s| s.step_id == "sink_step")
            .expect("the relay ran")
            .output["relayed"],
        "second-derived-leaf",
        "the relay really did carry the second source's leaf, unredacted, for \
         dispatch"
    );

    let logged = format!("{:?}", sink.emitted);
    for leaf in ["first-derived-leaf", "second-derived-leaf"] {
        assert!(
            !logged.contains(leaf),
            "a derived leaf must not reach the log in cleartext: {leaf} in {logged}"
        );
    }
}

/// The finding `title` is the third sink for a step's failure message, and
/// until this round the only unbounded one — the other two are `durability`'s
/// `MAX_STORED_STEP_ERROR_LEN` and `exec`'s `MAX_STEPS_CONTEXT_ERROR_LEN`,
/// both 512. An unbounded `call:` workflow name became an unbounded finding
/// title in a table that physically rejects `UPDATE`/`DELETE`.
#[test]
fn a_findings_title_is_bounded_even_when_the_step_message_that_produced_it_is_not() {
    let long_name = "w".repeat(20_000);
    let (_, _, sink, _, result) = drive(
        &format!(
            "steps:\n\
             \x20 - id: sub\n\
             \x20   call: {long_name}\n"
        ),
        10,
    );
    let RunOutcome::Terminal { state, .. } = result.expect("the run drives") else {
        panic!("no gate");
    };
    assert_eq!(
        state,
        RunState::Failed,
        "the workflow name does not resolve"
    );

    let report = sink.the_report();
    let title = report["findings"][0]["title"]
        .as_str()
        .expect("one finding for the failed step");
    assert!(
        title.len() < 700,
        "512 bytes plus the truncation suffix, not 20,000: {} bytes",
        title.len()
    );
    assert!(
        title.ends_with("bytes total)"),
        "and it says how much was dropped rather than silently cutting: \
         {title:?}"
    );
}

/// The other two members of "the author declared a `report:` but there is no
/// document": it **failed**, and its own `when:` **skipped** it. With the emit
/// deferred, both must fall through to the synthesised producer — §8.6 still
/// owes the run exactly one report, and it must not be an empty or invented
/// stand-in for the author's.
///
/// (Before this round the failed case was guarded by a second flag in
/// `record`, which the mutation sweep showed no test could distinguish once
/// the document became the gate. The flag is gone; these two tests are what
/// hold the gate.)
#[test]
fn a_report_step_that_fails_leaves_the_run_the_synthesised_report_not_a_missing_one() {
    let (conn, run_id, sink, _, result) = drive(
        "steps:\n\
         \x20 - id: report\n\
         \x20   report:\n\
         \x20     outcome: not_a_real_outcome\n\
         \x20     severity: low\n\
         \x20     headline: invalid\n\
         \x20     needs_human: false\n\
         \x20     cost: { usd: 0.0, tokens: 0 }\n",
        10,
    );
    let RunOutcome::Terminal { state, report, .. } = result.expect("the run drives") else {
        panic!("no gate");
    };
    assert_eq!(
        state,
        RunState::Failed,
        "an invalid `report:` fails its step"
    );
    assert_eq!(
        report,
        ReportOrigin::Synthesised,
        "no document was produced, so the second producer runs"
    );
    assert_eq!(step_row(&conn, run_id, "report").0, StepRunState::Failed);
    let document = sink.the_report();
    assert_eq!(document["synthesised_by"], "run_loop");
    assert_eq!(document["run_state"], "failed");
}

#[test]
fn a_report_step_skipped_by_its_own_when_gate_is_not_re_rendered_into_existence() {
    let (conn, run_id, sink, _, result) = drive(
        "steps:\n\
         \x20 - id: work\n\
         \x20   emit: { a: 1 }\n\
         \x20 - id: report\n\
         \x20   needs: [work]\n\
         \x20   when: \"${{ false }}\"\n\
         \x20   report:\n\
         \x20     outcome: changed\n\
         \x20     severity: low\n\
         \x20     headline: never written\n\
         \x20     needs_human: false\n\
         \x20     cost: { usd: 0.0, tokens: 0 }\n",
        10,
    );
    let RunOutcome::Terminal { state, report, .. } = result.expect("the run drives") else {
        panic!("no gate");
    };
    assert_eq!(state, RunState::Completed);
    assert_eq!(step_row(&conn, run_id, "report").0, StepRunState::Skipped);
    assert_eq!(
        report,
        ReportOrigin::Synthesised,
        "a step the author's own `when:` skipped did not write a report, and \
         the loop must not run it anyway to manufacture one"
    );
    assert_eq!(
        sink.the_report()["headline"],
        "run completed: 2 steps",
        "the synthesised headline, not the author's `never written`"
    );
}

/// The **matched-against** half of the restore (P99 rule 4): the checkpoint
/// scan iterates every finished row, and the row it must match is the
/// `report:` step's — not merely "some row is `Completed`".
///
/// Two passes, and on the second the report step is skipped by its own
/// `when:`. A restore keyed on any completed row would set
/// `report_completed_before` from `work`'s pass-one row and then **re-render
/// the report step the author's condition skipped**, manufacturing an
/// `Authored` report for a document the run never asked for. Caught by nothing
/// in the single-pass fixtures, because there is no earlier row in them at
/// all.
#[test]
fn the_restore_matches_the_report_steps_own_row_and_not_merely_some_completed_row() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: work\n\
         \x20   emit: { a: 1 }\n\
         \x20 - id: approve\n\
         \x20   needs: [work]\n\
         \x20   gate:\n\
         \x20     title: \"ok?\"\n\
         \x20     form: { approve: { type: boolean } }\n\
         \x20     timeout: 1h\n\
         \x20     on_timeout: deny\n\
         \x20 - id: report\n\
         \x20   needs: [approve]\n\
         \x20   when: \"${{ false }}\"\n\
         \x20   report:\n\
         \x20     outcome: changed\n\
         \x20     severity: low\n\
         \x20     headline: never written\n\
         \x20     needs_human: false\n\
         \x20     cost: { usd: 0.0, tokens: 0 }\n",
    ))
    .expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();

    let first = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        at(10),
        None,
    )
    .expect("pass one drives");
    assert!(matches!(first, RunOutcome::Parked(_)));
    assert_eq!(
        step_row(&conn, run_id, "work").0,
        StepRunState::Completed,
        "so pass two starts with a completed row that is NOT the report step's"
    );

    let second = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        at(20),
        Some(GateAnswer {
            step_id: "approve".into(),
            output: serde_json::json!({ "approve": true }),
        }),
    )
    .expect("pass two drives");
    let RunOutcome::Terminal { report, state, .. } = second else {
        panic!("the gate was answered");
    };
    assert_eq!(state, RunState::Completed);
    assert_eq!(step_row(&conn, run_id, "report").0, StepRunState::Skipped);
    assert_eq!(
        report,
        ReportOrigin::Synthesised,
        "the author's own `when:` skipped the report step, and an earlier \
         step's completed row must not be mistaken for the report step's"
    );
    assert_eq!(sink.reports().len(), 1, "across both passes");
    assert_eq!(sink.the_report()["synthesised_by"], "run_loop");
}

// ---------------------------------------------------------------------------
// Task 19a: `build_carry_over_seed` wired at the run-start path
// ---------------------------------------------------------------------------

/// This is an executor-level test, not a re-test of `build_carry_over_seed`
/// in isolation (`tests/report.rs` already covers that function's own
/// logic): it fails if `run_loop::run_workflow` stops binding the seed into
/// the run's `ExprContext`, which is the part a unit test of the pure
/// function cannot see.
///
/// Asserted through a `when:` gate rather than the persisted log, and
/// deliberately: `carry_over` is bound through `set_secret` (ruling P35 —
/// the previous report's provenance is unknown at the binding site), so an
/// `emit:` step's own *logged* rendering of a value read through it is
/// always `"***"` by design — that would make a log-content assertion prove
/// nothing about whether the real value is actually reachable. A `when:`
/// gate's pass/fail is control flow, computed from the real, untainted-for-
/// evaluation-purposes value; taint only ever affects what gets logged
/// verbatim, never what a comparison decides. Two gates, only one of which
/// should pass, so this cannot pass merely because "some step ran" or
/// because an unbound root's `null` happens to make a lenient comparison
/// true.
#[test]
fn carry_over_seed_from_the_previous_run_is_reachable_from_a_workflow_expression() {
    let previous = Report {
        outcome: Outcome::Findings,
        severity: Severity::Med,
        headline: "2 flaky tests quarantined".into(),
        needs_human: false,
        cost: Cost {
            usd: 0.1,
            tokens: 500,
        },
        findings: vec![],
        artifacts: vec![],
        next_actions: vec![],
        extra: serde_json::Map::new(),
    };

    let (conn, run_id, _sink, result) = drive_with_previous_report(
        "defaults: { carry_over: { last_report: true } }\n\
         steps:\n\
         \x20 - id: headline_matches\n\
         \x20   when: \"${{ carry_over.previous_report.headline == '2 flaky tests quarantined' }}\"\n\
         \x20   emit: { ok: true }\n\
         \x20 - id: outcome_matches\n\
         \x20   when: \"${{ carry_over.previous_report.outcome == 'findings' }}\"\n\
         \x20   emit: { ok: true }\n\
         \x20 - id: headline_does_not_match\n\
         \x20   when: \"${{ carry_over.previous_report.headline == 'a different headline' }}\"\n\
         \x20   emit: { ok: true }\n",
        previous,
    );
    result.expect("the run drives");

    assert_eq!(
        step_row(&conn, run_id, "headline_matches").0,
        StepRunState::Completed,
        "a workflow expression must be able to read the previous run's real \
         headline through the `carry_over` root — this fails if the call to \
         build_carry_over_seed / ExprContext::set_secret at the run-start \
         path in run_loop::run_workflow is ever removed"
    );
    assert_eq!(
        step_row(&conn, run_id, "outcome_matches").0,
        StepRunState::Completed,
        "same for the previous run's outcome"
    );
    assert_eq!(
        step_row(&conn, run_id, "headline_does_not_match").0,
        StepRunState::Skipped,
        "proves the comparison reads the actual headline value rather than \
         e.g. always resolving truthy"
    );
}

/// `carry_over.last_report` defaults to `false` (§8.6 says nothing runs
/// unless a job opts in), so a workflow with no `defaults.carry_over` at all
/// must not have a `carry_over` root bound. An unbound root resolves to
/// `null` in this evaluator (`expr.rs`'s bare-identifier lookup), not an
/// evaluation error, so the observable behavior is: the field read off it is
/// `null`, never the previous run's real data leaking into a job that never
/// opted in.
#[test]
fn no_carry_over_root_is_bound_when_the_job_does_not_opt_in() {
    let previous = Report {
        outcome: Outcome::Nothing,
        severity: Severity::Low,
        headline: "should never be seen".into(),
        needs_human: false,
        cost: Cost {
            usd: 0.0,
            tokens: 0,
        },
        findings: vec![],
        artifacts: vec![],
        next_actions: vec![],
        extra: serde_json::Map::new(),
    };

    // `null` on the right of `==` here is not a literal — this expression
    // language has no `null` keyword (`expr.rs`'s `parse_primary` only
    // handles string/number/array literals and identifiers). It is a bare,
    // never-bound identifier, which resolves to `Value::Null` by the same
    // unbound-root rule the doc comment above cites for `carry_over` itself
    // — two applications of one rule, not a coincidence.
    let (conn, run_id, _sink, result) = drive_with_previous_report(
        "steps:\n\
         \x20 - id: unset\n\
         \x20   when: \"${{ carry_over.previous_report.headline == null }}\"\n\
         \x20   emit: { ok: true }\n\
         \x20 - id: leaked\n\
         \x20   when: \"${{ carry_over.previous_report.headline == 'should never be seen' }}\"\n\
         \x20   emit: { ok: true }\n",
        previous,
    );
    result.expect("the run drives");

    assert_eq!(
        step_row(&conn, run_id, "unset").0,
        StepRunState::Completed,
        "with no `defaults.carry_over.last_report: true`, the root must \
         resolve to null, not silently disappear or error"
    );
    assert_eq!(
        step_row(&conn, run_id, "leaked").0,
        StepRunState::Skipped,
        "the previous run's real report must never be visible to a job \
         that did not opt into carry_over"
    );
}
