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

use roundhouse_core::{
    EventPayload, JobId, Origin, SessionId, TaskId, TaskInput, TaskKind, TaskOutput, Timestamp,
};
use roundhouse_flow::caps::ResourceCaps;
use roundhouse_flow::durability::{
    insert_workflow_run, open_test_db, recover_run, transition_run, RunState, StepRunState,
    WorkflowRun,
};
use roundhouse_flow::exec::run_loop::{
    run_workflow, CalledWorkflow, CrashRecoveryAnswer, GateAnswer, ReportOrigin, Resume,
    RunLoopError, RunOutcome, WorkflowHost, WorkflowHostError,
};
use roundhouse_flow::exec::{RunContext, RunId, StepStatus, TaskSink};
use roundhouse_flow::expr::EnvAllowlist;
use roundhouse_flow::hitl::CrashResolution;
use roundhouse_flow::ledger::run_ledger;
use roundhouse_flow::parking::{CheckpointError, CheckpointRef, Checkpointer};
use roundhouse_flow::parse::parse_workflow;
use roundhouse_flow::report::{Cost, Outcome, Report, Severity};
use rusqlite::Connection;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

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
    /// Every `(parent session, child session)` the run loop reported as
    /// terminated — the runtime fan-out slot the daemon's real host gives back
    /// to `SpawnTree`.
    terminated: Vec<(SessionId, SessionId)>,
}

impl FakeHost {
    fn new() -> Self {
        FakeHost {
            checkpoints: Vec::new(),
            resolvable: HashMap::new(),
            direct_children: 0,
            sessions_created: Vec::new(),
            reservations: Vec::new(),
            terminated: Vec::new(),
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
        parent_step: &roundhouse_flow::durability::WorkflowStepRun,
        parent_call: &roundhouse_flow::durability::WorkflowChildCall,
        _parent_task_input: TaskInput,
    ) -> Result<(), WorkflowHostError> {
        let txn = roundhouse_store::begin_immediate(conn)?;
        if let Err(error) =
            roundhouse_flow::durability::insert_workflow_run_in_transaction(&txn, child)
        {
            self.release_child_session(_parent, called);
            return Err(error.into());
        }
        if let Err(error) =
            roundhouse_flow::durability::checkpoint_step_in_transaction(&txn, parent_step)
        {
            self.release_child_session(_parent, called);
            return Err(error.into());
        }
        if let Err(error) = roundhouse_flow::durability::insert_workflow_child_call_in_transaction(
            &txn,
            parent_call,
        ) {
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

    fn child_session_terminated(&mut self, parent: SessionId, child: SessionId) {
        self.terminated.push((parent, child));
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
        inputs_secret_derived: false,
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
    resume: Option<Resume>,
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
    let result = run_to_terminal(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        now,
        resume,
    );
    (conn, run_id, sink, host, result)
}

/// Drives [`run_workflow`] until it stops returning
/// [`RunOutcome::AwaitingWork`], answering every pending `tool:`/`agent:`
/// step with exactly the stub this crate always produced for them before
/// the suspend/resume seam existed (Phase 8 Task 25.1): a `TaskCreated`
/// reaches `sink` and the step "completes" with a fixed empty object — see
/// `Executor::dispatch_step_or_stub`'s own doc, which this mirrors on the
/// caller side of the seam. This is the stand-in for `roundhouse-daemon`'s
/// real driving loop (Phase 8 Task 25.2/25.3), which is what actually
/// dispatches these for real; nothing in this crate does.
#[allow(clippy::too_many_arguments)]
fn run_to_terminal(
    conn: &mut Connection,
    def: &roundhouse_flow::parse::WorkflowDef,
    run_id: RunId,
    sink: &mut RecordingSink,
    host: &mut FakeHost,
    run_ctx: RunContext,
    now: i64,
    resume: Option<Resume>,
) -> Result<RunOutcome, RunLoopError> {
    run_to_terminal_failing(conn, def, run_id, sink, host, run_ctx, now, resume, &[])
}

/// The most segments any fixture in this file legitimately needs — one per
/// `tool:`/`agent:` step, plus one to reach the terminal transition.
///
/// A cap rather than an unbounded loop because the failure this guards is a
/// **livelock**, not a wrong value: a run whose later segment re-decides a
/// step an earlier segment already settled suspends on it again, forever,
/// and the only thing that eventually stops it is `Loop::admit` exhausting
/// the run's grant — at which point the run ends `Failed` with a spurious
/// "admission refused" rather than with what actually happened. Tripping
/// this assertion names the defect; letting the loop run to the cap would
/// hide it behind an unrelated ledger message.
const MAX_SEGMENTS: usize = 16;

/// [`run_to_terminal`], but answering every pending step named in `failing`
/// with [`WorkStatus::Failed`] instead of the completing stub.
///
/// The real driver fails a `PendingWork` for ordinary reasons — a tool this
/// daemon cannot dispatch yet, a tool call the policy gate refuses, a tool
/// that ran and returned an error — so a step that suspends and then comes
/// back failed is the common case, not an exotic one, and nothing in this
/// file could produce it before.
#[allow(clippy::too_many_arguments)]
fn run_to_terminal_failing(
    conn: &mut Connection,
    def: &roundhouse_flow::parse::WorkflowDef,
    run_id: RunId,
    sink: &mut RecordingSink,
    host: &mut FakeHost,
    run_ctx: RunContext,
    now: i64,
    mut resume: Option<Resume>,
    failing: &[&str],
) -> Result<RunOutcome, RunLoopError> {
    let mut segments = 0usize;
    loop {
        segments += 1;
        assert!(
            segments <= MAX_SEGMENTS,
            "the run has been re-entered {segments} times without reaching a terminal state: \
             a step settled by an earlier segment is being re-decided by a later one"
        );
        let outcome = run_workflow(
            conn,
            def,
            run_id,
            sink,
            host,
            run_ctx.clone(),
            at(now),
            resume.take(),
        )?;
        let pending = match outcome {
            RunOutcome::AwaitingWork { pending } => pending,
            other => return Ok(other),
        };
        let mut done = Vec::with_capacity(pending.len());
        for p in pending {
            let task_id = match p.kind {
                roundhouse_flow::exec::run_loop::PendingKind::Tool {
                    task_kind,
                    logged_input,
                    ..
                } => {
                    let task_id = TaskId::new();
                    sink.emit(
                        task_id,
                        None,
                        task_kind.clone(),
                        EventPayload::TaskCreated {
                            kind: task_kind,
                            parent: None,
                            origin: Origin::System,
                            input: TaskInput::Json(logged_input),
                        },
                    );
                    task_id
                }
                roundhouse_flow::exec::run_loop::PendingKind::Agent { logged_prompt, .. } => {
                    let task_id = TaskId::new();
                    sink.emit(
                        task_id,
                        None,
                        TaskKind::Agent,
                        EventPayload::TaskCreated {
                            kind: TaskKind::Agent,
                            parent: None,
                            origin: Origin::System,
                            input: TaskInput::Json(logged_prompt),
                        },
                    );
                    task_id
                }
                roundhouse_flow::exec::run_loop::PendingKind::ChildRun {
                    parent_task_id, ..
                } => parent_task_id,
            };
            let status = if failing.contains(&p.step_id.as_str()) {
                roundhouse_flow::exec::run_loop::WorkStatus::Failed {
                    message: format!("the caller could not dispatch {:?}", p.step_id),
                }
            } else {
                roundhouse_flow::exec::run_loop::WorkStatus::Completed
            };
            done.push(roundhouse_flow::exec::run_loop::WorkDone {
                step_id: p.step_id,
                // Mirrors what this `PendingWork` itself carries — always
                // `None` today, since nothing produces a real map item's
                // pending work yet (Phase 8 Task 25.7 Task 2).
                item_index: p.item_index,
                status,
                output: serde_json::json!({}),
                output_is_secret_derived: false,
                task_id: Some(task_id),
                first_task_seq: None,
                last_task_seq: None,
            });
        }
        resume = Some(Resume::Work(done));
    }
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
// `agent:` step dispatch — Phase 8 Task 25.5 (#62)
// ---------------------------------------------------------------------------

/// `Executor::dispatch_step`'s `StepBody::Agent` arm used to destructure only
/// `prompt`, silently dropping `model`/`tools`/`output_schema` via `..` — a
/// caller answering `PendingKind::Agent` had no way to know which model, tool
/// allowlist, or output schema the step declared. §8.9's own reference
/// workflow's `review` step (`tests/fixtures/pr_review.yaml`) sets all four.
#[test]
fn an_agent_step_carries_its_model_tools_and_output_schema_into_pending_work() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: review\n\
         \x20   agent:\n\
         \x20     model: \"claude-x\"\n\
         \x20     tools: [read, find]\n\
         \x20     prompt: \"hi\"\n\
         \x20     output_schema: { type: object, properties: { findings: { type: array } } }\n",
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
        at(0),
        None,
    )
    .expect("dispatching an `agent:` step suspends the run rather than erroring");
    let RunOutcome::AwaitingWork { pending } = outcome else {
        panic!("an `agent:` step needs real dispatch and must suspend the run, got {outcome:?}");
    };
    assert_eq!(pending.len(), 1, "exactly one pending item for one step");
    let roundhouse_flow::exec::run_loop::PendingKind::Agent {
        model,
        tools,
        output_schema,
        dispatch_prompt,
        ..
    } = &pending[0].kind
    else {
        panic!("expected PendingKind::Agent, got {:?}", pending[0].kind);
    };
    assert_eq!(
        model.as_deref(),
        Some("claude-x"),
        "the step's declared model must not be dropped"
    );
    assert_eq!(
        tools,
        &vec!["read".to_string(), "find".to_string()],
        "the step's declared tool allowlist must not be dropped"
    );
    assert_eq!(
        output_schema,
        &Some(serde_json::json!({
            "type": "object",
            "properties": { "findings": { "type": "array" } }
        })),
        "the step's declared output schema must not be dropped"
    );
    assert_eq!(dispatch_prompt, "hi");
}

/// A workflow `agent:` step has no authored token budget — unlike the
/// model-issued `agent` tool, whose `budget_tokens` argument the model
/// picks. `Loop::run_phase` already reads the run's real remaining ceiling
/// into `executor.map_budget` before every dispatch (ruling P108 §C,
/// `step_timeout`'s existing source); this is the same value, for the same
/// reason: the caller that spawns the child (Phase 8 Task 25.5 #62) needs a
/// real number to transfer, not an invented one.
#[test]
fn an_agent_steps_budget_tokens_comes_from_the_runs_real_remaining_ceiling() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: review\n\
         \x20   agent:\n\
         \x20     prompt: \"hi\"\n",
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
        at(0),
        None,
    )
    .expect("dispatching an `agent:` step suspends the run rather than erroring");
    let RunOutcome::AwaitingWork { pending } = outcome else {
        panic!("an `agent:` step needs real dispatch and must suspend the run, got {outcome:?}");
    };
    let roundhouse_flow::exec::run_loop::PendingKind::Agent { budget_tokens, .. } =
        &pending[0].kind
    else {
        panic!("expected PendingKind::Agent, got {:?}", pending[0].kind);
    };
    assert_eq!(
        *budget_tokens,
        a_grant().max_tokens,
        "nothing has spent any tokens yet, so the real remaining ceiling equals the run's \
         full grant"
    );
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
        Some(Resume::Gate(GateAnswer {
            step_id: "approve".into(),
            item_index: None,
            output: serde_json::json!({ "approve": true }),
        })),
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
        Some(Resume::Gate(GateAnswer {
            step_id: "work".into(),
            item_index: None,
            output: serde_json::json!({}),
        })),
    );
    assert!(
        matches!(result, Err(RunLoopError::UnknownGateStep { .. })),
        "got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// The `call:` arm — §8.12's child run and its budget transfer
// ---------------------------------------------------------------------------

#[test]
fn a_call_step_suspends_until_its_child_result_arrives() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: child\n\
         \x20   call: child-flow\n\
         \x20   with: { token: \"${{ secrets.TOKEN }}\" }\n\
         \x20 - id: after\n\
         \x20   emit: { ran: true }\n",
    ))
    .expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new().resolving("child-flow");
    let mut run_ctx = ctx(run_id);
    run_ctx
        .secrets
        .insert("TOKEN".into(), "child-secret".into());

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
    .expect("the parent run drives to its child");

    let RunOutcome::AwaitingWork { pending } = outcome else {
        panic!("a call waits for its child before continuing");
    };
    assert_eq!(pending.len(), 1, "one child run is awaiting completion");
    let roundhouse_flow::exec::run_loop::PendingKind::ChildRun {
        child_run_id,
        child_session_id,
        parent_task_id,
        dispatch_input,
        ..
    } = &pending[0].kind
    else {
        panic!("a call creates pending child work");
    };
    assert_eq!(
        dispatch_input,
        &serde_json::json!({ "token": "child-secret" }),
        "the child receives the real resolved input only through pending work"
    );
    assert_eq!(*child_session_id, host.sessions_created[0]);
    assert_eq!(
        recover_run(&conn, *child_run_id)
            .expect("recover child")
            .run
            .parent_run_id,
        Some(run_id)
    );
    let state: String = conn
        .query_row(
            "SELECT state FROM workflow_step_run WHERE run_id = ?1 AND step_id = ?2",
            [run_id.to_string(), "child".to_string()],
            |row| row.get(0),
        )
        .expect("the pending call is checkpointed");
    assert_eq!(state, "running");
    assert!(
        recover_run(&conn, run_id)
            .expect("recover parent")
            .steps
            .iter()
            .all(|row| row.step_id != "after"),
        "the step after a pending child must not execute"
    );
    assert_eq!(
        sink.emitted
            .iter()
            .filter(|(kind, payload)| {
                *kind == TaskKind::Agent && matches!(payload, EventPayload::TaskCreated { .. })
            })
            .count(),
        1,
        "the parent logs exactly one task for the child call"
    );
    assert_eq!(*parent_task_id, sink.task_ids[0]);
    assert!(
        !format!("{:?}", sink.emitted).contains("child-secret"),
        "the real child input is never persisted in the parent log"
    );
}

#[test]
fn a_resumed_call_uses_the_original_parent_agent_task() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: child\n\
         \x20   call: child-flow\n\
         \x20 - id: after\n\
         \x20   needs: [child]\n\
         \x20   emit: { ran: true }\n",
    ))
    .expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new().resolving("child-flow");

    let initial = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        at(10),
        None,
    )
    .expect("the parent run drives to its child");
    let RunOutcome::AwaitingWork { pending } = initial else {
        panic!("the parent waits for its child");
    };
    let roundhouse_flow::exec::run_loop::PendingKind::ChildRun { parent_task_id, .. } =
        &pending[0].kind
    else {
        panic!("the call creates pending child work");
    };
    let parent_task_id = *parent_task_id;

    let resumed = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        at(11),
        Some(Resume::Work(vec![
            roundhouse_flow::exec::run_loop::WorkDone {
                step_id: "child".into(),
                item_index: None,
                status: roundhouse_flow::exec::run_loop::WorkStatus::Completed,
                output: serde_json::json!({ "result": "child complete" }),
                output_is_secret_derived: false,
                task_id: Some(parent_task_id),
                first_task_seq: Some(41),
                last_task_seq: Some(43),
            },
        ])),
    )
    .expect("the completed child resumes its parent");

    assert!(matches!(resumed, RunOutcome::Terminal { .. }));
    let child = recover_run(&conn, run_id)
        .expect("recover parent")
        .steps
        .into_iter()
        .find(|row| row.step_id == "child")
        .expect("the call step is checkpointed");
    assert_eq!(child.state, StepRunState::Completed);
    assert_eq!(child.first_task_seq, Some(41));
    assert_eq!(child.last_task_seq, Some(43));
    assert_eq!(
        child
            .output
            .expect("the child result is persisted")
            .value_unredacted_for_resume(),
        &serde_json::json!({ "result": "child complete" })
    );
    assert_eq!(
        host.sessions_created.len(),
        1,
        "resume does not create another child"
    );
    assert_eq!(
        sink.task_ids
            .iter()
            .zip(&sink.emitted)
            .filter_map(|(task_id, (kind, payload))| {
                (*kind == TaskKind::Agent && matches!(payload, EventPayload::TaskCreated { .. }))
                    .then_some(*task_id)
            })
            .collect::<Vec<_>>(),
        vec![parent_task_id],
        "the completed child is associated with the original parent task"
    );
}

#[test]
fn a_failed_call_running_checkpoint_rolls_back_its_child() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    conn.execute_batch(
        "CREATE TRIGGER reject_call_running_checkpoint
         BEFORE INSERT ON workflow_step_run
         WHEN NEW.step_id = 'child' AND NEW.state = 'running'
         BEGIN
             SELECT RAISE(ABORT, 'test call checkpoint failure');
         END;",
    )
    .expect("install call checkpoint failure");
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: child\n\
         \x20   call: child-flow\n",
    ))
    .expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new().resolving("child-flow");

    let result = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        at(10),
        None,
    );

    let RunOutcome::Terminal { state, .. } = result.expect("the failed hand-off is a step failure")
    else {
        panic!("a failed child hand-off must not suspend");
    };
    assert_eq!(state, RunState::Failed);
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM workflow_run WHERE parent_run_id = ?1",
            [run_id.to_string()],
            |row| row.get::<_, i64>(0),
        )
        .expect("count child runs"),
        0,
        "without the running checkpoint, no funded child may survive to be duplicated on re-drive"
    );
    assert!(host.sessions_created.is_empty());
    assert!(host.reservations.is_empty());
}

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
    let RunOutcome::AwaitingWork { pending } = outcome else {
        panic!("the call must wait for its child");
    };
    let roundhouse_flow::exec::run_loop::PendingKind::ChildRun { child_run_id, .. } =
        &pending[0].kind
    else {
        panic!("the call creates pending child work");
    };
    let child_id = *child_run_id;

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

    let RunOutcome::AwaitingWork { pending } = outcome else {
        panic!("the funded child awaits driving");
    };
    let roundhouse_flow::exec::run_loop::PendingKind::ChildRun { child_run_id, .. } =
        &pending[0].kind
    else {
        panic!("the call creates pending child work");
    };
    let child_id = *child_run_id;
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

/// Seeds a `Running` + `Effectful` `workflow_step_run` row for `step_id` —
/// exactly what a daemon killed mid-dispatch of a `shell`/`write`/`edit`
/// step leaves behind, and what `recover_run` reclassifies `Indeterminate`
/// on the next load.
fn seed_crashed_effectful_step(conn: &mut Connection, run_id: RunId, step_id: &str) {
    roundhouse_flow::durability::checkpoint_step(
        conn,
        &roundhouse_flow::durability::WorkflowStepRun {
            run_id,
            step_id: step_id.to_string(),
            attempt: 1,
            item_index: None,
            disposition: roundhouse_flow::durability::StepDisposition::Effectful,
            state: StepRunState::Running,
            first_task_seq: None,
            last_task_seq: None,
            output: None,
            error: None,
        },
    )
    .expect("seed a Running Effectful row, simulating a crash mid-dispatch");
}

/// The `awaiting_human` payload the run loop put in the log for a park, as
/// JSON — §8.11's *"a JSON-Schema form that TUI and web render from the same
/// schema"*, which is the only thing that actually asks the human anything.
fn the_awaiting_human_form(sink: &RecordingSink) -> Value {
    let forms: Vec<Value> = sink
        .emitted
        .iter()
        .filter_map(|(_, payload)| match payload {
            EventPayload::TaskCreated {
                input: TaskInput::Json(input),
                ..
            } => input.get("awaiting_human").cloned(),
            _ => None,
        })
        .collect();
    assert_eq!(
        forms.len(),
        1,
        "exactly one human-wait form must reach the log per park, got {forms:?}"
    );
    forms.into_iter().next().expect("checked non-empty above")
}

/// §8.10 tier 2's crash-policy wiring, completed (Phase 8 Task 25.4 Task 5):
/// a step `recover_run` reclassifies `Indeterminate` (`Running` +
/// `Effectful`, with no caller-supplied `WorkDone` answering it) whose
/// resolved `CrashPolicy` is `Ask` — §8.10's default for **every**
/// `Effectful` step with no declared `on_crash:` — **parks the run on a
/// human**, rather than failing the run closed as Task 25.3's interim
/// behaviour did.
///
/// This test's predecessor asserted the fail-closed behaviour and was
/// renamed rather than kept: leaving it would pin a rule this task
/// deliberately replaced. Failing closed meant any daemon restart mid-`shell`
/// / `write` / `edit` permanently failed the run.
#[test]
fn an_indeterminate_effectful_step_with_no_on_crash_declared_parks_for_a_human_instead_of_failing_closed(
) {
    let mut conn = open_test_db();
    let (run_id, session_id) = seed_run(&mut conn);
    seed_crashed_effectful_step(&mut conn, run_id, "risky");

    let def = parse_workflow(&workflow(
        "steps:\n \x20- id: risky\n \x20  tool: shell\n \x20  with: { cmd: [ls] }\n",
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
    .expect("the run re-drives");

    let RunOutcome::Parked(parked) = outcome else {
        panic!("an `Effectful` step's `Ask` crash policy parks the run, got {outcome:?}");
    };
    assert_eq!(parked.session_id, session_id);
    assert_eq!(
        host.checkpoints.len(),
        1,
        "§8.11's implicit checkpoint runs before any release, exactly as it does for a gate"
    );
    // The durable row, not the returned value: the defect this subsystem
    // keeps producing is an in-memory answer nothing else can see.
    assert_eq!(
        recover_run(&conn, run_id).unwrap().run.state,
        RunState::AwaitingHuman
    );
    assert_eq!(
        parked.awaiting_until,
        Some(at(10 + 72 * 3600)),
        "§8.11's *with no explicit gate timeout, fall back to 72h* — and a crash park has no \
         author at all to declare one"
    );
    assert!(
        sink.reports().is_empty(),
        "a parked run has not ended, so it has no result to report"
    );
    // The step's own row still says `Running`: that is what makes the next
    // load reclassify it `Indeterminate` again, which is how the answer
    // finds the step it belongs to.
    assert_eq!(
        step_row(&conn, run_id, "risky").0,
        StepRunState::Indeterminate
    );

    let form = the_awaiting_human_form(&sink);
    assert_eq!(
        form["source"], "crash_recovery",
        "the park must name its source, or nothing can tell a crash question from a gate"
    );
    assert_eq!(
        form["form_schema"]["properties"]["resolution"]["enum"],
        serde_json::json!(["rerun", "skip", "fail"])
    );
    assert!(
        form["form_schema"]["title"]
            .as_str()
            .is_some_and(|t| t.contains("risky")),
        "the prompt must say which step is being asked about: {form:?}"
    );
    assert_eq!(
        form["on_timeout"],
        serde_json::json!({ "unchecked": "fail" }),
        "a crash park has no author to write `on_timeout:`, so it defaults to the \
         conservative `fail`"
    );
}

/// The first of §8.10's three answers: `rerun` re-dispatches the step, which
/// is exactly an at-least-once crash re-run — the step is re-admitted and
/// suspends on the same `AwaitingWork` seam every `tool:` step suspends on,
/// and the run then reaches a normal terminal state.
#[test]
fn answering_a_crash_recovery_park_with_rerun_re_dispatches_the_step() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    seed_crashed_effectful_step(&mut conn, run_id, "risky");
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: risky\n\
         \x20   tool: shell\n\
         \x20   with: { cmd: [ls] }\n\
         \x20 - id: after\n\
         \x20   needs: [risky]\n\
         \x20   emit: { saw: \"${{ steps.risky.status }}\" }\n",
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
        at(10),
        None,
    )
    .expect("the run re-drives");
    assert!(matches!(parked, RunOutcome::Parked(_)), "got {parked:?}");

    let mut sink = RecordingSink::default();
    let outcome = run_to_terminal(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        20,
        Some(Resume::CrashRecovery(CrashRecoveryAnswer {
            step_id: "risky".into(),
            resolution: CrashResolution::Rerun,
        })),
    )
    .expect("the answer releases the park");

    let RunOutcome::Terminal { state, steps, .. } = outcome else {
        panic!("a re-run step drives the run to a terminal state, got {outcome:?}");
    };
    assert_eq!(state, RunState::Completed);
    assert!(
        steps.iter().any(|s| s.step_id == "risky"),
        "`rerun` re-dispatches the step rather than inheriting a decision: {steps:?}"
    );
    assert_eq!(step_row(&conn, run_id, "risky").0, StepRunState::Completed);
    assert_eq!(
        steps
            .iter()
            .find(|s| s.step_id == "after")
            .expect("the dependent ran")
            .output["saw"],
        "completed",
        "the dependent reads the re-run step's real outcome"
    );
    assert_eq!(sink.reports().len(), 1);
}

/// The second answer: `skip` records the step durably skipped — with a
/// reason naming the human — and the phase carries on.
#[test]
fn answering_a_crash_recovery_park_with_skip_records_the_step_skipped_and_continues() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    seed_crashed_effectful_step(&mut conn, run_id, "risky");
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: risky\n\
         \x20   tool: shell\n\
         \x20   with: { cmd: [ls] }\n\
         \x20 - id: after\n\
         \x20   needs: [risky]\n\
         \x20   emit: { saw: \"${{ steps.risky.status }}\" }\n",
    ))
    .expect("fixture parses");

    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        at(10),
        None,
    )
    .expect("the run parks");

    let mut sink = RecordingSink::default();
    let outcome = run_to_terminal(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        20,
        Some(Resume::CrashRecovery(CrashRecoveryAnswer {
            step_id: "risky".into(),
            resolution: CrashResolution::Skip,
        })),
    )
    .expect("the answer releases the park");

    let RunOutcome::Terminal { state, steps, .. } = outcome else {
        panic!("a skipped step does not suspend the run, got {outcome:?}");
    };
    assert_eq!(
        state,
        RunState::Completed,
        "`skip` continues the phase rather than ending the run"
    );
    let (row_state, reason) = step_row(&conn, run_id, "risky");
    assert_eq!(row_state, StepRunState::Skipped);
    assert!(
        reason.is_some_and(|r| r.contains("skip")),
        "the row must say a human chose to skip it, not merely that it was skipped"
    );
    assert_eq!(
        steps
            .iter()
            .find(|s| s.step_id == "after")
            .expect("the dependent ran")
            .output["saw"],
        "skipped",
        "a dependent reads the skip back out of the fold, exactly as for a `when:` skip"
    );
}

/// The third answer: `fail` fails the step, with a message naming the
/// human's decision rather than the crash policy — the run did not fail
/// closed on a rule, a person decided.
#[test]
fn answering_a_crash_recovery_park_with_fail_fails_the_step_naming_the_humans_decision() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    seed_crashed_effectful_step(&mut conn, run_id, "risky");
    let def = parse_workflow(&workflow(
        "steps:\n \x20- id: risky\n \x20  tool: shell\n \x20  with: { cmd: [ls] }\n",
    ))
    .expect("fixture parses");

    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        at(10),
        None,
    )
    .expect("the run parks");

    let mut sink = RecordingSink::default();
    let outcome = run_to_terminal(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        20,
        Some(Resume::CrashRecovery(CrashRecoveryAnswer {
            step_id: "risky".into(),
            resolution: CrashResolution::Fail,
        })),
    )
    .expect("the answer releases the park");

    let RunOutcome::Terminal { state, .. } = outcome else {
        panic!("a failed step ends the run, got {outcome:?}");
    };
    assert_eq!(state, RunState::Failed);
    let (row_state, error) = step_row(&conn, run_id, "risky");
    assert_eq!(row_state, StepRunState::Failed);
    let error = error.expect("a failed step's row carries its message");
    assert!(
        error.contains("human") && error.contains("fail"),
        "the message must name the human's decision, not a policy: {error:?}"
    );
    assert_eq!(sink.reports().len(), 1);
}

/// An answer naming a step this workflow has no crash-recovery park for is
/// refused rather than silently ignored — the same rule
/// `a_gate_answer_naming_a_non_gate_step_is_refused` states for the gate
/// channel, and for a sharper version of the same reason: an answer nothing
/// consumes would release the park and leave the run driving on with the
/// question it parked for still unanswered.
#[test]
fn a_crash_recovery_answer_naming_a_step_that_cannot_crash_park_is_refused() {
    let (_, _, _, _, result) = drive_with(
        // `read` is `Pure`, so it is never reclassified `Indeterminate` and
        // its crash policy is `Rerun`, never `Ask`.
        "steps:\n \x20- id: work\n \x20  tool: read\n \x20  with: { path: a }\n",
        10,
        FakeHost::new(),
        Some(Resume::CrashRecovery(CrashRecoveryAnswer {
            step_id: "work".into(),
            resolution: CrashResolution::Rerun,
        })),
    );
    assert!(
        matches!(result, Err(RunLoopError::UnknownCrashRecoveryStep { .. })),
        "got {result:?}"
    );
}

/// §8.13's *cancel must converge*, at this park's own site: a run already
/// draining a cancel must not acquire a new indefinite wait on a human. The
/// run loop's leg of the same rule `Loop::dispatch_gate` applies to a
/// `gate:` in `catch:`/`finally:`.
#[test]
fn a_cancelling_run_fails_an_indeterminate_step_closed_rather_than_parking_it() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    seed_crashed_effectful_step(&mut conn, run_id, "risky");
    roundhouse_flow::control::cancel(&mut conn, run_id, at(5))
        .expect("marking a Running run Cancelling must succeed");

    let def = parse_workflow(&workflow(
        "steps:\n \x20- id: risky\n \x20  tool: shell\n \x20  with: { cmd: [ls] }\n",
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
    .expect("a cancelling run still drains to a terminal state");

    let RunOutcome::Terminal { state, .. } = outcome else {
        panic!("a cancelling run must converge, not park, got {outcome:?}");
    };
    assert_eq!(state, RunState::Cancelled);
    assert!(
        host.checkpoints.is_empty(),
        "nothing parked, so §8.11's implicit checkpoint never ran"
    );
    let (row_state, error) = step_row(&conn, run_id, "risky");
    assert_eq!(row_state, StepRunState::Failed);
    assert!(
        error.is_some_and(|e| e.contains("must converge")),
        "the row must say why the step could not park"
    );
}

/// The same refusal for the block a park would deadlock: a crash-recovery
/// park inside `finally:` would suspend a run that is already ending.
#[test]
fn an_indeterminate_step_inside_finally_fails_closed_rather_than_parking_a_run_that_is_ending() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    seed_crashed_effectful_step(&mut conn, run_id, "cleanup");

    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: work\n\
         \x20   emit: { a: 1 }\n\
         finally:\n\
         \x20 - id: cleanup\n\
         \x20   tool: shell\n\
         \x20   with: { cmd: [ls] }\n",
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
    .expect("the run drives");

    let RunOutcome::Terminal { state, .. } = outcome else {
        panic!("`finally:` must not park, got {outcome:?}");
    };
    assert_eq!(state, RunState::Failed);
    assert!(host.checkpoints.is_empty(), "no park, so no checkpoint");
    let (row_state, error) = step_row(&conn, run_id, "cleanup");
    assert_eq!(row_state, StepRunState::Failed);
    assert!(
        error.is_some_and(|e| e.contains("finally:")),
        "the row says which block could not park"
    );
}

/// The declared half of the same wiring: `on_crash: fail` on an Effectful
/// step must win over the derived `Ask` default and fail the run closed with
/// **no** park — a regression pin that this task's park did not swallow the
/// one policy that asks for the old behaviour.
#[test]
fn an_indeterminate_effectful_step_with_on_crash_fail_declared_still_fails_closed_without_parking()
{
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    seed_crashed_effectful_step(&mut conn, run_id, "risky");

    let def = parse_workflow(&workflow(
        "steps:\n \x20- id: risky\n \x20  tool: shell\n \x20  on_crash: fail\n \x20  with: { cmd: [ls] }\n",
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
    .expect("the run re-drives");

    let RunOutcome::Terminal { state, .. } = outcome else {
        panic!("a declared `on_crash: fail` fails closed rather than parking, got {outcome:?}");
    };
    assert_eq!(state, RunState::Failed);
    assert!(
        host.checkpoints.is_empty(),
        "an `on_crash: fail` step never parks, so nothing is checkpointed"
    );
    let (row_state, error) = step_row(&conn, run_id, "risky");
    assert_eq!(row_state, StepRunState::Failed);
    assert!(
        error.is_some_and(|e| e.contains("on_crash policy is Fail")),
        "the failure must name the crash policy it refused to silently re-run under"
    );
}

/// The declared half of the same wiring: `on_crash: rerun` on an Effectful
/// step must win over the derived `Ask` default and let the step proceed to
/// ordinary re-dispatch — proving the loop's crash-policy branch honours an
/// author's override in both directions, not just the default it derives.
#[test]
fn an_indeterminate_effectful_step_with_on_crash_rerun_declared_is_re_dispatched_instead() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    roundhouse_flow::durability::checkpoint_step(
        &mut conn,
        &roundhouse_flow::durability::WorkflowStepRun {
            run_id,
            step_id: "risky".to_string(),
            attempt: 1,
            item_index: None,
            disposition: roundhouse_flow::durability::StepDisposition::Effectful,
            state: StepRunState::Running,
            first_task_seq: None,
            last_task_seq: None,
            output: None,
            error: None,
        },
    )
    .expect("seed a Running Effectful row, simulating a crash mid-dispatch");

    let def = parse_workflow(&workflow(
        "steps:\n \x20- id: risky\n \x20  tool: shell\n \x20  on_crash: rerun\n \x20  with: { cmd: [ls] }\n",
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
    .expect("the run re-drives");

    let RunOutcome::AwaitingWork { pending } = outcome else {
        panic!(
            "an on_crash: rerun override must let the step proceed to ordinary re-dispatch, \
             which suspends on the same seam every tool: step suspends on, not fail closed"
        );
    };
    assert_eq!(
        pending.len(),
        1,
        "exactly the one step this run has must be re-dispatched"
    );
    assert_eq!(pending[0].step_id, "risky");
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
    let outcome = run_to_terminal(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        10,
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
        let RunOutcome::AwaitingWork { pending } = outcome else {
            panic!("the funded child awaits driving")
        };
        let roundhouse_flow::exec::run_loop::PendingKind::ChildRun { child_run_id, .. } =
            &pending[0].kind
        else {
            panic!("the call creates pending child work");
        };
        let id = *child_run_id;
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

/// A child must inherit secret provenance from its parent's interpolated
/// `call.with`, even though the child receives the resolved value as `inputs`.
/// The daemon uses this bit to bind the child's whole `inputs` root as secret
/// derived, conservatively redacting any later use rather than leaking it.
#[test]
fn a_calls_secret_derived_with_block_marks_the_child_inputs_secret_derived() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: sub\n\
         \x20   call: child-flow\n\
         \x20   with: { token: \"${{ secrets.TOKEN }}\" }\n",
    ))
    .expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new().resolving("child-flow");
    let mut run_ctx = ctx(run_id);
    run_ctx
        .secrets
        .insert("TOKEN".into(), "sk-child-secret".into());

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
    .expect("the parent reaches child dispatch");

    let RunOutcome::AwaitingWork { pending } = outcome else {
        panic!("the funded child awaits driving");
    };
    let roundhouse_flow::exec::run_loop::PendingKind::ChildRun {
        inputs_secret_derived,
        ..
    } = &pending[0].kind
    else {
        panic!("the call creates pending child work");
    };

    assert!(
        inputs_secret_derived,
        "the child driver must receive the source interpolation's provenance"
    );
}

#[test]
fn secret_derived_inputs_are_redacted_when_a_child_uses_them() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: expose_input\n\
         \x20   emit: { token: \"${{ inputs.token }}\" }\n",
    ))
    .expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let mut run_ctx = ctx(run_id);
    run_ctx.inputs = serde_json::json!({ "token": "sk-child-secret" });
    run_ctx.inputs_secret_derived = true;

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
    .expect("the child run completes");

    assert!(matches!(outcome, RunOutcome::Terminal { .. }));
    let logged = format!("{:?}", sink.emitted);
    assert!(
        !logged.contains("sk-child-secret"),
        "a secret-derived child input must not reach the task log: {logged}"
    );
    assert!(
        logged.contains("***"),
        "the emitted value must be redacted: {logged}"
    );
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
        Some(Resume::Gate(GateAnswer {
            step_id: "second_gate".into(),
            item_index: None,
            output: serde_json::json!({ "ok": true }),
        })),
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

/// §7.7's fan-out ceiling is a **concurrency** bound, not a lifetime quota:
/// a `call:` child that has ended must give its parent's slot back, exactly
/// as it gives its unspent grant back.
///
/// The two halves are deliberately asserted together, because they close the
/// same transfer at the same instant and from the same branch of
/// `finish_run`: the durable one through `refund_child_run`, the runtime one
/// through `WorkflowHost::child_session_terminated`. Before this, only the
/// first existed — `SpawnTree::remove_child` had no caller at all, so eight
/// `call:` children was every `call:` a parent would ever get out of one
/// daemon process, however long ago they finished.
#[test]
fn a_child_run_reaching_a_terminal_state_gives_its_parents_fan_out_slot_back() {
    let mut conn = open_test_db();
    let (parent_id, parent_session) = seed_run(&mut conn);

    let child_id = RunId::new();
    let child_session = SessionId::new();
    let mut child = a_run(child_id, child_session);
    child.parent_run_id = Some(parent_id);
    child.session_depth = Some(1);
    child.caps = Some(ResourceCaps {
        max_tokens: 400,
        ..a_grant()
    });
    insert_workflow_run(&mut conn, &child).expect("the child draws its grant at insert");

    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: alpha\n\
         \x20   emit: { a: 1 }\n",
    ))
    .expect("fixture parses");
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
    .expect("the child run completes");
    let RunOutcome::Terminal { state, .. } = outcome else {
        panic!("no gate");
    };
    assert_eq!(state, RunState::Completed);

    assert_eq!(
        host.terminated,
        vec![(parent_session, child_session)],
        "the ended child's runtime edge is reported against the PARENT's \
         session, which is the key `SpawnTree` indexes children under — not \
         the parent run id, and not the child's own session"
    );
    assert!(
        run_ledger(&conn, child_id).unwrap().refunded_at.is_some(),
        "and the durable half of the same transfer still closes"
    );
}

/// The other half of the same branch: a **root** run reports nothing.
///
/// A root run has no parent session, so there is no edge to drop — and
/// reporting one anyway would hand `SpawnTree::remove_child` a fabricated
/// parent, which at best does nothing and at worst names a real session that
/// happens to have this run's session as a child by some other route.
#[test]
fn a_root_runs_completion_reports_no_child_termination() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);

    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: alpha\n\
         \x20   emit: { a: 1 }\n",
    ))
    .expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        at(10),
        None,
    )
    .expect("the root run completes");

    assert!(
        host.terminated.is_empty(),
        "a run with no parent has no fan-out slot to release, got {:?}",
        host.terminated
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
        Some(Resume::Gate(GateAnswer {
            step_id: "approve".into(),
            item_index: None,
            output: serde_json::json!({ "approve": true }),
        })),
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
        Some(Resume::Gate(GateAnswer {
            step_id: "approve".into(),
            item_index: None,
            output: serde_json::json!({ "approve": true }),
        })),
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

// ---------------------------------------------------------------------------
// A step settled by one segment stays settled in the next
// ---------------------------------------------------------------------------

/// **A `tool:` step that failed in an earlier segment of the same live run
/// must stay failed.** `run_workflow` is re-entered once per
/// [`RunOutcome::AwaitingWork`] suspension — many times within a single,
/// uncrashed run, not just once after a crash — and each re-entry rebuilds
/// its "already finished" set from the durable step rows. A `Failed` row is
/// deliberately not in that set (§8.10 tier 2 re-decides one left behind by
/// a *previous, crashed* run) and is not `Indeterminate` either, so nothing
/// used to stop a later segment re-admitting and re-dispatching a step this
/// very drive had already settled — discarding, on the way, the completed
/// answer it was handed for the step it actually suspended on.
///
/// The failing step is **first** in `steps:` here and last-but-one in
/// [`a_step_that_failed_with_continue_on_error_stays_failed_across_segments`],
/// per this file's fixture convention.
#[test]
fn a_step_that_failed_in_an_earlier_segment_is_not_re_decided_by_a_later_one() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: a\n\
         \x20   tool: write\n\
         \x20   with: { path: out.txt, content: hi }\n\
         \x20 - id: b\n\
         \x20   tool: read\n\
         \x20   with: { path: out.txt }\n\
         finally:\n\
         \x20 - id: f1\n\
         \x20   tool: read\n\
         \x20   with: { path: one }\n\
         \x20 - id: f2\n\
         \x20   tool: read\n\
         \x20   with: { path: two }\n",
    ))
    .expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let outcome = run_to_terminal_failing(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        10,
        None,
        &["a"],
    )
    .expect("the run drives");

    let RunOutcome::Terminal { state, .. } = outcome else {
        panic!("the run must reach a terminal state, got {outcome:?}")
    };
    assert_eq!(state, RunState::Failed);

    // The failure that actually happened, recorded once — not the
    // "admission refused" a re-decided step eventually produces when it has
    // burned through the run's grant suspending on itself.
    let (a_state, a_error) = step_row(&conn, run_id, "a");
    assert_eq!(a_state, StepRunState::Failed);
    assert!(
        a_error
            .as_deref()
            .is_some_and(|e| e.contains("the caller could not dispatch")),
        "the step's row must keep the failure the caller reported, got {a_error:?}"
    );

    assert_eq!(
        step_row(&conn, run_id, "b").0,
        StepRunState::Skipped,
        "stop-on-failure still holds on the segment that inherits the failure"
    );
    assert_eq!(step_row(&conn, run_id, "f1").0, StepRunState::Completed);
    assert_eq!(
        step_row(&conn, run_id, "f2").0,
        StepRunState::Completed,
        "the `finally:` step answered by the previous segment must not have \
         its answer discarded"
    );

    // Three admitted steps — `a`, `f1`, `f2` — each charged exactly once.
    // `b` never ran, so it was never admitted.
    let spent = run_ledger(&conn, run_id).unwrap().spent;
    assert_eq!(
        (spent.tasks, spent.tool_calls),
        (3, 3),
        "a step re-decided by a later segment is re-admitted, and double-charges the ledger"
    );
}

/// The same defect with `continue_on_error: true`, which needs no
/// `finally:` block at all: the later suspension is an ordinary `steps:`
/// step that runs *after* the failed one, in the same phase.
#[test]
fn a_step_that_failed_with_continue_on_error_stays_failed_across_segments() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: a\n\
         \x20   tool: read\n\
         \x20   with: { path: one }\n\
         \x20 - id: b\n\
         \x20   tool: write\n\
         \x20   continue_on_error: true\n\
         \x20   with: { path: out.txt, content: hi }\n\
         \x20 - id: c\n\
         \x20   tool: read\n\
         \x20   with: { path: two }\n",
    ))
    .expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let outcome = run_to_terminal_failing(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        ctx(run_id),
        10,
        None,
        &["b"],
    )
    .expect("the run drives");

    let RunOutcome::Terminal { state, .. } = outcome else {
        panic!("the run must reach a terminal state, got {outcome:?}")
    };
    assert_eq!(
        state,
        RunState::Completed,
        "`continue_on_error` makes b's failure data, not control flow"
    );
    assert_eq!(step_row(&conn, run_id, "a").0, StepRunState::Completed);
    assert_eq!(step_row(&conn, run_id, "b").0, StepRunState::Failed);
    assert_eq!(
        step_row(&conn, run_id, "c").0,
        StepRunState::Completed,
        "the step answered by the previous segment must not have its answer discarded"
    );
    let spent = run_ledger(&conn, run_id).unwrap().spent;
    assert_eq!((spent.tasks, spent.tool_calls), (3, 3));
}

/// The other half of the same discriminator, and the property the fix above
/// must not cost: a `Failed` row found on a **cold** entry — no
/// [`Resume::Work`] to carry, which is how a driver recovering a run after a
/// restart necessarily enters — is still re-decided, exactly as §8.10 tier 2
/// and `finished_step_rows`' own doc comment require.
#[test]
fn a_failed_row_from_a_previous_crashed_run_is_still_re_decided_on_a_cold_entry() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    // The state a daemon that died after this step failed leaves behind.
    roundhouse_flow::durability::checkpoint_step(
        &mut conn,
        &roundhouse_flow::durability::WorkflowStepRun {
            run_id,
            step_id: "a".to_string(),
            attempt: 1,
            item_index: None,
            disposition: roundhouse_flow::durability::StepDisposition::Pure,
            state: StepRunState::Failed,
            first_task_seq: None,
            last_task_seq: None,
            output: None,
            error: Some("the previous process reported this".into()),
        },
    )
    .expect("checkpoint the failed step");

    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: a\n\
         \x20   tool: read\n\
         \x20   with: { path: one }\n\
         \x20 - id: b\n\
         \x20   tool: read\n\
         \x20   with: { path: two }\n",
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
    .expect("the run drives");

    match outcome {
        RunOutcome::AwaitingWork { pending } => assert_eq!(
            pending
                .iter()
                .map(|p| p.step_id.as_str())
                .collect::<Vec<_>>(),
            vec!["a"],
            "a cold entry must re-dispatch the failed step, not inherit its row"
        ),
        other => panic!("the failed step must be re-decided, not inherited: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// `map:` wave dispatch — Phase 8 Task 25.7 (#64) Task 2
//
// Before this, `StepBody::Map` was dispatched entirely inside
// `Executor::dispatch_step`, whose inner-step loop called
// `Executor::dispatch_step_or_stub` — so a `tool:`/`agent:` step nested in a
// `map` fabricated a `{}` `Completed` outcome and never reached the real
// suspend/resume seam at all. These tests drive a `map` through
// `run_workflow` and assert on the waves it hands back.
// ---------------------------------------------------------------------------

/// One wave of a `map:` fan-out, as its caller saw it: the
/// `(step_id, item_index)` pairs one `RunOutcome::AwaitingWork` asked to have
/// dispatched.
type Wave = Vec<(String, Option<u32>)>;

/// Drives a workflow to a terminal state, recording every wave and failing
/// exactly the `(step_id, item_index)` pairs named in `failing`.
///
/// Unlike [`run_to_terminal_failing`], which fails a whole step id across
/// every item, this fails **one item of one inner step** and leaves its
/// siblings succeeding — the shape every per-item `on_item_error` assertion
/// below needs.
fn drive_waves(
    body: &str,
    inputs: Value,
    failing: &[(&str, u32)],
) -> (
    Connection,
    RunId,
    RecordingSink,
    Vec<Wave>,
    Result<RunOutcome, RunLoopError>,
) {
    drive_waves_with_context(body, failing, |run_ctx| run_ctx.inputs = inputs)
}

fn drive_waves_with_context(
    body: &str,
    failing: &[(&str, u32)],
    configure: impl FnOnce(&mut RunContext),
) -> (
    Connection,
    RunId,
    RecordingSink,
    Vec<Wave>,
    Result<RunOutcome, RunLoopError>,
) {
    drive_waves_with_grant(body, failing, a_grant(), configure)
}

/// [`drive_waves_with_context`], against a run whose grant is `grant` rather
/// than [`a_grant`]'s.
///
/// The per-item ceiling a `map` enforces is a *share* of what the run has
/// left, so a test that wants a small share asks for a small grant rather than
/// for an implausible number of items.
fn drive_waves_with_grant(
    body: &str,
    failing: &[(&str, u32)],
    grant: ResourceCaps,
    configure: impl FnOnce(&mut RunContext),
) -> (
    Connection,
    RunId,
    RecordingSink,
    Vec<Wave>,
    Result<RunOutcome, RunLoopError>,
) {
    use roundhouse_flow::exec::run_loop::{PendingKind, WorkDone, WorkStatus};

    let mut conn = open_test_db();
    let run_id = RunId::new();
    let mut run = a_run(run_id, SessionId::new());
    run.caps = Some(grant);
    insert_workflow_run(&mut conn, &run).expect("seed the run row");
    let def = parse_workflow(&workflow(body)).expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let mut run_ctx = ctx(run_id);
    configure(&mut run_ctx);

    let mut waves: Vec<Wave> = Vec::new();
    let mut resume: Option<Resume> = None;
    let mut segments = 0usize;
    loop {
        segments += 1;
        assert!(
            segments <= MAX_SEGMENTS,
            "the run has been re-entered {segments} times without reaching a terminal state: \
             an item settled by an earlier wave is being re-decided by a later one. Waves so \
             far: {waves:?}"
        );
        let outcome = match run_workflow(
            &mut conn,
            &def,
            run_id,
            &mut sink,
            &mut host,
            run_ctx.clone(),
            at(10),
            resume.take(),
        ) {
            Ok(outcome) => outcome,
            Err(e) => return (conn, run_id, sink, waves, Err(e)),
        };
        let pending = match outcome {
            RunOutcome::AwaitingWork { pending } => pending,
            other => return (conn, run_id, sink, waves, Ok(other)),
        };
        waves.push(
            pending
                .iter()
                .map(|p| (p.step_id.clone(), p.item_index))
                .collect(),
        );
        let mut done = Vec::with_capacity(pending.len());
        for p in pending {
            let task_id = TaskId::new();
            match &p.kind {
                PendingKind::Tool {
                    task_kind,
                    logged_input,
                    ..
                } => sink.emit(
                    task_id,
                    None,
                    task_kind.clone(),
                    EventPayload::TaskCreated {
                        kind: task_kind.clone(),
                        parent: None,
                        origin: Origin::System,
                        input: TaskInput::Json(logged_input.clone()),
                    },
                ),
                PendingKind::Agent { logged_prompt, .. } => sink.emit(
                    task_id,
                    None,
                    TaskKind::Agent,
                    EventPayload::TaskCreated {
                        kind: TaskKind::Agent,
                        parent: None,
                        origin: Origin::System,
                        input: TaskInput::Json(logged_prompt.clone()),
                    },
                ),
                PendingKind::ChildRun { .. } => {
                    panic!("no fixture in this section declares a `call:`")
                }
            }
            let fails = failing
                .iter()
                .any(|(id, idx)| *id == p.step_id && p.item_index == Some(*idx));
            done.push(WorkDone {
                step_id: p.step_id.clone(),
                item_index: p.item_index,
                status: if fails {
                    WorkStatus::Failed {
                        message: format!(
                            "item {:?} of {:?} could not be dispatched",
                            p.item_index, p.step_id
                        ),
                    }
                } else {
                    WorkStatus::Completed
                },
                output: serde_json::json!({ "dispatched": p.item_index }),
                output_is_secret_derived: false,
                task_id: Some(task_id),
                first_task_seq: None,
                last_task_seq: None,
            });
        }
        resume = Some(Resume::Work(done));
    }
}

/// The `map` step's own aggregate output, read off the terminal outcome.
fn map_output(outcome: &RunOutcome, step_id: &str) -> Value {
    let RunOutcome::Terminal { steps, .. } = outcome else {
        panic!("the run must reach a terminal state, got {outcome:?}");
    };
    steps
        .iter()
        .find(|s| s.step_id == step_id)
        .unwrap_or_else(|| panic!("no outcome for map step {step_id:?}"))
        .output
        .clone()
}

fn shell_tasks(sink: &RecordingSink) -> usize {
    sink.kinds()
        .iter()
        .filter(|k| **k == TaskKind::Shell)
        .count()
}

/// A `map` whose one inner step is a real `tool:` — the shape that used to be
/// stubbed out entirely.
fn map_over_tool(max_parallel: u32, on_item_error: &str) -> String {
    format!(
        "steps:\n\
         \x20 - id: fan\n\
         \x20   map:\n\
         \x20     over: \"${{{{ inputs.items }}}}\"\n\
         \x20     as: item\n\
         \x20     max_parallel: {max_parallel}\n\
         \x20     on_item_error: {on_item_error}\n\
         \x20   steps:\n\
         \x20     - id: build\n\
         \x20       tool: shell\n\
         \x20       with: {{ cmd: [echo, \"${{{{ item }}}}\"] }}\n"
    )
}

fn map_items(n: usize) -> Value {
    Value::Array((0..n).map(|i| serde_json::json!(i)).collect())
}

/// **The whole point of this task.** A `tool:` step nested in a `map` must
/// reach the same suspend/resume seam a top-level one does, once per item,
/// carrying its own `item_index` — not be answered by
/// `dispatch_step_or_stub`'s fabricated `{}`.
#[test]
fn a_maps_inner_tool_step_suspends_per_item_instead_of_being_stubbed() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(&map_over_tool(2, "continue"))).expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let mut run_ctx = ctx(run_id);
    run_ctx.inputs = serde_json::json!({ "items": map_items(2) });

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

    let RunOutcome::AwaitingWork { pending } = outcome else {
        panic!("a `map`'s inner `tool:` step must reach real dispatch, got {outcome:?}");
    };
    assert_eq!(pending.len(), 2, "both items are in the first wave");
    assert!(
        pending.iter().all(|p| p.step_id == "build"),
        "every entry names the inner step, not the map: {pending:?}"
    );
    let mut indices: Vec<Option<u32>> = pending.iter().map(|p| p.item_index).collect();
    indices.sort();
    assert_eq!(
        indices,
        vec![Some(0), Some(1)],
        "each item's pending work carries its own index — the field `PendingWork::item_index` \
         was documented as 'always None today' until this task"
    );
}

/// `max_parallel` is a real ceiling on one wave, and the fan-out still
/// finishes: five items at two-at-a-time is `[2, 2, 1]`, never `[5]`.
#[test]
fn max_parallel_bounds_one_waves_size_and_the_map_still_finishes() {
    let (_conn, _run_id, sink, waves, result) = drive_waves(
        &map_over_tool(2, "continue"),
        serde_json::json!({ "items": map_items(5) }),
        &[],
    );
    let outcome = result.expect("the run drives");

    assert_eq!(
        waves.iter().map(Vec::len).collect::<Vec<_>>(),
        vec![2, 2, 1],
        "`max_parallel: 2` caps each wave at two entries: {waves:?}"
    );
    let mut dispatched: Vec<Option<u32>> = waves.iter().flatten().map(|(_, i)| *i).collect();
    dispatched.sort();
    assert_eq!(
        dispatched,
        vec![Some(0), Some(1), Some(2), Some(3), Some(4)],
        "every item is dispatched exactly once across the waves: {waves:?}"
    );
    assert_eq!(
        shell_tasks(&sink),
        5,
        "one real shell task per item — no item is re-dispatched by a later wave"
    );

    let output = map_output(&outcome, "fan");
    let entries = output["items"].as_array().expect("one entry per item");
    assert_eq!(entries.len(), 5);
    assert!(
        entries.iter().all(|e| e["status"] == "completed"),
        "every item completed: {entries:?}"
    );
}

/// `max_parallel: 1` is the sequential case, and it is where a per-item
/// cursor that failed to reconstruct from the durable rows would show up as
/// an item's first inner step being dispatched twice.
#[test]
fn a_two_step_item_advances_one_inner_step_per_wave_without_re_dispatching() {
    let (_conn, _run_id, sink, waves, result) = drive_waves(
        "steps:\n\
         \x20 - id: fan\n\
         \x20   map:\n\
         \x20     over: \"${{ inputs.items }}\"\n\
         \x20     as: item\n\
         \x20     max_parallel: 1\n\
         \x20   steps:\n\
         \x20     - id: build\n\
         \x20       tool: shell\n\
         \x20       with: { cmd: [echo, build] }\n\
         \x20     - id: publish\n\
         \x20       tool: shell\n\
         \x20       with: { cmd: [echo, publish] }\n",
        serde_json::json!({ "items": map_items(2) }),
        &[],
    );
    let outcome = result.expect("the run drives");

    assert_eq!(
        waves,
        vec![
            vec![("build".to_string(), Some(0))],
            vec![("publish".to_string(), Some(0))],
            vec![("build".to_string(), Some(1))],
            vec![("publish".to_string(), Some(1))],
        ],
        "each wave advances the one in-flight item by exactly one inner step"
    );
    assert_eq!(
        shell_tasks(&sink),
        4,
        "two items x two inner steps, each dispatched once"
    );
    let output = map_output(&outcome, "fan");
    assert_eq!(output["items"].as_array().expect("items").len(), 2);
}

/// A `map` step is one step of the run, so §8.4's admission charges it once —
/// however many waves it takes. Proven by comparing two runs of the same
/// fixture that differ only in wave count.
#[test]
fn a_map_step_is_admitted_once_however_many_waves_it_takes() {
    let (sequential_conn, sequential_run, _, sequential_waves, sequential) = drive_waves(
        &map_over_tool(1, "continue"),
        serde_json::json!({ "items": map_items(4) }),
        &[],
    );
    let (parallel_conn, parallel_run, _, parallel_waves, parallel) = drive_waves(
        &map_over_tool(4, "continue"),
        serde_json::json!({ "items": map_items(4) }),
        &[],
    );
    sequential.expect("the sequential run drives");
    parallel.expect("the parallel run drives");

    assert_eq!(sequential_waves.len(), 4, "one item per wave");
    assert_eq!(parallel_waves.len(), 1, "all four items in one wave");

    let sequential_ledger = run_ledger(&sequential_conn, sequential_run).expect("ledger");
    let parallel_ledger = run_ledger(&parallel_conn, parallel_run).expect("ledger");
    assert_eq!(
        sequential_ledger.spent.tasks, parallel_ledger.spent.tasks,
        "a `map` re-admitted once per wave would charge four tasks in the sequential run and \
         one in the parallel one"
    );
}

/// The same invariant for a `map` that declares an `idempotency_key:`, which
/// makes it `Idempotent` rather than `Effectful` — so `recover_run` leaves its
/// row `Running` and never reclassifies it `Indeterminate`. A "this map is
/// mid-flight" test keyed on the reclassification alone would miss exactly
/// these, and re-admit one per wave.
#[test]
fn a_map_with_an_idempotency_key_is_also_admitted_only_once_across_waves() {
    let fixture = |max_parallel: u32| {
        format!(
            "steps:\n\
             \x20 - id: fan\n\
             \x20   idempotency_key: \"fan-once\"\n\
             \x20   map:\n\
             \x20     over: \"${{{{ inputs.items }}}}\"\n\
             \x20     as: item\n\
             \x20     max_parallel: {max_parallel}\n\
             \x20   steps:\n\
             \x20     - id: build\n\
             \x20       tool: shell\n\
             \x20       with: {{ cmd: [echo, hi] }}\n"
        )
    };
    let (sequential_conn, sequential_run, _, sequential_waves, sequential) = drive_waves(
        &fixture(1),
        serde_json::json!({ "items": map_items(4) }),
        &[],
    );
    let (parallel_conn, parallel_run, _, parallel_waves, parallel) = drive_waves(
        &fixture(4),
        serde_json::json!({ "items": map_items(4) }),
        &[],
    );
    sequential.expect("the sequential run drives");
    parallel.expect("the parallel run drives");

    assert_eq!(sequential_waves.len(), 4);
    assert_eq!(parallel_waves.len(), 1);
    assert_eq!(
        run_ledger(&sequential_conn, sequential_run)
            .expect("ledger")
            .spent
            .tasks,
        run_ledger(&parallel_conn, parallel_run)
            .expect("ledger")
            .spent
            .tasks,
    );
}

/// §8.9's `fail_fast` stops the fan-out. Under waves the cutover point is
/// *starting a new item*: item 0 fails, so items 1 and 2 are never dispatched
/// at all and are recorded `Skipped` rather than dropped.
#[test]
fn fail_fast_stops_pulling_new_items_into_later_waves() {
    let (_conn, _run_id, sink, waves, result) = drive_waves(
        &map_over_tool(1, "fail_fast"),
        serde_json::json!({ "items": map_items(3) }),
        &[("build", 0)],
    );
    let outcome = result.expect("the run drives");

    assert_eq!(
        waves,
        vec![vec![("build".to_string(), Some(0))]],
        "only the first item is ever dispatched: {waves:?}"
    );
    assert_eq!(shell_tasks(&sink), 1);

    let output = map_output(&outcome, "fan");
    let entries = output["items"].as_array().expect("one entry per item");
    assert_eq!(entries.len(), 3, "§8.9: never drop an item");
    assert_eq!(entries[0]["status"], "failed");
    for entry in &entries[1..] {
        assert_eq!(entry["status"], "skipped");
        assert!(
            entry["reason"]
                .as_str()
                .is_some_and(|r| r.contains("fail_fast")),
            "an item the fan-out never started says so: {entry:?}"
        );
    }
}

/// **`fail_fast` must not discard work that already ran.** With
/// `max_parallel: 1` only one item is ever in flight, so the failing item is
/// always the only one with an answer outstanding. At `max_parallel: 3` all
/// three items are dispatched together and all three really run — so an
/// implementation that stops replaying items the moment the first failure is
/// observed drops two items' answers on the floor and backfills them
/// `skipped`, producing a `map` output that contradicts its own event log
/// (three `TaskCreated`, one item reported as having run).
///
/// The cutover point is *starting a new item*, which is §8.9's own wording
/// ("stop dispatching further **items**") — an item already started finishes.
#[test]
fn fail_fast_still_records_an_already_dispatched_items_real_outcome() {
    let (_conn, _run_id, sink, waves, result) = drive_waves(
        &map_over_tool(3, "fail_fast"),
        serde_json::json!({ "items": map_items(3) }),
        &[("build", 0)],
    );
    let outcome = result.expect("the run drives");

    assert_eq!(
        waves.iter().map(Vec::len).collect::<Vec<_>>(),
        vec![3],
        "all three items are in flight before any of them can fail: {waves:?}"
    );
    assert_eq!(shell_tasks(&sink), 3, "all three really dispatched");

    let output = map_output(&outcome, "fan");
    let entries = output["items"].as_array().expect("one entry per item");
    assert_eq!(
        entries
            .iter()
            .map(|e| e["status"].as_str().unwrap_or("?"))
            .collect::<Vec<_>>(),
        vec!["failed", "completed", "completed"],
        "items 1 and 2 ran and succeeded — reporting them `skipped` would throw away real \
         work and contradict the three tasks in the log: {entries:?}"
    );
}

/// The cutover point, named: an item already started runs to **completion**,
/// not merely to the end of the round trip that was outstanding when the
/// failure was seen. Three items of two inner steps each, all three in flight
/// on the first step when item 0 fails — items 1 and 2 go on to dispatch
/// their *second* inner step, and no fourth item is ever started because
/// there isn't one to start.
///
/// Stated as a test rather than only in prose because the alternative (stop
/// an in-flight item at its current step and record what it had) is also
/// defensible, and the two differ in how many tasks reach the log.
#[test]
fn fail_fast_lets_an_already_started_item_finish_its_remaining_inner_steps() {
    let (_conn, _run_id, sink, waves, result) = drive_waves(
        "steps:\n\
         \x20 - id: fan\n\
         \x20   map:\n\
         \x20     over: \"${{ inputs.items }}\"\n\
         \x20     as: item\n\
         \x20     max_parallel: 3\n\
         \x20     on_item_error: fail_fast\n\
         \x20   steps:\n\
         \x20     - id: build\n\
         \x20       tool: shell\n\
         \x20       with: { cmd: [echo, build] }\n\
         \x20     - id: publish\n\
         \x20       tool: shell\n\
         \x20       with: { cmd: [echo, publish] }\n",
        serde_json::json!({ "items": map_items(3) }),
        &[("build", 0)],
    );
    let outcome = result.expect("the run drives");

    assert_eq!(
        waves.iter().map(Vec::len).collect::<Vec<_>>(),
        vec![3, 2],
        "three items start together; after item 0 fails the other two advance to their \
         second inner step, and nothing new is started: {waves:?}"
    );
    assert_eq!(shell_tasks(&sink), 5, "3 builds + 2 publishes");
    let output = map_output(&outcome, "fan");
    let entries = output["items"].as_array().expect("one entry per item");
    assert_eq!(
        entries
            .iter()
            .map(|e| e["status"].as_str().unwrap_or("?"))
            .collect::<Vec<_>>(),
        vec!["failed", "completed", "completed"]
    );
}

/// **§8.13's cooperative cancel has to be observed once per wave, not once
/// per `map`.** `Loop::admit` is the one in-phase observer of a `Cancelling`
/// run, and a `map` mid-fan-out deliberately skips admission on every wave
/// after its first so the ledger is not charged again — so without a second,
/// zero-charge observation an operator's cancel is invisible to the map, and
/// a 2,000-item fan-out at `max_parallel: 1` would issue ~2,000 further real
/// dispatches before the *next* step's admission finally drained the run.
#[test]
fn a_cancel_between_waves_stops_a_mid_flight_map_from_dispatching_more() {
    use roundhouse_flow::exec::run_loop::{WorkDone, WorkStatus};

    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(&map_over_tool(1, "continue"))).expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let mut run_ctx = ctx(run_id);
    run_ctx.inputs = serde_json::json!({ "items": map_items(4) });

    let first = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx.clone(),
        at(10),
        None,
    )
    .expect("the run drives");
    let RunOutcome::AwaitingWork { pending } = first else {
        panic!("the first wave dispatches item 0, got {first:?}");
    };
    assert_eq!(pending.len(), 1, "one item per wave at `max_parallel: 1`");
    let answer = vec![WorkDone {
        step_id: pending[0].step_id.clone(),
        item_index: pending[0].item_index,
        status: WorkStatus::Completed,
        output: serde_json::json!({}),
        output_is_secret_derived: false,
        task_id: Some(TaskId::new()),
        first_task_seq: None,
        last_task_seq: None,
    }];

    // An operator cancels while the wave is out — the one window in which
    // nothing inside the loop is looking.
    transition_run(&mut conn, run_id, RunState::Cancelling, at(11)).expect("the cancel lands");

    let second = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx,
        at(12),
        Some(Resume::Work(answer)),
    )
    .expect("the run drives");

    match second {
        RunOutcome::Terminal { state, .. } => assert_eq!(
            state,
            RunState::Cancelled,
            "the cancel drains at the map rather than three waves later"
        ),
        other => panic!("a cancelled run must not dispatch another wave, got {other:?}"),
    }
    assert_eq!(
        recover_run(&conn, run_id).unwrap().run.state,
        RunState::Cancelled
    );
}

/// **A crashed run must not silently re-run a `map` item's in-flight
/// `Effectful` inner step.** §8.10 tier 2 gives a top-level step an
/// `on_crash` policy consulted on its own cold-entry re-decision; before this
/// fix a `map` item's inner step bypassed that entirely and simply re-ran —
/// which, now that the dispatch is real, means a `shell` step that may
/// already have executed once executes again, at-least-once, with nothing
/// recorded and no operator asked.
///
/// Driven the way it really happens: one wave goes out, the daemon dies, the
/// run is re-driven cold (so the *map step itself* parks on §8.10's `ask`),
/// the human answers `rerun`, and only then is the item's own interrupted
/// inner step reached.
#[test]
fn a_crashed_maps_in_flight_effectful_inner_step_is_not_silently_re_run() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(&map_over_tool(1, "continue"))).expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let mut run_ctx = ctx(run_id);
    run_ctx.inputs = serde_json::json!({ "items": map_items(2) });

    let first = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx.clone(),
        at(10),
        None,
    )
    .expect("the run drives");
    assert!(
        matches!(first, RunOutcome::AwaitingWork { .. }),
        "item 0's `tool: shell` step is dispatched and the daemon then dies"
    );

    // The cold re-drive: no `Resume`, exactly as a recovered run is
    // re-entered. The `map` step's own row is `Indeterminate`, so §8.10's
    // `ask` parks before anything re-runs.
    let recovered = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx.clone(),
        at(20),
        None,
    )
    .expect("the run drives");
    assert!(
        matches!(recovered, RunOutcome::Parked(_)),
        "an interrupted `map` asks before anything re-runs, got {recovered:?}"
    );

    // The human says "rerun the map" — which re-drives the fan-out, and is
    // where the item's own interrupted inner step is finally reached. Item 1
    // was never started, so it still dispatches normally; `run_to_terminal`
    // answers its wave the way the daemon would.
    let before_rerun = shell_tasks(&sink);
    let resumed = run_to_terminal(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx,
        30,
        Some(Resume::CrashRecovery(CrashRecoveryAnswer {
            step_id: "fan".to_string(),
            resolution: CrashResolution::Rerun,
        })),
    )
    .expect("the run drives");

    let RunOutcome::Terminal { steps, .. } = &resumed else {
        panic!(
            "item 0's interrupted `shell` step must not be re-dispatched without a policy \
             that permits it, got {resumed:?}"
        );
    };
    let map = steps.iter().find(|s| s.step_id == "fan").expect("the map");
    let entries = map.output["items"].as_array().expect("one entry per item");
    assert_eq!(entries[0]["status"], "failed");
    let error = entries[0]["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("interrupted mid-dispatch") && error.contains("on_crash"),
        "the refusal names what is unsupported, the way `isolation: worktree` across a \
         suspend does: {error:?}"
    );
    assert_eq!(
        entries[1]["status"], "completed",
        "item 1 was never started before the crash, so it runs normally"
    );
    assert_eq!(
        shell_tasks(&sink) - before_rerun,
        1,
        "exactly one further shell task — item 1's. Item 0's interrupted one is refused, \
         not dispatched a second time"
    );
}

/// `collect` keeps dispatching every item and gathers each failure's message
/// onto the map step's own output — across waves, once each, in item order.
#[test]
fn on_item_error_collect_gathers_every_failing_items_message_across_waves() {
    let (_conn, _run_id, sink, waves, result) = drive_waves(
        &map_over_tool(2, "collect"),
        serde_json::json!({ "items": map_items(4) }),
        &[("build", 0), ("build", 3)],
    );
    let outcome = result.expect("the run drives");

    assert_eq!(waves.iter().map(Vec::len).sum::<usize>(), 4);
    assert_eq!(shell_tasks(&sink), 4, "`collect` dispatches every item");

    let output = map_output(&outcome, "fan");
    let entries = output["items"].as_array().expect("one entry per item");
    assert_eq!(
        entries
            .iter()
            .map(|e| e["status"].as_str().unwrap_or("?"))
            .collect::<Vec<_>>(),
        vec!["failed", "completed", "completed", "failed"],
        "the failing entry is first in one place and last in another (ruling P92)"
    );
    let collected = output["collected_errors"]
        .as_array()
        .expect("collected_errors");
    assert_eq!(
        collected.len(),
        2,
        "each failure is collected exactly once, not once per wave it was replayed in: \
         {collected:?}"
    );
}

/// A `map` whose inner steps are all pure still resolves in one call —
/// nothing about moving dispatch into the run loop makes a `map` suspend when
/// it has nothing to suspend on.
#[test]
fn a_map_over_pure_inner_steps_still_completes_without_suspending() {
    let (_conn, _run_id, _sink, waves, result) = drive_waves(
        "steps:\n\
         \x20 - id: fan\n\
         \x20   map:\n\
         \x20     over: \"${{ inputs.items }}\"\n\
         \x20     as: item\n\
         \x20   steps:\n\
         \x20     - id: note\n\
         \x20       emit: { saw: \"${{ item }}\" }\n",
        serde_json::json!({ "items": map_items(3) }),
        &[],
    );
    let outcome = result.expect("the run drives");
    assert!(waves.is_empty(), "a pure `map` never suspends: {waves:?}");
    let output = map_output(&outcome, "fan");
    let entries = output["items"].as_array().expect("one entry per item");
    assert_eq!(entries.len(), 3);
    assert!(entries.iter().all(|e| e["status"] == "completed"));
}

/// An inner step's own `when:` gate still decides before dispatch — moving
/// the inner loop into `Loop` must not reintroduce the fail-open defect Task
/// 14's fix round 2 closed (`evaluate_when_gate` is still the one evaluator).
#[test]
fn an_inner_steps_when_gate_still_skips_the_dispatch_from_inside_the_run_loop() {
    let (_conn, _run_id, sink, waves, result) = drive_waves(
        "steps:\n\
         \x20 - id: fan\n\
         \x20   map:\n\
         \x20     over: \"${{ inputs.items }}\"\n\
         \x20     as: item\n\
         \x20   steps:\n\
         \x20     - id: guarded\n\
         \x20       when: \"${{ inputs.approved }}\"\n\
         \x20       tool: shell\n\
         \x20       with: { cmd: [rm, -rf, /] }\n",
        serde_json::json!({ "items": map_items(2), "approved": false }),
        &[],
    );
    let outcome = result.expect("the run drives");
    assert!(
        waves.is_empty(),
        "a `when: false` inner step must never reach dispatch: {waves:?}"
    );
    assert_eq!(shell_tasks(&sink), 0, "zero sink events, counted");
    let output = map_output(&outcome, "fan");
    let entries = output["items"].as_array().expect("one entry per item");
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|e| e["status"] == "skipped"));
}

/// **A `when:` gate's taint has to survive the suspension it caused.** An
/// inner step's `gate_condition_was_secret_derived` is computed on the
/// segment that dispatches it and folded into the `map`'s one aggregate
/// (`dispatch_map_step`'s fix round 3, item 1) — but `WorkDone` has no field
/// for it, so a gate that reads a secret and *then* suspends would have lost
/// the bit at the wave boundary and let the map's output reach a dependent
/// unredacted.
///
/// Measured against the same gate the top-level case is pinned with:
/// `${{ secrets.K == '…' }}` guarding a step whose own output is clean, with
/// the gate true so the step really does dispatch and really does suspend.
#[test]
fn an_inner_steps_secret_derived_gate_still_taints_the_map_after_a_suspension() {
    let body = "steps:\n\
         \x20 - id: fan\n\
         \x20   map:\n\
         \x20     over: \"${{ inputs.items }}\"\n\
         \x20     as: item\n\
         \x20     max_parallel: 1\n\
         \x20   steps:\n\
         \x20     - id: build\n\
         \x20       when: \"${{ secrets.K == 'yesyesyesyes' }}\"\n\
         \x20       tool: shell\n\
         \x20       with: { cmd: [echo, hi] }\n";
    let (_conn, _run_id, _sink, waves, result) = drive_waves_with_context(body, &[], |run_ctx| {
        run_ctx.inputs = serde_json::json!({ "items": map_items(2) });
        run_ctx
            .secrets
            .insert("K".to_string(), "yesyesyesyes".to_string());
    });
    let outcome = result.expect("the run drives");

    assert_eq!(
        waves.len(),
        2,
        "the gate is true, so each item really does dispatch and suspend: {waves:?}"
    );
    let RunOutcome::Terminal { steps, .. } = &outcome else {
        panic!("the run must reach a terminal state, got {outcome:?}");
    };
    let map = steps.iter().find(|s| s.step_id == "fan").expect("the map");
    assert!(
        map.output_is_secret_derived,
        "the gate read `secrets.K`, so the map's own output is secret-derived — the bit is \
         parked on the suspended step's own row and carried back when its answer arrives"
    );
}

/// A `WorktreeProvider` that hands out distinct fake paths and counts both
/// halves of the lifecycle, so a test can prove a worktree is never
/// materialized twice for one item and never leaked.
#[derive(Default)]
struct CountingWorktreeProvider {
    materialized: std::sync::Mutex<Vec<std::path::PathBuf>>,
    released: std::sync::Mutex<Vec<std::path::PathBuf>>,
}

impl roundhouse_flow::worktree::WorktreeProvider for CountingWorktreeProvider {
    fn materialize(
        &self,
        _base_ref: &str,
    ) -> Result<std::path::PathBuf, roundhouse_flow::worktree::WorktreeProviderError> {
        let mut made = self.materialized.lock().expect("not poisoned");
        let path = std::path::PathBuf::from(format!("/fake/worktree/{}", made.len()));
        made.push(path.clone());
        Ok(path)
    }

    fn release(
        &self,
        worktree_path: &std::path::Path,
    ) -> Result<(), roundhouse_flow::worktree::WorktreeProviderError> {
        self.released
            .lock()
            .expect("not poisoned")
            .push(worktree_path.to_path_buf());
        Ok(())
    }
}

/// **The worktree-across-suspend boundary, failed closed rather than
/// silently re-materialized.** A worktree guard's lifetime is one synchronous
/// call, and `Loop`/`Executor` are rebuilt fresh on every re-entry — so an
/// item that suspended inside its own worktree would come back bound to a
/// *different* path. Refused per item, with the reason named, and the
/// worktree that was materialized is still released.
#[test]
fn an_items_worktree_cannot_span_a_suspend_and_says_so_rather_than_re_materializing() {
    let provider = Arc::new(CountingWorktreeProvider::default());
    let (_conn, _run_id, sink, waves, result) = drive_waves_with_context(
        "steps:\n\
         \x20 - id: fan\n\
         \x20   map:\n\
         \x20     over: \"${{ inputs.items }}\"\n\
         \x20     as: item\n\
         \x20     on_item_error: continue\n\
         \x20     isolation: worktree\n\
         \x20   steps:\n\
         \x20     - id: build\n\
         \x20       tool: shell\n\
         \x20       with: { cmd: [echo, hi] }\n",
        &[],
        |run_ctx| {
            run_ctx.inputs = serde_json::json!({ "items": map_items(2) });
            run_ctx.worktree_provider = Some(provider.clone());
        },
    );
    let outcome = result.expect("the run drives");

    assert!(
        waves.is_empty(),
        "an item that would suspend inside its worktree is refused, never dispatched: {waves:?}"
    );
    assert_eq!(shell_tasks(&sink), 0);

    let output = map_output(&outcome, "fan");
    let entries = output["items"].as_array().expect("one entry per item");
    assert_eq!(entries.len(), 2);
    for entry in entries {
        assert_eq!(entry["status"], "failed");
        assert!(
            entry["error"]
                .as_str()
                .is_some_and(|e| e.contains("isolation: worktree") && e.contains("suspend")),
            "the refusal names exactly what is unsupported: {entry:?}"
        );
    }

    let materialized = provider.materialized.lock().expect("not poisoned").clone();
    let released = provider.released.lock().expect("not poisoned").clone();
    assert_eq!(
        materialized.len(),
        2,
        "one worktree per item, materialized once — never re-materialized on a resume"
    );
    assert_eq!(
        released, materialized,
        "every worktree the refusal abandoned is still released"
    );
}

// ---------------------------------------------------------------------------
// Per-item admission — Phase 8 Task 25.7 (#64) Task 4
//
// `split_budget` has computed each item's even share of the run's remaining
// ceiling since B12c, and until this task **nothing read it** — the parameter
// was literally named `_item_caps`, which is why that slice's mutation sweep
// could not kill either mutant of the split arithmetic. These tests assert the
// enforcement half, and they assert it the only way that distinguishes it from
// arithmetic: a real dispatch that would otherwise have happened, and does
// not.
// ---------------------------------------------------------------------------

/// [`a_grant`] with the one field the per-item ceiling is a share of set to
/// `max_tool_calls`.
fn a_grant_of_tool_calls(max_tool_calls: u32) -> ResourceCaps {
    ResourceCaps {
        max_tool_calls,
        ..a_grant()
    }
}

/// **The claim this task exists to make: the item's next dispatch never
/// happens.** Two items over a run with two tool calls left is one call each
/// (`split_budget`'s even share), so each item spends its share on `build` and
/// its `publish` is refused — one wave, two shell tasks, and a `publish` that
/// never reaches the caller as pending work at all.
#[test]
fn a_per_item_cap_refuses_an_items_second_dispatch_instead_of_running_it() {
    let (_conn, _run_id, sink, waves, result) = drive_waves_with_grant(
        "steps:\n\
         \x20 - id: fan\n\
         \x20   map:\n\
         \x20     over: \"${{ inputs.items }}\"\n\
         \x20     as: item\n\
         \x20     max_parallel: 2\n\
         \x20     on_item_error: continue\n\
         \x20   steps:\n\
         \x20     - id: build\n\
         \x20       tool: shell\n\
         \x20       with: { cmd: [echo, build] }\n\
         \x20     - id: publish\n\
         \x20       tool: shell\n\
         \x20       with: { cmd: [echo, publish] }\n",
        &[],
        a_grant_of_tool_calls(2),
        |run_ctx| run_ctx.inputs = serde_json::json!({ "items": map_items(2) }),
    );
    let outcome = result.expect("the run drives");

    assert_eq!(
        waves,
        vec![vec![
            ("build".to_string(), Some(0)),
            ("build".to_string(), Some(1)),
        ]],
        "each item's one call is spent on `build`, so `publish` is never dispatched for \
         either: {waves:?}"
    );
    assert_eq!(
        shell_tasks(&sink),
        2,
        "two real dispatches reached the log, not four"
    );

    let output = map_output(&outcome, "fan");
    let entries = output["items"].as_array().expect("one entry per item");
    assert_eq!(entries.len(), 2, "§8.9: never drop an item");
    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(
            entry["status"], "failed",
            "item {index} ran, and then ran out of its own share — it is not `skipped`: \
             {entry:?}"
        );
        let error = entry["error"].as_str().unwrap_or_default();
        assert!(
            error.contains("publish") && error.contains("max_tool_calls"),
            "the refusal names the step it withheld and the field that ran out: {error:?}"
        );
    }
}

/// **The running tally is re-derived from the durable rows on every wave.**
/// `Loop` is rebuilt from scratch on each re-entry, so an item mid-fan-out
/// carries nothing in memory — the tally has to be reconstructed the way
/// `map_item_is_in_flight`/`decided_map_item_step` reconstruct everything else
/// about an item.
///
/// Three inner steps against a share of two calls pins both ways that can go
/// wrong at once: a tally reset to zero at the wave boundary would dispatch
/// `publish` (a third wave and six shell tasks), and one that counted an
/// in-flight step's row twice would refuse `test` (one wave and two).
#[test]
fn an_items_running_tally_is_re_derived_from_durable_rows_on_every_wave() {
    let (_conn, _run_id, sink, waves, result) = drive_waves_with_grant(
        "steps:\n\
         \x20 - id: fan\n\
         \x20   map:\n\
         \x20     over: \"${{ inputs.items }}\"\n\
         \x20     as: item\n\
         \x20     max_parallel: 2\n\
         \x20     on_item_error: continue\n\
         \x20   steps:\n\
         \x20     - id: build\n\
         \x20       tool: shell\n\
         \x20       with: { cmd: [echo, build] }\n\
         \x20     - id: test\n\
         \x20       tool: shell\n\
         \x20       with: { cmd: [echo, test] }\n\
         \x20     - id: publish\n\
         \x20       tool: shell\n\
         \x20       with: { cmd: [echo, publish] }\n",
        &[],
        a_grant_of_tool_calls(4),
        |run_ctx| run_ctx.inputs = serde_json::json!({ "items": map_items(2) }),
    );
    let outcome = result.expect("the run drives");

    assert_eq!(
        waves,
        vec![
            vec![
                ("build".to_string(), Some(0)),
                ("build".to_string(), Some(1)),
            ],
            vec![("test".to_string(), Some(0)), ("test".to_string(), Some(1)),],
        ],
        "two calls each, spent one per wave, and then nothing: {waves:?}"
    );
    assert_eq!(shell_tasks(&sink), 4, "2 items x their 2 calls");

    let output = map_output(&outcome, "fan");
    let entries = output["items"].as_array().expect("one entry per item");
    assert_eq!(
        entries
            .iter()
            .map(|e| e["status"].as_str().unwrap_or("?"))
            .collect::<Vec<_>>(),
        vec!["failed", "failed"],
        "both items spent their share and were refused at the third step: {entries:?}"
    );
}

/// **Only a real dispatch spends a call.** An item's share is consumed by the
/// inner steps that actually reach the suspend seam — not by an `emit:` this
/// crate answers itself, and not by a `tool:` step its own `when:` gate
/// skipped before dispatch.
///
/// The two items reach the same last step with different tallies, which is
/// what makes the refusal per *item* rather than per map: `"a"`'s gate is true
/// so it spends both its calls before `publish` and is refused, while `"b"`'s
/// is false so `publish` still fits and the item completes.
///
/// The grant is **three** tool calls across two items rather than four, so
/// that the share is `split_budget`'s `ceil(3 / 2) = 2`: a division that
/// floored instead would hand each item one call and change every assertion
/// below. That rounding is one of the two mutants B12c's sweep could not kill
/// while `_item_caps` went unread.
#[test]
fn an_inner_step_that_never_dispatched_does_not_spend_an_items_share() {
    let (_conn, _run_id, sink, waves, result) = drive_waves_with_grant(
        "steps:\n\
         \x20 - id: fan\n\
         \x20   map:\n\
         \x20     over: \"${{ inputs.items }}\"\n\
         \x20     as: item\n\
         \x20     max_parallel: 2\n\
         \x20     on_item_error: continue\n\
         \x20   steps:\n\
         \x20     - id: note\n\
         \x20       emit: { saw: \"${{ item }}\" }\n\
         \x20     - id: build\n\
         \x20       tool: shell\n\
         \x20       with: { cmd: [echo, build] }\n\
         \x20     - id: extra\n\
         \x20       when: \"${{ item == 'a' }}\"\n\
         \x20       tool: shell\n\
         \x20       with: { cmd: [echo, extra] }\n\
         \x20     - id: publish\n\
         \x20       tool: shell\n\
         \x20       with: { cmd: [echo, publish] }\n",
        &[],
        a_grant_of_tool_calls(3),
        |run_ctx| run_ctx.inputs = serde_json::json!({ "items": ["a", "b"] }),
    );
    let outcome = result.expect("the run drives");

    assert_eq!(
        waves,
        vec![
            vec![
                ("build".to_string(), Some(0)),
                ("build".to_string(), Some(1)),
            ],
            vec![
                ("extra".to_string(), Some(0)),
                ("publish".to_string(), Some(1)),
            ],
        ],
        "item 1 skipped `extra` without spending a call, so its `publish` still fits: {waves:?}"
    );
    assert_eq!(shell_tasks(&sink), 4);

    let output = map_output(&outcome, "fan");
    let entries = output["items"].as_array().expect("one entry per item");
    assert_eq!(
        entries
            .iter()
            .map(|e| e["status"].as_str().unwrap_or("?"))
            .collect::<Vec<_>>(),
        vec!["failed", "completed"],
        "the ceiling is spent per item, not per map: {entries:?}"
    );
    assert!(
        entries[0]["error"]
            .as_str()
            .is_some_and(|e| e.contains("publish")),
        "item 0's refusal names the step it withheld: {entries:?}"
    );
}

fn read_tasks(sink: &RecordingSink) -> usize {
    sink.kinds()
        .iter()
        .filter(|k| **k == TaskKind::Read)
        .count()
}

/// What the daemon does the instant it takes a `PendingWork`: mint the task
/// and log it. Separated from *answering* it, because the gap between the two
/// is exactly where a crash leaves a dispatch that really happened with no
/// answer to show for it.
fn mint_task(sink: &mut RecordingSink, kind: TaskKind) -> TaskId {
    let task_id = TaskId::new();
    sink.emit(
        task_id,
        None,
        kind.clone(),
        EventPayload::TaskCreated {
            kind,
            parent: None,
            origin: Origin::System,
            input: TaskInput::Json(serde_json::json!({})),
        },
    );
    task_id
}

/// The inner step a per-item cap refusal names, read back out of the message
/// `per_item_dispatch_refusal` builds. `"?"` for an item that failed for any
/// other reason, so a right-answer-wrong-reason pass is impossible.
fn refused_inner_step(entry: &Value) -> String {
    let error = entry["error"].as_str().unwrap_or_default();
    if !error.contains("max_tool_calls") {
        return "?".to_string();
    }
    error
        .split_once("inner step `")
        .and_then(|(_, rest)| rest.split_once('`'))
        .map_or_else(|| "?".to_string(), |(id, _)| id.to_string())
}

/// Seeds a `Running` root run whose grant is `grant` rather than [`a_grant`]'s.
fn seed_run_with_grant(conn: &mut Connection, grant: ResourceCaps) -> RunId {
    let run_id = RunId::new();
    let mut run = a_run(run_id, SessionId::new());
    run.caps = Some(grant);
    insert_workflow_run(conn, &run).expect("seed the run row");
    run_id
}

/// The fixture both re-decide tests drive, so that the only thing that differs
/// between them is the size of an item's share.
///
/// Two things make it reach a `map` item's own interrupted inner step with no
/// human in the loop: `probe` is `tool: read`, which is `Pure`, so
/// `recover_run` leaves its row `Running` and its `on_crash` policy is `rerun`;
/// and the `map` carries an `idempotency_key:`, which makes it `Idempotent`, so
/// the map's own row is not reclassified `Indeterminate` and the fan-out
/// re-drives on a cold entry instead of parking on §8.10's `ask`.
fn map_with_a_rerunnable_first_step() -> &'static str {
    "steps:\n\
     \x20 - id: fan\n\
     \x20   idempotency_key: \"fan-once\"\n\
     \x20   map:\n\
     \x20     over: \"${{ inputs.items }}\"\n\
     \x20     as: item\n\
     \x20     max_parallel: 1\n\
     \x20     on_item_error: continue\n\
     \x20   steps:\n\
     \x20     - id: probe\n\
     \x20       tool: read\n\
     \x20       with: { path: \"${{ item }}\" }\n\
     \x20     - id: build\n\
     \x20       tool: shell\n\
     \x20       with: { cmd: [echo, build] }\n\
     \x20     - id: publish\n\
     \x20       tool: shell\n\
     \x20       with: { cmd: [echo, publish] }\n"
}

/// **A step that is re-decided is charged to the item once, however many times
/// it actually dispatches — so when the item has room to spare, the ceiling
/// has a soft overshoot, and this pins its exact size.**
///
/// The tally is read out of `item_steps_before`, which is a
/// `HashMap<(step_id, item_index), _>`: one row per inner step per item, no
/// attempt dimension. So when §8.10 tier 2 re-decides a step — `on_crash:
/// rerun` for the `Pure`/`Idempotent` half here, and the same shape for a
/// `Failed` row re-decided on a cold entry — the second real dispatch of that
/// step is not seen by the ceiling, and the item makes one dispatch more than
/// its share nominally allows, per re-decide.
///
/// **"Room to spare" is the load-bearing condition, and it is why this test
/// has two siblings.** The re-decided step's own interrupted row is already in
/// the snapshot, so it counts toward the tally its re-dispatch is measured
/// against: with `P` other started steps and a ceiling of `allowed`, the
/// re-dispatch proceeds exactly when `P + 1 < allowed`. This is the
/// `P = 0, allowed = 2` instance, so one call is left and it goes out. The two
/// `P + 1 >= allowed` instances — reached by a small share and by siblings
/// eating the room — are
/// `a_re_decided_inner_steps_own_re_dispatch_is_refused_when_the_share_is_one`
/// and `a_re_decided_step_is_refused_at_itself_when_siblings_used_the_room_up`.
///
/// Note where refusal actually lands here, because it is *not* the step after
/// the re-decided one: the re-dispatch leaves the running total at 1, so
/// `build` proceeds, and it is `publish` — two steps later — that first finds
/// the total at `allowed`.
#[test]
fn a_re_decided_inner_step_is_charged_to_the_item_once_however_often_it_dispatches() {
    let mut conn = open_test_db();
    // Two items over four calls: a share of two each.
    let run_id = seed_run_with_grant(&mut conn, a_grant_of_tool_calls(4));

    let def =
        parse_workflow(&workflow(map_with_a_rerunnable_first_step())).expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let mut run_ctx = ctx(run_id);
    run_ctx.inputs = serde_json::json!({ "items": map_items(2) });

    let first = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx.clone(),
        at(10),
        None,
    )
    .expect("the run drives");
    let RunOutcome::AwaitingWork { pending } = first else {
        panic!("item 0's `probe` is dispatched and the daemon then dies, got {first:?}");
    };
    assert_eq!(
        pending
            .iter()
            .map(|p| (p.step_id.clone(), p.item_index))
            .collect::<Vec<_>>(),
        vec![("probe".to_string(), Some(0))],
    );
    // The daemon mints the task — the dispatch really happens — and *then*
    // dies, so this attempt is in the log with no answer behind it. That gap
    // is the whole reason §8.10 tier 2 exists.
    for p in &pending {
        assert_eq!(p.item_index, Some(0));
        mint_task(&mut sink, TaskKind::Read);
    }
    assert_eq!(read_tasks(&sink), 1, "item 0's first `probe` attempt");

    // The cold re-drive: no `Resume`, exactly as a recovered run is
    // re-entered, and the answer to the first wave is lost with the process
    // that was holding it.
    let recovered = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx.clone(),
        at(20),
        None,
    )
    .expect("the run drives");
    let RunOutcome::AwaitingWork { pending } = recovered else {
        panic!("`probe` is `Pure`, so its `on_crash` policy re-runs it, got {recovered:?}");
    };
    assert_eq!(
        pending
            .iter()
            .map(|p| (p.step_id.clone(), p.item_index))
            .collect::<Vec<_>>(),
        vec![("probe".to_string(), Some(0))],
        "the interrupted step really is dispatched a second time — the ceiling did not \
         withhold it, because its one row is worth one call however many attempts it takes"
    );

    // Answer this second wave the way the daemon would, then let the run
    // finish normally.
    let answer = pending
        .iter()
        .map(|p| {
            let task_id = mint_task(&mut sink, TaskKind::Read);
            roundhouse_flow::exec::run_loop::WorkDone {
                step_id: p.step_id.clone(),
                item_index: p.item_index,
                status: roundhouse_flow::exec::run_loop::WorkStatus::Completed,
                output: serde_json::json!({}),
                output_is_secret_derived: false,
                task_id: Some(task_id),
                first_task_seq: None,
                last_task_seq: None,
            }
        })
        .collect::<Vec<_>>();
    let outcome = run_to_terminal(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx,
        30,
        Some(Resume::Work(answer)),
    )
    .expect("the run drives");

    // Item 0: `probe` twice + `build` once = three real dispatches against a
    // share of two. Item 1: `probe` + `build` = two, exactly its share.
    assert_eq!(
        read_tasks(&sink),
        3,
        "item 0's interrupted `probe` dispatched twice and item 1's once — the overshoot is \
         one call, and it is the re-decided step's own second attempt"
    );
    assert_eq!(
        shell_tasks(&sink),
        2,
        "`build` still fits for both items — the re-dispatch left the running total where it \
         was — and neither item's `publish` does"
    );

    let RunOutcome::Terminal { steps, .. } = &outcome else {
        panic!("the run must reach a terminal state, got {outcome:?}");
    };
    let map = steps.iter().find(|s| s.step_id == "fan").expect("the map");
    let entries = map.output["items"].as_array().expect("one entry per item");
    assert_eq!(
        entries
            .iter()
            .map(|e| e["status"].as_str().unwrap_or("?"))
            .collect::<Vec<_>>(),
        vec!["failed", "failed"],
        "the overshoot is bounded, not a hole — the ceiling still closes on both items: \
         {entries:?}"
    );
    for entry in entries {
        assert!(
            entry["error"]
                .as_str()
                .is_some_and(|e| e.contains("publish") && e.contains("max_tool_calls")),
            "refusal lands where the running total first reaches the share — `publish`, not \
             the step immediately after the re-decided one: {entry:?}"
        );
    }
}

/// **The other half of the same rule: when there is no room, the re-decided
/// step's own re-dispatch is what gets refused, and there is no overshoot at
/// all.** This is `P + 1 >= allowed` reached by a **small share** — the
/// `P = 0, allowed = 1` instance.
///
/// A re-decided step's interrupted row is already in the snapshot when its
/// re-dispatch is measured, so the step's own prior attempt counts toward the
/// tally. A share of one — `ceil(2 / 2)` over an ordinary two-item `map`, not a
/// contrived figure — means that row alone reaches the ceiling, so the step is
/// refused where it stands. `a_re_decided_step_is_refused_at_itself_when_siblings_used_the_room_up`
/// reaches the same condition by the other route (`P = 1, allowed = 2`).
///
/// Same fixture as the overshoot sibling, same crash, smaller grant. Item 1
/// supplies the contrast in the same run: it never crashed, so it spends its
/// one call on `probe` and is refused at `build`. One test, both refusal
/// sites — a re-decided step refused at itself, and a fresh one refused where
/// the running total first reaches the share.
#[test]
fn a_re_decided_inner_steps_own_re_dispatch_is_refused_when_the_share_is_one() {
    let mut conn = open_test_db();
    // Two items over two calls: a share of one each.
    let run_id = seed_run_with_grant(&mut conn, a_grant_of_tool_calls(2));

    let def =
        parse_workflow(&workflow(map_with_a_rerunnable_first_step())).expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let mut run_ctx = ctx(run_id);
    run_ctx.inputs = serde_json::json!({ "items": map_items(2) });

    let first = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx.clone(),
        at(10),
        None,
    )
    .expect("the run drives");
    let RunOutcome::AwaitingWork { pending } = first else {
        panic!("item 0's `probe` is dispatched and the daemon then dies, got {first:?}");
    };
    assert_eq!(
        pending
            .iter()
            .map(|p| (p.step_id.clone(), p.item_index))
            .collect::<Vec<_>>(),
        vec![("probe".to_string(), Some(0))],
        "item 0 spends its one call on `probe`"
    );
    for _ in &pending {
        mint_task(&mut sink, TaskKind::Read);
    }

    // The cold re-drive, with the answer to that wave lost.
    let recovered = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx.clone(),
        at(20),
        None,
    )
    .expect("the run drives");
    let RunOutcome::AwaitingWork { pending } = recovered else {
        panic!("item 1 has not started and still has its own call, got {recovered:?}");
    };
    assert_eq!(
        pending
            .iter()
            .map(|p| (p.step_id.clone(), p.item_index))
            .collect::<Vec<_>>(),
        vec![("probe".to_string(), Some(1))],
        "item 0's `probe` is **not** re-dispatched: its own interrupted row already fills the \
         item's share of one, so the re-decided step is refused where it stands rather than \
         one step later. The wave belongs to item 1: {pending:?}"
    );

    let answer = pending
        .iter()
        .map(|p| {
            let task_id = mint_task(&mut sink, TaskKind::Read);
            roundhouse_flow::exec::run_loop::WorkDone {
                step_id: p.step_id.clone(),
                item_index: p.item_index,
                status: roundhouse_flow::exec::run_loop::WorkStatus::Completed,
                output: serde_json::json!({}),
                output_is_secret_derived: false,
                task_id: Some(task_id),
                first_task_seq: None,
                last_task_seq: None,
            }
        })
        .collect::<Vec<_>>();
    let outcome = run_to_terminal(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx,
        30,
        Some(Resume::Work(answer)),
    )
    .expect("the run drives");

    assert_eq!(
        read_tasks(&sink),
        2,
        "one `probe` per item and no more — zero overshoot, where the share-two case had one"
    );
    assert_eq!(shell_tasks(&sink), 0, "no item ever reaches `build`");

    let RunOutcome::Terminal { steps, .. } = &outcome else {
        panic!("the run must reach a terminal state, got {outcome:?}");
    };
    let map = steps.iter().find(|s| s.step_id == "fan").expect("the map");
    let entries = map.output["items"].as_array().expect("one entry per item");
    assert_eq!(
        entries
            .iter()
            .map(|e| e["status"].as_str().unwrap_or("?"))
            .collect::<Vec<_>>(),
        vec!["failed", "failed"],
    );
    assert_eq!(
        entries.iter().map(refused_inner_step).collect::<Vec<_>>(),
        vec!["probe", "build"],
        "item 0 is refused at the re-decided step itself; item 1, which never crashed, is \
         refused where its own running total first reaches the share: {entries:?}"
    );
}

/// **`P + 1 >= allowed` reached by the other route: the room is gone because
/// the item's *siblings* used it, not because the share is small.**
///
/// `allowed` is **two** here — the same share that overshoots in
/// `a_re_decided_inner_step_is_charged_to_the_item_once_however_often_it_dispatches`.
/// What differs is that the re-decided step is the item's *second*, so one
/// other step already holds a started row (`P = 1`) and the re-decided step's
/// own row takes the tally to `2 >= 2`: refused at itself, zero overshoot, at a
/// share no smaller than the one that overshoots.
///
/// Without this case the rule would be pinned only at `P = 0`, and "no room"
/// would read as though it meant "a share of one".
///
/// Item 1 again supplies the contrast in the same run: it never crashed, so it
/// spends its two calls on `setup` and `probe` and is refused at `build`.
#[test]
fn a_re_decided_step_is_refused_at_itself_when_siblings_used_the_room_up() {
    let mut conn = open_test_db();
    // Two items over four calls: a share of two each, as in the overshoot
    // test — the room is used up by a sibling step, not by the share.
    let run_id = seed_run_with_grant(&mut conn, a_grant_of_tool_calls(4));

    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: fan\n\
         \x20   idempotency_key: \"fan-once\"\n\
         \x20   map:\n\
         \x20     over: \"${{ inputs.items }}\"\n\
         \x20     as: item\n\
         \x20     max_parallel: 1\n\
         \x20     on_item_error: continue\n\
         \x20   steps:\n\
         \x20     - id: setup\n\
         \x20       tool: shell\n\
         \x20       with: { cmd: [echo, setup] }\n\
         \x20     - id: probe\n\
         \x20       tool: read\n\
         \x20       with: { path: \"${{ item }}\" }\n\
         \x20     - id: build\n\
         \x20       tool: shell\n\
         \x20       with: { cmd: [echo, build] }\n",
    ))
    .expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let mut run_ctx = ctx(run_id);
    run_ctx.inputs = serde_json::json!({ "items": map_items(2) });

    // Segment 1: item 0 spends its first call on `setup`, which is answered
    // normally — this is the sibling that later leaves `probe` no room.
    let first = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx.clone(),
        at(10),
        None,
    )
    .expect("the run drives");
    let RunOutcome::AwaitingWork { pending } = first else {
        panic!("item 0's `setup` is dispatched first, got {first:?}");
    };
    assert_eq!(
        pending
            .iter()
            .map(|p| (p.step_id.clone(), p.item_index))
            .collect::<Vec<_>>(),
        vec![("setup".to_string(), Some(0))],
    );
    let answer: Vec<_> = pending
        .iter()
        .map(|p| {
            let task_id = mint_task(&mut sink, TaskKind::Shell);
            roundhouse_flow::exec::run_loop::WorkDone {
                step_id: p.step_id.clone(),
                item_index: p.item_index,
                status: roundhouse_flow::exec::run_loop::WorkStatus::Completed,
                output: serde_json::json!({}),
                output_is_secret_derived: false,
                task_id: Some(task_id),
                first_task_seq: None,
                last_task_seq: None,
            }
        })
        .collect();

    // Segment 2: `setup` completes and item 0 spends its second call on
    // `probe` — `P = 1`, tally 1 < 2, so this one still fits. The daemon mints
    // the task and then dies.
    let second = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx.clone(),
        at(20),
        Some(Resume::Work(answer)),
    )
    .expect("the run drives");
    let RunOutcome::AwaitingWork { pending } = second else {
        panic!("item 0's `probe` still fits at `P = 1`, got {second:?}");
    };
    assert_eq!(
        pending
            .iter()
            .map(|p| (p.step_id.clone(), p.item_index))
            .collect::<Vec<_>>(),
        vec![("probe".to_string(), Some(0))],
    );
    for _ in &pending {
        mint_task(&mut sink, TaskKind::Read);
    }

    // Segment 3, cold: `setup`'s `Completed` row is inherited and `probe` is
    // re-decided — so the tally is that sibling plus `probe`'s own interrupted
    // row, which is the whole share.
    let recovered = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx.clone(),
        at(30),
        None,
    )
    .expect("the run drives");
    let RunOutcome::AwaitingWork { pending } = recovered else {
        panic!("item 1 has not started and still has its whole share, got {recovered:?}");
    };
    assert_eq!(
        pending
            .iter()
            .map(|p| (p.step_id.clone(), p.item_index))
            .collect::<Vec<_>>(),
        vec![("setup".to_string(), Some(1))],
        "item 0's `probe` is **not** re-dispatched: one completed sibling plus its own \
         interrupted row already fills a share of two, so a re-decided step is refused at \
         itself even where that same share leaves room when it is the item's first step. The \
         wave belongs to item 1: {pending:?}"
    );

    let answer: Vec<_> = pending
        .iter()
        .map(|p| {
            let task_id = mint_task(&mut sink, TaskKind::Shell);
            roundhouse_flow::exec::run_loop::WorkDone {
                step_id: p.step_id.clone(),
                item_index: p.item_index,
                status: roundhouse_flow::exec::run_loop::WorkStatus::Completed,
                output: serde_json::json!({}),
                output_is_secret_derived: false,
                task_id: Some(task_id),
                first_task_seq: None,
                last_task_seq: None,
            }
        })
        .collect();
    let outcome = run_to_terminal(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx,
        40,
        Some(Resume::Work(answer)),
    )
    .expect("the run drives");

    assert_eq!(
        shell_tasks(&sink),
        2,
        "one `setup` per item; `build` is never dispatched for either"
    );
    assert_eq!(
        read_tasks(&sink),
        2,
        "one `probe` attempt per item — item 0's is not repeated, so there is no overshoot \
         here even though the share is the same as the case that overshoots"
    );

    let RunOutcome::Terminal { steps, .. } = &outcome else {
        panic!("the run must reach a terminal state, got {outcome:?}");
    };
    let map = steps.iter().find(|s| s.step_id == "fan").expect("the map");
    let entries = map.output["items"].as_array().expect("one entry per item");
    assert_eq!(
        entries.iter().map(refused_inner_step).collect::<Vec<_>>(),
        vec!["probe", "build"],
        "item 0 is refused at the re-decided step itself; item 1, which never crashed, spends \
         both its calls and is refused at the step after them: {entries:?}"
    );
}

// ---------------------------------------------------------------------------
// Cooperative run-budget exhaustion — Phase 8 Task 25.7 (#64) Task 5
//
// Task 4's per-item ceiling bounds one item against its siblings, and
// `split_budget` rounds an item's share **up**, so an n-item `map` still issues
// n real dispatches however little the run has left. These tests assert the
// aggregate bound that ceiling's own doc comment defers to: the fan-out
// measured against the run's remainder, with the items it never reached
// recorded `Skipped { reason: "run_budget_exhausted" }` and the run's
// synthesised report flagged for a human.
// ---------------------------------------------------------------------------

/// **The claim: an item the run ran out of budget before reaching is never
/// dispatched at all** — it produces no `PendingWork`, mints no task, and is
/// recorded `Skipped` rather than dropped or failed.
///
/// Five items over a run with two tool calls left. Task 4's share is
/// `ceil(2 / 5) = 1`, so nothing about the *per-item* ceiling stops any of the
/// five making its one call: without the aggregate bound this run dispatches
/// five times over a budget of two.
#[test]
fn a_map_stops_starting_new_items_once_the_runs_own_budget_is_spent() {
    let (_conn, _run_id, sink, waves, result) = drive_waves_with_grant(
        &map_over_tool(2, "continue"),
        &[],
        a_grant_of_tool_calls(2),
        |run_ctx| run_ctx.inputs = serde_json::json!({ "items": map_items(5) }),
    );
    let outcome = result.expect("the run drives");

    assert_eq!(
        waves,
        vec![vec![
            ("build".to_string(), Some(0)),
            ("build".to_string(), Some(1)),
        ]],
        "the run's two calls go to the first wave, and no later item ever reaches the caller \
         as pending work: {waves:?}"
    );
    assert_eq!(
        shell_tasks(&sink),
        2,
        "two real dispatches reached the log, not five"
    );

    let output = map_output(&outcome, "fan");
    let entries = output["items"].as_array().expect("one entry per item");
    assert_eq!(entries.len(), 5, "§8.9: never drop an item");
    assert_eq!(
        entries
            .iter()
            .map(|e| e["status"].as_str().unwrap_or("?"))
            .collect::<Vec<_>>(),
        vec!["completed", "completed", "skipped", "skipped", "skipped"],
        "the two items already in flight finish; the three the run could not afford are \
         skipped: {entries:?}"
    );
    assert_eq!(
        entries[2..]
            .iter()
            .map(|e| e["reason"].as_str().unwrap_or("?"))
            .collect::<Vec<_>>(),
        vec![
            "run_budget_exhausted",
            "run_budget_exhausted",
            "run_budget_exhausted"
        ],
        "the reason is §8.9's own, not `fail_fast`'s — no item failed: {entries:?}"
    );
}

/// **The in-flight half of the same rule, across a suspend/resume boundary.**
/// Exhaustion is discovered on the *second* segment, by which point items 0
/// and 1 are already dispatched — §8.9 lets them finish their round-trip, and
/// nothing retroactively un-dispatches them.
///
/// The assertion that makes this more than a restatement of the test above is
/// the pair of `completed` entries carrying their real answers: a bound applied
/// to every undecided item rather than to every *unstarted* one would discard
/// two real, already-computed outputs and backfill them `Skipped`.
#[test]
fn an_item_already_in_flight_when_the_budget_runs_out_still_finishes() {
    let (_conn, _run_id, _sink, waves, result) = drive_waves_with_grant(
        &map_over_tool(2, "continue"),
        &[],
        a_grant_of_tool_calls(2),
        |run_ctx| run_ctx.inputs = serde_json::json!({ "items": map_items(5) }),
    );
    let outcome = result.expect("the run drives");

    assert_eq!(waves.len(), 1, "exhaustion is found on the second segment");
    let output = map_output(&outcome, "fan");
    let entries = output["items"].as_array().expect("one entry per item");
    assert_eq!(
        entries[..2]
            .iter()
            .map(|e| e["output"]["dispatched"].clone())
            .collect::<Vec<_>>(),
        vec![serde_json::json!(0), serde_json::json!(1)],
        "each in-flight item's own answer survives the segment that found the budget spent: \
         {entries:?}"
    );
}

/// **§8.6's flag, on a run that otherwise looks like a success.** The `map`
/// step's aggregate status is `Completed` (a skipped item is not a failed one)
/// and no step failed, so the run ends `Completed` — and without this the
/// synthesised report would read `outcome: nothing, severity: low,
/// needs_human: false` and sort to the bottom of the inbox, presenting a
/// partial result as if it were whole.
#[test]
fn a_run_whose_map_ran_out_of_budget_flags_its_report_for_a_human() {
    let (_conn, _run_id, sink, _waves, result) = drive_waves_with_grant(
        &map_over_tool(2, "continue"),
        &[],
        a_grant_of_tool_calls(2),
        |run_ctx| run_ctx.inputs = serde_json::json!({ "items": map_items(5) }),
    );
    let outcome = result.expect("the run drives");

    let RunOutcome::Terminal { state, .. } = &outcome else {
        panic!("the run must reach a terminal state, got {outcome:?}");
    };
    assert_eq!(
        *state,
        RunState::Completed,
        "nothing failed: the flag has to come from the skipped items, not from the run state"
    );

    let report = sink.the_report();
    assert_eq!(report["synthesised_by"], "run_loop");
    assert_eq!(report["needs_human"], true);
    assert_eq!(
        report["outcome"], "needs_human",
        "`outcome: nothing` beside `needs_human: true` would read as a contradiction: {report:?}"
    );
    assert_eq!(report["severity"], "med");
}

/// **The flag survives a `map` that finished on an earlier segment.** A run
/// whose `map` completes and then suspends on a later step ends on an entry
/// that never calls `dispatch_map` at all: the map's outcome is inherited from
/// its durable row and is deliberately absent from the returned `steps`, so a
/// signal carried only in memory — or read only off this segment's own
/// outcomes — is lost exactly here.
#[test]
fn a_run_budget_skip_still_flags_the_report_when_the_run_ends_on_a_later_segment() {
    let (_conn, _run_id, sink, waves, result) = drive_waves_with_grant(
        "steps:\n\
         \x20 - id: fan\n\
         \x20   map:\n\
         \x20     over: \"${{ inputs.items }}\"\n\
         \x20     as: item\n\
         \x20     max_parallel: 2\n\
         \x20     on_item_error: continue\n\
         \x20   steps:\n\
         \x20     - id: build\n\
         \x20       tool: shell\n\
         \x20       with: { cmd: [echo, build] }\n\
         \x20 - id: after\n\
         \x20   needs: [fan]\n\
         \x20   tool: shell\n\
         \x20   with: { cmd: [echo, after] }\n",
        &[],
        a_grant_of_tool_calls(2),
        |run_ctx| run_ctx.inputs = serde_json::json!({ "items": map_items(5) }),
    );
    let outcome = result.expect("the run drives");

    assert_eq!(
        waves,
        vec![
            vec![
                ("build".to_string(), Some(0)),
                ("build".to_string(), Some(1)),
            ],
            vec![("after".to_string(), None)],
        ],
        "the map finishes on the second segment and the run suspends again on `after`, so it \
         ends on a third: {waves:?}"
    );
    let RunOutcome::Terminal { state, steps, .. } = &outcome else {
        panic!("the run must reach a terminal state, got {outcome:?}");
    };
    assert_eq!(*state, RunState::Completed);
    assert!(
        !steps.iter().any(|s| s.step_id == "fan"),
        "the map's outcome is inherited on the terminal segment, not re-recorded: {steps:?}"
    );
    assert_eq!(sink.the_report()["needs_human"], true);
}

/// **The residual this bound does not close, measured rather than reasoned.**
/// `map_item_is_in_flight` exempts an item from the exhaustion guard for good
/// once any of its inner steps holds a row — not for one outstanding
/// round-trip — so an item already started goes on dispatching the rest of its
/// inner steps however far past the run's remainder that takes, held by its own
/// `split_budget` share rather than by this bound.
///
/// Three items over three inner steps with seven calls left: the share is
/// `ceil(7 / 3) = 3`, item 2 starts at a tally of 6 (`6 >= 7` is false) and
/// then spends all three of its own calls, so the fan-out issues **nine**
/// dispatches against a remainder of seven. `max_parallel` is 1 here precisely
/// to show the overshoot is not bounded by it.
///
/// The second half of the claim matters as much as the first: every item
/// completes, so **nothing is `Skipped`** and the run is not flagged.
/// `needs_human` means "at least one item was withheld", not "this run never
/// overspent".
#[test]
fn an_already_started_item_keeps_dispatching_past_the_runs_remainder_unflagged() {
    let (_conn, _run_id, sink, waves, result) = drive_waves_with_grant(
        "steps:\n\
         \x20 - id: fan\n\
         \x20   map:\n\
         \x20     over: \"${{ inputs.items }}\"\n\
         \x20     as: item\n\
         \x20     max_parallel: 1\n\
         \x20     on_item_error: continue\n\
         \x20   steps:\n\
         \x20     - id: a\n\
         \x20       tool: shell\n\
         \x20       with: { cmd: [echo, a] }\n\
         \x20     - id: b\n\
         \x20       tool: shell\n\
         \x20       with: { cmd: [echo, b] }\n\
         \x20     - id: c\n\
         \x20       tool: shell\n\
         \x20       with: { cmd: [echo, c] }\n",
        &[],
        a_grant_of_tool_calls(7),
        |run_ctx| run_ctx.inputs = serde_json::json!({ "items": map_items(3) }),
    );
    let outcome = result.expect("the run drives");

    assert_eq!(
        waves,
        vec![
            vec![("a".to_string(), Some(0))],
            vec![("b".to_string(), Some(0))],
            vec![("c".to_string(), Some(0))],
            vec![("a".to_string(), Some(1))],
            vec![("b".to_string(), Some(1))],
            vec![("c".to_string(), Some(1))],
            vec![("a".to_string(), Some(2))],
            vec![("b".to_string(), Some(2))],
            vec![("c".to_string(), Some(2))],
        ],
        "item 2's `b` and `c` are dispatched at tallies of 7 and 8, both past the run's \
         remainder of 7, because the item was already started when the budget ran out: {waves:?}"
    );
    assert_eq!(
        shell_tasks(&sink),
        9,
        "nine real dispatches against a remainder of seven: the overshoot is bounded by the \
         item count (3 x the per-item share of 3), not by `max_parallel: 1`"
    );

    let output = map_output(&outcome, "fan");
    let entries = output["items"].as_array().expect("one entry per item");
    assert_eq!(
        entries
            .iter()
            .map(|e| e["status"].as_str().unwrap_or("?"))
            .collect::<Vec<_>>(),
        vec!["completed", "completed", "completed"],
        "no item is withheld, so there is no `run_budget_exhausted` skip to record: {entries:?}"
    );
    assert_eq!(
        sink.the_report()["needs_human"],
        false,
        "the flag reports withheld items, not overspend — an operator reading it as an \
         overshoot alarm would miss this run"
    );
}

/// **The reactive half of §8.9's "whichever way it is discovered": the `map`
/// step's own admission.** A run with no tasks left cannot admit the `map` at
/// all, so the step fails before any item starts — the existing
/// "admission refused" path, pinned here for a `map:` body specifically
/// because that is the one body whose admission `run_phase` re-enters on every
/// resumed wave.
///
/// The proactive check above cannot cover this case and is not asked to: there
/// are no items to skip when the fan-out never began.
#[test]
fn a_map_the_ledger_refuses_to_admit_fails_before_any_item_starts() {
    let (conn, run_id, sink, waves, result) = drive_waves_with_grant(
        &map_over_tool(2, "continue"),
        &[],
        ResourceCaps {
            max_tasks: 0,
            ..a_grant()
        },
        |run_ctx| run_ctx.inputs = serde_json::json!({ "items": map_items(5) }),
    );
    let outcome = result.expect("the run drives");

    assert!(waves.is_empty(), "no item is ever dispatched: {waves:?}");
    assert_eq!(shell_tasks(&sink), 0);
    let RunOutcome::Terminal { state, .. } = &outcome else {
        panic!("the run must reach a terminal state, got {outcome:?}");
    };
    assert_eq!(*state, RunState::Failed);
    let (fan_state, fan_error) = step_row(&conn, run_id, "fan");
    assert_eq!(fan_state, StepRunState::Failed);
    assert!(
        fan_error
            .as_deref()
            .is_some_and(|e| e.contains("admission refused") && e.contains("max_tasks")),
        "the refusal names the field that ran out: {fan_error:?}"
    );
    assert_eq!(sink.the_report()["needs_human"], true);
}

// ---------------------------------------------------------------------------
// A nested `gate:` inside a `map:` — Phase 8 Task 25.7 (#64) Task 6
//
// §8.9's own reference workflow nests a `gate:` in a `map`'s `steps:`; until
// this task it took `Executor::dispatch_step`'s catch-all refusal, because a
// park is a transition of the *run* and one run cannot be parked per item
// (§8.11). The resolution: an item's gate **requests** a run-wide park, and
// that request does not take effect until the whole current wave has drained
// — cooperative, the way §8.13's cancel is, rather than abandoning the
// dispatches its siblings already have out.
// ---------------------------------------------------------------------------

/// One `map` item's own inner-step row — [`step_row`]'s per-item counterpart.
///
/// Returns `None` rather than panicking when the row is absent, because
/// "this sibling was never started" is an assertion in its own right here: it
/// is exactly what an unstarted item looks like durably.
fn item_step_row(
    conn: &Connection,
    run_id: RunId,
    step_id: &str,
    item_index: u32,
) -> Option<(StepRunState, Option<String>)> {
    recover_run(conn, run_id)
        .expect("the run is recoverable")
        .steps
        .iter()
        .find(|s| s.step_id == step_id && s.item_index == Some(item_index))
        .map(|row| (row.state, row.error.clone()))
}

/// Every `awaiting_human` form a park put in the log, in the order they were
/// emitted — §8.11's *"an `AwaitingHuman` task with a JSON-Schema form"*,
/// which is the only thing a human is ever actually shown.
fn awaiting_human_forms(sink: &RecordingSink) -> Vec<Value> {
    sink.emitted
        .iter()
        .filter_map(|(_, payload)| match payload {
            EventPayload::TaskCreated {
                input: TaskInput::Json(v),
                ..
            } => v.get("awaiting_human").cloned(),
            _ => None,
        })
        .collect()
}

/// A `map` whose inner steps are a nested `gate:` and a free `emit:`, with the
/// gate's own `when:` reading the item — so one fixture can hold items that
/// need a human and items that do not.
///
/// The gate is **first**, so an item that wants to park has no other inner
/// step's row to make it look started: the park's own durable record is the
/// only thing that can.
fn map_over_gate(max_parallel: u32) -> String {
    format!(
        "steps:\n\
         \x20 - id: fan\n\
         \x20   map:\n\
         \x20     over: \"${{{{ inputs.items }}}}\"\n\
         \x20     as: item\n\
         \x20     max_parallel: {max_parallel}\n\
         \x20     on_item_error: continue\n\
         \x20   steps:\n\
         \x20     - id: approve\n\
         \x20       when: \"${{{{ item.gated }}}}\"\n\
         \x20       gate:\n\
         \x20         title: \"ship ${{{{ item.name }}}}?\"\n\
         \x20         form: {{ approve: {{ type: boolean }} }}\n\
         \x20         timeout: 24h\n\
         \x20         on_timeout: deny\n\
         \x20     - id: done\n\
         \x20       emit: {{ shipped: \"${{{{ item.name }}}}\" }}\n"
    )
}

/// `[{name: item-0, gated: <g0>}, ..]` — one object per entry of `gated`.
fn gated_items(gated: &[bool]) -> Value {
    Value::Array(
        gated
            .iter()
            .enumerate()
            .map(|(i, g)| serde_json::json!({ "name": format!("item-{i}"), "gated": g }))
            .collect(),
    )
}

/// **The task's headline case.** An item's nested `gate:` parks the run;
/// answering it resumes exactly that item; and the siblings — one that had
/// already completed, one that had not started — are untouched by either the
/// park or the answer.
#[test]
fn a_map_items_nested_gate_parks_the_run_and_its_answer_resumes_exactly_that_item() {
    let mut conn = open_test_db();
    let (run_id, session_id) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(&map_over_gate(3))).expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let mut run_ctx = ctx(run_id);
    run_ctx.inputs = serde_json::json!({ "items": gated_items(&[false, true, true]) });

    let first = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx.clone(),
        at(100),
        None,
    )
    .expect("the run drives to the item's gate");

    let RunOutcome::Parked(parked) = first else {
        panic!("a `map` item's nested gate must park the run, got {first:?}");
    };
    assert_eq!(
        parked.item_index,
        Some(1),
        "item 0's gate is skipped by its own `when:`, so the first item that needs a human is 1"
    );
    assert_eq!(parked.session_id, session_id);
    assert_eq!(
        parked.awaiting_until,
        Some(at(100 + 24 * 3600)),
        "the nested gate's own `timeout:` decides the wait, exactly as a top-level one's does"
    );
    assert_eq!(
        recover_run(&conn, run_id).unwrap().run.state,
        RunState::AwaitingHuman
    );
    assert_eq!(host.checkpoints.len(), 1, "§8.11's implicit checkpoint ran");

    // The durable record §8.11's resume needs: *which item*, at *which inner
    // step*.
    assert_eq!(
        item_step_row(&conn, run_id, "approve", 1).map(|r| r.0),
        Some(StepRunState::Running),
        "the parked item's own gate row is what says the map is mid-fan-out at this item"
    );
    // The sibling that finished before the park.
    assert_eq!(
        item_step_row(&conn, run_id, "approve", 0).map(|r| r.0),
        Some(StepRunState::Skipped)
    );
    assert_eq!(
        item_step_row(&conn, run_id, "done", 0).map(|r| r.0),
        Some(StepRunState::Completed)
    );
    // The sibling that wanted to park too: only one park can be live, so it
    // is left with no row at all rather than a second park's worth of state.
    assert_eq!(item_step_row(&conn, run_id, "approve", 2), None);

    let forms = awaiting_human_forms(&sink);
    assert_eq!(forms.len(), 1, "exactly one human is asked: {forms:?}");
    assert_eq!(
        forms[0]["item_index"], 1,
        "the form says which item is being asked about: {:?}",
        forms[0]
    );
    assert_eq!(
        forms[0]["form_schema"]["title"], "ship item-1?",
        "the title is interpolated against the item that parked: {:?}",
        forms[0]
    );

    // The human answers item 1's gate. Item 0 is inherited, item 1 finishes,
    // and item 2 — which wanted to park in the first wave too — takes its
    // turn now that the run is drivable again.
    let second = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx.clone(),
        at(200),
        Some(Resume::Gate(GateAnswer {
            step_id: "approve".into(),
            item_index: Some(1),
            output: serde_json::json!({ "approve": true }),
        })),
    )
    .expect("the answer releases the park");

    let RunOutcome::Parked(second_park) = second else {
        panic!("item 2's gate has no answer, so the map parks again, got {second:?}");
    };
    assert_eq!(
        second_park.item_index,
        Some(2),
        "the siblings' parks resolve one at a time, in item order"
    );
    let forms = awaiting_human_forms(&sink);
    assert_eq!(
        forms.last().map(|f| f["source"].clone()),
        Some(serde_json::json!("gate")),
        "**the hazard the `resuming_map` guard closes**: the parked `map`'s own row is \
         `Indeterminate` on this entry, so without it §8.10 tier 2 would re-park the run on a \
         crash question about a `map` that never crashed: {forms:?}"
    );
    assert_eq!(
        item_step_row(&conn, run_id, "approve", 1).map(|r| r.0),
        Some(StepRunState::Completed),
        "the answered item's gate is settled, not re-presented"
    );
    assert_eq!(
        item_step_row(&conn, run_id, "done", 1).map(|r| r.0),
        Some(StepRunState::Completed),
        "and the item carried on past its gate"
    );

    let third = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx,
        at(300),
        Some(Resume::Gate(GateAnswer {
            step_id: "approve".into(),
            item_index: Some(2),
            output: serde_json::json!({ "approve": false }),
        })),
    )
    .expect("the answer releases the second park");

    let RunOutcome::Terminal { state, .. } = &third else {
        panic!("every gate is answered, so the map finishes, got {third:?}");
    };
    assert_eq!(*state, RunState::Completed);
    let output = map_output(&third, "fan");
    let entries = output["items"].as_array().expect("one entry per item");
    assert_eq!(
        entries
            .iter()
            .map(|e| e["status"].as_str().unwrap_or("?"))
            .collect::<Vec<_>>(),
        vec!["completed", "completed", "completed"],
        "every item ran its own inner steps to the end: {entries:?}"
    );
    assert_eq!(
        entries
            .iter()
            .map(|e| e["output"]["shipped"].as_str().unwrap_or("?"))
            .collect::<Vec<_>>(),
        vec!["item-0", "item-1", "item-2"],
        "each item's own `as:` binding survived its own park: {entries:?}"
    );
    let shipped_emits = sink
        .emitted
        .iter()
        .filter(|(_, p)| match p {
            EventPayload::TaskCreated {
                input: TaskInput::Json(v),
                ..
            } => v.get("shipped").is_some(),
            _ => false,
        })
        .count();
    assert_eq!(
        shipped_emits, 3,
        "one `emit:` per item and no more — a resumed park must not re-run a sibling's \
         already-completed inner step"
    );
}

/// **The cooperative half, which is the whole reason a park request is not a
/// park.** A wave that discovers one item wants a human must still dispatch
/// the real work its other items decided they need — §8.13's cancel semantics
/// applied to a park: nothing already in flight is abandoned, and nothing the
/// wave has already decided to start is withheld.
#[test]
fn a_wave_still_dispatches_its_other_items_work_before_a_nested_gates_park_takes_effect() {
    use roundhouse_flow::exec::run_loop::{PendingWork, WorkDone, WorkStatus};

    let body = "steps:\n\
         \x20 - id: fan\n\
         \x20   map:\n\
         \x20     over: \"${{ inputs.items }}\"\n\
         \x20     as: item\n\
         \x20     max_parallel: 1\n\
         \x20     on_item_error: continue\n\
         \x20   steps:\n\
         \x20     - id: build\n\
         \x20       tool: shell\n\
         \x20       with: { cmd: [echo, \"${{ item }}\"] }\n\
         \x20     - id: approve\n\
         \x20       gate:\n\
         \x20         title: \"ship ${{ item }}?\"\n\
         \x20         form: { approve: { type: boolean } }\n\
         \x20         timeout: 24h\n\
         \x20         on_timeout: deny\n";
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(body)).expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let mut run_ctx = ctx(run_id);
    run_ctx.inputs = serde_json::json!({ "items": map_items(2) });

    // What the loop asked to have dispatched, across every wave — the tally
    // the closing assertion reads, since a `map` mid-fan-out must never ask
    // for the same item's work twice.
    let mut dispatched: Vec<(String, Option<u32>)> = Vec::new();

    /// Answers a wave the way the daemon would, recording what it was asked
    /// to dispatch.
    fn answer(
        pending: &[PendingWork],
        dispatched: &mut Vec<(String, Option<u32>)>,
    ) -> Vec<WorkDone> {
        pending
            .iter()
            .map(|p| {
                dispatched.push((p.step_id.clone(), p.item_index));
                WorkDone {
                    step_id: p.step_id.clone(),
                    item_index: p.item_index,
                    status: WorkStatus::Completed,
                    output: serde_json::json!({ "built": p.item_index }),
                    output_is_secret_derived: false,
                    task_id: Some(TaskId::new()),
                    first_task_seq: None,
                    last_task_seq: None,
                }
            })
            .collect()
    }

    // Wave 1: `max_parallel: 1`, so only item 0's `build` goes out.
    let first = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx.clone(),
        at(10),
        None,
    )
    .expect("the run drives");
    let RunOutcome::AwaitingWork { pending } = first else {
        panic!("item 0's `build` is real work, got {first:?}");
    };
    assert_eq!(
        pending
            .iter()
            .map(|p| (p.step_id.as_str(), p.item_index))
            .collect::<Vec<_>>(),
        vec![("build", Some(0))]
    );

    // Wave 2: item 0 reaches its gate and asks to park — and item 1's `build`
    // is dispatched anyway. This is the assertion the whole mechanism exists
    // for: the run is still `Running`, and no checkpoint has been taken.
    let second = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx.clone(),
        at(20),
        Some(Resume::Work(answer(&pending, &mut dispatched))),
    )
    .expect("the run drives");
    let RunOutcome::AwaitingWork { pending } = second else {
        panic!(
            "the wave must drain before the park takes effect: item 1's `build` still needs \
             dispatching, got {second:?}"
        );
    };
    assert_eq!(
        pending
            .iter()
            .map(|p| (p.step_id.as_str(), p.item_index))
            .collect::<Vec<_>>(),
        vec![("build", Some(1))],
        "item 0 wants a human, but item 1's real work is not withheld for it"
    );
    assert_eq!(
        recover_run(&conn, run_id).unwrap().run.state,
        RunState::Running,
        "a park request is not a park: the run is not suspended while work is outstanding"
    );
    assert!(
        host.checkpoints.is_empty(),
        "and §8.11's implicit checkpoint has not been taken either"
    );
    assert_eq!(
        item_step_row(&conn, run_id, "approve", 0),
        None,
        "nor is any durable park record written for a request that did not park"
    );

    // Wave 3: nothing is left to dispatch, so the park finally takes effect —
    // on item 0, the first item that asked.
    let third = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx,
        at(30),
        Some(Resume::Work(answer(&pending, &mut dispatched))),
    )
    .expect("the run drives");
    let RunOutcome::Parked(parked) = third else {
        panic!("with the wave drained, the deferred park takes effect, got {third:?}");
    };
    assert_eq!(parked.item_index, Some(0));
    assert_eq!(
        recover_run(&conn, run_id).unwrap().run.state,
        RunState::AwaitingHuman
    );
    assert_eq!(
        item_step_row(&conn, run_id, "build", 1).map(|r| r.0),
        Some(StepRunState::Completed),
        "item 1's dispatch was answered and recorded before the park, not discarded by it"
    );
    assert_eq!(
        dispatched,
        vec![
            ("build".to_string(), Some(0)),
            ("build".to_string(), Some(1)),
        ],
        "each item's `build` was asked for exactly once: a park deferred across a wave must not \
         re-dispatch the work that wave already did"
    );
}

/// Two siblings reaching their own gates in one wave is an ordinary shape,
/// and only one park can be live at a time (§8.11). They resolve **in
/// sequence** — one park, one answer, the next park — rather than
/// simultaneously, and rather than deadlocking because neither can park.
#[test]
fn two_items_wanting_to_park_in_one_wave_resolve_one_at_a_time() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(&map_over_gate(2))).expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let mut run_ctx = ctx(run_id);
    run_ctx.inputs = serde_json::json!({ "items": gated_items(&[true, true]) });

    let mut parked_items: Vec<Option<u32>> = Vec::new();
    let mut resume: Option<Resume> = None;
    let mut segments = 0usize;
    let terminal = loop {
        segments += 1;
        assert!(
            segments <= MAX_SEGMENTS,
            "the run has been re-entered {segments} times without reaching a terminal state: \
             parks so far {parked_items:?}"
        );
        let outcome = run_workflow(
            &mut conn,
            &def,
            run_id,
            &mut sink,
            &mut host,
            run_ctx.clone(),
            at(100 * segments as i64),
            resume.take(),
        )
        .expect("the run drives");
        match outcome {
            RunOutcome::Parked(parked) => {
                parked_items.push(parked.item_index);
                resume = Some(Resume::Gate(GateAnswer {
                    step_id: "approve".into(),
                    item_index: parked.item_index,
                    output: serde_json::json!({ "approve": true }),
                }));
            }
            other => break other,
        }
    };

    assert_eq!(
        parked_items,
        vec![Some(0), Some(1)],
        "both items want a human in the first wave; the run parks on one, and the other takes \
         its turn once that one is answered"
    );
    let RunOutcome::Terminal { state, .. } = &terminal else {
        panic!("both gates are answered, so the map finishes, got {terminal:?}");
    };
    assert_eq!(*state, RunState::Completed);
    assert_eq!(
        host.checkpoints.len(),
        2,
        "one implicit checkpoint per park, not one for a batch of them"
    );
    let forms = awaiting_human_forms(&sink);
    assert_eq!(
        forms
            .iter()
            .map(|f| f["item_index"].clone())
            .collect::<Vec<_>>(),
        vec![serde_json::json!(0), serde_json::json!(1)],
        "each park asks about exactly one item: {forms:?}"
    );
}

/// **A park is a durable suspension, so the entry that answers it continues
/// the drive that took it.** A sibling item this same drive already failed
/// must therefore be inherited, not re-decided: re-deciding it would
/// re-dispatch a `shell` step that already ran and already failed, once per
/// park the fan-out takes.
#[test]
fn a_sibling_item_that_failed_before_the_park_is_not_re_dispatched_by_the_answer() {
    use roundhouse_flow::exec::run_loop::{WorkDone, WorkStatus};

    let body = "steps:\n\
         \x20 - id: fan\n\
         \x20   map:\n\
         \x20     over: \"${{ inputs.items }}\"\n\
         \x20     as: item\n\
         \x20     max_parallel: 2\n\
         \x20     on_item_error: continue\n\
         \x20   steps:\n\
         \x20     - id: build\n\
         \x20       tool: shell\n\
         \x20       with: { cmd: [echo, \"${{ item.name }}\"] }\n\
         \x20     - id: approve\n\
         \x20       when: \"${{ item.gated }}\"\n\
         \x20       gate:\n\
         \x20         title: \"ship ${{ item.name }}?\"\n\
         \x20         form: { approve: { type: boolean } }\n\
         \x20         timeout: 24h\n\
         \x20         on_timeout: deny\n";
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(body)).expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let mut run_ctx = ctx(run_id);
    run_ctx.inputs = serde_json::json!({ "items": gated_items(&[false, true]) });

    let mut waves: Vec<Wave> = Vec::new();
    let mut resume: Option<Resume> = None;
    let terminal = loop {
        assert!(
            waves.len() <= MAX_SEGMENTS,
            "the run never reached a terminal state; waves so far: {waves:?}"
        );
        let outcome = run_workflow(
            &mut conn,
            &def,
            run_id,
            &mut sink,
            &mut host,
            run_ctx.clone(),
            at(10),
            resume.take(),
        )
        .expect("the run drives");
        match outcome {
            RunOutcome::AwaitingWork { pending } => {
                waves.push(
                    pending
                        .iter()
                        .map(|p| (p.step_id.clone(), p.item_index))
                        .collect(),
                );
                // Item 0's `build` fails; item 1's succeeds and carries it on
                // to its gate.
                resume = Some(Resume::Work(
                    pending
                        .iter()
                        .map(|p| WorkDone {
                            step_id: p.step_id.clone(),
                            item_index: p.item_index,
                            status: if p.item_index == Some(0) {
                                WorkStatus::Failed {
                                    message: "the build broke".to_string(),
                                }
                            } else {
                                WorkStatus::Completed
                            },
                            output: Value::Null,
                            output_is_secret_derived: false,
                            task_id: Some(TaskId::new()),
                            first_task_seq: None,
                            last_task_seq: None,
                        })
                        .collect(),
                ));
            }
            RunOutcome::Parked(parked) => {
                assert_eq!(parked.item_index, Some(1));
                resume = Some(Resume::Gate(GateAnswer {
                    step_id: "approve".into(),
                    item_index: parked.item_index,
                    output: serde_json::json!({ "approve": true }),
                }));
            }
            other => break other,
        }
    };

    assert_eq!(
        waves,
        vec![vec![
            ("build".to_string(), Some(0)),
            ("build".to_string(), Some(1)),
        ]],
        "one wave: item 0's failed `build` must not be dispatched a second time when the \
         answer to item 1's gate re-enters the run: {waves:?}"
    );
    let output = map_output(&terminal, "fan");
    let entries = output["items"].as_array().expect("one entry per item");
    assert_eq!(entries[0]["status"], "failed");
    assert_eq!(
        entries[0]["error"], "the build broke",
        "the failure this drive already decided is carried, not re-derived: {entries:?}"
    );
    assert_eq!(entries[1]["status"], "completed");
}

/// A park spans a resume even more surely than a dispatch does — it waits for
/// a human — so an item holding a worktree is refused at its gate for exactly
/// the reason it is refused at a dispatch, with the worktree still released.
#[test]
fn an_items_worktree_cannot_span_a_nested_gates_park_either() {
    let provider = Arc::new(CountingWorktreeProvider::default());
    let (conn, run_id, sink, waves, result) = drive_waves_with_context(
        "steps:\n\
         \x20 - id: fan\n\
         \x20   map:\n\
         \x20     over: \"${{ inputs.items }}\"\n\
         \x20     as: item\n\
         \x20     on_item_error: continue\n\
         \x20     isolation: worktree\n\
         \x20   steps:\n\
         \x20     - id: approve\n\
         \x20       gate:\n\
         \x20         title: \"ship it?\"\n\
         \x20         form: { approve: { type: boolean } }\n\
         \x20         timeout: 1h\n\
         \x20         on_timeout: deny\n",
        &[],
        |run_ctx| {
            run_ctx.inputs = serde_json::json!({ "items": map_items(2) });
            run_ctx.worktree_provider = Some(provider.clone());
        },
    );
    let outcome = result.expect("the run drives");

    assert!(waves.is_empty(), "nothing is dispatched: {waves:?}");
    assert!(
        awaiting_human_forms(&sink).is_empty(),
        "and nobody is asked, because the park is refused before it is taken"
    );
    assert_eq!(
        recover_run(&conn, run_id).unwrap().run.state,
        RunState::Completed,
        "the run is not left suspended on a park that was refused"
    );
    let output = map_output(&outcome, "fan");
    let entries = output["items"].as_array().expect("one entry per item");
    assert_eq!(entries.len(), 2);
    for entry in entries {
        assert_eq!(entry["status"], "failed");
        assert!(
            entry["error"]
                .as_str()
                .is_some_and(|e| e.contains("isolation: worktree") && e.contains("parks the run")),
            "the refusal names the suspension it is about: {entry:?}"
        );
    }
    let materialized = provider.materialized.lock().expect("not poisoned").clone();
    assert_eq!(materialized.len(), 2, "one worktree per item");
    assert_eq!(
        provider.released.lock().expect("not poisoned").clone(),
        materialized,
        "every worktree the refusal abandoned is still released"
    );
}

/// A `map` is one step of the run, so §8.4's admission charges it once —
/// however many of its items park. The companion of
/// [`a_map_step_is_admitted_once_however_many_waves_it_takes`] for the other
/// way a `map` is re-entered, and the same comparison: two runs of one
/// fixture differing only in whether its items need a human.
#[test]
fn a_map_is_admitted_once_however_many_of_its_items_park() {
    fn drive_to_terminal(gated: &[bool]) -> (Connection, RunId) {
        let mut conn = open_test_db();
        let (run_id, _) = seed_run(&mut conn);
        let def = parse_workflow(&workflow(&map_over_gate(2))).expect("fixture parses");
        let mut sink = RecordingSink::default();
        let mut host = FakeHost::new();
        let mut run_ctx = ctx(run_id);
        run_ctx.inputs = serde_json::json!({ "items": gated_items(gated) });
        let mut resume: Option<Resume> = None;
        for segment in 1..=MAX_SEGMENTS {
            let outcome = run_workflow(
                &mut conn,
                &def,
                run_id,
                &mut sink,
                &mut host,
                run_ctx.clone(),
                at(100 * segment as i64),
                resume.take(),
            )
            .expect("the run drives");
            match outcome {
                RunOutcome::Parked(parked) => {
                    resume = Some(Resume::Gate(GateAnswer {
                        step_id: "approve".into(),
                        item_index: parked.item_index,
                        output: serde_json::json!({ "approve": true }),
                    }))
                }
                RunOutcome::Terminal { .. } => return (conn, run_id),
                other => panic!("this fixture dispatches nothing, got {other:?}"),
            }
        }
        panic!("the run never reached a terminal state");
    }

    let (parking_conn, parking_run) = drive_to_terminal(&[true, true]);
    let (quiet_conn, quiet_run) = drive_to_terminal(&[false, false]);
    assert_eq!(
        run_ledger(&parking_conn, parking_run)
            .expect("ledger")
            .spent
            .tasks,
        run_ledger(&quiet_conn, quiet_run)
            .expect("ledger")
            .spent
            .tasks,
        "a `map` re-admitted once per park would charge three tasks in the run whose items \
         both needed a human and one in the run whose items did not"
    );
}

/// A nested gate cannot park a run from `finally:` for the same reason a
/// top-level one cannot (§8.13: the cancel must converge) — the item fails
/// with the reason on its own row rather than suspending a run that is
/// ending.
#[test]
fn a_nested_gate_inside_finally_fails_its_item_rather_than_parking_a_run_that_is_ending() {
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(
        "steps:\n\
         \x20 - id: work\n\
         \x20   emit: { a: 1 }\n\
         finally:\n\
         \x20 - id: fan\n\
         \x20   map:\n\
         \x20     over: \"${{ inputs.items }}\"\n\
         \x20     as: item\n\
         \x20     on_item_error: continue\n\
         \x20   steps:\n\
         \x20     - id: approve\n\
         \x20       gate:\n\
         \x20         title: \"one more thing?\"\n\
         \x20         form: { ok: { type: boolean } }\n\
         \x20         timeout: 1h\n\
         \x20         on_timeout: deny\n",
    ))
    .expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let mut run_ctx = ctx(run_id);
    run_ctx.inputs = serde_json::json!({ "items": map_items(2) });
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
    let RunOutcome::Terminal { .. } = &outcome else {
        panic!("a `finally:` map must not park, got {outcome:?}");
    };
    assert!(host.checkpoints.is_empty(), "no park, so no checkpoint");
    assert!(
        awaiting_human_forms(&sink).is_empty(),
        "and nobody was asked"
    );
    let output = map_output(&outcome, "fan");
    let entries = output["items"].as_array().expect("one entry per item");
    assert!(
        entries.iter().all(|e| e["status"] == "failed"
            && e["error"].as_str().is_some_and(|m| m.contains("finally:"))),
        "each item's entry says why it could not park: {entries:?}"
    );
}

/// **One human's answer must not resolve a question they were never shown.**
/// A [`GateAnswer`] names a step id and an item index, and two `map` steps may
/// declare inner gates under the same id — so an answer for the first map's
/// item is scoped to that map, rather than also releasing the second map's
/// item of the same index when the run drives on to it.
#[test]
fn a_nested_gate_answer_does_not_also_release_a_second_maps_gate_of_the_same_id() {
    let body = "steps:\n\
         \x20 - id: first\n\
         \x20   map:\n\
         \x20     over: \"${{ inputs.items }}\"\n\
         \x20     as: item\n\
         \x20     on_item_error: continue\n\
         \x20   steps:\n\
         \x20     - id: approve\n\
         \x20       gate:\n\
         \x20         title: \"first: ship ${{ item.name }}?\"\n\
         \x20         form: { approve: { type: boolean } }\n\
         \x20         timeout: 1h\n\
         \x20         on_timeout: deny\n\
         \x20 - id: second\n\
         \x20   needs: [first]\n\
         \x20   map:\n\
         \x20     over: \"${{ inputs.items }}\"\n\
         \x20     as: item\n\
         \x20     on_item_error: continue\n\
         \x20   steps:\n\
         \x20     - id: approve\n\
         \x20       gate:\n\
         \x20         title: \"second: ship ${{ item.name }}?\"\n\
         \x20         form: { approve: { type: boolean } }\n\
         \x20         timeout: 1h\n\
         \x20         on_timeout: deny\n";
    let mut conn = open_test_db();
    let (run_id, _) = seed_run(&mut conn);
    let def = parse_workflow(&workflow(body)).expect("fixture parses");
    let mut sink = RecordingSink::default();
    let mut host = FakeHost::new();
    let mut run_ctx = ctx(run_id);
    run_ctx.inputs = serde_json::json!({ "items": gated_items(&[true]) });

    let first = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx.clone(),
        at(10),
        None,
    )
    .expect("the run drives");
    assert!(
        matches!(first, RunOutcome::Parked(_)),
        "the first map's item parks, got {first:?}"
    );

    let second = run_workflow(
        &mut conn,
        &def,
        run_id,
        &mut sink,
        &mut host,
        run_ctx,
        at(20),
        Some(Resume::Gate(GateAnswer {
            step_id: "approve".into(),
            item_index: Some(0),
            output: serde_json::json!({ "approve": true }),
        })),
    )
    .expect("the answer releases the park");

    assert!(
        matches!(second, RunOutcome::Parked(_)),
        "the second map's identically-named gate still has to be asked, got {second:?}"
    );
    assert_eq!(
        item_step_row(&conn, run_id, "approve", 0).map(|r| r.0),
        Some(StepRunState::Running),
        "and it is waiting on its own park, not carrying the first map's answer"
    );
    let titles: Vec<String> = awaiting_human_forms(&sink)
        .iter()
        .map(|f| {
            f["form_schema"]["title"]
                .as_str()
                .unwrap_or("?")
                .to_string()
        })
        .collect();
    assert_eq!(
        titles,
        vec!["first: ship item-0?", "second: ship item-0?"],
        "two questions were asked, and the second is the second map's own: {titles:?}"
    );
}

/// A gate answer's `item_index` decides **which list** it is validated
/// against, so an answer filed at the wrong nesting level is refused rather
/// than silently resolving a same-named gate at the other one.
#[test]
fn a_gate_answer_filed_at_the_wrong_nesting_level_is_refused() {
    let nested = map_over_gate(1);
    let top_level = "steps:\n\
         \x20 - id: approve\n\
         \x20   gate:\n\
         \x20     title: \"ship it?\"\n\
         \x20     form: { approve: { type: boolean } }\n\
         \x20     timeout: 1h\n\
         \x20     on_timeout: deny\n";

    for (body, answer, why) in [
        (
            nested.as_str(),
            GateAnswer {
                step_id: "approve".into(),
                item_index: None,
                output: serde_json::json!({}),
            },
            "`approve` is a `map` inner step, so a top-level answer names no gate of the \
             `steps:` phase",
        ),
        (
            nested.as_str(),
            GateAnswer {
                step_id: "done".into(),
                item_index: Some(0),
                output: serde_json::json!({}),
            },
            "`done` is an `emit:` inner step, not a gate — injecting an output under its id \
             would overwrite the value it is about to write",
        ),
        (
            top_level,
            GateAnswer {
                step_id: "approve".into(),
                item_index: Some(0),
                output: serde_json::json!({}),
            },
            "a top-level gate has no item dimension, so an indexed answer names no nested gate",
        ),
    ] {
        let (_, _, _, _, result) =
            drive_with(body, 10, FakeHost::new(), Some(Resume::Gate(answer)));
        assert!(
            matches!(result, Err(RunLoopError::UnknownGateStep { .. })),
            "{why}: got {result:?}"
        );
    }
}
