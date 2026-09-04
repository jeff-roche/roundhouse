//! Task 20a (B12a) — §8.13's run controls, over the durable row.
//!
//! Every assertion here reads the run back out of SQLite rather than
//! inspecting a returned value: the defect this task closes is that the
//! planned controls mutated a borrowed enum and changed nothing durable.
//!
//! Every test supplies `now` explicitly — this crate reads no clock.

use roundhouse_core::{JobId, SessionId, Timestamp};
use roundhouse_flow::control::{cancel, pause, resume, retry_from_step, ControlError};
use roundhouse_flow::durability::{
    checkpoint_step, insert_workflow_run, open_test_db, recover_run, transition_run,
    DurabilityError, RunState, StepDisposition, StepOutput, StepRunState, WorkflowRun,
    WorkflowStepRun,
};
use roundhouse_flow::exec::{RunId, StepOutcome, StepStatus};
use rusqlite::Connection;

const NANOS_PER_SEC: i64 = 1_000_000_000;

fn a_run(id: RunId, session_id: SessionId) -> WorkflowRun {
    WorkflowRun {
        id,
        job_id: JobId::new(),
        job_version: 3,
        content_hash: "sha256:pinned".into(),
        session_id,
        binding_id: None,
        trigger_event_id: None,
        state: RunState::Running,
        parent_run_id: None,
        forked_from_run_id: None,
        awaiting_until: None,
        started_at: Timestamp::from_unix_nanos(1_000 * NANOS_PER_SEC),
        ended_at: None,
    }
}

fn a_running_run() -> (Connection, RunId) {
    let mut conn = open_test_db();
    let run_id = RunId::new();
    insert_workflow_run(&mut conn, &a_run(run_id, SessionId::new())).expect("insert the run row");
    (conn, run_id)
}

fn at(secs: i64) -> Timestamp {
    Timestamp::from_unix_nanos(secs * NANOS_PER_SEC)
}

/// A completed step row carrying a real output, built through
/// `StepOutput::from_outcome` so the taint flag is the executor's own.
fn completed_step(run_id: RunId, step_id: &str, output: serde_json::Value) -> WorkflowStepRun {
    WorkflowStepRun {
        run_id,
        step_id: step_id.to_string(),
        attempt: 1,
        item_index: None,
        disposition: StepDisposition::Effectful,
        state: StepRunState::Completed,
        first_task_seq: Some(10),
        last_task_seq: Some(12),
        output: Some(StepOutput::from_outcome(&StepOutcome {
            step_id: step_id.to_string(),
            output,
            status: StepStatus::Completed,
            output_is_secret_derived: false,
            gate_condition_was_secret_derived: false,
        })),
        error: None,
    }
}

// ---------------------------------------------------------------------------
// cancel / pause / resume — durable, not a borrowed enum
// ---------------------------------------------------------------------------

#[test]
fn cancel_marks_cancelling_in_the_row_rather_than_in_a_borrowed_enum() {
    let (mut conn, run_id) = a_running_run();

    cancel(&mut conn, run_id, at(2_000)).expect("a running run can be cancelled");

    let row = recover_run(&conn, run_id).unwrap().run;
    assert_eq!(
        row.state,
        RunState::Cancelling,
        "§8.13's cancel is cooperative: it marks Cancelling and lets in-flight \
         work drain; it does not jump straight to Cancelled"
    );
    assert_eq!(
        row.ended_at, None,
        "a cancelling run has not ended yet — the drain and `finally:` still run"
    );
}

#[test]
fn a_cancelling_run_reaches_cancelled_with_the_instant_it_ended() {
    let (mut conn, run_id) = a_running_run();
    cancel(&mut conn, run_id, at(2_000)).unwrap();

    transition_run(&mut conn, run_id, RunState::Cancelled, at(2_500))
        .expect("the drain finishes and the terminal state lands");

    let row = recover_run(&conn, run_id).unwrap().run;
    assert_eq!(row.state, RunState::Cancelled);
    assert_eq!(row.ended_at, Some(at(2_500)));
}

#[test]
fn pause_and_resume_round_trip_through_the_row() {
    let (mut conn, run_id) = a_running_run();

    pause(&mut conn, run_id, at(2_000)).expect("a running run can be paused");
    assert_eq!(
        recover_run(&conn, run_id).unwrap().run.state,
        RunState::Paused
    );

    resume(&mut conn, run_id, at(3_000)).expect("a paused run can be resumed");
    let row = recover_run(&conn, run_id).unwrap().run;
    assert_eq!(row.state, RunState::Running);
    assert_eq!(
        row.ended_at, None,
        "neither pause nor resume is a terminal transition"
    );
}

#[test]
fn resuming_a_run_that_is_not_paused_reports_the_state_it_actually_found() {
    let (mut conn, run_id) = a_running_run();

    let err = resume(&mut conn, run_id, at(2_000)).expect_err("a running run is not resumable");

    match err {
        ControlError::NotPaused { run_id: r, state } => {
            assert_eq!(r, run_id);
            assert_eq!(
                state,
                RunState::Running,
                "the error names the state the row was actually in, so an \
                 operator is not told only that the call failed"
            );
        }
        other => panic!("expected NotPaused, got {other:?}"),
    }
    assert_eq!(
        recover_run(&conn, run_id).unwrap().run.state,
        RunState::Running
    );
}

#[test]
fn pausing_a_run_that_is_already_cancelling_is_refused() {
    let (mut conn, run_id) = a_running_run();
    cancel(&mut conn, run_id, at(2_000)).unwrap();

    let err = pause(&mut conn, run_id, at(3_000)).expect_err("a cancel in flight is not pausable");

    assert!(
        matches!(
            err,
            ControlError::NotRunning {
                state: RunState::Cancelling,
                ..
            }
        ),
        "got {err:?}"
    );
    assert_eq!(
        recover_run(&conn, run_id).unwrap().run.state,
        RunState::Cancelling,
        "the cancel stands"
    );
}

#[test]
fn cancelling_an_already_cancelling_run_is_refused_rather_than_reported_as_a_fresh_cancel() {
    let (mut conn, run_id) = a_running_run();
    cancel(&mut conn, run_id, at(2_000)).unwrap();

    let err = cancel(&mut conn, run_id, at(3_000)).expect_err("already draining");

    assert!(
        matches!(
            err,
            ControlError::NotCancellable {
                state: RunState::Cancelling,
                ..
            }
        ),
        "an operator asking twice is told the run is already draining: {err:?}"
    );
}

#[test]
fn a_parked_run_can_still_be_cancelled() {
    let (mut conn, run_id) = a_running_run();
    transition_run(&mut conn, run_id, RunState::AwaitingHuman, at(2_000)).unwrap();

    cancel(&mut conn, run_id, at(3_000))
        .expect("a run waiting on a human who never answers must remain cancellable");

    assert_eq!(
        recover_run(&conn, run_id).unwrap().run.state,
        RunState::Cancelling
    );
}

#[test]
fn controlling_a_run_with_no_row_is_not_found_not_a_state_complaint() {
    let mut conn = open_test_db();
    let absent = RunId::new();

    let err = cancel(&mut conn, absent, at(1)).expect_err("no row, no control");

    assert!(
        matches!(
            err,
            ControlError::Durability(DurabilityError::RunNotFound { .. })
        ),
        "got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// retry-from-step: §8.13's fork (history is append-only, never rewritten)
// ---------------------------------------------------------------------------

/// A finished run with three completed steps, ready to be forked.
fn a_finished_run_with_three_steps() -> (Connection, RunId) {
    let (mut conn, run_id) = a_running_run();
    for (step_id, value) in [
        ("checkout", serde_json::json!({"sha": "abc"})),
        ("build", serde_json::json!({"artifact": "app.tar"})),
        ("deploy", serde_json::json!({"url": "https://x"})),
    ] {
        checkpoint_step(&mut conn, &completed_step(run_id, step_id, value)).unwrap();
    }
    transition_run(&mut conn, run_id, RunState::Failed, at(5_000)).unwrap();
    (conn, run_id)
}

const STEP_ORDER: &[&str] = &["checkout", "build", "deploy"];

#[test]
fn retry_from_step_writes_a_new_run_row_linked_by_forked_from_run_id() {
    let (mut conn, original) = a_finished_run_with_three_steps();
    let new_session = SessionId::new();

    let forked = retry_from_step(
        &mut conn,
        original,
        "build",
        STEP_ORDER,
        new_session,
        at(6_000),
    )
    .expect("a failed run can be retried from a step");

    assert_ne!(
        forked.new_run_id, original,
        "a genuinely new run, not a mutation of the old one"
    );
    assert_eq!(forked.forked_from_run_id, original);

    let fork_row = recover_run(&conn, forked.new_run_id)
        .expect("the fork is a real row, not just a returned value")
        .run;
    assert_eq!(
        fork_row.forked_from_run_id,
        Some(original),
        "the column migration 0007 added for §8.13's fork link is finally written"
    );
    assert_eq!(fork_row.state, RunState::Running);
    assert_eq!(fork_row.started_at, at(6_000));
    assert_eq!(fork_row.ended_at, None);
    assert_eq!(
        fork_row.session_id, new_session,
        "§8.6: each run is a new Session"
    );
    assert_eq!(
        (fork_row.job_id, fork_row.job_version, fork_row.content_hash),
        {
            let origin = recover_run(&conn, original).unwrap().run;
            (origin.job_id, origin.job_version, origin.content_hash)
        },
        "the fork runs the same pinned job content as the run it forks"
    );
}

#[test]
fn a_fork_inherits_completed_steps_before_the_cut_and_nothing_from_the_cut_onward() {
    let (mut conn, original) = a_finished_run_with_three_steps();

    let forked = retry_from_step(
        &mut conn,
        original,
        "build",
        STEP_ORDER,
        SessionId::new(),
        at(6_000),
    )
    .unwrap();

    let inherited: Vec<&str> = forked
        .inherited_step_outputs
        .iter()
        .map(|s| s.step_id.as_str())
        .collect();
    assert_eq!(
        inherited,
        vec!["checkout"],
        "`build` is the retry point and `deploy` is downstream of it, so both re-run"
    );

    let fork_steps = recover_run(&conn, forked.new_run_id).unwrap().steps;
    assert_eq!(
        fork_steps.len(),
        1,
        "the fork's own rows are the inherited ones and nothing else"
    );
    assert_eq!(fork_steps[0].step_id, "checkout");
    assert_eq!(fork_steps[0].run_id, forked.new_run_id);
    assert_eq!(fork_steps[0].state, StepRunState::Completed);
    assert_eq!(
        fork_steps[0]
            .output
            .as_ref()
            .expect("the inherited output is the point of the fork")
            .value_unredacted_for_resume(),
        &serde_json::json!({"sha": "abc"}),
        "§8.13: the fork inherits completed step OUTPUTS, so `${{ steps.checkout.output }}` \
         still resolves in the new run"
    );
}

#[test]
fn an_inherited_step_carries_no_task_seq_range_because_its_evidence_is_the_originals() {
    let (mut conn, original) = a_finished_run_with_three_steps();

    let forked = retry_from_step(
        &mut conn,
        original,
        "deploy",
        STEP_ORDER,
        SessionId::new(),
        at(6_000),
    )
    .unwrap();

    let fork_steps = recover_run(&conn, forked.new_run_id).unwrap().steps;
    assert_eq!(fork_steps.len(), 2);
    for step in &fork_steps {
        assert_eq!(
            (step.first_task_seq, step.last_task_seq),
            (None, None),
            "§8.10's seq range joins back to a session's log, and the tasks live \
             in the ORIGINAL run's session — copying the range would point the \
             fork's join at tasks its own session never emitted"
        );
    }

    let origin_steps = recover_run(&conn, original).unwrap().steps;
    assert!(
        origin_steps
            .iter()
            .all(|s| s.first_task_seq == Some(10) && s.last_task_seq == Some(12)),
        "the original keeps its ranges: the evidence is still exactly where it was"
    );
}

#[test]
fn retry_from_step_never_rewrites_the_run_it_forks() {
    let (mut conn, original) = a_finished_run_with_three_steps();
    let before = recover_run(&conn, original).unwrap();

    retry_from_step(
        &mut conn,
        original,
        "build",
        STEP_ORDER,
        SessionId::new(),
        at(6_000),
    )
    .unwrap();

    let after = recover_run(&conn, original).unwrap();
    assert_eq!(
        after.run, before.run,
        "§8.13: history is append-only, so a fork never rewrites it"
    );
    assert_eq!(after.steps, before.steps);
    assert_eq!(after.run.state, RunState::Failed);
    assert_eq!(after.run.ended_at, Some(at(5_000)));
}

#[test]
fn forking_from_a_step_the_job_never_declared_is_refused_rather_than_inheriting_everything() {
    let (mut conn, original) = a_finished_run_with_three_steps();

    let err = retry_from_step(
        &mut conn,
        original,
        "publsh",
        STEP_ORDER,
        SessionId::new(),
        at(6_000),
    )
    .expect_err("a typo'd step id must not silently fork the whole run");

    match err {
        ControlError::UnknownStep { ref step_id } => assert_eq!(step_id, "publsh"),
        ref other => panic!("expected UnknownStep, got {other:?}"),
    }
    assert_eq!(
        count_runs(&conn),
        1,
        "a refused retry writes no fork row at all"
    );
}

/// Fix round 1 (Task 20a, item E): a `Completed` step `step_order` never
/// mentions must not be silently dropped from the fork — for an `Effectful`
/// step that is a duplicate side effect on re-drive, the exact consequence
/// `fork_run`'s own transaction exists to prevent for any other reason.
#[test]
fn a_completed_step_missing_from_step_order_is_refused_rather_than_dropped_and_rerun() {
    let (mut conn, original) = a_finished_run_with_three_steps();
    // "deploy" completed in the original run but the caller's step_order
    // never names it — a wrong step_order reaching the fork with the
    // transaction fully intact.
    let incomplete_step_order: &[&str] = &["checkout", "build"];

    let err = retry_from_step(
        &mut conn,
        original,
        "build",
        incomplete_step_order,
        SessionId::new(),
        at(6_000),
    )
    .expect_err("a completed step invisible to step_order would silently re-execute in the fork");

    match err {
        ControlError::StepOrderMissingCompletedStep {
            run_id,
            ref step_id,
        } => {
            assert_eq!(run_id, original);
            assert_eq!(step_id, "deploy");
        }
        ref other => panic!("expected StepOrderMissingCompletedStep, got {other:?}"),
    }
    assert_eq!(
        count_runs(&conn),
        1,
        "a refused retry writes no fork row at all"
    );
}

/// Fix round 1 (Task 20a, item D): the one property `StepOutput`'s design
/// exists to carry — `output_is_secret_derived` — must survive a fork.
/// Every other fork fixture in this file builds `false`, so this is the only
/// test that exercises the `true` path through `..step.clone()`.
#[test]
fn a_fork_preserves_a_secret_derived_output_flag() {
    let (mut conn, run_id) = a_running_run();
    let tainted = WorkflowStepRun {
        run_id,
        step_id: "fetch_secret".to_string(),
        attempt: 1,
        item_index: None,
        disposition: StepDisposition::Effectful,
        state: StepRunState::Completed,
        first_task_seq: Some(1),
        last_task_seq: Some(2),
        output: Some(StepOutput::from_outcome(&StepOutcome {
            step_id: "fetch_secret".to_string(),
            output: serde_json::json!({"token": "abc"}),
            status: StepStatus::Completed,
            output_is_secret_derived: true,
            gate_condition_was_secret_derived: false,
        })),
        error: None,
    };
    checkpoint_step(&mut conn, &tainted).unwrap();
    transition_run(&mut conn, run_id, RunState::Failed, at(5_000)).unwrap();

    let forked = retry_from_step(
        &mut conn,
        run_id,
        "next",
        &["fetch_secret", "next"],
        SessionId::new(),
        at(6_000),
    )
    .expect("a failed run with a tainted completed step can be forked");

    let fork_steps = recover_run(&conn, forked.new_run_id).unwrap().steps;
    assert_eq!(fork_steps.len(), 1);
    assert!(
        fork_steps[0]
            .output
            .as_ref()
            .expect("the tainted output is the point of this test")
            .is_secret_derived(),
        "the fork must inherit the taint flag, not silently launder it"
    );
}

#[test]
fn retry_from_step_refuses_a_run_that_has_not_ended() {
    let (mut conn, original) = a_running_run();

    let err = retry_from_step(
        &mut conn,
        original,
        "build",
        STEP_ORDER,
        SessionId::new(),
        at(6_000),
    )
    .expect_err("forking a live run would duplicate its in-flight effectful steps");

    assert!(
        matches!(
            err,
            ControlError::RunStillActive {
                state: RunState::Running,
                ..
            }
        ),
        "got {err:?}"
    );
    assert_eq!(count_runs(&conn), 1);
}

#[test]
fn retrying_a_run_that_does_not_exist_is_not_found() {
    let mut conn = open_test_db();

    let err = retry_from_step(
        &mut conn,
        RunId::new(),
        "build",
        STEP_ORDER,
        SessionId::new(),
        at(6_000),
    )
    .expect_err("nothing to fork");

    assert!(
        matches!(
            err,
            ControlError::Durability(DurabilityError::RunNotFound { .. })
        ),
        "got {err:?}"
    );
}

#[test]
fn a_fork_can_itself_be_forked_so_a_lineage_is_a_chain_not_a_star() {
    let (mut conn, original) = a_finished_run_with_three_steps();
    let first = retry_from_step(
        &mut conn,
        original,
        "deploy",
        STEP_ORDER,
        SessionId::new(),
        at(6_000),
    )
    .unwrap();
    transition_run(&mut conn, first.new_run_id, RunState::Failed, at(7_000)).unwrap();

    let second = retry_from_step(
        &mut conn,
        first.new_run_id,
        "build",
        STEP_ORDER,
        SessionId::new(),
        at(8_000),
    )
    .unwrap();

    assert_eq!(second.forked_from_run_id, first.new_run_id);
    assert_eq!(
        recover_run(&conn, second.new_run_id)
            .unwrap()
            .run
            .forked_from_run_id,
        Some(first.new_run_id),
        "each fork links to the run it was forked from, not to the root of the lineage"
    );
    assert_eq!(
        recover_run(&conn, second.new_run_id)
            .unwrap()
            .steps
            .iter()
            .map(|s| s.step_id.clone())
            .collect::<Vec<_>>(),
        vec!["checkout".to_string()],
        "the second fork inherits from the FIRST fork's own rows, which is why \
         those rows had to be copied rather than left behind"
    );
}

fn count_runs(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM workflow_run", [], |row| row.get(0))
        .unwrap()
}

/// A `map` step's per-item rows are distinct rows only because
/// `(step_id, attempt, item_index)` is part of the key — so a fork must carry
/// each item across separately rather than collapsing them into one row.
#[test]
fn a_fork_carries_each_map_item_row_across_separately() {
    let (mut conn, run_id) = a_running_run();
    for item in 0u32..2 {
        let mut row = completed_step(run_id, "fanout", serde_json::json!({ "item": item }));
        row.item_index = Some(item);
        row.attempt = 2;
        checkpoint_step(&mut conn, &row).unwrap();
    }
    checkpoint_step(
        &mut conn,
        &completed_step(run_id, "collect", serde_json::json!({})),
    )
    .unwrap();
    transition_run(&mut conn, run_id, RunState::Failed, at(5_000)).unwrap();

    let forked = retry_from_step(
        &mut conn,
        run_id,
        "collect",
        &["fanout", "collect"],
        SessionId::new(),
        at(6_000),
    )
    .unwrap();

    let fork_steps = recover_run(&conn, forked.new_run_id).unwrap().steps;
    assert_eq!(
        fork_steps
            .iter()
            .map(|s| (s.step_id.as_str(), s.item_index, s.attempt))
            .collect::<Vec<_>>(),
        vec![("fanout", Some(0), 2), ("fanout", Some(1), 2)],
        "both items survive with their own index, and the attempt number is \
         the original's — the fork did not re-run these steps, so claiming \
         attempt 1 would misreport how the output was reached"
    );
    assert_eq!(
        fork_steps[1]
            .output
            .as_ref()
            .unwrap()
            .value_unredacted_for_resume(),
        &serde_json::json!({"item": 1}),
        "each item keeps its own output rather than one overwriting the other"
    );
}
