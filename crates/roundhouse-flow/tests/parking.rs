//! Task 17 (B9) — §8.11's stateless parking: the relative -> absolute
//! deadline conversion, `hold_workspace`'s TTL resolution, and the 7-day
//! reaper predicate.
//!
//! Every test supplies `now` explicitly. This crate reads no clock (ruling
//! P65, `durability.rs`'s "This module never reads a clock"), so nothing
//! here is wall-clock dependent and no test needs slack for drift.

use roundhouse_core::{JobId, SessionId, TaskId, Timestamp};
use roundhouse_flow::durability::{
    insert_workflow_run, open_test_db, recover_run, RunState, WorkflowRun,
};
use roundhouse_flow::exec::RunId;
use roundhouse_flow::hitl::{AwaitingHuman, HumanWaitSource, UncheckedOnTimeout};
use roundhouse_flow::parking::{
    absolute_deadline, park, reaper_cutoff, resolve_hold_ttl, CheckpointError, CheckpointRef,
    Checkpointer, ParkError, WorkspaceDisposition, DEFAULT_HOLD_TTL, SYSTEM_WIDE_HOLD_CAP,
};
use roundhouse_flow::parse::steps::{parse_step, StepBody, StepDef};
use roundhouse_flow::parse::types::OnTimeout;
use rusqlite::Connection;
use std::time::Duration;

const NANOS_PER_SEC: i64 = 1_000_000_000;

/// Records every `checkpoint` call so the tests can assert that one ran, and
/// in which order relative to the durable write.
struct FakeCheckpointer {
    calls: Vec<(SessionId, String)>,
}

impl FakeCheckpointer {
    fn new() -> Self {
        FakeCheckpointer { calls: Vec::new() }
    }
}

impl Checkpointer for FakeCheckpointer {
    fn checkpoint(
        &mut self,
        session_id: SessionId,
        label: &str,
    ) -> Result<CheckpointRef, CheckpointError> {
        self.calls.push((session_id, label.to_string()));
        Ok(CheckpointRef(format!("checkpoint:{session_id}")))
    }
}

/// The §8.11 ordering's failing half: "before releasing, it runs an implicit
/// `checkpoint` task". If the checkpoint cannot be taken, nothing may be
/// released and nothing may be parked.
struct FailingCheckpointer;

impl Checkpointer for FailingCheckpointer {
    fn checkpoint(
        &mut self,
        _session_id: SessionId,
        _label: &str,
    ) -> Result<CheckpointRef, CheckpointError> {
        Err(CheckpointError {
            message: "worktree has an unresolvable merge conflict".to_string(),
        })
    }
}

fn a_run(id: RunId, session_id: SessionId) -> WorkflowRun {
    WorkflowRun {
        id,
        job_id: JobId::new(),
        job_version: 1,
        content_hash: "sha256:a".into(),
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

/// A run row already in the database, plus its connection.
fn a_running_run(session_id: SessionId) -> (Connection, RunId) {
    let mut conn = open_test_db();
    let run_id = RunId::new();
    insert_workflow_run(&mut conn, &a_run(run_id, session_id)).expect("insert the run row");
    (conn, run_id)
}

/// A real parsed `gate:` step, so the human wait under test comes from the
/// parser rather than a hand-built value.
fn gate_step(yaml: &str) -> StepDef {
    parse_step(&serde_yaml::from_str(yaml).expect("fixture parses as YAML"))
        .expect("fixture parses as a step")
}

fn awaiting_from_gate(step: &StepDef) -> AwaitingHuman {
    let StepBody::Gate {
        title,
        form,
        timeout,
        on_timeout,
        ..
    } = &step.body
    else {
        panic!("expected a gate step");
    };
    AwaitingHuman::from_gate(TaskId::new(), title, form, timeout, on_timeout)
        .expect("the fixture gate builds a human wait")
}

/// A mid-step elicitation with no declared window — `timeout_after: None`
/// paired with `HumanWaitSource::Elicitation`, the only shape `hitl.rs:249-252`
/// documents as reachable for a `None` deadline. Built literally, field by
/// field, rather than by mutating a `from_gate` value down to `None`: every
/// `AwaitingHuman` field is `pub` and `HumanWaitSource::Elicitation` has no
/// constructor in this crate on purpose (the elicitation call site is
/// outside it, Phase 3's MCP host), so a hand-built struct literal *is* the
/// shape the real caller will eventually pass, not a test-only shortcut.
fn an_elicitation_with_no_deadline() -> AwaitingHuman {
    AwaitingHuman {
        task_id: TaskId::new(),
        source: HumanWaitSource::Elicitation,
        form_schema: serde_json::json!({
            "type": "object",
            "title": "Provide input",
            "properties": {},
        }),
        timeout_after: None,
        on_timeout: UncheckedOnTimeout::new(OnTimeout::Deny),
    }
}

// ---------------------------------------------------------------------------
// The durable park: relative -> absolute, written with the run state
// ---------------------------------------------------------------------------

#[test]
fn park_writes_an_absolute_deadline_derived_from_now_plus_the_relative_window() {
    let session_id = SessionId::new();
    let (mut conn, run_id) = a_running_run(session_id);
    let step =
        gate_step("id: approve\ngate: { title: 'Ship it?', timeout: 12h, on_timeout: deny }");
    let awaiting = awaiting_from_gate(&step);
    let now = Timestamp::from_unix_nanos(1_700_000_000 * NANOS_PER_SEC);
    let mut cp = FakeCheckpointer::new();

    let result = park(&mut conn, run_id, &awaiting, false, now, &mut cp).expect("park succeeds");

    let expected = Timestamp::from_unix_nanos((1_700_000_000 + 12 * 3600) * NANOS_PER_SEC);
    assert_eq!(result.awaiting_until, Some(expected));

    let recovered = recover_run(&conn, run_id).expect("recover the parked run");
    assert_eq!(recovered.run.state, RunState::AwaitingHuman);
    assert_eq!(
        recovered.run.awaiting_until,
        Some(expected),
        "the durable truth is the row, not the returned value"
    );
}

#[test]
fn a_re_driven_park_never_gets_a_fresh_window_it_moves_only_by_the_now_the_caller_supplied() {
    // The property `hitl::AwaitingHuman`'s missing `Deserialize` exists to
    // protect. Both orderings of the claim are measured (P70), because
    // either one alone is consistent with the bug: re-driving at the SAME
    // instant must be a no-op, and re-driving at a LATER instant must move
    // the deadline by exactly the caller's own delta — never by a fresh full
    // 1h window re-derived off the row.
    let session_id = SessionId::new();
    let (mut conn, run_id) = a_running_run(session_id);
    let step = gate_step("id: approve\ngate: { title: 'Ship it?', timeout: 1h, on_timeout: deny }");
    let awaiting = awaiting_from_gate(&step);
    let first_now = Timestamp::from_unix_nanos(1_000 * NANOS_PER_SEC);
    let mut cp = FakeCheckpointer::new();

    park(&mut conn, run_id, &awaiting, false, first_now, &mut cp).expect("first park");
    let after_first = recover_run(&conn, run_id).unwrap().run.awaiting_until;
    assert_eq!(
        after_first,
        Some(Timestamp::from_unix_nanos((1_000 + 3600) * NANOS_PER_SEC))
    );

    park(&mut conn, run_id, &awaiting, false, first_now, &mut cp)
        .expect("re-drive with the same now");
    assert_eq!(
        recover_run(&conn, run_id).unwrap().run.awaiting_until,
        after_first,
        "re-driving a park at the same instant must not extend it"
    );

    // 10 minutes later: the deadline moves 10 minutes, not a fresh hour.
    let later = Timestamp::from_unix_nanos((1_000 + 600) * NANOS_PER_SEC);
    park(&mut conn, run_id, &awaiting, false, later, &mut cp).expect("re-drive at a later now");
    assert_eq!(
        recover_run(&conn, run_id).unwrap().run.awaiting_until,
        Some(Timestamp::from_unix_nanos(
            (1_000 + 600 + 3600) * NANOS_PER_SEC
        )),
        "the new deadline is the caller's new `now` plus the same window"
    );
}

#[test]
fn an_elicitation_with_no_declared_window_parks_with_a_null_deadline() {
    let session_id = SessionId::new();
    let (mut conn, run_id) = a_running_run(session_id);
    let awaiting = an_elicitation_with_no_deadline();
    let now = Timestamp::from_unix_nanos(1_000 * NANOS_PER_SEC);
    let mut cp = FakeCheckpointer::new();

    let result = park(&mut conn, run_id, &awaiting, false, now, &mut cp).expect("park succeeds");

    assert_eq!(result.awaiting_until, None);
    let recovered = recover_run(&conn, run_id).expect("recover");
    assert_eq!(recovered.run.state, RunState::AwaitingHuman);
    assert_eq!(recovered.run.awaiting_until, None);
}

#[test]
fn parking_a_run_with_no_row_is_rejected_rather_than_writing_nothing_silently() {
    let mut conn = open_test_db();
    let absent = RunId::new();
    let step = gate_step("id: approve\ngate: { title: 'Ship it?', timeout: 1h, on_timeout: deny }");
    let awaiting = awaiting_from_gate(&step);
    let mut cp = FakeCheckpointer::new();

    let err = park(
        &mut conn,
        absent,
        &awaiting,
        false,
        Timestamp::from_unix_nanos(0),
        &mut cp,
    )
    .expect_err("a run with no row cannot be parked");

    match err {
        ParkError::RunNotFound { run_id } => assert_eq!(run_id, absent),
        other => panic!("expected RunNotFound, got {other:?}"),
    }
    assert!(
        cp.calls.is_empty(),
        "no restore point should be taken for a run that cannot be parked"
    );
}

// ---------------------------------------------------------------------------
// §8.11's ordering: checkpoint first, both arms
// ---------------------------------------------------------------------------

#[test]
fn a_successful_park_checkpoints_the_runs_session_before_it_writes_the_row() {
    let session_id = SessionId::new();
    let (mut conn, run_id) = a_running_run(session_id);
    let step = gate_step("id: approve\ngate: { title: 'Ship it?', timeout: 1h, on_timeout: deny }");
    let awaiting = awaiting_from_gate(&step);
    let mut cp = FakeCheckpointer::new();

    let result = park(
        &mut conn,
        run_id,
        &awaiting,
        false,
        Timestamp::from_unix_nanos(0),
        &mut cp,
    )
    .expect("park succeeds");

    assert_eq!(
        cp.calls,
        vec![(session_id, "awaiting_human_park".to_string())],
        "exactly one checkpoint, of the run row's own session — `park` reads \
         `workflow_run.session_id` rather than taking it from the caller, so \
         this cannot pass by the test having handed it the right one"
    );
    assert_eq!(result.session_id, session_id);
    assert_eq!(
        result.checkpoint_ref,
        CheckpointRef(format!("checkpoint:{session_id}"))
    );
    assert_eq!(
        recover_run(&conn, run_id).unwrap().run.state,
        RunState::AwaitingHuman
    );
}

#[test]
fn a_failed_checkpoint_leaves_the_run_running_with_no_deadline_written() {
    // The other half of the ordering claim (P70): asserting the success
    // ordering alone would not show the write is actually gated on the
    // checkpoint.
    let session_id = SessionId::new();
    let (mut conn, run_id) = a_running_run(session_id);
    let step = gate_step("id: approve\ngate: { title: 'Ship it?', timeout: 1h, on_timeout: deny }");
    let awaiting = awaiting_from_gate(&step);

    let err = park(
        &mut conn,
        run_id,
        &awaiting,
        false,
        Timestamp::from_unix_nanos(0),
        &mut FailingCheckpointer,
    )
    .expect_err("a park whose checkpoint failed must not park");

    assert!(matches!(err, ParkError::Checkpoint(_)), "got {err:?}");
    let recovered = recover_run(&conn, run_id).expect("recover");
    assert_eq!(recovered.run.state, RunState::Running);
    assert_eq!(recovered.run.awaiting_until, None);
}

// ---------------------------------------------------------------------------
// `hold_workspace` TTL resolution (§8.11)
// ---------------------------------------------------------------------------

#[test]
fn hold_workspace_ttl_defaults_to_the_enclosing_gates_own_timeout() {
    assert_eq!(
        resolve_hold_ttl(Some(Duration::from_secs(24 * 3600))),
        Duration::from_secs(24 * 3600)
    );
}

#[test]
fn hold_workspace_falls_back_to_72h_with_no_explicit_gate_timeout() {
    assert_eq!(resolve_hold_ttl(None), Duration::from_secs(72 * 3600));
    assert_eq!(DEFAULT_HOLD_TTL, Duration::from_secs(72 * 3600));
}

#[test]
fn the_seven_day_cap_clamps_a_gate_that_asks_for_longer() {
    assert_eq!(
        resolve_hold_ttl(Some(Duration::from_secs(30 * 86400))),
        Duration::from_secs(7 * 86400)
    );
    assert_eq!(SYSTEM_WIDE_HOLD_CAP, Duration::from_secs(7 * 86400));
}

#[test]
fn park_without_hold_workspace_directs_the_caller_to_release_the_worktree() {
    let session_id = SessionId::new();
    let (mut conn, run_id) = a_running_run(session_id);
    let step = gate_step("id: approve\ngate: { title: 'Ship it?', timeout: 1h, on_timeout: deny }");
    let awaiting = awaiting_from_gate(&step);
    let mut cp = FakeCheckpointer::new();

    let result = park(
        &mut conn,
        run_id,
        &awaiting,
        false,
        Timestamp::from_unix_nanos(0),
        &mut cp,
    )
    .expect("park succeeds");

    assert_eq!(result.workspace, WorkspaceDisposition::Release);
}

#[test]
fn park_with_hold_workspace_returns_an_absolute_hold_deadline_not_a_relative_ttl() {
    let session_id = SessionId::new();
    let (mut conn, run_id) = a_running_run(session_id);
    let step =
        gate_step("id: approve\ngate: { title: 'Ship it?', timeout: 24h, on_timeout: deny }");
    let awaiting = awaiting_from_gate(&step);
    let now = Timestamp::from_unix_nanos(500 * NANOS_PER_SEC);
    let mut cp = FakeCheckpointer::new();

    let result = park(&mut conn, run_id, &awaiting, true, now, &mut cp).expect("park succeeds");

    assert_eq!(
        result.workspace,
        WorkspaceDisposition::HoldUntil(Timestamp::from_unix_nanos(
            (500 + 24 * 3600) * NANOS_PER_SEC
        ))
    );
}

#[test]
fn holding_a_workspace_for_a_wait_with_no_window_uses_the_72h_fallback() {
    // The `DEFAULT_HOLD_TTL` arm reached through `park` rather than through
    // `resolve_hold_ttl` alone. `timeout_after: None` is an elicitation, the
    // one source that can produce it.
    let session_id = SessionId::new();
    let (mut conn, run_id) = a_running_run(session_id);
    let awaiting = an_elicitation_with_no_deadline();
    let now = Timestamp::from_unix_nanos(0);
    let mut cp = FakeCheckpointer::new();

    let result = park(&mut conn, run_id, &awaiting, true, now, &mut cp).expect("park succeeds");

    assert_eq!(
        result.workspace,
        WorkspaceDisposition::HoldUntil(Timestamp::from_unix_nanos(72 * 3600 * NANOS_PER_SEC))
    );
    assert_eq!(
        result.awaiting_until, None,
        "the fallback bounds the workspace hold, not the wait — the wait still has no deadline"
    );
}

#[test]
fn a_held_workspace_never_outlives_the_seven_day_cap_even_when_the_gate_asks_for_a_month() {
    let session_id = SessionId::new();
    let (mut conn, run_id) = a_running_run(session_id);
    let step =
        gate_step("id: approve\ngate: { title: 'Ship it?', timeout: 720h, on_timeout: deny }");
    let awaiting = awaiting_from_gate(&step);
    let now = Timestamp::from_unix_nanos(0);
    let mut cp = FakeCheckpointer::new();

    let result = park(&mut conn, run_id, &awaiting, true, now, &mut cp).expect("park succeeds");

    assert_eq!(
        result.workspace,
        WorkspaceDisposition::HoldUntil(Timestamp::from_unix_nanos(7 * 86400 * NANOS_PER_SEC)),
        "the hold is clamped to 7 days"
    );
    assert_eq!(
        result.awaiting_until,
        Some(Timestamp::from_unix_nanos(720 * 3600 * NANOS_PER_SEC)),
        "the WAIT itself is not clamped — the 7-day cap is about held disk, not about how long a human may take"
    );
}

// ---------------------------------------------------------------------------
// The overflow arm (no `Add<Duration>` on `Timestamp`, and `as_nanos()` is u128)
// ---------------------------------------------------------------------------

#[test]
fn a_duration_whose_nanoseconds_do_not_fit_an_i64_is_rejected_not_wrapped() {
    let now = Timestamp::from_unix_nanos(0);
    // ~292 years is the whole i64-nanosecond range; u64::MAX seconds is far
    // past it, and `Duration::as_nanos()` is a `u128` that would truncate.
    let err = absolute_deadline(now, Duration::from_secs(u64::MAX))
        .expect_err("must not wrap into the past");
    assert!(
        matches!(err, ParkError::DeadlineOverflow { .. }),
        "got {err:?}"
    );
}

#[test]
fn a_deadline_past_the_end_of_the_i64_nanosecond_range_is_rejected_not_wrapped() {
    // Fits a u128->i64 conversion, but `now + delta` overflows the addition.
    let now = Timestamp::from_unix_nanos(i64::MAX - 5);
    let err =
        absolute_deadline(now, Duration::from_secs(1)).expect_err("must not wrap into the past");
    assert!(
        matches!(err, ParkError::DeadlineOverflow { .. }),
        "got {err:?}"
    );
}

#[test]
fn an_overflowing_park_writes_nothing() {
    let session_id = SessionId::new();
    let (mut conn, run_id) = a_running_run(session_id);
    let step = gate_step("id: approve\ngate: { title: 'Ship it?', timeout: 1h, on_timeout: deny }");
    let mut awaiting = awaiting_from_gate(&step);
    awaiting.timeout_after = Some(Duration::from_secs(u64::MAX));
    let mut cp = FakeCheckpointer::new();

    let err = park(
        &mut conn,
        run_id,
        &awaiting,
        false,
        Timestamp::from_unix_nanos(0),
        &mut cp,
    )
    .expect_err("an unrepresentable deadline cannot be parked");

    assert!(
        matches!(err, ParkError::DeadlineOverflow { .. }),
        "got {err:?}"
    );
    let recovered = recover_run(&conn, run_id).expect("recover");
    assert_eq!(recovered.run.state, RunState::Running);
    assert_eq!(recovered.run.awaiting_until, None);
}

#[test]
fn a_representable_deadline_is_computed_exactly() {
    assert_eq!(
        absolute_deadline(Timestamp::from_unix_nanos(7), Duration::from_nanos(11))
            .expect("representable"),
        Timestamp::from_unix_nanos(18)
    );
}

#[test]
fn a_deadline_landing_exactly_on_the_largest_representable_instant_succeeds() {
    // The two overflow tests and `a_representable_deadline_is_computed_exactly`
    // bracket `i64::MAX` from either side but never land on it. `now + after
    // == i64::MAX` is the last instant `checked_add` accepts before the
    // overflow arm those other tests exercise.
    let now = Timestamp::from_unix_nanos(i64::MAX - 11);
    assert_eq!(
        absolute_deadline(now, Duration::from_nanos(11)).expect("i64::MAX itself fits"),
        Timestamp::from_unix_nanos(i64::MAX)
    );
}

// ---------------------------------------------------------------------------
// The reaper predicate
// ---------------------------------------------------------------------------

#[test]
fn reaper_cutoff_is_true_well_past_seven_days_and_false_well_within_it() {
    // No gate and no gate TTL are involved here — this is a pure
    // `reaper_cutoff` boundary test, not a claim about any individual
    // gate's timeout (the previous name over-claimed that).
    let now = Timestamp::from_unix_nanos(30 * 86400 * NANOS_PER_SEC);
    let eight_days_ago = Timestamp::from_unix_nanos((30 - 8) * 86400 * NANOS_PER_SEC);
    assert!(reaper_cutoff(eight_days_ago, now));

    let one_day_ago = Timestamp::from_unix_nanos((30 - 1) * 86400 * NANOS_PER_SEC);
    assert!(!reaper_cutoff(one_day_ago, now));
}

#[test]
fn the_reaper_fires_at_exactly_seven_days_and_not_one_nanosecond_earlier() {
    let now = Timestamp::from_unix_nanos(30 * 86400 * NANOS_PER_SEC);
    let exactly_seven = Timestamp::from_unix_nanos((30 - 7) * 86400 * NANOS_PER_SEC);
    assert!(
        reaper_cutoff(exactly_seven, now),
        "`>=`, matching `gc_eligible_blobs`'s own boundary"
    );
    let one_nanosecond_short = Timestamp::from_unix_nanos((30 - 7) * 86400 * NANOS_PER_SEC + 1);
    assert!(!reaper_cutoff(one_nanosecond_short, now));
}

#[test]
fn a_park_timestamp_in_the_future_is_never_reaped_and_never_wraps() {
    // `now < parked_at` is a clock the caller supplied out of order. The
    // subtraction must not wrap into an enormous positive elapsed time.
    assert!(!reaper_cutoff(
        Timestamp::from_unix_nanos(i64::MAX),
        Timestamp::from_unix_nanos(i64::MIN)
    ));
}
