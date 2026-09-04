//! The run-level ledger (B12b): migration 0008's columns, and the arithmetic
//! §8.4 and §8.12 describe over them.
//!
//! Fixture convention, per ruling P92 and its amendment: anything feeding a
//! multi-row query carries **at least two** rows, and the row that makes the
//! assertion interesting appears **first in one test and last in another**, so
//! neither a `.take(1)`-shaped truncation nor a `.skip(1)`-shaped one is
//! invisible to the suite.

use roundhouse_core::{JobId, SessionId, Timestamp};
use roundhouse_flow::caps::ResourceCaps;
use roundhouse_flow::compose::{MAX_CALL_DEPTH, MAX_DIRECT_CHILD_CALLS};
use roundhouse_flow::durability::{
    insert_workflow_run, open_test_db, transition_run, RunState, WorkflowRun,
};
use roundhouse_flow::exec::map_step::MapBudget;
use roundhouse_flow::exec::RunId;
use roundhouse_flow::ledger::{
    active_elapsed, admit_call_from_run, admit_spend, parked_runs_past_hold_cap, refund_child_run,
    remaining_caps, run_ledger, LedgerError, Spend,
};
use rusqlite::Connection;
use std::time::Duration;

const NANOS_PER_SEC: i64 = 1_000_000_000;
const RUN_START: i64 = 1_000 * NANOS_PER_SEC;

fn at_secs(seconds: i64) -> Timestamp {
    Timestamp::from_unix_nanos(RUN_START + seconds * NANOS_PER_SEC)
}

/// A grant whose every field differs from [`ResourceCaps::default`], so a test
/// that accidentally reads the default instead of the row fails loudly rather
/// than passing on a coincidence.
fn a_grant() -> ResourceCaps {
    ResourceCaps {
        run_wall_timeout: Duration::from_secs(3_600),
        run_active_timeout: Duration::from_secs(600),
        step_timeout: Duration::from_secs(60),
        max_tokens: 1_000,
        max_cost_usd: 4.0,
        max_tasks: 20,
        max_tool_calls: 30,
        max_subagents: 5,
        max_bytes_written: 8_000,
        max_escalations: 3,
    }
}

fn a_run(id: RunId, session_depth: Option<u32>, caps: Option<ResourceCaps>) -> WorkflowRun {
    WorkflowRun {
        id,
        job_id: JobId::new(),
        job_version: 1,
        content_hash: "sha256:a".into(),
        session_id: SessionId::new(),
        binding_id: None,
        trigger_event_id: None,
        state: RunState::Running,
        parent_run_id: None,
        forked_from_run_id: None,
        awaiting_until: None,
        started_at: at_secs(0),
        ended_at: None,
        session_depth,
        caps,
    }
}

/// Seeds one run and returns its id.
fn seed(conn: &mut Connection, run: &WorkflowRun) -> RunId {
    insert_workflow_run(conn, run).expect("a fresh run row inserts");
    run.id
}

fn a_seeded_run(conn: &mut Connection) -> RunId {
    seed(conn, &a_run(RunId::new(), Some(0), Some(a_grant())))
}

fn a_spend_of(tokens: u64, cost_usd: f64) -> Spend {
    Spend {
        tokens,
        cost_usd,
        ..Spend::ZERO
    }
}

// ---------------------------------------------------------------------------
// Active time: §8.4's run_active_timeout "excludes AwaitingHuman"
// ---------------------------------------------------------------------------

/// The property the whole migration exists for, stated as arithmetic: two
/// completed parks plus one in progress are all excluded from active time and
/// all included in wall time.
#[test]
fn active_time_excludes_every_park_the_run_has_taken_including_the_one_in_progress() {
    let mut conn = open_test_db();
    let run_id = a_seeded_run(&mut conn);

    // Park 1: 100s..160s. Park 2: 300s..340s. Park 3 opens at 500s and is
    // still open. Three parks rather than one, so a writer that banked only
    // the first or only the last would be visible here.
    for (parked_at, resumed_at) in [(100, 160), (300, 340)] {
        transition_run(
            &mut conn,
            run_id,
            RunState::AwaitingHuman,
            at_secs(parked_at),
        )
        .unwrap();
        transition_run(&mut conn, run_id, RunState::Running, at_secs(resumed_at)).unwrap();
    }
    transition_run(&mut conn, run_id, RunState::AwaitingHuman, at_secs(500)).unwrap();

    let ledger = run_ledger(&conn, run_id).unwrap();
    assert_eq!(
        ledger.parked_nanos,
        100 * NANOS_PER_SEC as u64,
        "60s + 40s of completed parks are banked; the open one is not"
    );
    assert_eq!(ledger.parked_at, Some(at_secs(500)));

    // At 600s: 600s wall, minus 60 + 40 completed and 100 in progress.
    assert_eq!(
        active_elapsed(&ledger, at_secs(600)),
        Duration::from_secs(400)
    );
}

#[test]
fn a_finished_runs_elapsed_time_stops_at_ended_at_rather_than_growing_with_now() {
    let mut conn = open_test_db();
    let run_id = a_seeded_run(&mut conn);
    transition_run(&mut conn, run_id, RunState::Completed, at_secs(90)).unwrap();

    let ledger = run_ledger(&conn, run_id).unwrap();
    assert_eq!(
        active_elapsed(&ledger, at_secs(90)),
        active_elapsed(&ledger, at_secs(9_000)),
        "a completed run's active time is a fixed quantity"
    );
    assert_eq!(
        active_elapsed(&ledger, at_secs(9_000)),
        Duration::from_secs(90)
    );
}

/// The reason `run_active_timeout` is a separate knob at all, as a case that
/// would come out the other way without the ledger: a run that has been
/// waiting on a human for hours is still well inside its *active* window, and
/// is admitted.
#[test]
fn a_long_park_exhausts_no_active_budget_although_it_burns_wall_clock() {
    let mut conn = open_test_db();
    let run_id = a_seeded_run(&mut conn); // active window 600s, wall 3600s

    transition_run(&mut conn, run_id, RunState::AwaitingHuman, at_secs(60)).unwrap();
    transition_run(&mut conn, run_id, RunState::Running, at_secs(2_000)).unwrap();

    let ledger = run_ledger(&conn, run_id).unwrap();
    assert_eq!(
        active_elapsed(&ledger, at_secs(2_060)),
        Duration::from_secs(120),
        "only the 60s before and the 60s after the park are active"
    );
    admit_spend(&mut conn, run_id, &a_spend_of(1, 0.0), at_secs(2_060))
        .expect("2060s of wall clock, but only 120s of the 600s active window, admits");
}

#[test]
fn admission_refuses_once_the_active_window_is_used_up() {
    let mut conn = open_test_db();
    let run_id = a_seeded_run(&mut conn);

    // Exactly at the 600s active window: `>=`, so the window is used up.
    let refused = admit_spend(&mut conn, run_id, &a_spend_of(1, 0.0), at_secs(600));
    assert!(
        matches!(
            refused,
            Err(LedgerError::CapsExceeded {
                field: "run_active_timeout",
                ..
            })
        ),
        "got {refused:?}"
    );
    admit_spend(&mut conn, run_id, &a_spend_of(1, 0.0), at_secs(599))
        .expect("one nanosecond-equivalent under the window still admits");
}

// ---------------------------------------------------------------------------
// remaining_caps: what MapBudget was built to divide
// ---------------------------------------------------------------------------

#[test]
fn remaining_is_the_grant_minus_the_spend_with_both_windows_decremented() {
    let mut conn = open_test_db();
    let run_id = a_seeded_run(&mut conn);

    transition_run(&mut conn, run_id, RunState::AwaitingHuman, at_secs(10)).unwrap();
    transition_run(&mut conn, run_id, RunState::Running, at_secs(110)).unwrap();
    admit_spend(
        &mut conn,
        run_id,
        &Spend {
            tokens: 400,
            cost_usd: 1.5,
            tasks: 2,
            tool_calls: 3,
            subagents: 1,
            bytes_written: 1_000,
            escalations: 1,
        },
        at_secs(120),
    )
    .unwrap();

    let remaining = remaining_caps(&conn, run_id, at_secs(130)).unwrap();
    assert_eq!(remaining.max_tokens, 600);
    assert_eq!(remaining.max_cost_usd, 2.5);
    assert_eq!(remaining.max_tasks, 18);
    assert_eq!(remaining.max_tool_calls, 27);
    assert_eq!(remaining.max_subagents, 4);
    assert_eq!(remaining.max_bytes_written, 7_000);
    assert_eq!(remaining.max_escalations, 2);
    // 130s of wall, of which 100s were parked.
    assert_eq!(remaining.run_wall_timeout, Duration::from_secs(3_600 - 130));
    assert_eq!(remaining.run_active_timeout, Duration::from_secs(600 - 30));
    assert_eq!(
        remaining.step_timeout,
        Duration::from_secs(60),
        "a per-step ceiling is not a run-level pool and is not decremented"
    );
}

#[test]
fn a_run_with_no_recorded_grant_is_refused_rather_than_handed_the_default() {
    let mut conn = open_test_db();
    let run_id = seed(&mut conn, &a_run(RunId::new(), Some(0), None));

    let refused = remaining_caps(&conn, run_id, at_secs(1));
    assert!(
        matches!(refused, Err(LedgerError::CapsNotRecorded { .. })),
        "got {refused:?}"
    );
    let refused = admit_spend(&mut conn, run_id, &a_spend_of(1, 0.0), at_secs(1));
    assert!(
        matches!(refused, Err(LedgerError::CapsNotRecorded { .. })),
        "got {refused:?}"
    );
}

#[test]
fn a_map_budget_built_from_the_ledger_divides_the_runs_own_ceiling_not_the_default() {
    let mut conn = open_test_db();
    let run_id = a_seeded_run(&mut conn);
    admit_spend(&mut conn, run_id, &a_spend_of(250, 0.0), at_secs(1)).unwrap();

    let budget = MapBudget::from_run_ledger(&conn, run_id, at_secs(1)).unwrap();
    assert_eq!(budget.total_remaining.max_tokens, 750);
    assert_ne!(
        budget.total_remaining.max_tokens,
        ResourceCaps::default().max_tokens,
        "the whole point of the constructor is that it is not the default"
    );
}

// ---------------------------------------------------------------------------
// admit_spend
// ---------------------------------------------------------------------------

#[test]
fn admission_records_what_it_admits_and_reports_what_is_left() {
    let mut conn = open_test_db();
    let run_id = a_seeded_run(&mut conn);

    let after_first = admit_spend(&mut conn, run_id, &a_spend_of(600, 1.0), at_secs(1)).unwrap();
    assert_eq!(after_first.max_tokens, 400);
    let after_second = admit_spend(&mut conn, run_id, &a_spend_of(300, 1.0), at_secs(2)).unwrap();
    assert_eq!(
        after_second.max_tokens, 100,
        "spends accumulate; the second is not measured against a fresh grant"
    );
    assert_eq!(run_ledger(&conn, run_id).unwrap().spent.tokens, 900);
}

#[test]
fn a_spend_past_the_grant_is_refused_and_records_nothing() {
    let mut conn = open_test_db();
    let run_id = a_seeded_run(&mut conn);
    admit_spend(&mut conn, run_id, &a_spend_of(900, 0.0), at_secs(1)).unwrap();

    let refused = admit_spend(&mut conn, run_id, &a_spend_of(200, 0.0), at_secs(2));
    assert!(
        matches!(
            refused,
            Err(LedgerError::CapsExceeded {
                field: "max_tokens",
                ..
            })
        ),
        "got {refused:?}"
    );
    assert_eq!(
        run_ledger(&conn, run_id).unwrap().spent.tokens,
        900,
        "a refused admission must not have banked a partial spend"
    );
    admit_spend(&mut conn, run_id, &a_spend_of(100, 0.0), at_secs(3))
        .expect("the last 100 of the grant still fits exactly");
}

/// §8.13's *"refuse new task admission"* is stated about `Cancelling`; the
/// other five refusals are this module's own reading, and the test covers all
/// six rather than the one that is quoted.
#[test]
fn no_state_but_running_admits_new_work() {
    for (target, via) in [
        (RunState::Paused, None),
        (RunState::Cancelling, None),
        (RunState::AwaitingHuman, None),
        (RunState::Completed, None),
        (RunState::Failed, None),
        (RunState::Cancelled, Some(RunState::Cancelling)),
    ] {
        let mut conn = open_test_db();
        let run_id = a_seeded_run(&mut conn);
        if let Some(intermediate) = via {
            transition_run(&mut conn, run_id, intermediate, at_secs(1)).unwrap();
        }
        transition_run(&mut conn, run_id, target, at_secs(2)).unwrap();

        let refused = admit_spend(&mut conn, run_id, &a_spend_of(1, 0.0), at_secs(3));
        assert!(
            matches!(refused, Err(LedgerError::NotAdmitting { state, .. }) if state == target),
            "{target:?} must not admit work, got {refused:?}"
        );
    }
}

/// Measured in `roundhouse-store`'s `migration_0008` tests: the column's
/// `CHECK (spent_cost_usd >= 0)` stops a negative and `NOT NULL` stops a
/// `NaN`, but `+inf` passes both. So the writer has to be the guard.
#[test]
fn a_dollar_amount_that_is_not_a_usable_number_is_refused_at_the_writer() {
    for amount in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0] {
        let mut conn = open_test_db();
        let run_id = a_seeded_run(&mut conn);
        let refused = admit_spend(&mut conn, run_id, &a_spend_of(0, amount), at_secs(1));
        assert!(
            matches!(refused, Err(LedgerError::UnusableCostAmount { .. })),
            "{amount} must be refused, got {refused:?}"
        );
        assert_eq!(run_ledger(&conn, run_id).unwrap().spent.cost_usd, 0.0);
    }
}

// ---------------------------------------------------------------------------
// The reaper's query
// ---------------------------------------------------------------------------

const SEVEN_DAYS_SECS: i64 = 7 * 86_400;

/// Four runs, three of them parked at different times, with the expired one
/// **last** in insertion order — the `.skip(1)`/`.take(1)` pair P92's
/// amendment names. Its mirror (`..._when_it_is_the_first_row`) puts it first.
#[test]
fn the_reaper_lists_only_parks_past_the_cap_when_the_expired_one_is_last() {
    let mut conn = open_test_db();
    let now = at_secs(SEVEN_DAYS_SECS + 1_000);

    let fresh = a_seeded_run(&mut conn);
    let unparked = a_seeded_run(&mut conn);
    let just_inside = a_seeded_run(&mut conn);
    let expired = a_seeded_run(&mut conn);

    transition_run(&mut conn, fresh, RunState::AwaitingHuman, at_secs(1_000)).unwrap();
    // One second short of the cap.
    transition_run(
        &mut conn,
        just_inside,
        RunState::AwaitingHuman,
        at_secs(1_001),
    )
    .unwrap();
    transition_run(&mut conn, expired, RunState::AwaitingHuman, at_secs(0)).unwrap();

    let listed = parked_runs_past_hold_cap(&conn, now).unwrap();
    assert_eq!(listed, vec![expired, fresh], "oldest park first");
    assert!(!listed.contains(&just_inside));
    assert!(
        !listed.contains(&unparked),
        "an unparked run is never listed"
    );
}

#[test]
fn the_reaper_lists_the_expired_run_when_it_is_the_first_row_too() {
    let mut conn = open_test_db();
    let now = at_secs(SEVEN_DAYS_SECS + 1_000);

    let expired = a_seeded_run(&mut conn);
    let just_inside = a_seeded_run(&mut conn);

    transition_run(&mut conn, expired, RunState::AwaitingHuman, at_secs(0)).unwrap();
    transition_run(
        &mut conn,
        just_inside,
        RunState::AwaitingHuman,
        at_secs(1_001),
    )
    .unwrap();

    assert_eq!(
        parked_runs_past_hold_cap(&conn, now).unwrap(),
        vec![expired]
    );
}

/// The query and `parking::reaper_cutoff` must be the same rule. Checked on
/// **both sides** of the boundary and on the boundary itself, since a query
/// that agreed only for values far from it would still be a second leg.
#[test]
fn every_run_the_query_lists_is_one_the_predicate_calls_expired_and_vice_versa() {
    use roundhouse_flow::parking::reaper_cutoff;

    let mut conn = open_test_db();
    let now = at_secs(SEVEN_DAYS_SECS + 500);
    let mut parked = Vec::new();
    for offset in [-1, 0, 1, 400, 500, 600] {
        let run_id = a_seeded_run(&mut conn);
        let parked_at = at_secs(500 + offset);
        transition_run(&mut conn, run_id, RunState::AwaitingHuman, parked_at).unwrap();
        parked.push((run_id, parked_at));
    }

    let listed = parked_runs_past_hold_cap(&conn, now).unwrap();
    for (run_id, parked_at) in parked {
        assert_eq!(
            listed.contains(&run_id),
            reaper_cutoff(parked_at, now),
            "the query and reaper_cutoff disagree for a park at {parked_at:?}"
        );
    }
}

/// The bypass the column exists to close: a run that re-drives its own park
/// must not restart the seven-day clock.
#[test]
fn re_driving_a_park_moves_the_wait_deadline_but_never_the_reaper_clock() {
    let mut conn = open_test_db();
    let run_id = a_seeded_run(&mut conn);

    transition_run(&mut conn, run_id, RunState::AwaitingHuman, at_secs(0)).unwrap();
    for re_park_at in [1_000, 2_000, SEVEN_DAYS_SECS] {
        transition_run(
            &mut conn,
            run_id,
            RunState::AwaitingHuman,
            at_secs(re_park_at),
        )
        .unwrap();
    }

    assert_eq!(
        run_ledger(&conn, run_id).unwrap().parked_at,
        Some(at_secs(0)),
        "parked_at is the start of the park, not of its latest re-drive"
    );
    assert_eq!(
        parked_runs_past_hold_cap(&conn, at_secs(SEVEN_DAYS_SECS)).unwrap(),
        vec![run_id]
    );
}

// ---------------------------------------------------------------------------
// The call bounds, over the session tree
// ---------------------------------------------------------------------------

#[test]
fn a_call_is_admitted_from_the_runs_own_session_depth_and_refused_at_the_limit() {
    let mut conn = open_test_db();
    let shallow = seed(&mut conn, &a_run(RunId::new(), Some(0), Some(a_grant())));
    let at_limit = seed(
        &mut conn,
        &a_run(RunId::new(), Some(MAX_CALL_DEPTH), Some(a_grant())),
    );

    assert_eq!(admit_call_from_run(&conn, shallow, 0).unwrap(), 1);
    let refused = admit_call_from_run(&conn, at_limit, 0);
    assert!(
        matches!(refused, Err(LedgerError::CallDepth(_))),
        "got {refused:?}"
    );
}

/// The escape ruling P76 §1 describes, reached through the schema instead of
/// through the wrong counter: a run whose depth was never recorded must not be
/// treated as a root.
#[test]
fn a_run_with_no_recorded_session_depth_refuses_a_call_rather_than_assuming_zero() {
    let mut conn = open_test_db();
    let run_id = seed(&mut conn, &a_run(RunId::new(), None, Some(a_grant())));

    let refused = admit_call_from_run(&conn, run_id, 0);
    assert!(
        matches!(refused, Err(LedgerError::SessionDepthNotRecorded { .. })),
        "got {refused:?}"
    );
}

#[test]
fn a_call_that_fits_the_depth_can_still_be_refused_on_fan_out() {
    let mut conn = open_test_db();
    let run_id = a_seeded_run(&mut conn);

    assert_eq!(
        admit_call_from_run(&conn, run_id, MAX_DIRECT_CHILD_CALLS - 1).unwrap(),
        1,
        "the last admissible child still gets its depth back"
    );
    let refused = admit_call_from_run(&conn, run_id, MAX_DIRECT_CHILD_CALLS);
    assert!(
        matches!(refused, Err(LedgerError::CallFanOut(_))),
        "got {refused:?}"
    );
}

#[test]
fn admitting_a_call_from_a_run_with_no_row_is_not_found() {
    let conn = open_test_db();
    let refused = admit_call_from_run(&conn, RunId::new(), 0);
    assert!(
        matches!(refused, Err(LedgerError::RunNotFound { .. })),
        "got {refused:?}"
    );
}

// ---------------------------------------------------------------------------
// §8.12's refund, re-derived from rows
// ---------------------------------------------------------------------------

/// Seeds a parent charged the child's whole grant, plus the child itself.
fn a_parent_and_child(conn: &mut Connection, child_grant: ResourceCaps) -> (RunId, RunId) {
    let parent = a_seeded_run(conn);
    admit_spend(conn, parent, &Spend::for_grant(&child_grant), at_secs(1))
        .expect("the draw is a spend against the parent");
    let mut child = a_run(RunId::new(), Some(1), Some(child_grant));
    child.parent_run_id = Some(parent);
    let child = seed(conn, &child);
    (parent, child)
}

fn a_small_grant() -> ResourceCaps {
    ResourceCaps {
        max_tokens: 500,
        max_cost_usd: 2.0,
        ..a_grant()
    }
}

#[test]
fn a_finished_child_returns_its_unspent_grant_to_the_parent_exactly_once() {
    let mut conn = open_test_db();
    let (parent, child) = a_parent_and_child(&mut conn, a_small_grant());

    admit_spend(&mut conn, child, &a_spend_of(200, 0.5), at_secs(2)).unwrap();
    transition_run(&mut conn, child, RunState::Completed, at_secs(3)).unwrap();

    let before = remaining_caps(&conn, parent, at_secs(4)).unwrap();
    let refunded = refund_child_run(&mut conn, child, at_secs(4)).unwrap();
    assert_eq!(refunded.tokens, 300);
    assert_eq!(refunded.cost_usd, 1.5);

    let after = remaining_caps(&conn, parent, at_secs(4)).unwrap();
    assert_eq!(after.max_tokens, before.max_tokens + 300);
    assert_eq!(after.max_cost_usd, before.max_cost_usd + 1.5);

    let repeated = refund_child_run(&mut conn, child, at_secs(5));
    assert!(
        matches!(repeated, Err(LedgerError::AlreadyRefunded { .. })),
        "a second refund would mint budget the root never granted, got {repeated:?}"
    );
    assert_eq!(
        remaining_caps(&conn, parent, at_secs(6))
            .unwrap()
            .max_tokens,
        after.max_tokens,
        "and it must not have credited anything on its way to refusing"
    );
}

/// `compose::ChildBudget`'s "the token names an amount, not a parent"
/// residual, closed by construction: with two parents in the database and no
/// parent parameter to pass, only the child's own parent can be credited.
#[test]
fn the_refund_reaches_the_childs_own_parent_and_not_the_other_one() {
    let mut conn = open_test_db();
    let (parent, child) = a_parent_and_child(&mut conn, a_small_grant());
    let bystander = a_seeded_run(&mut conn);
    admit_spend(
        &mut conn,
        bystander,
        &Spend::for_grant(&a_small_grant()),
        at_secs(1),
    )
    .unwrap();

    let bystander_before = remaining_caps(&conn, bystander, at_secs(4)).unwrap();
    transition_run(&mut conn, child, RunState::Completed, at_secs(3)).unwrap();
    refund_child_run(&mut conn, child, at_secs(4)).unwrap();

    assert_eq!(
        remaining_caps(&conn, bystander, at_secs(4)).unwrap(),
        bystander_before,
        "the other parent's pool is untouched"
    );
    assert_eq!(
        remaining_caps(&conn, parent, at_secs(4))
            .unwrap()
            .max_tokens,
        a_grant().max_tokens,
        "the child spent nothing, so the parent is whole again"
    );
}

#[test]
fn a_child_that_spent_its_whole_grant_refunds_nothing_and_is_still_stamped() {
    let mut conn = open_test_db();
    let (parent, child) = a_parent_and_child(&mut conn, a_small_grant());

    // The *whole* grant, every countable — not just the two an earlier draft
    // of this test spent, which left the other five refundable and made the
    // test's own name a claim the fixture did not support.
    admit_spend(
        &mut conn,
        child,
        &Spend::for_grant(&a_small_grant()),
        at_secs(2),
    )
    .unwrap();
    transition_run(&mut conn, child, RunState::Failed, at_secs(3)).unwrap();

    let before = remaining_caps(&conn, parent, at_secs(4)).unwrap();
    let refunded = refund_child_run(&mut conn, child, at_secs(4)).unwrap();
    assert_eq!(refunded, Spend::ZERO);
    assert_eq!(remaining_caps(&conn, parent, at_secs(4)).unwrap(), before);
    assert_eq!(
        run_ledger(&conn, child).unwrap().refunded_at,
        Some(at_secs(4)),
        "a zero refund is still a refund and must not be repeatable"
    );
}

#[test]
fn a_child_that_has_not_finished_cannot_have_its_grant_reclaimed() {
    let mut conn = open_test_db();
    let (_, child) = a_parent_and_child(&mut conn, a_small_grant());

    let refused = refund_child_run(&mut conn, child, at_secs(4));
    assert!(
        matches!(refused, Err(LedgerError::ChildNotFinished { .. })),
        "got {refused:?}"
    );
}

#[test]
fn a_run_with_no_parent_has_nothing_to_refund_to() {
    let mut conn = open_test_db();
    let root = a_seeded_run(&mut conn);
    transition_run(&mut conn, root, RunState::Completed, at_secs(3)).unwrap();

    let refused = refund_child_run(&mut conn, root, at_secs(4));
    assert!(
        matches!(refused, Err(LedgerError::NotAChildRun { .. })),
        "got {refused:?}"
    );
}

// ---------------------------------------------------------------------------
// The claim the whole migration rests on
// ---------------------------------------------------------------------------

/// Every doc comment behind these columns says the same thing: an in-process
/// tracker *"would be lost on the first daemon restart, which is precisely the
/// case it exists to measure."* This is that claim, tested rather than
/// asserted — a park, a spend and a depth written through one `Connection`,
/// read back through a second one opened on the same file after the first is
/// dropped.
#[test]
fn a_park_a_spend_and_a_depth_survive_the_connection_that_wrote_them() {
    // Under the crate's own `target/`, never `/tmp`: ruling P91's fourth
    // variant is a build artefact leaking between worktrees through a shared
    // temp path.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("ledger_restart_fixture");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the fixture directory");
    let path = dir.join("runs.sqlite3");

    let run_id = RunId::new();
    {
        let mut conn = Connection::open(&path).expect("open the fixture database");
        roundhouse_store::migrations()
            .to_latest(&mut conn)
            .expect("migrate the fixture database");
        seed(&mut conn, &a_run(run_id, Some(2), Some(a_grant())));
        admit_spend(&mut conn, run_id, &a_spend_of(250, 1.25), at_secs(1)).unwrap();
        transition_run(&mut conn, run_id, RunState::AwaitingHuman, at_secs(10)).unwrap();
    }

    let conn = Connection::open(&path).expect("reopen the fixture database");
    let ledger = run_ledger(&conn, run_id).expect("the row is still there");
    assert_eq!(ledger.parked_at, Some(at_secs(10)));
    assert_eq!(ledger.session_depth, Some(2));
    assert_eq!(ledger.spent.tokens, 250);
    assert_eq!(ledger.spent.cost_usd, 1.25);
    assert_eq!(ledger.caps.as_ref().map(|c| c.max_tokens), Some(1_000));
    assert_eq!(
        active_elapsed(&ledger, at_secs(3_610)),
        Duration::from_secs(10),
        "the park that began before the restart is still excluded after it"
    );

    drop(conn);
    let _ = std::fs::remove_dir_all(&dir);
}
