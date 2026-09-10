//! The run-level ledger (B12b): migration 0008's columns, and the arithmetic
//! §8.4 and §8.12 describe over them.
//!
//! Fixture convention, per ruling P92 and its amendment: anything feeding a
//! multi-row query carries **at least two** rows, and the row that makes the
//! assertion interesting appears **first in one test and last in another**, so
//! neither a `.take(1)`-shaped truncation nor a `.skip(1)`-shaped one is
//! invisible to the suite.

use roundhouse_core::{JobId, SessionId, Timestamp};
use roundhouse_flow::caps::{is_usable_cost_usd, ResourceCaps};
use roundhouse_flow::compose::{MAX_CALL_DEPTH, MAX_DIRECT_CHILD_CALLS};
use roundhouse_flow::durability::{
    insert_workflow_run, open_test_db, transition_run, DurabilityError, RunState, WorkflowRun,
};
use roundhouse_flow::exec::map_step::MapBudget;
use roundhouse_flow::exec::RunId;
use roundhouse_flow::ledger::{
    active_elapsed, admit_call_from_run, admit_spend, admit_spend_during_finally, draw_child_run,
    parked_runs_past_hold_cap, refund_child_run, remaining_caps, run_ledger, wall_elapsed,
    LedgerError, Spend,
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
        checkpoint_ref: None,
        checkpoint_blob_ref: None,
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

    // A spend far past `ResourceCaps::default()`, so the refusal has to name
    // the right fact. Found by mutation `A11`, which swapped
    // `ok_or(CapsNotRecorded)` for `unwrap_or(&ResourceCaps::default())` and
    // survived the two assertions above: the closing `remaining_caps` call
    // still errored, so the *outcome* was unchanged for a small spend and only
    // the *reason* differed. A run with no recorded grant has not exceeded a
    // budget — it has no budget — and telling an operator it ran out is a
    // wrong answer even when the refusal is right.
    let refused = admit_spend(
        &mut conn,
        run_id,
        &a_spend_of(ResourceCaps::default().max_tokens * 2, 0.0),
        at_secs(1),
    );
    assert!(
        matches!(refused, Err(LedgerError::CapsNotRecorded { .. })),
        "an unrecorded grant is not an exceeded one, got {refused:?}"
    );
}

/// Both of §8.4's run-level elapsed-time ceilings are enforced at admission,
/// not only the active one. Found by mutation `A1`: with
/// `run_wall_timeout`'s check removed the whole suite stayed green, because
/// every other test's window is the *active* one, which is always the smaller
/// of the two in the fixture grant.
#[test]
fn admission_refuses_once_the_wall_clock_window_is_used_up() {
    let mut conn = open_test_db();
    // A grant whose wall window is the binding one: an hour of wall clock, a
    // day of active time, so only the wall check can produce this refusal.
    let run_id = seed(
        &mut conn,
        &a_run(
            RunId::new(),
            Some(0),
            Some(ResourceCaps {
                run_wall_timeout: Duration::from_secs(3_600),
                run_active_timeout: Duration::from_secs(86_400),
                ..a_grant()
            }),
        ),
    );

    admit_spend(&mut conn, run_id, &a_spend_of(1, 0.0), at_secs(3_599))
        .expect("one second short of the wall window still admits");
    let refused = admit_spend(&mut conn, run_id, &a_spend_of(1, 0.0), at_secs(3_600));
    assert!(
        matches!(
            refused,
            Err(LedgerError::CapsExceeded {
                field: "run_wall_timeout",
                ..
            })
        ),
        "got {refused:?}"
    );
}

/// §8.12 names `max_cost_usd` as one of the two fields drawn by a `call:`, and
/// it is the only countable that is an `f64` rather than an integer — so it is
/// checked by its own comparison rather than by `checked_total`. Found by
/// mutation `A6`: removing that comparison left the suite green, because every
/// other admission test measured tokens.
#[test]
fn a_dollar_spend_past_the_grant_is_refused_and_records_nothing() {
    let mut conn = open_test_db();
    let run_id = a_seeded_run(&mut conn); // $4.00 granted
    admit_spend(&mut conn, run_id, &a_spend_of(0, 3.5), at_secs(1)).unwrap();

    let refused = admit_spend(&mut conn, run_id, &a_spend_of(0, 1.0), at_secs(2));
    assert!(
        matches!(
            refused,
            Err(LedgerError::CapsExceeded {
                field: "max_cost_usd",
                ..
            })
        ),
        "got {refused:?}"
    );
    assert_eq!(
        run_ledger(&conn, run_id).unwrap().spent.cost_usd,
        3.5,
        "a refused admission must not have banked a partial dollar spend"
    );
    admit_spend(&mut conn, run_id, &a_spend_of(0, 0.5), at_secs(3))
        .expect("the last 50 cents of the grant still fits exactly");
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

/// SQLite has no unsigned integers, so a `u64` counter round-trips through
/// `i64`. The only grant under which a spend can reach that boundary is one
/// that names `u64::MAX` — where the ceiling comparison admits it and the
/// *column* is what cannot hold it. Refused rather than wrapped: a wrapped
/// counter reads back negative and then saturates to zero, turning an
/// enormous spend into no spend at all.
///
/// Parameterised over **both** `u64` columns. An earlier version tested only
/// `spent_tokens`, and `u64_to_sql(…, "spent_bytes_written") -> as i64`
/// survived a mutation sweep at zero failures: the same call, one line down,
/// with nothing measuring it.
#[test]
fn a_spend_that_does_not_fit_a_sqlite_integer_is_refused_rather_than_wrapped() {
    for (column, grant, requested) in [
        (
            "spent_tokens",
            ResourceCaps {
                max_tokens: u64::MAX,
                ..a_grant()
            },
            Spend {
                tokens: u64::MAX,
                ..Spend::ZERO
            },
        ),
        (
            "spent_bytes_written",
            ResourceCaps {
                max_bytes_written: u64::MAX,
                ..a_grant()
            },
            Spend {
                bytes_written: u64::MAX,
                ..Spend::ZERO
            },
        ),
    ] {
        let mut conn = open_test_db();
        let run_id = seed(&mut conn, &a_run(RunId::new(), Some(0), Some(grant)));

        let refused = admit_spend(&mut conn, run_id, &requested, at_secs(1));
        assert!(
            matches!(
                refused,
                Err(LedgerError::ValueOutOfRange {
                    column: c,
                    value: u64::MAX
                }) if c == column
            ),
            "{column} must refuse a value past i64::MAX, got {refused:?}"
        );
        let after = run_ledger(&conn, run_id).unwrap().spent;
        assert_eq!(
            (after.tokens, after.bytes_written),
            (0, 0),
            "and the transaction that could not write {column} rolled back"
        );
    }
}

/// `checked_total`'s anti-wrap guard, which its own doc says exists so *"a
/// hostile pair cannot wrap into a small total that fits"* — and which nothing
/// measured: `saturating_add` -> `wrapping_add` survived a sweep at zero
/// failures in **both** the `u64` and `u32` functions.
///
/// The reason it survived is the whole point of this test. Every prior
/// admission test started from `spent = 0`, where saturating and wrapping
/// arithmetic are identical. The scenario needs a **non-zero prior spend**:
/// with `spent = 1` and `requested = u64::MAX`, a wrapping total is `0`,
/// `0 > ceiling` is false, and an unbounded spend is admitted **and recorded
/// as zero** — the ceiling comparison intact and useless, because the
/// arithmetic feeding it lied.
///
/// Ruling P110 §A, which is P92's new fifth clause: a guard on a comparison
/// has two populations — the values compared, and the arithmetic that produces
/// them.
#[test]
fn a_total_that_would_wrap_is_refused_rather_than_admitted_as_a_small_number() {
    let mut conn = open_test_db();
    let run_id = a_seeded_run(&mut conn); // 1_000 tokens, 20 tasks

    // The non-zero prior spend, without which this test cannot distinguish
    // saturating from wrapping at all.
    admit_spend(&mut conn, run_id, &a_spend_of(1, 0.0), at_secs(1)).unwrap();
    admit_spend(
        &mut conn,
        run_id,
        &Spend {
            tasks: 1,
            ..Spend::ZERO
        },
        at_secs(1),
    )
    .unwrap();

    let u64_leg = admit_spend(&mut conn, run_id, &a_spend_of(u64::MAX, 0.0), at_secs(2));
    assert!(
        matches!(
            u64_leg,
            Err(LedgerError::CapsExceeded {
                field: "max_tokens",
                ..
            })
        ),
        "1 + u64::MAX must saturate past the ceiling, not wrap to 0; got {u64_leg:?}"
    );

    let u32_leg = admit_spend(
        &mut conn,
        run_id,
        &Spend {
            tasks: u32::MAX,
            ..Spend::ZERO
        },
        at_secs(2),
    );
    assert!(
        matches!(
            u32_leg,
            Err(LedgerError::CapsExceeded {
                field: "max_tasks",
                ..
            })
        ),
        "1 + u32::MAX must saturate past the ceiling, not wrap to 0; got {u32_leg:?}"
    );

    let after = run_ledger(&conn, run_id).unwrap().spent;
    assert_eq!(
        (after.tokens, after.tasks),
        (1, 1),
        "and neither refusal recorded a wrapped total over the real spend"
    );
}

/// Ruling P109 §D: `admit_spend` guarded both operands of the cost comparison
/// and **not its ceiling**.
///
/// # What is reachable here, measured rather than assumed
///
/// P109 §D's scenario is a `NaN`/`+inf` ceiling, against which
/// `cost_total > caps.max_cost_usd` is `false` and every spend is admitted. It
/// says a hand-built `caps_json` reaches that because *"`1e999` parses back as
/// `+Inf` cleanly"*. **Measured in this tree, it does not**: `serde_json`
/// refuses an out-of-range float on the way *in* as well as writing `null` on
/// the way out — see
/// [`serde_json_refuses_a_non_finite_dollar_figure_in_both_directions`]. So no
/// non-finite ceiling can reach this comparison through `caps_json` at all,
/// and the fail-*open* direction is not reachable today.
///
/// What **is** reachable is a **negative** ceiling: `-1.0` is finite, valid
/// JSON, and round-trips cleanly. Its old behaviour was fail-closed but
/// misnamed — every spend refused as `CapsExceeded { field: "max_cost_usd" }`,
/// which says the run is over budget when in fact its stored ceiling is
/// nonsense. It now says so.
#[test]
fn a_negative_stored_ceiling_names_itself_rather_than_reporting_every_spend_as_over_budget() {
    let mut conn = open_test_db();
    let run_id = a_seeded_run(&mut conn);

    let valid = serde_json::to_string(&a_grant()).unwrap();
    let poisoned = valid.replace("\"max_cost_usd\":4.0", "\"max_cost_usd\":-1.0");
    assert_ne!(poisoned, valid, "the fixture must really have been edited");
    conn.execute(
        "UPDATE workflow_run SET caps_json = ?1 WHERE id = ?2",
        rusqlite::params![poisoned, run_id.to_string()],
    )
    .unwrap();
    let stored = run_ledger(&conn, run_id)
        .unwrap()
        .caps
        .unwrap()
        .max_cost_usd;
    assert_eq!(
        stored, -1.0,
        "a negative ceiling round-trips cleanly, which is what makes it the reachable case"
    );
    assert!(!is_usable_cost_usd(stored));

    let refused = admit_spend(&mut conn, run_id, &a_spend_of(0, 0.01), at_secs(1));
    assert!(
        matches!(refused, Err(LedgerError::UnusableCostAmount { .. })),
        "the ceiling is what is wrong, not the request; got {refused:?}"
    );
    assert_eq!(run_ledger(&conn, run_id).unwrap().spent.cost_usd, 0.0);
}

/// The measurement the guard above is scoped against, pinned rather than
/// asserted — ruling P108 §B's rule that a claim about a dependency's
/// behaviour is worth exactly the run that produced it.
///
/// `serde_json` treats a non-finite `f64` as unrepresentable **in both
/// directions**: it writes `inf`/`NaN` as `null`, and it *refuses to parse* an
/// out-of-range literal rather than yielding `inf`. That second half is the
/// one ruling P109 §D got wrong, and it is why `caps_json` cannot deliver a
/// non-finite ceiling to `admit_spend`.
///
/// This does not make either guard redundant. `1e308` shows the boundary is
/// magnitude, not syntax, so the two legs are what keep the crate from
/// depending on a serialiser convention nobody wrote down — and the *negative*
/// ceiling, which needs no convention to arrive, is reachable regardless.
#[test]
fn serde_json_refuses_a_non_finite_dollar_figure_in_both_directions() {
    assert_eq!(serde_json::to_string(&f64::INFINITY).unwrap(), "null");
    assert_eq!(serde_json::to_string(&f64::NAN).unwrap(), "null");

    for out_of_range in ["1e999", "-1e999", "1e309"] {
        let parsed: Result<f64, _> = serde_json::from_str(out_of_range);
        assert!(
            parsed.is_err(),
            "{out_of_range} must be refused on the way in, not read back as an infinity"
        );
    }
    assert_eq!(
        serde_json::from_str::<f64>("1e308").unwrap(),
        1e308,
        "the boundary is magnitude, not syntax"
    );
    assert_eq!(serde_json::from_str::<f64>("-1.0").unwrap(), -1.0);
}

/// The diagnosis leg of the same rule (ruling P109 §D): a `ResourceCaps` whose
/// `max_cost_usd` is unusable is refused **at the insert**, rather than
/// serialised as `null` and failing at whatever unrelated read next loads the
/// row. `serde_json` does not refuse a non-finite `f64` — that was the reason
/// `insert_run_row`'s `expect` gave, and it was not the true one.
#[test]
fn a_run_cannot_be_inserted_with_a_ceiling_that_is_not_a_usable_dollar_amount() {
    for amount in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.01] {
        let mut conn = open_test_db();
        let run = a_run(
            RunId::new(),
            Some(0),
            Some(ResourceCaps {
                max_cost_usd: amount,
                ..a_grant()
            }),
        );
        let refused = insert_workflow_run(&mut conn, &run);
        assert!(
            matches!(refused, Err(DurabilityError::UnusableCostAmount { .. })),
            "{amount} must be refused at the writer, got {refused:?}"
        );
        assert!(
            matches!(
                run_ledger(&conn, run.id),
                Err(LedgerError::RunNotFound { .. })
            ),
            "and no row is left behind"
        );
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

/// Ruling P109 §C: a `call:` **is** new task admission — §8.12 describes it as
/// creating a child `workflow_run`, a child Session and an `agent`-kind task —
/// so §8.13's *"refuse new task admission"* binds here exactly as it binds
/// `admit_spend`. Before this, `admit_call_from_run` read the run's state and
/// then consulted only `session_depth`, so an operator could cancel a
/// misbehaving run and watch it keep spawning children, each starting
/// `Running` and admitting freely.
///
/// Mirrors `no_state_but_running_admits_new_work` deliberately: the two
/// chokepoints share one predicate, so they are tested over one list.
#[test]
fn no_state_but_running_admits_a_call_either() {
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

        // Depth 0 with no children: every §7.7 bound would admit this call, so
        // the only thing that can refuse it is the run's state.
        let refused = admit_call_from_run(&conn, run_id, 0);
        assert!(
            matches!(refused, Err(LedgerError::NotAdmitting { state, .. }) if state == target),
            "{target:?} must not admit a call, got {refused:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// §8.12's refund, re-derived from rows
// ---------------------------------------------------------------------------

/// Seeds a child of a parent. The **insert is the draw** (ruling P114 §A's
/// invariant, B12c): `insert_run_row` charges the parent through
/// `draw_child_run_within` in the insert's own transaction, so no separate
/// call is needed and the child's `started_at` is the draw's instant.
///
/// Before `drawn_at` existed this helper did the draw by hand as a bare
/// `admit_spend`, and a row that merely *looked* like a child (a parent id and
/// a grant, which `retry_from_step`'s fork copies) was refundable too.
fn a_parent_and_child(conn: &mut Connection, child_grant: ResourceCaps) -> (RunId, RunId) {
    let parent = a_seeded_run(conn);
    let mut child = a_run(RunId::new(), Some(1), Some(child_grant));
    child.parent_run_id = Some(parent);
    child.started_at = at_secs(1);
    let child = seed(conn, &child);
    (parent, child)
}

/// A child row with a parent and a grant but **no draw** — the shape a fork
/// had before ruling P113, and the shape a row written before B12c still has.
///
/// **No writer in the crate can produce it any more**, which is the invariant
/// working: `insert_run_row` draws for every parented row it commits. So it is
/// reconstructed here by hand — clearing the child's stamp and rewinding the
/// parent's accumulators to the zero they held before the insert charged them
/// — exactly as a hand-edited or pre-B12c row would read. That is the same
/// read-back-leg discipline `from_sql_str`'s unrecognised-discriminant tests
/// use: the guard has to hold against a row the current writer cannot write.
fn an_undrawn_child(conn: &mut Connection, child_grant: ResourceCaps) -> (RunId, RunId) {
    let (parent, child) = a_parent_and_child(conn, child_grant);
    conn.execute(
        "UPDATE workflow_run SET drawn_at = NULL WHERE id = ?1",
        [child.to_string()],
    )
    .expect("clear the child's draw stamp");
    conn.execute(
        "UPDATE workflow_run
            SET spent_tokens = 0, spent_cost_usd = 0, spent_tasks = 0, spent_tool_calls = 0,
                spent_subagents = 0, spent_bytes_written = 0, spent_escalations = 0
          WHERE id = ?1",
        [parent.to_string()],
    )
    .expect("rewind the parent's accumulators to before the draw");
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

/// The draw half, which until this fix round had no caller anywhere in the
/// workspace — the asymmetry ruling P109 §A found: a durable stamp on the
/// refund and nothing on the draw.
#[test]
fn the_draw_charges_the_parent_the_childs_whole_grant_and_stamps_the_child() {
    let mut conn = open_test_db();
    let (parent, child) = an_undrawn_child(&mut conn, a_small_grant());

    assert_eq!(run_ledger(&conn, parent).unwrap().spent, Spend::ZERO);
    let drawn = draw_child_run(&mut conn, child, at_secs(1)).unwrap();

    assert_eq!(
        drawn,
        Spend::for_grant(&a_small_grant()),
        "a draw is the child's whole grant, not its running total: a parent \
         with $1 left cannot start two children each promised $1"
    );
    assert_eq!(run_ledger(&conn, parent).unwrap().spent, drawn);
    assert_eq!(run_ledger(&conn, child).unwrap().drawn_at, Some(at_secs(1)));
}

#[test]
fn a_second_draw_for_one_child_is_refused_rather_than_charging_the_parent_twice() {
    let mut conn = open_test_db();
    let (parent, child) = a_parent_and_child(&mut conn, a_small_grant());
    let charged = run_ledger(&conn, parent).unwrap().spent;

    let repeated = draw_child_run(&mut conn, child, at_secs(2));
    assert!(
        matches!(repeated, Err(LedgerError::AlreadyDrawn { .. })),
        "got {repeated:?}"
    );
    assert_eq!(run_ledger(&conn, parent).unwrap().spent, charged);
}

/// The draw goes through `admit_spend`'s chokepoint, so a parent that is not
/// admitting new work cannot be charged for a new child either — §8.13's
/// *"refuse new task admission"*, reached through the draw.
#[test]
fn a_parent_that_is_not_admitting_cannot_be_drawn_from() {
    let mut conn = open_test_db();
    let (parent, child) = an_undrawn_child(&mut conn, a_small_grant());
    transition_run(&mut conn, parent, RunState::Cancelling, at_secs(1)).unwrap();

    let refused = draw_child_run(&mut conn, child, at_secs(2));
    assert!(
        matches!(
            refused,
            Err(LedgerError::NotAdmitting {
                state: RunState::Cancelling,
                ..
            })
        ),
        "got {refused:?}"
    );
    assert_eq!(
        run_ledger(&conn, child).unwrap().drawn_at,
        None,
        "and the child is not stamped by a draw that did not happen"
    );
}

/// Ruling P109 §A / P110's Critical, at the ledger's own level: a child that
/// carries a parent id and a grant but **no recorded draw** is not refundable.
/// `control::retry_from_step`'s fork is the row that shape describes, and
/// `tests/control.rs` measures that whole path; this pins the refusal itself.
#[test]
fn a_child_whose_draw_was_never_recorded_cannot_be_refunded() {
    let mut conn = open_test_db();
    let (parent, child) = an_undrawn_child(&mut conn, a_small_grant());
    transition_run(&mut conn, child, RunState::Completed, at_secs(3)).unwrap();
    let before = run_ledger(&conn, parent).unwrap().spent;

    let refused = refund_child_run(&mut conn, child, at_secs(4));
    assert!(
        matches!(refused, Err(LedgerError::DrawNotRecorded { .. })),
        "refunding a draw that never happened would decrement spend the parent \
         really made; got {refused:?}"
    );
    assert_eq!(
        run_ledger(&conn, parent).unwrap().spent,
        before,
        "and nothing is credited on the way to refusing"
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

// ---------------------------------------------------------------------------
// The read-back guards, each of which the code argues for at length and none
// of which had a test (they survived a mutation sweep at zero failures).
//
// All of them are reachable only from a **hand-edited or pre-`CHECK` row**,
// which is why they are guards rather than paths — and why these tests write
// their fixtures with `PRAGMA ignore_check_constraints`, the closest thing to
// an operator with a `sqlite3` prompt. A guard nothing exercises is a claim,
// not a guard.
// ---------------------------------------------------------------------------

/// Writes a value the column's own `CHECK` would reject — the hand-edited row
/// every read-back guard below exists for. The pragma is per-connection and
/// this is a per-test in-memory database, so it leaks nowhere.
fn hand_edit(conn: &Connection, set_clause: &str, run_id: RunId) {
    conn.execute_batch("PRAGMA ignore_check_constraints = ON;")
        .expect("a hand-edited row is what these guards exist for");
    conn.execute(
        &format!("UPDATE workflow_run SET {set_clause} WHERE id = ?1"),
        rusqlite::params![run_id.to_string()],
    )
    .expect("the hand edit lands");
    conn.execute_batch("PRAGMA ignore_check_constraints = OFF;")
        .unwrap();
}

/// `nonneg_u32` saturates **up**, not down: for a spend, the larger number is
/// the one that admits less. Down would be the fail-open direction — a stored
/// count past `u32::MAX` read as a small spend, and the run handed budget it
/// had already used.
#[test]
fn a_stored_u32_counter_past_its_range_reads_as_the_maximum_not_as_a_small_number() {
    let mut conn = open_test_db();
    let run_id = a_seeded_run(&mut conn);
    // Above u32::MAX and comfortably inside i64, so the column's own
    // `CHECK (>= 0)` is satisfied and only the read-back guard is in play.
    hand_edit(&conn, "spent_tasks = 5000000000", run_id);

    assert_eq!(run_ledger(&conn, run_id).unwrap().spent.tasks, u32::MAX);
    let refused = admit_spend(
        &mut conn,
        run_id,
        &Spend {
            tasks: 1,
            ..Spend::ZERO
        },
        at_secs(1),
    );
    assert!(
        matches!(
            refused,
            Err(LedgerError::CapsExceeded {
                field: "max_tasks",
                ..
            })
        ),
        "saturating up must refuse further work, not admit it; got {refused:?}"
    );
}

/// The negative half of the same pair: a negative accumulator reads as zero
/// rather than wrapping into an enormous unsigned value. Documented as the
/// deliberate difference from `session_depth`, which refuses — an accounting
/// figure saturates because the alternative is a run that can never be
/// admitted again, while a bypassed *bound* must refuse.
#[test]
fn a_negative_stored_accumulator_reads_as_zero_rather_than_wrapping() {
    let mut conn = open_test_db();
    let run_id = a_seeded_run(&mut conn);
    hand_edit(
        &conn,
        "spent_tokens = -5, spent_tasks = -5, spent_bytes_written = -5",
        run_id,
    );

    let spent = run_ledger(&conn, run_id).unwrap().spent;
    assert_eq!(
        (spent.tokens, spent.tasks, spent.bytes_written),
        (0, 0, 0),
        "a wrapped read would report an enormous spend and lock the run out forever"
    );
}

/// `remaining_from_ledger`'s `.max(0.0)`: an `f64` subtraction of a stored
/// `+inf` spend yields `-inf`, and an un-normalised negative remaining would
/// make every later `min` hand the whole pool back. Measured in
/// `roundhouse-store`'s `migration_0008` tests: `+inf` satisfies
/// `CHECK (spent_cost_usd >= 0)` and is stored, so this row needs no pragma.
#[test]
fn an_infinite_stored_dollar_spend_leaves_no_remaining_pool_rather_than_a_negative_one() {
    let mut conn = open_test_db();
    let run_id = a_seeded_run(&mut conn);
    conn.execute(
        "UPDATE workflow_run SET spent_cost_usd = ?1 WHERE id = ?2",
        rusqlite::params![f64::INFINITY, run_id.to_string()],
    )
    .expect("+inf passes the column's CHECK; that is the whole point");

    let remaining = remaining_caps(&conn, run_id, at_secs(1)).unwrap();
    assert_eq!(
        remaining.max_cost_usd, 0.0,
        "an empty pool, not -inf: a negative remaining would make min() hand it all back"
    );
}

/// `active_elapsed`'s floor. `parked_nanos` cannot exceed the wall clock in a
/// row this crate wrote, but a hand-edited one can — and an unsigned
/// subtraction that wrapped would report an *enormous* active time, the
/// direction that refuses work forever.
#[test]
fn parked_time_larger_than_the_wall_clock_floors_active_time_at_zero() {
    let mut conn = open_test_db();
    let run_id = a_seeded_run(&mut conn);
    hand_edit(&conn, &format!("parked_nanos = {}", i64::MAX), run_id);

    let ledger = run_ledger(&conn, run_id).unwrap();
    assert_eq!(
        active_elapsed(&ledger, at_secs(60)),
        Duration::ZERO,
        "a wrapped subtraction would report centuries of active time and lock the run out"
    );
    // And the run is still admissible, which is the consequence that matters.
    admit_spend(&mut conn, run_id, &a_spend_of(1, 0.0), at_secs(60))
        .expect("a floored active time must not exhaust the active window");
}

/// The refund's banking `.max(0)`. A parent whose accumulators do not cover
/// the refund can only be a row that was never charged the draw it is being
/// credited for; the direction that under-credits is the one that does not
/// wrap a `u64` counter into an enormous apparent spend.
///
/// Stated exactly, because the comment this replaces overclaimed: the floor
/// keeps the counter non-negative. It does **not** make refunding a child that
/// was never charged for safe — that is `DrawNotRecorded`'s job.
#[test]
fn a_refund_larger_than_the_parents_recorded_spend_floors_at_zero_rather_than_wrapping() {
    let mut conn = open_test_db();
    let (parent, child) = a_parent_and_child(&mut conn, a_small_grant());
    // The parent really was charged 500 tokens and $2.00 by the draw; an
    // operator edits both down, so neither leg of the refund can be covered.
    // Both legs, because they are different arithmetic — `saturating_sub` on a
    // `u64` and `.max(0.0)` on an `f64` — and an earlier version of this test
    // edited only the integer one, leaving the dollar floor unmeasured.
    hand_edit(&conn, "spent_tokens = 100, spent_cost_usd = 0.5", parent);

    transition_run(&mut conn, child, RunState::Completed, at_secs(3)).unwrap();
    let refunded = refund_child_run(&mut conn, child, at_secs(4)).unwrap();
    assert_eq!(refunded.tokens, 500, "the child spent none of its grant");
    assert_eq!(refunded.cost_usd, 2.0);

    let after = run_ledger(&conn, parent).unwrap().spent;
    assert_eq!(after.tokens, 0, "floored, not wrapped into 18 quintillion");
    assert_eq!(
        after.cost_usd, 0.0,
        "and floored on the dollar leg too — an un-floored -1.5 would not even \
         survive the column's CHECK (spent_cost_usd >= 0)"
    );
}

// ---------------------------------------------------------------------------
// The per-field floors, against a row whose SPEND EXCEEDS ITS GRANT.
//
// Ruling P110 §A's fifth P92 clause, applied and then re-applied: the first
// pass mutated the arithmetic and found seven survivors, six of which needed
// this one fixture shape. `admit_spend` cannot produce a spend past the
// ceiling, so every earlier test in this file has `spent <= grant` — and every
// `saturating_sub` in `remaining_from_ledger` and `refund_child_run` is
// *exactly* the guard for the case where that does not hold. Whole families of
// floors were unmeasured because the fixture could never reach them.
//
// These rows need no `PRAGMA` where the values are non-negative: a spend of
// 2_000 against a grant of 1_000 satisfies every column `CHECK` there is. The
// schema has no cross-column constraint tying a spend to its grant, and
// migration 0008's doc says why one is not there (it would need the table
// rebuild). So this is a row the database will hold quite happily and only the
// Rust floors refuse to be misled by.
// ---------------------------------------------------------------------------

/// Every countable in `remaining_caps` floors at zero when the stored spend is
/// larger than the grant. Wrapping instead would report a pool of roughly
/// `u64::MAX` — a run whose budget is exhausted being handed an unbounded one,
/// which is the fail-open direction on the number `MapBudget` divides.
#[test]
fn a_stored_spend_larger_than_the_grant_leaves_no_remaining_pool_in_any_field() {
    let mut conn = open_test_db();
    let run_id = a_seeded_run(&mut conn);
    conn.execute(
        "UPDATE workflow_run
            SET spent_tokens = 2000, spent_cost_usd = 9.0, spent_tasks = 50,
                spent_tool_calls = 60, spent_subagents = 9,
                spent_bytes_written = 9000, spent_escalations = 7
          WHERE id = ?1",
        rusqlite::params![run_id.to_string()],
    )
    .expect("every one of these satisfies its column CHECK; only the grant disagrees");

    let remaining = remaining_caps(&conn, run_id, at_secs(1)).unwrap();
    assert_eq!(
        (
            remaining.max_tokens,
            remaining.max_cost_usd,
            remaining.max_tasks,
            remaining.max_tool_calls,
            remaining.max_subagents,
            remaining.max_bytes_written,
            remaining.max_escalations,
        ),
        (0, 0.0, 0, 0, 0, 0, 0),
        "an exhausted budget is zero in every field, never a wrapped maximum"
    );
}

/// The same shape one level over: a **child** whose stored spend exceeds its
/// grant refunds **nothing**, per field. Wrapping would return roughly
/// `u64::MAX` to the parent — §8.12's invariant inverted as far as it goes.
#[test]
fn a_child_that_overspent_its_grant_refunds_nothing_rather_than_an_enormous_amount() {
    let mut conn = open_test_db();
    let (parent, child) = a_parent_and_child(&mut conn, a_small_grant());
    let parent_before = run_ledger(&conn, parent).unwrap().spent;
    conn.execute(
        "UPDATE workflow_run
            SET spent_tokens = 900, spent_cost_usd = 5.0, spent_tasks = 40,
                spent_tool_calls = 50, spent_subagents = 8,
                spent_bytes_written = 9000, spent_escalations = 6
          WHERE id = ?1",
        rusqlite::params![child.to_string()],
    )
    .unwrap();
    transition_run(&mut conn, child, RunState::Completed, at_secs(3)).unwrap();

    let refunded = refund_child_run(&mut conn, child, at_secs(4)).unwrap();
    assert_eq!(
        refunded,
        Spend::ZERO,
        "there is nothing unspent to give back, in any field"
    );
    assert_eq!(
        run_ledger(&conn, parent).unwrap().spent,
        parent_before,
        "and the parent's ledger is untouched by a zero refund"
    );
}

/// `refundable_dollars`'s guard on an unusable stored spend, and the one input
/// shape where it is load-bearing.
///
/// Measured: for `+inf` and `NaN` the guard is redundant — `(grant - inf)` is
/// `-inf` and `(grant - NaN)` is `NaN`, and `f64::max(0.0)` turns both into
/// `0.0` on its own. The case that needs it is a **negative** stored spend,
/// where `(grant - -5.0)` is `grant + 5` and the refund *inflates*: the parent
/// is credited more than the draw ever took out.
#[test]
fn a_negative_stored_dollar_spend_refunds_nothing_rather_than_inflating_the_parents_pool() {
    let mut conn = open_test_db();
    let (parent, child) = a_parent_and_child(&mut conn, a_small_grant());
    let parent_charged = run_ledger(&conn, parent).unwrap().spent.cost_usd;
    assert_eq!(
        parent_charged, 2.0,
        "the draw charged the child's whole grant"
    );

    hand_edit(&conn, "spent_cost_usd = -5.0, spent_tokens = 500", child);
    transition_run(&mut conn, child, RunState::Completed, at_secs(3)).unwrap();

    let refunded = refund_child_run(&mut conn, child, at_secs(4)).unwrap();
    assert_eq!(
        refunded.cost_usd, 0.0,
        "an unusable stored spend refunds nothing; grant - (-5) would refund 7.0"
    );
    assert_eq!(
        run_ledger(&conn, parent).unwrap().spent.cost_usd,
        parent_charged,
        "so the parent's recorded spend is not decremented by budget nobody granted"
    );
}

/// `wall_elapsed`'s floor at the boundary the *signature* admits rather than
/// the one the schema usually holds — ruling P108 §E's "accurate about the
/// values you had in mind and wrong about the values the signature admits".
///
/// `saturating_sub` and a plain subtraction agree everywhere except where
/// `end - started` overflows `i64`, which needs the two extremes. There it
/// matters a great deal: saturating reports ~292 years of elapsed wall time and
/// the run is refused, wrapping reports **zero** and the run has an unbounded
/// window.
#[test]
fn a_wall_clock_that_overflows_i64_saturates_rather_than_wrapping_to_no_elapsed_time() {
    let mut conn = open_test_db();
    let run_id = a_seeded_run(&mut conn);
    conn.execute(
        "UPDATE workflow_run SET started_at = ?1 WHERE id = ?2",
        rusqlite::params![i64::MIN, run_id.to_string()],
    )
    .expect("started_at carries no CHECK, so this needs no pragma");
    let far_future = Timestamp::from_unix_nanos(i64::MAX);

    let ledger = run_ledger(&conn, run_id).unwrap();
    assert_eq!(
        wall_elapsed(&ledger, far_future),
        Duration::from_nanos(i64::MAX as u64),
        "i64::MAX - i64::MIN saturates; wrapping would report -1 and read back as zero"
    );

    let refused = admit_spend(&mut conn, run_id, &a_spend_of(1, 0.0), far_future);
    assert!(
        matches!(
            refused,
            Err(LedgerError::CapsExceeded {
                field: "run_wall_timeout",
                ..
            })
        ),
        "and the wall window is what refuses it, before the active one does; got {refused:?}"
    );
}

// ---------------------------------------------------------------------------
// Ruling P114 §A's invariant: no `workflow_run` row carrying a `parent_run_id`
// is committed without a draw in the same transaction
// ---------------------------------------------------------------------------

/// Counts the `workflow_run` rows for one id, so a refusal can be shown to
/// have left **nothing** behind rather than a row whose draw merely failed.
fn row_count(conn: &Connection, run_id: RunId) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM workflow_run WHERE id = ?1",
        [run_id.to_string()],
        |row| row.get(0),
    )
    .unwrap()
}

/// The invariant as the happy path: the insert *is* the draw, stamped with the
/// child's own `started_at`, and the parent is charged before the transaction
/// commits.
///
/// Stated as the invariant rather than as "the fork draws" because the
/// spend-direction hole was never fork-specific (ruling P114 §A):
/// `insert_workflow_run` with a caller-supplied `parent_run_id` and `caps`
/// minted a grant at **every** site, and `call:` would have done exactly what
/// the fork did the moment it had a production caller.
#[test]
fn inserting_a_parented_row_draws_its_grant_from_the_parent_in_the_same_transaction() {
    let mut conn = open_test_db();
    let parent = a_seeded_run(&mut conn);
    assert_eq!(run_ledger(&conn, parent).unwrap().spent, Spend::ZERO);

    let mut child = a_run(RunId::new(), Some(1), Some(a_small_grant()));
    child.parent_run_id = Some(parent);
    child.started_at = at_secs(7);
    insert_workflow_run(&mut conn, &child).expect("the child fits its parent's grant");

    assert_eq!(
        run_ledger(&conn, parent).unwrap().spent,
        Spend::for_grant(&a_small_grant()),
        "the parent is charged the child's whole grant by the insert itself"
    );
    assert_eq!(
        run_ledger(&conn, child.id).unwrap().drawn_at,
        Some(at_secs(7)),
        "and the stamp is the child's own creation instant, not a second parameter"
    );
}

/// The refusal, in the three shapes it takes — and in every one of them the
/// child row must be **absent**, not present-but-uncharged. A committed child
/// that is `Running` and spends anyway is exactly what ruling P114 §B says a
/// non-composing draw would leave behind.
#[test]
fn a_parented_row_whose_draw_is_refused_leaves_no_row_at_all() {
    // 1. The parent's grant cannot cover the child's.
    {
        let mut conn = open_test_db();
        let parent = a_seeded_run(&mut conn);
        let mut child = a_run(
            RunId::new(),
            Some(1),
            Some(ResourceCaps {
                max_tokens: a_grant().max_tokens + 1,
                ..a_small_grant()
            }),
        );
        child.parent_run_id = Some(parent);
        let refused = insert_workflow_run(&mut conn, &child);
        let Err(DurabilityError::ChildDrawRefused { source, .. }) = refused else {
            panic!("an uncoverable grant must be refused, got {refused:?}");
        };
        assert!(
            matches!(
                *source,
                LedgerError::CapsExceeded {
                    field: "max_tokens",
                    ..
                }
            ),
            "and the reason names what ran out, got {source:?}"
        );
        assert_eq!(row_count(&conn, child.id), 0);
        assert_eq!(run_ledger(&conn, parent).unwrap().spent, Spend::ZERO);
    }

    // 2. The child records no grant of its own, so there is nothing to draw.
    {
        let mut conn = open_test_db();
        let parent = a_seeded_run(&mut conn);
        let mut child = a_run(RunId::new(), Some(1), None);
        child.parent_run_id = Some(parent);
        let refused = insert_workflow_run(&mut conn, &child);
        assert!(
            matches!(
                refused,
                Err(DurabilityError::ChildDrawRefused { ref source, .. })
                    if matches!(**source, LedgerError::CapsNotRecorded { .. })
            ),
            "got {refused:?}"
        );
        assert_eq!(row_count(&conn, child.id), 0);
    }

    // 3. The parent is not admitting new work — §8.13's cancel, reached
    //    through child creation rather than through a task.
    {
        let mut conn = open_test_db();
        let parent = a_seeded_run(&mut conn);
        transition_run(&mut conn, parent, RunState::Cancelling, at_secs(1)).unwrap();
        let mut child = a_run(RunId::new(), Some(1), Some(a_small_grant()));
        child.parent_run_id = Some(parent);
        let refused = insert_workflow_run(&mut conn, &child);
        assert!(
            matches!(
                refused,
                Err(DurabilityError::ChildDrawRefused { ref source, .. })
                    if matches!(**source, LedgerError::NotAdmitting {
                        state: RunState::Cancelling, ..
                    })
            ),
            "a cancelling run must not acquire new children; got {refused:?}"
        );
        assert_eq!(row_count(&conn, child.id), 0);
    }
}

/// A **root** run is unaffected: it has no parent to draw from, and refusing
/// one would make the invariant unsatisfiable for the first run of any tree.
#[test]
fn a_row_with_no_parent_is_inserted_without_any_draw() {
    let mut conn = open_test_db();
    let root = a_seeded_run(&mut conn);
    assert_eq!(run_ledger(&conn, root).unwrap().drawn_at, None);
    assert_eq!(run_ledger(&conn, root).unwrap().spent, Spend::ZERO);
}

// ---------------------------------------------------------------------------
// §8.13's one exemption: `finally:` runs during `Cancelling`
// ---------------------------------------------------------------------------

/// §8.13 requires *both* *"refuse new task admission"* **and** *"run
/// `finally:`"* of one cancel, so an exemption is unavoidable. This is its
/// exact width: `Cancelling` admits a `finally:` step and nothing else admits
/// anything extra.
#[test]
fn a_finally_step_is_admitted_while_cancelling_and_an_ordinary_step_is_not() {
    let mut conn = open_test_db();
    let run_id = a_seeded_run(&mut conn);
    transition_run(&mut conn, run_id, RunState::Cancelling, at_secs(1)).unwrap();

    let ordinary = admit_spend(&mut conn, run_id, &a_spend_of(10, 0.0), at_secs(2));
    assert!(
        matches!(
            ordinary,
            Err(LedgerError::NotAdmitting {
                state: RunState::Cancelling,
                ..
            })
        ),
        "a cancel still refuses new task admission; got {ordinary:?}"
    );
    assert_eq!(
        run_ledger(&conn, run_id).unwrap().spent.tokens,
        0,
        "and the refusal records nothing"
    );

    admit_spend_during_finally(&mut conn, run_id, &a_spend_of(10, 0.0), at_secs(3))
        .expect("a cleanup step runs: a cancel that skips `finally:` is not a cancel");
    assert_eq!(run_ledger(&conn, run_id).unwrap().spent.tokens, 10);
}

/// The exemption is scoped to the one clause that forces it. A `finally:`
/// block does not resurrect a paused, parked or ended run — those are not
/// states §8.13's sentence is about.
#[test]
fn the_finally_exemption_does_not_extend_to_any_other_non_running_state() {
    for target in [
        RunState::Paused,
        RunState::AwaitingHuman,
        RunState::Completed,
        RunState::Failed,
    ] {
        let mut conn = open_test_db();
        let run_id = a_seeded_run(&mut conn);
        transition_run(&mut conn, run_id, target, at_secs(1)).unwrap();

        let refused =
            admit_spend_during_finally(&mut conn, run_id, &a_spend_of(1, 0.0), at_secs(2));
        assert!(
            matches!(refused, Err(LedgerError::NotAdmitting { state, .. }) if state == target),
            "{target:?} must refuse a `finally:` step too, got {refused:?}"
        );
    }

    // `Cancelled` is reachable only through `Cancelling`, so it needs its own
    // two-step fixture rather than the loop's single transition.
    let mut conn = open_test_db();
    let run_id = a_seeded_run(&mut conn);
    transition_run(&mut conn, run_id, RunState::Cancelling, at_secs(1)).unwrap();
    transition_run(&mut conn, run_id, RunState::Cancelled, at_secs(2)).unwrap();
    let refused = admit_spend_during_finally(&mut conn, run_id, &a_spend_of(1, 0.0), at_secs(3));
    assert!(
        matches!(
            refused,
            Err(LedgerError::NotAdmitting {
                state: RunState::Cancelled,
                ..
            })
        ),
        "the drain has finished, so `finally:` has already run; got {refused:?}"
    );
}

/// **A `call:` inside `finally:` is not exempt.** There is no
/// `admit_call_from_run` twin of `admit_spend_during_finally`, and this is the
/// property that absence buys: cleanup that spawns an unbounded subtree of
/// child runs and child Sessions is not cleanup, and cancel must converge.
#[test]
fn a_call_is_never_exempt_from_the_cancel_refusal_however_it_is_reached() {
    let mut conn = open_test_db();
    let parent = a_seeded_run(&mut conn);
    transition_run(&mut conn, parent, RunState::Cancelling, at_secs(1)).unwrap();

    // Depth 0 with no children: every §7.7 bound would admit this call, so the
    // only thing that can refuse it is the run's state.
    let refused = admit_call_from_run(&conn, parent, 0);
    assert!(
        matches!(
            refused,
            Err(LedgerError::NotAdmitting {
                state: RunState::Cancelling,
                ..
            })
        ),
        "got {refused:?}"
    );

    // And the other half of a `call:` — creating the child run — is refused
    // too, so neither leg of it can be reached from a `finally:` block.
    let mut child = a_run(RunId::new(), Some(1), Some(a_small_grant()));
    child.parent_run_id = Some(parent);
    assert!(
        matches!(
            insert_workflow_run(&mut conn, &child),
            Err(DurabilityError::ChildDrawRefused { .. })
        ),
        "a cancelling run must not acquire a child through any route"
    );
}
