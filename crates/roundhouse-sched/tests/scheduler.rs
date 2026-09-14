use chrono::{DateTime, TimeZone, Utc};
use chrono_tz::Tz;
use roundhouse_core::JobId;
use roundhouse_sched::cron::CronError;
use roundhouse_sched::scheduler::{
    ClockSource, ScheduledOccurrence, Scheduler, SchedulerEvent,
    MAX_CATCH_UP_OCCURRENCES_PER_BINDING_PER_TICK,
};
use roundhouse_sched::trigger::{Binding, CatchUp, DstAmbiguous, DstGap, TriggerSpec};
use std::cell::RefCell;
use std::time::Duration;

/// A fake wall clock whose reading can be set directly, so forward and
/// backward wall-clock steps are reproduced deterministically rather than by
/// sleeping and hoping.
struct FakeClock {
    wall: RefCell<DateTime<Utc>>,
}

impl ClockSource for FakeClock {
    fn wall_now(&self) -> DateTime<Utc> {
        *self.wall.borrow()
    }
}

fn fires_for(
    events: &[SchedulerEvent],
    binding_id: roundhouse_core::BindingId,
) -> Vec<DateTime<Utc>> {
    events
        .iter()
        .filter_map(|e| match e {
            SchedulerEvent::Fire(ScheduledOccurrence {
                binding_id: id,
                scheduled_for,
                ..
            }) if *id == binding_id => Some(*scheduled_for),
            _ => None,
        })
        .collect()
}

/// Bug fix (Task 1, Phase 8 rebuild): the old scheduler also read a
/// monotonic clock and treated any disagreement between it and the wall
/// clock beyond a 2s threshold as "drift," calling `recompute_all`
/// regardless of whether the wall clock had moved forward or backward.
/// Since `recompute_all` only computes the *next* occurrence after the new
/// wall time (it never fires anything itself — see its doc comment), an
/// ordinary forward jump — even a large one, with no real backlog problem —
/// silently dropped whatever was actually due. A forward wall-clock jump,
/// however large, must instead always drain through `drain_due` and
/// actually fire what's due.
#[test]
fn tick_forward_wall_clock_jump_of_any_size_still_drains_the_backlog_instead_of_discarding_it() {
    let start_wall = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let clock = FakeClock {
        wall: RefCell::new(start_wall),
    };
    let mut sched = Scheduler::new();
    let binding = Binding::new_cron(JobId::new(), "* * * * *".to_string(), Tz::UTC);
    let binding_id = binding.id;
    sched.add_binding(binding, &clock).unwrap();

    // A forward jump far beyond the old 2s drift threshold — a full hour,
    // with the binding's one-minute cron due 59 times over. The bug this
    // guards against: the old drift check would have seen this same jump as
    // drift and called `recompute_all`, which fires nothing and simply
    // reschedules from the new wall time — silently dropping every one of
    // those due occurrences.
    let target = start_wall + chrono::Duration::hours(1);
    *clock.wall.borrow_mut() = target;

    let events = sched.tick(&clock);
    assert!(
        !fires_for(&events, binding_id).is_empty(),
        "a forward wall-clock jump, however large, must drain and fire what's due, not \
         silently discard it via recompute_all: {events:?}"
    );
}

/// A backward wall-clock step — an NTP correction after a suspend/resume
/// cycle overshoots, or a manual clock change — is the one case that must
/// still trigger a full `recompute_all`, dropping whatever schedule was
/// pending in favor of one recomputed from the corrected time. Proven by
/// re-anchoring: probing at a wall time that is only reachable if the
/// schedule was actually recomputed from the backward reading (not left
/// anchored to the pre-step schedule, which `drain_due` alone would do
/// nothing to change since nothing in it is yet due at an earlier time).
#[test]
fn tick_backward_wall_clock_step_triggers_recompute_and_drops_the_pending_schedule() {
    let start_wall = Utc.with_ymd_and_hms(2026, 1, 1, 0, 10, 0).unwrap();
    let clock = FakeClock {
        wall: RefCell::new(start_wall),
    };
    let mut sched = Scheduler::new();
    let binding = Binding::new_cron(JobId::new(), "* * * * *".to_string(), Tz::UTC);
    let binding_id = binding.id;
    sched.add_binding(binding, &clock).unwrap(); // next fire: 00:11:00

    // Ordinary forward tick, nothing due yet — establishes `last_wall`.
    let advanced = start_wall + chrono::Duration::seconds(30);
    *clock.wall.borrow_mut() = advanced;
    let events = sched.tick(&clock);
    assert!(
        fires_for(&events, binding_id).is_empty(),
        "nothing is due yet: {events:?}"
    );

    // A backward step: 00:09:00 is earlier than the 00:10:30 this scheduler
    // just recorded. Must recompute (next fire becomes 00:10:00), not
    // silently do nothing.
    let backward = Utc.with_ymd_and_hms(2026, 1, 1, 0, 9, 0).unwrap();
    *clock.wall.borrow_mut() = backward;
    let events2 = sched.tick(&clock);
    assert!(
        fires_for(&events2, binding_id).is_empty(),
        "a backward step must not itself fire anything: {events2:?}"
    );

    // Probe at 00:10:01 — past the recompute-derived next fire (00:10:00)
    // but well before the original, pre-step schedule's next fire
    // (00:11:00). Only reachable if `recompute_all` actually ran and
    // re-anchored the schedule to the corrected (backward) wall clock.
    let probe = Utc.with_ymd_and_hms(2026, 1, 1, 0, 10, 1).unwrap();
    *clock.wall.borrow_mut() = probe;
    let events3 = sched.tick(&clock);
    assert_eq!(
        fires_for(&events3, binding_id),
        vec![Utc.with_ymd_and_hms(2026, 1, 1, 0, 10, 0).unwrap()],
        "the schedule must be recomputed from the corrected (backward) wall clock, dropping \
         whatever was pending before the step, not left anchored to the pre-step schedule: \
         {events3:?}"
    );
}

#[test]
fn due_binding_fires_and_reschedules_its_next_occurrence() {
    let start_wall = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let clock = FakeClock {
        wall: RefCell::new(start_wall),
    };
    let mut sched = Scheduler::new();
    let binding = Binding::new_cron(JobId::new(), "0 2 * * *".to_string(), Tz::UTC);
    let binding_id = binding.id;
    sched.add_binding(binding, &clock).unwrap();

    // Advance to just past the first fire time (2026-01-01T02:00:00Z).
    let target = Utc.with_ymd_and_hms(2026, 1, 1, 2, 0, 1).unwrap();
    *clock.wall.borrow_mut() = target;

    let events = sched.tick(&clock);
    assert_eq!(
        fires_for(&events, binding_id),
        vec![Utc.with_ymd_and_hms(2026, 1, 1, 2, 0, 0).unwrap()]
    );

    // Tick again well past the *next* day's occurrence: the binding must
    // have rescheduled itself, not gone silent after firing once.
    let next_target = Utc.with_ymd_and_hms(2026, 1, 2, 2, 0, 1).unwrap();
    *clock.wall.borrow_mut() = next_target;
    let events = sched.tick(&clock);
    assert_eq!(
        fires_for(&events, binding_id),
        vec![Utc.with_ymd_and_hms(2026, 1, 2, 2, 0, 0).unwrap()]
    );
}

/// Ruling P16: `next_fire_after` alone can only ever report one instant of a
/// `DstAmbiguous::Both` fold. This test wires the scheduler's own detection
/// (`is_ambiguous_local`) and fan-out (`fire_all_ambiguous`) end to end: a
/// `Both`-policy binding whose next occurrence falls in a real DST fold must
/// produce *two* `Fire` events, one per UTC instant of the doubled local
/// hour, not one.
#[test]
fn dst_ambiguous_both_schedules_and_fires_both_instants() {
    // America/New_York, 2026-11-01: 01:30 local occurs twice — first at EDT
    // (UTC-4, i.e. 05:30 UTC), second at EST (UTC-5, i.e. 06:30 UTC). Same
    // real transition instant verified in `tests/cron.rs`.
    let tz = Tz::America__New_York;
    // Start right before the fold (same `after` used in `tests/cron.rs`'s
    // equivalent `next_fire_after` test) so this daily cron's very next
    // occurrence *is* the ambiguous one, isolating the double-fire case
    // rather than also picking up 31 days of unrelated prior fires.
    let start_wall = Utc.with_ymd_and_hms(2026, 11, 1, 4, 0, 0).unwrap();
    let clock = FakeClock {
        wall: RefCell::new(start_wall),
    };

    let mut sched = Scheduler::new();
    let binding = Binding::new(
        JobId::new(),
        TriggerSpec::Cron {
            expr: "30 1 * * *".to_string(),
            tz,
            catch_up: CatchUp::Latest,
            jitter: Duration::ZERO,
            dst_gap: DstGap::FireAtGapEnd,
            dst_ambiguous: DstAmbiguous::Both,
        },
    );
    let binding_id = binding.id;
    sched.add_binding(binding, &clock).unwrap();

    // Advance past both fold instants.
    let target = Utc.with_ymd_and_hms(2026, 11, 1, 7, 0, 0).unwrap();
    *clock.wall.borrow_mut() = target;

    let events = sched.tick(&clock);
    let mut fires = fires_for(&events, binding_id);
    fires.sort();
    assert_eq!(
        fires,
        vec![
            Utc.with_ymd_and_hms(2026, 11, 1, 5, 30, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 11, 1, 6, 30, 0).unwrap(),
        ],
        "DstAmbiguous::Both must fire both UTC instants of the fold, not just one: {events:?}"
    );
}

/// A `DstAmbiguous::First` binding on the same real fold must fire only
/// once — contrast case for the `Both` test above, confirming the
/// double-fire path is genuinely gated on the policy rather than always
/// firing twice near a fold.
#[test]
fn dst_ambiguous_first_fires_only_the_earlier_instant_on_the_same_fold() {
    let tz = Tz::America__New_York;
    let start_wall = Utc.with_ymd_and_hms(2026, 11, 1, 4, 0, 0).unwrap();
    let clock = FakeClock {
        wall: RefCell::new(start_wall),
    };

    let mut sched = Scheduler::new();
    let binding = Binding::new_cron(JobId::new(), "30 1 * * *".to_string(), tz);
    let binding_id = binding.id;
    sched.add_binding(binding, &clock).unwrap();

    let target = Utc.with_ymd_and_hms(2026, 11, 1, 7, 0, 0).unwrap();
    *clock.wall.borrow_mut() = target;

    let events = sched.tick(&clock);
    assert_eq!(
        fires_for(&events, binding_id),
        vec![Utc.with_ymd_and_hms(2026, 11, 1, 5, 30, 0).unwrap()],
        "DstAmbiguous::First must fire exactly once, at the earlier instant: {events:?}"
    );
}

/// M5: `Scheduler::tick` previously never consulted `CatchUp` at all — every
/// missed occurrence fired regardless of the binding's policy. A binding
/// offline for several missed once-a-minute occurrences under
/// `CatchUp::None` must fire nothing, while still advancing its schedule
/// past the whole missed backlog (not re-considering it on the next tick).
#[test]
fn catch_up_none_is_actually_applied_by_tick_and_still_advances_the_schedule() {
    let start_wall = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let clock = FakeClock {
        wall: RefCell::new(start_wall),
    };
    let mut sched = Scheduler::new();
    let mut binding = Binding::new_cron(JobId::new(), "* * * * *".to_string(), Tz::UTC);
    if let TriggerSpec::Cron { catch_up, .. } = &mut binding.spec {
        *catch_up = CatchUp::None;
    }
    let binding_id = binding.id;
    sched.add_binding(binding, &clock).unwrap();

    // Simulate an outage: 5 missed once-a-minute occurrences (00:01..00:05).
    let target = start_wall + chrono::Duration::minutes(5);
    *clock.wall.borrow_mut() = target;

    let events = sched.tick(&clock);
    assert!(
        fires_for(&events, binding_id).is_empty(),
        "CatchUp::None must fire nothing for missed occurrences: {events:?}"
    );

    // The schedule must have advanced past the whole missed backlog, not
    // gotten stuck re-considering it: the very next occurrence (00:06) must
    // now be the one that's due, not 00:01 again.
    let next_target = target + chrono::Duration::minutes(1);
    *clock.wall.borrow_mut() = next_target;
    let events2 = sched.tick(&clock);
    assert_eq!(fires_for(&events2, binding_id), vec![next_target]);
}

/// M5: `CatchUp::Latest` applied through `tick` for real — a 5-minute
/// backlog must fire exactly the most recent missed occurrence, not all 5.
#[test]
fn catch_up_latest_is_actually_applied_by_tick() {
    let start_wall = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let clock = FakeClock {
        wall: RefCell::new(start_wall),
    };
    let mut sched = Scheduler::new();
    // `Binding::new_cron` already defaults to `CatchUp::Latest`.
    let binding = Binding::new_cron(JobId::new(), "* * * * *".to_string(), Tz::UTC);
    let binding_id = binding.id;
    sched.add_binding(binding, &clock).unwrap();

    let target = start_wall + chrono::Duration::minutes(5);
    *clock.wall.borrow_mut() = target;

    let events = sched.tick(&clock);
    assert_eq!(
        fires_for(&events, binding_id),
        vec![target],
        "CatchUp::Latest must fire only the most recent missed occurrence: {events:?}"
    );
}

/// M5: `CatchUp::All` applied through `tick` for real — every missed
/// occurrence in a small backlog must fire.
#[test]
fn catch_up_all_is_actually_applied_by_tick() {
    let start_wall = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let clock = FakeClock {
        wall: RefCell::new(start_wall),
    };
    let mut sched = Scheduler::new();
    let mut binding = Binding::new_cron(JobId::new(), "* * * * *".to_string(), Tz::UTC);
    if let TriggerSpec::Cron { catch_up, .. } = &mut binding.spec {
        *catch_up = CatchUp::All;
    }
    let binding_id = binding.id;
    sched.add_binding(binding, &clock).unwrap();

    let target = start_wall + chrono::Duration::minutes(5);
    *clock.wall.borrow_mut() = target;

    let events = sched.tick(&clock);
    let expected: Vec<DateTime<Utc>> = (1..=5)
        .map(|m| start_wall + chrono::Duration::minutes(m))
        .collect();
    assert_eq!(fires_for(&events, binding_id), expected);
}

/// M5: a backlog larger than
/// `MAX_CATCH_UP_OCCURRENCES_PER_BINDING_PER_TICK` must not flood a single
/// `tick()` call — each call processes at most one capped batch per
/// binding, catching up progressively over successive calls instead of all
/// at once.
#[test]
fn catch_up_all_is_capped_per_tick_and_completes_progressively_across_calls() {
    let start_wall = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let clock = FakeClock {
        wall: RefCell::new(start_wall),
    };
    let mut sched = Scheduler::new();
    let mut binding = Binding::new_cron(JobId::new(), "* * * * *".to_string(), Tz::UTC);
    if let TriggerSpec::Cron { catch_up, .. } = &mut binding.spec {
        *catch_up = CatchUp::All;
    }
    let binding_id = binding.id;
    sched.add_binding(binding, &clock).unwrap();

    let cap = MAX_CATCH_UP_OCCURRENCES_PER_BINDING_PER_TICK;
    let extra = 51usize;
    let total_missed = cap * 2 + extra;
    let target = start_wall + chrono::Duration::minutes(total_missed as i64);
    *clock.wall.borrow_mut() = target;

    let first = sched.tick(&clock);
    assert_eq!(
        fires_for(&first, binding_id).len(),
        cap,
        "the first tick's catch-up pass must be capped, not unbounded: {first:?}"
    );

    let second = sched.tick(&clock);
    assert_eq!(
        fires_for(&second, binding_id).len(),
        cap,
        "the backlog must continue draining on the next tick: {second:?}"
    );

    let third = sched.tick(&clock);
    assert_eq!(
        fires_for(&third, binding_id).len(),
        extra,
        "the remainder must fire once the backlog is exhausted: {third:?}"
    );

    let fourth = sched.tick(&clock);
    assert!(
        fires_for(&fourth, binding_id).is_empty(),
        "the backlog is fully caught up; a later tick at the same wall clock must fire nothing more: {fourth:?}"
    );
}

/// A held-constant clock (whatever `catch_up_after_wake` last set as the
/// baseline) used to drive further `tick()` calls in the progressive-drain
/// test below without introducing any *additional* forward movement of its
/// own — isolating "does the backlog drain" from "does advancing the clock
/// further also work" (already covered by
/// `catch_up_all_is_capped_per_tick_and_completes_progressively_across_calls`).
fn clock_at(wall: DateTime<Utc>) -> FakeClock {
    FakeClock {
        wall: RefCell::new(wall),
    }
}

/// Task 6 (§8.7): `Scheduler::catch_up_after_wake` must drain a real
/// suspend-scale backlog through the same capped, progressive machinery as
/// `tick`'s ordinary catch-up path — not the backward-step-triggered
/// `recompute_all` path, which would discard it. Modeled as a genuinely
/// long sleep (a `* * * * *` cron offline for 10 days — 14,400 missed
/// occurrences, two orders of magnitude past the per-call cap).
#[test]
fn catch_up_after_wake_drains_a_long_sleep_progressively_across_calls() {
    let start_wall = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let mut binding = Binding::new_cron(JobId::new(), "* * * * *".to_string(), Tz::UTC);
    if let TriggerSpec::Cron { catch_up, .. } = &mut binding.spec {
        *catch_up = CatchUp::All;
    }
    let binding_id = binding.id;

    let clock = FakeClock {
        wall: RefCell::new(start_wall),
    };
    let mut sched = Scheduler::new();
    sched.add_binding(binding, &clock).unwrap();

    let cap = MAX_CATCH_UP_OCCURRENCES_PER_BINDING_PER_TICK;
    let total_missed = cap * 100 + 7; // a "daemon asleep for ~10 days" scale backlog
    let target_wall = start_wall + chrono::Duration::minutes(total_missed as i64);

    let first = sched.catch_up_after_wake(target_wall);
    assert_eq!(
        fires_for(&first, binding_id).len(),
        cap,
        "a single wake call must drain at most one capped batch, not the whole 10-day \
         backlog and not zero of it: {first:?}"
    );
    assert!(
        sched.heap_len() > 0,
        "the rest of the backlog must remain heaped for progressive draining, not be lost"
    );

    // The remainder drains across subsequent calls exactly like `tick`'s
    // own progressive catch-up (proving the wake path really does go
    // through that shared machinery, not around it).
    let mut remaining = total_missed - cap;
    let mut guard_iterations = 0;
    while remaining > 0 {
        guard_iterations += 1;
        assert!(
            guard_iterations <= 200,
            "catch-up did not converge; backlog is not draining"
        );
        let events = sched.tick(&clock_at(target_wall));
        let fired = fires_for(&events, binding_id).len();
        assert!(
            fired > 0,
            "backlog stalled with {remaining} occurrences left"
        );
        assert!(
            fired <= cap,
            "a single tick must never exceed the per-binding cap"
        );
        remaining -= fired;
    }
    assert_eq!(remaining, 0);

    // Fully drained: a later tick at the same wall clock must fire nothing
    // more.
    let last = sched.tick(&clock_at(target_wall));
    assert!(
        fires_for(&last, binding_id).is_empty(),
        "backlog is fully caught up; nothing more should fire: {last:?}"
    );
}

/// Fix round 1 (M2): `CatchUp::None` must drop an *entire* multi-batch
/// backlog, not just each capped batch independently — the bug this guards
/// against is a trailing batch that happens to contain exactly one
/// occurrence being treated as an ordinary (always-fires) single
/// occurrence instead of the tail of a real backlog. `cap * 3` is
/// deliberately an exact multiple of the per-call cap, exercising the
/// `next_after_cursor` lookahead fix (the gather loop hitting the cap and
/// running out of backlog on the very same batch).
#[test]
fn catch_up_after_wake_with_none_policy_drops_an_entire_multi_batch_backlog() {
    let start_wall = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let mut binding = Binding::new_cron(JobId::new(), "* * * * *".to_string(), Tz::UTC);
    if let TriggerSpec::Cron { catch_up, .. } = &mut binding.spec {
        *catch_up = CatchUp::None;
    }
    let binding_id = binding.id;

    let clock = FakeClock {
        wall: RefCell::new(start_wall),
    };
    let mut sched = Scheduler::new();
    sched.add_binding(binding, &clock).unwrap();

    let cap = MAX_CATCH_UP_OCCURRENCES_PER_BINDING_PER_TICK;
    let total_missed = cap * 3; // exact multiple of the cap: 3 batches, none partial
    let target_wall = start_wall + chrono::Duration::minutes(total_missed as i64);

    let mut all_fires = fires_for(&sched.catch_up_after_wake(target_wall), binding_id);
    for _ in 0..10 {
        if sched.heap_len() == 0 {
            break;
        }
        all_fires.extend(fires_for(&sched.tick(&clock_at(target_wall)), binding_id));
    }
    assert!(
        all_fires.is_empty(),
        "CatchUp::None must drop the whole backlog across every batch, including an exact \
         multiple of the cap where the last batch's gather loop stops for the same reason \
         (hitting the cap) as it running out of backlog: {all_fires:?}"
    );

    // The pass must actually finish (not leave `catch_up_progress` stuck):
    // a later, genuinely ordinary single occurrence must still fire.
    let next_minute = target_wall + chrono::Duration::minutes(1);
    let after = sched.tick(&clock_at(next_minute));
    assert_eq!(
        fires_for(&after, binding_id),
        vec![next_minute],
        "a single ordinary occurrence after the backlog must still fire normally, proving the \
         catch-up pass actually finalized rather than leaving state stuck: {after:?}"
    );
}

/// Fix round 2 (Low, security review of Task 6): `recompute_all` must clear
/// `catch_up_progress`, or a binding caught mid-backlog keeps a stranded
/// entry that outlives the backlog it was tracking. Sequence: (1) put a
/// `CatchUp::None` binding genuinely mid-backlog (a capped batch that did
/// *not* exhaust it, so a `catch_up_progress` entry is left behind); (2) a
/// backward wall-clock step at wake, which routes through `recompute_all`;
/// (3) let one *ordinary* single occurrence come due afterward and assert it
/// fires. Without the `clear()`, the stranded entry makes `is_catch_up_pass`
/// true for that lone, unrelated occurrence, and `CatchUp::None` swallows
/// it — a genuinely ordinary firing lost to a backlog that no longer exists.
#[test]
fn recompute_all_clears_catch_up_progress_so_a_later_ordinary_occurrence_still_fires() {
    let start_wall = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let mut binding = Binding::new_cron(JobId::new(), "* * * * *".to_string(), Tz::UTC);
    if let TriggerSpec::Cron { catch_up, .. } = &mut binding.spec {
        *catch_up = CatchUp::None;
    }
    let binding_id = binding.id;

    let add_clock = FakeClock {
        wall: RefCell::new(start_wall),
    };
    let mut sched = Scheduler::new();
    sched.add_binding(binding, &add_clock).unwrap();

    // Step 1: a backlog bigger than the cap, advanced in a single tick, so
    // the first capped batch does *not* exhaust the backlog and leaves a
    // `catch_up_progress` entry behind.
    let cap = MAX_CATCH_UP_OCCURRENCES_PER_BINDING_PER_TICK;
    let backlog_wall = start_wall + chrono::Duration::minutes((cap + 50) as i64);
    let first = sched.tick(&clock_at(backlog_wall));
    assert!(
        fires_for(&first, binding_id).is_empty(),
        "CatchUp::None must fire nothing from the first (non-exhausting) batch: {first:?}"
    );

    // Step 2: a backward wake step relative to `backlog_wall` — routes
    // through `recompute_all`, which must also clear the `catch_up_progress`
    // entry step 1 just left behind.
    let corrected_wall = start_wall + chrono::Duration::minutes(10);
    let woke = sched.catch_up_after_wake(corrected_wall);
    assert!(
        woke.is_empty(),
        "a backward step must not itself fire anything: {woke:?}"
    );

    // Step 3: the schedule is now re-anchored to `corrected_wall`
    // (`* * * * *` → next fire at `corrected_wall + 1min`). This is a
    // genuinely ordinary single occurrence, unrelated to the backlog from
    // step 1 — it must fire regardless of `CatchUp::None`, which is only
    // fixed by `recompute_all` having cleared the stranded progress entry.
    let ordinary_fire_at = corrected_wall + chrono::Duration::minutes(1);
    let after = sched.tick(&clock_at(ordinary_fire_at));
    assert_eq!(
        fires_for(&after, binding_id),
        vec![ordinary_fire_at],
        "a genuinely ordinary single occurrence after an unrelated backlog was abandoned by \
         recompute_all must still fire — CatchUp::None must not swallow it via a stale, \
         stranded catch_up_progress entry from the old backlog: {after:?}"
    );
}

/// Fix round 2 (CRITICAL, security review of Task 6): a non-cron trigger
/// (in practice, only `TriggerSpec::Interval` is heap-scheduled) has no
/// `CatchUp` concept at all — `compute_catch_up`'s documented contract is
/// that every missed instant always fires for these. The original fix
/// round 1 M2 fold tested only `Some(CatchUp::All)` for the "fire every
/// batch immediately" identity path, so a non-cron binding
/// (`catch_up_policy` returns `None` for it) fell through into the
/// `Latest`-shaped branch instead, where `compute_catch_up` correctly
/// returns `missed` unchanged (its non-cron contract) but the surrounding
/// `.into_iter().max()` then collapsed it to a single instant anyway —
/// unrecoverably dropping every other missed `Interval` occurrence, on any
/// late tick (not just a suspend/wake). Spans two capped batches
/// (`cap * 2 + 3`) so the fix is proven across `drain_due`'s cross-batch
/// bookkeeping too, not just within a single batch.
#[test]
fn interval_binding_backlog_fires_every_missed_occurrence_across_multiple_capped_batches() {
    let start_wall = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let clock = FakeClock {
        wall: RefCell::new(start_wall),
    };
    let mut sched = Scheduler::new();
    let binding = Binding::new(
        JobId::new(),
        TriggerSpec::Interval {
            every: Duration::from_secs(60),
            align: false,
            anchor: None,
        },
    );
    let binding_id = binding.id;
    sched.add_binding(binding, &clock).unwrap();

    let cap = MAX_CATCH_UP_OCCURRENCES_PER_BINDING_PER_TICK;
    let total_missed = cap * 2 + 3;
    let target = start_wall + chrono::Duration::minutes(total_missed as i64);
    *clock.wall.borrow_mut() = target;

    let mut all_fires: Vec<DateTime<Utc>> = Vec::new();
    for _ in 0..10 {
        let fired = fires_for(&sched.tick(&clock), binding_id);
        if fired.is_empty() {
            break;
        }
        all_fires.extend(fired);
    }

    let expected: Vec<DateTime<Utc>> = (1..=total_missed as i64)
        .map(|m| start_wall + chrono::Duration::minutes(m))
        .collect();
    assert_eq!(
        all_fires,
        expected,
        "a non-cron (Interval) binding has no CatchUp policy to apply — every missed \
         occurrence must fire, not just the latest one, across every capped batch: \
         got {} fires, expected {}",
        all_fires.len(),
        expected.len()
    );
}

/// Fix round 1 (M1): a *backward* wall-clock step reported at wake must fall
/// back to a full `recompute_all`, not be treated as a catch-up backlog. An
/// `Interval` binding (no `CatchUp` policy at all) isolates this from M2's
/// concerns: the only question here is which of `drain_due`/`recompute_all`
/// ran, observed indirectly through where the schedule ends up anchored.
#[test]
fn catch_up_after_wake_falls_back_to_recompute_on_a_backward_wall_clock_step() {
    let t0 = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let add_clock = FakeClock {
        wall: RefCell::new(t0),
    };
    let mut sched = Scheduler::new();
    let every = chrono::Duration::minutes(200).to_std().unwrap();
    let binding = Binding::new(
        JobId::new(),
        TriggerSpec::Interval {
            every,
            align: false,
            anchor: None,
        },
    );
    let binding_id = binding.id;
    sched.add_binding(binding, &add_clock).unwrap(); // next fire: t0 + 200min

    // First wake: forward step to t0 + 60min. Nothing due yet (200min away),
    // so this is indistinguishable from a no-op either way — it only
    // advances the baseline `last_wall` this test's backward step below
    // needs to be backward *relative to*.
    let fired1 = sched.catch_up_after_wake(t0 + chrono::Duration::minutes(60));
    assert!(fired1.is_empty());

    // Second wake: a *backward* step to t0 + 10min (50 minutes earlier than
    // the t0 + 60min this scheduler just recorded — an NTP correction
    // overshooting after a resume). Must re-anchor via `recompute_all`, not
    // silently do nothing via `drain_due` (which would find the still-
    // t0+200min heap entry not yet due and leave it untouched).
    let fired2 = sched.catch_up_after_wake(t0 + chrono::Duration::minutes(10));
    assert!(
        fired2.is_empty(),
        "a clock correction must not itself fire a Fire event: {fired2:?}"
    );

    // Probe with plain `tick` at a wall clock chosen to fall strictly
    // between the two possible re-anchor points: t0 + 200min (if the
    // backward step were wrongly treated as a catch-up backlog and the
    // stale heap entry left untouched) and t0 + 210min (t0 + 10min + 200min,
    // the correct `recompute_all`-from-the-corrected-clock answer).
    let probe_wall = t0 + chrono::Duration::minutes(205);
    let probe = sched.tick(&clock_at(probe_wall));
    assert!(
        fires_for(&probe, binding_id).is_empty(),
        "a backward wake step must re-anchor the schedule to the corrected clock (next fire \
         t0+210min), not leave the stale t0+200min entry due: {probe:?}"
    );

    let later_wall = t0 + chrono::Duration::minutes(211);
    let later = sched.tick(&clock_at(later_wall));
    assert_eq!(
        fires_for(&later, binding_id),
        vec![t0 + chrono::Duration::minutes(210)],
        "the re-anchored schedule must still fire once the corrected clock actually reaches \
         it, proving the fallback re-anchored rather than losing the binding entirely: {later:?}"
    );
}

/// Fold-in fix: an `Interval` binding with `every == Duration::ZERO` must be
/// rejected at registration time, not accepted and left to hang `tick`'s
/// catch-up gather loop on a never-advancing occurrence.
#[test]
fn adding_a_zero_duration_interval_binding_is_rejected_not_silently_accepted() {
    let clock = FakeClock {
        wall: RefCell::new(Utc::now()),
    };
    let mut sched = Scheduler::new();
    let binding = Binding::new(
        JobId::new(),
        TriggerSpec::Interval {
            every: Duration::ZERO,
            align: false,
            anchor: None,
        },
    );

    let err = sched.add_binding(binding, &clock).unwrap_err();
    assert!(matches!(err, CronError::ZeroInterval));
}

/// NEW-2 (fix round 2): `is_zero()` alone missed a non-zero magnitude beyond
/// `chrono::TimeDelta::MAX` (~9.22e15s), where `chrono::Duration::from_std`
/// returns `Err` and the old `unwrap_or_default()` silently turned that into
/// `TimeDelta::zero()` — bit-for-bit the same degenerate never-advances
/// behavior `ZeroInterval` exists to prevent. Confirmed this is rejected
/// (not silently accepted, and not a panic) at registration time.
#[test]
fn adding_an_interval_binding_beyond_chronos_representable_range_is_rejected() {
    let clock = FakeClock {
        wall: RefCell::new(Utc::now()),
    };
    let mut sched = Scheduler::new();
    let binding = Binding::new(
        JobId::new(),
        TriggerSpec::Interval {
            every: Duration::from_secs(u64::MAX),
            align: false,
            anchor: None,
        },
    );

    let err = sched.add_binding(binding, &clock).unwrap_err();
    assert!(matches!(err, CronError::IntervalTooLarge(_)));
}

/// NEW-2 (fix round 2): the second missed magnitude — roughly
/// 8.3e12s <= `every` <= `TimeDelta::MAX`, where `from_std` succeeds but the
/// later `DateTime<Utc> + TimeDelta` overflows chrono's representable year
/// range (max year 262143) and panics via `.expect(...)`-style addition, a
/// panic no `if let Ok(..)` call site could catch. Confirmed this magnitude
/// is rejected at registration time rather than reaching, and panicking,
/// inside `occurrences_after`'s arithmetic.
#[test]
fn adding_an_interval_binding_that_would_overflow_datetime_arithmetic_is_rejected() {
    let clock = FakeClock {
        wall: RefCell::new(Utc::now()),
    };
    let mut sched = Scheduler::new();
    let binding = Binding::new(
        JobId::new(),
        TriggerSpec::Interval {
            // ~9e12 seconds: from_std succeeds at this magnitude, but the
            // resulting DateTime addition would overflow chrono's range.
            every: Duration::from_secs(9_000_000_000_000),
            align: false,
            anchor: None,
        },
    );

    let err = sched.add_binding(binding, &clock).unwrap_err();
    assert!(matches!(err, CronError::IntervalTooLarge(_)));
}
