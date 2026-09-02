use chrono::{DateTime, TimeZone, Utc};
use chrono_tz::Tz;
use roundhouse_core::JobId;
use roundhouse_sched::cron::CronError;
use roundhouse_sched::scheduler::{
    ClockSource, Scheduler, SchedulerEvent, MAX_CATCH_UP_OCCURRENCES_PER_BINDING_PER_TICK,
};
use roundhouse_sched::trigger::{Binding, CatchUp, DstAmbiguous, DstGap, TriggerSpec};
use std::cell::RefCell;
use std::time::Duration;
use tokio::time::Instant;

/// A fake clock whose monotonic and wall clocks can be independently
/// advanced, so drift (NTP step, suspend/resume) is reproducible in a unit
/// test rather than relying on sleeping and hoping.
struct FakeClock {
    mono: RefCell<Instant>,
    wall: RefCell<DateTime<Utc>>,
}

impl ClockSource for FakeClock {
    fn monotonic_now(&self) -> Instant {
        *self.mono.borrow()
    }
    fn wall_now(&self) -> DateTime<Utc> {
        *self.wall.borrow()
    }
}

#[test]
fn wall_clock_step_beyond_2s_triggers_drift_event_and_full_recompute() {
    let start_mono = Instant::now();
    let start_wall = Utc::now();
    let clock = FakeClock {
        mono: RefCell::new(start_mono),
        wall: RefCell::new(start_wall),
    };
    let mut sched = Scheduler::new();
    let binding = Binding::new_cron(JobId::new(), "0 2 * * *".to_string(), Tz::UTC);
    sched.add_binding(binding.clone(), &clock).unwrap();

    // Advance monotonic by 1s, wall by 30s (simulating an NTP step / resume-from-suspend).
    *clock.mono.borrow_mut() = start_mono + Duration::from_secs(1);
    *clock.wall.borrow_mut() = start_wall + chrono::Duration::seconds(30);

    let events = sched.tick(&clock);
    assert!(events
        .iter()
        .any(|e| matches!(e, SchedulerEvent::DriftDetected { .. })));
}

#[test]
fn wall_clock_step_backward_beyond_2s_also_triggers_drift_event() {
    // A naive `(now_wall - last_wall).to_std().unwrap_or_default()` collapses
    // a negative wall delta to zero and would silently miss this case — a
    // backward wall-clock correction (e.g. an NTP step that overshoots after
    // suspend/resume) must be detected exactly as reliably as a forward one.
    let start_mono = Instant::now();
    let start_wall = Utc::now();
    let clock = FakeClock {
        mono: RefCell::new(start_mono),
        wall: RefCell::new(start_wall),
    };
    let mut sched = Scheduler::new();
    let binding = Binding::new_cron(JobId::new(), "0 2 * * *".to_string(), Tz::UTC);
    sched.add_binding(binding.clone(), &clock).unwrap();

    // Monotonic advances normally by 1s; wall clock jumps *backward* by 30s.
    *clock.mono.borrow_mut() = start_mono + Duration::from_secs(1);
    *clock.wall.borrow_mut() = start_wall - chrono::Duration::seconds(30);

    let events = sched.tick(&clock);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, SchedulerEvent::DriftDetected { .. })),
        "backward wall-clock steps must be detected as drift too, not silently dropped: {events:?}"
    );
}

#[test]
fn small_wall_clock_slack_under_2s_does_not_trigger_drift() {
    let start_mono = Instant::now();
    let start_wall = Utc::now();
    let clock = FakeClock {
        mono: RefCell::new(start_mono),
        wall: RefCell::new(start_wall),
    };
    let mut sched = Scheduler::new();
    let binding = Binding::new_cron(JobId::new(), "0 2 * * *".to_string(), Tz::UTC);
    sched.add_binding(binding, &clock).unwrap();

    // Monotonic and wall both advance by ~1s (well under the 2s threshold).
    *clock.mono.borrow_mut() = start_mono + Duration::from_millis(1_000);
    *clock.wall.borrow_mut() = start_wall + chrono::Duration::milliseconds(1_500);

    let events = sched.tick(&clock);
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, SchedulerEvent::DriftDetected { .. })),
        "sub-threshold slack must not be reported as drift: {events:?}"
    );
}

#[test]
fn due_binding_fires_and_reschedules_its_next_occurrence() {
    let start_wall = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let start_mono = Instant::now();
    let clock = FakeClock {
        mono: RefCell::new(start_mono),
        wall: RefCell::new(start_wall),
    };
    let mut sched = Scheduler::new();
    let binding = Binding::new_cron(JobId::new(), "0 2 * * *".to_string(), Tz::UTC);
    let binding_id = binding.id;
    sched.add_binding(binding, &clock).unwrap();

    // Advance to just past the first fire time (2026-01-01T02:00:00Z), keeping
    // monotonic and wall in lockstep so no drift event is produced.
    let target = Utc.with_ymd_and_hms(2026, 1, 1, 2, 0, 1).unwrap();
    let elapsed = (target - start_wall).to_std().unwrap();
    *clock.mono.borrow_mut() = start_mono + elapsed;
    *clock.wall.borrow_mut() = target;

    let events = sched.tick(&clock);
    let fires: Vec<DateTime<Utc>> = events
        .iter()
        .filter_map(|e| match e {
            SchedulerEvent::Fire(id, at) if *id == binding_id => Some(*at),
            _ => None,
        })
        .collect();
    assert_eq!(
        fires,
        vec![Utc.with_ymd_and_hms(2026, 1, 1, 2, 0, 0).unwrap()]
    );

    // Tick again well past the *next* day's occurrence: the binding must
    // have rescheduled itself, not gone silent after firing once. Both
    // clocks are advanced from `start_mono`/`start_wall` by the same total
    // elapsed amount, so they stay in lockstep and no drift event fires.
    let next_target = Utc.with_ymd_and_hms(2026, 1, 2, 2, 0, 1).unwrap();
    let total_elapsed = (next_target - start_wall).to_std().unwrap();
    *clock.mono.borrow_mut() = start_mono + total_elapsed;
    *clock.wall.borrow_mut() = next_target;
    let events = sched.tick(&clock);
    let fires: Vec<DateTime<Utc>> = events
        .iter()
        .filter_map(|e| match e {
            SchedulerEvent::Fire(id, at) if *id == binding_id => Some(*at),
            _ => None,
        })
        .collect();
    assert_eq!(
        fires,
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
    let start_mono = Instant::now();
    let clock = FakeClock {
        mono: RefCell::new(start_mono),
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

    // Advance past both fold instants, keeping monotonic and wall in
    // lockstep so no drift event muddies the assertion.
    let target = Utc.with_ymd_and_hms(2026, 11, 1, 7, 0, 0).unwrap();
    let elapsed = (target - start_wall).to_std().unwrap();
    *clock.mono.borrow_mut() = start_mono + elapsed;
    *clock.wall.borrow_mut() = target;

    let events = sched.tick(&clock);
    let mut fires: Vec<DateTime<Utc>> = events
        .iter()
        .filter_map(|e| match e {
            SchedulerEvent::Fire(id, at) if *id == binding_id => Some(*at),
            _ => None,
        })
        .collect();
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
    let start_mono = Instant::now();
    let clock = FakeClock {
        mono: RefCell::new(start_mono),
        wall: RefCell::new(start_wall),
    };

    let mut sched = Scheduler::new();
    let binding = Binding::new_cron(JobId::new(), "30 1 * * *".to_string(), tz);
    let binding_id = binding.id;
    sched.add_binding(binding, &clock).unwrap();

    let target = Utc.with_ymd_and_hms(2026, 11, 1, 7, 0, 0).unwrap();
    let elapsed = (target - start_wall).to_std().unwrap();
    *clock.mono.borrow_mut() = start_mono + elapsed;
    *clock.wall.borrow_mut() = target;

    let events = sched.tick(&clock);
    let fires: Vec<DateTime<Utc>> = events
        .iter()
        .filter_map(|e| match e {
            SchedulerEvent::Fire(id, at) if *id == binding_id => Some(*at),
            _ => None,
        })
        .collect();
    assert_eq!(
        fires,
        vec![Utc.with_ymd_and_hms(2026, 11, 1, 5, 30, 0).unwrap()],
        "DstAmbiguous::First must fire exactly once, at the earlier instant: {events:?}"
    );
}

fn fires_for(
    events: &[SchedulerEvent],
    binding_id: roundhouse_core::BindingId,
) -> Vec<DateTime<Utc>> {
    events
        .iter()
        .filter_map(|e| match e {
            SchedulerEvent::Fire(id, at) if *id == binding_id => Some(*at),
            _ => None,
        })
        .collect()
}

/// M5: `Scheduler::tick` previously never consulted `CatchUp` at all — every
/// missed occurrence fired regardless of the binding's policy. A binding
/// offline for several missed once-a-minute occurrences under
/// `CatchUp::None` must fire nothing, while still advancing its schedule
/// past the whole missed backlog (not re-considering it on the next tick).
#[test]
fn catch_up_none_is_actually_applied_by_tick_and_still_advances_the_schedule() {
    let start_wall = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let start_mono = Instant::now();
    let clock = FakeClock {
        mono: RefCell::new(start_mono),
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
    let elapsed = (target - start_wall).to_std().unwrap();
    *clock.mono.borrow_mut() = start_mono + elapsed;
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
    let total_elapsed = (next_target - start_wall).to_std().unwrap();
    *clock.mono.borrow_mut() = start_mono + total_elapsed;
    *clock.wall.borrow_mut() = next_target;
    let events2 = sched.tick(&clock);
    assert_eq!(fires_for(&events2, binding_id), vec![next_target]);
}

/// M5: `CatchUp::Latest` applied through `tick` for real — a 5-minute
/// backlog must fire exactly the most recent missed occurrence, not all 5.
#[test]
fn catch_up_latest_is_actually_applied_by_tick() {
    let start_wall = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let start_mono = Instant::now();
    let clock = FakeClock {
        mono: RefCell::new(start_mono),
        wall: RefCell::new(start_wall),
    };
    let mut sched = Scheduler::new();
    // `Binding::new_cron` already defaults to `CatchUp::Latest`.
    let binding = Binding::new_cron(JobId::new(), "* * * * *".to_string(), Tz::UTC);
    let binding_id = binding.id;
    sched.add_binding(binding, &clock).unwrap();

    let target = start_wall + chrono::Duration::minutes(5);
    let elapsed = (target - start_wall).to_std().unwrap();
    *clock.mono.borrow_mut() = start_mono + elapsed;
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
    let start_mono = Instant::now();
    let clock = FakeClock {
        mono: RefCell::new(start_mono),
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
    let elapsed = (target - start_wall).to_std().unwrap();
    *clock.mono.borrow_mut() = start_mono + elapsed;
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
    let start_mono = Instant::now();
    let clock = FakeClock {
        mono: RefCell::new(start_mono),
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
    let elapsed = (target - start_wall).to_std().unwrap();
    *clock.mono.borrow_mut() = start_mono + elapsed;
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

/// Task 6 (§8.7): `Scheduler::catch_up_after_wake` must drain a real
/// suspend-scale backlog through the same capped, progressive machinery as
/// `tick`'s ordinary catch-up path — not the drift-triggered
/// `recompute_all` path, which would silently discard it. Modeled as a
/// genuinely long sleep (a `* * * * *` cron offline for 10 days — 14,400
/// missed occurrences, two orders of magnitude past the per-call cap), with
/// the monotonic/wall asymmetry a real suspend produces: the monotonic
/// clock barely advances while the wall clock jumps by the full sleep
/// duration.
#[test]
fn catch_up_after_wake_drains_a_long_sleep_progressively_across_calls() {
    let start_wall = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let start_mono = Instant::now();
    let mut binding = Binding::new_cron(JobId::new(), "* * * * *".to_string(), Tz::UTC);
    if let TriggerSpec::Cron { catch_up, .. } = &mut binding.spec {
        *catch_up = CatchUp::All;
    }
    let binding_id = binding.id;

    let clock = FakeClock {
        mono: RefCell::new(start_mono),
        wall: RefCell::new(start_wall),
    };
    let mut sched = Scheduler::new();
    sched.add_binding(binding, &clock).unwrap();

    let cap = MAX_CATCH_UP_OCCURRENCES_PER_BINDING_PER_TICK;
    let total_missed = cap * 100 + 7; // a "daemon asleep for ~10 days" scale backlog
    let target_wall = start_wall + chrono::Duration::minutes(total_missed as i64);
    // The whole point: monotonic barely moves across a real suspend, unlike
    // an NTP-style correction where both clocks would move in step.
    let woke_mono = start_mono + Duration::from_millis(5);

    let first = sched.catch_up_after_wake(woke_mono, target_wall);
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
        let events = sched.tick(&clock_at(target_wall, woke_mono));
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
    // more, and must not report the already-handled sleep gap as fresh
    // drift (the wake call already reset the drift baseline).
    let last = sched.tick(&clock_at(target_wall, woke_mono));
    assert!(
        fires_for(&last, binding_id).is_empty(),
        "backlog is fully caught up; nothing more should fire: {last:?}"
    );
    assert!(
        !last
            .iter()
            .any(|e| matches!(e, SchedulerEvent::DriftDetected { .. })),
        "catch_up_after_wake must reset the drift baseline so the already-handled sleep gap \
         is not re-reported as drift by a later tick at the same clock reading: {last:?}"
    );
}

/// A held-constant clock (both readings equal to whatever
/// `catch_up_after_wake` last set as the baseline) used to drive further
/// `tick()` calls in the progressive-drain test above without introducing
/// any *additional* drift of its own — isolating "does the backlog drain"
/// from "does advancing the clock further also work" (already covered by
/// `catch_up_all_is_capped_per_tick_and_completes_progressively_across_calls`).
fn clock_at(wall: DateTime<Utc>, mono: Instant) -> FakeClock {
    FakeClock {
        mono: RefCell::new(mono),
        wall: RefCell::new(wall),
    }
}

/// Fold-in fix: an `Interval` binding with `every == Duration::ZERO` must be
/// rejected at registration time, not accepted and left to hang `tick`'s
/// catch-up gather loop on a never-advancing occurrence.
#[test]
fn adding_a_zero_duration_interval_binding_is_rejected_not_silently_accepted() {
    let clock = FakeClock {
        mono: RefCell::new(Instant::now()),
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
        mono: RefCell::new(Instant::now()),
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
        mono: RefCell::new(Instant::now()),
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
