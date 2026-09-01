use chrono::{DateTime, TimeZone, Utc};
use chrono_tz::Tz;
use roundhouse_core::JobId;
use roundhouse_sched::scheduler::{ClockSource, Scheduler, SchedulerEvent};
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
