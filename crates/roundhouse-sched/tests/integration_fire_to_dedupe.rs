//! Phase 5, Subsystem A, Task 7: the end-to-end scheduling integration test.
//!
//! Exercises the whole subsystem's public surface together — the real
//! `Scheduler` heap firing a real cron `Binding` (Tasks 1-3), the
//! overlap-policy admission gate (Task 5), and `trigger_event`
//! persistence/dedupe (Task 4) — to prove the phase exit criterion this
//! subsystem exists for: **exactly one run per scheduled occurrence, even
//! under crash-and-retry.**
//!
//! Deliberately stronger than a version that only calls `decide_admission`
//! and `record_trigger_event` once each with a hand-built `TriggerEvent`:
//! that would pass without ever exercising `Scheduler::tick` at all, and
//! without ever showing that admission's in-memory state is *not* what
//! prevents a double run — the persisted dedupe is. See the two-phase
//! structure below.
use chrono::{TimeZone, Utc};
use chrono_tz::Tz;
use roundhouse_core::{BindingId, JobId};
use roundhouse_sched::admission::{
    decide_admission, AdmissionDecision, CancellationOutcome, RegistryError, RunRegistry,
};
use roundhouse_sched::scheduler::{ClockSource, Scheduler, SchedulerEvent};
use roundhouse_sched::store::{occurrence_key, open_test_db, record_trigger_event};
use roundhouse_sched::trigger::{Binding, TriggerEvent};
use std::cell::RefCell;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::Instant;

/// A fake clock whose monotonic and wall clocks are advanced together (no
/// drift), so a cron binding's next occurrence fires deterministically
/// instead of the test waiting on real wall-clock time. Mirrors
/// `tests/scheduler.rs`'s own `FakeClock`.
struct FakeClock {
    mono: RefCell<Instant>,
    wall: RefCell<chrono::DateTime<Utc>>,
}

impl ClockSource for FakeClock {
    fn monotonic_now(&self) -> Instant {
        *self.mono.borrow()
    }
    fn wall_now(&self) -> chrono::DateTime<Utc> {
        *self.wall.borrow()
    }
}

/// An in-memory `RunRegistry`, fresh for every instance — standing in for
/// whatever admission-tracking state a real daemon process holds. Used
/// twice below with two *separate* instances, precisely to model that a
/// crashed-and-restarted daemon's in-memory admission bookkeeping is gone;
/// only what made it to the durable `trigger_event` table survives.
#[derive(Default)]
struct FakeRegistry {
    active: RefCell<HashMap<BindingId, u32>>,
    queued: RefCell<HashMap<BindingId, u32>>,
}

impl RunRegistry for FakeRegistry {
    fn active_run_count(&self, binding_id: BindingId) -> Result<u32, RegistryError> {
        Ok(*self.active.borrow().get(&binding_id).unwrap_or(&0))
    }
    fn queued_count(&self, binding_id: BindingId) -> Result<u32, RegistryError> {
        Ok(*self.queued.borrow().get(&binding_id).unwrap_or(&0))
    }
    fn cancel_active(&self, binding_id: BindingId) -> Result<CancellationOutcome, RegistryError> {
        self.active.borrow_mut().insert(binding_id, 0);
        Ok(CancellationOutcome::Confirmed)
    }
    fn note_admitted(&self, binding_id: BindingId) -> Result<(), RegistryError> {
        let mut active = self.active.borrow_mut();
        let slot = active.entry(binding_id).or_insert(0);
        *slot = slot
            .checked_add(1)
            .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
        Ok(())
    }
    fn note_queued(&self, binding_id: BindingId) -> Result<(), RegistryError> {
        let mut queued = self.queued.borrow_mut();
        let slot = queued.entry(binding_id).or_insert(0);
        *slot = slot
            .checked_add(1)
            .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
        Ok(())
    }
    fn note_finished(&self, binding_id: BindingId) -> Result<(), RegistryError> {
        let mut active = self.active.borrow_mut();
        let slot = active.entry(binding_id).or_insert(0);
        *slot = slot
            .checked_sub(1)
            .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
        Ok(())
    }
    fn note_dequeued(&self, binding_id: BindingId) -> Result<(), RegistryError> {
        let mut queued = self.queued.borrow_mut();
        let slot = queued.entry(binding_id).or_insert(0);
        *slot = slot
            .checked_sub(1)
            .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
        Ok(())
    }
    fn note_promoted(&self, binding_id: BindingId) -> Result<(), RegistryError> {
        {
            let mut queued = self.queued.borrow_mut();
            let slot = queued.entry(binding_id).or_insert(0);
            *slot = slot
                .checked_sub(1)
                .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
        }
        {
            let mut active = self.active.borrow_mut();
            let slot = active.entry(binding_id).or_insert(0);
            *slot = slot
                .checked_add(1)
                .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
        }
        Ok(())
    }
}

#[test]
fn a_fired_binding_that_admits_and_then_repeats_its_idempotency_key_is_not_double_run() {
    // --- Phase 0: get a real Fire event out of the real scheduler heap. ---
    // Hand-building a `TriggerEvent` with a made-up timestamp would never
    // prove the scheduler, cron next-fire computation, and dedupe actually
    // agree on what "the same occurrence" means — driving a real `tick()`
    // does.
    let start_wall = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let start_mono = Instant::now();
    let clock = FakeClock {
        mono: RefCell::new(start_mono),
        wall: RefCell::new(start_wall),
    };

    let mut sched = Scheduler::new();
    let binding = Binding::new_cron(JobId::new(), "* * * * *".to_string(), Tz::UTC);
    let binding_id = binding.id;
    let overlap = binding.overlap;
    sched.add_binding(binding, &clock).unwrap();

    // Advance both clocks together by the same amount (no drift) past the
    // next minute boundary, so the cron binding is genuinely due.
    *clock.mono.borrow_mut() = start_mono + Duration::from_secs(61);
    *clock.wall.borrow_mut() = start_wall + chrono::Duration::seconds(61);

    let events = sched.tick(&clock);
    let scheduled_for = events
        .iter()
        .find_map(|event| match event {
            SchedulerEvent::Fire(id, at) if *id == binding_id => Some(*at),
            _ => None,
        })
        .expect("a `* * * * *` cron binding due 61s after registration must fire");

    // --- Phase 1: the occurrence's first (successful) run. ---
    let registry = FakeRegistry::default();
    let decision = decide_admission(overlap, &registry, binding_id).unwrap();
    assert_eq!(decision, AdmissionDecision::Admit);

    let mut conn = open_test_db();
    let fired_at = Utc::now();
    let ev = TriggerEvent {
        binding_id,
        // Using the crate's own canonical derivation, not a hand-rolled
        // key — this is exactly what a real caller must do to get real
        // dedupe (see `occurrence_key`'s own doc comment on why a
        // `fired_at`-derived key would defeat the whole point).
        idempotency_key: occurrence_key(binding_id, scheduled_for),
        scheduled_for,
        fired_at,
        is_catch_up: false,
        session_id: None,
    };
    assert!(
        record_trigger_event(&mut conn, &ev).unwrap(),
        "the occurrence's first fire must be recorded as new"
    );

    // --- Phase 2: crash-and-retry of the *same* scheduled occurrence. ---
    // Model the crash by starting from a brand-new, empty `RunRegistry`
    // rather than reusing the one above: a real daemon's in-memory
    // admission bookkeeping does not survive a process crash, so a retry
    // after restart sees exactly this — a registry with no memory of the
    // run that was already admitted. If admission alone gated correctness,
    // this second call would incorrectly kick off a second run of the same
    // occurrence.
    let retry_registry = FakeRegistry::default();
    let retry_decision = decide_admission(overlap, &retry_registry, binding_id).unwrap();
    assert_eq!(
        retry_decision,
        AdmissionDecision::Admit,
        "a fresh post-crash registry has no memory of the earlier run and admits again — \
         this is exactly why admission alone cannot be the exactly-once guarantee"
    );

    // The retry reconstructs the same occurrence (same binding, same
    // `scheduled_for`) but at a later wall-clock moment — proving the
    // dedupe key is derived from `scheduled_for`, the occurrence's own
    // identity, not from `fired_at`/`Utc::now()`, which would differ on
    // every retry and defeat the `trigger_event_dedupe` UNIQUE index in
    // exactly the case it exists to catch.
    let retry_ev = TriggerEvent {
        binding_id,
        idempotency_key: occurrence_key(binding_id, scheduled_for),
        scheduled_for,
        fired_at: fired_at + chrono::Duration::seconds(5),
        is_catch_up: false,
        session_id: None,
    };
    assert!(
        !record_trigger_event(&mut conn, &retry_ev).unwrap(),
        "a retry of the same scheduled occurrence must be deduped at the store layer, even \
         though the (post-crash, memory-less) admission gate said Admit — this is the actual \
         exactly-once backstop"
    );
}
