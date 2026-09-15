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
use roundhouse_core::{BindingId, JobId, WorkspaceId};
use roundhouse_sched::admission::{
    decide_admission, AdmissionDecision, CancellationOutcome, RegistryError, RunRegistry,
};
use roundhouse_sched::delivery::DeliveryState;
use roundhouse_sched::scheduler::{ClockSource, ScheduledOccurrence, Scheduler, SchedulerEvent};
use roundhouse_sched::store::{
    accept_occurrence, occurrence_key, open_test_db, record_trigger_event, Acceptance,
};
use roundhouse_sched::trigger::{Binding, StoredBinding, TriggerEvent};
use std::cell::RefCell;
use std::collections::HashMap;

/// A fake wall clock, advanced directly, so a cron binding's next occurrence
/// fires deterministically instead of the test waiting on real wall-clock
/// time. Mirrors `tests/scheduler.rs`'s own `FakeClock`.
struct FakeClock {
    wall: RefCell<chrono::DateTime<Utc>>,
}

impl ClockSource for FakeClock {
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
    let clock = FakeClock {
        wall: RefCell::new(start_wall),
    };

    let mut sched = Scheduler::new();
    let binding = Binding::new_cron(JobId::new(), "* * * * *".to_string(), Tz::UTC);
    let binding_id = binding.id;
    let overlap = binding.overlap;
    sched.add_binding(binding, &clock).unwrap();

    // Advance the wall clock past the next minute boundary, so the cron
    // binding is genuinely due.
    *clock.wall.borrow_mut() = start_wall + chrono::Duration::seconds(61);

    let events = sched.tick(&clock);
    let scheduled_for = events
        .iter()
        .find_map(|event| match event {
            SchedulerEvent::Fire(ScheduledOccurrence {
                binding_id: id,
                scheduled_for,
                ..
            }) if *id == binding_id => Some(*scheduled_for),
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
        outcome: None,
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
        outcome: None,
    };
    assert!(
        !record_trigger_event(&mut conn, &retry_ev).unwrap(),
        "a retry of the same scheduled occurrence must be deduped at the store layer, even \
         though the (post-crash, memory-less) admission gate said Admit — this is the actual \
         exactly-once backstop"
    );
}

/// The test above predates Task 3's atomic `accept_occurrence` — it drives
/// `decide_admission` and `record_trigger_event` as two separate steps,
/// which is how the pipeline worked *before* that task existed. Every real
/// production caller (`scheduler_driver.rs`'s heartbeat, via
/// `accept_due_occurrences`) calls `accept_occurrence` itself, never the two
/// split calls, so this test exercises the CURRENT real pipeline: a real
/// `Scheduler::tick` firing a real cron `Binding`, then a single
/// `accept_occurrence` call turning that occurrence into a durable `Ready`
/// `trigger_delivery` row, and a retry of the identical occurrence — through
/// a fresh, memory-less `RunRegistry`, exactly modelling a post-crash
/// restart — reusing that same durable row rather than fabricating a second
/// one.
///
/// This does not replace the coverage above: `decide_admission` and
/// `record_trigger_event` are still real functions `accept_occurrence` calls
/// internally, so both tests keep exercising real production code, just at
/// different call boundaries.
#[test]
fn accept_occurrence_creates_one_ready_delivery_and_a_retry_reuses_it_rather_than_duplicating() {
    // --- Phase 0: a real Fire event out of the real scheduler heap. ---
    let start_wall = Utc.with_ymd_and_hms(2026, 3, 1, 0, 0, 0).unwrap();
    let clock = FakeClock {
        wall: RefCell::new(start_wall),
    };

    let mut sched = Scheduler::new();
    let binding = Binding::new_cron(JobId::new(), "* * * * *".to_string(), Tz::UTC);
    let binding_id = binding.id;
    let stored = StoredBinding {
        workspace: WorkspaceId::new(),
        binding,
    };
    sched.add_binding(stored.binding.clone(), &clock).unwrap();

    *clock.wall.borrow_mut() = start_wall + chrono::Duration::seconds(61);
    let events = sched.tick(&clock);
    let occurrence = events
        .into_iter()
        .find_map(|event| {
            let SchedulerEvent::Fire(occurrence) = event;
            (occurrence.binding_id == binding_id).then_some(occurrence)
        })
        .expect("a `* * * * *` cron binding due 61s after registration must fire");

    let mut conn = open_test_db();
    let fired_at = Utc::now();

    // --- Phase 1: first acceptance of a genuinely new occurrence. ---
    let registry = FakeRegistry::default();
    let first_delivery =
        match accept_occurrence(&mut conn, &stored, &occurrence, fired_at, &registry).unwrap() {
            Acceptance::New {
                delivery: Some(delivery),
                decision,
                ..
            } => {
                assert_eq!(
                    decision,
                    AdmissionDecision::Admit,
                    "an empty registry must admit this binding's first occurrence"
                );
                delivery
            }
            other => panic!(
                "the first acceptance of a fresh occurrence must create a Ready delivery, got \
             {other:?}"
            ),
        };
    assert_eq!(
        first_delivery.state,
        DeliveryState::Ready,
        "an admitted occurrence's delivery must start Ready on first acceptance"
    );

    // --- Phase 2: crash-and-retry of the SAME occurrence. --- A fresh,
    // empty `RunRegistry` models a restarted daemon's memory-less admission
    // bookkeeping — the same reasoning the split-call test above already
    // established. `accept_occurrence` must not call `decide_admission`
    // again for a duplicate occurrence: it must reuse the durable row.
    let retry_registry = FakeRegistry::default();
    let retry_fired_at = fired_at + chrono::Duration::seconds(5);
    match accept_occurrence(
        &mut conn,
        &stored,
        &occurrence,
        retry_fired_at,
        &retry_registry,
    )
    .unwrap()
    {
        Acceptance::Duplicate {
            delivery: Some(delivery),
            ..
        } => {
            assert_eq!(
                delivery.delivery_id, first_delivery.delivery_id,
                "a retry of the same occurrence must reuse the existing durable delivery, not \
                 fabricate a second row"
            );
        }
        other => panic!(
            "a retry of the same occurrence must report Duplicate, reusing the existing \
             delivery, got {other:?}"
        ),
    }

    // Belt-and-suspenders: exactly one row for this binding exists, however
    // `Acceptance` reports it.
    let delivery_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM trigger_delivery WHERE binding_id = ?1",
            rusqlite::params![binding_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        delivery_count, 1,
        "a duplicated occurrence must never leave a second trigger_delivery row behind"
    );
}
