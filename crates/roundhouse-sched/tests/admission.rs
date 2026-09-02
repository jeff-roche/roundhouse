//! Integration tests for the overlap-policy admission gate (Task 5).
//!
//! Deviation from the plan text's supplied test (see task-05-report.md
//! "Deviations from the plan text"): `roundhouse_sched::ids::BindingId`
//! does not exist — `BindingId` is a flat re-export of `roundhouse-core`
//! (Ruling P3/P6). `RunRegistry` also grew well beyond the plan's two
//! methods across the initial implementation and fix round 1 (see the
//! report's "Deviations" and "Fix round 1" sections), so `FakeRegistry`
//! here implements the full real trait rather than the plan's stub.
use roundhouse_core::BindingId;
use roundhouse_sched::admission::{
    decide_admission, AdmissionDecision, CancellationOutcome, RegistryError, RunRegistry,
    SharedRegistry,
};
use roundhouse_sched::trigger::OverlapPolicy;
use std::collections::HashMap;
use std::sync::{Arc, Barrier};
use std::thread;

#[derive(Default)]
struct FakeRegistry {
    active: HashMap<BindingId, u32>,
    queued: HashMap<BindingId, u32>,
}

impl RunRegistry for FakeRegistry {
    fn active_run_count(&self, binding_id: BindingId) -> Result<u32, RegistryError> {
        Ok(*self.active.get(&binding_id).unwrap_or(&0))
    }
    fn queued_count(&self, binding_id: BindingId) -> Result<u32, RegistryError> {
        Ok(*self.queued.get(&binding_id).unwrap_or(&0))
    }
    fn cancel_active(
        &mut self,
        binding_id: BindingId,
    ) -> Result<CancellationOutcome, RegistryError> {
        self.active.insert(binding_id, 0);
        Ok(CancellationOutcome::Confirmed)
    }
    fn note_admitted(&mut self, binding_id: BindingId) -> Result<(), RegistryError> {
        let slot = self.active.entry(binding_id).or_insert(0);
        *slot = slot
            .checked_add(1)
            .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
        Ok(())
    }
    fn note_queued(&mut self, binding_id: BindingId) -> Result<(), RegistryError> {
        let slot = self.queued.entry(binding_id).or_insert(0);
        *slot = slot
            .checked_add(1)
            .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
        Ok(())
    }
    fn note_finished(&mut self, binding_id: BindingId) -> Result<(), RegistryError> {
        let slot = self.active.entry(binding_id).or_insert(0);
        *slot = slot
            .checked_sub(1)
            .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
        Ok(())
    }
    fn note_dequeued(&mut self, binding_id: BindingId) -> Result<(), RegistryError> {
        let slot = self.queued.entry(binding_id).or_insert(0);
        *slot = slot
            .checked_sub(1)
            .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
        Ok(())
    }
}

fn with_active(binding_id: BindingId, count: u32) -> FakeRegistry {
    let mut registry = FakeRegistry::default();
    registry.active.insert(binding_id, count);
    registry
}

#[test]
fn skip_policy_skips_when_a_run_is_already_active() {
    let binding_id = BindingId::new();
    let mut registry = with_active(binding_id, 1);
    let decision = decide_admission(OverlapPolicy::Skip, &mut registry, binding_id).unwrap();
    assert_eq!(decision, AdmissionDecision::SkipDueToOverlap);
    // Skip never mutates the count it declined to add to.
    assert_eq!(registry.active_run_count(binding_id).unwrap(), 1);
}

#[test]
fn skip_policy_admits_when_nothing_is_active() {
    let binding_id = BindingId::new();
    let mut registry = FakeRegistry::default();
    let decision = decide_admission(OverlapPolicy::Skip, &mut registry, binding_id).unwrap();
    assert_eq!(decision, AdmissionDecision::Admit);
    assert_eq!(registry.active_run_count(binding_id).unwrap(), 1);
}

#[test]
fn cancel_previous_cancels_then_admits() {
    let binding_id = BindingId::new();
    let mut registry = with_active(binding_id, 1);
    let decision =
        decide_admission(OverlapPolicy::CancelPrevious, &mut registry, binding_id).unwrap();
    assert_eq!(decision, AdmissionDecision::CancelledPreviousAndAdmit);
    // Cancelled the old run, then counted the new one: net active count is
    // exactly 1, not 0 (forgot to admit) and not 2 (didn't really cancel).
    assert_eq!(registry.active_run_count(binding_id).unwrap(), 1);
}

#[test]
fn cancel_previous_admits_directly_when_nothing_was_active() {
    let binding_id = BindingId::new();
    let mut registry = FakeRegistry::default();
    let decision =
        decide_admission(OverlapPolicy::CancelPrevious, &mut registry, binding_id).unwrap();
    assert_eq!(decision, AdmissionDecision::CancelledPreviousAndAdmit);
    assert_eq!(registry.active_run_count(binding_id).unwrap(), 1);
}

/// D (fix round 1): an unconfirmed cancellation must not admit a
/// replacement on top of a predecessor that might still be alive.
#[test]
fn cancel_previous_fails_closed_when_cancellation_is_unconfirmed() {
    struct UnconfirmedCancelRegistry {
        active: HashMap<BindingId, u32>,
    }
    impl RunRegistry for UnconfirmedCancelRegistry {
        fn active_run_count(&self, binding_id: BindingId) -> Result<u32, RegistryError> {
            Ok(*self.active.get(&binding_id).unwrap_or(&0))
        }
        fn queued_count(&self, _binding_id: BindingId) -> Result<u32, RegistryError> {
            Ok(0)
        }
        fn cancel_active(
            &mut self,
            _binding_id: BindingId,
        ) -> Result<CancellationOutcome, RegistryError> {
            Ok(CancellationOutcome::Unconfirmed)
        }
        fn note_admitted(&mut self, binding_id: BindingId) -> Result<(), RegistryError> {
            *self.active.entry(binding_id).or_insert(0) += 1;
            Ok(())
        }
        fn note_queued(&mut self, _binding_id: BindingId) -> Result<(), RegistryError> {
            Ok(())
        }
        fn note_finished(&mut self, binding_id: BindingId) -> Result<(), RegistryError> {
            *self.active.entry(binding_id).or_insert(0) = 0;
            Ok(())
        }
        fn note_dequeued(&mut self, _binding_id: BindingId) -> Result<(), RegistryError> {
            Ok(())
        }
    }

    let binding_id = BindingId::new();
    let mut registry = UnconfirmedCancelRegistry {
        active: HashMap::from([(binding_id, 1)]),
    };
    let decision =
        decide_admission(OverlapPolicy::CancelPrevious, &mut registry, binding_id).unwrap();
    assert_eq!(decision, AdmissionDecision::SkippedCancellationUnconfirmed);
    assert_eq!(registry.active_run_count(binding_id).unwrap(), 1);
}

#[test]
fn concurrent_policy_admits_below_max_and_skips_at_max() {
    let binding_id = BindingId::new();
    let mut registry = with_active(binding_id, 1);
    let policy = OverlapPolicy::Concurrent { max: 2 };

    assert_eq!(
        decide_admission(policy, &mut registry, binding_id).unwrap(),
        AdmissionDecision::Admit
    );
    assert_eq!(registry.active_run_count(binding_id).unwrap(), 2);
    assert_eq!(
        decide_admission(policy, &mut registry, binding_id).unwrap(),
        AdmissionDecision::SkipDueToOverlap
    );
}

#[test]
fn queue_policy_queues_behind_an_active_run_up_to_depth() {
    let binding_id = BindingId::new();
    let mut registry = with_active(binding_id, 1);
    let policy = OverlapPolicy::Queue { depth: 1 };

    assert_eq!(
        decide_admission(policy, &mut registry, binding_id).unwrap(),
        AdmissionDecision::QueueAt(0)
    );
    // Queue is now full at depth 1: backpressure, not unbounded growth,
    // and distinguishable from a routine `SkipDueToOverlap`.
    assert_eq!(
        decide_admission(policy, &mut registry, binding_id).unwrap(),
        AdmissionDecision::SkippedQueueFull { depth: 1 }
    );
    assert_eq!(registry.queued_count(binding_id).unwrap(), 1);
}

#[test]
fn queue_policy_admits_immediately_when_nothing_is_active() {
    let binding_id = BindingId::new();
    let mut registry = FakeRegistry::default();
    let decision =
        decide_admission(OverlapPolicy::Queue { depth: 8 }, &mut registry, binding_id).unwrap();
    assert_eq!(decision, AdmissionDecision::Admit);
    assert_eq!(registry.active_run_count(binding_id).unwrap(), 1);
    assert_eq!(registry.queued_count(binding_id).unwrap(), 0);
}

/// E (fix round 1): once anything is queued, a later arrival must queue
/// behind it too, even if `active_run_count` has since dropped to 0 —
/// otherwise a fresh arrival jumps the whole backlog (LIFO instead of
/// FIFO) and older queued occurrences can starve indefinitely under a
/// sustained stream.
#[test]
fn queue_policy_does_not_let_a_new_arrival_jump_an_existing_backlog() {
    let binding_id = BindingId::new();
    let mut registry = with_active(binding_id, 1);
    let policy = OverlapPolicy::Queue { depth: 8 };

    // Occurrence 2 arrives while occurrence 1 is running: queues at 0.
    assert_eq!(
        decide_admission(policy, &mut registry, binding_id).unwrap(),
        AdmissionDecision::QueueAt(0)
    );
    // Occurrence 1 finishes, but the flow layer hasn't yet promoted
    // occurrence 2 out of the queue (that promotion is `roundhouse-flow`'s
    // job, driven by `note_dequeued`, not this gate's).
    registry.note_finished(binding_id).unwrap();
    assert_eq!(registry.active_run_count(binding_id).unwrap(), 0);

    // Occurrence 3 now arrives. `active_run_count == 0`, but occurrence 2
    // is still waiting — occurrence 3 must queue behind it, not jump ahead.
    assert_eq!(
        decide_admission(policy, &mut registry, binding_id).unwrap(),
        AdmissionDecision::QueueAt(1)
    );
}

/// Availability-control regression: a single scheduler tick can hand this
/// gate up to `MAX_CATCH_UP_OCCURRENCES_PER_BINDING_PER_TICK` (100) `Fire`
/// events for one binding (see `scheduler.rs`'s catch-up gather loop). Feed
/// exactly that many admission calls through in sequence, as the real
/// caller would when draining one tick's event `Vec`, and confirm the
/// `Skip` policy still only ever lets one run through.
#[test]
fn skip_policy_holds_under_a_full_catch_up_burst() {
    let binding_id = BindingId::new();
    let mut registry = FakeRegistry::default();
    let policy = OverlapPolicy::Skip;

    let mut admitted = 0;
    for _ in 0..100 {
        if decide_admission(policy, &mut registry, binding_id).unwrap() == AdmissionDecision::Admit
        {
            admitted += 1;
        }
    }
    assert_eq!(admitted, 1);
    assert_eq!(registry.active_run_count(binding_id).unwrap(), 1);
}

#[test]
fn concurrent_policy_holds_under_a_full_catch_up_burst() {
    let binding_id = BindingId::new();
    let mut registry = FakeRegistry::default();
    let policy = OverlapPolicy::Concurrent { max: 5 };

    let mut admitted = 0;
    for _ in 0..100 {
        if decide_admission(policy, &mut registry, binding_id).unwrap() == AdmissionDecision::Admit
        {
            admitted += 1;
        }
    }
    assert_eq!(admitted, 5);
    assert_eq!(registry.active_run_count(binding_id).unwrap(), 5);
}

#[test]
fn queue_policy_bounds_backlog_under_a_full_catch_up_burst() {
    let binding_id = BindingId::new();
    let mut registry = FakeRegistry::default();
    let policy = OverlapPolicy::Queue { depth: 8 };

    let mut dropped = 0;
    for _ in 0..100 {
        if matches!(
            decide_admission(policy, &mut registry, binding_id).unwrap(),
            AdmissionDecision::SkippedQueueFull { .. }
        ) {
            dropped += 1;
        }
    }
    // 1 admitted immediately + 8 queued + the rest (91) dropped as backpressure.
    assert_eq!(dropped, 91);
    assert_eq!(registry.active_run_count(binding_id).unwrap(), 1);
    assert_eq!(registry.queued_count(binding_id).unwrap(), 8);
}

/// B (fix round 1): a registry that cannot complete a read must deny, not
/// silently default to "nothing active" and admit — a degraded registry
/// (pool exhaustion, `SQLITE_BUSY`) is exactly the condition this gate
/// exists to stay safe under.
#[test]
fn an_unreadable_registry_denies_every_policy() {
    struct AlwaysFailingRegistry;
    impl RunRegistry for AlwaysFailingRegistry {
        fn active_run_count(&self, binding_id: BindingId) -> Result<u32, RegistryError> {
            Err(RegistryError::ReadFailed { binding_id })
        }
        fn queued_count(&self, binding_id: BindingId) -> Result<u32, RegistryError> {
            Err(RegistryError::ReadFailed { binding_id })
        }
        fn cancel_active(
            &mut self,
            binding_id: BindingId,
        ) -> Result<CancellationOutcome, RegistryError> {
            Err(RegistryError::ReadFailed { binding_id })
        }
        fn note_admitted(&mut self, binding_id: BindingId) -> Result<(), RegistryError> {
            Err(RegistryError::ReadFailed { binding_id })
        }
        fn note_queued(&mut self, binding_id: BindingId) -> Result<(), RegistryError> {
            Err(RegistryError::ReadFailed { binding_id })
        }
        fn note_finished(&mut self, binding_id: BindingId) -> Result<(), RegistryError> {
            Err(RegistryError::ReadFailed { binding_id })
        }
        fn note_dequeued(&mut self, binding_id: BindingId) -> Result<(), RegistryError> {
            Err(RegistryError::ReadFailed { binding_id })
        }
    }

    let binding_id = BindingId::new();
    let mut registry = AlwaysFailingRegistry;
    for policy in [
        OverlapPolicy::Skip,
        OverlapPolicy::Concurrent { max: 5 },
        OverlapPolicy::Queue { depth: 5 },
        OverlapPolicy::CancelPrevious,
    ] {
        assert!(decide_admission(policy, &mut registry, binding_id).is_err());
    }
}

/// F (fix round 1): `Concurrent{max}`/`Queue{depth}` must not be
/// effectively unbounded just because nothing upstream validates the
/// policy value.
#[test]
fn queue_depth_is_clamped_to_the_sanity_ceiling() {
    let binding_id = BindingId::new();
    let mut registry = with_active(binding_id, 1);
    let policy = OverlapPolicy::Queue { depth: u32::MAX };

    for i in 0..roundhouse_sched::admission::MAX_OVERLAP_QUEUE_DEPTH {
        assert_eq!(
            decide_admission(policy, &mut registry, binding_id).unwrap(),
            AdmissionDecision::QueueAt(i)
        );
    }
    assert!(matches!(
        decide_admission(policy, &mut registry, binding_id).unwrap(),
        AdmissionDecision::SkippedQueueFull { .. }
    ));
}

/// A (fix round 1): the property the crate previously — wrongly — claimed
/// was true "by construction". `SharedRegistry` is what actually makes it
/// true: many threads race `decide_admission` for the *same* `Skip`
/// binding through one shared registry, and exactly one must be admitted,
/// however much real concurrency the OS scheduler gives them.
#[test]
fn shared_registry_serializes_concurrent_admission_for_one_binding() {
    let binding_id = BindingId::new();
    let shared = Arc::new(SharedRegistry::new(FakeRegistry::default()));
    const THREADS: usize = 64;
    let barrier = Arc::new(Barrier::new(THREADS));

    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let shared = Arc::clone(&shared);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                // Line every thread up so as many as possible genuinely
                // race `decide` at the same instant, rather than mostly
                // running one-at-a-time by scheduling luck.
                barrier.wait();
                shared.decide(OverlapPolicy::Skip, binding_id)
            })
        })
        .collect();

    let mut admitted = 0;
    for handle in handles {
        if handle.join().unwrap().unwrap() == AdmissionDecision::Admit {
            admitted += 1;
        }
    }

    assert_eq!(
        admitted, 1,
        "exactly one of {THREADS} racing threads must be admitted for a Skip binding"
    );
    assert_eq!(
        shared.decide(OverlapPolicy::Skip, binding_id).unwrap(),
        AdmissionDecision::SkipDueToOverlap
    );
}
