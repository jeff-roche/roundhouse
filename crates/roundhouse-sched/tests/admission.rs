//! Integration tests for the overlap-policy admission gate (Task 5).
//!
//! Deviation from the plan text's supplied test (see task-05-report.md
//! "Deviations from the plan text"): `roundhouse_sched::ids::BindingId`
//! does not exist — `BindingId` is a flat re-export of `roundhouse-core`
//! (Ruling P3/P6). `RunRegistry` also grew well beyond the plan's two
//! methods across the initial implementation and two fix rounds (see the
//! report's "Deviations"/"Fix round 1"/"Fix round 2" sections), so
//! `FakeRegistry` here implements the full real trait rather than the
//! plan's stub.
use roundhouse_core::BindingId;
use roundhouse_sched::admission::{
    decide_admission, AdmissionDecision, CancellationOutcome, RegistryError, RunRegistry,
    SharedRegistry,
};
use roundhouse_sched::trigger::OverlapPolicy;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Default)]
struct FakeRegistry {
    active: Mutex<HashMap<BindingId, u32>>,
    queued: Mutex<HashMap<BindingId, u32>>,
}

impl FakeRegistry {
    fn with_active(binding_id: BindingId, count: u32) -> Self {
        let registry = FakeRegistry::default();
        registry.active.lock().unwrap().insert(binding_id, count);
        registry
    }
}

impl RunRegistry for FakeRegistry {
    fn active_run_count(&self, binding_id: BindingId) -> Result<u32, RegistryError> {
        Ok(*self.active.lock().unwrap().get(&binding_id).unwrap_or(&0))
    }
    fn queued_count(&self, binding_id: BindingId) -> Result<u32, RegistryError> {
        Ok(*self.queued.lock().unwrap().get(&binding_id).unwrap_or(&0))
    }
    fn cancel_active(&self, binding_id: BindingId) -> Result<CancellationOutcome, RegistryError> {
        self.active.lock().unwrap().insert(binding_id, 0);
        Ok(CancellationOutcome::Confirmed)
    }
    fn note_admitted(&self, binding_id: BindingId) -> Result<(), RegistryError> {
        let mut active = self.active.lock().unwrap();
        let slot = active.entry(binding_id).or_insert(0);
        *slot = slot
            .checked_add(1)
            .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
        Ok(())
    }
    fn note_queued(&self, binding_id: BindingId) -> Result<(), RegistryError> {
        let mut queued = self.queued.lock().unwrap();
        let slot = queued.entry(binding_id).or_insert(0);
        *slot = slot
            .checked_add(1)
            .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
        Ok(())
    }
    fn note_finished(&self, binding_id: BindingId) -> Result<(), RegistryError> {
        let mut active = self.active.lock().unwrap();
        let slot = active.entry(binding_id).or_insert(0);
        *slot = slot
            .checked_sub(1)
            .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
        Ok(())
    }
    fn note_dequeued(&self, binding_id: BindingId) -> Result<(), RegistryError> {
        let mut queued = self.queued.lock().unwrap();
        let slot = queued.entry(binding_id).or_insert(0);
        *slot = slot
            .checked_sub(1)
            .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
        Ok(())
    }
    fn note_promoted(&self, binding_id: BindingId) -> Result<(), RegistryError> {
        {
            let mut queued = self.queued.lock().unwrap();
            let slot = queued.entry(binding_id).or_insert(0);
            *slot = slot
                .checked_sub(1)
                .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
        }
        {
            let mut active = self.active.lock().unwrap();
            let slot = active.entry(binding_id).or_insert(0);
            *slot = slot
                .checked_add(1)
                .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
        }
        Ok(())
    }
}

#[test]
fn skip_policy_skips_when_a_run_is_already_active() {
    let binding_id = BindingId::new();
    let registry = FakeRegistry::with_active(binding_id, 1);
    let decision = decide_admission(OverlapPolicy::Skip, &registry, binding_id).unwrap();
    assert_eq!(decision, AdmissionDecision::SkipDueToOverlap);
    // Skip never mutates the count it declined to add to.
    assert_eq!(registry.active_run_count(binding_id).unwrap(), 1);
}

#[test]
fn skip_policy_admits_when_nothing_is_active() {
    let binding_id = BindingId::new();
    let registry = FakeRegistry::default();
    let decision = decide_admission(OverlapPolicy::Skip, &registry, binding_id).unwrap();
    assert_eq!(decision, AdmissionDecision::Admit);
    assert_eq!(registry.active_run_count(binding_id).unwrap(), 1);
}

#[test]
fn cancel_previous_cancels_then_admits() {
    let binding_id = BindingId::new();
    let registry = FakeRegistry::with_active(binding_id, 1);
    let decision = decide_admission(OverlapPolicy::CancelPrevious, &registry, binding_id).unwrap();
    assert_eq!(decision, AdmissionDecision::CancelledPreviousAndAdmit);
    // Cancelled the old run, then counted the new one: net active count is
    // exactly 1, not 0 (forgot to admit) and not 2 (didn't really cancel).
    assert_eq!(registry.active_run_count(binding_id).unwrap(), 1);
}

#[test]
fn cancel_previous_admits_directly_when_nothing_was_active() {
    let binding_id = BindingId::new();
    let registry = FakeRegistry::default();
    let decision = decide_admission(OverlapPolicy::CancelPrevious, &registry, binding_id).unwrap();
    assert_eq!(decision, AdmissionDecision::CancelledPreviousAndAdmit);
    assert_eq!(registry.active_run_count(binding_id).unwrap(), 1);
}

/// D (fix round 1): an unconfirmed cancellation must not admit a
/// replacement on top of a predecessor that might still be alive.
#[test]
fn cancel_previous_fails_closed_when_cancellation_is_unconfirmed() {
    struct UnconfirmedCancelRegistry {
        active: Mutex<HashMap<BindingId, u32>>,
    }
    impl RunRegistry for UnconfirmedCancelRegistry {
        fn active_run_count(&self, binding_id: BindingId) -> Result<u32, RegistryError> {
            Ok(*self.active.lock().unwrap().get(&binding_id).unwrap_or(&0))
        }
        fn queued_count(&self, _binding_id: BindingId) -> Result<u32, RegistryError> {
            Ok(0)
        }
        fn cancel_active(
            &self,
            _binding_id: BindingId,
        ) -> Result<CancellationOutcome, RegistryError> {
            Ok(CancellationOutcome::Unconfirmed)
        }
        fn note_admitted(&self, binding_id: BindingId) -> Result<(), RegistryError> {
            *self.active.lock().unwrap().entry(binding_id).or_insert(0) += 1;
            Ok(())
        }
        fn note_queued(&self, _binding_id: BindingId) -> Result<(), RegistryError> {
            Ok(())
        }
        fn note_finished(&self, binding_id: BindingId) -> Result<(), RegistryError> {
            *self.active.lock().unwrap().entry(binding_id).or_insert(0) = 0;
            Ok(())
        }
        fn note_dequeued(&self, _binding_id: BindingId) -> Result<(), RegistryError> {
            Ok(())
        }
        fn note_promoted(&self, _binding_id: BindingId) -> Result<(), RegistryError> {
            Ok(())
        }
    }

    let binding_id = BindingId::new();
    let registry = UnconfirmedCancelRegistry {
        active: Mutex::new(HashMap::from([(binding_id, 1)])),
    };
    let decision = decide_admission(OverlapPolicy::CancelPrevious, &registry, binding_id).unwrap();
    assert_eq!(decision, AdmissionDecision::SkippedCancellationUnconfirmed);
    assert_eq!(registry.active_run_count(binding_id).unwrap(), 1);
}

#[test]
fn concurrent_policy_admits_below_max_and_skips_at_max() {
    let binding_id = BindingId::new();
    let registry = FakeRegistry::with_active(binding_id, 1);
    let policy = OverlapPolicy::Concurrent { max: 2 };

    assert_eq!(
        decide_admission(policy, &registry, binding_id).unwrap(),
        AdmissionDecision::Admit
    );
    assert_eq!(registry.active_run_count(binding_id).unwrap(), 2);
    assert_eq!(
        decide_admission(policy, &registry, binding_id).unwrap(),
        AdmissionDecision::SkipDueToOverlap
    );
}

#[test]
fn queue_policy_queues_behind_an_active_run_up_to_depth() {
    let binding_id = BindingId::new();
    let registry = FakeRegistry::with_active(binding_id, 1);
    let policy = OverlapPolicy::Queue { depth: 1 };

    assert_eq!(
        decide_admission(policy, &registry, binding_id).unwrap(),
        AdmissionDecision::QueueAt(0)
    );
    // Queue is now full at depth 1: backpressure, not unbounded growth,
    // and distinguishable from a routine `SkipDueToOverlap`.
    assert_eq!(
        decide_admission(policy, &registry, binding_id).unwrap(),
        AdmissionDecision::SkippedQueueFull { depth: 1 }
    );
    assert_eq!(registry.queued_count(binding_id).unwrap(), 1);
}

#[test]
fn queue_policy_admits_immediately_when_nothing_is_active() {
    let binding_id = BindingId::new();
    let registry = FakeRegistry::default();
    let decision =
        decide_admission(OverlapPolicy::Queue { depth: 8 }, &registry, binding_id).unwrap();
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
    let registry = FakeRegistry::with_active(binding_id, 1);
    let policy = OverlapPolicy::Queue { depth: 8 };

    // Occurrence 2 arrives while occurrence 1 is running: queues at 0.
    assert_eq!(
        decide_admission(policy, &registry, binding_id).unwrap(),
        AdmissionDecision::QueueAt(0)
    );
    // Occurrence 1 finishes, but the flow layer hasn't yet promoted
    // occurrence 2 out of the queue (that promotion is `roundhouse-flow`'s
    // job, driven by `note_promoted`, not this gate's).
    registry.note_finished(binding_id).unwrap();
    assert_eq!(registry.active_run_count(binding_id).unwrap(), 0);

    // Occurrence 3 now arrives. `active_run_count == 0`, but occurrence 2
    // is still waiting — occurrence 3 must queue behind it, not jump ahead.
    assert_eq!(
        decide_admission(policy, &registry, binding_id).unwrap(),
        AdmissionDecision::QueueAt(1)
    );
}

/// M1 (fix round 2): promoting a queued occurrence to running must move
/// both counters together via `note_promoted` — the gate's subsequent
/// view of the binding stays consistent (the promoted run is counted as
/// active), so a further occurrence queues behind it rather than jumping
/// ahead or being double-admitted alongside it.
#[test]
fn note_promoted_keeps_the_gate_consistent_after_a_promotion() {
    let binding_id = BindingId::new();
    let registry = FakeRegistry::with_active(binding_id, 1);
    let policy = OverlapPolicy::Queue { depth: 8 };

    decide_admission(policy, &registry, binding_id).unwrap(); // occurrence 2 queues at 0
    registry.note_finished(binding_id).unwrap(); // occurrence 1 finishes
    registry.note_promoted(binding_id).unwrap(); // occurrence 2 promoted

    assert_eq!(registry.active_run_count(binding_id).unwrap(), 1);
    assert_eq!(registry.queued_count(binding_id).unwrap(), 0);

    // Occurrence 3 arrives: must queue behind the promoted run, not admit
    // alongside it.
    assert_eq!(
        decide_admission(policy, &registry, binding_id).unwrap(),
        AdmissionDecision::QueueAt(0)
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
    let registry = FakeRegistry::default();
    let policy = OverlapPolicy::Skip;

    let mut admitted = 0;
    for _ in 0..100 {
        if decide_admission(policy, &registry, binding_id).unwrap() == AdmissionDecision::Admit {
            admitted += 1;
        }
    }
    assert_eq!(admitted, 1);
    assert_eq!(registry.active_run_count(binding_id).unwrap(), 1);
}

#[test]
fn concurrent_policy_holds_under_a_full_catch_up_burst() {
    let binding_id = BindingId::new();
    let registry = FakeRegistry::default();
    let policy = OverlapPolicy::Concurrent { max: 5 };

    let mut admitted = 0;
    for _ in 0..100 {
        if decide_admission(policy, &registry, binding_id).unwrap() == AdmissionDecision::Admit {
            admitted += 1;
        }
    }
    assert_eq!(admitted, 5);
    assert_eq!(registry.active_run_count(binding_id).unwrap(), 5);
}

#[test]
fn queue_policy_bounds_backlog_under_a_full_catch_up_burst() {
    let binding_id = BindingId::new();
    let registry = FakeRegistry::default();
    let policy = OverlapPolicy::Queue { depth: 8 };

    let mut dropped = 0;
    for _ in 0..100 {
        if matches!(
            decide_admission(policy, &registry, binding_id).unwrap(),
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
            &self,
            binding_id: BindingId,
        ) -> Result<CancellationOutcome, RegistryError> {
            Err(RegistryError::ReadFailed { binding_id })
        }
        fn note_admitted(&self, binding_id: BindingId) -> Result<(), RegistryError> {
            Err(RegistryError::ReadFailed { binding_id })
        }
        fn note_queued(&self, binding_id: BindingId) -> Result<(), RegistryError> {
            Err(RegistryError::ReadFailed { binding_id })
        }
        fn note_finished(&self, binding_id: BindingId) -> Result<(), RegistryError> {
            Err(RegistryError::ReadFailed { binding_id })
        }
        fn note_dequeued(&self, binding_id: BindingId) -> Result<(), RegistryError> {
            Err(RegistryError::ReadFailed { binding_id })
        }
        fn note_promoted(&self, binding_id: BindingId) -> Result<(), RegistryError> {
            Err(RegistryError::ReadFailed { binding_id })
        }
    }

    let binding_id = BindingId::new();
    let registry = AlwaysFailingRegistry;
    for policy in [
        OverlapPolicy::Skip,
        OverlapPolicy::Concurrent { max: 5 },
        OverlapPolicy::Queue { depth: 5 },
        OverlapPolicy::CancelPrevious,
    ] {
        assert!(decide_admission(policy, &registry, binding_id).is_err());
    }
}

/// F (fix round 1): `Concurrent{max}`/`Queue{depth}` must not be
/// effectively unbounded just because nothing upstream validates the
/// policy value.
#[test]
fn queue_depth_is_clamped_to_the_sanity_ceiling() {
    let binding_id = BindingId::new();
    let registry = FakeRegistry::with_active(binding_id, 1);
    let policy = OverlapPolicy::Queue { depth: u32::MAX };

    for i in 0..roundhouse_sched::admission::MAX_OVERLAP_QUEUE_DEPTH {
        assert_eq!(
            decide_admission(policy, &registry, binding_id).unwrap(),
            AdmissionDecision::QueueAt(i)
        );
    }
    assert!(matches!(
        decide_admission(policy, &registry, binding_id).unwrap(),
        AdmissionDecision::SkippedQueueFull { .. }
    ));
}

/// A (fix round 1), tightened by fix round 2 to use `SharedRegistry`
/// directly rather than the crate's own withdrawn "compile-time-enforced"
/// claim: many threads race `decide_admission` for the *same* `Skip`
/// binding through one `SharedRegistry`, and exactly one must be admitted,
/// however much real concurrency the OS scheduler gives them. Kept
/// alongside the deterministic guard below per the fix-round-2 review's
/// explicit "keep the barrier test too".
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

/// Fix round 2, "Test quality": the barrier test above is real concurrency
/// but only *probabilistically* catches a broken lock — measured against
/// the exact regression it exists to catch (the lock decomposed into
/// separate lock/read/unlock and lock/write/unlock steps), only ~2 of 200
/// trials produced more than one admit. This test instead makes the
/// registry's own read artificially slow *while tracking how many calls
/// are concurrently inside it*: if `SharedRegistry` genuinely holds one
/// lock across the whole `decide_admission` call, at most one call can
/// ever be inside `active_run_count` at a time, however many threads race
/// it and however long any one call takes. A 50ms hold is orders of
/// magnitude larger than realistic thread-scheduling jitter, so this
/// deterministically (in practice) fails against the broken shape instead
/// of relying on scheduling luck.
#[test]
fn shared_registry_never_lets_two_calls_run_concurrently_for_one_binding() {
    struct SlowProbeRegistry {
        inner: FakeRegistry,
        in_flight: AtomicU32,
        max_observed: AtomicU32,
    }
    impl RunRegistry for SlowProbeRegistry {
        fn active_run_count(&self, binding_id: BindingId) -> Result<u32, RegistryError> {
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_observed.fetch_max(now, Ordering::SeqCst);
            // Widen the window: if `SharedRegistry` decomposed its lock
            // into separate lock/read/unlock and lock/write/unlock steps
            // (the exact regression this test exists to catch), sleeping
            // here — while genuinely holding no lock in that broken
            // shape — gives every other racing thread on this binding
            // ample time to slip its own read in concurrently.
            thread::sleep(Duration::from_millis(50));
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            self.inner.active_run_count(binding_id)
        }
        fn queued_count(&self, binding_id: BindingId) -> Result<u32, RegistryError> {
            self.inner.queued_count(binding_id)
        }
        fn cancel_active(
            &self,
            binding_id: BindingId,
        ) -> Result<CancellationOutcome, RegistryError> {
            self.inner.cancel_active(binding_id)
        }
        fn note_admitted(&self, binding_id: BindingId) -> Result<(), RegistryError> {
            self.inner.note_admitted(binding_id)
        }
        fn note_queued(&self, binding_id: BindingId) -> Result<(), RegistryError> {
            self.inner.note_queued(binding_id)
        }
        fn note_finished(&self, binding_id: BindingId) -> Result<(), RegistryError> {
            self.inner.note_finished(binding_id)
        }
        fn note_dequeued(&self, binding_id: BindingId) -> Result<(), RegistryError> {
            self.inner.note_dequeued(binding_id)
        }
        fn note_promoted(&self, binding_id: BindingId) -> Result<(), RegistryError> {
            self.inner.note_promoted(binding_id)
        }
    }

    let binding_id = BindingId::new();
    let shared = Arc::new(SharedRegistry::new(SlowProbeRegistry {
        inner: FakeRegistry::default(),
        in_flight: AtomicU32::new(0),
        max_observed: AtomicU32::new(0),
    }));
    const THREADS: usize = 8;
    let barrier = Arc::new(Barrier::new(THREADS));

    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let shared = Arc::clone(&shared);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                shared.decide(OverlapPolicy::Skip, binding_id)
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap().unwrap();
    }

    // All threads have joined, so nothing else can be touching `shared`;
    // `Arc::try_unwrap` succeeds because every thread already dropped its
    // clone, and `into_inner` hands back the wrapped registry so the test
    // can inspect its own concurrency counter directly.
    let max_concurrent = {
        let shared =
            Arc::try_unwrap(shared).unwrap_or_else(|_| panic!("threads still hold a clone"));
        shared.into_inner().max_observed.load(Ordering::SeqCst)
    };

    assert_eq!(
        max_concurrent, 1,
        "two decide() calls for the same binding ran active_run_count concurrently \
         — the per-binding lock is not held across the whole call"
    );
}

/// H (fix round 2): the admission lock is per-binding, not global. A slow
/// (or, in the worst case, stuck) call for one binding must not stall an
/// unrelated binding's admission decisions — this is exactly the scenario
/// the review's finding H describes: a `CancelPrevious` binding whose
/// `cancel_active` is slow to confirm must not freeze every other binding
/// in the process.
#[test]
fn shared_registry_does_not_block_unrelated_bindings() {
    use std::sync::atomic::AtomicBool;

    struct SlowForOneBindingRegistry {
        inner: FakeRegistry,
        slow_binding: BindingId,
        release: Arc<AtomicBool>,
    }
    impl RunRegistry for SlowForOneBindingRegistry {
        fn active_run_count(&self, binding_id: BindingId) -> Result<u32, RegistryError> {
            if binding_id == self.slow_binding {
                // Simulates a slow/blocked registry call for this one
                // binding — e.g. a `cancel_active` waiting on a
                // termination-resistant process group.
                while !self.release.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(5));
                }
            }
            self.inner.active_run_count(binding_id)
        }
        fn queued_count(&self, binding_id: BindingId) -> Result<u32, RegistryError> {
            self.inner.queued_count(binding_id)
        }
        fn cancel_active(
            &self,
            binding_id: BindingId,
        ) -> Result<CancellationOutcome, RegistryError> {
            self.inner.cancel_active(binding_id)
        }
        fn note_admitted(&self, binding_id: BindingId) -> Result<(), RegistryError> {
            self.inner.note_admitted(binding_id)
        }
        fn note_queued(&self, binding_id: BindingId) -> Result<(), RegistryError> {
            self.inner.note_queued(binding_id)
        }
        fn note_finished(&self, binding_id: BindingId) -> Result<(), RegistryError> {
            self.inner.note_finished(binding_id)
        }
        fn note_dequeued(&self, binding_id: BindingId) -> Result<(), RegistryError> {
            self.inner.note_dequeued(binding_id)
        }
        fn note_promoted(&self, binding_id: BindingId) -> Result<(), RegistryError> {
            self.inner.note_promoted(binding_id)
        }
    }

    let slow_binding = BindingId::new();
    let other_binding = BindingId::new();
    let release = Arc::new(AtomicBool::new(false));
    let shared = Arc::new(SharedRegistry::new(SlowForOneBindingRegistry {
        inner: FakeRegistry::default(),
        slow_binding,
        release: Arc::clone(&release),
    }));

    let blocked_shared = Arc::clone(&shared);
    let blocked_handle =
        thread::spawn(move || blocked_shared.decide(OverlapPolicy::Skip, slow_binding));
    // Give the blocked thread time to actually enter and start waiting.
    thread::sleep(Duration::from_millis(50));

    // A decision for a totally different binding must complete promptly,
    // proving the per-binding lock does not serialize across bindings.
    let start = Instant::now();
    let other_decision = shared.decide(OverlapPolicy::Skip, other_binding).unwrap();
    let elapsed = start.elapsed();

    release.store(true, Ordering::SeqCst);
    blocked_handle.join().unwrap().unwrap();

    assert_eq!(other_decision, AdmissionDecision::Admit);
    assert!(
        elapsed < Duration::from_millis(500),
        "an unrelated binding's decision waited {elapsed:?} for another binding's slow call \
         — the admission lock is not properly scoped per binding"
    );
}
