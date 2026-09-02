//! Overlap-policy admission gate (Subsystem A, Task 5).
//!
//! Every `Fire` a [`Scheduler`](crate::scheduler::Scheduler) tick emits still
//! has to pass through here before it becomes an actual run:
//! [`decide_admission`] is what enforces a [`Binding`](crate::trigger::Binding)'s
//! [`OverlapPolicy`] against whatever runs of that binding are currently
//! active or queued. It is the real bound on concurrent runs — the
//! scheduler's own `MAX_CATCH_UP_OCCURRENCES_PER_BINDING_PER_TICK` cap
//! (100) still lets up to 100 `Fire` events for one binding arrive here in
//! a single tick for any non-`Cron` spec, so this gate, not the scheduler,
//! is what decides how many of those actually start a run.
//!
//! # Race-freedom
//!
//! The textbook failure mode for an admission gate is read-then-admit:
//! read "is anything active", decide to admit, and only *afterwards* write
//! down that a new run now counts as active. Two decisions for the same
//! binding made back-to-back can both observe the pre-admission count and
//! both admit, double-booking a `Skip` or `Concurrent{max}` binding.
//!
//! [`decide_admission`] closes that window by never splitting the read
//! from the write across a return: every branch that results in a new run
//! starting or being queued issues the matching [`RunRegistry`] mutation
//! ([`RunRegistry::note_admitted`] / [`RunRegistry::note_queued`] /
//! [`RunRegistry::cancel_active`]) itself, through the same `&mut dyn
//! RunRegistry` borrow it used to read the counts, before it returns. There
//! is no step where the caller is trusted to "remember" to record the
//! admission later — by the time `decide_admission` returns, the registry
//! already reflects the decision.
//!
//! That makes one call to `decide_admission` atomic. Extending that to two
//! calls for the *same* `binding_id` made from different tasks is a
//! property of the `RunRegistry` implementation, not of this function: every
//! trait method takes `&mut self`, so Rust's exclusivity rule already
//! forbids two such calls from literally executing at the same instant
//! against one shared value. A real implementation shared across async
//! tasks (necessarily behind something like `Arc<Mutex<...>>`, since
//! `decide_admission` itself holds no lock) **must** acquire that lock
//! before calling `decide_admission` and hold it until the call returns —
//! never lock only around the individual accessor methods. Locking the
//! accessors individually would let a second call's read land in the gap
//! between the first call's read and its write, reopening exactly the
//! window this contract exists to close. Given that discipline at the call
//! site, decisions for one binding are fully serialized and no interleaving
//! is possible.
use crate::trigger::OverlapPolicy;
use roundhouse_core::BindingId;

/// Read/write access to the run-concurrency state admission decisions are
/// made against. Deliberately thin — no dependency on `roundhouse-flow`'s
/// actual run machinery — so `roundhouse-sched` stays independently
/// testable with a fake in-memory implementation (see the crate's
/// `tests/admission.rs`). The real implementation, backed by whatever
/// run-tracking state `roundhouse-flow`'s run-start path owns, is that
/// crate's job, not this one's.
///
/// See the [module docs](self) for the atomicity obligation every method
/// here participates in.
pub trait RunRegistry {
    /// Runs of `binding_id` currently executing (admitted and started, not
    /// yet finished).
    fn active_run_count(&self, binding_id: BindingId) -> u32;

    /// Occurrences of `binding_id` admitted under `OverlapPolicy::Queue`
    /// but not yet started — waiting for a running slot to free up.
    /// Deliberately distinct from `active_run_count`: a `Queue` binding's
    /// bound limits how much *unstarted* backlog can accumulate, not how
    /// many runs execute concurrently (which for `Queue` is expected to
    /// stay at most 1, but this gate does not assume that).
    fn queued_count(&self, binding_id: BindingId) -> u32;

    /// Cancels `binding_id`'s currently active run(s)
    /// (`OverlapPolicy::CancelPrevious`). Must bring `active_run_count`
    /// back to 0 for `binding_id` before returning.
    fn cancel_active(&mut self, binding_id: BindingId);

    /// Records that a new run of `binding_id` is starting immediately.
    /// `active_run_count(binding_id)` must reflect the increment before
    /// this call returns — see the module-level race-freedom contract.
    fn note_admitted(&mut self, binding_id: BindingId);

    /// Records that one occurrence of `binding_id` has been queued.
    /// `queued_count(binding_id)` must reflect the increment before this
    /// call returns.
    fn note_queued(&mut self, binding_id: BindingId);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// Nothing else of this binding is active (or the policy allows more
    /// concurrency); a new run starts now.
    Admit,
    /// The policy forbids a new run right now and there is no room to
    /// queue it (or the policy doesn't queue at all): the occurrence is
    /// dropped. The caller must log this — it is backpressure, not a
    /// silent drop.
    SkipDueToOverlap,
    /// Queued at the given 0-indexed position behind the currently active
    /// run(s); not started yet.
    QueueAt(u32),
    /// The previously active run was cancelled and a new one starts now.
    CancelledPreviousAndAdmit,
}

/// Decides what happens to one incoming occurrence of `binding_id` under
/// `policy`, given the current state of `registry`. See the [module
/// docs](self) for the race-freedom contract this function and
/// [`RunRegistry`] together provide.
pub fn decide_admission(
    policy: OverlapPolicy,
    registry: &mut dyn RunRegistry,
    binding_id: BindingId,
) -> AdmissionDecision {
    match policy {
        OverlapPolicy::Skip => {
            if registry.active_run_count(binding_id) > 0 {
                AdmissionDecision::SkipDueToOverlap
            } else {
                registry.note_admitted(binding_id);
                AdmissionDecision::Admit
            }
        }
        OverlapPolicy::Concurrent { max } => {
            if registry.active_run_count(binding_id) < max {
                registry.note_admitted(binding_id);
                AdmissionDecision::Admit
            } else {
                AdmissionDecision::SkipDueToOverlap
            }
        }
        OverlapPolicy::Queue { depth } => {
            if registry.active_run_count(binding_id) == 0 {
                registry.note_admitted(binding_id);
                AdmissionDecision::Admit
            } else {
                let queued = registry.queued_count(binding_id);
                if queued < depth {
                    registry.note_queued(binding_id);
                    AdmissionDecision::QueueAt(queued)
                } else {
                    // Queue is full: backpressure, not a silent drop — the
                    // caller must log it (see `AdmissionDecision::SkipDueToOverlap`).
                    AdmissionDecision::SkipDueToOverlap
                }
            }
        }
        OverlapPolicy::CancelPrevious => {
            if registry.active_run_count(binding_id) > 0 {
                registry.cancel_active(binding_id);
            }
            registry.note_admitted(binding_id);
            AdmissionDecision::CancelledPreviousAndAdmit
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct FakeRegistry {
        active: HashMap<BindingId, u32>,
        queued: HashMap<BindingId, u32>,
    }

    impl RunRegistry for FakeRegistry {
        fn active_run_count(&self, binding_id: BindingId) -> u32 {
            *self.active.get(&binding_id).unwrap_or(&0)
        }
        fn queued_count(&self, binding_id: BindingId) -> u32 {
            *self.queued.get(&binding_id).unwrap_or(&0)
        }
        fn cancel_active(&mut self, binding_id: BindingId) {
            self.active.insert(binding_id, 0);
        }
        fn note_admitted(&mut self, binding_id: BindingId) {
            *self.active.entry(binding_id).or_insert(0) += 1;
        }
        fn note_queued(&mut self, binding_id: BindingId) {
            *self.queued.entry(binding_id).or_insert(0) += 1;
        }
    }

    #[test]
    fn concurrent_admits_up_to_max_then_skips() {
        let binding_id = BindingId::new();
        let mut registry = FakeRegistry::default();
        let policy = OverlapPolicy::Concurrent { max: 2 };

        assert_eq!(
            decide_admission(policy, &mut registry, binding_id),
            AdmissionDecision::Admit
        );
        assert_eq!(
            decide_admission(policy, &mut registry, binding_id),
            AdmissionDecision::Admit
        );
        assert_eq!(registry.active_run_count(binding_id), 2);
        assert_eq!(
            decide_admission(policy, &mut registry, binding_id),
            AdmissionDecision::SkipDueToOverlap
        );
    }

    #[test]
    fn queue_bounds_backlog_independently_of_active_count() {
        let binding_id = BindingId::new();
        let mut registry = FakeRegistry::default();
        let policy = OverlapPolicy::Queue { depth: 2 };

        // First occurrence: nothing active, admitted immediately.
        assert_eq!(
            decide_admission(policy, &mut registry, binding_id),
            AdmissionDecision::Admit
        );
        // Now something is active; subsequent occurrences queue up to depth.
        assert_eq!(
            decide_admission(policy, &mut registry, binding_id),
            AdmissionDecision::QueueAt(0)
        );
        assert_eq!(
            decide_admission(policy, &mut registry, binding_id),
            AdmissionDecision::QueueAt(1)
        );
        // Queue is now at depth: further arrivals are backpressured, not
        // silently treated as more concurrency.
        assert_eq!(
            decide_admission(policy, &mut registry, binding_id),
            AdmissionDecision::SkipDueToOverlap
        );
        assert_eq!(registry.active_run_count(binding_id), 1);
        assert_eq!(registry.queued_count(binding_id), 2);
    }

    #[test]
    fn admission_state_is_isolated_per_binding() {
        let a = BindingId::new();
        let b = BindingId::new();
        let mut registry = FakeRegistry::default();
        let policy = OverlapPolicy::Skip;

        assert_eq!(
            decide_admission(policy, &mut registry, a),
            AdmissionDecision::Admit
        );
        // A second, unrelated binding is unaffected by `a`'s active run.
        assert_eq!(
            decide_admission(policy, &mut registry, b),
            AdmissionDecision::Admit
        );
        assert_eq!(
            decide_admission(policy, &mut registry, a),
            AdmissionDecision::SkipDueToOverlap
        );
    }

    /// Simulates the exact hazard the module docs describe: a burst of
    /// `Fire` events for one binding (up to 100 in a single scheduler tick,
    /// per `MAX_CATCH_UP_OCCURRENCES_PER_BINDING_PER_TICK`) run one after
    /// another through `decide_admission` against one shared registry.
    /// Because every mutation happens inside `decide_admission` itself
    /// (never deferred to the caller), sequential admission of a burst can
    /// never let more than `max` runs end up active, however many
    /// occurrences arrive.
    #[test]
    fn a_burst_of_fire_events_never_exceeds_the_concurrency_bound() {
        let binding_id = BindingId::new();
        let mut registry = FakeRegistry::default();
        let policy = OverlapPolicy::Concurrent { max: 3 };

        let mut admitted = 0;
        for _ in 0..100 {
            if decide_admission(policy, &mut registry, binding_id) == AdmissionDecision::Admit {
                admitted += 1;
            }
        }
        assert_eq!(admitted, 3);
        assert_eq!(registry.active_run_count(binding_id), 3);
    }
}
