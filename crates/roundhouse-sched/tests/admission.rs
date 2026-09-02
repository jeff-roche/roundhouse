//! Integration tests for the overlap-policy admission gate (Task 5).
//!
//! Deviation from the plan text's supplied test (see task-05-report.md
//! "Deviations from the plan text"): `roundhouse_sched::ids::BindingId`
//! does not exist — `BindingId` is a flat re-export of `roundhouse-core`
//! (Ruling P3/P6). `RunRegistry` also grew `queued_count`/`note_admitted`/
//! `note_queued` beyond the plan's two methods, so `FakeRegistry` here
//! implements the full real trait rather than the plan's two-method stub.
use roundhouse_core::BindingId;
use roundhouse_sched::admission::{decide_admission, AdmissionDecision, RunRegistry};
use roundhouse_sched::trigger::OverlapPolicy;
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

fn with_active(binding_id: BindingId, count: u32) -> FakeRegistry {
    let mut registry = FakeRegistry::default();
    registry.active.insert(binding_id, count);
    registry
}

#[test]
fn skip_policy_skips_when_a_run_is_already_active() {
    let binding_id = BindingId::new();
    let mut registry = with_active(binding_id, 1);
    let decision = decide_admission(OverlapPolicy::Skip, &mut registry, binding_id);
    assert_eq!(decision, AdmissionDecision::SkipDueToOverlap);
    // Skip never mutates the count it declined to add to.
    assert_eq!(registry.active_run_count(binding_id), 1);
}

#[test]
fn skip_policy_admits_when_nothing_is_active() {
    let binding_id = BindingId::new();
    let mut registry = FakeRegistry::default();
    let decision = decide_admission(OverlapPolicy::Skip, &mut registry, binding_id);
    assert_eq!(decision, AdmissionDecision::Admit);
    assert_eq!(registry.active_run_count(binding_id), 1);
}

#[test]
fn cancel_previous_cancels_then_admits() {
    let binding_id = BindingId::new();
    let mut registry = with_active(binding_id, 1);
    let decision = decide_admission(OverlapPolicy::CancelPrevious, &mut registry, binding_id);
    assert_eq!(decision, AdmissionDecision::CancelledPreviousAndAdmit);
    // Cancelled the old run, then counted the new one: net active count is
    // exactly 1, not 0 (forgot to admit) and not 2 (didn't really cancel).
    assert_eq!(registry.active_run_count(binding_id), 1);
}

#[test]
fn cancel_previous_admits_directly_when_nothing_was_active() {
    let binding_id = BindingId::new();
    let mut registry = FakeRegistry::default();
    let decision = decide_admission(OverlapPolicy::CancelPrevious, &mut registry, binding_id);
    assert_eq!(decision, AdmissionDecision::CancelledPreviousAndAdmit);
    assert_eq!(registry.active_run_count(binding_id), 1);
}

#[test]
fn concurrent_policy_admits_below_max_and_skips_at_max() {
    let binding_id = BindingId::new();
    let mut registry = with_active(binding_id, 1);
    let policy = OverlapPolicy::Concurrent { max: 2 };

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
fn queue_policy_queues_behind_an_active_run_up_to_depth() {
    let binding_id = BindingId::new();
    let mut registry = with_active(binding_id, 1);
    let policy = OverlapPolicy::Queue { depth: 1 };

    assert_eq!(
        decide_admission(policy, &mut registry, binding_id),
        AdmissionDecision::QueueAt(0)
    );
    // Queue is now full at depth 1: backpressure, not unbounded growth.
    assert_eq!(
        decide_admission(policy, &mut registry, binding_id),
        AdmissionDecision::SkipDueToOverlap
    );
    assert_eq!(registry.queued_count(binding_id), 1);
}

#[test]
fn queue_policy_admits_immediately_when_nothing_is_active() {
    let binding_id = BindingId::new();
    let mut registry = FakeRegistry::default();
    let decision = decide_admission(OverlapPolicy::Queue { depth: 8 }, &mut registry, binding_id);
    assert_eq!(decision, AdmissionDecision::Admit);
    assert_eq!(registry.active_run_count(binding_id), 1);
    assert_eq!(registry.queued_count(binding_id), 0);
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
        if decide_admission(policy, &mut registry, binding_id) == AdmissionDecision::Admit {
            admitted += 1;
        }
    }
    assert_eq!(admitted, 1);
    assert_eq!(registry.active_run_count(binding_id), 1);
}

#[test]
fn concurrent_policy_holds_under_a_full_catch_up_burst() {
    let binding_id = BindingId::new();
    let mut registry = FakeRegistry::default();
    let policy = OverlapPolicy::Concurrent { max: 5 };

    let mut admitted = 0;
    for _ in 0..100 {
        if decide_admission(policy, &mut registry, binding_id) == AdmissionDecision::Admit {
            admitted += 1;
        }
    }
    assert_eq!(admitted, 5);
    assert_eq!(registry.active_run_count(binding_id), 5);
}

#[test]
fn queue_policy_bounds_backlog_under_a_full_catch_up_burst() {
    let binding_id = BindingId::new();
    let mut registry = FakeRegistry::default();
    let policy = OverlapPolicy::Queue { depth: 8 };

    let mut skipped = 0;
    for _ in 0..100 {
        if decide_admission(policy, &mut registry, binding_id)
            == AdmissionDecision::SkipDueToOverlap
        {
            skipped += 1;
        }
    }
    // 1 admitted immediately + 8 queued + the rest (91) skipped as backpressure.
    assert_eq!(skipped, 91);
    assert_eq!(registry.active_run_count(binding_id), 1);
    assert_eq!(registry.queued_count(binding_id), 8);
}
