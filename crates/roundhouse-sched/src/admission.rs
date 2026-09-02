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
//! both admit, double-booking a `Skip` binding.
//!
//! [`decide_admission`] closes that window *within one call*: every branch
//! that results in a new run starting or being queued issues the matching
//! [`RunRegistry`] mutation ([`RunRegistry::note_admitted`] /
//! [`RunRegistry::note_queued`] / [`RunRegistry::cancel_active`]) itself,
//! through the same `&mut dyn RunRegistry` borrow it used to read the
//! counts, before it returns. There is no step where a caller is trusted
//! to "remember" to record the admission later.
//!
//! **Fix round 1 correction — withdrawing an earlier, wrong claim.** The
//! first version of this module argued that `&mut self` on every
//! [`RunRegistry`] method makes two concurrent `decide_admission` calls
//! against the same binding impossible "by construction", full stop. That
//! claim does not hold and is withdrawn. `&mut self` only protects one
//! in-memory *value*; it says nothing about state shared *behind* it. The
//! shape a real registry shared across a daemon's tasks must take defeats
//! the old argument with no `unsafe` code at all:
//!
//! ```ignore
//! #[derive(Clone)]
//! struct FlowRegistry(Arc<Mutex<Inner>>); // or Arc<DbPool> for a DB-backed one
//! ```
//!
//! Two tokio tasks each hold their own clone. Each has an exclusive `&mut`
//! to *its own* clone — the borrow checker is fully satisfied — while both
//! call methods that read and write the same shared `Inner`. Nothing in
//! the trait or in `decide_admission` stops both from reading
//! `active_run_count == 0` before either writes back, and a `Skip` binding
//! runs twice. This is the realistic shape, not a contrived one: it is the
//! only way a single registry can be shared across concurrent callers at
//! all.
//!
//! The actual fix is structural, not a doc-comment: [`SharedRegistry`]
//! below is the crate-supported way to share one [`RunRegistry`] across
//! concurrent callers. It holds a `std::sync::Mutex` locked for the
//! *entire* [`decide_admission`] call — acquire, decide (every read and
//! every write), release — so two callers racing the same binding are
//! fully serialized: the second call's reads cannot start until the
//! first call's writes have already landed. Callers embedding this crate
//! must go through `SharedRegistry::decide` (or reproduce its exact lock
//! discipline) rather than decomposing a decision into separate
//! lock-read / decide / lock-write steps — decomposing it that way
//! reopens precisely the window this type exists to close.
//!
//! A registry backed by a real database (e.g. SQLite via
//! `roundhouse-store`, per Ruling P4) cannot use `SharedRegistry` as-is —
//! there's no single in-process value to put behind one `Mutex` once
//! multiple daemon processes or connections are in play. Such an
//! implementation must not decompose the check into separate read/write
//! calls against a pool at all: route the whole `decide_admission` call
//! through one transaction (`BEGIN IMMEDIATE` per Ruling P4, so the read
//! and the write are serialized by SQLite itself), or, better, collapse
//! the check into one conditional statement that is atomic by
//! construction, e.g. `UPDATE bindings SET active = active + 1 WHERE id =
//! ?1 AND active < ?2` and branching on the affected-row count — never
//! `SELECT active ...` followed by a separate `UPDATE` on the same
//! connection or pool checkout.
//!
//! # Deferred hazard: `CancelPrevious` thrash (not fixed here)
//!
//! `decide_admission` takes no clock and no debounce window — it decides
//! purely from the current active/queued counts. That means a
//! `CancelPrevious` binding fired faster than one run of its job can
//! complete never makes progress: each new occurrence cancels the run
//! before it finishes and starts another, forever, at unbounded cost and
//! zero completed work. This is deliberately deferred (assigned to
//! Subsystem B's run-start task, which has the clock this decision would
//! need), but it must not be deferred *silently*:
//!
//! - `TriggerSpec::Fs` defaults to `CancelPrevious`
//!   (`OverlapPolicy::default_for`), so an agent's *own* runs writing into
//!   a watched tree can drive this thrash with no adversary involved at
//!   all.
//! - The scheduler's `MAX_CATCH_UP_OCCURRENCES_PER_BINDING_PER_TICK` cap
//!   does **not** bound this hazard: `Scheduler::occurrences_after`
//!   returns an empty `Vec` for `Fs`/`Webhook`/`Message`/`Git` specs (they
//!   are event-driven, not heap-scheduled), so those specs never flow
//!   through `Scheduler::tick`'s catch-up loop at all, and nothing in this
//!   crate rate-limits how often their `Fire`-equivalent events can arrive
//!   from outside.
use crate::trigger::OverlapPolicy;
use roundhouse_core::BindingId;
use std::sync::Mutex;

/// Hard sanity ceiling on `OverlapPolicy::Concurrent`'s `max`. Without
/// this, a binding configured (accidentally or maliciously — this policy
/// round-trips through `serde` with no validation of its own) with
/// `max: u32::MAX` disables the concurrency bound entirely while still
/// looking like a bounded policy to anyone reading the config. Chosen the
/// same way `scheduler.rs`'s `MAX_INTERVAL` is: comfortably above any
/// concurrency a real deployment would legitimately configure (a binding
/// running 1,000 copies of its job at once is already a misconfiguration
/// worth surfacing), while still bounding the worst case.
pub const MAX_OVERLAP_CONCURRENCY: u32 = 1_000;

/// Hard sanity ceiling on `OverlapPolicy::Queue`'s `depth`, for the same
/// reason and by the same reasoning as [`MAX_OVERLAP_CONCURRENCY`].
pub const MAX_OVERLAP_QUEUE_DEPTH: u32 = 1_000;

/// Failure modes a [`RunRegistry`] can report. Every one of them makes
/// [`decide_admission`] fail *closed* (return `Err`, admit nothing) rather
/// than falling back to a default count — see the type's own doc comment
/// for why a bare `u32` read that silently defaults to `0` on failure
/// would make a degraded registry admit everything, which is the opposite
/// of what an availability control is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    /// A read (`active_run_count`/`queued_count`) could not be completed
    /// (e.g. a SQLite-backed implementation hit `SQLITE_BUSY` or a pool
    /// checkout timed out). The gate cannot tell "0 active" from "unknown"
    /// from this alone, so it must not guess `0`.
    #[error("run registry read failed for binding {binding_id}; admission gate fails closed")]
    ReadFailed { binding_id: BindingId },
    /// A counter mutation (`note_admitted`/`note_queued`/`note_finished`/
    /// `note_dequeued`) would have overflowed or underflowed. Implementors
    /// must report this instead of wrapping — a wrapping `+= 1` on a
    /// `u32::MAX` counter silently becomes `0`, which is exactly the
    /// fail-open failure mode this whole gate exists to prevent.
    #[error(
        "run registry counter for binding {binding_id} would overflow or underflow; \
         admission gate fails closed"
    )]
    CounterOutOfRange { binding_id: BindingId },
    /// A [`SharedRegistry`]'s internal mutex was poisoned by a panic while
    /// a previous call held it. The wrapped registry's state after a panic
    /// mid-mutation cannot be trusted, so this also fails closed rather
    /// than silently recovering the poisoned guard's contents.
    #[error(
        "shared registry lock was poisoned by a panicking holder; admission gate fails closed"
    )]
    Poisoned,
}

/// How a [`RunRegistry::cancel_active`] attempt actually concluded.
/// Distinct from a plain `bool` so the two states are named, not
/// inferred, at every call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancellationOutcome {
    /// The previous run is verified stopped.
    Confirmed,
    /// Cancellation was requested but could not be confirmed within this
    /// call. The previous run may still be alive.
    Unconfirmed,
}

/// Read/write access to the run-concurrency state admission decisions are
/// made against. Deliberately thin — no dependency on `roundhouse-flow`'s
/// actual run machinery — so `roundhouse-sched` stays independently
/// testable with a fake in-memory implementation (see the crate's
/// `tests/admission.rs`). The real implementation, backed by whatever
/// run-tracking state `roundhouse-flow`'s run-start path owns, is that
/// crate's job, not this one's.
///
/// See the [module docs](self) for the race-freedom obligation every
/// method here participates in, and [`SharedRegistry`] for the supported
/// way to share one implementation across concurrent callers.
///
/// Every counter-mutating method's contract requires the mutation to be
/// visible to the matching read (`active_run_count`/`queued_count`)
/// before the mutating call returns, and requires reporting
/// [`RegistryError::CounterOutOfRange`] rather than wrapping on overflow
/// or underflow.
pub trait RunRegistry {
    /// Runs of `binding_id` currently executing (admitted and started, not
    /// yet finished).
    fn active_run_count(&self, binding_id: BindingId) -> Result<u32, RegistryError>;

    /// Occurrences of `binding_id` admitted under `OverlapPolicy::Queue`
    /// but not yet started — waiting for a running slot to free up.
    /// Deliberately distinct from `active_run_count`: a `Queue` binding's
    /// bound limits how much *unstarted* backlog can accumulate, not how
    /// many runs execute concurrently.
    fn queued_count(&self, binding_id: BindingId) -> Result<u32, RegistryError>;

    /// Attempts to cancel `binding_id`'s currently active run and reports
    /// whether termination was actually confirmed before returning.
    ///
    /// `roundhouse-flow`'s real implementation sits on top of
    /// `roundhouse_tools::shell::cancel::cancel_running_shell` — an async
    /// SIGTERM -> wait -> SIGKILL -> re-probe sequence whose own
    /// `CancelError::GroupStillAlive` variant documents that it may not
    /// confirm an empty process group within any bounded time. This
    /// method's contract is honest about that instead of pretending
    /// cancellation is always immediate and complete:
    /// - `Ok(CancellationOutcome::Confirmed)` (a real implementation's
    ///   `Ok(ExitDisposition::Terminated | ExitDisposition::Killed)`
    ///   case): the previous run is verified gone.
    ///   `active_run_count(binding_id)` must already reflect 0.
    /// - `Ok(CancellationOutcome::Unconfirmed)` (a real implementation's
    ///   `Err(CancelError::GroupStillAlive)` case, mapped rather than
    ///   propagated as a hard error — an unconfirmed cancel is an expected
    ///   outcome this trait models explicitly, not a failure of the
    ///   registry itself): the implementor must **not** report
    ///   `active_run_count` as 0 — the process group may still be alive.
    ///   [`decide_admission`] fails closed on this: it will not admit a
    ///   replacement run on top of a predecessor that might still be
    ///   running.
    /// - `Err(RegistryError)`: some other, genuine registry failure (e.g.
    ///   `CancelError::Signal`/`Wait`/`Probe`'s underlying I/O error).
    fn cancel_active(
        &mut self,
        binding_id: BindingId,
    ) -> Result<CancellationOutcome, RegistryError>;

    /// Records that a new run of `binding_id` is starting immediately.
    /// `active_run_count(binding_id)` must reflect the increment before
    /// this call returns.
    fn note_admitted(&mut self, binding_id: BindingId) -> Result<(), RegistryError>;

    /// Records that one occurrence of `binding_id` has been queued.
    /// `queued_count(binding_id)` must reflect the increment before this
    /// call returns.
    fn note_queued(&mut self, binding_id: BindingId) -> Result<(), RegistryError>;

    /// Records that one of `binding_id`'s active runs has finished.
    /// `active_run_count(binding_id)` must reflect the decrement before
    /// this call returns. Without this release side, every
    /// `note_admitted` is permanent: a `Skip` binding that is never told
    /// its run finished is wedged shut forever (see the module docs'
    /// note on the leaked-admission hazard this closes).
    fn note_finished(&mut self, binding_id: BindingId) -> Result<(), RegistryError>;

    /// Records that one of `binding_id`'s queued occurrences has been
    /// dequeued (promoted to running, or otherwise removed from the
    /// backlog). `queued_count(binding_id)` must reflect the decrement
    /// before this call returns. Without this release side,
    /// `queued_count` only ever grows, and once it reaches `depth` every
    /// later occurrence for that binding is dropped forever — a `Message`
    /// binding could be permanently silenced by one small burst.
    fn note_dequeued(&mut self, binding_id: BindingId) -> Result<(), RegistryError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// Nothing else of this binding is active (or the policy allows more
    /// concurrency); a new run starts now.
    Admit,
    /// Routine, by-design overlap suppression: `Skip` found something
    /// already active, or `Concurrent{max}` is already at its cap. Not to
    /// be confused with [`AdmissionDecision::SkippedQueueFull`] — that one
    /// means a `Queue` binding's backlog bound was actually exceeded under
    /// load, which is an operational signal this variant deliberately does
    /// not carry.
    SkipDueToOverlap,
    /// Queued at the given 0-indexed position behind the currently active
    /// run(s); not started yet.
    QueueAt(u32),
    /// The previously active run was cancelled and a new one starts now.
    CancelledPreviousAndAdmit,
    /// A `Queue{depth}` binding's backlog was already at `depth` when this
    /// occurrence arrived: dropped as backpressure, not queued. Kept
    /// distinct from `SkipDueToOverlap` so an operator can tell "overflow
    /// under load" (this) from "suppression by design" (that) — see the
    /// module's fix-round-1 notes. `decide_admission` also emits a
    /// `tracing::warn!` when returning this, so the drop is visible even
    /// if a caller doesn't inspect the decision.
    SkippedQueueFull { depth: u32 },
    /// `CancelPrevious` found an active run but could not confirm it
    /// actually stopped; the replacement was **not** admitted (fail
    /// closed — see [`RunRegistry::cancel_active`]'s doc comment).
    /// `decide_admission` also emits a `tracing::warn!` when returning
    /// this.
    SkippedCancellationUnconfirmed,
}

/// Decides what happens to one incoming occurrence of `binding_id` under
/// `policy`, given the current state of `registry`. See the [module
/// docs](self) for the race-freedom contract this function and
/// [`RunRegistry`] together provide, and [`SharedRegistry`] for sharing a
/// registry across concurrent callers.
///
/// Fails closed: any [`RegistryError`] from a read or a write is
/// propagated immediately, admitting nothing, rather than treating an
/// unreadable count as `0` (which would admit everything a degraded
/// registry is asked about — exactly backwards for an availability
/// control).
pub fn decide_admission(
    policy: OverlapPolicy,
    registry: &mut dyn RunRegistry,
    binding_id: BindingId,
) -> Result<AdmissionDecision, RegistryError> {
    match policy {
        OverlapPolicy::Skip => {
            if registry.active_run_count(binding_id)? > 0 {
                Ok(AdmissionDecision::SkipDueToOverlap)
            } else {
                registry.note_admitted(binding_id)?;
                Ok(AdmissionDecision::Admit)
            }
        }
        OverlapPolicy::Concurrent { max } => {
            let max = max.min(MAX_OVERLAP_CONCURRENCY);
            if registry.active_run_count(binding_id)? < max {
                registry.note_admitted(binding_id)?;
                Ok(AdmissionDecision::Admit)
            } else {
                Ok(AdmissionDecision::SkipDueToOverlap)
            }
        }
        OverlapPolicy::Queue { depth } => {
            let depth = depth.min(MAX_OVERLAP_QUEUE_DEPTH);
            let active = registry.active_run_count(binding_id)?;
            let queued = registry.queued_count(binding_id)?;
            // E (fix round 1): admit immediately only when *nothing* —
            // running or already waiting — is ahead of this occurrence.
            // Checking `active == 0` alone let an arrival jump the entire
            // queue whenever the running occurrence finished before the
            // flow layer got around to promoting the oldest queued one,
            // inverting the queue to LIFO and starving older occurrences
            // under a sustained stream.
            if active == 0 && queued == 0 {
                registry.note_admitted(binding_id)?;
                Ok(AdmissionDecision::Admit)
            } else if queued < depth {
                registry.note_queued(binding_id)?;
                Ok(AdmissionDecision::QueueAt(queued))
            } else {
                tracing::warn!(
                    binding_id = %binding_id,
                    depth,
                    "overlap-policy Queue backlog is full; dropping occurrence as backpressure"
                );
                Ok(AdmissionDecision::SkippedQueueFull { depth })
            }
        }
        OverlapPolicy::CancelPrevious => {
            if registry.active_run_count(binding_id)? > 0 {
                match registry.cancel_active(binding_id)? {
                    CancellationOutcome::Confirmed => {
                        registry.note_admitted(binding_id)?;
                        Ok(AdmissionDecision::CancelledPreviousAndAdmit)
                    }
                    CancellationOutcome::Unconfirmed => {
                        tracing::warn!(
                            binding_id = %binding_id,
                            "CancelPrevious could not confirm the previous run terminated; \
                             refusing to admit a replacement"
                        );
                        Ok(AdmissionDecision::SkippedCancellationUnconfirmed)
                    }
                }
            } else {
                registry.note_admitted(binding_id)?;
                Ok(AdmissionDecision::CancelledPreviousAndAdmit)
            }
        }
    }
}

/// The crate-supported way to share one [`RunRegistry`] across concurrent
/// callers (threads or async tasks). See the [module docs](self) for why
/// `&mut self` alone cannot provide this on its own — `SharedRegistry`
/// holds a `std::sync::Mutex` locked for an entire [`decide_admission`]
/// call, so two callers racing the same binding are fully serialized.
///
/// Only usable for a single in-process registry value. A registry backed
/// by a real database shared across multiple processes needs its own
/// atomicity story (one transaction or one conditional statement per
/// decision — see the module docs) rather than this wrapper.
pub struct SharedRegistry<R> {
    inner: Mutex<R>,
}

impl<R: RunRegistry> SharedRegistry<R> {
    pub fn new(registry: R) -> Self {
        SharedRegistry {
            inner: Mutex::new(registry),
        }
    }

    /// Runs [`decide_admission`] against the wrapped registry with the
    /// lock held for the call's entire duration. This is the supported
    /// way to share a [`RunRegistry`] across concurrent callers — never
    /// decompose this into a separate lock/read/decide/write/unlock
    /// sequence at the call site; that reintroduces the exact race this
    /// type exists to close.
    pub fn decide(
        &self,
        policy: OverlapPolicy,
        binding_id: BindingId,
    ) -> Result<AdmissionDecision, RegistryError> {
        let mut guard = self.lock()?;
        decide_admission(policy, &mut *guard, binding_id)
    }

    /// Records a run's completion under the same lock discipline as
    /// [`Self::decide`] (see [`RunRegistry::note_finished`]).
    pub fn note_finished(&self, binding_id: BindingId) -> Result<(), RegistryError> {
        self.lock()?.note_finished(binding_id)
    }

    /// Records a queued occurrence's dequeue under the same lock
    /// discipline as [`Self::decide`] (see [`RunRegistry::note_dequeued`]).
    pub fn note_dequeued(&self, binding_id: BindingId) -> Result<(), RegistryError> {
        self.lock()?.note_dequeued(binding_id)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, R>, RegistryError> {
        // A poisoned mutex means some previous holder panicked mid-call,
        // possibly after mutating the registry but before its invariants
        // were restored. Recovering the guard and proceeding as if nothing
        // happened would risk making decisions against corrupted state;
        // failing closed instead (Ruling: see `RegistryError::Poisoned`).
        self.inner.lock().map_err(|_| RegistryError::Poisoned)
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

    /// A registry whose reads always fail — for proving `decide_admission`
    /// fails closed (denies) rather than defaulting an unreadable count to
    /// `0` (which would admit).
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

    #[test]
    fn concurrent_admits_up_to_max_then_skips() {
        let binding_id = BindingId::new();
        let mut registry = FakeRegistry::default();
        let policy = OverlapPolicy::Concurrent { max: 2 };

        assert_eq!(
            decide_admission(policy, &mut registry, binding_id).unwrap(),
            AdmissionDecision::Admit
        );
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
    fn queue_bounds_backlog_independently_of_active_count() {
        let binding_id = BindingId::new();
        let mut registry = FakeRegistry::default();
        let policy = OverlapPolicy::Queue { depth: 2 };

        // First occurrence: nothing active, admitted immediately.
        assert_eq!(
            decide_admission(policy, &mut registry, binding_id).unwrap(),
            AdmissionDecision::Admit
        );
        // Now something is active; subsequent occurrences queue up to depth.
        assert_eq!(
            decide_admission(policy, &mut registry, binding_id).unwrap(),
            AdmissionDecision::QueueAt(0)
        );
        assert_eq!(
            decide_admission(policy, &mut registry, binding_id).unwrap(),
            AdmissionDecision::QueueAt(1)
        );
        // Queue is now at depth: further arrivals are backpressured, not
        // silently treated as more concurrency.
        assert_eq!(
            decide_admission(policy, &mut registry, binding_id).unwrap(),
            AdmissionDecision::SkippedQueueFull { depth: 2 }
        );
        assert_eq!(registry.active_run_count(binding_id).unwrap(), 1);
        assert_eq!(registry.queued_count(binding_id).unwrap(), 2);
    }

    #[test]
    fn admission_state_is_isolated_per_binding() {
        let a = BindingId::new();
        let b = BindingId::new();
        let mut registry = FakeRegistry::default();
        let policy = OverlapPolicy::Skip;

        assert_eq!(
            decide_admission(policy, &mut registry, a).unwrap(),
            AdmissionDecision::Admit
        );
        // A second, unrelated binding is unaffected by `a`'s active run.
        assert_eq!(
            decide_admission(policy, &mut registry, b).unwrap(),
            AdmissionDecision::Admit
        );
        assert_eq!(
            decide_admission(policy, &mut registry, a).unwrap(),
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
            if decide_admission(policy, &mut registry, binding_id).unwrap()
                == AdmissionDecision::Admit
            {
                admitted += 1;
            }
        }
        assert_eq!(admitted, 3);
        assert_eq!(registry.active_run_count(binding_id).unwrap(), 3);
    }

    /// B: an unreadable registry must deny, not admit. A bare-`u32` read
    /// that silently defaulted to `0` on failure would admit under every
    /// policy — exactly backwards for an availability control that exists
    /// to absorb load a degraded registry is, by definition, under.
    #[test]
    fn an_unreadable_registry_fails_closed_not_open() {
        let binding_id = BindingId::new();
        let mut registry = AlwaysFailingRegistry;

        for policy in [
            OverlapPolicy::Skip,
            OverlapPolicy::Concurrent { max: 5 },
            OverlapPolicy::Queue { depth: 5 },
            OverlapPolicy::CancelPrevious,
        ] {
            let result = decide_admission(policy, &mut registry, binding_id);
            assert!(
                result.is_err(),
                "policy {policy:?} admitted against an unreadable registry"
            );
        }
    }

    /// F: `Concurrent{max}` and `Queue{depth}` are clamped to a sane
    /// ceiling — a binding configured with `max: u32::MAX` must not
    /// actually get unbounded concurrency just because nothing else
    /// validates the policy.
    #[test]
    fn concurrent_max_is_clamped_to_the_sanity_ceiling() {
        let binding_id = BindingId::new();
        let mut registry = FakeRegistry::default();
        let policy = OverlapPolicy::Concurrent { max: u32::MAX };

        for _ in 0..MAX_OVERLAP_CONCURRENCY {
            assert_eq!(
                decide_admission(policy, &mut registry, binding_id).unwrap(),
                AdmissionDecision::Admit
            );
        }
        assert_eq!(
            decide_admission(policy, &mut registry, binding_id).unwrap(),
            AdmissionDecision::SkipDueToOverlap,
            "max: u32::MAX must still be bounded by MAX_OVERLAP_CONCURRENCY"
        );
    }

    /// D: an unconfirmed cancellation must not admit a replacement — the
    /// predecessor might still be alive.
    #[test]
    fn cancel_previous_does_not_admit_when_cancellation_is_unconfirmed() {
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
                // Requested, but (like a real SIGKILL that still can't
                // confirm an empty process group) not confirmed: the
                // active count is deliberately left unchanged.
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
        // Still 1, not 2 (no replacement admitted) and not 0 (the
        // predecessor's own count wasn't fabricated away either).
        assert_eq!(registry.active_run_count(binding_id).unwrap(), 1);
    }
}
