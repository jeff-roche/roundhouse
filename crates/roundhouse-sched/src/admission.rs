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
//! through the same `&dyn RunRegistry` borrow it used to read the counts,
//! before it returns. There is no step where a caller is trusted to
//! "remember" to record the admission later.
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
//! concurrent callers. Every [`RunRegistry`] method now takes `&self`
//! (fix round 2 — see below) because a value shared across concurrent
//! callers was always going to need interior mutability; `SharedRegistry`
//! makes that honest instead of pretending a single exclusive `&mut`
//! owner exists.
//!
//! A registry backed by a real database (e.g. SQLite via
//! `roundhouse-store`, per Ruling P4) cannot use `SharedRegistry` as-is —
//! there's no single in-process value to put behind one lock once
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
//! **Fix round 2 — the lock must be per-binding, and `cancel_active` must
//! never block.** Round 1's `SharedRegistry` held one `Mutex` across the
//! *whole registry*, keyed by nothing. Under `OverlapPolicy::CancelPrevious`
//! that lock's critical section includes a call to
//! [`RunRegistry::cancel_active`], and this module's own docs mapped that
//! to `cancel_running_shell` — an async SIGTERM → wait-up-to-`grace` →
//! SIGKILL → re-probe sequence that can legitimately run for several
//! seconds and can fail to confirm at all. A single global lock held
//! across that call means one binding stuck in a slow or
//! termination-resistant cancellation (a `D`-state process, or one that
//! traps `SIGTERM`) stalls admission for *every other binding in the
//! process* for the duration — and `TriggerSpec::Fs` defaults to
//! `CancelPrevious` with no `tick()` rate limit on that path (see the
//! deferred-hazard section below), so this needs no adversary at all.
//! Worse, a synchronous trait method has no legitimate way to wait on that
//! async primitive other than `Handle::block_on`, and calling that from
//! inside a tokio worker thread panics — poisoning the (global) lock
//! permanently.
//!
//! Two changes close this:
//! 1. [`SharedRegistry`]'s lock is now **per-binding**: a panic, a slow
//!    call, or a poisoned lock for one `BindingId` cannot stall or wedge
//!    admission for any other binding. See
//!    `shared_registry_does_not_block_unrelated_bindings` in
//!    `tests/admission.rs`.
//! 2. [`RunRegistry::cancel_active`]'s contract is now a hard requirement
//!    that it **must not block** and **must never** bridge to an async
//!    runtime via `block_on` — it requests termination and reports
//!    whatever it can confirm *synchronously, immediately*. This needs no
//!    new state machine: it composes directly with the `Unconfirmed`
//!    outcome fix round 1 already added (finding D) — a non-blocking
//!    `cancel_active` returns `Unconfirmed` for anything it can't confirm
//!    on the spot, `decide_admission` declines to admit a replacement,
//!    and a *later* occurrence's call re-checks and can see `Confirmed`
//!    once the (separately, asynchronously driven) cancellation actually
//!    lands.
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
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

// Re-exported so existing callers of this module see no path change now
// that the sanity ceilings are defined alongside `OverlapPolicy` itself
// (fix round 2, finding L1) — see `crate::trigger` for the values and the
// reasoning.
pub use crate::trigger::{MAX_OVERLAP_CONCURRENCY, MAX_OVERLAP_QUEUE_DEPTH};

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
    /// `note_dequeued`/`note_promoted`) would have overflowed or
    /// underflowed. Implementors must report this instead of wrapping — a
    /// wrapping `+= 1` on a `u32::MAX` counter silently becomes `0`, which
    /// is exactly the fail-open failure mode this whole gate exists to
    /// prevent.
    #[error(
        "run registry counter for binding {binding_id} would overflow or underflow; \
         admission gate fails closed"
    )]
    CounterOutOfRange { binding_id: BindingId },
    /// A [`SharedRegistry`]'s internal lock was poisoned by a panic while
    /// a previous call held it. The wrapped registry's state after a panic
    /// mid-mutation cannot be trusted, so this also fails closed rather
    /// than silently recovering the poisoned guard's contents.
    ///
    /// Fix round 2: [`SharedRegistry`]'s locks are per-binding, so a
    /// poison event denies admission only for the `BindingId` whose lock
    /// was held at the time of the panic — every other binding continues
    /// operating normally. `decide`/`note_finished`/`note_dequeued`/
    /// `note_promoted` all emit `tracing::error!` at the moment a poison
    /// is detected, naming the affected binding, so the outage is
    /// observable rather than silently inferred from a stream of `Err`
    /// returns. **Operator recovery:** a poisoned in-process lock has no
    /// programmatic reset exposed today (`SharedRegistry` does not hand
    /// out its internal lock handles); the supported recovery path is
    /// restarting the daemon process, which drops every lock — poisoned
    /// or not — along with the in-memory registry state itself. A future
    /// enhancement could expose a per-binding `clear_poison`-style
    /// recovery call if operational experience shows a restart is too
    /// coarse; that is out of scope for this fix round.
    #[error("admission lock for binding {binding_id} is poisoned; admission gate fails closed")]
    Poisoned { binding_id: BindingId },
}

/// How a [`RunRegistry::cancel_active`] attempt actually concluded.
/// Distinct from a plain `bool` so the two states are named, not
/// inferred, at every call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancellationOutcome {
    /// The previous run is verified stopped.
    Confirmed,
    /// Cancellation was requested but could not be confirmed
    /// synchronously. The previous run may still be alive.
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
/// Every method takes `&self`, not `&mut self` (fix round 2): a
/// `RunRegistry` shared across concurrent callers always needs interior
/// mutability in any real implementation (there is no way to hand out
/// `&mut` to two callers at once), so implementors must provide their own
/// synchronization (a `Mutex`/`RwLock` field, a lock-free map, a DB
/// connection) rather than this trait pretending a single exclusive owner
/// exists.
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
    /// whatever can be confirmed *synchronously, without blocking*.
    ///
    /// **Hard requirement (fix round 2, finding H): this method must not
    /// block, and must never bridge to an async runtime via
    /// `Handle::block_on` or equivalent.** This is a documentation-only
    /// requirement — nothing in this trait or in `decide_admission` can
    /// check it at compile time or at runtime; a violating implementation
    /// still type-checks and still compiles. The per-binding lock in
    /// [`SharedRegistry`] is the *containment*, not an enforcement of this
    /// rule: precisely *because* the crate cannot verify an implementor
    /// obeys it, blast radius is scoped so that a violation (a
    /// blocking, or a panicking, `cancel_active`) can only ever stall or
    /// poison the one `BindingId` whose lock it runs under, never any
    /// other binding. A call that blocks for any real amount of time
    /// stalls every other admission decision *for that one binding* for
    /// as long as it blocks, and calling `block_on` from within a tokio
    /// worker thread panics outright, poisoning that binding's lock (see
    /// `RegistryError::Poisoned`). `roundhouse-flow`'s real
    /// implementation sits on top of
    /// `roundhouse_tools::shell::cancel::cancel_running_shell` — an async
    /// SIGTERM -> wait -> SIGKILL -> re-probe sequence that can run for
    /// multiple seconds and whose own `CancelError::GroupStillAlive`
    /// variant documents that it may never confirm at all. The correct
    /// bridge is: kick that async sequence off *without waiting for it*
    /// (e.g. `tokio::spawn` it, with the spawned task updating the
    /// registry's real state via `note_finished` once it actually
    /// confirms), and have this method report whatever is already known
    /// synchronously — which, the first time it's called for a given
    /// active run, is essentially always
    /// `CancellationOutcome::Unconfirmed`. That composes correctly with
    /// no new state machine needed:
    /// - `Ok(CancellationOutcome::Confirmed)`: the previous run is
    ///   *already* verified gone (e.g. a prior spawned cancellation
    ///   already landed). `active_run_count(binding_id)` must already
    ///   reflect 0.
    /// - `Ok(CancellationOutcome::Unconfirmed)`: cancellation has been
    ///   requested (or was already in flight) but nothing confirms
    ///   termination yet. The implementor must **not** report
    ///   `active_run_count` as 0 — the process group may still be alive.
    ///   [`decide_admission`] fails closed on this: it will not admit a
    ///   replacement run on top of a predecessor that might still be
    ///   running. A *later* occurrence's call will see `Confirmed` once
    ///   the spawned cancellation actually completes and updates the
    ///   registry.
    /// - `Err(RegistryError)`: some other, genuine registry failure (e.g.
    ///   the underlying `CancelError::Signal`/`Wait`/`Probe` I/O error
    ///   *synchronously* returned by issuing the signal itself, as
    ///   opposed to waiting for the group to die).
    fn cancel_active(&self, binding_id: BindingId) -> Result<CancellationOutcome, RegistryError>;

    /// Records that a new run of `binding_id` is starting immediately.
    /// `active_run_count(binding_id)` must reflect the increment before
    /// this call returns.
    fn note_admitted(&self, binding_id: BindingId) -> Result<(), RegistryError>;

    /// Records that one occurrence of `binding_id` has been queued.
    /// `queued_count(binding_id)` must reflect the increment before this
    /// call returns.
    fn note_queued(&self, binding_id: BindingId) -> Result<(), RegistryError>;

    /// Records that one of `binding_id`'s active runs has finished.
    /// `active_run_count(binding_id)` must reflect the decrement before
    /// this call returns. Without this release side, every
    /// `note_admitted` is permanent: a `Skip` binding that is never told
    /// its run finished is wedged shut forever (see the module docs'
    /// note on the leaked-admission hazard this closes).
    fn note_finished(&self, binding_id: BindingId) -> Result<(), RegistryError>;

    /// Records that one of `binding_id`'s queued occurrences has been
    /// removed from the backlog *without* starting it (e.g. the binding
    /// was disabled, or the queued occurrence expired). `queued_count`
    /// must reflect the decrement before this call returns.
    ///
    /// Do **not** use this when a queued occurrence is being promoted to
    /// running — use [`Self::note_promoted`] for that. Calling
    /// `note_dequeued` followed by a separate `note_admitted` for the same
    /// promotion reopens a real race: a `decide_admission` call for a
    /// third occurrence landing in the gap between those two calls can
    /// observe `queued_count == 0 && active_run_count == 0` (the
    /// momentarily-decremented queue, before the increment lands) and
    /// admit immediately — jumping ahead of the very occurrence that was
    /// mid-promotion (fix round 2, finding M1).
    fn note_dequeued(&self, binding_id: BindingId) -> Result<(), RegistryError>;

    /// Records that one of `binding_id`'s queued occurrences has been
    /// promoted to running — `queued_count` decremented and
    /// `active_run_count` incremented **together**, both visible before
    /// this call returns. This is the only correct way to move an
    /// occurrence out of the queue and into execution; see
    /// [`Self::note_dequeued`]'s doc comment for the race two separate
    /// calls would reopen.
    fn note_promoted(&self, binding_id: BindingId) -> Result<(), RegistryError>;
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
    /// under load" (this) from "suppression by design" (that). Logged via
    /// `tracing::warn!`, rate-limited per binding (see the module's
    /// internal `DropLogGate`) so a sustained flood cannot itself become a
    /// logging flood.
    SkippedQueueFull { depth: u32 },
    /// `CancelPrevious` found an active run but could not confirm it
    /// actually stopped; the replacement was **not** admitted (fail
    /// closed — see [`RunRegistry::cancel_active`]'s doc comment). Logged
    /// the same way as `SkippedQueueFull`.
    SkippedCancellationUnconfirmed,
}

/// Rate-limits a repeating `tracing::warn!` for one condition (there are
/// two instances of this type: one for `Queue`-full drops, one for
/// `CancelPrevious`-unconfirmed occurrences) so a sustained flood — which
/// costs whoever's driving it nothing — cannot turn into a logging flood
/// of its own (fix round 2, finding L2). Logs are worth emitting at
/// occurrence 1, 2, 4, 8, 16, ... (so an operator sees the *start* of an
/// episode immediately, and its ongoing severity without linear volume).
///
/// **Reset semantics (corrected, fix round 3):** `decide_admission` calls
/// `reset(binding_id)` only from *this gate's own* policy branch's success
/// path — the `Queue` arm resets the queue-full gate on `Admit`/`QueueAt`,
/// the `CancelPrevious` arm resets the cancellation-unconfirmed gate on
/// `Confirmed`. It is **not** reset by "any other decision for this
/// binding", and in particular not by a *different* `OverlapPolicy`
/// entirely: if a binding's policy changes at runtime (e.g. `Queue` ->
/// `Skip` -> back to `Queue`), the queue-full gate's count for that
/// binding is untouched by the intervening `Skip` decisions and resumes
/// from wherever it left off. This is a minor, accepted imprecision (a
/// binding's `OverlapPolicy` is not expected to change mid-flood in
/// practice) rather than a bug to fix — noted here so the doc matches
/// what the code actually does.
///
/// Deliberately process-global (keyed by `BindingId`, not by which
/// `RunRegistry`/`SharedRegistry` instance is asking): this is purely a
/// log-volume control, not decision state, so sharing it across every
/// registry in the process is harmless and keeps `decide_admission`
/// itself free of extra parameters.
#[derive(Default)]
struct DropLogGate {
    counts: Mutex<HashMap<BindingId, u64>>,
    // Fix round 3, finding 3: `reset` is called from every *success* path
    // (the overwhelmingly common case) of the policy branch it belongs
    // to, but almost always has nothing to remove. Without this flag,
    // every such call — for every binding, on every admission — would
    // acquire this gate's single `Mutex`, reintroducing exactly the kind
    // of global contention on the hot path that per-binding locking
    // (fix round 2, finding H) was about eliminating. `has_any` lets the
    // overwhelmingly common "nothing has ever gone wrong on this gate"
    // case skip the lock entirely; once anything has actually triggered a
    // drop (a real anomaly), later `reset` calls fall back to acquiring
    // the lock as before, which is an acceptable cost only in the
    // already-degraded case this gate exists to log.
    has_any: std::sync::atomic::AtomicBool,
}

impl DropLogGate {
    /// Notes one more occurrence for `binding_id` and returns the running
    /// count for this episode.
    fn note(&self, binding_id: BindingId) -> u64 {
        self.has_any
            .store(true, std::sync::atomic::Ordering::Relaxed);
        // A poisoned counter here is a logging-volume concern, not a
        // correctness one — recover rather than propagate, unlike every
        // other lock in this module.
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = counts.entry(binding_id).or_insert(0);
        *entry += 1;
        *entry
    }

    /// Ends `binding_id`'s current episode, so the next one starts at 1.
    fn reset(&self, binding_id: BindingId) {
        if !self.has_any.load(std::sync::atomic::Ordering::Relaxed) {
            // Nothing has ever been recorded on this gate (for any
            // binding), so there is certainly nothing to remove for this
            // one — skip the lock entirely.
            return;
        }
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        counts.remove(&binding_id);
    }

    /// Whether `count` (as returned by [`Self::note`]) is worth a log
    /// line: the first occurrence, then every power of two after it.
    fn is_log_worthy(count: u64) -> bool {
        count.is_power_of_two()
    }
}

fn queue_full_drop_gate() -> &'static DropLogGate {
    static GATE: OnceLock<DropLogGate> = OnceLock::new();
    GATE.get_or_init(DropLogGate::default)
}

fn cancellation_unconfirmed_drop_gate() -> &'static DropLogGate {
    static GATE: OnceLock<DropLogGate> = OnceLock::new();
    GATE.get_or_init(DropLogGate::default)
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
    registry: &dyn RunRegistry,
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
                queue_full_drop_gate().reset(binding_id);
                Ok(AdmissionDecision::Admit)
            } else if queued < depth {
                registry.note_queued(binding_id)?;
                queue_full_drop_gate().reset(binding_id);
                Ok(AdmissionDecision::QueueAt(queued))
            } else {
                let count = queue_full_drop_gate().note(binding_id);
                if DropLogGate::is_log_worthy(count) {
                    tracing::warn!(
                        binding_id = %binding_id,
                        depth,
                        dropped_so_far = count,
                        "overlap-policy Queue backlog is full; dropping occurrences as \
                         backpressure (logged at drop 1, 2, 4, 8, ... to bound log volume \
                         under a sustained flood)"
                    );
                }
                Ok(AdmissionDecision::SkippedQueueFull { depth })
            }
        }
        OverlapPolicy::CancelPrevious => {
            if registry.active_run_count(binding_id)? > 0 {
                match registry.cancel_active(binding_id)? {
                    CancellationOutcome::Confirmed => {
                        registry.note_admitted(binding_id)?;
                        cancellation_unconfirmed_drop_gate().reset(binding_id);
                        Ok(AdmissionDecision::CancelledPreviousAndAdmit)
                    }
                    CancellationOutcome::Unconfirmed => {
                        let count = cancellation_unconfirmed_drop_gate().note(binding_id);
                        if DropLogGate::is_log_worthy(count) {
                            tracing::warn!(
                                binding_id = %binding_id,
                                occurrences_so_far = count,
                                "CancelPrevious could not confirm the previous run terminated; \
                                 refusing to admit a replacement (logged at occurrence 1, 2, 4, \
                                 8, ... to bound log volume under a sustained flood)"
                            );
                        }
                        Ok(AdmissionDecision::SkippedCancellationUnconfirmed)
                    }
                }
            } else {
                registry.note_admitted(binding_id)?;
                cancellation_unconfirmed_drop_gate().reset(binding_id);
                Ok(AdmissionDecision::CancelledPreviousAndAdmit)
            }
        }
    }
}

/// The crate-supported way to share one [`RunRegistry`] across concurrent
/// callers (threads or async tasks). See the [module docs](self) for why
/// `&mut self` alone cannot provide this on its own.
///
/// **Fix round 2:** the lock here is **per-binding**, not one lock for the
/// whole registry. A `Mutex` per `BindingId` is created on first use and
/// held for the entire [`decide_admission`] (or `note_*`) call, so two
/// callers racing the *same* binding are fully serialized, while calls
/// for *different* bindings never wait on each other — a slow, panicking,
/// or poisoned call for one binding cannot stall or wedge any other
/// binding's admission decisions. See
/// `shared_registry_does_not_block_unrelated_bindings` and
/// `shared_registry_never_lets_two_calls_run_concurrently_for_one_binding`
/// in `tests/admission.rs`.
///
/// Only usable for a single in-process registry value. A registry backed
/// by a real database shared across multiple processes needs its own
/// atomicity story (one transaction or one conditional statement per
/// decision — see the module docs) rather than this wrapper.
///
/// **Caller obligation (fix round 3, finding 2): `binding_locks` never
/// evicts.** Every distinct `BindingId` ever passed to [`Self::decide`] or
/// any `note_*` method permanently allocates one `Arc<Mutex<()>>` entry —
/// there is no automatic eviction, and nothing here checks that the id
/// names a real, registered binding before allocating its lock. Only ever
/// call this with a `BindingId` of an actually-registered binding (e.g.
/// one resolved from the scheduler's own `Binding` table), never with an
/// id taken directly from untrusted external input (a webhook path
/// parameter, say) — an unauthenticated caller able to invoke `decide`
/// with arbitrary UUIDs could otherwise grow this map without bound. Call
/// [`Self::forget`] when a binding is unbound/deleted to reclaim its
/// entry.
pub struct SharedRegistry<R> {
    registry: R,
    // The directory itself is protected by a short-lived lock (just a
    // hashmap get-or-insert/remove, no user code runs under it — see
    // `with_binding_lock`'s doc comment for why this essentially never
    // poisons in practice); each binding's own `Mutex<()>` is what's
    // actually held across the real work.
    binding_locks: Mutex<HashMap<BindingId, std::sync::Arc<Mutex<()>>>>,
}

impl<R: RunRegistry> SharedRegistry<R> {
    pub fn new(registry: R) -> Self {
        SharedRegistry {
            registry,
            binding_locks: Mutex::new(HashMap::new()),
        }
    }

    /// Runs [`decide_admission`] against the wrapped registry with
    /// `binding_id`'s own lock held for the call's entire duration. This
    /// is the supported way to share a [`RunRegistry`] across concurrent
    /// callers — never decompose this into a separate
    /// lock/read/decide/write/unlock sequence at the call site; that
    /// reintroduces the exact race this type exists to close.
    pub fn decide(
        &self,
        policy: OverlapPolicy,
        binding_id: BindingId,
    ) -> Result<AdmissionDecision, RegistryError> {
        self.with_binding_lock(binding_id, || {
            decide_admission(policy, &self.registry, binding_id)
        })
    }

    /// Consumes the `SharedRegistry`, returning the wrapped registry.
    /// Useful for graceful-shutdown paths that want to inspect or persist
    /// final state, and for tests that need to assert on the wrapped
    /// registry's own state directly.
    ///
    /// **Do not re-share the returned `R` across concurrent callers
    /// directly** (e.g. by putting it behind a new `Arc<R>` without a
    /// `Mutex`, or by handing clones to multiple tasks) — doing so
    /// silently drops the per-binding locking discipline this type exists
    /// to provide, reopening the exact race fix round 2 closed. If the
    /// registry needs to be shared again, re-wrap it in a *new*
    /// `SharedRegistry::new(...)` first.
    pub fn into_inner(self) -> R {
        self.registry
    }

    /// Reclaims `binding_id`'s lock entry — call this when a binding is
    /// unbound/deleted so [`SharedRegistry`]'s directory does not retain
    /// an entry for it forever (see the struct's own doc comment on why
    /// the directory never evicts on its own). Safe to call even if no
    /// entry exists (a no-op) or if the binding is not currently under
    /// contention; do **not** call this while a `decide`/`note_*` call for
    /// the same `binding_id` might still be in flight elsewhere — doing so
    /// cannot corrupt state (a fresh lock is simply created on the next
    /// call), but it does mean that in-flight call's lock is no longer the
    /// one new callers will contend on, briefly narrowing the mutual
    /// exclusion this type provides for that one id.
    pub fn forget(&self, binding_id: BindingId) -> Result<(), RegistryError> {
        let mut directory = self.binding_locks.lock().map_err(|_| {
            tracing::error!(
                "SharedRegistry's binding-lock directory was poisoned; admission is \
                 denied for ALL bindings until the process is restarted"
            );
            RegistryError::Poisoned { binding_id }
        })?;
        directory.remove(&binding_id);
        Ok(())
    }

    /// Records a run's completion under the same per-binding lock
    /// discipline as [`Self::decide`] (see [`RunRegistry::note_finished`]).
    pub fn note_finished(&self, binding_id: BindingId) -> Result<(), RegistryError> {
        self.with_binding_lock(binding_id, || self.registry.note_finished(binding_id))
    }

    /// Records a queued occurrence's removal without starting it, under
    /// the same lock discipline as [`Self::decide`] (see
    /// [`RunRegistry::note_dequeued`]).
    pub fn note_dequeued(&self, binding_id: BindingId) -> Result<(), RegistryError> {
        self.with_binding_lock(binding_id, || self.registry.note_dequeued(binding_id))
    }

    /// Records a queued occurrence's promotion to running, under the same
    /// lock discipline as [`Self::decide`] (see
    /// [`RunRegistry::note_promoted`]).
    pub fn note_promoted(&self, binding_id: BindingId) -> Result<(), RegistryError> {
        self.with_binding_lock(binding_id, || self.registry.note_promoted(binding_id))
    }

    /// Looks up (creating if necessary) `binding_id`'s own lock, holds it
    /// for the duration of `f`, and runs `f`. `f` must not block for any
    /// real amount of time (see [`RunRegistry::cancel_active`]'s "must not
    /// block" requirement, which is what this is here to contain) and
    /// must not call back into this `SharedRegistry` for **any**
    /// `binding_id` — not just the same one.
    ///
    /// Fix round 3, finding 4: an earlier version of this doc only
    /// forbade re-entrancy for *the same* `binding_id` (which does matter
    /// — it self-deadlocks on `std::sync::Mutex`, which is not
    /// reentrant). But permitting cross-binding re-entrancy by omission is
    /// the more dangerous case: a call already holding binding A's lock
    /// that calls back in for binding B establishes an A-then-B lock
    /// order; a concurrent call doing the reverse (holding B, calling in
    /// for A) is a textbook ABBA deadlock that hangs both threads
    /// permanently. Nothing in a `RunRegistry` implementation should ever
    /// need to call back into its own `SharedRegistry` wrapper regardless
    /// of which binding is named, so the rule is simply: don't.
    fn with_binding_lock<T>(
        &self,
        binding_id: BindingId,
        f: impl FnOnce() -> Result<T, RegistryError>,
    ) -> Result<T, RegistryError> {
        let lock = {
            // Held only long enough to get-or-insert one map entry — no
            // user-supplied code runs in this critical section, so in
            // practice this directory lock does not poison; if it ever
            // did, that failure is genuinely global (there would be no
            // way to look up *any* binding's own lock), unlike the
            // per-binding poison case below.
            let mut directory = self.binding_locks.lock().map_err(|_| {
                tracing::error!(
                    "SharedRegistry's binding-lock directory was poisoned; admission is \
                     denied for ALL bindings until the process is restarted"
                );
                RegistryError::Poisoned { binding_id }
            })?;
            std::sync::Arc::clone(
                directory
                    .entry(binding_id)
                    .or_insert_with(|| std::sync::Arc::new(Mutex::new(()))),
            )
        };
        let _guard = lock.lock().map_err(|_| {
            tracing::error!(
                binding_id = %binding_id,
                "admission lock for this binding was poisoned by a panicking holder; \
                 admission is denied for this binding until the process is restarted \
                 (poisoning is scoped to this binding only — other bindings are unaffected)"
            );
            RegistryError::Poisoned { binding_id }
        })?;
        f()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    #[derive(Default)]
    struct FakeRegistry {
        active: StdMutex<HashMap<BindingId, u32>>,
        queued: StdMutex<HashMap<BindingId, u32>>,
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
        fn cancel_active(
            &self,
            binding_id: BindingId,
        ) -> Result<CancellationOutcome, RegistryError> {
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
        // Fix round 3, finding 5: two separate critical sections (queued,
        // then active), which only satisfies `note_promoted`'s "both
        // visible together" contract because every real caller reaches
        // this through `SharedRegistry::note_promoted`'s per-binding
        // lock — see `tests/admission.rs`'s identical `FakeRegistry` for
        // the full explanation aimed at implementors who'd copy this
        // shape.
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

    #[test]
    fn concurrent_admits_up_to_max_then_skips() {
        let binding_id = BindingId::new();
        let registry = FakeRegistry::default();
        let policy = OverlapPolicy::Concurrent { max: 2 };

        assert_eq!(
            decide_admission(policy, &registry, binding_id).unwrap(),
            AdmissionDecision::Admit
        );
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
    fn queue_bounds_backlog_independently_of_active_count() {
        let binding_id = BindingId::new();
        let registry = FakeRegistry::default();
        let policy = OverlapPolicy::Queue { depth: 2 };

        // First occurrence: nothing active, admitted immediately.
        assert_eq!(
            decide_admission(policy, &registry, binding_id).unwrap(),
            AdmissionDecision::Admit
        );
        // Now something is active; subsequent occurrences queue up to depth.
        assert_eq!(
            decide_admission(policy, &registry, binding_id).unwrap(),
            AdmissionDecision::QueueAt(0)
        );
        assert_eq!(
            decide_admission(policy, &registry, binding_id).unwrap(),
            AdmissionDecision::QueueAt(1)
        );
        // Queue is now at depth: further arrivals are backpressured, not
        // silently treated as more concurrency.
        assert_eq!(
            decide_admission(policy, &registry, binding_id).unwrap(),
            AdmissionDecision::SkippedQueueFull { depth: 2 }
        );
        assert_eq!(registry.active_run_count(binding_id).unwrap(), 1);
        assert_eq!(registry.queued_count(binding_id).unwrap(), 2);
    }

    #[test]
    fn admission_state_is_isolated_per_binding() {
        let a = BindingId::new();
        let b = BindingId::new();
        let registry = FakeRegistry::default();
        let policy = OverlapPolicy::Skip;

        assert_eq!(
            decide_admission(policy, &registry, a).unwrap(),
            AdmissionDecision::Admit
        );
        // A second, unrelated binding is unaffected by `a`'s active run.
        assert_eq!(
            decide_admission(policy, &registry, b).unwrap(),
            AdmissionDecision::Admit
        );
        assert_eq!(
            decide_admission(policy, &registry, a).unwrap(),
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
        let registry = FakeRegistry::default();
        let policy = OverlapPolicy::Concurrent { max: 3 };

        let mut admitted = 0;
        for _ in 0..100 {
            if decide_admission(policy, &registry, binding_id).unwrap() == AdmissionDecision::Admit
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
        let registry = AlwaysFailingRegistry;

        for policy in [
            OverlapPolicy::Skip,
            OverlapPolicy::Concurrent { max: 5 },
            OverlapPolicy::Queue { depth: 5 },
            OverlapPolicy::CancelPrevious,
        ] {
            let result = decide_admission(policy, &registry, binding_id);
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
        let registry = FakeRegistry::default();
        let policy = OverlapPolicy::Concurrent { max: u32::MAX };

        for _ in 0..MAX_OVERLAP_CONCURRENCY {
            assert_eq!(
                decide_admission(policy, &registry, binding_id).unwrap(),
                AdmissionDecision::Admit
            );
        }
        assert_eq!(
            decide_admission(policy, &registry, binding_id).unwrap(),
            AdmissionDecision::SkipDueToOverlap,
            "max: u32::MAX must still be bounded by MAX_OVERLAP_CONCURRENCY"
        );
    }

    /// D: an unconfirmed cancellation must not admit a replacement — the
    /// predecessor might still be alive.
    #[test]
    fn cancel_previous_does_not_admit_when_cancellation_is_unconfirmed() {
        struct UnconfirmedCancelRegistry {
            active: StdMutex<HashMap<BindingId, u32>>,
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
                // Requested, but (like a real, non-blocking SIGTERM whose
                // effect hasn't been re-probed yet) not confirmed: the
                // active count is deliberately left unchanged.
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
            active: StdMutex::new(HashMap::from([(binding_id, 1)])),
        };
        let decision =
            decide_admission(OverlapPolicy::CancelPrevious, &registry, binding_id).unwrap();
        assert_eq!(decision, AdmissionDecision::SkippedCancellationUnconfirmed);
        // Still 1, not 2 (no replacement admitted) and not 0 (the
        // predecessor's own count wasn't fabricated away either).
        assert_eq!(registry.active_run_count(binding_id).unwrap(), 1);
    }

    /// M1: `note_promoted` must move a queued occurrence to active in one
    /// call — `queued_count` and `active_run_count` both update together,
    /// and the gate's subsequent view of the binding is consistent (the
    /// promoted run is now counted as active, so a further occurrence
    /// queues behind it rather than jumping ahead).
    #[test]
    fn note_promoted_moves_a_queued_occurrence_to_active_in_one_call() {
        let binding_id = BindingId::new();
        let registry = FakeRegistry::default();
        let policy = OverlapPolicy::Queue { depth: 2 };

        // Occurrence 1 admitted; occurrence 2 queues behind it.
        assert_eq!(
            decide_admission(policy, &registry, binding_id).unwrap(),
            AdmissionDecision::Admit
        );
        assert_eq!(
            decide_admission(policy, &registry, binding_id).unwrap(),
            AdmissionDecision::QueueAt(0)
        );

        // Occurrence 1 finishes; the flow layer promotes occurrence 2.
        registry.note_finished(binding_id).unwrap();
        registry.note_promoted(binding_id).unwrap();
        assert_eq!(registry.active_run_count(binding_id).unwrap(), 1);
        assert_eq!(registry.queued_count(binding_id).unwrap(), 0);

        // Occurrence 3 arrives: the promoted run is correctly counted as
        // active, so this queues rather than jumping ahead or double-admitting.
        assert_eq!(
            decide_admission(policy, &registry, binding_id).unwrap(),
            AdmissionDecision::QueueAt(0)
        );
    }

    /// The `note_dequeued`/`CounterOutOfRange` paths the fix-round-2
    /// review flagged as untested: a queued occurrence can be dropped
    /// without ever starting (distinct from `note_promoted`), and an
    /// implementor's own counter arithmetic must report underflow rather
    /// than wrap.
    #[test]
    fn note_dequeued_drops_a_queued_occurrence_without_starting_it() {
        let binding_id = BindingId::new();
        let registry = FakeRegistry::default();
        let policy = OverlapPolicy::Queue { depth: 2 };

        decide_admission(policy, &registry, binding_id).unwrap(); // Admit
        decide_admission(policy, &registry, binding_id).unwrap(); // QueueAt(0)

        registry.note_dequeued(binding_id).unwrap();
        assert_eq!(registry.queued_count(binding_id).unwrap(), 0);
        // Unaffected — the active run was never touched by this dequeue.
        assert_eq!(registry.active_run_count(binding_id).unwrap(), 1);
    }

    #[test]
    fn note_finished_reports_counter_out_of_range_on_underflow() {
        let binding_id = BindingId::new();
        let registry = FakeRegistry::default();
        assert_eq!(
            registry.note_finished(binding_id).unwrap_err(),
            RegistryError::CounterOutOfRange { binding_id }
        );
    }

    #[test]
    fn note_dequeued_reports_counter_out_of_range_on_underflow() {
        let binding_id = BindingId::new();
        let registry = FakeRegistry::default();
        assert_eq!(
            registry.note_dequeued(binding_id).unwrap_err(),
            RegistryError::CounterOutOfRange { binding_id }
        );
    }

    /// Pure-logic coverage for the L2 rate limiter, independent of
    /// `tracing`'s own output (which nothing here asserts on): the count
    /// sequence that's "log worthy" is 1, 2, 4, 8, ... and `reset` starts
    /// a fresh episode at 1 again.
    #[test]
    fn drop_log_gate_is_worth_logging_at_powers_of_two_and_resets() {
        assert!(DropLogGate::is_log_worthy(1));
        assert!(DropLogGate::is_log_worthy(2));
        assert!(!DropLogGate::is_log_worthy(3));
        assert!(DropLogGate::is_log_worthy(4));
        assert!(!DropLogGate::is_log_worthy(5));
        assert!(!DropLogGate::is_log_worthy(7));
        assert!(DropLogGate::is_log_worthy(8));

        let gate = DropLogGate::default();
        let binding_id = BindingId::new();
        assert_eq!(gate.note(binding_id), 1);
        assert_eq!(gate.note(binding_id), 2);
        assert_eq!(gate.note(binding_id), 3);
        gate.reset(binding_id);
        assert_eq!(gate.note(binding_id), 1);

        // Independent of other bindings.
        let other = BindingId::new();
        assert_eq!(gate.note(other), 1);
    }

    #[test]
    fn fake_registry_with_active_seeds_the_active_count() {
        let binding_id = BindingId::new();
        let registry = FakeRegistry::with_active(binding_id, 3);
        assert_eq!(registry.active_run_count(binding_id).unwrap(), 3);
    }

    /// Finding 2: `SharedRegistry::forget` reclaims a binding's lock entry,
    /// and — since the wrapped `RunRegistry`'s own state is untouched by
    /// this — a later `decide` for the same binding still behaves
    /// correctly against a freshly-created lock.
    #[test]
    fn forget_reclaims_a_binding_lock_entry_without_disturbing_registry_state() {
        let binding_id = BindingId::new();
        let shared = SharedRegistry::new(FakeRegistry::default());

        assert_eq!(
            shared.decide(OverlapPolicy::Skip, binding_id).unwrap(),
            AdmissionDecision::Admit
        );
        shared.forget(binding_id).unwrap();
        // Forgetting the lock entry is not the same as forgetting the
        // binding's run state: the underlying registry still reports the
        // active run, so a fresh lock still enforces `Skip` correctly.
        assert_eq!(
            shared.decide(OverlapPolicy::Skip, binding_id).unwrap(),
            AdmissionDecision::SkipDueToOverlap
        );
    }
}
