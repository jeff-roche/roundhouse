//! Monotonic-timer min-heap scheduler with drift detection.
//!
//! Phase 5, Subsystem A, Task 3. Consumes `Binding` (Task 1) and
//! `next_fire_after`/`fire_all_ambiguous`/`is_ambiguous_local` (Task 2); its
//! `SchedulerEvent`s are consumed by the `trigger_event` persistence/dedupe
//! task (Task 4) and the overlap-policy admission task (Task 5). See
//! `docs/architecture/05-scheduling-and-workflows.md`.
//!
//! **Monotonic vs. wall clock, and why both are read every tick.** A
//! scheduler that only reads the wall clock cannot tell "the wall clock
//! jumped" from "time actually passed" — an NTP step, a manual clock change,
//! or a suspend/resume cycle all move `Utc::now()` without any real time
//! having elapsed on the machine's monotonic counter. [`ClockSource`]
//! exposes both readings so [`Scheduler::tick`] can compare how much time
//! *actually* passed (`tokio::time::Instant`, monotonic, immune to wall-clock
//! adjustments) against how much the wall clock *reports* passed
//! (`DateTime<Utc>`). When the two disagree by more than [`DRIFT_THRESHOLD`],
//! that is drift — not "usually about on time" — and it is measured, not
//! assumed: a full recompute is forced from the new wall-clock reading
//! rather than trusting the heap's already-computed fire times, any of which
//! could now be stale (in the past, or wildly in the future) relative to
//! wall-clock reality.
use crate::cron::{fire_all_ambiguous, is_ambiguous_local, next_fire_after, CronError};
use crate::store::{catch_up_policy, compute_catch_up};
use crate::trigger::{Binding, CatchUp, DstAmbiguous, TriggerSpec};
use chrono::{DateTime, Utc};
use roundhouse_core::BindingId;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::time::Duration;
use tokio::time::Instant;

/// Test-injectable source of both the monotonic and wall clocks. Production
/// code uses [`SystemClock`]; tests use a fake whose two readings can be
/// advanced independently of each other, so drift is reproduced
/// deterministically rather than by sleeping and hoping.
pub trait ClockSource {
    fn monotonic_now(&self) -> Instant;
    fn wall_now(&self) -> DateTime<Utc>;
}

/// The real clock: `tokio::time::Instant::now()` for the monotonic reading
/// (unaffected by wall-clock adjustments) and `Utc::now()` for wall time.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl ClockSource for SystemClock {
    fn monotonic_now(&self) -> Instant {
        Instant::now()
    }
    fn wall_now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SchedulerEvent {
    Fire(BindingId, DateTime<Utc>),
    DriftDetected {
        monotonic_elapsed: Duration,
        wall_elapsed: Duration,
    },
}

/// Beyond this much disagreement between the monotonic and wall-clock
/// readings since the previous tick, the wall clock is considered to have
/// stepped (NTP correction, manual change, suspend/resume) rather than
/// merely to have ticked normally, and every binding is recomputed from
/// scratch against the new wall-clock reading.
const DRIFT_THRESHOLD: Duration = Duration::from_secs(2);

/// M5: hard ceiling on how many missed occurrences a single binding's
/// catch-up pass considers in one `tick()` call. Without this, a binding
/// that was offline for an extended period (e.g. a daemon down for a month
/// with a `* * * * *` cron) would have its entire backlog computed and,
/// under `CatchUp::All`, fired in one pass — unbounded work and an
/// unbounded burst of `Fire` events from a single tick. A binding whose
/// backlog exceeds this cap simply catches up progressively: each `tick()`
/// call processes at most one capped batch per binding, deferring the rest
/// to the next call (see `tick`'s `processed_this_tick` guard). Chosen
/// generously above what any realistic short outage at the tightest
/// practical cron cadence (once a minute) would produce, while still
/// bounding the worst case.
pub const MAX_CATCH_UP_OCCURRENCES_PER_BINDING_PER_TICK: usize = 100;

/// NEW-2 (fix round 2): upper bound on `TriggerSpec::Interval`'s `every`.
/// Comfortably below both degenerate magnitudes confirmed against pinned
/// chrono 0.4.45 — `chrono::TimeDelta::MAX` (~9.22e15s, beyond which
/// `chrono::Duration::from_std` returns `Err`) and the much smaller
/// ~8.3e12s threshold beyond which `DateTime<Utc> + TimeDelta` overflows
/// chrono's representable year range (max year 262143) and panics. No real
/// interval trigger fires less often than once a century (100 years ≈
/// 3.16e9 seconds — a margin of roughly six orders of magnitude below the
/// nearer of the two thresholds), so anything at or beyond this bound is
/// necessarily degenerate configuration, not a legitimate schedule.
pub const MAX_INTERVAL: Duration = Duration::from_secs(100 * 365 * 24 * 60 * 60);

/// One scheduled occurrence in the heap. Multiple entries can share a
/// `binding_id` — most obviously the two instants of a `DstAmbiguous::Both`
/// fold (Ruling P16), which are pushed as two independent entries for the
/// same binding.
#[derive(Debug, Clone, Copy)]
struct HeapEntry {
    fire_at: DateTime<Utc>,
    binding_id: BindingId,
    /// Whether firing this entry should advance the binding's schedule
    /// (recompute and push its next occurrence(s)). `false` only for the
    /// earlier instant of a `DstAmbiguous::Both` pair — the pair's *later*
    /// instant is the one that advances the schedule when it fires, so a
    /// fold is never double-scheduled by both of its own instants firing.
    advances_schedule: bool,
}

// `PartialEq`/`Eq` are implemented explicitly (rather than derived) to key
// only on `(fire_at, binding_id)` — the same fields `Ord` compares — so
// `Ord::cmp` returning `Equal` and `PartialEq::eq` returning `true` agree.
// A derived `PartialEq` would also compare `advances_schedule`, which would
// let two entries be `Ord`-equal (same heap position) yet `PartialEq`-unequal.
impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.fire_at == other.fire_at && self.binding_id == other.binding_id
    }
}

impl Eq for HeapEntry {}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // `BinaryHeap` is a max-heap; reverse so the soonest `fire_at` sorts
        // to the top. Equal fire times are broken by `binding_id` (`Uuid`
        // has a total order) rather than left to the heap's internal
        // shuffling, so which of two simultaneously-due bindings pops first
        // is deterministic and reproducible, not arbitrary.
        other
            .fire_at
            .cmp(&self.fire_at)
            .then_with(|| other.binding_id.as_uuid().cmp(&self.binding_id.as_uuid()))
    }
}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// The monotonic min-heap scheduler. Holds every registered [`Binding`] plus
/// a heap of their upcoming fire instants, and on each [`tick`](Self::tick)
/// pops whatever is now due and detects monotonic-vs-wall-clock drift.
pub struct Scheduler {
    bindings: HashMap<BindingId, Binding>,
    heap: BinaryHeap<HeapEntry>,
    last_mono: Option<Instant>,
    last_wall: Option<DateTime<Utc>>,
    /// Fix round 1 (M2, security review of Task 6): a binding whose backlog
    /// spans more than one capped `drain_due` batch needs its `CatchUp`
    /// policy applied *once, over the whole backlog* — not once per batch.
    /// Without this, `CatchUp::Latest` fires once per capped batch (a
    /// 12-hour suspend of a once-a-minute cron is ~7 batches, hence ~7
    /// fires instead of exactly one) and `CatchUp::None` can wrongly fire
    /// on a trailing batch that happens to contain exactly one occurrence.
    /// Present only while a binding is mid-backlog; the payload carries the
    /// running temporally-latest occurrence seen so far (`CatchUp::Latest`
    /// only — `None` always carries `None`, `All` doesn't need the payload
    /// at all since it fires every batch immediately and correctly). Purely
    /// in-memory bookkeeping, not persisted.
    catch_up_progress: HashMap<BindingId, Option<DateTime<Utc>>>,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl Scheduler {
    pub fn new() -> Self {
        Scheduler {
            bindings: HashMap::new(),
            heap: BinaryHeap::new(),
            last_mono: None,
            last_wall: None,
            catch_up_progress: HashMap::new(),
        }
    }

    /// Registers `binding`, computing and scheduling its next occurrence(s)
    /// (plural for a `DstAmbiguous::Both` fold) from the current wall clock.
    pub fn add_binding(
        &mut self,
        mut binding: Binding,
        clock: &dyn ClockSource,
    ) -> Result<(), CronError> {
        // Establish the drift baseline from the first clock reading this
        // scheduler ever sees, so that a *single* subsequent `tick` can
        // already detect drift relative to it. Without this, a scheduler
        // that has never ticked would have no baseline to compare against
        // on its very first tick and would silently skip drift detection
        // for it.
        if self.last_mono.is_none() {
            self.last_mono = Some(clock.monotonic_now());
            self.last_wall = Some(clock.wall_now());
        }
        let instants = Self::occurrences_after(&binding, clock.wall_now())?;
        Self::push_occurrences(&mut self.heap, &mut binding, &instants);
        self.bindings.insert(binding.id, binding);
        Ok(())
    }

    /// Computes the set of UTC instants at which `binding` should next fire,
    /// strictly after `after`. Ordinarily a single instant; two for a
    /// `DstAmbiguous::Both` cron binding whose next occurrence falls in a
    /// DST fold (Ruling P16) — `next_fire_after` alone can only ever report
    /// one instant, so `Both` is detected here via `is_ambiguous_local` and
    /// resolved via `fire_all_ambiguous` to get the real double-fire.
    fn occurrences_after(
        binding: &Binding,
        after: DateTime<Utc>,
    ) -> Result<Vec<DateTime<Utc>>, CronError> {
        match &binding.spec {
            TriggerSpec::Cron {
                expr,
                tz,
                dst_gap,
                dst_ambiguous,
                jitter,
                ..
            } => {
                let first = next_fire_after(expr, *tz, after, dst_gap, dst_ambiguous, *jitter)?;
                if matches!(dst_ambiguous, DstAmbiguous::Both) {
                    let naive_local = first.with_timezone(tz).naive_local();
                    if is_ambiguous_local(*tz, naive_local) {
                        let both = fire_all_ambiguous(expr, *tz, after)?;
                        if both.len() == 2 {
                            return Ok(both);
                        }
                    }
                }
                Ok(vec![first])
            }
            TriggerSpec::Interval { every, .. } => {
                // Fold-in fix: `every == Duration::ZERO` would make this
                // return `after` unchanged (`after + 0`) forever, which
                // `tick`'s catch-up gather loop (and, before this fix, its
                // per-fire reschedule) would treat as an always-due,
                // never-advancing occurrence — a hang from one malformed
                // binding. Refused here so `add_binding` fails fast instead.
                if every.is_zero() {
                    return Err(CronError::ZeroInterval);
                }
                // NEW-2 (fix round 2): a single upper bound rejects both of
                // the non-zero degenerate magnitudes `is_zero()` missed (see
                // `CronError::IntervalTooLarge`'s doc comment) before ever
                // reaching `chrono::Duration::from_std`/`checked_add_signed`
                // — neither of which is then allowed to silently default or
                // panic; both map to the same typed error instead.
                if *every > MAX_INTERVAL {
                    return Err(CronError::IntervalTooLarge(*every));
                }
                let delta = chrono::Duration::from_std(*every)
                    .map_err(|_| CronError::IntervalTooLarge(*every))?;
                let next = after
                    .checked_add_signed(delta)
                    .ok_or(CronError::IntervalTooLarge(*every))?;
                // `align`/`anchor` are not applied here — no task in this
                // phase's plan implements interval alignment, and Task 3's
                // scope is heap scheduling + drift detection, not that
                // feature. Left as a plain fixed-offset-from-`after` step.
                Ok(vec![next])
            }
            // Fs/Git/Webhook/RunComplete/Message/Manual are event-driven,
            // not heap-scheduled: they have no "next fire" to compute.
            TriggerSpec::Manual
            | TriggerSpec::Fs { .. }
            | TriggerSpec::Git { .. }
            | TriggerSpec::Webhook { .. }
            | TriggerSpec::RunComplete { .. }
            | TriggerSpec::Message { .. } => Ok(vec![]),
        }
    }

    /// Records `instants` on `binding.next_fire_at` (the earliest, for
    /// bookkeeping/inspection) and pushes one heap entry per instant, tagging
    /// only the last (chronologically latest) as `advances_schedule`.
    fn push_occurrences(
        heap: &mut BinaryHeap<HeapEntry>,
        binding: &mut Binding,
        instants: &[DateTime<Utc>],
    ) {
        binding.next_fire_at = instants.iter().min().copied();
        let last_index = instants.len().saturating_sub(1);
        for (index, fire_at) in instants.iter().enumerate() {
            heap.push(HeapEntry {
                fire_at: *fire_at,
                binding_id: binding.id,
                advances_schedule: index == last_index,
            });
        }
    }

    /// Recomputes every binding's next occurrence(s) from `after`, replacing
    /// the heap outright. Called on drift detection, where every
    /// already-heaped fire time is potentially stale relative to the new
    /// wall-clock reading.
    pub fn recompute_all(&mut self, after: DateTime<Utc>) {
        let mut new_heap = BinaryHeap::new();
        for binding in self.bindings.values_mut() {
            if let Ok(instants) = Self::occurrences_after(binding, after) {
                Self::push_occurrences(&mut new_heap, binding, &instants);
            }
        }
        self.heap = new_heap;
    }

    /// One scheduler tick: measures monotonic-vs-wall-clock drift since the
    /// previous tick, then pops and fires whatever is now due. Returns the
    /// events produced, in order (a `DriftDetected` event first, if drift
    /// was found, since it implies a full recompute happened before any
    /// firing decisions were made).
    pub fn tick(&mut self, clock: &dyn ClockSource) -> Vec<SchedulerEvent> {
        let mut events = Vec::new();
        let now_mono = clock.monotonic_now();
        let now_wall = clock.wall_now();

        if let (Some(last_mono), Some(last_wall)) = (self.last_mono, self.last_wall) {
            // Real drift measurement, not an approximation: compare how much
            // time the monotonic clock says passed against how much the
            // wall clock says passed, in signed arithmetic throughout, so a
            // *backward* wall-clock step (e.g. an NTP correction after a
            // suspend/resume cycle overshoots) is detected exactly as
            // reliably as a forward one. A naive unsigned
            // `(now_wall - last_wall).to_std().unwrap_or_default()` would
            // silently collapse a negative wall delta to zero and miss
            // backward steps entirely.
            let mono_elapsed = now_mono.duration_since(last_mono);
            let wall_elapsed_signed = now_wall - last_wall;
            let mono_elapsed_signed = chrono::Duration::from_std(mono_elapsed)
                .unwrap_or_else(|_| chrono::Duration::zero());
            let disagreement = (wall_elapsed_signed - mono_elapsed_signed).abs();

            if disagreement.to_std().unwrap_or(Duration::ZERO) > DRIFT_THRESHOLD {
                events.push(SchedulerEvent::DriftDetected {
                    monotonic_elapsed: mono_elapsed,
                    wall_elapsed: wall_elapsed_signed.abs().to_std().unwrap_or(Duration::ZERO),
                });
                self.recompute_all(now_wall);
            }
        }
        self.last_mono = Some(now_mono);
        self.last_wall = Some(now_wall);

        events.extend(self.drain_due(now_wall));
        events
    }

    /// Task 6 (§8.7): wake-from-suspend handling. Unlike the drift-triggered
    /// path inside [`tick`](Self::tick) — which calls
    /// [`recompute_all`](Self::recompute_all) and thereby *discards* every
    /// occurrence a binding missed, rescheduling only its next future one —
    /// a real suspend/resume must not silently drop the backlog that
    /// accumulated while the machine was asleep, nor flood the caller with
    /// an unbounded burst of catch-up fires. `recompute_all` is correct for
    /// an ordinary clock step (an NTP correction with no real backlog to
    /// speak of) but exactly wrong for this case.
    ///
    /// This reuses [`drain_due`](Self::drain_due) — the *same*
    /// per-binding-capped, `CatchUp`-policy-aware machinery `tick` already
    /// applies to a binding that merely falls behind between ordinary
    /// ticks — against the heap exactly as it stood before the sleep. Every
    /// already-heaped fire time remains a valid absolute UTC instant
    /// regardless of how long the process was suspended, so it is a
    /// perfectly good seed for `drain_due`'s missed-occurrence walk; nothing
    /// needs to be recomputed from scratch. A backlog beyond
    /// `MAX_CATCH_UP_OCCURRENCES_PER_BINDING_PER_TICK` per binding drains
    /// progressively across successive calls (a wake event, then the
    /// daemon's own regular `tick` calls), exactly as it would for any other
    /// capped catch-up pass.
    ///
    /// `monotonic_now`/`wall_now` are both taken explicitly — not read
    /// internally via a `ClockSource` — so the caller's choice of which
    /// clock backs which value is visible at the call site. They reset this
    /// scheduler's drift baseline exactly as an ordinary `tick` would,
    /// so the very next `tick` call measures drift from *this* wake instant
    /// forward and does not re-report the already-handled sleep gap as
    /// fresh drift.
    ///
    /// Fix round 1 (M1, security review of Task 6): a *backward* wall-clock
    /// reading here — the same "NTP correction after suspend/resume
    /// overshoots" scenario `tick`'s own drift check exists to catch (see
    /// its doc comment above) — is not a backlog to drain. If `wall_now` is
    /// earlier than the last wall-clock reading this scheduler saw, every
    /// already-heaped fire time is now further in the future than it was,
    /// not overdue, so `drain_due` would find nothing to do; worse, this
    /// call's own baseline reset would then suppress `tick`'s drift
    /// detection from ever catching the anomaly afterwards, since the next
    /// `tick` would measure elapsed time from this already-corrupted
    /// baseline forward. A backward step beyond `DRIFT_THRESHOLD` instead
    /// falls back to [`recompute_all`](Self::recompute_all) — exactly what
    /// `tick` does for any drift beyond that threshold — so the schedule is
    /// re-anchored to the corrected clock rather than left silently
    /// unreconciled. A forward step (the overwhelmingly common real case —
    /// an actual suspend/resume) drains as documented above.
    #[must_use]
    pub fn catch_up_after_wake(
        &mut self,
        monotonic_now: Instant,
        wall_now: DateTime<Utc>,
    ) -> Vec<SchedulerEvent> {
        let backward_step_beyond_threshold = self.last_wall.is_some_and(|last_wall| {
            (last_wall - wall_now)
                .to_std()
                .is_ok_and(|backward| backward > DRIFT_THRESHOLD)
        });

        self.last_mono = Some(monotonic_now);
        self.last_wall = Some(wall_now);

        if backward_step_beyond_threshold {
            tracing::warn!(
                "wake reported a wall clock reading earlier than the last one this scheduler \
                 saw (beyond the drift threshold); treating as a clock correction, not a \
                 catch-up backlog, and forcing a full recompute instead of draining"
            );
            self.recompute_all(wall_now);
            Vec::new()
        } else {
            self.drain_due(wall_now)
        }
    }

    /// Pops and fires whatever in the heap is now due (`fire_at <=
    /// now_wall`), applying each binding's `CatchUp` policy to any backlog
    /// found and capping the work done per binding to
    /// `MAX_CATCH_UP_OCCURRENCES_PER_BINDING_PER_TICK` (M5). Shared by
    /// [`tick`](Self::tick) (called after its own drift check) and
    /// [`catch_up_after_wake`](Self::catch_up_after_wake) (called directly,
    /// with no drift check or heap replacement first) — the two differ only
    /// in what happens *before* this runs, not in how the actual draining
    /// and catch-up capping works.
    fn drain_due(&mut self, now_wall: DateTime<Utc>) -> Vec<SchedulerEvent> {
        let mut events = Vec::new();

        // M5: bindings whose catch-up pass has already run once this call.
        // A capped pass (see the loop body below) can reschedule an
        // occurrence that is still `<= now_wall` — without this guard, the
        // outer `while` loop would immediately pop that freshly-rescheduled
        // entry and run a *second* capped pass for the same binding within
        // the same call, and so on, defeating
        // `MAX_CATCH_UP_OCCURRENCES_PER_BINDING_PER_TICK` entirely. Entries
        // deferred here are pushed back onto the heap once the loop ends, so
        // they are due again — and processed exactly once more — on the
        // *next* call.
        let mut processed_this_drain: HashSet<BindingId> = HashSet::new();
        let mut deferred: Vec<HeapEntry> = Vec::new();

        while let Some(top) = self.heap.peek() {
            if top.fire_at > now_wall {
                break;
            }
            let entry = self.heap.pop().expect("heap.peek() just returned Some");

            if !entry.advances_schedule {
                // The earlier instant of a `DstAmbiguous::Both` fold
                // (Ruling P16): always fires exactly once and never
                // accumulates catch-up backlog — the later instant is what
                // advances the schedule.
                events.push(SchedulerEvent::Fire(entry.binding_id, entry.fire_at));
                if let Some(binding) = self.bindings.get_mut(&entry.binding_id) {
                    binding.last_fired_for = Some(entry.fire_at);
                }
                continue;
            }

            if !processed_this_drain.insert(entry.binding_id) {
                deferred.push(entry);
                continue;
            }

            let Some(binding) = self.bindings.get_mut(&entry.binding_id) else {
                continue;
            };

            // Walk forward from the entry that just came due, collecting
            // every occurrence this binding missed, capped so an extended
            // outage can never flood this call with an unbounded backlog
            // (M5). A single `occurrences_after` call can yield more than
            // one instant (a `DstAmbiguous::Both` fold), so each is
            // considered individually against both the `now_wall` bound and
            // the cap, rather than only ever inspecting the first.
            //
            // `backlog_exhausted` (fix round 1, M2) distinguishes *why* the
            // gather loop stopped: `true` means it ran out of occurrences
            // that are actually due (nothing left to gather, regardless of
            // the cap) — this is the *last* batch of whatever backlog this
            // binding had. `false` means it stopped only because it hit the
            // per-call cap, with more of the same backlog still to come on
            // a later call. `CatchUp` policy needs this distinction: it
            // must be decided once over the whole backlog, not once per
            // capped batch (see below).
            let mut missed = vec![entry.fire_at];
            let mut cursor = entry.fire_at;
            let mut backlog_exhausted = false;
            'gather: while missed.len() < MAX_CATCH_UP_OCCURRENCES_PER_BINDING_PER_TICK {
                let Ok(instants) = Self::occurrences_after(binding, cursor) else {
                    backlog_exhausted = true;
                    break;
                };
                for next in instants {
                    if next > now_wall {
                        backlog_exhausted = true;
                        break 'gather;
                    }
                    cursor = next;
                    missed.push(next);
                    if missed.len() >= MAX_CATCH_UP_OCCURRENCES_PER_BINDING_PER_TICK {
                        break 'gather;
                    }
                }
            }

            // Fix round 1 (M2): the gather loop above can stop for two
            // different reasons that look identical from `missed.len()`
            // alone — it ran out of overdue occurrences
            // (`backlog_exhausted` already `true`), or it hit the per-call
            // cap exactly, with the *coincidence* that the backlog's total
            // size happens to be an exact multiple of the cap, so there is
            // also nothing left overdue. Without this lookahead, that
            // coincidence would leave `catch_up_progress` (and, for
            // `Latest`, its accumulated fire) stuck unflushed forever: no
            // *future* call would ever find a newly-overdue entry to
            // trigger the finalization check below, because the very next
            // occurrence is already in the future. Computed once and reused
            // for the reschedule below, rather than recomputed twice.
            let next_after_cursor = Self::occurrences_after(binding, cursor);
            if !backlog_exhausted {
                backlog_exhausted = match &next_after_cursor {
                    Ok(instants) => instants.iter().all(|next| *next > now_wall),
                    Err(_) => true,
                };
            }

            // M5 / fix round 1 (M2): the binding's own `CatchUp` policy
            // decides which of the missed occurrences actually fire. The
            // policy only applies to a genuine backlog (more than one
            // occurrence overdue at once, *or* the tail end of a backlog
            // that already spanned an earlier capped batch this same
            // binding — `catch_up_progress` tracks that). The ordinary
            // single-occurrence case (a normal call finding its one due
            // occurrence, whether exactly on time or a tick-interval late,
            // with no backlog before or after it) is not catching up at all
            // and must always fire regardless of `CatchUp`: `CatchUp::None`
            // means "silently drop a backlog," not "never fire this binding
            // again."
            //
            // `CatchUp::All`'s reduction is the identity (fire everything),
            // so firing each batch immediately and unconditionally is
            // already globally correct — the union of every batch's full
            // contents is the whole backlog, no cross-batch state needed.
            // `None`/`Latest` are not: reducing *each batch* independently
            // (what a naive per-batch `compute_catch_up` call would do)
            // makes `Latest` fire once per batch instead of once for the
            // whole backlog, and can make `None` wrongly fire on a trailing
            // batch that happens to contain exactly one occurrence. Both
            // are folded into `catch_up_progress`'s running
            // temporally-latest-seen value instead, and only actually fired
            // (or, for `None`, confirmed as never fired) once
            // `backlog_exhausted` says the whole backlog has been walked.
            let is_catch_up_pass =
                missed.len() > 1 || self.catch_up_progress.contains_key(&entry.binding_id);
            if is_catch_up_pass {
                if matches!(catch_up_policy(binding), Some(CatchUp::All)) {
                    for fire_at in &missed {
                        events.push(SchedulerEvent::Fire(entry.binding_id, *fire_at));
                    }
                    if backlog_exhausted {
                        self.catch_up_progress.remove(&entry.binding_id);
                    } else {
                        self.catch_up_progress
                            .entry(entry.binding_id)
                            .or_insert(None);
                    }
                } else {
                    let batch_latest = compute_catch_up(binding, missed.clone()).into_iter().max();
                    let carried = self
                        .catch_up_progress
                        .get(&entry.binding_id)
                        .copied()
                        .flatten();
                    let combined_latest = match (carried, batch_latest) {
                        (Some(a), Some(b)) => Some(a.max(b)),
                        (a, b) => a.or(b),
                    };
                    if backlog_exhausted {
                        if let Some(fire_at) = combined_latest {
                            events.push(SchedulerEvent::Fire(entry.binding_id, fire_at));
                        }
                        self.catch_up_progress.remove(&entry.binding_id);
                    } else {
                        self.catch_up_progress
                            .insert(entry.binding_id, combined_latest);
                    }
                }
            } else {
                for fire_at in &missed {
                    events.push(SchedulerEvent::Fire(entry.binding_id, *fire_at));
                }
            }
            binding.last_fired_for = missed.last().copied();

            // Reschedule from the last instant *considered*, not just the
            // last one *fired*: `CatchUp::None`/`Latest` intentionally drop
            // occurrences from what actually fires, but the schedule must
            // still advance past every considered instant, or a dropped
            // occurrence would be reconsidered (and re-dropped, forever) on
            // every subsequent call.
            if let Ok(instants) = next_after_cursor {
                Self::push_occurrences(&mut self.heap, binding, &instants);
            }
        }

        for entry in deferred {
            self.heap.push(entry);
        }

        events
    }

    /// Test-observability accessor (Task 6): the number of entries currently
    /// heaped, across all bindings.
    pub fn heap_len(&self) -> usize {
        self.heap.len()
    }
}
