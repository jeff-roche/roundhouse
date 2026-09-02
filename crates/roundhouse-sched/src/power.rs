//! Sleep/wake integration (Phase 5, Subsystem A, Task 6).
//!
//! §8.7 requires that on resume from suspend the daemon "recompute
//! schedules, run catch-up, and mark all in-flight provider calls
//! retryable." [`Scheduler`] already has the pieces this composes:
//! [`Scheduler::catch_up_after_wake`] (this task) drains any backlog that
//! accumulated during the sleep through the same capped,
//! `CatchUp`-policy-aware machinery `tick` already applies to a binding that
//! merely falls behind between ordinary ticks (see that method's doc
//! comment for why a plain [`Scheduler::recompute_all`] is the wrong tool
//! here — it discards the backlog rather than draining it). This module's
//! job is purely the integration: turn OS-level power events into calls
//! against that scheduler machinery, plus the separate (`roundhouse-engine`
//! owned) concern of marking in-flight provider calls retryable.
use crate::scheduler::{ClockSource, Scheduler, SchedulerEvent};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerEvent {
    PrepareForSleep,
    Woke,
}

#[allow(async_fn_in_trait)]
pub trait PowerEvents {
    async fn next_event(&mut self) -> PowerEvent;
}

/// Real implementation: subscribes to logind's `PrepareForSleep` signal over
/// D-Bus (`false` payload = about to sleep, `true` = resumed). Linux-only.
///
/// Deliberately left unimplemented here (no `new()`, no `PowerEvents` impl):
/// wiring a real D-Bus connection would require adding a new, unpinned
/// dependency (e.g. `zbus`) that is not listed anywhere in this phase's
/// Global Constraints or §5.3 pin table, and which D-Bus client to use is
/// exactly the kind of architectural choice that belongs to whichever task
/// actually wires `roundhouse-daemon`'s startup (the plan's own "exercised
/// by an integration test gated on `#[ignore]`, not this unit suite" note
/// already anticipates that the real body lands separately from this one).
///
/// Its absence does not weaken correctness: [`run_power_watch`] treats this
/// source as an optimization, not a correctness dependency. A missed (or,
/// today, entirely absent) `PrepareForSleep` signal just means the wake is
/// instead caught by the scheduler's own monotonic-vs-wall drift check on
/// its next ordinary `tick` — slower to react, but not silently wrong — so
/// `cargo test` never depends on a live logind/D-Bus session, which would
/// make the suite machine-dependent (absent on other platforms, in
/// containers, and on headless CI).
#[cfg(target_os = "linux")]
pub struct LogindPowerEvents {
    // A real `zbus::Connection` + signal stream would be constructed in
    // `new()` here; see the doc comment above for why that is out of scope
    // for this task.
}

/// G6's fix: §8.7 requires that on resume, the daemon "mark all in-flight
/// provider calls retryable — their sockets are dead." An earlier version of
/// this function left that as an unwired comment ("the caller's job in
/// roundhouse-engine"), which is where G6's audit finding ("OS-liveness
/// artifacts have no task in any plan... Phase 5's scope notes don't flag
/// it") landed — the seam existed but nothing plugged into it. `roundhouse-sched`
/// has no visibility into in-flight provider calls itself (that state lives
/// in `roundhouse-engine`), so this stays a thin trait exactly like
/// `PowerEvents`/`ClockSource` — but it is now a real, exercised parameter,
/// not a dangling comment.
///
/// What "retryable" licenses is deliberately left to the implementor on the
/// `roundhouse-engine` side, and is *not* a blanket "safe to resend": a
/// dead socket does not tell you whether the request reached the provider,
/// so a call that already had an observable side effect (e.g. a completed
/// tool invocation whose result just hadn't been read back yet) must not be
/// blindly retried as if it never happened. `roundhouse-sched` has no
/// visibility into which in-flight calls are idempotent versus
/// already-side-effecting, so it cannot make that distinction here — this
/// trait only tells the engine side "these sockets are dead, go decide what
/// retryable means for each one."
#[allow(async_fn_in_trait)]
pub trait RetryableMarker {
    fn mark_all_in_flight_retryable(&mut self);
}

/// Fix round 1 (H, security review of Task 6): what `run_power_watch`
/// reports to its caller for each power-related occurrence it observes or
/// acts on. Before this, `run_power_watch` took `events: impl PowerEvents`
/// *by value* with `next_event(&mut self)`, so it owned the event stream
/// exclusively — there was no parameter of any kind through which a caller
/// could learn a `PrepareForSleep` happened (so it could, say, pause new
/// admissions, exactly as the old inline comment on that branch claimed
/// "is handled by the caller" without ever giving the caller a way to do
/// it) or receive the `SchedulerEvent`s a wake's catch-up drain produced.
/// That second gap was worse than a missing feature: the drain is
/// *destructive* (`Scheduler::catch_up_after_wake` advances
/// `last_fired_for` and reschedules past every considered occurrence), so
/// discarding its return value — which the pre-fix code did — permanently
/// loses whichever occurrences it decided to fire, with no way for
/// anything downstream (the admission gate, session dispatch) to ever see
/// them. A `Binding` using the default `CatchUp::Latest` reduces an entire
/// missed backlog to exactly one `Fire`; dropping that one event means the
/// wake performs a catch-up that delivers nothing, while still logging
/// "system woke; draining..." as if it had succeeded.
///
/// `roundhouse-sched` has no opinion on how the daemon actually reacts to
/// either signal (pausing admissions on `PrepareForSleep`, or dispatching a
/// `Fire` event from a wake's drain — the same admission-gate/dispatch path
/// an ordinary `tick`'s events already go through) — a thin seam, exactly
/// like `PowerEvents`/`RetryableMarker`, guarantees only that both actually
/// reach the caller.
#[derive(Debug)]
pub enum PowerWatchEvent {
    /// The system is about to suspend. Purely advisory — nothing has been
    /// drained or fired — so the caller can react before the process is
    /// frozen (e.g. pause new admissions).
    PrepareForSleep,
    /// The system woke. Carries every [`SchedulerEvent`]
    /// [`Scheduler::catch_up_after_wake`] produced. The caller must
    /// actually consume these (e.g. hand each `Fire` to the same
    /// admission-gate/dispatch path an ordinary `tick`'s events go
    /// through) — the drain that produced them already happened and is not
    /// repeatable; an event dropped here is gone.
    Woke(Vec<SchedulerEvent>),
}

#[allow(async_fn_in_trait)]
pub trait PowerWatchSink {
    fn accept(&mut self, event: PowerWatchEvent);
}

/// Drives the scheduler's sleep/wake handling: on `Woke`, drains any
/// catch-up backlog that accumulated during the sleep via
/// [`Scheduler::catch_up_after_wake`], hands the resulting events to `sink`,
/// and marks every in-flight provider call retryable via `retryable` (§8.7,
/// G6's fix — both halves of "on resume, recompute schedules, run
/// catch-up, and mark all in-flight provider calls retryable" now actually
/// happen from this one call site, and now actually reach a consumer — see
/// [`PowerWatchEvent`]'s doc comment for why that matters). "Retryable"
/// here carries the same caveat documented on [`RetryableMarker`] itself —
/// it does not mean every in-flight call is safe to blindly resend; see
/// that trait's doc comment before implementing it.
///
/// Both clock readings are taken explicitly at the point of use, not routed
/// through a single ambiguous "now": `monotonic_now` only resets the
/// scheduler's drift baseline (so the *next* ordinary `tick` does not
/// re-report this same sleep gap as fresh drift — see
/// [`Scheduler::catch_up_after_wake`]'s doc comment), while `wall_now` is
/// what the catch-up drain actually measures "how much was missed" against.
/// Conflating the two would either misreport a wake as drift or
/// (`monotonic_now` is expected to barely advance across a real suspend,
/// unlike `wall_now`) under-measure how much was actually missed.
pub async fn run_power_watch(
    sched: Arc<Mutex<Scheduler>>,
    clock: Arc<dyn ClockSource + Send + Sync>,
    mut events: impl PowerEvents,
    retryable: Arc<Mutex<dyn RetryableMarker + Send>>,
    mut sink: impl PowerWatchSink,
) {
    loop {
        match events.next_event().await {
            PowerEvent::PrepareForSleep => {
                tracing::info!(
                    "system preparing for sleep; notifying sink so the caller can pause new admissions"
                );
                sink.accept(PowerWatchEvent::PrepareForSleep);
            }
            PowerEvent::Woke => {
                tracing::info!(
                    "system woke; draining any missed-occurrence backlog and marking in-flight provider calls retryable"
                );
                let monotonic_now = clock.monotonic_now();
                let wall_now = clock.wall_now();
                let drained = lock_or_recover(&sched, "scheduler")
                    .catch_up_after_wake(monotonic_now, wall_now);
                sink.accept(PowerWatchEvent::Woke(drained));
                lock_or_recover(&retryable, "retryable marker").mark_all_in_flight_retryable();
            }
        }
    }
}

/// Fix round 1 (L1, security review of Task 6): recovers from a poisoned
/// mutex instead of panicking. `run_power_watch` is meant to run inside a
/// `tokio::spawn`ed task whose `JoinHandle` the daemon is not guaranteed to
/// await; an unhandled panic in this `loop {}` would silently end sleep/wake
/// handling for the rest of the process's lifetime with nothing visibly
/// wrong. The data behind a poisoned lock may be inconsistent (something
/// panicked mid-mutation), but for this loop's purposes — keep observing
/// wake events and keep trying to drain/mark-retryable — recovering and
/// continuing, loudly, is strictly better than going permanently and
/// silently dark.
fn lock_or_recover<'a, T: ?Sized>(mutex: &'a Mutex<T>, what: &str) -> std::sync::MutexGuard<'a, T> {
    mutex.lock().unwrap_or_else(|poisoned| {
        tracing::error!("{what} mutex poisoned; recovering its last state and continuing");
        poisoned.into_inner()
    })
}
