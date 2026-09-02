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
use crate::scheduler::{ClockSource, Scheduler};
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

/// Drives the scheduler's sleep/wake handling: on `Woke`, drains any
/// catch-up backlog that accumulated during the sleep via
/// [`Scheduler::catch_up_after_wake`] and marks every in-flight provider
/// call retryable via `retryable` (§8.7, G6's fix — both halves of "on
/// resume, recompute schedules, run catch-up, and mark all in-flight
/// provider calls retryable" now actually happen from this one call site).
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
) {
    loop {
        match events.next_event().await {
            PowerEvent::PrepareForSleep => {
                tracing::info!(
                    "system preparing for sleep; scheduler pausing new admissions is handled by the caller"
                );
            }
            PowerEvent::Woke => {
                tracing::info!(
                    "system woke; draining any missed-occurrence backlog and marking in-flight provider calls retryable"
                );
                let monotonic_now = clock.monotonic_now();
                let wall_now = clock.wall_now();
                sched
                    .lock()
                    .expect("scheduler lock")
                    .catch_up_after_wake(monotonic_now, wall_now);
                retryable
                    .lock()
                    .expect("retryable marker lock")
                    .mark_all_in_flight_retryable();
            }
        }
    }
}
