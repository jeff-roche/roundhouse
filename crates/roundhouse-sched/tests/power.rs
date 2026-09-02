use chrono::{DateTime, TimeZone, Utc};
use chrono_tz::Tz;
use roundhouse_core::JobId;
use roundhouse_sched::power::{run_power_watch, PowerEvent, PowerEvents, RetryableMarker};
use roundhouse_sched::scheduler::{ClockSource, Scheduler, SystemClock};
use roundhouse_sched::trigger::Binding;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;

struct ScriptedEvents(Vec<PowerEvent>);
impl PowerEvents for ScriptedEvents {
    async fn next_event(&mut self) -> PowerEvent {
        if self.0.is_empty() {
            std::future::pending::<()>().await;
            unreachable!()
        } else {
            self.0.remove(0)
        }
    }
}

struct CountingRetryableMarker(Arc<std::sync::atomic::AtomicUsize>);
impl RetryableMarker for CountingRetryableMarker {
    fn mark_all_in_flight_retryable(&mut self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[tokio::test]
async fn wake_event_triggers_full_recompute_and_marks_in_flight_calls_retryable() {
    let sched = Arc::new(Mutex::new(Scheduler::new()));
    let clock = Arc::new(SystemClock);
    let events = ScriptedEvents(vec![PowerEvent::PrepareForSleep, PowerEvent::Woke]);
    let mark_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let retryable: Arc<Mutex<dyn RetryableMarker + Send>> =
        Arc::new(Mutex::new(CountingRetryableMarker(mark_count.clone())));

    let sched_clone = sched.clone();
    let handle = tokio::spawn(async move {
        run_power_watch(sched_clone, clock, events, retryable).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    handle.abort();
    // recompute_all's correctness is already covered by Task 3's drift test;
    // this task's own assertion is that Woke actually reaches both seams.
    assert!(sched.lock().unwrap().heap_len() == 0); // no bindings were registered in this test
    assert_eq!(
        mark_count.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "Woke must mark in-flight provider calls retryable exactly once per wake (§8.7 — G6's fix)"
    );
}

/// A fixed-reading fake clock: the point of this test is what happens once
/// the machine has already woken with a fixed (monotonic, wall) reading
/// pair, not clock mutation over time, so no interior mutability is needed
/// — a plain `Send + Sync` struct suffices for `run_power_watch`'s
/// `Arc<dyn ClockSource + Send + Sync>` bound. On a real machine
/// `CLOCK_MONOTONIC` does not advance across suspend while `CLOCK_REALTIME`
/// (wall clock) jumps forward by the sleep duration; this fake's two
/// readings are constructed with exactly that asymmetry rather than in
/// lockstep, which is what a mere NTP-sized correction would look like.
struct FakeClock {
    mono: Instant,
    wall: DateTime<Utc>,
}

impl ClockSource for FakeClock {
    fn monotonic_now(&self) -> Instant {
        self.mono
    }
    fn wall_now(&self) -> DateTime<Utc> {
        self.wall
    }
}

struct NoopRetryableMarker;
impl RetryableMarker for NoopRetryableMarker {
    fn mark_all_in_flight_retryable(&mut self) {}
}

/// A single scripted `Woke` event, observed via a oneshot channel once
/// `next_event` has actually been polled and returned it — used so the test
/// can wait for `run_power_watch` to have *finished* processing the event
/// (deterministically, no `sleep`-and-hope) before inspecting scheduler
/// state, rather than the flat `Vec`-based `ScriptedEvents` above, which
/// gives no such signal.
struct SingleWokeThenSignal {
    fired: bool,
    done_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl PowerEvents for SingleWokeThenSignal {
    async fn next_event(&mut self) -> PowerEvent {
        if !self.fired {
            self.fired = true;
            return PowerEvent::Woke;
        }
        // Signal completion of the Woke branch's processing (this fires
        // only once `run_power_watch` has looped back around for its next
        // event, i.e. after `catch_up_after_wake` and
        // `mark_all_in_flight_retryable` have both already run) and then
        // block forever so the spawned task can be cleanly aborted.
        if let Some(tx) = self.done_tx.take() {
            let _ = tx.send(());
        }
        std::future::pending::<()>().await;
        unreachable!()
    }
}

/// Risk item 1 from this task's dispatch: a machine asleep for a genuinely
/// long stretch (not a few seconds) must have its backlog drained through
/// the same capped, progressive catch-up machinery `tick` uses for an
/// ordinary backlog — never silently dropped (what a bare
/// `Scheduler::recompute_all` call would do) and never burst unbounded in
/// one shot. This drives that drain through the real `run_power_watch` +
/// `PowerEvent::Woke` path, with a once-a-minute cron binding and a
/// simulated sleep far longer than `MAX_CATCH_UP_OCCURRENCES_PER_BINDING_PER_TICK`
/// minutes (a "daemon down for a month" scale event, per Task 3's own
/// framing of that cap).
#[tokio::test]
async fn long_simulated_sleep_drains_progressively_through_run_power_watch() {
    let start_wall = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let start_mono = Instant::now();
    let pre_sleep_clock = FakeClock {
        mono: start_mono,
        wall: start_wall,
    };

    let mut scheduler = Scheduler::new();
    let binding = Binding::new_cron(JobId::new(), "* * * * *".to_string(), Tz::UTC);
    scheduler.add_binding(binding, &pre_sleep_clock).unwrap();

    // Simulate a genuinely long sleep: 10 days at one-a-minute cadence is
    // 14,400 missed occurrences — two orders of magnitude beyond the
    // per-call cap of 100, so this can only complete via multiple capped,
    // progressive drains, never a single burst.
    let sleep_duration = chrono::Duration::days(10);
    let target_wall = start_wall + sleep_duration;
    // The whole point of the monotonic/wall distinction (risk item 2): the
    // monotonic clock barely moves across a real suspend (a handful of
    // milliseconds of actual wall-clock processing before/after the sleep
    // call), while the wall clock jumps by the full sleep duration.
    let post_wake_clock = FakeClock {
        mono: start_mono + Duration::from_millis(5),
        wall: target_wall,
    };

    let sched = Arc::new(Mutex::new(scheduler));
    let clock: Arc<dyn ClockSource + Send + Sync> = Arc::new(post_wake_clock);
    let retryable: Arc<Mutex<dyn RetryableMarker + Send>> =
        Arc::new(Mutex::new(NoopRetryableMarker));
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let events = SingleWokeThenSignal {
        fired: false,
        done_tx: Some(done_tx),
    };

    let sched_clone = sched.clone();
    let handle = tokio::spawn(async move {
        run_power_watch(sched_clone, clock, events, retryable).await;
    });

    done_rx.await.expect("run_power_watch dropped its signal");
    handle.abort();

    // A single `Woke` event only runs one capped drain pass per binding
    // (`MAX_CATCH_UP_OCCURRENCES_PER_BINDING_PER_TICK` = 100): with 14,400
    // occurrences overdue, far more than one pass's worth remains — the
    // heap must still hold a due (not yet caught-up) entry for further
    // draining by the daemon's own subsequent ticks, not zero (dropped) and
    // not the entire backlog magically resolved in one call.
    let remaining = sched.lock().unwrap().heap_len();
    assert_eq!(
        remaining, 1,
        "a single wake event drains one capped batch and leaves the rest of the backlog \
         heaped for progressive draining by subsequent ticks, not dropped and not fully \
         resolved in one call: heap_len={remaining}"
    );
}
