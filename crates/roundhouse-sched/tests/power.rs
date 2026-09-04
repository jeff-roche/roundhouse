use chrono::{DateTime, TimeZone, Utc};
use chrono_tz::Tz;
use roundhouse_core::JobId;
use roundhouse_sched::power::{
    run_power_watch, PowerEvent, PowerEvents, PowerWatchEvent, PowerWatchSink, RetryableMarker,
};
use roundhouse_sched::scheduler::{ClockSource, Scheduler, SchedulerEvent, SystemClock};
use roundhouse_sched::trigger::{Binding, CatchUp, TriggerSpec};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;

struct CountingRetryableMarker(Arc<std::sync::atomic::AtomicUsize>);
impl RetryableMarker for CountingRetryableMarker {
    fn mark_all_in_flight_retryable(&mut self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Fix round 1 (H): records every `PowerWatchEvent` `run_power_watch` hands
/// it, so tests can assert the drained `SchedulerEvent`s (and the
/// `PrepareForSleep` notification) actually reach a consumer, not just that
/// `Scheduler`'s own internal state changed. Wraps a `Vec` behind a
/// `std::sync::Mutex` since `run_power_watch` calls `PowerWatchSink::accept`
/// from inside its own task, while the test inspects the same `Vec` from
/// the outside after the task is done.
#[derive(Clone, Default)]
struct RecordingSink(Arc<Mutex<Vec<PowerWatchEvent>>>);

impl PowerWatchSink for RecordingSink {
    fn accept(&mut self, event: PowerWatchEvent) {
        self.0.lock().unwrap().push(event);
    }
}

/// Fix round 1 (fold-in item): a single scripted `Woke` event, observed via
/// a oneshot channel once `next_event` has actually been polled and
/// returned it — used so a test can wait for `run_power_watch` to have
/// *finished* processing the event (deterministically, no `sleep`-and-hope,
/// which is flaky on a loaded CI box) before inspecting state. Generalizes
/// the pattern the second test in this file already used, now applied to
/// the brief-supplied test too.
struct EventsThenSignal {
    remaining: Vec<PowerEvent>,
    done_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl PowerEvents for EventsThenSignal {
    async fn next_event(&mut self) -> PowerEvent {
        if !self.remaining.is_empty() {
            return self.remaining.remove(0);
        }
        // Signal completion only once every scripted event has actually
        // been consumed by `run_power_watch`'s loop (i.e. after whatever
        // that event's branch does has already run), then block forever so
        // the spawned task can be cleanly aborted.
        if let Some(tx) = self.done_tx.take() {
            let _ = tx.send(());
        }
        std::future::pending::<()>().await;
        unreachable!()
    }
}

#[tokio::test]
async fn wake_event_triggers_full_recompute_and_marks_in_flight_calls_retryable() {
    let sched = Arc::new(Mutex::new(Scheduler::new()));
    let clock = Arc::new(SystemClock);
    let mark_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let retryable: Arc<Mutex<dyn RetryableMarker + Send>> =
        Arc::new(Mutex::new(CountingRetryableMarker(mark_count.clone())));
    let sink = RecordingSink::default();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let events = EventsThenSignal {
        remaining: vec![PowerEvent::PrepareForSleep, PowerEvent::Woke],
        done_tx: Some(done_tx),
    };

    let sched_clone = sched.clone();
    let sink_clone = sink.clone();
    let handle = tokio::spawn(async move {
        run_power_watch(sched_clone, clock, events, retryable, sink_clone).await;
    });

    done_rx.await.expect("run_power_watch dropped its signal");
    handle.abort();

    // recompute_all's correctness is already covered by Task 3's drift test;
    // this task's own assertion is that Woke actually reaches both seams.
    assert!(sched.lock().unwrap().heap_len() == 0); // no bindings were registered in this test
    assert_eq!(
        mark_count.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "Woke must mark in-flight provider calls retryable exactly once per wake (§8.7 — G6's fix)"
    );

    // Fix round 1 (H): the drained events must actually reach the sink, not
    // be silently discarded — assert on the sink's contents, not just on
    // `Scheduler`'s own state.
    let recorded = sink.0.lock().unwrap();
    assert_eq!(
        recorded.len(),
        2,
        "expected one notification per scripted event: {recorded:?}"
    );
    assert!(
        matches!(recorded[0], PowerWatchEvent::PrepareForSleep),
        "PrepareForSleep must reach the sink so a real caller can pause admissions: {recorded:?}"
    );
    match &recorded[1] {
        PowerWatchEvent::Woke(fired) => assert!(
            fired.is_empty(),
            "no bindings were registered, so the drain must produce no events: {fired:?}"
        ),
        other => panic!("expected PowerWatchEvent::Woke, got {other:?}"),
    }
}

/// Fix round 1 (L1): `run_power_watch` must recover from a poisoned
/// scheduler mutex rather than let the panic propagate into its own
/// `loop {}` (see `lock_or_recover` in `power.rs`). A poisoned
/// `std::sync::Mutex` does not block future `lock()` calls — it just makes
/// them return `Err(PoisonError)` — so this test poisons the mutex directly
/// (panicking on a separate OS thread while holding the lock, which unwinds
/// and releases it, marking it poisoned; this cannot deadlock, the
/// poisoning thread's panic completes almost immediately) and then drives a
/// real `Woke` event through `run_power_watch`, asserting the drained
/// events still reach the sink.
///
/// If `lock_or_recover` regresses back to `.expect(...)`/`.unwrap()`, this
/// fails rather than hangs: the spawned task panics while processing
/// `Woke`, which drops its `done_tx` sender, so `done_rx.await` resolves to
/// `Err` immediately — verified by actually reverting the helper and
/// watching this test fail (see the fix-round-1 report addendum for the
/// exact command and output).
#[tokio::test]
async fn poisoned_scheduler_mutex_is_recovered_not_left_permanently_broken() {
    let sched = Arc::new(Mutex::new(Scheduler::new()));

    // Poison the mutex: panic on a separate thread while holding the lock.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {})); // suppress this deliberate panic's backtrace noise
    let poison_sched = sched.clone();
    let joined = std::thread::spawn(move || {
        let _guard = poison_sched.lock().unwrap();
        panic!("deliberately poisoning the scheduler mutex for this test");
    })
    .join();
    std::panic::set_hook(default_hook);
    assert!(joined.is_err(), "the poisoning thread should have panicked");
    assert!(
        sched.lock().is_err(),
        "the mutex should now report itself as poisoned"
    );

    // Drive one real `Woke` through `run_power_watch` anyway.
    let clock = Arc::new(SystemClock);
    let retryable: Arc<Mutex<dyn RetryableMarker + Send>> =
        Arc::new(Mutex::new(NoopRetryableMarker));
    let sink = RecordingSink::default();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let events = SingleWokeThenSignal {
        fired: false,
        done_tx: Some(done_tx),
    };

    let sched_clone = sched.clone();
    let sink_clone = sink.clone();
    let handle = tokio::spawn(async move {
        run_power_watch(sched_clone, clock, events, retryable, sink_clone).await;
    });

    done_rx
        .await
        .expect("run_power_watch must recover from the poisoned lock and keep running, not panic");
    handle.abort();

    let recorded = sink.0.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    match &recorded[0] {
        PowerWatchEvent::Woke(fired) => assert!(
            fired.is_empty(),
            "no bindings were registered, so the recovered drain must produce no events: {fired:?}"
        ),
        other => panic!("expected PowerWatchEvent::Woke, got {other:?}"),
    }
}

/// Fix round 3 (Important, security review of Task 6): `std::sync::Mutex`
/// poison is *latched* — it stays set on every future `lock()` until
/// `clear_poison()` is called. `run_power_watch`'s poison-recovery repair
/// (`recompute_all` on the scheduler mutex) must be one-shot: without
/// clearing the latch after repairing, `sched_was_poisoned` would be `true`
/// again on *every subsequent* `Woke`, re-running `recompute_all` forever —
/// permanently discarding every future wake's real backlog, not just the
/// one that actually followed the panic. This drives two `Woke` events
/// through the same poisoned scheduler and asserts the *second* one drains
/// a real, since-accumulated backlog normally, which only happens if the
/// first wake's repair actually cleared the poison.
///
/// A shared, externally-mutable clock (unlike the fixed-reading `FakeClock`
/// below, which only ever needs one reading per test) — the test advances
/// the wall/monotonic readings *between* the two `Woke` events, which
/// `run_power_watch` observes on its next `clock.monotonic_now()`/
/// `clock.wall_now()` read. `Mutex` (not `RefCell`) because this is shared
/// across the test's thread and `run_power_watch`'s spawned task via
/// `Arc<dyn ClockSource + Send + Sync>`, which requires `Sync`.
struct MutableClock(Mutex<(Instant, DateTime<Utc>)>);

impl MutableClock {
    fn new(mono: Instant, wall: DateTime<Utc>) -> Self {
        Self(Mutex::new((mono, wall)))
    }

    fn set(&self, mono: Instant, wall: DateTime<Utc>) {
        *self.0.lock().unwrap() = (mono, wall);
    }
}

impl ClockSource for MutableClock {
    fn monotonic_now(&self) -> Instant {
        self.0.lock().unwrap().0
    }
    fn wall_now(&self) -> DateTime<Utc> {
        self.0.lock().unwrap().1
    }
}

/// Yields `Woke` twice, with a rendezvous in between so the test can
/// deterministically advance the clock (see `MutableClock`) *after* the
/// first `Woke` has been fully processed and *before* the second one
/// starts — no `sleep`-and-hope. Signals `event1_done` only once
/// `run_power_watch`'s loop has looped back around to poll for the next
/// event (i.e. the first `Woke` branch's body, including the sink call,
/// has already run to completion), then blocks on `proceed_rx` until the
/// test says it has finished mutating state and inspecting the first
/// event's effects. Signals `event2_done` the same way once the second
/// `Woke` has likewise fully completed, then blocks forever so the spawned
/// task can be cleanly aborted.
struct TwoWokesWithGate {
    calls: u8,
    event1_done_tx: Option<tokio::sync::oneshot::Sender<()>>,
    proceed_rx: Option<tokio::sync::oneshot::Receiver<()>>,
    event2_done_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl PowerEvents for TwoWokesWithGate {
    async fn next_event(&mut self) -> PowerEvent {
        self.calls += 1;
        match self.calls {
            1 => PowerEvent::Woke,
            2 => {
                if let Some(tx) = self.event1_done_tx.take() {
                    let _ = tx.send(());
                }
                if let Some(rx) = self.proceed_rx.take() {
                    let _ = rx.await;
                }
                PowerEvent::Woke
            }
            _ => {
                if let Some(tx) = self.event2_done_tx.take() {
                    let _ = tx.send(());
                }
                std::future::pending::<()>().await;
                unreachable!()
            }
        }
    }
}

#[tokio::test]
async fn poison_recovery_is_one_shot_not_permanent() {
    let start_wall = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let start_mono = Instant::now();

    let mut scheduler = Scheduler::new();
    let mut binding = Binding::new_cron(JobId::new(), "* * * * *".to_string(), Tz::UTC);
    if let TriggerSpec::Cron { catch_up, .. } = &mut binding.spec {
        *catch_up = CatchUp::All;
    }
    let binding_id = binding.id;
    let add_clock = FakeClock {
        mono: start_mono,
        wall: start_wall,
    };
    scheduler.add_binding(binding, &add_clock).unwrap();
    let sched = Arc::new(Mutex::new(scheduler));

    // Poison the mutex exactly as in `poisoned_scheduler_mutex_is_recovered_not_left_permanently_broken`.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let poison_sched = sched.clone();
    let joined = std::thread::spawn(move || {
        let _guard = poison_sched.lock().unwrap();
        panic!("deliberately poisoning the scheduler mutex for this test");
    })
    .join();
    std::panic::set_hook(default_hook);
    assert!(joined.is_err(), "the poisoning thread should have panicked");
    assert!(
        sched.lock().is_err(),
        "the mutex should now report itself as poisoned"
    );

    let clock = Arc::new(MutableClock::new(start_mono, start_wall));
    let clock_dyn: Arc<dyn ClockSource + Send + Sync> = clock.clone();
    let retryable: Arc<Mutex<dyn RetryableMarker + Send>> =
        Arc::new(Mutex::new(NoopRetryableMarker));
    let sink = RecordingSink::default();

    let (event1_done_tx, event1_done_rx) = tokio::sync::oneshot::channel();
    let (proceed_tx, proceed_rx) = tokio::sync::oneshot::channel();
    let (event2_done_tx, event2_done_rx) = tokio::sync::oneshot::channel();
    let events = TwoWokesWithGate {
        calls: 0,
        event1_done_tx: Some(event1_done_tx),
        proceed_rx: Some(proceed_rx),
        event2_done_tx: Some(event2_done_tx),
    };

    let sched_clone = sched.clone();
    let sink_clone = sink.clone();
    let handle = tokio::spawn(async move {
        run_power_watch(sched_clone, clock_dyn, events, retryable, sink_clone).await;
    });

    // First Woke: recovers from the poison (asserted exactly as the
    // existing poisoned-mutex test does), and — the fix round 3 assertion —
    // the poison must actually be *cleared*, not merely worked around for
    // this one call.
    event1_done_rx
        .await
        .expect("run_power_watch must recover from the poisoned lock, not panic");
    assert!(
        sched.lock().is_ok(),
        "fix round 3: the poison must be cleared once the repair (recompute_all) has run, not \
         left latched forever"
    );

    // Advance the clock past several real occurrences before the second
    // wake — a genuine backlog that accumulated *after* the poison was
    // already repaired and cleared.
    let target_wall = start_wall + chrono::Duration::minutes(5);
    let target_mono = start_mono + Duration::from_secs(5 * 60);
    clock.set(target_mono, target_wall);
    proceed_tx
        .send(())
        .expect("the events source must still be waiting on this rendezvous");

    event2_done_rx
        .await
        .expect("run_power_watch must still be running for the second wake");
    handle.abort();

    let recorded = sink.0.lock().unwrap();
    assert_eq!(
        recorded.len(),
        2,
        "expected one sink notification per Woke event: {recorded:?}"
    );
    match &recorded[1] {
        PowerWatchEvent::Woke(events) => {
            let fires: Vec<DateTime<Utc>> = events
                .iter()
                .filter_map(|e| match e {
                    SchedulerEvent::Fire(id, at) if *id == binding_id => Some(*at),
                    _ => None,
                })
                .collect();
            let expected: Vec<DateTime<Utc>> = (1..=5)
                .map(|m| start_wall + chrono::Duration::minutes(m))
                .collect();
            assert_eq!(
                fires, expected,
                "the second wake must drain its real, since-accumulated backlog normally — \
                 an empty or partial result here means the poison latch was never cleared and \
                 this wake was wrongly treated as still recovering from the first panic: \
                 {events:?}"
            );
        }
        other => panic!("expected PowerWatchEvent::Woke, got {other:?}"),
    }
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
/// state.
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
        // event, i.e. after `catch_up_after_wake`, the sink, and
        // `mark_all_in_flight_retryable` have all already run) and then
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
///
/// `Binding::new_cron` defaults to `CatchUp::Latest` (fix round 1, M2:
/// `Latest` is resolved once over the *whole* backlog, not once per capped
/// batch), so a single `Woke` event — one capped batch, with far more than
/// a batch's worth of backlog still outstanding — must not have fired
/// anything yet: `heap_len` still shows a due-but-not-yet-caught-up entry,
/// and the sink's `Woke` payload for this one event is empty.
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
    let sink = RecordingSink::default();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let events = SingleWokeThenSignal {
        fired: false,
        done_tx: Some(done_tx),
    };

    let sched_clone = sched.clone();
    let sink_clone = sink.clone();
    let handle = tokio::spawn(async move {
        run_power_watch(sched_clone, clock, events, retryable, sink_clone).await;
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

    let recorded = sink.0.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    match &recorded[0] {
        PowerWatchEvent::Woke(fired) => assert!(
            fired.is_empty(),
            "CatchUp::Latest must not fire anything until the whole backlog is drained, \
             which takes many more calls than this single Woke event: {fired:?}"
        ),
        other => panic!("expected PowerWatchEvent::Woke, got {other:?}"),
    }
}

/// Fix round 1 (H): once the rest of the 10-day backlog above is drained by
/// plain `tick` calls (mirroring what the daemon's own regular ticking
/// would do after the wake event above), `CatchUp::Latest` must produce
/// *exactly one* `Fire` for the whole backlog — not one per capped batch
/// (M2) — and it must be the temporally *last* missed occurrence.
#[test]
fn latest_policy_backlog_collapses_to_one_fire_once_fully_drained_via_tick() {
    let start_wall = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let start_mono = Instant::now();
    let pre_sleep_clock = FakeClock {
        mono: start_mono,
        wall: start_wall,
    };
    let mut scheduler = Scheduler::new();
    let binding = Binding::new_cron(JobId::new(), "* * * * *".to_string(), Tz::UTC);
    let binding_id = binding.id;
    scheduler.add_binding(binding, &pre_sleep_clock).unwrap();

    let sleep_duration = chrono::Duration::days(10);
    let target_wall = start_wall + sleep_duration;
    let woke_mono = start_mono + Duration::from_millis(5);

    // 10 days at one-a-minute cadence is 14,400 missed occurrences —
    // exactly 144 capped batches of 100 (`MAX_CATCH_UP_OCCURRENCES_PER_BINDING_PER_TICK`),
    // deliberately chosen as an exact multiple to exercise the fix-round-1
    // edge case where the cap and the true end of the backlog coincide on
    // the same batch (see `drain_due`'s `next_after_cursor` lookahead).
    let mut fired: Vec<SchedulerEvent> = scheduler.catch_up_after_wake(woke_mono, target_wall);

    let hold_clock = FakeClock {
        mono: woke_mono,
        wall: target_wall,
    };
    // `heap_len()` never reaches 0 for a registered cron binding (a
    // rescheduled future entry always remains); the real completion signal
    // is a `Fire` event finally showing up for our binding, which — under
    // `CatchUp::Latest` — happens on exactly one of these calls, not on
    // every one.
    for _ in 0..200 {
        fired.extend(scheduler.tick(&hold_clock));
        if fired
            .iter()
            .any(|e| matches!(e, SchedulerEvent::Fire(id, _) if *id == binding_id))
        {
            break;
        }
    }

    let fires: Vec<_> = fired
        .into_iter()
        .filter_map(|e| match e {
            SchedulerEvent::Fire(id, at) if id == binding_id => Some(at),
            _ => None,
        })
        .collect();
    assert_eq!(
        fires,
        vec![target_wall],
        "CatchUp::Latest must fire exactly once for the whole backlog, carrying the \
         temporally latest missed occurrence, not once per capped batch"
    );
}
