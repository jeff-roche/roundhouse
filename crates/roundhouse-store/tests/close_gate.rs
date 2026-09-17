//! Phase 8, T19a Task 4, fix round 2 (review finding N1): pins that
//! [`roundhouse_store::test_util::CloseGate`] never lets a stray wakeup cross generations.
//!
//! `CloseGate::release` is only ever meant to unblock the `hold()` it is paired with. A
//! `release()` called while nothing is genuinely parked on the gate (or after the one
//! `close_session` call it was meant for has already been admitted) must be a true no-op —
//! it must never leave anything behind that a LATER, unrelated `hold()` could be woken by
//! instead of a real, subsequent `release()`. Driven entirely on `tokio::task::yield_now`
//! plus `JoinHandle::is_finished` (never a sleep): a spawned `close_session` call that is
//! genuinely still gated cannot complete no matter how many scheduler turns it is given,
//! because nothing has fired the oneshot it is waiting on — so bounded yielding proves
//! "still gated" exactly as reliably as it proves "now resolved" once a real `release()`
//! runs.

use std::sync::Arc;

use roundhouse_core::{SessionId, SessionOutcome, Timestamp};
use roundhouse_store::open;
use roundhouse_store::test_util::{spawn_gated_writer, CloseGate};

static RUNNER: once_cell::sync::Lazy<roundhouse_core::TaskRunner> =
    once_cell::sync::Lazy::new(roundhouse_core::TaskRunner::bootstrap);

fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

/// Yields a generous, bounded number of scheduler turns — enough for any amount of real
/// cross-task async work (channel sends, SQLite round trips) to finish, but never a sleep:
/// this returns as soon as the runtime has nothing else ready to run, not after any fixed
/// wall-clock duration.
async fn drain_scheduler() {
    for _ in 0..1024 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn a_released_then_re_armed_gate_still_holds_the_next_close() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir.path().join("events.db")).await.unwrap();
    let gate = CloseGate::new();
    let writer = spawn_gated_writer(store, Arc::clone(&gate)).await;
    let session_id = SessionId::new();

    // Arm a hold, then release it with no `close_session` call genuinely parked on it yet
    // (the stray release the bug is about), then re-arm with a fresh hold.
    gate.hold().await;
    gate.release().await;
    gate.hold().await;

    let closing_writer = writer.clone();
    let closing = tokio::spawn(async move {
        closing_writer
            .close_session(&RUNNER, session_id, now_ts(), SessionOutcome::Completed)
            .await
    });

    drain_scheduler().await;
    assert!(
        !closing.is_finished(),
        "a close_session call must still be gated by the re-armed hold — it must not be \
         satisfied by a permit left behind from the earlier, stray release()"
    );

    // A real release now must be the one that actually lets it through.
    gate.release().await;
    let receipt = closing.await.unwrap().unwrap();
    assert_eq!(
        receipt,
        roundhouse_store::CloseReceipt::Closed { swept: 0 },
        "the close must still complete correctly once genuinely released"
    );
}
