//! Tests for `roundhouse_store::CommitFeed`/`CommitWatch` (Phase 8 Task 21, Task 1) and
//! the sync `events_after`/`session_head` readers they exist to serve.
//!
//! `CommitFeed` is the store-side half of "committed session events reach clients in
//! `seq` order": every successful writer command bumps a per-session generation counter
//! (`tokio::sync::watch`'s value, NOT a `seq` — see `commit_feed.rs`'s own doc comment for
//! why), and a follower `watch()`es it, `mark_seen()`s before reading the store, then
//! `changed()`s to know when to read again. These tests pin the primitive's own contract
//! (mark/notify ordering, cancel-safety, per-session isolation) and the writer's actual
//! wiring (notify only after a commit, never after a rejection, once per distinct session
//! in a batch).
//!
//! Per this lane's no-clock-timing-tests rule, every assertion here is driven by an
//! explicit signal (`changed()`, `now_or_never()`), never a `sleep`-then-assert. The one
//! `tokio::time::timeout` used is a failure bound only — a hang becomes a failed test, not
//! the thing being asserted.

use std::time::Duration;

use futures::FutureExt;
use roundhouse_core::{NoteLevel, SessionId, SessionOutcome, Timestamp};
use roundhouse_store::{events_after, open, session_head, spawn_writer, CommitFeed, StoreError};

static RUNNER: once_cell::sync::Lazy<roundhouse_core::TaskRunner> =
    once_cell::sync::Lazy::new(roundhouse_core::TaskRunner::bootstrap);

/// `Timestamp` (Phase 0, frozen) exposes only `from_unix_nanos`/`as_unix_nanos` — no
/// `now()` (see Resolved Ambiguity #5 / audit finding X4), matching this crate's other
/// integration tests' own `now_ts` helper.
fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

/// A `notify()` that lands after `mark_seen()` must wake a pending `changed()`. The
/// `timeout` here is a failure bound only (a hang fails the test) — the assertion itself
/// is `changed()` resolving, not any elapsed time.
#[tokio::test]
async fn notify_after_mark_seen_wakes_changed() {
    let feed = CommitFeed::default();
    let session_id = SessionId::new();

    let mut watch = feed.watch(session_id);
    watch.mark_seen();
    feed.notify(session_id);

    tokio::time::timeout(Duration::from_secs(1), watch.changed())
        .await
        .expect("changed() must resolve once a notify lands after mark_seen");
}

/// A `notify()` that lands BEFORE `mark_seen()` must not leave a stale wake behind:
/// `mark_seen()` consumes it, so the next `changed()` must still be pending. Checked with
/// `now_or_never()` (an immediate poll), never a sleep.
#[tokio::test]
async fn notify_before_mark_seen_does_not_leave_a_stale_wake() {
    let feed = CommitFeed::default();
    let session_id = SessionId::new();

    let mut watch = feed.watch(session_id);
    feed.notify(session_id);
    watch.mark_seen();

    assert!(
        watch.changed().now_or_never().is_none(),
        "a notify consumed by mark_seen must not leave changed() already resolved"
    );
}

/// The real writer, over a real (temp-file) store: a successful `append` must notify only
/// AFTER the write commits — by the time `changed()` resolves, `events_after` (a sync
/// read, callable from inside the same `interact` closure a real follower would use) must
/// already see the row it just committed.
///
/// Races the wake against the append itself (`tokio::join!`) rather than awaiting the
/// append to completion first: awaiting it first would let BOTH `notify()` and the actual
/// commit finish before this test ever checks anything, which can't tell "notified before
/// commit" apart from "notified after" — either ordering looks identical once both are
/// already done. Racing them means a `notify()` that fires too early can be observed
/// racing ahead of the commit it should have waited for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn writer_append_notifies_only_after_commit() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let feed = store.commit_feed().clone();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();
    let mut watch = feed.watch(session_id);
    watch.mark_seen();

    let query_store = open(&db_path).await.unwrap();

    let append_fut = writer.append(RUNNER.record_note(
        session_id,
        0,
        now_ts(),
        None,
        NoteLevel::Info,
        "hello".into(),
        1,
    ));
    let wake_then_read_fut = async {
        watch.changed().await;
        let conn = query_store.pool.get().await.unwrap();
        conn.interact(move |c| events_after(c, session_id, None, 10))
            .await
            .unwrap()
            .unwrap()
    };

    let (append_result, events_seen_at_wake) =
        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(append_fut, wake_then_read_fut)
        })
        .await
        .expect("append and the notify wake must both resolve");

    append_result.unwrap();
    assert_eq!(
        events_seen_at_wake.len(),
        1,
        "the committed row must already be visible at the moment changed() resolves"
    );
}

/// An append rejected by the tail guard (`StoreError::SessionClosed`) must never notify —
/// nothing committed, so nothing changed.
#[tokio::test]
async fn rejected_append_does_not_notify() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let feed = store.commit_feed().clone();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();
    writer
        .close_session(&RUNNER, session_id, now_ts(), SessionOutcome::Completed)
        .await
        .unwrap();

    let mut watch = feed.watch(session_id);
    watch.mark_seen();

    let result = writer
        .append(RUNNER.record_note(
            session_id,
            0,
            now_ts(),
            None,
            NoteLevel::Info,
            "must not land".into(),
            1,
        ))
        .await;
    assert!(
        matches!(result, Err(StoreError::SessionClosed(_))),
        "append after close must be rejected with SessionClosed, got {result:?}"
    );

    assert!(
        watch.changed().now_or_never().is_none(),
        "a rejected append must not notify"
    );
}

/// A batch touching two sessions — one of them with TWO events in the same batch — must
/// notify each distinct session exactly once, not once per event.
#[tokio::test]
async fn append_batch_notifies_each_session_once_per_batch() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let feed = store.commit_feed().clone();
    let writer = spawn_writer(store).await;

    let session_a = SessionId::new();
    let session_b = SessionId::new();
    let mut watch_a = feed.watch(session_a);
    let mut watch_b = feed.watch(session_b);
    watch_a.mark_seen();
    watch_b.mark_seen();

    let events = vec![
        RUNNER.record_note(
            session_a,
            0,
            now_ts(),
            None,
            NoteLevel::Info,
            "a1".into(),
            1,
        ),
        RUNNER.record_note(
            session_a,
            0,
            now_ts(),
            None,
            NoteLevel::Info,
            "a2".into(),
            1,
        ),
        RUNNER.record_note(
            session_b,
            0,
            now_ts(),
            None,
            NoteLevel::Info,
            "b1".into(),
            1,
        ),
    ];
    writer.append_batch(events).await.unwrap();

    tokio::time::timeout(Duration::from_secs(1), watch_a.changed())
        .await
        .expect("session_a must be notified for its two events");
    tokio::time::timeout(Duration::from_secs(1), watch_b.changed())
        .await
        .expect("session_b must be notified for its one event");

    // session_a had TWO events in the batch. If the writer notified once per event
    // rather than once per distinct session, this second, immediate poll would already
    // be resolved from the leftover second bump.
    assert!(
        watch_a.changed().now_or_never().is_none(),
        "session_a must be notified exactly once per batch, not once per event"
    );
}

/// `events_after` pages in ascending `seq` order, honors `after`/`limit`, treats `None` as
/// "from the start" (seq 0 included), and never leaks another session's rows.
#[tokio::test]
async fn events_after_pages_in_seq_order() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();
    let other_session = SessionId::new();

    for i in 0..5 {
        writer
            .append(RUNNER.record_note(
                session_id,
                0,
                now_ts(),
                None,
                NoteLevel::Info,
                format!("note {i}"),
                1,
            ))
            .await
            .unwrap();
    }
    writer
        .append(RUNNER.record_note(
            other_session,
            0,
            now_ts(),
            None,
            NoteLevel::Info,
            "other session's own note".into(),
            1,
        ))
        .await
        .unwrap();

    let query_store = open(&db_path).await.unwrap();

    let conn = query_store.pool.get().await.unwrap();
    let page = conn
        .interact(move |c| events_after(c, session_id, Some(1), 2))
        .await
        .unwrap()
        .unwrap();
    let seqs: Vec<u64> = page.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, vec![2, 3], "after=Some(1), limit=2 must page [2, 3]");

    let conn = query_store.pool.get().await.unwrap();
    let from_start = conn
        .interact(move |c| events_after(c, session_id, None, 10))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from_start.len(), 5);
    assert_eq!(
        from_start.first().unwrap().seq,
        0,
        "after=None must start at seq 0, not seq 1"
    );
    assert!(
        from_start.iter().all(|e| e.session_id == session_id),
        "a different session's rows must never appear"
    );
}

/// `session_head` is `None` for a session with no events, then the highest committed
/// `seq` once events exist.
#[tokio::test]
async fn session_head_is_none_then_highest_seq() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();

    let session_id = SessionId::new();

    let conn = store.pool.get().await.unwrap();
    let head_before = conn
        .interact(move |c| session_head(c, session_id))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head_before, None);

    let writer = spawn_writer(store).await;
    for _ in 0..3 {
        writer
            .append(RUNNER.record_note(
                session_id,
                0,
                now_ts(),
                None,
                NoteLevel::Info,
                "x".into(),
                1,
            ))
            .await
            .unwrap();
    }

    let query_store = open(&db_path).await.unwrap();
    let conn = query_store.pool.get().await.unwrap();
    let head_after = conn
        .interact(move |c| session_head(c, session_id))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head_after, Some(2));
}
