//! Tests for `roundhouse_store::SessionFollower`/`PageSource` (Phase 8 Task 21, Task 3): a
//! cancel-safe catch-up-then-follow reader built on `CommitFeed` (`commit_feed.rs`) and the
//! paged `events_after` (`session_events.rs`). These tests pin: catch-up from an arbitrary
//! cursor, following live commits, paging past `FOLLOW_PAGE`, and — the two tests that
//! matter most, since `next()` is a `tokio::select!` arm in the daemon's connection loop —
//! that a commit landing while a read is in flight is never lost, and that dropping a
//! `next()` future mid-read never loses or duplicates an event.
//!
//! Per this lane's no-clock-timing-tests rule, every assertion here is driven by an
//! explicit signal (`tokio::sync::Notify`, `futures::poll!`), never a `sleep`-then-assert.
//! Every `tokio::time::timeout` used is a failure bound only — a hang becomes a failed
//! test, not the thing being asserted.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use roundhouse_core::{EventPayload, NoteLevel, SessionId, Timestamp};
use roundhouse_store::{open, spawn_writer, PageSource, SessionFollower, StoreError, StoredEvent};
use tokio::sync::Notify;

static RUNNER: once_cell::sync::Lazy<roundhouse_core::TaskRunner> =
    once_cell::sync::Lazy::new(roundhouse_core::TaskRunner::bootstrap);

/// `Timestamp` (Phase 0, frozen) exposes only `from_unix_nanos`/`as_unix_nanos` — no
/// `now()` — matching this crate's other integration tests' own `now_ts` helper.
fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

/// A `PageSource` that lets a test control exactly when its FIRST `read_after` call
/// resolves, without depending on real I/O timing.
///
/// The real read is kicked off on a background task immediately when `read_after` is
/// *called* (not when the returned future is first polled) — this is what makes the
/// mark-seen-before-read RED-verification actually bite: the query reflects the store's
/// state at call time, not at whatever moment the caller gets around to awaiting it. Only
/// the FIRST call is gated (tracked by `first_call_pending`, consumed with a `swap` at call
/// time so it doesn't matter whether that first call's returned future is ever polled to
/// completion or dropped instead); every later call passes straight through.
///
/// `read_done` fires once the background read for the gated call has actually finished —
/// the explicit signal a test awaits before doing anything it needs ordered strictly after
/// that read, instead of guessing at scheduling. `release` is the gate itself: the gated
/// call's future stays pending until a test calls `release.notify_one()`.
struct GatedPageSource {
    inner: roundhouse_store::StorePool,
    first_call_pending: Arc<AtomicBool>,
    read_done: Arc<Notify>,
    release: Arc<Notify>,
}

impl PageSource for GatedPageSource {
    fn read_after(
        &self,
        session_id: SessionId,
        after: Option<u64>,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<StoredEvent>, StoreError>> + Send {
        let gated = self.first_call_pending.swap(false, Ordering::SeqCst);
        let read_done = self.read_done.clone();
        let release = self.release.clone();
        let inner = self.inner.clone();
        let handle = tokio::spawn(async move { inner.read_after(session_id, after, limit).await });
        async move {
            let result = handle.await.expect("background read_after task panicked");
            if gated {
                read_done.notify_one();
                release.notified().await;
            }
            result
        }
    }

    fn head(
        &self,
        session_id: SessionId,
    ) -> impl Future<Output = Result<Option<u64>, StoreError>> + Send {
        self.inner.head(session_id)
    }
}

/// Three events already committed before the follower is even created: `next()` must
/// return them in order (catch-up), and then, once caught up, keep following a live
/// append.
#[tokio::test]
async fn catches_up_then_follows() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let feed = store.commit_feed().clone();
    let writer = spawn_writer(store).await;
    let session_id = SessionId::new();

    for i in 0..3 {
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

    let query_store = open(&db_path).await.unwrap();
    let mut follower = SessionFollower::new(query_store, &feed, session_id, None);

    for expected_seq in 0..3u64 {
        let event = tokio::time::timeout(Duration::from_secs(1), follower.next())
            .await
            .expect("catch-up read must not hang")
            .unwrap();
        assert_eq!(event.seq, expected_seq);
        assert_eq!(follower.cursor(), Some(expected_seq));
    }

    let append_task = tokio::spawn({
        let writer = writer.clone();
        async move {
            writer
                .append(RUNNER.record_note(
                    session_id,
                    0,
                    now_ts(),
                    None,
                    NoteLevel::Info,
                    "note 3".into(),
                    1,
                ))
                .await
                .unwrap();
        }
    });

    let event = tokio::time::timeout(Duration::from_secs(1), follower.next())
        .await
        .expect("follow read must not hang")
        .unwrap();
    assert_eq!(event.seq, 3);
    assert_eq!(follower.cursor(), Some(3));
    append_task.await.unwrap();
}

/// Starting from `after = Some(1)` must skip seqs 0 and 1 entirely and resume at 2, with no
/// duplicate of anything at or before the cursor.
#[tokio::test]
async fn resumes_after_cursor_without_duplicates() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let feed = store.commit_feed().clone();
    let writer = spawn_writer(store).await;
    let session_id = SessionId::new();

    for i in 0..4 {
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

    let query_store = open(&db_path).await.unwrap();
    let mut follower = SessionFollower::new(query_store, &feed, session_id, Some(1));

    let first = tokio::time::timeout(Duration::from_secs(1), follower.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.seq, 2);

    let second = tokio::time::timeout(Duration::from_secs(1), follower.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second.seq, 3);
}

/// A commit that lands while a `read_after` call is already in flight — after the
/// underlying query has already run and observed nothing new, but before that (empty)
/// result reaches `next()` — must still be picked up, without the test having to send a
/// second `notify()`. This is exactly the race `CommitWatch::mark_seen`'s own doc comment
/// warns about: `mark_seen` must run BEFORE the read, not after.
#[tokio::test]
async fn commit_between_catch_up_and_wait_is_not_lost() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let feed = store.commit_feed().clone();
    let writer = spawn_writer(store).await;
    let session_id = SessionId::new();

    let query_store = open(&db_path).await.unwrap();
    let read_done = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let gated = GatedPageSource {
        inner: query_store,
        first_call_pending: Arc::new(AtomicBool::new(true)),
        read_done: read_done.clone(),
        release: release.clone(),
    };
    let mut follower = SessionFollower::new(gated, &feed, session_id, None);

    let next_fut = follower.next();
    let driver_fut = async {
        // Wait for the gated read to have already run (and seen nothing, since nothing has
        // been appended yet) before appending anything — this is what makes the scenario
        // "a commit lands while a stale read is in flight" rather than a lucky race.
        read_done.notified().await;
        writer
            .append(RUNNER.record_note(
                session_id,
                0,
                now_ts(),
                None,
                NoteLevel::Info,
                "late".into(),
                1,
            ))
            .await
            .unwrap();
        feed.notify(session_id);
        release.notify_one();
    };

    let (event_result, ()) = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(next_fut, driver_fut)
    })
    .await
    .expect("next() must return the late commit without hanging");

    let event = event_result.unwrap();
    assert_eq!(event.seq, 0);
    assert!(
        matches!(&event.payload, EventPayload::Note { text, .. } if text == "late"),
        "must be the event committed during the gated read, not something else"
    );
}

/// Polling `next()` once while its read is gated, then dropping it, must lose nothing: a
/// second `next()` call afterward returns the very same seq, exactly once — not skipped
/// (proving the cursor never moved for the abandoned attempt) and not duplicated.
///
/// Seeds TWO events, not one: the retried read comes back as a single two-event page, which
/// is what makes this test able to catch a cursor that advances to the PAGE's last seq as
/// soon as it's read rather than to each event's own seq as it's actually returned — with
/// only one event in the page the two buggy and correct cursor values would coincide and
/// this test would pass either way.
#[tokio::test]
async fn dropping_next_mid_read_loses_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let feed = store.commit_feed().clone();
    let writer = spawn_writer(store).await;
    let session_id = SessionId::new();

    for i in 0..2 {
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

    let query_store = open(&db_path).await.unwrap();
    let gated = GatedPageSource {
        inner: query_store,
        first_call_pending: Arc::new(AtomicBool::new(true)),
        read_done: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()), // never released — the first call must stay pending
    };
    let mut follower = SessionFollower::new(gated, &feed, session_id, None);

    {
        let fut = follower.next();
        futures::pin_mut!(fut);
        let poll = futures::poll!(&mut fut);
        assert!(
            poll.is_pending(),
            "the gated first read must not have resolved yet"
        );
    } // `fut` dropped here, mid-read.

    assert_eq!(
        follower.cursor(),
        None,
        "dropping a future mid-read must not advance the cursor"
    );

    let event = tokio::time::timeout(Duration::from_secs(1), follower.next())
        .await
        .expect("the retried read must not hang")
        .unwrap();
    assert_eq!(event.seq, 0, "the same seq must come back, exactly once");
    assert_eq!(
        follower.cursor(),
        Some(0),
        "cursor must advance to the returned event's own seq, not the page's last seq"
    );

    let second = tokio::time::timeout(Duration::from_secs(1), follower.next())
        .await
        .expect("the second buffered event must not hang")
        .unwrap();
    assert_eq!(second.seq, 1, "the second event must not be skipped");
    assert_eq!(follower.cursor(), Some(1));
}

/// 600 events — more than two full `FOLLOW_PAGE` (256) pages — must still come back in
/// exactly one order: 0, 1, 2, ..., 599, with no gaps and no repeats across the page
/// boundaries.
#[tokio::test]
async fn pages_larger_than_follow_page_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let feed = store.commit_feed().clone();
    let writer = spawn_writer(store).await;
    let session_id = SessionId::new();

    let events: Vec<_> = (0..600)
        .map(|i| {
            RUNNER.record_note(
                session_id,
                0,
                now_ts(),
                None,
                NoteLevel::Info,
                format!("note {i}"),
                1,
            )
        })
        .collect();
    writer.append_batch(events).await.unwrap();

    let query_store = open(&db_path).await.unwrap();
    let mut follower = SessionFollower::new(query_store, &feed, session_id, None);

    for expected_seq in 0..600u64 {
        let event = tokio::time::timeout(Duration::from_secs(5), follower.next())
            .await
            .expect("paged catch-up must not hang")
            .unwrap();
        assert_eq!(event.seq, expected_seq);
    }
    assert_eq!(follower.cursor(), Some(599));
}
