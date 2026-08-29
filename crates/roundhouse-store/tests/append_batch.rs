//! Tests for `EventWriter::append_batch` (Task 2): the batched-write path
//! `recovery.rs` uses to commit every interrupted task's synthetic
//! `TaskCancelled` event in one transaction instead of one round-trip per task.
//!
//! The one property that matters most here — and the one a naive
//! implementation gets wrong (see `writer.rs`'s doc comment on the seq-
//! assignment trap) — is that `events.seq` is scoped per `session_id`
//! (`PRIMARY KEY (session_id, seq)`), so a batch containing *multiple events
//! for the same session* must assign them sequential, non-colliding seqs
//! without re-querying the database mid-batch.

use roundhouse_core::{Event, Origin, SessionId, TaskId, TaskInput, TaskKind, Timestamp};
use roundhouse_store::{open, spawn_writer};

static RUNNER: once_cell::sync::Lazy<roundhouse_core::TaskRunner> =
    once_cell::sync::Lazy::new(roundhouse_core::TaskRunner::bootstrap);

fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

fn task_created_event(session_id: SessionId, task_id: TaskId) -> Event {
    RUNNER.record_task_created(
        session_id,
        0, // seq — ignored, reassigned by the writer
        now_ts(),
        task_id,
        TaskKind::Shell,
        None,
        Origin::Model,
        TaskInput::Text("test".into()),
        1,
    )
}

async fn events_for_session(
    store: &roundhouse_store::StorePool,
    session_id: SessionId,
) -> Vec<i64> {
    let conn = store.pool.get().await.unwrap();
    let session_id_str = session_id.to_string();
    conn.interact(move |c| {
        let mut stmt = c
            .prepare("SELECT seq FROM events WHERE session_id = ?1 ORDER BY seq")
            .unwrap();
        stmt.query_map([session_id_str], |row| row.get::<_, i64>(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    })
    .await
    .unwrap()
}

/// The critical case: a single batch carrying THREE events for the SAME
/// session_id (interleaved with events for a second, unrelated session) must
/// assign each of the three a distinct, sequential seq — not have two or more
/// collide on the same "next" value computed from an unchanged database MAX.
#[tokio::test]
async fn append_batch_assigns_sequential_seqs_within_one_session() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_a = SessionId::new();
    let session_b = SessionId::new();

    // Session A already has one committed event (seq 0) before the batch —
    // exercises the "seed from DB MAX the first time this session is seen"
    // half of the design, not just the "start from -1+1" empty-session case.
    let pre_existing = task_created_event(session_a, TaskId::new());
    let pre_seq = writer.append(pre_existing).await.unwrap();
    assert_eq!(pre_seq, 0);

    // Interleaved on purpose: A, B, A, B, A — so a broken implementation that
    // only special-cases "consecutive" same-session events would still be
    // caught.
    let batch = vec![
        task_created_event(session_a, TaskId::new()), // expect seq 1
        task_created_event(session_b, TaskId::new()), // expect seq 0
        task_created_event(session_a, TaskId::new()), // expect seq 2
        task_created_event(session_b, TaskId::new()), // expect seq 1
        task_created_event(session_a, TaskId::new()), // expect seq 3
    ];

    let seqs = writer.append_batch(batch).await.unwrap();

    assert_eq!(seqs, vec![1, 0, 2, 1, 3]);

    // Read back from the database directly: exactly 4 events for session A
    // (the pre-existing one plus 3 from the batch) with seqs 0..=3, and
    // exactly 2 for session B with seqs 0..=1 — no duplicates, no gaps, no
    // PRIMARY KEY collision (which would have surfaced as an error above).
    // `spawn_writer` moved the original `store` into the writer task, so a
    // fresh `StorePool` against the same path is opened for reading (`open`
    // is idempotent — migrations are already applied), same pattern
    // `tests/recovery.rs` and `tests/tasks_view.rs` use.
    let query_store = open(&db_path).await.unwrap();
    let session_a_seqs = events_for_session(&query_store, session_a).await;
    assert_eq!(session_a_seqs, vec![0, 1, 2, 3]);

    let session_b_seqs = events_for_session(&query_store, session_b).await;
    assert_eq!(session_b_seqs, vec![0, 1]);
}

/// `append_batch` must maintain the `tasks` materialized-cache row for EVERY
/// event in the batch, not just the first — the same invariant `append_one`
/// upholds for the single-event path (Task 0.5).
#[tokio::test]
async fn append_batch_upserts_tasks_row_for_every_event_in_the_batch() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();
    let task_ids: Vec<TaskId> = (0..5).map(|_| TaskId::new()).collect();
    let batch: Vec<Event> = task_ids
        .iter()
        .map(|&task_id| task_created_event(session_id, task_id))
        .collect();

    writer.append_batch(batch).await.unwrap();

    let query_store = open(&db_path).await.unwrap();
    let conn = query_store.pool.get().await.unwrap();
    for task_id in task_ids {
        let task_id_str = task_id.to_string();
        let state: String = conn
            .interact(move |c| {
                c.query_row(
                    "SELECT state FROM tasks WHERE task_id = ?1",
                    [task_id_str],
                    |row| row.get(0),
                )
            })
            .await
            .unwrap()
            .unwrap_or_else(|e| panic!("expected a tasks row for every batch member: {e}"));
        assert_eq!(state, "Created");
    }
}

/// An empty batch is a no-op, not an error — `recovery.rs` calls
/// `append_batch` with however many interrupted tasks it found, which is
/// legitimately zero on a clean boot.
#[tokio::test]
async fn append_batch_of_zero_events_is_a_harmless_no_op() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir.path().join("events.db")).await.unwrap();
    let writer = spawn_writer(store).await;

    let seqs = writer.append_batch(Vec::new()).await.unwrap();
    assert_eq!(seqs, Vec::<u64>::new());
}
