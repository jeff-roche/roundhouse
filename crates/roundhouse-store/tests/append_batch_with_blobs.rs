//! Tests for `EventWriter::append_batch_with_blobs` (Phase 8, Task 19 lane B, Task 5):
//! event-append and blob ref-count bookkeeping must commit together, in ONE transaction,
//! for every `Delta::Blob`/`TaskInput::Blob`/`TaskOutput::Blob` a batch's events carry.
//!
//! Two properties matter here, matching `blobs::record_blob_write`'s own doc comment
//! ("a blob can never be referenced by an event that isn't durably recorded, and vice
//! versa"), extended from the single-write path to the batch path:
//! - the ref-count bump and the event commit happen together (this file's first two
//!   tests), and
//! - a `record_blob_write` failure (a `BlobRef` with no backing file) rolls back the
//!   WHOLE batch — neither the events nor any ref-count bump for the batch commits.

use roundhouse_core::{
    Blake3Hash, BlobRef, Delta, Origin, SessionId, TaskId, TaskInput, TaskKind, TaskOutput,
    Timestamp, Trust, Usage,
};
use roundhouse_store::blobs::write_blob;
use roundhouse_store::{open, session_events, spawn_writer};

static RUNNER: once_cell::sync::Lazy<roundhouse_core::TaskRunner> =
    once_cell::sync::Lazy::new(roundhouse_core::TaskRunner::bootstrap);

fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

async fn ref_count(store: &roundhouse_store::StorePool, hash: &Blake3Hash) -> Option<i64> {
    let conn = store.pool.get().await.unwrap();
    let hash = hash.as_str().to_string();
    conn.interact(move |c| {
        c.query_row(
            "SELECT ref_count FROM blobs WHERE hash = ?1",
            [hash],
            |row| row.get::<_, i64>(0),
        )
    })
    .await
    .unwrap()
    .ok()
}

/// The core guarantee: a batch containing a single `Delta::Blob` event commits the event
/// AND bumps the blob's `ref_count`, together, in the same call.
#[tokio::test]
async fn append_batch_with_blobs_commits_the_event_and_bumps_ref_count_together() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let blob = write_blob(dir.path(), b"streamed shell stdout", None).unwrap();

    let session_id = SessionId::new();
    let task_id = TaskId::new();
    let event = RUNNER.record_task_delta(
        session_id,
        0,
        now_ts(),
        task_id,
        Delta::Blob(blob.clone()),
        1,
    );

    let seqs = writer
        .append_batch_with_blobs(vec![event], dir.path().to_path_buf())
        .await
        .unwrap();
    assert_eq!(seqs, vec![0]);

    let query_store = open(&db_path).await.unwrap();
    assert_eq!(
        ref_count(&query_store, &blob.hash).await,
        Some(1),
        "the blob's ref_count must be bumped in the same call that commits the event"
    );

    let events = session_events(&query_store, session_id).await.unwrap();
    assert_eq!(
        events.len(),
        1,
        "the event itself must be committed alongside the ref-count bump"
    );
}

/// Every blob-carrying payload shape this task covers — `TaskInput::Blob` (on
/// `TaskCreated`) and `TaskOutput::Blob` (on `TaskCompleted`) — must each get their own
/// `record_blob_write` call, all inside the one batch transaction.
#[tokio::test]
async fn append_batch_with_blobs_covers_task_input_and_task_output_blob_refs() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let input_blob = write_blob(dir.path(), b"input payload", None).unwrap();
    let output_blob = write_blob(dir.path(), b"output payload", None).unwrap();

    let session_id = SessionId::new();
    let task_id = TaskId::new();
    let created = RUNNER.record_task_created(
        session_id,
        0,
        now_ts(),
        task_id,
        TaskKind::Read,
        None,
        Origin::Model,
        TaskInput::Blob(input_blob.clone()),
        1,
    );
    let completed = RUNNER.record_task_completed(
        session_id,
        0,
        now_ts(),
        task_id,
        TaskOutput::Blob(output_blob.clone()),
        Usage::default(),
        Trust::Trusted,
        1,
    );

    let seqs = writer
        .append_batch_with_blobs(vec![created, completed], dir.path().to_path_buf())
        .await
        .unwrap();
    assert_eq!(seqs, vec![0, 1]);

    let query_store = open(&db_path).await.unwrap();
    assert_eq!(ref_count(&query_store, &input_blob.hash).await, Some(1));
    assert_eq!(ref_count(&query_store, &output_blob.hash).await, Some(1));

    let events = session_events(&query_store, session_id).await.unwrap();
    assert_eq!(events.len(), 2);
}

/// A `RecordBlobError::MissingFile` (a `BlobRef` whose file isn't actually on disk) must
/// roll back the WHOLE batch: neither the event nor the ref-count bump may commit.
#[tokio::test]
async fn a_missing_blob_file_rolls_back_both_the_event_and_the_ref_count() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let phantom_hash = "c".repeat(64);
    let phantom = BlobRef {
        hash: Blake3Hash::from_hex(phantom_hash).unwrap(),
        len: 4,
        mime: None,
    };

    let session_id = SessionId::new();
    let task_id = TaskId::new();
    let event = RUNNER.record_task_delta(
        session_id,
        0,
        now_ts(),
        task_id,
        Delta::Blob(phantom.clone()),
        1,
    );

    let result = writer
        .append_batch_with_blobs(vec![event], dir.path().to_path_buf())
        .await;
    assert!(
        result.is_err(),
        "a blob ref with no backing file must fail the whole call"
    );

    let query_store = open(&db_path).await.unwrap();
    assert_eq!(
        ref_count(&query_store, &phantom.hash).await,
        None,
        "no blobs row may exist for a ref that was never successfully indexed"
    );
    let events = session_events(&query_store, session_id).await.unwrap();
    assert!(
        events.is_empty(),
        "the event must not commit either — the whole batch rolls back together"
    );
}
