//! Tests for `EventWriter::append_batch_with_blobs` (Phase 8, Task 19 lane B, Task 5):
//! event-append and blob ref-count bookkeeping must commit together, in ONE transaction,
//! for every `Delta::Blob`/`TaskInput::Blob`/`TaskOutput::Blob` a batch's events carry.
//!
//! Properties covered here, matching `blobs::record_blob_write`'s own doc comment
//! ("a blob can never be referenced by an event that isn't durably recorded, and vice
//! versa"), extended from the single-write path to the batch path:
//! - the ref-count bump and the event commit happen together (this file's first two
//!   tests);
//! - a `record_blob_write` failure (a `BlobRef` with no backing file) rolls back the
//!   WHOLE batch, including an EARLIER member's already-successful ref-count bump — not
//!   just the failing member's own effects (fix round 1, security finding S5); and
//! - redaction genuinely runs on this path, not just on `append`/`append_batch` (fix
//!   round 1, security finding S6).

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
/// roll back the WHOLE batch, not just the failing member. Fix round 1, security finding
/// S5: the original version of this test used a single-member batch, which could only
/// prove "the failing member's own effects didn't commit" — it could not distinguish that
/// from a (buggy) implementation that rolled back only the failing member while letting an
/// EARLIER member's successful `record_blob_write`/event-append commit anyway. This
/// version uses a two-member batch — `[event with a REAL, on-disk blob, event with the
/// phantom blob]` — so a real ref-count bump for the first member is what's actually on
/// the line, and asserts it did NOT commit either.
#[tokio::test]
async fn a_missing_blob_file_rolls_back_the_whole_batch_including_an_earlier_real_blob() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let real_blob = write_blob(dir.path(), b"this one really exists on disk", None).unwrap();
    let phantom_hash = "c".repeat(64);
    let phantom = BlobRef {
        hash: Blake3Hash::from_hex(phantom_hash).unwrap(),
        len: 4,
        mime: None,
    };

    let session_id = SessionId::new();
    let real_task_id = TaskId::new();
    let phantom_task_id = TaskId::new();
    let real_event = RUNNER.record_task_delta(
        session_id,
        0,
        now_ts(),
        real_task_id,
        Delta::Blob(real_blob.clone()),
        1,
    );
    let phantom_event = RUNNER.record_task_delta(
        session_id,
        0,
        now_ts(),
        phantom_task_id,
        Delta::Blob(phantom.clone()),
        1,
    );

    let result = writer
        .append_batch_with_blobs(vec![real_event, phantom_event], dir.path().to_path_buf())
        .await;
    assert!(
        result.is_err(),
        "a blob ref with no backing file must fail the whole call"
    );

    let query_store = open(&db_path).await.unwrap();
    assert_eq!(
        ref_count(&query_store, &phantom.hash).await,
        None,
        "no blobs row may exist for the ref that was never successfully indexed"
    );
    assert_eq!(
        ref_count(&query_store, &real_blob.hash).await,
        None,
        "the EARLIER member's real, on-disk blob must not have its ref_count bumped either \
         — the whole batch rolls back together, not just the member that failed"
    );
    let events = session_events(&query_store, session_id).await.unwrap();
    assert!(
        events.is_empty(),
        "neither event may commit — the whole batch rolls back together"
    );
}

/// Fix round 1, security finding S6: proves redaction actually runs on THIS path, not just
/// on `append`/`append_batch`. A `Delta::Stdout` chunk carrying a live secret, appended
/// through `append_batch_with_blobs`, must have its raw stored payload scrubbed exactly
/// like the plain `append` path already does (see `tests/redaction.rs`'s
/// `live_secret_value_never_lands_in_the_stored_row`) — checked with the same raw-column
/// read, not by trusting the in-memory `EventPayload`.
#[tokio::test]
async fn append_batch_with_blobs_redacts_a_secret_in_a_stdout_delta() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    writer.set_redactor(roundhouse_store::redact::Redactor::build(&[
        "sk-live-abc123".to_string(),
    ]));

    let session_id = SessionId::new();
    let task_id = TaskId::new();
    // A TaskDelta needs a prior TaskCreated row before a redaction match on it can
    // increment `tasks.redactions` without hard-erroring (Task 19 addendum, Ruling 5's
    // fail-closed check) — same precondition `tests/redaction.rs`'s own `create_task`
    // helper exists for. Appended directly, not through `append_batch_with_blobs` —
    // this test is about the STDOUT delta's redaction, not about batching TaskCreated.
    writer
        .append(RUNNER.record_task_created(
            session_id,
            0,
            now_ts(),
            task_id,
            TaskKind::Shell,
            None,
            Origin::Model,
            TaskInput::Text("run a command".into()),
            1,
        ))
        .await
        .unwrap();

    let event = RUNNER.record_task_delta(
        session_id,
        0,
        now_ts(),
        task_id,
        Delta::Stdout {
            bytes: b"stdout: the key is sk-live-abc123".to_vec().into(),
        },
        1,
    );

    writer
        .append_batch_with_blobs(vec![event], dir.path().to_path_buf())
        .await
        .unwrap();

    let query_store = open(&db_path).await.unwrap();
    let raw_row_text =
        roundhouse_store::redact::debug_read_raw_payload_text(&query_store, session_id, task_id)
            .await
            .unwrap();
    // `Delta::Stdout.bytes` serializes to a JSON array of byte VALUES (not inline text —
    // see `Delta`'s `bytes_as_vec` serde shim), so a literal-substring check on the raw
    // JSON text would never find "[REDACTED]" even when redaction worked correctly. This
    // decodes the actual stored byte array back to text to check the real content, the
    // way this payload shape requires.
    let raw_value: serde_json::Value = serde_json::from_str(&raw_row_text).unwrap();
    let stored_bytes: Vec<u8> = raw_value["TaskDelta"]["delta"]["Stdout"]
        .as_array()
        .unwrap_or_else(|| panic!("expected a Stdout byte array in: {raw_row_text}"))
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect();
    let stored_text = String::from_utf8(stored_bytes).unwrap();
    assert!(
        !stored_text.contains("sk-live-abc123"),
        "a live secret in a Delta::Stdout chunk appended through append_batch_with_blobs \
         must never reach the stored row: {stored_text}"
    );
    assert!(
        stored_text.contains("[REDACTED]"),
        "the redacted placeholder must appear in its place: {stored_text}"
    );
}
