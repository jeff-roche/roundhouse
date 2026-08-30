//! Tests for Task 19: Aho-Corasick redaction at the persistence boundary
//! (`roundhouse_store::redact::Redactor`). Real store types throughout, per the task-19
//! addendum: `StorePool`/`EventWriter`/`TaskRunner`, not the brief's fictional `Store`.
//!
//! Step 1's core guarantee: a live secret value must never physically reach the raw
//! `events.payload` column — checked with a direct raw-SQL read
//! (`redact::debug_read_raw_payload_text`), not by trusting the redacted `EventPayload`
//! constructed in memory. Step 6 (scoped per Ruling 8): `Redactor::scan_outbound` is
//! exercised directly against a real `StorePool`/`EventWriter`/`TaskRunner` trio — it is
//! not wired into any provider call site by this task.

use roundhouse_core::{
    Delta, EventPayload, NoteLevel, Origin, SessionId, TaskId, TaskInput, TaskKind, Timestamp,
};
use roundhouse_store::redact::{debug_read_raw_payload_text, Redactor, SecretLeakDisposition};
use roundhouse_store::{open, session_events, spawn_writer};

/// `TaskRunner::bootstrap()` panics on a second call in the same process (S-LOG-1) — every
/// test in this file shares one process, so they must share one `TaskRunner` instance
/// (same pattern as `tests/append.rs`/`tests/session_events.rs`).
static RUNNER: once_cell::sync::Lazy<roundhouse_core::TaskRunner> =
    once_cell::sync::Lazy::new(roundhouse_core::TaskRunner::bootstrap);

fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

/// `upsert_for_event`'s `UPDATE` branch hard-errors on a zero-row match (Task 0.5's
/// security fix) — a `TaskDelta` needs a real `TaskCreated` row to update first. Returns
/// the new `task_id`.
async fn create_task(writer: &roundhouse_store::EventWriter, session_id: SessionId) -> TaskId {
    let task_id = TaskId::new();
    writer
        .append(RUNNER.record_task_created(
            session_id,
            0,
            now_ts(),
            task_id,
            TaskKind::Chat,
            None,
            Origin::Model,
            TaskInput::Text("test".into()),
            1,
        ))
        .await
        .unwrap();
    task_id
}

#[tokio::test]
async fn live_secret_value_never_lands_in_the_stored_row() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir.path().join("events.db")).await.unwrap();
    let writer = spawn_writer(store).await;
    writer.set_redactor(Redactor::build(&["sk-live-abc123".to_string()]));

    let session_id = SessionId::new();
    let task_id = create_task(&writer, session_id).await;

    writer
        .append(RUNNER.record_task_delta(
            session_id,
            0,
            now_ts(),
            task_id,
            Delta::Text {
                text: "the key is sk-live-abc123 don't share it".into(),
            },
            1,
        ))
        .await
        .unwrap();

    let query_store = open(&dir.path().join("events.db")).await.unwrap();
    let raw_row_text = debug_read_raw_payload_text(&query_store, session_id, task_id)
        .await
        .unwrap();
    assert!(
        !raw_row_text.contains("sk-live-abc123"),
        "a leaked value must never reach the SQLite row, even read directly: {raw_row_text}"
    );
    assert!(
        raw_row_text.contains("[REDACTED]"),
        "the redacted placeholder must appear in its place: {raw_row_text}"
    );
}

#[tokio::test]
async fn redaction_count_is_zero_when_nothing_matches_making_failure_visible() {
    let redactor = Redactor::build(&["sk-live-abc123".to_string()]);
    let (redacted, count) = redactor.redact_event_payload(EventPayload::TaskDelta {
        delta: Delta::Text {
            text: "nothing secret here".into(),
        },
    });
    assert_eq!(
        count, 0,
        "0 is the diagnostic signal that redaction found nothing — not an error, but must \
         be visible per-task, never silently dropped"
    );
    match redacted {
        EventPayload::TaskDelta {
            delta: Delta::Text { text },
        } => assert_eq!(text, "nothing secret here"),
        other => panic!("unexpected payload: {other:?}"),
    }
}

/// Proves the redaction-count accumulation runs on a path INDEPENDENT of
/// `upsert_for_event`'s early-return for `TaskDelta`/`Note` (Task 19 addendum, Ruling 5's
/// gotcha) — this test would fail (`redactions` would stay 0) if the accumulation had been
/// naively added inside `upsert_for_event`'s existing match arms instead of as a separate,
/// unconditional `UPDATE` alongside it.
#[tokio::test]
async fn redaction_count_accumulates_on_the_tasks_row_for_task_delta_and_note_events() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    writer.set_redactor(Redactor::build(&["sk-live-abc123".to_string()]));

    let session_id = SessionId::new();
    let task_id = create_task(&writer, session_id).await;

    // Two redactable events for the same task: one TaskDelta match, one Note match.
    writer
        .append(RUNNER.record_task_delta(
            session_id,
            0,
            now_ts(),
            task_id,
            Delta::Text {
                text: "leak: sk-live-abc123".into(),
            },
            1,
        ))
        .await
        .unwrap();
    writer
        .append(RUNNER.record_note(
            session_id,
            0,
            now_ts(),
            Some(task_id),
            NoteLevel::Info,
            "also leaked: sk-live-abc123".into(),
            1,
        ))
        .await
        .unwrap();

    let query_store = open(&db_path).await.unwrap();
    let conn = query_store.pool.get().await.unwrap();
    let task_id_str = task_id.to_string();
    let redactions: i64 = conn
        .interact(move |c| {
            c.query_row(
                "SELECT redactions FROM tasks WHERE task_id = ?1",
                [task_id_str],
                |row| row.get(0),
            )
        })
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        redactions, 2,
        "the tasks.redactions counter must accumulate across both the TaskDelta and Note \
         events for this task, even though upsert_for_event itself early-returns (no state \
         change) for both payload kinds"
    );
}

#[tokio::test]
async fn outbound_payload_containing_a_live_secret_is_ask_by_default_and_deny_hardened() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir.path().join("events.db")).await.unwrap();
    let writer = spawn_writer(store).await;
    let redactor = Redactor::build(&["sk-live-abc123".to_string()]);

    let session_id = SessionId::new();
    let outbound = "please use this key: sk-live-abc123 to authenticate";

    let disposition = redactor
        .scan_outbound(&RUNNER, &writer, session_id, outbound, false)
        .await
        .unwrap();
    assert_eq!(
        disposition,
        Some(SecretLeakDisposition::Ask),
        "§6.7: SecretLeak is Ask by default"
    );

    let hardened_disposition = redactor
        .scan_outbound(&RUNNER, &writer, session_id, outbound, true)
        .await
        .unwrap();
    assert_eq!(
        hardened_disposition,
        Some(SecretLeakDisposition::Deny),
        "§6.7: SecretLeak is Deny under --profile hardened"
    );

    let events = session_events(
        &open(&dir.path().join("events.db")).await.unwrap(),
        session_id,
    )
    .await
    .unwrap();
    assert!(
        events.iter().any(|e| matches!(
            &e.payload,
            EventPayload::Note { level: NoteLevel::Warn, text } if text.contains("SecretLeak")
        )),
        "a detected leak must be a visible Note event, not a log line"
    );
}

#[tokio::test]
async fn outbound_payload_with_no_secret_is_none_and_never_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir.path().join("events.db")).await.unwrap();
    let writer = spawn_writer(store).await;
    let redactor = Redactor::build(&["sk-live-abc123".to_string()]);

    let disposition = redactor
        .scan_outbound(
            &RUNNER,
            &writer,
            SessionId::new(),
            "nothing sensitive here",
            false,
        )
        .await
        .unwrap();
    assert_eq!(disposition, None);
}
