//! Tests for `roundhouse_store::session_events` (Task 18): every event for
//! a session, in `seq` order — the session-scoped counterpart to
//! `suspended_tasks`, matching that function's own test coverage bar (see
//! `tests/suspended.rs`): multi-session isolation, ordering with more than
//! one event, and the corrupt-data error paths returning a real
//! `StoreError` rather than panicking or silently defaulting.

use roundhouse_core::{EventPayload, NoteLevel, SessionId, Timestamp};
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

/// A second session's events must never appear in the first session's
/// query results — `session_events` is scoped by `session_id`, not a
/// global scan.
#[tokio::test]
async fn session_events_isolates_events_by_session() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_a = SessionId::new();
    let session_b = SessionId::new();

    writer
        .append(RUNNER.record_note(
            session_a,
            0,
            now_ts(),
            None,
            NoteLevel::Info,
            "for session a".into(),
            1,
        ))
        .await
        .unwrap();
    writer
        .append(RUNNER.record_note(
            session_b,
            0,
            now_ts(),
            None,
            NoteLevel::Info,
            "for session b".into(),
            1,
        ))
        .await
        .unwrap();

    let query_store = open(&db_path).await.unwrap();
    let events_a = session_events(&query_store, session_a).await.unwrap();

    assert_eq!(events_a.len(), 1);
    assert!(matches!(
        &events_a[0].payload,
        EventPayload::Note { text, .. } if text == "for session a"
    ));
}

/// More than one event for the same session must come back in ascending
/// `seq` order, matching the real order they were appended in — not
/// insertion order of some other index, and not reversed.
#[tokio::test]
async fn session_events_returns_events_in_seq_ascending_order() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();

    for i in 0..5 {
        writer
            .append(RUNNER.record_note(
                session_id,
                0, // placeholder — EventWriter::append assigns the real seq
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
    let events = session_events(&query_store, session_id).await.unwrap();

    assert_eq!(events.len(), 5);
    // seq itself must be strictly ascending...
    for pair in events.windows(2) {
        assert!(
            pair[0].seq < pair[1].seq,
            "events must be returned in ascending seq order, got {} then {}",
            pair[0].seq,
            pair[1].seq
        );
    }
    // ...and it must be the REAL order events were appended in, not just
    // any ascending order the query happens to produce.
    for (i, event) in events.iter().enumerate() {
        assert!(
            matches!(&event.payload, EventPayload::Note { text, .. } if text == &format!("note {i}")),
            "event at position {i} must be \"note {i}\", proving seq order matches append order"
        );
    }
}

/// No events for a session (a session that doesn't exist, or exists but has
/// none) must return an empty `Vec`, not error.
#[tokio::test]
async fn session_events_is_empty_for_an_unknown_session() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();

    let events = session_events(&store, SessionId::new()).await.unwrap();
    assert!(events.is_empty());
}

/// The `events` table is physically append-only (S-LOG-2: `BEFORE
/// UPDATE`/`BEFORE DELETE` triggers `RAISE(ABORT, ...)` — see
/// `migrations.rs`), so these corrupt-data tests can't seed a legitimate
/// row and then `UPDATE` it corrupt the way `tests/suspended.rs` does
/// against the mutable `tasks` cache table. Instead they `INSERT` a
/// corrupt row directly via a raw connection, simulating data corruption
/// (e.g. from an incompatible schema version, or a bug in some other
/// writer) that the sanctioned `EventWriter::append` path itself would
/// never produce.
/// `session_events` must return `Err` for a non-JSON `payload` column, not
/// panic and not silently skip the corrupt row.
#[tokio::test]
async fn session_events_errors_on_corrupt_payload_instead_of_panicking() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();

    let session_id = SessionId::new();
    {
        let session_id_str = session_id.to_string();
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "INSERT INTO events (session_id, seq, ts, task_id, payload, schema_v) \
             VALUES (?1, 0, 0, NULL, 'not valid json', 1)",
            [session_id_str],
        )
        .unwrap();
    }

    let query_store = open(&db_path).await.unwrap();
    let _ = store; // keep the first pool alive for the duration of the test
    let result = session_events(&query_store, session_id).await;
    assert!(
        result.is_err(),
        "a corrupt payload column must be a hard error, not a panic or a silently-skipped row"
    );
}

/// Same fail-closed guard, other column: a raw-inserted row whose
/// `task_id` isn't a valid UUID. `session_events` must return `Err`.
#[tokio::test]
async fn session_events_errors_on_corrupt_task_id_instead_of_panicking() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();

    let session_id = SessionId::new();
    let valid_payload = serde_json::to_string(&EventPayload::Note {
        level: NoteLevel::Info,
        text: "otherwise valid".into(),
    })
    .unwrap();
    {
        let session_id_str = session_id.to_string();
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "INSERT INTO events (session_id, seq, ts, task_id, payload, schema_v) \
             VALUES (?1, 0, 0, 'not-a-uuid', ?2, 1)",
            rusqlite::params![session_id_str, valid_payload],
        )
        .unwrap();
    }

    let query_store = open(&db_path).await.unwrap();
    let _ = store; // keep the first pool alive for the duration of the test
    let result = session_events(&query_store, session_id).await;
    assert!(
        result.is_err(),
        "a corrupt task_id column must be a hard error, not a panic"
    );
}
