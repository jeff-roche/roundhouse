use roundhouse_store::{migrations, open_memory_connection};

fn seeded_conn() -> rusqlite::Connection {
    let mut conn = open_memory_connection();
    migrations().to_latest(&mut conn).unwrap();
    conn.execute(
        "INSERT INTO events (session_id, seq, ts, task_id, payload, schema_v) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params!["session-a", 1i64, 0i64, Option::<String>::None, "{}", 1i64],
    )
    .unwrap();
    conn
}

#[test]
fn raw_update_on_events_is_aborted_by_trigger() {
    let conn = seeded_conn();
    let result = conn.execute(
        "UPDATE events SET payload = ?1 WHERE session_id = ?2 AND seq = ?3",
        rusqlite::params!["{\"tampered\":true}", "session-a", 1i64],
    );
    assert!(
        result.is_err(),
        "S-LOG-2: UPDATE on events must be aborted by the trigger"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("append-only"),
        "trigger error should explain why: {msg}"
    );
}

#[test]
fn raw_delete_on_events_is_aborted_by_trigger() {
    let conn = seeded_conn();
    let result = conn.execute(
        "DELETE FROM events WHERE session_id = ?1 AND seq = ?2",
        rusqlite::params!["session-a", 1i64],
    );
    assert!(
        result.is_err(),
        "S-LOG-2: DELETE on events must be aborted by the trigger"
    );
}

#[test]
fn append_still_works_after_trigger_install() {
    let conn = seeded_conn();
    let inserted = conn.execute(
        "INSERT INTO events (session_id, seq, ts, task_id, payload, schema_v) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params!["session-a", 2i64, 1i64, Option::<String>::None, "{}", 1i64],
    );
    assert_eq!(
        inserted.unwrap(),
        1,
        "INSERT must remain unaffected by the append-only triggers"
    );
}
