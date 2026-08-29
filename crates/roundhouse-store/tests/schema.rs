use roundhouse_store::{migrations, open_memory_connection};

#[test]
fn migrations_create_events_tasks_and_fts_tables() {
    let mut conn = open_memory_connection();
    migrations()
        .to_latest(&mut conn)
        .expect("migrations apply cleanly");

    let table_names: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type IN ('table', 'trigger')")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();

    for expected in [
        "events",
        "tasks",
        "tasks_fts",
        "events_no_update",
        "events_no_delete",
    ] {
        assert!(
            table_names.iter().any(|n| n == expected),
            "expected {expected} to exist after migration, found {table_names:?}"
        );
    }
}

#[test]
fn events_primary_key_is_session_id_and_seq() {
    let mut conn = open_memory_connection();
    migrations().to_latest(&mut conn).unwrap();

    conn.execute(
        "INSERT INTO events (session_id, seq, ts, task_id, payload, schema_v) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params!["session-a", 1i64, 0i64, Option::<String>::None, "{}", 1i64],
    )
    .unwrap();

    let duplicate = conn.execute(
        "INSERT INTO events (session_id, seq, ts, task_id, payload, schema_v) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params!["session-a", 1i64, 1i64, Option::<String>::None, "{}", 1i64],
    );
    assert!(
        duplicate.is_err(),
        "duplicate (session_id, seq) must violate the primary key"
    );
}

#[test]
fn tasks_state_column_rejects_unrecognized_values_and_accepts_known_ones() {
    // X1 fix: `tasks.state` used to be an unconstrained TEXT column. This
    // CHECK constraint is the insert-time enforcement leg matching
    // roundhouse_core::TaskState's eight variants (the discriminant only —
    // see the migration's comment).
    let mut conn = open_memory_connection();
    migrations().to_latest(&mut conn).unwrap();

    let valid = conn.execute(
        "INSERT INTO tasks (task_id, session_id, kind, state, parent, created_seq, updated_seq) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            "task-a",
            "session-a",
            "Shell",
            "Running",
            Option::<String>::None,
            1i64,
            1i64
        ],
    );
    assert!(
        valid.is_ok(),
        "a recognized TaskState discriminant must be accepted: {valid:?}"
    );

    let invalid = conn.execute(
        "INSERT INTO tasks (task_id, session_id, kind, state, parent, created_seq, updated_seq) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            "task-b",
            "session-a",
            "Shell",
            "bogus",
            Option::<String>::None,
            1i64,
            1i64
        ],
    );
    assert!(
        invalid.is_err(),
        "an unrecognized state string must violate the CHECK constraint"
    );
}
