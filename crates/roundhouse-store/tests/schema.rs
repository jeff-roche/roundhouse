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
        // Phase 5: `trigger_event` (migration 0006) and the workflow
        // durability pair (migration 0007) live in the real store migration
        // list per ruling P4, not in a per-crate migrations file — so this
        // assertion is where "the daemon's actual database has them" is
        // checked.
        "trigger_event",
        "workflow_run",
        "workflow_step_run",
        "jobs",
        "job_versions",
        "jobs_no_update",
        "jobs_no_delete",
        "job_versions_no_update",
        "job_versions_no_delete",
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

#[test]
fn workflow_run_and_workflow_step_run_reject_unrecognized_discriminants() {
    // Migration 0007's CHECK constraints are the insert-time enforcement leg
    // for the state/disposition discriminants; `roundhouse_flow::durability`'s
    // fallible `from_sql_str` helpers are the read-back leg. This test covers
    // the first leg, which the typed Rust API cannot reach.
    let mut conn = open_memory_connection();
    migrations().to_latest(&mut conn).unwrap();

    conn.execute(
        "INSERT INTO workflow_run \
         (id, job_id, job_version, content_hash, session_id, state, started_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            "run-a",
            "job-a",
            1i64,
            "sha256:a",
            "session-a",
            "running",
            0i64
        ],
    )
    .expect("a recognized run state is accepted");

    let bogus_run_state = conn.execute(
        "INSERT INTO workflow_run \
         (id, job_id, job_version, content_hash, session_id, state, started_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            "run-b",
            "job-a",
            1i64,
            "sha256:a",
            "session-a",
            "bogus",
            0i64
        ],
    );
    assert!(
        bogus_run_state.is_err(),
        "an unrecognized workflow_run.state must violate the CHECK constraint"
    );

    // The positive control for every workflow_step_run assertion below. Without
    // it, a typo in the column list would make each of them fail for the wrong
    // reason and still pass. It also pins the column list itself, and its
    // 'skipped' state pins that a `when:`-skipped step — which Task 20 (B12)
    // writes and `exec::StepStatus::Skipped` already produces — is storable
    // without rebuilding a table SQLite cannot alter in place.
    const STEP_RUN_INSERT: &str = "INSERT INTO workflow_step_run \
         (run_id, step_id, attempt, item_index, disposition, state, output_is_secret_derived) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
    conn.execute(
        STEP_RUN_INSERT,
        rusqlite::params!["run-a", "s", 1i64, -1i64, "effectful", "skipped", 0i64],
    )
    .expect("a recognized disposition and state, with the sentinel item_index, is accepted");

    let bogus_disposition = conn
        .execute(
            STEP_RUN_INSERT,
            rusqlite::params!["run-a", "s2", 1i64, -1i64, "bogus", "running", 0i64],
        )
        .expect_err("an unrecognized workflow_step_run.disposition must be refused");
    // Not `ErrorCode::ConstraintViolation`, which also covers PRIMARY KEY and
    // NOT NULL and so would not discriminate between "the CHECK caught it" and
    // "the insert was malformed".
    assert!(
        bogus_disposition
            .to_string()
            .contains("CHECK constraint failed"),
        "expected a CHECK constraint failure, got: {bogus_disposition}"
    );

    let bogus_state = conn
        .execute(
            STEP_RUN_INSERT,
            rusqlite::params!["run-a", "s3", 1i64, -1i64, "effectful", "bogus", 0i64],
        )
        .expect_err("an unrecognized workflow_step_run.state must be refused");
    assert!(
        bogus_state.to_string().contains("CHECK constraint failed"),
        "expected a CHECK constraint failure, got: {bogus_state}"
    );

    let tainted_without_output = conn
        .execute(
            STEP_RUN_INSERT,
            rusqlite::params!["run-a", "s4", 1i64, -1i64, "effectful", "running", 1i64],
        )
        .expect_err("a row with no output cannot claim its (absent) output is secret-derived");
    assert!(
        tainted_without_output
            .to_string()
            .contains("CHECK constraint failed"),
        "expected a CHECK constraint failure, got: {tainted_without_output}"
    );

    // item_index is bounded at BOTH ends. The upper bound exists because
    // item_index is a u32 in Rust: an out-of-domain stored value would read
    // back through the same "not a u32" path as the -1 sentinel, aliasing two
    // rows with different states onto one identity.
    for (label, index) in [("above u32::MAX", 4_294_967_296i64), ("below -1", -2i64)] {
        let err = conn
            .execute(
                STEP_RUN_INSERT,
                rusqlite::params!["run-a", "s5", 1i64, index, "effectful", "running", 0i64],
            )
            .expect_err(label);
        assert!(
            err.to_string().contains("CHECK constraint failed"),
            "an item_index {label} must fail the CHECK constraint, got: {err}"
        );
    }
}
