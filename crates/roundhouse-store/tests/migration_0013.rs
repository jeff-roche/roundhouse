//! Migration 0013 (`trigger_binding`, `trigger_binding_cursor`,
//! `trigger_delivery`, and `trigger_event.outcome`; Phase 8, Task 2 of the
//! trigger-delivery rebuild).
//!
//! Modelled directly on `tests/migration_0008.rs`: see that file's own doc
//! comment for what the fresh-vs-upgraded comparison can and cannot prove on
//! today's `rusqlite_migration` (no consolidated baseline exists in this
//! tree, so the two paths execute the identical statement sequence and
//! cannot diverge on their own — the assertions that actually discriminate
//! are the column/CHECK/index ones below).

use roundhouse_store::{migrations, open_memory_connection};
use rusqlite::Connection;

/// Migration 0013 is the 13th vec entry; a pre-0013 install sits at version
/// 12 (10 named migrations 0001..0010 plus the two trailing anonymous
/// `checkpoint_ref`/`checkpoint_blob_ref` `ALTER TABLE` strings).
const VERSION_BEFORE_TRIGGER_DELIVERY: usize = 12;

fn fresh_at_latest() -> Connection {
    let mut conn = open_memory_connection();
    migrations().to_latest(&mut conn).expect("fresh to latest");
    conn
}

fn upgraded_from_0012() -> Connection {
    let mut conn = open_memory_connection();
    migrations()
        .to_version(&mut conn, VERSION_BEFORE_TRIGGER_DELIVERY)
        .expect("stop at 0012");
    migrations()
        .to_latest(&mut conn)
        .expect("0012 -> latest applies");
    conn
}

/// `(name, type, notnull, dflt_value, pk)` for one column, in
/// `PRAGMA table_info` order.
type ColumnInfo = (String, String, bool, Option<String>, i64);

fn table_info(conn: &Connection, table: &str) -> Vec<ColumnInfo> {
    conn.prepare(&format!("PRAGMA table_info({table})"))
        .unwrap()
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// Every `CREATE` statement in the database, keyed by object name — the
/// stored text SQLite will re-parse on every future open.
fn schema_sql(conn: &Connection) -> Vec<(String, String)> {
    conn.prepare(
        "SELECT name, COALESCE(sql, '') FROM sqlite_master
         WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
    )
    .unwrap()
    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

#[test]
fn a_database_created_at_0012_reaches_exactly_the_schema_a_fresh_one_does() {
    let upgraded = upgraded_from_0012();
    let fresh = fresh_at_latest();

    assert_eq!(
        schema_sql(&upgraded),
        schema_sql(&fresh),
        "the 0012->0013 path and the fresh path must store identical schema text"
    );
    for table in [
        "trigger_binding",
        "trigger_binding_cursor",
        "trigger_delivery",
    ] {
        assert_eq!(
            table_info(&upgraded, table),
            table_info(&fresh, table),
            "table {table} must match on both migration paths"
        );
    }
    assert_eq!(
        table_info(&upgraded, "trigger_event"),
        table_info(&fresh, "trigger_event"),
    );
}

#[test]
fn trigger_binding_has_the_declared_columns() {
    let conn = fresh_at_latest();
    let info = table_info(&conn, "trigger_binding");
    let by_name = |name: &str| {
        info.iter()
            .find(|c| c.0 == name)
            .unwrap_or_else(|| panic!("trigger_binding has no column {name}, found {info:?}"))
            .clone()
    };

    let (_, ty, notnull, _default, pk) = by_name("binding_id");
    assert_eq!(ty, "TEXT");
    assert!(notnull);
    assert_eq!(pk, 1, "binding_id is the primary key");

    for column in ["workspace_id", "job_id", "spec_json", "overlap_json"] {
        let (_, ty, notnull, _default, pk) = by_name(column);
        assert_eq!(ty, "TEXT", "{column} must be TEXT");
        assert!(notnull, "{column} must be NOT NULL");
        assert_eq!(pk, 0, "{column} is not part of the primary key");
    }

    let (_, ty, notnull, default, _) = by_name("enabled");
    assert_eq!(ty, "INTEGER");
    assert!(notnull);
    assert_eq!(default, None, "enabled carries no default");

    let (_, ty, notnull, default, _) = by_name("created_at");
    assert_eq!(ty, "INTEGER");
    assert!(notnull, "created_at (unix nanos) is required");
    assert_eq!(default, None);
}

#[test]
fn trigger_binding_cursor_has_the_declared_columns() {
    let conn = fresh_at_latest();
    let info = table_info(&conn, "trigger_binding_cursor");
    let by_name = |name: &str| {
        info.iter()
            .find(|c| c.0 == name)
            .unwrap_or_else(|| {
                panic!("trigger_binding_cursor has no column {name}, found {info:?}")
            })
            .clone()
    };

    let (_, ty, notnull, _default, pk) = by_name("binding_id");
    assert_eq!(ty, "TEXT");
    assert!(notnull);
    assert_eq!(pk, 1);

    let (_, ty, notnull, default, _) = by_name("last_fired_for");
    assert_eq!(ty, "INTEGER");
    assert!(
        !notnull,
        "last_fired_for must stay nullable: NULL means never fired"
    );
    assert_eq!(default, None);

    // Deliberately absent: the scheduler recomputes its heap at boot rather
    // than trust a stored next-fire instant.
    assert!(
        info.iter().all(|c| c.0 != "next_fire_at"),
        "trigger_binding_cursor must not persist next_fire_at"
    );
}

#[test]
fn trigger_delivery_has_the_declared_columns() {
    let conn = fresh_at_latest();
    let info = table_info(&conn, "trigger_delivery");
    let by_name = |name: &str| {
        info.iter()
            .find(|c| c.0 == name)
            .unwrap_or_else(|| panic!("trigger_delivery has no column {name}, found {info:?}"))
            .clone()
    };

    let (_, ty, notnull, _default, pk) = by_name("delivery_id");
    assert_eq!(ty, "TEXT");
    assert!(notnull);
    assert_eq!(pk, 1);

    let (_, ty, notnull, _default, _) = by_name("trigger_event_id");
    assert_eq!(ty, "INTEGER");
    assert!(notnull);

    let (_, ty, notnull, _default, _) = by_name("binding_id");
    assert_eq!(ty, "TEXT");
    assert!(notnull);

    let (_, ty, notnull, _default, _) = by_name("state");
    assert_eq!(ty, "TEXT");
    assert!(notnull);

    let (_, ty, notnull, default, _) = by_name("attempts");
    assert_eq!(ty, "INTEGER");
    assert!(notnull);
    assert_eq!(
        default.as_deref(),
        Some("0"),
        "attempts defaults to an exact zero, not an unknown"
    );

    for nullable in ["lease_expires_at", "run_id", "session_id", "last_error"] {
        let (_, _, notnull, default, _) = by_name(nullable);
        assert!(!notnull, "{nullable} must stay nullable");
        assert_eq!(default, None, "{nullable} must carry no default");
    }

    for required_ts in ["created_at", "updated_at"] {
        let (_, ty, notnull, default, _) = by_name(required_ts);
        assert_eq!(ty, "INTEGER", "{required_ts} is unix nanos");
        assert!(notnull, "{required_ts} is required");
        assert_eq!(default, None);
    }
}

#[test]
fn trigger_event_gains_a_nullable_outcome_column_with_no_default() {
    let conn = fresh_at_latest();
    let info = table_info(&conn, "trigger_event");
    let (_, ty, notnull, default, _) = info
        .iter()
        .find(|c| c.0 == "outcome")
        .cloned()
        .expect("trigger_event.outcome must exist after migration 0013");
    assert_eq!(ty, "TEXT");
    assert!(
        !notnull,
        "outcome must stay nullable: a row can exist before admission decides"
    );
    assert_eq!(default, None);
}

/// A pre-0013 `trigger_event` row (inserted before migration 0013 ran) reads
/// back with `outcome = NULL` after the upgrade — the honest "never
/// recorded" state, not a manufactured default.
#[test]
fn a_pre_0013_trigger_event_row_survives_the_upgrade_with_no_outcome() {
    let mut conn = open_memory_connection();
    migrations()
        .to_version(&mut conn, VERSION_BEFORE_TRIGGER_DELIVERY)
        .unwrap();
    conn.execute(
        "INSERT INTO trigger_event
            (binding_id, idempotency_key, scheduled_for, fired_at, is_catch_up, session_id)
         VALUES ('binding-1', 'key-1', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 0, NULL)",
        [],
    )
    .unwrap();
    migrations().to_latest(&mut conn).unwrap();

    let outcome: Option<String> = conn
        .query_row(
            "SELECT outcome FROM trigger_event WHERE binding_id = 'binding-1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(outcome, None);
}

/// RED-verified: this insert must actually violate `enabled`'s `CHECK (enabled
/// IN (0, 1))`, not merely be assumed to.
#[test]
fn trigger_binding_enabled_rejects_out_of_domain_values_on_both_migration_paths() {
    for (label, conn) in [
        ("fresh", fresh_at_latest()),
        ("upgraded", upgraded_from_0012()),
    ] {
        let valid = conn.execute(
            "INSERT INTO trigger_binding
                (binding_id, workspace_id, job_id, spec_json, overlap_json, enabled, created_at)
             VALUES ('b-1', 'w-1', 'j-1', '{}', '{}', 1, 0)",
            [],
        );
        assert!(
            valid.is_ok(),
            "[{label}] a valid enabled value must insert: {valid:?}"
        );

        let invalid = conn.execute(
            "INSERT INTO trigger_binding
                (binding_id, workspace_id, job_id, spec_json, overlap_json, enabled, created_at)
             VALUES ('b-2', 'w-1', 'j-1', '{}', '{}', 2, 0)",
            [],
        );
        let err = invalid.expect_err(&format!("[{label}] enabled = 2 must be refused"));
        assert!(
            err.to_string().contains("CHECK constraint failed"),
            "[{label}] expected a CHECK constraint failure, got: {err}"
        );
    }
}

/// RED-verified: `trigger_delivery.state`'s `CHECK` actually enumerates the
/// nine declared states and actually refuses anything else.
#[test]
fn trigger_delivery_state_accepts_all_nine_states_and_rejects_others() {
    const INSERT: &str = "INSERT INTO trigger_delivery
        (delivery_id, trigger_event_id, binding_id, state, created_at, updated_at)
        VALUES (?1, 1, 'b-1', ?2, 0, 0)";

    for (label, conn) in [
        ("fresh", fresh_at_latest()),
        ("upgraded", upgraded_from_0012()),
    ] {
        for (i, state) in [
            "ready",
            "leased",
            "reserved",
            "running",
            "delivered",
            "failed",
            "cancellation_requested",
            "cancelled",
            "skipped",
        ]
        .into_iter()
        .enumerate()
        {
            let delivery_id = format!("d-{label}-{i}");
            conn.execute(INSERT, rusqlite::params![delivery_id, state])
                .unwrap_or_else(|e| panic!("[{label}] state {state:?} must be accepted: {e}"));
        }

        let bogus = conn.execute(INSERT, rusqlite::params!["d-bogus", "bogus"]);
        let err = bogus.expect_err(&format!("[{label}] an unrecognized state must be refused"));
        assert!(
            err.to_string().contains("CHECK constraint failed"),
            "[{label}] expected a CHECK constraint failure, got: {err}"
        );
    }
}

/// RED-verified: `attempts` really does default to an exact `0` on insert,
/// not merely claim to via `table_info`.
#[test]
fn trigger_delivery_attempts_defaults_to_zero() {
    let conn = fresh_at_latest();
    conn.execute(
        "INSERT INTO trigger_delivery
            (delivery_id, trigger_event_id, binding_id, state, created_at, updated_at)
         VALUES ('d-1', 1, 'b-1', 'ready', 0, 0)",
        [],
    )
    .unwrap();
    let attempts: i64 = conn
        .query_row(
            "SELECT attempts FROM trigger_delivery WHERE delivery_id = 'd-1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(attempts, 0);
}

/// RED-verified: `trigger_event.outcome`'s `CHECK` accepts every value in the
/// six-way `AdmissionDecision`-derived vocabulary and refuses anything else,
/// while still permitting `NULL` (an occurrence whose outcome is not yet
/// decided).
#[test]
fn trigger_event_outcome_accepts_the_admission_vocabulary_and_rejects_others() {
    const INSERT: &str = "INSERT INTO trigger_event
        (binding_id, idempotency_key, scheduled_for, fired_at, is_catch_up, session_id, outcome)
        VALUES (?1, ?2, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 0, NULL, ?3)";

    for (label, conn) in [
        ("fresh", fresh_at_latest()),
        ("upgraded", upgraded_from_0012()),
    ] {
        for (i, outcome) in [
            "admitted",
            "skipped_due_to_overlap",
            "queued",
            "cancelled_previous_and_admitted",
            "skipped_queue_full",
            "skipped_cancellation_unconfirmed",
        ]
        .into_iter()
        .enumerate()
        {
            let key = format!("key-{label}-{i}");
            conn.execute(
                INSERT,
                rusqlite::params![format!("binding-{i}"), key, outcome],
            )
            .unwrap_or_else(|e| panic!("[{label}] outcome {outcome:?} must be accepted: {e}"));
        }

        // NULL (not yet decided) must still be accepted.
        conn.execute(
            INSERT,
            rusqlite::params![
                "binding-null",
                format!("key-{label}-null"),
                Option::<String>::None
            ],
        )
        .unwrap_or_else(|e| panic!("[{label}] a NULL outcome must be accepted: {e}"));

        let bogus = conn.execute(
            INSERT,
            rusqlite::params!["binding-bogus", format!("key-{label}-bogus"), "bogus"],
        );
        let err = bogus.expect_err(&format!(
            "[{label}] an unrecognized outcome must be refused"
        ));
        assert!(
            err.to_string().contains("CHECK constraint failed"),
            "[{label}] expected a CHECK constraint failure, got: {err}"
        );
    }
}

/// The partial unique index on `run_id` enforces one delivery per run — but
/// only once `run_id` is actually set; any number of `NULL`-run rows coexist.
#[test]
fn trigger_delivery_run_id_is_unique_only_when_not_null() {
    let conn = fresh_at_latest();
    conn.execute(
        "INSERT INTO trigger_delivery
            (delivery_id, trigger_event_id, binding_id, state, run_id, created_at, updated_at)
         VALUES ('d-1', 1, 'b-1', 'running', 'run-1', 0, 0)",
        [],
    )
    .unwrap();

    let conflict = conn.execute(
        "INSERT INTO trigger_delivery
            (delivery_id, trigger_event_id, binding_id, state, run_id, created_at, updated_at)
         VALUES ('d-2', 1, 'b-1', 'running', 'run-1', 0, 0)",
        [],
    );
    assert!(
        conflict.is_err(),
        "a second delivery must not be able to claim the same run_id"
    );

    // Two NULL-run deliveries must coexist without conflict.
    conn.execute(
        "INSERT INTO trigger_delivery
            (delivery_id, trigger_event_id, binding_id, state, created_at, updated_at)
         VALUES ('d-3', 1, 'b-1', 'ready', 0, 0)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO trigger_delivery
            (delivery_id, trigger_event_id, binding_id, state, created_at, updated_at)
         VALUES ('d-4', 1, 'b-1', 'ready', 0, 0)",
        [],
    )
    .unwrap();
}

/// The partial unique index on `session_id` mirrors `run_id`'s.
#[test]
fn trigger_delivery_session_id_is_unique_only_when_not_null() {
    let conn = fresh_at_latest();
    conn.execute(
        "INSERT INTO trigger_delivery
            (delivery_id, trigger_event_id, binding_id, state, session_id, created_at, updated_at)
         VALUES ('d-1', 1, 'b-1', 'running', 'session-1', 0, 0)",
        [],
    )
    .unwrap();

    let conflict = conn.execute(
        "INSERT INTO trigger_delivery
            (delivery_id, trigger_event_id, binding_id, state, session_id, created_at, updated_at)
         VALUES ('d-2', 1, 'b-1', 'running', 'session-1', 0, 0)",
        [],
    );
    assert!(
        conflict.is_err(),
        "a second delivery must not be able to claim the same session_id"
    );
}

/// The claim query (find deliverable rows) is served by an index seek over
/// `trigger_delivery_claim_idx`, not a scan of terminal-state history.
#[test]
fn the_claim_index_serves_the_ready_or_leased_query() {
    let conn = fresh_at_latest();
    let plan: Vec<String> = conn
        .prepare(
            "EXPLAIN QUERY PLAN SELECT delivery_id FROM trigger_delivery
             WHERE state IN ('ready', 'leased') AND lease_expires_at <= ?1",
        )
        .unwrap()
        .query_map([0i64], |row| row.get::<_, String>(3))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let plan = plan.join(" | ");
    assert!(
        plan.contains("trigger_delivery_claim_idx"),
        "expected the partial claim index to serve this query, plan was: {plan}"
    );
}
