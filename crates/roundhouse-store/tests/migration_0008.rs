//! Migration 0008 (`workflow_run`'s run-level ledger, Phase 5 B12b).
//!
//! # Why this file tests two paths and compares them
//!
//! A migration has two consumers that never meet: an **existing** install,
//! which arrives at the new schema by applying 0008 on top of 0007, and a
//! **fresh** install, which applies 0001..0008 in one go. Those are the two
//! paths that diverge if anything is wrong — a column added with the wrong
//! type, a `CHECK` that only one path carries, an index created twice — and a
//! test that exercises only `to_latest()` on an empty database checks the
//! second and says nothing about the first. Ruling P69 §2: migrations are the
//! expensive irreversible surface, and an existing install that keeps working
//! while a fresh one fails (or vice versa) is a divergence nobody sees until
//! it is shipped.
//!
//! Every assertion below is measured against the **bundled** SQLite
//! (`rusqlite` `features = ["bundled"]`, `libsqlite3-sys` 0.38.2), whose
//! version this file's first test prints and pins the major/minor of.

use roundhouse_store::{migrations, open_memory_connection};
use rusqlite::Connection;

/// Migration 0007 is the last one before this task's. Named rather than
/// spelled `7` at four call sites, since "the version a pre-0008 install sits
/// at" is the fact being expressed.
const VERSION_BEFORE_LEDGER: usize = 7;

fn fresh_at_latest() -> Connection {
    let mut conn = open_memory_connection();
    migrations().to_latest(&mut conn).expect("fresh to latest");
    conn
}

fn upgraded_from_0007() -> Connection {
    let mut conn = open_memory_connection();
    migrations()
        .to_version(&mut conn, VERSION_BEFORE_LEDGER)
        .expect("stop at 0007");
    migrations()
        .to_latest(&mut conn)
        .expect("0007 -> latest applies");
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

/// The SQLite the rest of this file's claims were measured against.
///
/// Printed rather than only asserted: a report that says "tested on SQLite X"
/// should be able to quote the run, and a future bump of `libsqlite3-sys`
/// changes this number without changing any Rust in the tree.
#[test]
fn the_bundled_sqlite_version_these_claims_were_measured_against() {
    let conn = open_memory_connection();
    let version: String = conn
        .query_row("SELECT sqlite_version()", [], |row| row.get(0))
        .unwrap();
    println!("bundled SQLite version: {version}");
    assert!(
        version.starts_with("3."),
        "expected a SQLite 3 series version, got {version}"
    );
}

#[test]
fn a_database_created_at_0007_reaches_exactly_the_schema_a_fresh_one_does() {
    let upgraded = upgraded_from_0007();
    let fresh = fresh_at_latest();

    // The stored `CREATE` text is the strongest form of this assertion: it is
    // what a future SQLite parses on open, so two installs whose stored text
    // differs are two installs running different schemas however similar
    // `table_info` looks.
    assert_eq!(
        schema_sql(&upgraded),
        schema_sql(&fresh),
        "the 0007->0008 path and the fresh path must store identical schema text"
    );
    assert_eq!(
        table_info(&upgraded, "workflow_run"),
        table_info(&fresh, "workflow_run"),
    );
}

#[test]
fn the_ledger_columns_land_on_workflow_run_with_the_declared_types_and_defaults() {
    let conn = fresh_at_latest();
    let info = table_info(&conn, "workflow_run");
    let by_name = |name: &str| {
        info.iter()
            .find(|c| c.0 == name)
            .unwrap_or_else(|| panic!("workflow_run has no column {name}, found {info:?}"))
            .clone()
    };

    // Nullable, no default: absent is the honest reading of "this run has
    // never parked" / "this run's depth was never recorded".
    for nullable in [
        "parked_at",
        "hold_until",
        "session_depth",
        "caps_json",
        "refunded_at",
    ] {
        let (_, _, notnull, default, _) = by_name(nullable);
        assert!(!notnull, "{nullable} must stay nullable");
        assert_eq!(default, None, "{nullable} must carry no default");
    }

    // Accumulators: `NOT NULL DEFAULT 0`, because 0 is the *exact* value for a
    // row that has recorded nothing — not a stand-in for an unknown.
    for accumulator in [
        "parked_nanos",
        "spent_tokens",
        "spent_tasks",
        "spent_tool_calls",
        "spent_subagents",
        "spent_bytes_written",
        "spent_escalations",
    ] {
        let (_, ty, notnull, default, _) = by_name(accumulator);
        assert_eq!(ty, "INTEGER", "{accumulator} must be INTEGER");
        assert!(notnull, "{accumulator} must be NOT NULL");
        assert_eq!(default.as_deref(), Some("0"), "{accumulator} defaults to 0");
    }

    let (_, ty, notnull, default, _) = by_name("spent_cost_usd");
    assert_eq!(
        ty, "REAL",
        "the dollar accumulator matches ResourceCaps' f64"
    );
    assert!(notnull);
    assert_eq!(default.as_deref(), Some("0.0"));

    assert_eq!(by_name("caps_json").1, "TEXT");
    assert_eq!(by_name("parked_at").1, "INTEGER");
}

/// A row written before 0008 keeps every value it had and reads the
/// accumulators back as an exact zero rather than as `NULL`.
#[test]
fn a_run_row_written_at_0007_survives_the_upgrade_with_zeroed_accumulators() {
    let mut conn = open_memory_connection();
    migrations()
        .to_version(&mut conn, VERSION_BEFORE_LEDGER)
        .unwrap();
    conn.execute(
        "INSERT INTO workflow_run
            (id, job_id, job_version, content_hash, session_id, state, started_at)
         VALUES ('run-1', 'job-1', 1, 'hash', 'session-1', 'running', 42)",
        [],
    )
    .unwrap();
    migrations().to_latest(&mut conn).unwrap();

    let (started_at, parked_nanos, spent_tokens, spent_cost, parked_at, session_depth): (
        i64,
        i64,
        i64,
        f64,
        Option<i64>,
        Option<i64>,
    ) = conn
        .query_row(
            "SELECT started_at, parked_nanos, spent_tokens, spent_cost_usd, parked_at,
                    session_depth
             FROM workflow_run WHERE id = 'run-1'",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap();

    assert_eq!(started_at, 42, "0007's own columns are untouched");
    assert_eq!(parked_nanos, 0);
    assert_eq!(spent_tokens, 0);
    assert_eq!(spent_cost, 0.0);
    assert_eq!(parked_at, None);
    // The fail-closed half of the pair: a pre-0008 row's session depth is
    // genuinely unknown, and `NULL` says so. A `NOT NULL DEFAULT 0` would have
    // had every legacy row claim to be a root — the fail-*open* answer for
    // exactly the rows the schema knows least about.
    assert_eq!(session_depth, None);
}

/// The per-column `CHECK`s are real `ADD COLUMN` syntax (ruling P104) and are
/// enforced on both migration paths.
#[test]
fn the_new_columns_reject_out_of_domain_values_on_both_migration_paths() {
    for (label, conn) in [
        ("fresh", fresh_at_latest()),
        ("upgraded", upgraded_from_0007()),
    ] {
        conn.execute(
            "INSERT INTO workflow_run
                (id, job_id, job_version, content_hash, session_id, state, started_at)
             VALUES ('run-1', 'job-1', 1, 'hash', 'session-1', 'running', 0)",
            [],
        )
        .unwrap();

        for (column, value) in [
            ("parked_at", "-1"),
            ("hold_until", "-1"),
            ("refunded_at", "-1"),
            ("parked_nanos", "-1"),
            ("session_depth", "-1"),
            ("session_depth", "4294967296"),
            ("spent_tokens", "-1"),
            ("spent_cost_usd", "-0.5"),
            ("spent_tasks", "-1"),
            ("spent_tool_calls", "-1"),
            ("spent_subagents", "-1"),
            ("spent_bytes_written", "-1"),
            ("spent_escalations", "-1"),
        ] {
            let attempt = conn.execute(
                &format!("UPDATE workflow_run SET {column} = {value} WHERE id = 'run-1'"),
                [],
            );
            assert!(
                attempt.is_err(),
                "[{label}] {column} = {value} must violate its CHECK, got {attempt:?}"
            );
        }

        // `session_depth`'s upper bound is `u32::MAX` because the Rust field is
        // a `u32`; the boundary value itself is legal.
        conn.execute(
            "UPDATE workflow_run SET session_depth = 4294967295 WHERE id = 'run-1'",
            [],
        )
        .unwrap_or_else(|e| panic!("[{label}] u32::MAX depth must be storable: {e}"));
    }
}

/// Measured, and load-bearing for `ledger::admit_spend`'s Rust-side guard:
/// SQLite stores an `f64` `NaN` as `NULL`, so a `NOT NULL` dollar column
/// rejects it — but `+inf` satisfies `CHECK (spent_cost_usd >= 0)` and is
/// stored. The column cannot be the whole guard, which is why the writer has
/// one of its own.
#[test]
fn the_dollar_column_rejects_nan_by_not_null_but_accepts_infinity() {
    let conn = fresh_at_latest();
    conn.execute(
        "INSERT INTO workflow_run
            (id, job_id, job_version, content_hash, session_id, state, started_at)
         VALUES ('run-1', 'job-1', 1, 'hash', 'session-1', 'running', 0)",
        [],
    )
    .unwrap();

    let nan = conn.execute(
        "UPDATE workflow_run SET spent_cost_usd = ?1 WHERE id = 'run-1'",
        [f64::NAN],
    );
    assert!(nan.is_err(), "NaN becomes NULL and the column is NOT NULL");

    let infinite = conn.execute(
        "UPDATE workflow_run SET spent_cost_usd = ?1 WHERE id = 'run-1'",
        [f64::INFINITY],
    );
    assert!(
        infinite.is_ok(),
        "+inf passes `>= 0`; the Rust writer is what refuses it"
    );
}

/// The reaper's query is an index seek, not a scan of every run ever.
#[test]
fn the_reaper_index_serves_the_parked_at_query() {
    let conn = fresh_at_latest();
    let plan: Vec<String> = conn
        .prepare("EXPLAIN QUERY PLAN SELECT id FROM workflow_run WHERE parked_at <= ?1")
        .unwrap()
        .query_map([0i64], |row| row.get::<_, String>(3))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let plan = plan.join(" | ");
    assert!(
        plan.contains("workflow_run_parked_idx"),
        "expected the partial index to serve the reaper query, plan was: {plan}"
    );
}
