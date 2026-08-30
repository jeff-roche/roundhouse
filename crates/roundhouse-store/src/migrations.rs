use rusqlite_migration::{Migrations, M};

/// §4.1/§12.3 (S-LOG-2) — the events table is the source of truth and is
/// physically append-only: the two `BEFORE UPDATE`/`BEFORE DELETE` triggers
/// abort with `RAISE(ABORT, ...)`, not just a documented convention.
/// `tasks` is the derived materialised-view table (§4.1: "a derived cache
/// maintained by the single writer"). `tasks_fts` is the FTS5 index over
/// task content (§12.5's FTS search budget; §15's "memory is lexical FTS").
const MIGRATION_0001_INITIAL_SCHEMA: &str = r#"
CREATE TABLE events (
    session_id TEXT    NOT NULL,
    seq        INTEGER NOT NULL,
    ts         INTEGER NOT NULL,
    task_id    TEXT,
    payload    TEXT    NOT NULL,
    schema_v   INTEGER NOT NULL,
    PRIMARY KEY (session_id, seq)
) STRICT;

CREATE INDEX events_task_id_idx ON events (task_id) WHERE task_id IS NOT NULL;

-- S-LOG-2: events table is append-only by design (source of truth for
-- the whole system). These triggers enforce immutability at the
-- database level, not by application convention — do not drop them.
CREATE TRIGGER events_no_update
BEFORE UPDATE ON events
BEGIN
    SELECT RAISE(ABORT, 'events table is append-only: UPDATE forbidden (S-LOG-2)');
END;

CREATE TRIGGER events_no_delete
BEFORE DELETE ON events
BEGIN
    SELECT RAISE(ABORT, 'events table is append-only: DELETE forbidden (S-LOG-2)');
END;

CREATE TABLE tasks (
    task_id      TEXT    PRIMARY KEY,
    session_id   TEXT    NOT NULL,
    kind         TEXT    NOT NULL,
    -- Discriminant only (matches roundhouse_core::TaskState::as_sql_str /
    -- from_sql_str — X1 fix): a data-carrying variant's detail (e.g. which
    -- SuspendReason) lives in the event log, not this derived-cache row.
    -- The CHECK is the insert-time enforcement leg; from_sql_str is the
    -- read-back leg, so a hand-edited or corrupted row can't produce a
    -- Task in a state that doesn't exist either way.
    state        TEXT    NOT NULL CHECK (state IN (
        'Created', 'Decided', 'Running', 'Suspended', 'Completed', 'Failed', 'Cancelled', 'Interrupted'
    )),
    parent       TEXT,
    created_seq  INTEGER NOT NULL,
    updated_seq  INTEGER NOT NULL
) STRICT;

CREATE INDEX tasks_session_id_idx ON tasks (session_id);
CREATE INDEX tasks_parent_idx ON tasks (parent) WHERE parent IS NOT NULL;

CREATE VIRTUAL TABLE tasks_fts USING fts5(
    task_id UNINDEXED,
    content
);
"#;

const MIGRATION_0002_BLOBS: &str = r#"
CREATE TABLE blobs (
    hash               TEXT    PRIMARY KEY,
    len                INTEGER NOT NULL,
    mime               TEXT,
    created_at         INTEGER NOT NULL,
    last_referenced_at INTEGER NOT NULL,
    ref_count          INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX blobs_gc_eligible_idx ON blobs (ref_count, last_referenced_at) WHERE ref_count = 0;
"#;

/// Task 0.5: makes the `tasks` materialized-cache table live (see `tasks_view.rs`).
/// Both columns are nullable with no `DEFAULT` — a non-suspended task has neither.
/// `suspended_since` is the real event timestamp (unix nanos, matching `Timestamp`
/// elsewhere), not a `seq`. `suspend_reason_json` is the `SuspendReason` serialized
/// verbatim, since (per the `state` column's own comment) the `tasks` table is only a
/// derived cache and the event log stays the source of truth for the full reason detail.
/// This migration only adds columns — it does not, and structurally cannot (a
/// `rusqlite_migration::M::up` is a fixed SQL string, not application logic), backfill
/// `tasks` rows for tasks that already existed in the event log before it ran. That
/// backfill is `tasks_view::backfill_tasks_table`, run automatically by `open()` right
/// after migrations apply (security fix, Task 0.5 follow-up).
const MIGRATION_0003_TASKS_SUSPEND_COLUMNS: &str = r#"
ALTER TABLE tasks ADD COLUMN suspended_since INTEGER;
ALTER TABLE tasks ADD COLUMN suspend_reason_json TEXT;
"#;

/// Task 19: redaction at the persistence boundary. `redactions` is a per-task counter,
/// summed across every event folded into the task (see `writer::append_one`/
/// `append_batch`, which `UPDATE tasks SET redactions = redactions + ?1` alongside the
/// existing `tasks_view::upsert_for_event` call, in the same transaction as the events
/// insert) — 0 is the diagnostic signal that redaction found nothing for this task, not
/// an error, and must stay visible per-task rather than only existing transiently in
/// memory. `NOT NULL DEFAULT 0` so every pre-existing row (and every new
/// `TaskCreated`-triggered insert) starts at a well-defined zero.
const MIGRATION_0004_TASKS_REDACTIONS_COLUMN: &str = r#"
ALTER TABLE tasks ADD COLUMN redactions INTEGER NOT NULL DEFAULT 0;
"#;

pub fn migrations() -> Migrations<'static> {
    Migrations::new(vec![
        M::up(MIGRATION_0001_INITIAL_SCHEMA),
        M::up(MIGRATION_0002_BLOBS),
        M::up(MIGRATION_0003_TASKS_SUSPEND_COLUMNS),
        M::up(MIGRATION_0004_TASKS_REDACTIONS_COLUMN),
    ])
}
