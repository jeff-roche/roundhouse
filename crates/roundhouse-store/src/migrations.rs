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

pub fn migrations() -> Migrations<'static> {
    Migrations::new(vec![M::up(MIGRATION_0001_INITIAL_SCHEMA)])
}
