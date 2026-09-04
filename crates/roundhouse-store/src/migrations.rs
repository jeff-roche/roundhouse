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

/// Task 21 (S-OBS-4): the "blocked-anywhere" query's index. Matches
/// `suspended_tasks`'s (`suspended.rs`) real predicate exactly — the `tasks` table
/// has only one generic `state = 'Suspended'` value for every suspend reason, so
/// a partial index on that single value is what makes `attention::blocked_anywhere`
/// a fast index range scan instead of a full-table scan at 10,000-session scale.
/// Ordered by `suspended_since` to match the query's own `ORDER BY suspended_since
/// ASC` (oldest-blocked-first).
const MIGRATION_0005_ATTENTION_INDEX: &str = r#"
CREATE INDEX IF NOT EXISTS idx_tasks_suspended
    ON tasks(state, suspended_since)
    WHERE state = 'Suspended';
"#;

/// Phase 5, Subsystem A, Task 4 (scheduling): durable record of one trigger
/// firing, keyed for dedupe by `(binding_id, idempotency_key)`. Ruling P4
/// requires this table live in the real store's migration list — a
/// per-crate `roundhouse-sched/migrations/*.sql` file would never reach the
/// daemon's actual database. The `UNIQUE INDEX` is the real enforcement
/// mechanism for "exactly one run per scheduled occurrence, even under
/// crash-and-retry": `roundhouse_sched::store::record_trigger_event` relies
/// on this constraint via `INSERT ... ON CONFLICT DO NOTHING`, not a
/// check-then-insert in application code (which would race under concurrent
/// callers).
const MIGRATION_0006_TRIGGER_EVENT: &str = r#"
CREATE TABLE trigger_event (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    binding_id      TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    scheduled_for   TEXT NOT NULL,   -- RFC3339 UTC
    fired_at        TEXT NOT NULL,   -- RFC3339 UTC
    is_catch_up     INTEGER NOT NULL,
    session_id      TEXT
) STRICT;

CREATE UNIQUE INDEX trigger_event_dedupe
    ON trigger_event(binding_id, idempotency_key);
"#;

/// Phase 5, Subsystem B, Task 16 (workflow durability): §8.10's
/// "checkpoint-and-re-drive" state machine — `workflow_run` plus
/// `workflow_step_run`, "every transition one SQLite transaction through the
/// single writer. Recovery = load and resume." Ruling P4 applies here for the
/// same reason it did to `trigger_event` above: a per-crate
/// `roundhouse-flow/migrations/*.sql` file would never reach the daemon's
/// actual database. `roundhouse_flow::durability` reads and writes these two
/// tables; nothing else does.
///
/// Timestamps are unix **nanoseconds** (`INTEGER`, matching
/// `roundhouse_core::Timestamp` and the `events.ts`/`tasks.suspended_since`
/// columns), not `trigger_event`'s RFC3339 `TEXT`. These rows are siblings of
/// the task log, which they join back to via `first_task_seq`/`last_task_seq`
/// (§8.10), so they use the log's own time convention.
///
/// No `FOREIGN KEY` constraints: no connection in this workspace sets
/// `PRAGMA foreign_keys = ON` (see `pool.rs`, which sets only
/// `journal_mode`/`synchronous`/`busy_timeout`/`secure_delete`), so declaring
/// them would record an intention SQLite would not enforce.
/// `workflow_run.session_id`, `parent_run_id`, `forked_from_run_id` and
/// `trigger_event_id` are therefore documented references, checked by the
/// application, not by the engine.
///
/// # What protects `workflow_step_run.output` at rest — stated plainly
///
/// This is the first table in this database whose stored value may be
/// **unredacted** secret-derived material. Every other write path redacts
/// before storing (`redact.rs`: *"the stored row is always the already-redacted
/// form, never the original"*), and `output` deliberately does not, because
/// §8.13's fork *"inherit[s] completed step outputs"* and a redacted stand-in
/// would make a resumed run compute different results from the original.
///
/// The protection that actually exists for the file is therefore worth naming
/// rather than assuming:
///
/// - The **parent directory** is created `0700` by the daemon
///   (`roundhouse-daemon/src/main.rs`'s `RUNTIME_DIR_MODE`). That is the whole
///   of the access control.
/// - The **database file itself** is created by SQLite under the process
///   umask — this crate sets no mode on it — and the `-wal` and `-shm`
///   sidecars are created the same way. A permissive umask therefore yields a
///   world-readable db file inside a `0700` directory; the directory is what
///   keeps other users out, not the file bits.
/// - There is **no encryption at rest**, and none is implied anywhere here.
/// - `pool.rs` sets `PRAGMA secure_delete = ON` so that clearing an `output`
///   zeroes the freed bytes rather than leaving them there to be read back
///   raw (measured — see that pragma's comment for the full matrix, fix
///   round 2 M-1). The guarantee is conditional, not unconditional: it
///   bounds residue in the main database file only **once the clearing
///   write has itself been checkpointed** (before that, the cleared page
///   sits in `-wal` and the pre-clear bytes are still what's in the main
///   file), and it bounds residue in `-wal` only **once that checkpoint is a
///   TRUNCATE** — an ordinary PASSIVE autocheckpoint (SQLite's default)
///   backfills the main file but does not truncate or zero `-wal`, so the
///   pre-clear page image's raw bytes can still be sitting there.
///
/// Erasing outputs that no fork can still target is a named residual owned by
/// **Task 20 (B12)** — the mechanism exists (checkpoint the step with no
/// output, which writes `output = NULL`), only the caller is missing, and
/// per the conditional guarantee above that caller must also issue
/// `PRAGMA wal_checkpoint(TRUNCATE)` after the clear to actually reach
/// `-wal` (see `roundhouse-flow`'s `durability` module doc for where this is
/// tracked as part of that task's obligation).
const MIGRATION_0007_WORKFLOW_RUN: &str = r#"
CREATE TABLE workflow_run (
    id                 TEXT    PRIMARY KEY,
    -- The pinned (job_id, version, content_hash) triple: old JobVersions are
    -- never removed, so a run can always resolve the exact content it ran.
    job_id             TEXT    NOT NULL,
    job_version        INTEGER NOT NULL,
    content_hash       TEXT    NOT NULL,
    -- §8.6: each run creates a new Session.
    session_id         TEXT    NOT NULL,
    -- §8.6: "a workflow_run.binding_id / trigger_event_id column on every run
    -- row — this is how 'the previous run of this binding' is queried". Both
    -- nullable: a manually-invoked `round workflow run` has neither.
    -- trigger_event_id is INTEGER because trigger_event.id (migration 0006)
    -- is `INTEGER PRIMARY KEY AUTOINCREMENT`.
    binding_id         TEXT,
    trigger_event_id   INTEGER,
    state              TEXT    NOT NULL CHECK (state IN (
        'running', 'paused', 'cancelling', 'awaiting_human',
        'completed', 'failed', 'cancelled'
    )),
    -- §8.12: a `call:` sub-workflow creates a CHILD workflow_run.
    parent_run_id      TEXT,
    -- §8.13: retry-from-step forks a new run inheriting completed step
    -- outputs, linked back by this column. History is append-only; a fork is
    -- never a rewrite.
    forked_from_run_id TEXT,
    -- Nullable, ABSOLUTE deadline of a park (unix nanos). WRITTEN BY TASK 17
    -- (B9), which owns the relative->absolute conversion; this task only
    -- creates the column. `hitl::AwaitingHuman` carries a *relative*
    -- `timeout_after` and is deliberately not `Deserialize`, precisely so a
    -- park record cannot be stored as that struct and re-derived with a fresh
    -- full window on every resume. The absolute instant lives here instead.
    awaiting_until     INTEGER,
    started_at         INTEGER NOT NULL,
    ended_at           INTEGER
) STRICT;

-- The index behind `previous_run_for_binding` (§8.6's "the previous run of
-- this binding"). It serves that query's `binding_id` seek and its
-- `started_at` ordering, but not the whole ORDER BY: EXPLAIN QUERY PLAN on
-- both real statements reports
-- `SEARCH workflow_run USING INDEX workflow_run_binding_idx (binding_id=?)`
-- -- with `AND started_at<?` added for the bounded form -- followed by
-- `USE TEMP B-TREE FOR LAST TERM OF ORDER BY`, because the query breaks ties
-- on `id`, which this index does not carry. So: an index seek rather than a
-- table scan, plus a sort of only the matching rows on the tiebreak column.
-- Partial, because a manually-invoked run has no binding and can never be an
-- answer to that query.
CREATE INDEX workflow_run_binding_idx
    ON workflow_run (binding_id, started_at)
    WHERE binding_id IS NOT NULL;

CREATE TABLE workflow_step_run (
    run_id                   TEXT    NOT NULL,
    step_id                  TEXT    NOT NULL,
    attempt                  INTEGER NOT NULL,
    -- item_index is part of the PRIMARY KEY because
    -- `exec::provenance::Provenance` is exactly
    -- (run_id, step_id, attempt, item_index): without it, two items of one
    -- `map` step collide and the second silently overwrites the first.
    -- NOT NULL with a -1 sentinel for "not a map item", never NULL: this is
    -- a STRICT table, which makes every PRIMARY KEY column implicitly
    -- NOT NULL, so a "nullable" item_index would simply reject the insert
    -- ("NOT NULL constraint failed") the first time a top-level step was
    -- checkpointed. (In an ordinary rowid table the failure would instead be
    -- silent duplicate rows, since SQLite permits NULLs in such a PRIMARY KEY
    -- and compares every NULL as distinct -- verified both ways; STRICT is
    -- what makes it the loud failure rather than the quiet one.) -1 is
    -- outside u32, so it cannot collide with a real item index.
    -- The upper bound is u32::MAX: item_index is a u32 in Rust, and without
    -- a bound a larger stored value would read back through the same
    -- "not a u32" path as the sentinel, aliasing two distinct rows onto one
    -- identity. The read side rejects such a value rather than guessing; this
    -- is the insert-time leg of the same rule.
    item_index               INTEGER NOT NULL CHECK (item_index BETWEEN -1 AND 4294967295),
    disposition              TEXT    NOT NULL CHECK (disposition IN (
        'pure', 'idempotent', 'effectful'
    )),
    -- 'skipped' is here although nothing writes it yet, for the same reason
    -- workflow_run.state carries Task 17/20's states: a `when:`-skipped step
    -- is FINISHED (the run loop must not re-evaluate `when:` on re-drive --
    -- the condition may read differently by then -- and downstream steps
    -- interpolate `${{ steps.<id>.status }}`), `exec/mod.rs` already produces
    -- StepStatus::Skipped, and SQLite has no ALTER TABLE DROP/MODIFY
    -- CONSTRAINT, so omitting it would force Task 20 (B12) to rebuild this
    -- table. Shape now, behaviour later.
    state                    TEXT    NOT NULL CHECK (state IN (
        'pending', 'running', 'completed', 'indeterminate', 'failed', 'skipped'
    )),
    -- §8.10: "workflow_step_run.first_task_seq/last_task_seq join back to the
    -- log, so a step's full evidence is SELECT ... WHERE session_id = ? AND
    -- seq BETWEEN ? AND ?". Nullable, because a step checkpointed before it
    -- has emitted any task genuinely has no range — a NOT NULL column would
    -- have to fake one, and a fake 0..0 range silently mis-joins that query.
    -- A `seq` is a u64 in `roundhouse-core`; SQLite has no unsigned integers,
    -- so the non-negative half of the INTEGER range is the whole domain.
    first_task_seq           INTEGER CHECK (first_task_seq IS NULL OR first_task_seq >= 0),
    last_task_seq            INTEGER CHECK (last_task_seq IS NULL OR last_task_seq >= 0),
    -- §8.13's fork "inheriting completed step outputs" needs the real output,
    -- so this column holds the step's UNREDACTED output JSON.
    -- output_is_secret_derived is the executor's own flag, persisted verbatim
    -- from StepOutcome rather than re-derived later (exec/mod.rs: "a
    -- re-derivation that disagrees with this one is a leak"). Any consumer
    -- rendering `output` must consult it.
    output                   TEXT,
    output_is_secret_derived INTEGER NOT NULL CHECK (output_is_secret_derived IN (0, 1)),
    -- Why a step's failure message / skip reason is persisted rather than
    -- recomputed: exactly the argument that justified `output` above. Once
    -- the process that produced `StepStatus::Failed { message }` or
    -- `Skipped { reason }` is gone, the text cannot be re-derived from
    -- anything in this row -- and Task 20 (B12)'s `catch:` and the web Runs
    -- inbox both need it. Nullable and unconstrained: a step that has not
    -- failed or been skipped has no error, and a CHECK tying it to a state
    -- set would be one more thing a later task could not alter.
    --
    -- Like `output`, this text is NOT redacted. `StepStatus`'s own Debug
    -- bounds what a `{:?}` of a message prints, which is not the same as
    -- bounding what is stored here -- this column holds it in full -- so
    -- treat it with the same care as `output`. Unlike `output` there is no
    -- taint flag, because the executor computes none for it.
    error                    TEXT,
    -- Table constraints below this line: SQLite's grammar allows no further
    -- column definitions once one appears.
    --
    -- No output means nothing to be tainted: keeps "no output yet" a single
    -- representable state rather than two.
    CHECK (output IS NOT NULL OR output_is_secret_derived = 0),
    PRIMARY KEY (run_id, step_id, attempt, item_index)
) STRICT;
"#;

pub fn migrations() -> Migrations<'static> {
    Migrations::new(vec![
        M::up(MIGRATION_0001_INITIAL_SCHEMA),
        M::up(MIGRATION_0002_BLOBS),
        M::up(MIGRATION_0003_TASKS_SUSPEND_COLUMNS),
        M::up(MIGRATION_0004_TASKS_REDACTIONS_COLUMN),
        M::up(MIGRATION_0005_ATTENTION_INDEX),
        M::up(MIGRATION_0006_TRIGGER_EVENT),
        M::up(MIGRATION_0007_WORKFLOW_RUN),
    ])
}
