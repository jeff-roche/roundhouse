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

/// Phase 5, Subsystem B, B12b (ruling P77's split of Task 20): the
/// **run-level ledger** on `workflow_run` — the durable half of four things
/// the tree had only in memory or not at all. Ruling P4 again: the columns
/// live here, not in a per-crate `roundhouse-flow/migrations/*.sql` file that
/// would never reach the daemon's actual database. `roundhouse_flow::ledger`
/// (with `durability` and `parking`) is the only reader and writer.
///
/// # `ADD COLUMN` only, and why that is a rule rather than a preference
///
/// Every statement below is `ALTER TABLE … ADD COLUMN` or `CREATE INDEX`.
/// **`ALTER TABLE … ADD CONSTRAINT … CHECK (…)` is not used, although it
/// works** — measured on the bundled SQLite: it is accepted, lands in
/// `sqlite_master` as a genuine table-level constraint, and is enforced. It is
/// nonetheless not `ALTER TABLE` syntax (which covers only `RENAME TABLE`,
/// `RENAME COLUMN`, `ADD COLUMN` and `DROP COLUMN`); it survives only because
/// `ADD COLUMN` textually appends the column-def to the stored `CREATE TABLE`
/// and that clause happens to re-parse in table-constraint position. A
/// migration that works on today's parser and is rejected by a future one
/// means **existing installs keep working while fresh installs fail** —
/// divergence visible only to new users, long after the change — and
/// `rusqlite` is `features = ["bundled"]`, so a routine dependency bump is
/// exactly what would move the parser. Ruling P104.
/// `xtask/tests/no_alter_table_add_constraint.rs` is the enforcement leg, so
/// this paragraph cannot decay into advice.
///
/// **Per-column `CHECK`s are real `ADD COLUMN` syntax** and are used freely
/// below. What they cannot express is a *cross-column* invariant — e.g.
/// `state <> 'completed' OR ended_at IS NOT NULL`, which `durability`'s
/// `insert_run_row` and `transition` both enforce in Rust. Adding that leg to
/// the schema needs the 12-step create-copy-drop-rename rebuild, which is a
/// materially riskier migration than the `ADD COLUMN`s around it and is its
/// own task, not a rider here.
///
/// # The four facts these columns make durable
///
/// 1. **`parked_at`** — when the run's *current* park began.
///    `parking::reaper_cutoff(parked_at, now)` has existed since Task 17 with
///    **no durable source for its first argument anywhere in the schema**
///    (ruling P72): `started_at` is the run's start, not its park time,
///    `workflow_step_run` has no timestamp column, and
///    `WorkspaceDisposition::HoldUntil` is an in-process value. Written when a
///    run enters `awaiting_human` and **preserved across a re-park**, so
///    re-driving a park cannot reset the 7-day clock; cleared when the run
///    leaves. `workflow_run_parked_idx` is the reaper query's index.
/// 2. **`hold_until`** — the workspace hold's absolute, already-clamped
///    deadline, the durable half of §8.11's `hold_workspace` TTL. It and
///    `parked_at` are the two legs `parking::resolve_hold_ttl` describes: the
///    clamp records the intended expiry, and `parked_at` is the independent
///    backstop that bounds a hold whose deadline was never cancelled.
/// 3. **`parked_nanos`** — accumulated *completed* park time, which with
///    `parked_at` and `started_at` yields §8.4's active elapsed time
///    (`run_active_timeout` *"excludes `AwaitingHuman`"*). An in-memory
///    tracker would be lost on the first daemon restart, which is precisely
///    the multi-day park it exists to measure.
/// 4. **`session_depth`, `caps_json`, the seven `spent_*` accumulators,
///    `drawn_at` and `refunded_at`** — §8.12's budget transfer and §7.7's
///    recursion bound,
///    both of which must survive a restart. `session_depth` is the depth of
///    the run's **Session** in the session tree, the same number
///    `roundhouse_engine::agent_spawn` takes as `parent_depth` — deliberately
///    **not** a run depth derived from `parent_run_id`, because those are two
///    independent counters over one tree and a sub-agent at session depth 3
///    starting a run would begin its `call:` chain at run-depth 0 and be
///    granted four more (ruling P76 §1).
///
/// # Which columns are nullable, and why that is the fail-closed direction
///
/// `session_depth` and `caps_json` are nullable **with no default**, and a
/// `NULL` means *unknown*, which every reader in `roundhouse_flow::ledger`
/// refuses rather than substitutes. The alternative — `NOT NULL DEFAULT 0` /
/// a serialized `ResourceCaps` literal baked into this immutable string —
/// would have every row written before this migration silently claim to be a
/// depth-0 root with a full budget: the fail-*open* answer for exactly the
/// rows the schema knows least about, and (for the caps) a default that would
/// drift from `ResourceCaps::default()` the moment either changed.
///
/// The accumulators are the opposite case and are `NOT NULL DEFAULT 0`: zero
/// is the *exact* value for a run that has recorded no spend and no completed
/// park, not a stand-in for an unknown one.
///
/// `drawn_at` and `refunded_at` are the **two halves of one transfer**, and
/// shipping only the second is what ruling P109 §A found: `refunded_at` stamps
/// a child whose unspent grant has been returned, so a second refund cannot
/// mint budget the root never granted — but with no durable record that a draw
/// ever happened, *any* row that merely looks like a child (a parent id and a
/// recorded grant) was refundable, and `control::retry_from_step`'s fork is
/// exactly such a row. `drawn_at` records that a parent was actually charged
/// `Spend::for_grant`, and `ledger::refund_child_run` refuses a child that
/// carries none. That a run with no `parent_run_id` can never be refunded is a
/// cross-column rule and therefore lives in Rust
/// (`ledger::refund_child_run`), per the `ADD CONSTRAINT` section above.
///
/// The column lands here rather than in a later migration because it is
/// `ADD COLUMN`-shaped and this migration has not shipped: ruling P109 §B, and
/// ruling P77's whole reason for splitting Task 20 was to do this table's
/// schema once rather than across an 0008, an 0009 and an 0010.
///
/// # `spent_cost_usd` is `REAL`, and the column is not the whole guard
///
/// It matches `ResourceCaps::max_cost_usd`'s `f64` (see that type's recorded
/// deviation from §8.4's `Decimal`). Measured on the bundled SQLite: a `NaN`
/// bound to this column is stored as `NULL` and therefore rejected by
/// `NOT NULL`, but **`+inf` satisfies `CHECK (spent_cost_usd >= 0)` and is
/// stored**. `ledger::admit_spend` refuses non-finite dollars in Rust for that
/// reason; the `CHECK` bounds the sign, not the finiteness.
const MIGRATION_0008_WORKFLOW_RUN_LEDGER: &str = r#"
ALTER TABLE workflow_run ADD COLUMN parked_at INTEGER
    CHECK (parked_at IS NULL OR parked_at >= 0);
ALTER TABLE workflow_run ADD COLUMN hold_until INTEGER
    CHECK (hold_until IS NULL OR hold_until >= 0);
ALTER TABLE workflow_run ADD COLUMN parked_nanos INTEGER NOT NULL DEFAULT 0
    CHECK (parked_nanos >= 0);

ALTER TABLE workflow_run ADD COLUMN session_depth INTEGER
    CHECK (session_depth IS NULL OR (session_depth >= 0 AND session_depth <= 4294967295));

ALTER TABLE workflow_run ADD COLUMN caps_json TEXT;
ALTER TABLE workflow_run ADD COLUMN spent_tokens INTEGER NOT NULL DEFAULT 0
    CHECK (spent_tokens >= 0);
ALTER TABLE workflow_run ADD COLUMN spent_cost_usd REAL NOT NULL DEFAULT 0.0
    CHECK (spent_cost_usd >= 0);
ALTER TABLE workflow_run ADD COLUMN spent_tasks INTEGER NOT NULL DEFAULT 0
    CHECK (spent_tasks >= 0);
ALTER TABLE workflow_run ADD COLUMN spent_tool_calls INTEGER NOT NULL DEFAULT 0
    CHECK (spent_tool_calls >= 0);
ALTER TABLE workflow_run ADD COLUMN spent_subagents INTEGER NOT NULL DEFAULT 0
    CHECK (spent_subagents >= 0);
ALTER TABLE workflow_run ADD COLUMN spent_bytes_written INTEGER NOT NULL DEFAULT 0
    CHECK (spent_bytes_written >= 0);
ALTER TABLE workflow_run ADD COLUMN spent_escalations INTEGER NOT NULL DEFAULT 0
    CHECK (spent_escalations >= 0);
ALTER TABLE workflow_run ADD COLUMN drawn_at INTEGER
    CHECK (drawn_at IS NULL OR drawn_at >= 0);
ALTER TABLE workflow_run ADD COLUMN refunded_at INTEGER
    CHECK (refunded_at IS NULL OR refunded_at >= 0);

-- The reaper's index (ruling P69 §2 lists "a reaper index" among the cheap,
-- ADD COLUMN-shaped gaps). Partial, because a run that is not parked can
-- never be an answer to `ledger::parked_runs_past_hold_cap`, and that query is
-- `parked_at <= ?cutoff` — the cutoff computed once in Rust from
-- `parking::SYSTEM_WIDE_HOLD_CAP` so the constant is not restated in SQL.
CREATE INDEX workflow_run_parked_idx
    ON workflow_run (parked_at)
    WHERE parked_at IS NOT NULL;
"#;

/// Phase 8, Task 9: durable job registrations and immutable job versions.
/// A job name identifies one source within a workspace; each edit appends a
/// version instead of replacing the content a prior run pinned.
const MIGRATION_0009_JOBS: &str = r#"
CREATE TABLE jobs (
    id          TEXT NOT NULL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    source_path TEXT NOT NULL
) STRICT;

CREATE TABLE job_versions (
    job_id             TEXT NOT NULL,
    version            INTEGER NOT NULL CHECK (version > 0),
    content_hash       TEXT NOT NULL,
    template_json      TEXT NOT NULL,
    body_json          TEXT NOT NULL,
    input_schema_json  TEXT NOT NULL,
    PRIMARY KEY (job_id, version),
    UNIQUE (job_id, content_hash)
) STRICT;

CREATE INDEX job_versions_hash_idx ON job_versions (content_hash);

CREATE TRIGGER jobs_no_update
BEFORE UPDATE ON jobs
BEGIN
    SELECT RAISE(ABORT, 'jobs table is immutable: UPDATE forbidden');
END;

CREATE TRIGGER jobs_no_delete
BEFORE DELETE ON jobs
BEGIN
    SELECT RAISE(ABORT, 'jobs table is immutable: DELETE forbidden');
END;

CREATE TRIGGER job_versions_no_update
BEFORE UPDATE ON job_versions
BEGIN
    SELECT RAISE(ABORT, 'job_versions table is append-only: UPDATE forbidden');
END;

CREATE TRIGGER job_versions_no_delete
BEFORE DELETE ON job_versions
BEGIN
    SELECT RAISE(ABORT, 'job_versions table is append-only: DELETE forbidden');
END;
"#;

/// Phase 8, Task 26: the daemon-owned identity registry for named workspaces.
/// `root_path` preserves the path the operator registered so a changed symlink
/// target is detected on restart; `canonical_root` is the path execution uses.
/// `root_device`/`root_inode` detect replacement of a directory at the same
/// canonical path.
/// Rows are immutable: changing a name or root would silently rebind existing
/// sessions to a different filesystem identity.
const MIGRATION_0010_WORKSPACES: &str = r#"
CREATE TABLE workspaces (
    workspace_id   TEXT NOT NULL PRIMARY KEY,
    name           TEXT NOT NULL UNIQUE,
    root_path      TEXT NOT NULL,
    canonical_root TEXT NOT NULL UNIQUE,
    root_device    INTEGER,
    root_inode     INTEGER
) STRICT;

CREATE TRIGGER workspaces_no_update
BEFORE UPDATE ON workspaces
BEGIN
    SELECT RAISE(ABORT, 'workspaces table is immutable: UPDATE forbidden');
END;

CREATE TRIGGER workspaces_no_delete
BEFORE DELETE ON workspaces
BEGIN
    SELECT RAISE(ABORT, 'workspaces table is immutable: DELETE forbidden');
END;
"#;

/// Phase 8, Task 2 of the trigger-delivery rebuild: durable binding
/// registration and the delivery outbox. Before this migration, a `Binding`
/// (`roundhouse-sched`'s in-memory type) lived only in the scheduler's own
/// `HashMap` and vanished on daemon restart — every enabled trigger had to be
/// re-registered from scratch, and there was nowhere durable to persist an
/// admission decision or a delivery's lifecycle. This migration adds the
/// three tables that make both durable, plus one column recording what
/// admission actually decided for a `trigger_event` row.
///
/// # `trigger_binding` — the durable registry
///
/// `binding_id` TEXT PK (a `BindingId`'s UUID text), `workspace_id` and
/// `job_id` TEXT NOT NULL (the trusted workspace identity and the job this
/// binding starts), `spec_json`/`overlap_json` TEXT NOT NULL (the
/// `TriggerSpec`/`OverlapPolicy` serialized verbatim — no column-per-variant
/// shredding, matching how `job_versions.template_json`/`body_json` store
/// their own typed payloads as opaque JSON elsewhere in this file),
/// `enabled INTEGER NOT NULL CHECK (enabled IN (0, 1))` (SQLite has no native
/// boolean; `STRICT` still requires an explicit domain, hence the CHECK —
/// same shape as `workflow_step_run.output_is_secret_derived` in migration
/// 0007), `created_at INTEGER NOT NULL` (unix nanos, matching
/// `roundhouse_core::Timestamp::as_unix_nanos()` and every timestamp column
/// from migration 0007 onward — deliberately **not** `trigger_event`'s older
/// RFC3339-text convention, which predates that switch).
///
/// **This table is mutable, unlike every other identity/registry table in
/// this file.** `jobs`/`job_versions` (migration 0009) and `workspaces`
/// (migration 0010) are immutable by design and enforce it with
/// `BEFORE UPDATE`/`BEFORE DELETE` triggers that `RAISE(ABORT, ...)`. A
/// `trigger_binding` row is different: enable/disable/delete are real,
/// planned lifecycle operations on a binding (a later task), so adding those
/// same triggers here would be a house-convention error dressed up as a
/// house-convention match — this table intentionally carries no such
/// triggers.
///
/// No `FOREIGN KEY` on `workspace_id`/`job_id`: as migration 0007's own
/// comment establishes, no connection in this workspace sets `PRAGMA
/// foreign_keys = ON` (`pool.rs` sets only `journal_mode`/`synchronous`/
/// `busy_timeout`/`secure_delete`), so declaring one would record an
/// intention SQLite never enforces. Both are documented references, checked
/// by the application.
///
/// # `trigger_binding_cursor` — the persisted fire-cursor
///
/// Deliberately its own table rather than columns on `trigger_binding`, so
/// that editing a binding's spec/overlap/enabled state never has to touch
/// cursor state and vice versa. `binding_id` TEXT PK, `last_fired_for
/// INTEGER` nullable unix-nanos (`NULL` means "never fired" — the honest
/// reading for a freshly-registered binding, not a sentinel like `0`).
///
/// There is deliberately **no** `next_fire_at` column: the plan requires the
/// scheduler to recompute its own min-heap from `last_fired_for` at boot
/// rather than trust a stored next-fire instant, which could otherwise go
/// stale across a binding-spec edit or a timezone/DST rule change between
/// restarts.
///
/// # `trigger_delivery` — the delivery outbox
///
/// One row per admitted (or queued, or otherwise decided) occurrence that
/// became — or may yet become — a run. `delivery_id` TEXT PK (a UUID string
/// minted by the writer, not an `INTEGER PRIMARY KEY AUTOINCREMENT`, so a
/// delivery's identity is stable before it is ever inserted).
/// `trigger_event_id INTEGER NOT NULL` conceptually references
/// `trigger_event.id` (an `INTEGER PRIMARY KEY AUTOINCREMENT`, migration
/// 0006) but carries no SQL `FOREIGN KEY`, for the same no-enforcement
/// reason given above for `trigger_binding`. `binding_id TEXT NOT NULL` is
/// likewise a documented, unenforced reference to `trigger_binding`.
///
/// `state TEXT NOT NULL` carries a `CHECK` enumerating all nine states this
/// delivery can ever occupy, even though Task 3 (the next task in this
/// rebuild) only writes a subset of them at first:
/// `'ready', 'leased', 'reserved', 'running', 'delivered', 'failed',
/// 'cancellation_requested', 'cancelled', 'skipped'`. This is the same
/// "shape now, behaviour later" doctrine migration 0007's own comment states
/// for `workflow_step_run.state`'s `'skipped'` variant: SQLite has no
/// `ALTER TABLE ... DROP/MODIFY CONSTRAINT`, so a `CHECK` that omitted a
/// state some later task needs would force that task to rebuild this table
/// via the 12-step create-copy-drop-rename dance instead of just writing a
/// new value into an already-declared vocabulary.
///
/// `attempts INTEGER NOT NULL DEFAULT 0` — zero is the *exact* value for a
/// delivery that has not yet been attempted, not a stand-in for "unknown",
/// so a real default is correct here (matching migration 0008's accumulator
/// columns, not its nullable-with-no-default ones). Every other nullable
/// column below carries **no** default, per this codebase's nullability
/// doctrine (see migration 0008's own "which columns are nullable, and why
/// that is the fail-closed direction" section): `lease_expires_at INTEGER`
/// (unix nanos; `NULL` until a claim leases this delivery), `run_id TEXT`
/// (`NULL` until a run is actually started for this delivery — kept as a raw
/// string rather than `roundhouse_flow::RunId`, since `roundhouse-sched`
/// must not depend on `roundhouse-flow`), `session_id TEXT` (`NULL` until a
/// session exists for it), `last_error TEXT` (`NULL` while nothing has
/// failed).
///
/// `created_at`/`updated_at INTEGER NOT NULL` are both unix nanos, matching
/// every other timestamp column in this file from migration 0007 onward.
///
/// ## Indexes
///
/// - `trigger_delivery_run_id_idx`: `UNIQUE INDEX ... (run_id) WHERE run_id
///   IS NOT NULL`. Serves two purposes at once: it is the lookup a caller
///   uses to go from a `run_id` back to the delivery that started it, and it
///   is the enforcement that two deliveries can never claim the same run —
///   partial because the overwhelming majority of rows have no run yet, and
///   `NULL <> NULL` in SQLite's uniqueness comparison already lets any number
///   of not-yet-started deliveries coexist without the `WHERE` clause, but
///   the partial form keeps the index itself small (matching
///   `workflow_run_binding_idx`'s and `blobs_gc_eligible_idx`'s existing
///   partial-index style in this file).
/// - `trigger_delivery_session_id_idx`: the same shape, for `session_id`, for
///   the same reason — the lookup from a session back to its delivery, plus
///   the same one-delivery-per-session enforcement.
/// - `trigger_delivery_claim_idx`: `(state, lease_expires_at) WHERE state IN
///   ('ready', 'leased')`. Serves the claim query a delivery worker runs to
///   find the next deliverable row (and, for an already-`leased` row, to find
///   one whose lease has expired and can be reclaimed) without scanning
///   `delivered`/`failed`/`cancelled`/`skipped` history that can never be an
///   answer to that query — the same "partial index over the rows a
///   recurring query can actually match" reasoning as
///   `workflow_run_parked_idx`'s reaper index in migration 0008.
///
/// # `trigger_event.outcome`
///
/// `ALTER TABLE trigger_event ADD COLUMN outcome TEXT CHECK (outcome IS NULL
/// OR outcome IN (...))` — a per-column `CHECK` inside `ADD COLUMN`, which is
/// real `ADD COLUMN` syntax (ruling P104; see migration 0008's own extended
/// comment on why `ALTER TABLE ... ADD CONSTRAINT` is never used instead).
/// Nullable with no default: a `trigger_event` row can exist before its
/// outcome is decided (the row is inserted by `record_trigger_event` at fire
/// time; admission runs afterward), and every row that existed before this
/// migration ran never recorded one at all — both are the honest "not yet
/// known" case, not a value to default away.
///
/// The vocabulary mirrors `roundhouse_sched::admission::AdmissionDecision`'s
/// six variants exactly, lower-cased to snake_case and stripped of their
/// carried data (`QueueAt(u32)`'s position, `SkippedQueueFull { depth }`'s
/// depth) since this column records *which kind* of decision was made, not
/// its parameters: `'admitted'`, `'skipped_due_to_overlap'`, `'queued'`,
/// `'cancelled_previous_and_admitted'`, `'skipped_queue_full'`,
/// `'skipped_cancellation_unconfirmed'`. See
/// `roundhouse_sched::trigger::TriggerEventOutcome` for the paired Rust enum
/// and its `as_sql_str`/`from_sql_str`.
const MIGRATION_0013_TRIGGER_BINDINGS_AND_DELIVERIES: &str = r#"
CREATE TABLE trigger_binding (
    binding_id   TEXT NOT NULL PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    job_id       TEXT NOT NULL,
    spec_json    TEXT NOT NULL,
    overlap_json TEXT NOT NULL,
    enabled      INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    created_at   INTEGER NOT NULL
) STRICT;

CREATE TABLE trigger_binding_cursor (
    binding_id     TEXT NOT NULL PRIMARY KEY,
    last_fired_for INTEGER
) STRICT;

CREATE TABLE trigger_delivery (
    delivery_id       TEXT NOT NULL PRIMARY KEY,
    trigger_event_id  INTEGER NOT NULL,
    binding_id        TEXT NOT NULL,
    state             TEXT NOT NULL CHECK (state IN (
        'ready', 'leased', 'reserved', 'running', 'delivered', 'failed',
        'cancellation_requested', 'cancelled', 'skipped'
    )),
    attempts          INTEGER NOT NULL DEFAULT 0,
    lease_expires_at  INTEGER,
    run_id            TEXT,
    session_id        TEXT,
    last_error        TEXT,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
) STRICT;

CREATE UNIQUE INDEX trigger_delivery_run_id_idx
    ON trigger_delivery (run_id) WHERE run_id IS NOT NULL;
CREATE UNIQUE INDEX trigger_delivery_session_id_idx
    ON trigger_delivery (session_id) WHERE session_id IS NOT NULL;
CREATE INDEX trigger_delivery_claim_idx
    ON trigger_delivery (state, lease_expires_at) WHERE state IN ('ready', 'leased');

ALTER TABLE trigger_event ADD COLUMN outcome TEXT CHECK (outcome IS NULL OR outcome IN (
    'admitted', 'skipped_due_to_overlap', 'queued',
    'cancelled_previous_and_admitted', 'skipped_queue_full',
    'skipped_cancellation_unconfirmed'
));
"#;

/// Phase 8, Task 4: the durable identity of one outstanding `call:`
/// invocation. `workflow_run.parent_run_id` says only that a run has a parent;
/// it cannot distinguish a retry fork or identify the parent task that must be
/// terminalized. This row is written with child creation and the parent step's
/// `Running` checkpoint, then its `join_state` is advanced in the same
/// transaction as the parent task terminal event.
const MIGRATION_0014_WORKFLOW_CHILD_CALLS: &str = r#"
CREATE TABLE workflow_child_call (
    child_run_id      TEXT NOT NULL PRIMARY KEY,
    parent_run_id     TEXT NOT NULL,
    parent_step_id    TEXT NOT NULL,
    parent_attempt    INTEGER NOT NULL CHECK (parent_attempt > 0),
    parent_item_index INTEGER NOT NULL CHECK (parent_item_index BETWEEN -1 AND 4294967295),
    parent_task_id    TEXT NOT NULL UNIQUE,
    join_state        TEXT NOT NULL CHECK (join_state IN ('pending', 'joined')),
    terminal_task_seq INTEGER CHECK (terminal_task_seq IS NULL OR terminal_task_seq >= 0),
    joined_at         INTEGER,
    CHECK (
        (join_state = 'pending' AND terminal_task_seq IS NULL AND joined_at IS NULL)
        OR (join_state = 'joined' AND terminal_task_seq IS NOT NULL AND joined_at IS NOT NULL)
    ),
    UNIQUE (parent_run_id, parent_step_id, parent_attempt, parent_item_index)
) STRICT;

CREATE INDEX workflow_child_call_parent_idx
    ON workflow_child_call (parent_run_id)
    WHERE join_state = 'pending';
"#;

/// Phase 8, Task 4 fix round 1: a continuation lease elects exactly one
/// process to resume a parent after its child becomes terminal. A lease is
/// intentionally recoverable: after a crash its expiry makes the call
/// claimable again, while a completed continuation is never re-driven.
const MIGRATION_0015_WORKFLOW_CHILD_CALL_CONTINUATIONS: &str = r#"
ALTER TABLE workflow_child_call ADD COLUMN continuation_state TEXT NOT NULL DEFAULT 'available'
    CHECK (continuation_state IN ('available', 'claimed', 'completed'));
ALTER TABLE workflow_child_call ADD COLUMN continuation_claim_token TEXT;
ALTER TABLE workflow_child_call ADD COLUMN continuation_lease_expires_at INTEGER;
ALTER TABLE workflow_child_call ADD COLUMN continuation_completed_at INTEGER;
"#;

/// Phase 8, Task 4 fix round 2: an in-process continuation claim must never
/// expire while its owner can still drive parent effects. Only boot may recover
/// an incomplete claim, after the former process is known to be gone.
const MIGRATION_0016_WORKFLOW_CHILD_CALL_NON_EXPIRING_CLAIMS: &str = r#"
ALTER TABLE workflow_child_call DROP COLUMN continuation_lease_expires_at;
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
        M::up(MIGRATION_0008_WORKFLOW_RUN_LEDGER),
        M::up(MIGRATION_0009_JOBS),
        M::up(MIGRATION_0010_WORKSPACES),
        M::up("ALTER TABLE workflow_run ADD COLUMN checkpoint_ref TEXT;"),
        M::up("ALTER TABLE workflow_run ADD COLUMN checkpoint_blob_ref TEXT;"),
        M::up(MIGRATION_0013_TRIGGER_BINDINGS_AND_DELIVERIES),
        M::up(MIGRATION_0014_WORKFLOW_CHILD_CALLS),
        M::up(MIGRATION_0015_WORKFLOW_CHILD_CALL_CONTINUATIONS),
        M::up(MIGRATION_0016_WORKFLOW_CHILD_CALL_NON_EXPIRING_CLAIMS),
    ])
}
