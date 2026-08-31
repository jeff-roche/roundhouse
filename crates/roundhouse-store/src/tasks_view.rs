//! Maintains the `tasks` materialized-cache table (§4.1: "a derived cache maintained by
//! the single writer") live, in the same SQLite transaction as the `events` insert that
//! produced the change (§6.10's pattern) — so a `tasks` row is never observably
//! inconsistent with the event log it derives from. Called from `writer::append_one`.

use roundhouse_core::{EventPayload, TaskState};
use rusqlite::{params, Transaction};

/// Maintains the `tasks` materialized-cache row for the task-lifecycle event just
/// appended, in the same transaction as the `events` insert. A no-op for events that
/// don't change task state (`TaskDelta`, `TaskProgress`, `Note` — matching
/// `fold_task_state`'s own `_ => state` arm). Callers are responsible for only invoking
/// this for events that carry a `task_id` (session-level events have no `tasks` row to
/// touch); see `writer::append_one`.
///
/// `ts_nanos` is the event's own timestamp (unix nanos, matching `Timestamp` elsewhere in
/// this crate) — used for `suspended_since` when the fold lands on `TaskState::Suspended`.
/// It is deliberately the event's timestamp, not `seq`: `seq` is a per-session sequence
/// number, not a point in time, and `suspended_since` needs to answer "how long has this
/// task been waiting", which only a real timestamp can do.
pub(crate) fn upsert_for_event(
    tx: &Transaction,
    task_id: &str,
    session_id: &str,
    seq: i64,
    ts_nanos: i64,
    payload: &EventPayload,
) -> rusqlite::Result<()> {
    // A single-event slice reuses fold_task_state's own match arms instead of
    // duplicating them here — the two must never independently drift.
    let Some(state) = roundhouse_core::fold_task_state(std::slice::from_ref(payload)) else {
        return Ok(()); // TaskDelta/TaskProgress/Note/Message: no state change.
    };

    let (suspended_since, suspend_reason_json) = match &state {
        TaskState::Suspended(reason) => (
            Some(ts_nanos),
            Some(
                serde_json::to_string(reason)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
            ),
        ),
        _ => (None, None),
    };

    // `prepare_cached`, not `tx.execute` (which reparses/recompiles the SQL
    // text from scratch on every call): this function runs once per
    // task-lifecycle event, including once per member of a
    // `writer::append_batch` batch — at crash-recovery scale (S-SESS-4's
    // 500 sessions x 200 tasks) that is up to 100,000 calls in a single
    // transaction, where re-parsing identical SQL text on every call was
    // confirmed empirically (`tests/recovery_scale.rs`) to be the dominant
    // cost. Both statements below are identical text on every call within a
    // transaction, so SQLite's per-connection statement cache turns each
    // repeat call into a cheap lookup-and-rebind instead of a fresh parse.
    if let EventPayload::TaskCreated { kind, parent, .. } = payload {
        let mut insert_task = tx.prepare_cached(
            "INSERT INTO tasks (task_id, session_id, kind, state, parent, created_seq, updated_seq, suspended_since, suspend_reason_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7, ?8)",
        )?;
        insert_task.execute(params![
            task_id,
            session_id,
            task_kind_as_sql_str(kind),
            state.as_sql_str(),
            parent.map(|p| p.to_string()),
            seq,
            suspended_since,
            suspend_reason_json
        ])?;
    } else {
        // Security fix: a zero-row UPDATE (no `tasks` row exists for this task_id) used to
        // be silently swallowed — the event still committed to `events`, the caller got
        // `Ok`, and the derived `tasks` cache silently failed to reflect the change. Per
        // this project's fail-closed invariant, that is a bug in itself: check the
        // rows-affected count and turn a zero-row match into a hard error instead of a
        // silent no-op. `backfill_tasks_table` (called from `open()`) is what keeps this
        // from being spuriously reachable on every legitimate upgrade of an existing
        // database — it seeds a `tasks` row for every task_id already in the event log
        // before this function is ever asked to UPDATE one.
        let mut update_task = tx.prepare_cached(
            "UPDATE tasks SET state = ?1, updated_seq = ?2, suspended_since = ?3, suspend_reason_json = ?4 WHERE task_id = ?5",
        )?;
        let rows_affected = update_task.execute(params![
            state.as_sql_str(),
            seq,
            suspended_since,
            suspend_reason_json,
            task_id
        ])?;
        if rows_affected == 0 {
            return Err(rusqlite::Error::StatementChangedRows(0));
        }
    }
    Ok(())
}

/// One raw `events` row read back for backfill purposes:
/// `(session_id, seq, ts_nanos, task_id, payload_json)`. `task_id` is a plain `String`
/// (not `Option`) here because the query that produces these rows already filters
/// `task_id IS NOT NULL`.
type BackfillRow = (String, i64, i64, String, String);

/// A `task_id`'s events, ordered by `seq`, plus the `session_id` they share (every event
/// bearing one `task_id` belongs to the same session).
struct TaskHistory {
    session_id: String,
    events: Vec<(i64, i64, EventPayload)>, // (seq, ts_nanos, payload), in seq order
}

/// Security fix: one-time reconciliation run automatically by `open()`, right after
/// migrations apply. Migration 0003 only adds the `suspended_since`/`suspend_reason_json`
/// columns — it does not backfill `tasks` rows for tasks that already existed in the event
/// log before this migration ran (there were none in Task 0.5's own tests, since the table
/// was previously dead, but every real database this daemon has ever written a task to has
/// them). Without this, every subsequent lifecycle event for such a pre-existing task would
/// hit `upsert_for_event`'s `UPDATE` branch and match zero rows — now a hard error (see
/// above), where it used to be a silent gap. Worse, a task already `Suspended` at the time
/// of the upgrade would never get an `INSERT` either (`recovery.rs` deliberately skips
/// `Suspended` tasks) and so could never appear in `tasks` at all.
///
/// Scans the full event log grouped by `task_id` — the same full-scan-and-group technique
/// `recovery.rs` already uses for its own purposes — folds each task's current state via
/// `roundhouse_core::fold_task_state` (the same function `upsert_for_event` calls
/// per-event), and inserts a `tasks` row for every `task_id` missing one, including the
/// real `SuspendReason` (not a placeholder) for anything currently suspended. Already-
/// present `task_id`s are left untouched (`INSERT OR IGNORE`), so this is idempotent and
/// safe to run on every `open()`, not just the first post-migration one — the query itself
/// is scoped to only `task_id`s missing from `tasks`, so once the backfill is complete a
/// later call is a cheap, empty-result query rather than a full parse-and-fold pass.
///
/// Runs in its own transaction (all-or-nothing): if it fails partway, nothing changes, and
/// since it is idempotent, the next `open()` call retries the same missing `task_id`s.
pub(crate) fn backfill_tasks_table(conn: &mut rusqlite::Connection) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;

    let mut stmt = tx.prepare(
        "SELECT session_id, seq, ts, task_id, payload FROM events \
         WHERE task_id IS NOT NULL AND task_id NOT IN (SELECT task_id FROM tasks) \
         ORDER BY task_id, seq",
    )?;
    let mapped = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ))
    })?;
    let rows: Vec<BackfillRow> = mapped.collect::<rusqlite::Result<_>>()?;
    drop(stmt);

    if rows.is_empty() {
        return Ok(()); // Every live task_id already has a tasks row — nothing to backfill.
    }

    let mut by_task: std::collections::HashMap<String, TaskHistory> =
        std::collections::HashMap::new();
    for (session_id, seq, ts_nanos, task_id, payload_json) in rows {
        let payload: EventPayload = serde_json::from_str(&payload_json)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        by_task
            .entry(task_id)
            .or_insert_with(|| TaskHistory {
                session_id,
                events: Vec::new(),
            })
            .events
            .push((seq, ts_nanos, payload));
    }

    for (task_id, history) in &by_task {
        // Fold one event at a time (rather than calling fold_task_state once on the whole
        // slice) so we can also track which event's seq/ts_nanos produced the final state —
        // exactly the (seq, ts_nanos) upsert_for_event would have used had it processed
        // this event live. `fold_task_state` only ever changes `state` on the exact same
        // match arms this loop checks, so the final `state` here is identical to calling
        // it once on the whole slice.
        let mut state: Option<TaskState> = None;
        let mut created_seq: Option<i64> = None;
        let mut kind: Option<roundhouse_core::TaskKind> = None;
        let mut parent: Option<String> = None;
        let mut last_state_seq: i64 = 0;
        let mut last_state_ts: i64 = 0;

        for (seq, ts_nanos, payload) in &history.events {
            if let EventPayload::TaskCreated {
                kind: k, parent: p, ..
            } = payload
            {
                created_seq = Some(*seq);
                kind = Some(k.clone());
                parent = p.map(|id| id.to_string());
            }
            if let Some(new_state) = roundhouse_core::fold_task_state(std::slice::from_ref(payload))
            {
                state = Some(new_state);
                last_state_seq = *seq;
                last_state_ts = *ts_nanos;
            }
        }

        // Defensive: a task_id with no TaskCreated event (corrupt/partial history) has
        // nothing well-formed to backfill — skip it rather than insert a bogus row, same
        // posture as fold_task's own `?` early-return for a missing TaskCreated.
        let (Some(state), Some(created_seq), Some(kind)) = (state, created_seq, kind) else {
            continue;
        };

        let (suspended_since, suspend_reason_json) = match &state {
            TaskState::Suspended(reason) => (
                Some(last_state_ts),
                Some(
                    serde_json::to_string(reason)
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
                ),
            ),
            _ => (None, None),
        };

        tx.execute(
            "INSERT OR IGNORE INTO tasks (task_id, session_id, kind, state, parent, created_seq, updated_seq, suspended_since, suspend_reason_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                task_id,
                history.session_id,
                task_kind_as_sql_str(&kind),
                state.as_sql_str(),
                parent,
                created_seq,
                last_state_seq,
                suspended_since,
                suspend_reason_json
            ],
        )?;
    }

    tx.commit()
}

/// `TaskKind`'s SQL-text representation for the `tasks.kind` column. `TaskKind` has no
/// `as_sql_str`/`Display` of its own (checked: `task_kind.rs` defines only
/// `Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema`, and no other crate
/// stores or reads it back as SQL text today — `tests/schema.rs`'s existing
/// `INSERT INTO tasks` coverage already uses the literal `"Shell"`, which is exactly
/// `TaskKind::Shell`'s `Debug` output). `Debug` format is used here as that same minimal,
/// already-precedented choice: every flat variant (`Chat`, `Shell`, `Read`, ...) Debug-
/// formats to just its bare name. The one rough edge is `Plugin { vendor, verb }`, whose
/// `Debug` output is `Plugin { vendor: "x", verb: "y" }` rather than the doc-commented
/// `vendor:verb` convention — this was an acceptable minimal choice at the time because no
/// code parsed `tasks.kind` back into a `TaskKind` (this column was a discriminant-only
/// cache per the `state` column's own precedent). That reader has since arrived: Task 21's
/// `attention::parse_task_kind` (`roundhouse-store/src/attention.rs`) is the first real
/// consumer that parses this column back, including a hand-rolled decoder for exactly this
/// `Plugin { vendor: "..", verb: ".." }` `Debug` shape — see that module's doc comment for
/// the resulting implicit, untyped cross-crate contract this now creates (this function is
/// the writer half of it; `parse_task_kind` is the reader half, and the two must be kept in
/// lockstep manually, since nothing here pins the format at compile time). A real
/// `TaskKind::as_sql_str`/`from_sql_str` pair (with a clean `vendor:verb` encoding for
/// `Plugin`) remains a reasonable future refactor if a second crate ever needs the same
/// read capability, so both readers share one source of truth instead of each hand-rolling
/// a parser against `Debug`'s output — not required now that there is exactly one reader.
fn task_kind_as_sql_str(kind: &roundhouse_core::TaskKind) -> String {
    format!("{kind:?}")
}
