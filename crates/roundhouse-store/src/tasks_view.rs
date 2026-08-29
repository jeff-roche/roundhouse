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

    if let EventPayload::TaskCreated { kind, parent, .. } = payload {
        tx.execute(
            "INSERT INTO tasks (task_id, session_id, kind, state, parent, created_seq, updated_seq, suspended_since, suspend_reason_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7, ?8)",
            params![
                task_id,
                session_id,
                task_kind_as_sql_str(kind),
                state.as_sql_str(),
                parent.map(|p| p.to_string()),
                seq,
                suspended_since,
                suspend_reason_json
            ],
        )?;
    } else {
        tx.execute(
            "UPDATE tasks SET state = ?1, updated_seq = ?2, suspended_since = ?3, suspend_reason_json = ?4 WHERE task_id = ?5",
            params![
                state.as_sql_str(),
                seq,
                suspended_since,
                suspend_reason_json,
                task_id
            ],
        )?;
    }
    Ok(())
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
/// `vendor:verb` convention — no code parses `tasks.kind` back into a `TaskKind` today
/// (this column is a discriminant-only cache per the `state` column's own precedent), so
/// this is an acceptable minimal choice now; a real `TaskKind::as_sql_str`/`from_sql_str`
/// pair (with a clean `vendor:verb` encoding for `Plugin`) is future work for whenever a
/// reader needs to parse this column back, not before.
fn task_kind_as_sql_str(kind: &roundhouse_core::TaskKind) -> String {
    format!("{kind:?}")
}
