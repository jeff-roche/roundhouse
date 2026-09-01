//! `trigger_event` persistence: catch-up policy application and idempotency
//! dedupe (Phase 5, Subsystem A, Task 4). See
//! `docs/architecture/05-scheduling-and-workflows.md` and Ruling P4 (the
//! `trigger_event` table itself lives in `roundhouse_store::migrations`, not
//! a per-crate migration file — this module only reads/writes it).
use crate::trigger::{Binding, CatchUp, TriggerEvent, TriggerSpec};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

/// Applies the binding's `CatchUp` policy to a list of missed scheduled
/// instants, returning the instants that should actually be run. Non-cron
/// triggers (e.g. `Message`, `Webhook`) don't accumulate misses the same
/// way a cron schedule does, so every missed instant is run for those.
pub fn compute_catch_up(binding: &Binding, missed: Vec<DateTime<Utc>>) -> Vec<DateTime<Utc>> {
    let catch_up = match &binding.spec {
        TriggerSpec::Cron { catch_up, .. } => catch_up,
        _ => return missed,
    };
    match catch_up {
        CatchUp::None => vec![],
        CatchUp::All => missed,
        CatchUp::Latest => missed.into_iter().last().into_iter().collect(),
    }
}

/// Inserts a `TriggerEvent`. Returns `Ok(true)` if this was a new firing,
/// `Ok(false)` if `(binding_id, idempotency_key)` already existed (a dedupe
/// hit — the caller must NOT start a run for a deduped event).
///
/// Deviation from the plan text: the plan's code block did a `SELECT`
/// existence check, then `INSERT`, wrapped in hand-rolled `BEGIN
/// IMMEDIATE`/`COMMIT`/`ROLLBACK` SQL strings. That races under concurrent
/// callers (two writers can both pass the `SELECT` before either commits its
/// `INSERT`) and violates the project's one hand-rolled-transaction
/// convention. This implementation instead relies on the real
/// `trigger_event_dedupe` UNIQUE index via `INSERT ... ON CONFLICT DO
/// NOTHING` — exactly what the task's own Interfaces section specifies —
/// through `roundhouse_store::begin_immediate` for the `BEGIN IMMEDIATE`
/// write transaction (Ruling P4).
pub fn record_trigger_event(conn: &mut Connection, ev: &TriggerEvent) -> Result<bool, StoreError> {
    let txn = roundhouse_store::begin_immediate(conn)?;
    let rows_changed = txn.execute(
        "INSERT INTO trigger_event
            (binding_id, idempotency_key, scheduled_for, fired_at, is_catch_up, session_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(binding_id, idempotency_key) DO NOTHING",
        params![
            ev.binding_id.to_string(),
            ev.idempotency_key,
            ev.scheduled_for.to_rfc3339(),
            ev.fired_at.to_rfc3339(),
            ev.is_catch_up as i64,
            ev.session_id.map(|s| s.to_string()),
        ],
    )?;
    txn.commit()?;
    Ok(rows_changed > 0)
}

/// Test-only helper: an in-memory SQLite connection with the real store
/// migrations applied (Ruling P4 — never a per-crate migration file, since
/// that would never reach the daemon's actual database).
pub fn open_test_db() -> Connection {
    let mut conn = roundhouse_store::open_memory_connection();
    roundhouse_store::migrations()
        .to_latest(&mut conn)
        .expect("apply store migrations, including trigger_event");
    conn
}
