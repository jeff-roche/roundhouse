//! `trigger_event` persistence: catch-up policy application and idempotency
//! dedupe (Phase 5, Subsystem A, Task 4). See
//! `docs/architecture/05-scheduling-and-workflows.md` and Ruling P4 (the
//! `trigger_event` table itself lives in `roundhouse_store::migrations`, not
//! a per-crate migration file — this module only reads/writes it).
use crate::trigger::{Binding, CatchUp, TriggerEvent, TriggerSpec};
use chrono::{DateTime, Utc};
use roundhouse_core::BindingId;
use rusqlite::{params, Connection};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    /// M3: the `idempotency_key` column has no cap in SQLite itself; this is
    /// the application-level bound so a pathological (or malicious, e.g. a
    /// webhook body reflected verbatim into a key) key can't grow the
    /// `trigger_event` table's rows without limit.
    #[error("idempotency key is {len} bytes, exceeds the {max}-byte cap")]
    IdempotencyKeyTooLong { len: usize, max: usize },
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
        // M5 fix: `.last()` is *positional* (whatever happened to be at the
        // end of the input `Vec`), not *temporal*. Callers are expected to
        // pass `missed` in chronological order, but "latest" must mean the
        // temporally latest occurrence regardless of input order — `.max()`
        // is the actual contract `CatchUp::Latest` names.
        CatchUp::Latest => missed.into_iter().max().into_iter().collect(),
    }
}

/// M3: the canonical idempotency-key derivation for one scheduled
/// occurrence. Keyed on `(binding_id, scheduled_for)` — the occurrence's own
/// identity — deliberately NOT on when it was actually *processed*
/// (`fired_at`/`Utc::now()`), which is a different value on every
/// crash-and-retry and would defeat the `trigger_event_dedupe` UNIQUE index
/// in exactly the case it exists to catch. `scheduled_for` is always UTC
/// (`DateTime<Utc>`), so the RFC3339 text is stable and unambiguous across
/// retries regardless of wall-clock/timezone at fire time.
pub fn occurrence_key(binding_id: BindingId, scheduled_for: DateTime<Utc>) -> String {
    format!("{binding_id}@{}", scheduled_for.to_rfc3339())
}

/// M3: application-level cap on `idempotency_key` length. Chosen generously
/// above any real occurrence key this crate derives (`occurrence_key`'s
/// output is well under 100 bytes) while still bounding a key sourced from
/// less trusted input (e.g. a future webhook-delivery-id-based key), so a
/// pathological key can't grow a `trigger_event` row without limit.
pub const MAX_IDEMPOTENCY_KEY_LEN: usize = 512;

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
    if ev.idempotency_key.len() > MAX_IDEMPOTENCY_KEY_LEN {
        return Err(StoreError::IdempotencyKeyTooLong {
            len: ev.idempotency_key.len(),
            max: MAX_IDEMPOTENCY_KEY_LEN,
        });
    }
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
///
/// L7: gated behind `cfg(test)`/the `test-util` feature so daemon code can
/// never reach for this as if it were the crate's normal way to get a
/// connection — doing so would silently write trigger events to a private
/// in-memory database, reducing dedupe to per-process scope (defeating the
/// exact "exactly one run per scheduled occurrence, even under
/// crash-and-retry" guarantee this table exists for). Integration tests
/// under `tests/` activate `test-util` via this crate's own dev-dependency
/// on itself (see `Cargo.toml`); `cfg(test)` alone only covers this crate's
/// in-lib unit tests, not the separate integration-test crates.
#[cfg(any(test, feature = "test-util"))]
pub fn open_test_db() -> Connection {
    let mut conn = roundhouse_store::open_memory_connection();
    roundhouse_store::migrations()
        .to_latest(&mut conn)
        .expect("apply store migrations, including trigger_event");
    conn
}
