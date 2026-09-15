//! `trigger_event`/`trigger_delivery` persistence: catch-up policy
//! application, idempotency dedupe (Phase 5, Subsystem A, Task 4), and —
//! Phase 8, Task 3 of the trigger-delivery rebuild — the durable
//! `accept_occurrence` acceptance path plus the `trigger_delivery` outbox's
//! predecessor-constrained lifecycle transitions. See
//! `docs/architecture/05-scheduling-and-workflows.md` and Ruling P4 (the
//! `trigger_event`/`trigger_binding`/`trigger_binding_cursor`/
//! `trigger_delivery` tables themselves live in `roundhouse_store::migrations`,
//! not a per-crate migration file — this module only reads/writes them).
use crate::admission::{decide_admission, AdmissionDecision, RegistryError, RunRegistry};
use crate::delivery::{DeliveryError, DeliveryState, TriggerDelivery};
use crate::scheduler::ScheduledOccurrence;
use crate::trigger::{
    Binding, CatchUp, StoredBinding, TriggerError, TriggerEvent, TriggerEventOutcome, TriggerSpec,
};
use chrono::{DateTime, Utc};
use roundhouse_core::{BindingId, SessionId, Timestamp};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use thiserror::Error;
use uuid::Uuid;

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
    /// Task 3, `accept_occurrence` step 1: the caller handed in a
    /// `StoredBinding`/`ScheduledOccurrence` pair that don't name the same
    /// binding. Checked *before* opening a transaction — see
    /// [`accept_occurrence`]'s own doc comment for why this can never be a
    /// database-observable error.
    #[error(
        "occurrence names binding {occurrence_binding_id}, but the supplied binding is \
         {binding_id}; refusing to touch the database"
    )]
    BindingIdentityMismatch {
        binding_id: BindingId,
        occurrence_binding_id: BindingId,
    },
    /// A `TEXT` id column (`binding_id`/`session_id`) held a value that does
    /// not parse as a UUID. Mirrors
    /// `roundhouse_flow::durability::DurabilityError::MalformedId`'s shape —
    /// a hand-edited or corrupted row must be refused, not silently coerced.
    #[error("column {column} holds a value that is not a valid UUID: {source}")]
    MalformedId {
        column: &'static str,
        #[source]
        source: uuid::Error,
    },
    /// A numeric column held a value outside the Rust-side type's domain
    /// (e.g. `trigger_delivery.attempts` not fitting in a `u32`). Refused
    /// rather than silently clamped, matching this column's own read-back
    /// discipline elsewhere in the codebase.
    #[error("column {column} holds out-of-range value {value}")]
    OutOfRange { column: &'static str, value: i64 },
    #[error(transparent)]
    Delivery(#[from] DeliveryError),
    #[error(transparent)]
    TriggerOutcome(#[from] TriggerError),
    #[error(transparent)]
    Admission(#[from] RegistryError),
}

/// The binding's configured `CatchUp` policy, or `None` for a non-cron
/// trigger (which has no such policy — `compute_catch_up` always runs every
/// missed instant for those). Shared by `compute_catch_up` below and by
/// `scheduler::Scheduler`'s `drain_due`, which needs to know the policy
/// *without* also needing a `missed` list on hand (fix round 1, M2: the
/// policy decision has to span potentially many `drain_due` batches, not
/// just the one batch `compute_catch_up` reduces).
pub(crate) fn catch_up_policy(binding: &Binding) -> Option<&CatchUp> {
    match &binding.spec {
        TriggerSpec::Cron { catch_up, .. } => Some(catch_up),
        _ => None,
    }
}

/// Applies the binding's `CatchUp` policy to a list of missed scheduled
/// instants, returning the instants that should actually be run. Non-cron
/// triggers (e.g. `Message`, `Webhook`) don't accumulate misses the same
/// way a cron schedule does, so every missed instant is run for those.
pub fn compute_catch_up(binding: &Binding, missed: Vec<DateTime<Utc>>) -> Vec<DateTime<Utc>> {
    let Some(catch_up) = catch_up_policy(binding) else {
        return missed;
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

/// The composable core of the `trigger_event` insert — executes the same
/// `INSERT ... ON CONFLICT DO NOTHING` against an already-open `&Transaction`
/// instead of owning its own `begin_immediate`/commit, so it can be called
/// both from [`record_trigger_event`]'s self-contained transaction and from
/// [`accept_occurrence`]'s larger one (Task 3 brief step 3: "do not call the
/// existing `record_trigger_event` directly from inside your transaction —
/// it owns its own `begin_immediate`/commit and can't be composed into a
/// shared transaction").
///
/// Returns `Some(trigger_event.id)` for a newly inserted row, `None` for a
/// dedupe hit (`(binding_id, idempotency_key)` already existed).
fn insert_trigger_event_in_txn(
    txn: &Transaction<'_>,
    ev: &TriggerEvent,
) -> Result<Option<i64>, StoreError> {
    if ev.idempotency_key.len() > MAX_IDEMPOTENCY_KEY_LEN {
        return Err(StoreError::IdempotencyKeyTooLong {
            len: ev.idempotency_key.len(),
            max: MAX_IDEMPOTENCY_KEY_LEN,
        });
    }
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
    if rows_changed > 0 {
        Ok(Some(txn.last_insert_rowid()))
    } else {
        Ok(None)
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
///
/// Task 3: the actual `INSERT` now lives in [`insert_trigger_event_in_txn`],
/// so this function is a thin, self-contained-transaction wrapper around it —
/// kept for existing callers (and for any caller that only needs the dedupe
/// insert, not the fuller `accept_occurrence` acceptance path).
pub fn record_trigger_event(conn: &mut Connection, ev: &TriggerEvent) -> Result<bool, StoreError> {
    let txn = roundhouse_store::begin_immediate(conn)?;
    let inserted = insert_trigger_event_in_txn(&txn, ev)?;
    txn.commit()?;
    Ok(inserted.is_some())
}

/// What `AdmissionDecision` variant, if any, admits a new `trigger_delivery`
/// row into existence. `SkipDueToOverlap`/`SkippedQueueFull`/
/// `SkippedCancellationUnconfirmed` never create one — the occurrence is
/// durably recorded (the `trigger_event` row, with its `outcome`) but never
/// becomes a delivery.
fn decision_creates_delivery(decision: AdmissionDecision) -> bool {
    matches!(
        decision,
        AdmissionDecision::Admit
            | AdmissionDecision::QueueAt(_)
            | AdmissionDecision::CancelledPreviousAndAdmit
    )
}

/// The durable, `CHECK`-vocabulary-matching sibling of one
/// `AdmissionDecision`, stripped of any carried data — see
/// [`TriggerEventOutcome`]'s own doc comment for why (a `CHECK` column can't
/// hold `QueueAt`'s position or `SkippedQueueFull`'s depth; that data is an
/// in-memory admission concern, not something this durable row needs to
/// answer "what kind of decision was this").
fn outcome_for_decision(decision: AdmissionDecision) -> TriggerEventOutcome {
    match decision {
        AdmissionDecision::Admit => TriggerEventOutcome::Admitted,
        AdmissionDecision::SkipDueToOverlap => TriggerEventOutcome::SkippedDueToOverlap,
        AdmissionDecision::QueueAt(_) => TriggerEventOutcome::Queued,
        AdmissionDecision::CancelledPreviousAndAdmit => {
            TriggerEventOutcome::CancelledPreviousAndAdmitted
        }
        AdmissionDecision::SkippedQueueFull { .. } => TriggerEventOutcome::SkippedQueueFull,
        AdmissionDecision::SkippedCancellationUnconfirmed => {
            TriggerEventOutcome::SkippedCancellationUnconfirmed
        }
    }
}

/// `DateTime<Utc>` -> `Timestamp` (unix nanos). Mirrors `cron.rs`'s
/// `deterministic_jitter`'s own `timestamp_nanos_opt().unwrap_or(0)`
/// fallback — the only way this can fail is a `DateTime` outside
/// `chrono`'s representable nanosecond range (year ~1677-2262), which no
/// real scheduled occurrence ever is.
fn timestamp_from_datetime(dt: DateTime<Utc>) -> Timestamp {
    Timestamp::from_unix_nanos(dt.timestamp_nanos_opt().unwrap_or(0))
}

fn parse_binding_id(s: &str, column: &'static str) -> Result<BindingId, StoreError> {
    Uuid::parse_str(s)
        .map(BindingId::from_uuid)
        .map_err(|source| StoreError::MalformedId { column, source })
}

fn parse_session_id(s: &str, column: &'static str) -> Result<SessionId, StoreError> {
    Uuid::parse_str(s)
        .map(SessionId::from_uuid)
        .map_err(|source| StoreError::MalformedId { column, source })
}

/// Raw column values for one `trigger_delivery` row, read inside a
/// `rusqlite` row-mapping closure (which must return `rusqlite::Result`, so
/// the fallible `BindingId`/`SessionId`/`DeliveryState` decoding happens
/// afterward, in [`decode_delivery_row`]).
struct RawDeliveryRow {
    delivery_id: String,
    trigger_event_id: i64,
    binding_id: String,
    state: String,
    attempts: i64,
    lease_expires_at: Option<i64>,
    run_id: Option<String>,
    session_id: Option<String>,
    last_error: Option<String>,
    created_at: i64,
    updated_at: i64,
}

const DELIVERY_COLUMNS: &str = "delivery_id, trigger_event_id, binding_id, state, attempts, \
     lease_expires_at, run_id, session_id, last_error, created_at, updated_at";

fn map_delivery_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawDeliveryRow> {
    Ok(RawDeliveryRow {
        delivery_id: row.get(0)?,
        trigger_event_id: row.get(1)?,
        binding_id: row.get(2)?,
        state: row.get(3)?,
        attempts: row.get(4)?,
        lease_expires_at: row.get(5)?,
        run_id: row.get(6)?,
        session_id: row.get(7)?,
        last_error: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
    })
}

fn decode_delivery_row(raw: RawDeliveryRow) -> Result<TriggerDelivery, StoreError> {
    let attempts = u32::try_from(raw.attempts).map_err(|_| StoreError::OutOfRange {
        column: "trigger_delivery.attempts",
        value: raw.attempts,
    })?;
    Ok(TriggerDelivery {
        delivery_id: raw.delivery_id,
        trigger_event_id: raw.trigger_event_id,
        binding_id: parse_binding_id(&raw.binding_id, "trigger_delivery.binding_id")?,
        state: DeliveryState::from_sql_str(&raw.state)?,
        attempts,
        lease_expires_at: raw.lease_expires_at.map(Timestamp::from_unix_nanos),
        run_id: raw.run_id,
        session_id: raw
            .session_id
            .as_deref()
            .map(|s| parse_session_id(s, "trigger_delivery.session_id"))
            .transpose()?,
        last_error: raw.last_error,
        created_at: Timestamp::from_unix_nanos(raw.created_at),
        updated_at: Timestamp::from_unix_nanos(raw.updated_at),
    })
}

fn insert_delivery_in_txn(txn: &Transaction<'_>, d: &TriggerDelivery) -> Result<(), StoreError> {
    txn.execute(
        "INSERT INTO trigger_delivery
            (delivery_id, trigger_event_id, binding_id, state, attempts,
             lease_expires_at, run_id, session_id, last_error, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            d.delivery_id,
            d.trigger_event_id,
            d.binding_id.to_string(),
            d.state.as_sql_str(),
            d.attempts,
            d.lease_expires_at.map(|t| t.as_unix_nanos()),
            d.run_id,
            d.session_id.map(|s| s.to_string()),
            d.last_error,
            d.created_at.as_unix_nanos(),
            d.updated_at.as_unix_nanos(),
        ],
    )?;
    Ok(())
}

fn select_delivery_by_trigger_event_id_in_txn(
    txn: &Transaction<'_>,
    trigger_event_id: i64,
) -> Result<Option<TriggerDelivery>, StoreError> {
    let raw = txn
        .query_row(
            &format!("SELECT {DELIVERY_COLUMNS} FROM trigger_delivery WHERE trigger_event_id = ?1"),
            params![trigger_event_id],
            map_delivery_row,
        )
        .optional()?;
    raw.map(decode_delivery_row).transpose()
}

/// The previous non-terminal delivery for `binding_id`, most recent by
/// `created_at` — the one an `AdmissionDecision::CancelledPreviousAndAdmit`
/// decision needs to request cancellation on. "Non-terminal" excludes
/// `delivered`, `failed`, `cancelled`, `skipped` — a delivery already in one
/// of those states has nothing left to cancel.
fn select_latest_nonterminal_delivery_for_binding_in_txn(
    txn: &Transaction<'_>,
    binding_id: BindingId,
) -> Result<Option<TriggerDelivery>, StoreError> {
    let raw = txn
        .query_row(
            &format!(
                "SELECT {DELIVERY_COLUMNS} FROM trigger_delivery
                 WHERE binding_id = ?1
                   AND state NOT IN ('delivered', 'failed', 'cancelled', 'skipped')
                 ORDER BY created_at DESC, delivery_id DESC
                 LIMIT 1"
            ),
            params![binding_id.to_string()],
            map_delivery_row,
        )
        .optional()?;
    raw.map(decode_delivery_row).transpose()
}

/// Reads one `trigger_delivery` row by its id — a plain read, not wrapped in
/// its own `begin_immediate` (a single `SELECT` needs no write-transaction
/// snapshot of its own). Exposed `pub` for callers (and this module's own
/// tests) that need to inspect a delivery's current state after calling one
/// of the lifecycle transitions below.
pub fn fetch_delivery(
    conn: &Connection,
    delivery_id: &str,
) -> Result<Option<TriggerDelivery>, StoreError> {
    let raw = conn
        .query_row(
            &format!("SELECT {DELIVERY_COLUMNS} FROM trigger_delivery WHERE delivery_id = ?1"),
            params![delivery_id],
            map_delivery_row,
        )
        .optional()?;
    raw.map(decode_delivery_row).transpose()
}

fn advance_cursor_in_txn(
    txn: &Transaction<'_>,
    binding_id: BindingId,
    scheduled_for: DateTime<Utc>,
) -> Result<(), StoreError> {
    let nanos = timestamp_from_datetime(scheduled_for).as_unix_nanos();
    // Task 3 step 6: the occurrence happened regardless of admission outcome
    // (a `Skip`ped occurrence still consumed its scheduled instant), so the
    // cursor always advances — but only forward. The `WHERE` clause on the
    // `DO UPDATE` is the guard: an out-of-order/replayed occurrence whose
    // `scheduled_for` predates what is already stored must never regress it.
    txn.execute(
        "INSERT INTO trigger_binding_cursor (binding_id, last_fired_for)
         VALUES (?1, ?2)
         ON CONFLICT(binding_id) DO UPDATE SET last_fired_for = excluded.last_fired_for
         WHERE trigger_binding_cursor.last_fired_for IS NULL
            OR excluded.last_fired_for > trigger_binding_cursor.last_fired_for",
        params![binding_id.to_string(), nanos],
    )?;
    Ok(())
}

/// Requests cancellation of `delivery_id`, predecessor-constrained on
/// `expected` — the state the caller last observed it in. Returns whether
/// the request actually applied; a lost race (the delivery already moved to
/// some other state before this ran) is `Ok(false)`, never an error.
///
/// **This — and nothing else in this crate — is as far as
/// `OverlapPolicy::CancelPrevious` goes here.** It records
/// `cancellation_requested` and stops; it never marks a delivery terminal
/// (`cancelled`/`failed`). The daemon (a later task) calls
/// `roundhouse_flow::control::cancel` and, once that confirms, completes the
/// cancellation by transitioning the delivery the rest of the way.
fn request_cancellation_in_txn(
    txn: &Transaction<'_>,
    delivery_id: &str,
    expected: DeliveryState,
    now: Timestamp,
) -> Result<bool, StoreError> {
    let rows = txn.execute(
        "UPDATE trigger_delivery
         SET state = 'cancellation_requested', updated_at = ?1
         WHERE delivery_id = ?2 AND state = ?3",
        params![now.as_unix_nanos(), delivery_id, expected.as_sql_str()],
    )?;
    Ok(rows > 0)
}

/// `pub` wrapper around [`request_cancellation_in_txn`], for a caller outside
/// `accept_occurrence` that needs to request cancellation of a specific
/// delivery (e.g. a future manual-cancel API) with its own transaction.
pub fn request_cancellation(
    conn: &mut Connection,
    delivery_id: &str,
    expected: DeliveryState,
    now: Timestamp,
) -> Result<bool, StoreError> {
    let txn = roundhouse_store::begin_immediate(conn)?;
    let applied = request_cancellation_in_txn(&txn, delivery_id, expected, now)?;
    txn.commit()?;
    Ok(applied)
}

/// What `accept_occurrence` decided for one already-durable `trigger_event`
/// row, and (for a `New` acceptance) the `trigger_delivery` row it may have
/// created.
#[derive(Debug, Clone, PartialEq)]
pub enum Acceptance {
    /// This occurrence's `(binding_id, idempotency_key)` had never been seen
    /// before: `decide_admission` ran, its outcome was persisted onto the
    /// `trigger_event` row, and (for `Admit`/`QueueAt`/
    /// `CancelledPreviousAndAdmit`) a new `trigger_delivery` row was created.
    New {
        trigger_event_id: i64,
        decision: AdmissionDecision,
        outcome: TriggerEventOutcome,
        delivery: Option<TriggerDelivery>,
    },
    /// This occurrence's `(binding_id, idempotency_key)` already had a
    /// `trigger_event` row (a re-fire of the same occurrence, e.g. after a
    /// crash-and-retry). No fresh `AdmissionDecision` was made — the
    /// existing row's already-decided `outcome` (or `None`, if the process
    /// crashed between recording the event and deciding admission for it)
    /// and any existing `trigger_delivery` are returned as-is.
    Duplicate {
        trigger_event_id: i64,
        outcome: Option<TriggerEventOutcome>,
        delivery: Option<TriggerDelivery>,
    },
}

/// Accepts one scheduler-emitted [`ScheduledOccurrence`] of `binding`: durably
/// records the `trigger_event` (idempotent — a repeat of the same occurrence
/// is a no-op that returns the original decision, never a fresh one), runs
/// `decide_admission` against `registry` exactly once per genuinely-new
/// occurrence, persists that decision's [`TriggerEventOutcome`], creates the
/// `trigger_delivery` row an admitting decision implies, requests
/// cancellation of the previous delivery for `OverlapPolicy::CancelPrevious`,
/// and advances `binding`'s fire-cursor — all inside one
/// `roundhouse_store::begin_immediate` transaction.
///
/// # Why this owns its transaction
///
/// Per §5.3 trap #2 (see `roundhouse_store::txn::begin_immediate`'s own doc
/// comment): a caller-supplied *deferred* transaction that later issues a
/// write returns `SQLITE_BUSY_SNAPSHOT`, for which SQLite's busy handler is
/// never invoked — so this function must open its own `BEGIN IMMEDIATE`
/// rather than accept one from a caller who might have opened it deferred.
///
/// # Identity check
///
/// `binding.binding.id` and `occurrence.binding_id` naming different
/// bindings is a caller bug, not a database state to reconcile — checked
/// before any statement runs (not even inside a transaction), so a
/// mismatched call can never partially write anything.
pub fn accept_occurrence(
    conn: &mut Connection,
    binding: &StoredBinding,
    occurrence: &ScheduledOccurrence,
    fired_at: DateTime<Utc>,
    registry: &dyn RunRegistry,
) -> Result<Acceptance, StoreError> {
    if binding.binding.id != occurrence.binding_id {
        return Err(StoreError::BindingIdentityMismatch {
            binding_id: binding.binding.id,
            occurrence_binding_id: occurrence.binding_id,
        });
    }

    let idempotency_key = occurrence_key(occurrence.binding_id, occurrence.scheduled_for);
    let fired_at_ts = timestamp_from_datetime(fired_at);

    let txn = roundhouse_store::begin_immediate(conn)?;

    let ev = TriggerEvent {
        binding_id: occurrence.binding_id,
        idempotency_key: idempotency_key.clone(),
        scheduled_for: occurrence.scheduled_for,
        fired_at,
        is_catch_up: occurrence.is_catch_up,
        session_id: None,
        outcome: None,
    };

    let acceptance = match insert_trigger_event_in_txn(&txn, &ev)? {
        None => {
            // Duplicate (Task 3 step 4): re-fetch what is already durable and
            // fabricate no fresh `AdmissionDecision` — `decide_admission` is
            // NOT called again.
            let (trigger_event_id, outcome_str): (i64, Option<String>) = txn.query_row(
                "SELECT id, outcome FROM trigger_event
                 WHERE binding_id = ?1 AND idempotency_key = ?2",
                params![occurrence.binding_id.to_string(), idempotency_key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let outcome = outcome_str
                .map(|s| TriggerEventOutcome::from_sql_str(&s))
                .transpose()?;
            let delivery = select_delivery_by_trigger_event_id_in_txn(&txn, trigger_event_id)?;
            Acceptance::Duplicate {
                trigger_event_id,
                outcome,
                delivery,
            }
        }
        Some(trigger_event_id) => {
            // Genuinely new occurrence (Task 3 step 5): decide admission
            // exactly once, against the caller's `registry`.
            let decision =
                decide_admission(binding.binding.overlap, registry, occurrence.binding_id)?;
            let outcome = outcome_for_decision(decision);

            txn.execute(
                "UPDATE trigger_event SET outcome = ?1 WHERE id = ?2",
                params![outcome.as_sql_str(), trigger_event_id],
            )?;

            // Looked up *before* inserting the new delivery row below, so
            // there is no need to filter the new row back out of this query.
            let previous_to_cancel = if decision == AdmissionDecision::CancelledPreviousAndAdmit {
                select_latest_nonterminal_delivery_for_binding_in_txn(&txn, occurrence.binding_id)?
            } else {
                None
            };

            let delivery = if decision_creates_delivery(decision) {
                let delivery = TriggerDelivery {
                    delivery_id: Uuid::new_v4().to_string(),
                    trigger_event_id,
                    binding_id: occurrence.binding_id,
                    state: DeliveryState::Ready,
                    attempts: 0,
                    lease_expires_at: None,
                    run_id: None,
                    session_id: None,
                    last_error: None,
                    created_at: fired_at_ts,
                    updated_at: fired_at_ts,
                };
                insert_delivery_in_txn(&txn, &delivery)?;
                Some(delivery)
            } else {
                None
            };

            if let Some(previous) = previous_to_cancel {
                // A lost race (the previous delivery moved to some other
                // state — e.g. it already finished — between the read above
                // and this write) is a no-op, not an error: the whole
                // `accept_occurrence` call must not fail over it.
                let applied = request_cancellation_in_txn(
                    &txn,
                    &previous.delivery_id,
                    previous.state,
                    fired_at_ts,
                )?;
                if !applied {
                    tracing::debug!(
                        delivery_id = %previous.delivery_id,
                        binding_id = %occurrence.binding_id,
                        "CancelPrevious: previous delivery's state changed before cancellation \
                         could be requested (lost race) — no-op, not an error"
                    );
                }
            }

            Acceptance::New {
                trigger_event_id,
                decision,
                outcome,
                delivery,
            }
        }
    };

    // Task 3 step 6: the occurrence happened regardless of admission
    // outcome, so the cursor advances unconditionally — but never backward.
    advance_cursor_in_txn(&txn, occurrence.binding_id, occurrence.scheduled_for)?;

    txn.commit()?;
    Ok(acceptance)
}

/// Leases a `ready` delivery: `ready` -> `leased`, stamping
/// `lease_expires_at`. Predecessor-constrained on `state = 'ready'`, so
/// leasing an already-`leased` (or otherwise not-`ready`) delivery is a
/// no-op (`Ok(false)`), not a clobber or an error.
pub fn lease_delivery(
    conn: &mut Connection,
    delivery_id: &str,
    lease_expires_at: Timestamp,
    now: Timestamp,
) -> Result<bool, StoreError> {
    let txn = roundhouse_store::begin_immediate(conn)?;
    let rows = txn.execute(
        "UPDATE trigger_delivery
         SET state = 'leased', lease_expires_at = ?1, updated_at = ?2
         WHERE delivery_id = ?3 AND state = 'ready'",
        params![
            lease_expires_at.as_unix_nanos(),
            now.as_unix_nanos(),
            delivery_id
        ],
    )?;
    txn.commit()?;
    Ok(rows > 0)
}

/// Reclaims an expired lease: `leased` -> `ready` when `now` is at-or-past
/// the delivery's stored `lease_expires_at`. `now` is an explicit parameter,
/// never a real clock read inside this function — callers (and this
/// module's own tests) drive it with whatever `Timestamp` they construct, so
/// lease-expiry behavior is deterministic and sleep-free to test.
/// Predecessor-constrained on `state = 'leased' AND lease_expires_at <= now`;
/// a lease that has not yet expired, or a delivery not currently `leased`,
/// is a no-op.
pub fn reclaim_expired_lease(
    conn: &mut Connection,
    delivery_id: &str,
    now: Timestamp,
) -> Result<bool, StoreError> {
    let txn = roundhouse_store::begin_immediate(conn)?;
    let rows = txn.execute(
        "UPDATE trigger_delivery
         SET state = 'ready', lease_expires_at = NULL, updated_at = ?1
         WHERE delivery_id = ?2 AND state = 'leased'
           AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?3",
        params![now.as_unix_nanos(), delivery_id, now.as_unix_nanos()],
    )?;
    txn.commit()?;
    Ok(rows > 0)
}

/// Reserves a `leased` delivery for a specific run: `leased` -> `reserved`,
/// stamping `run_id`/`session_id`. Predecessor-constrained on
/// `state = 'leased'`.
pub fn reserve_delivery(
    conn: &mut Connection,
    delivery_id: &str,
    run_id: &str,
    session_id: SessionId,
    now: Timestamp,
) -> Result<bool, StoreError> {
    let txn = roundhouse_store::begin_immediate(conn)?;
    let rows = txn.execute(
        "UPDATE trigger_delivery
         SET state = 'reserved', run_id = ?1, session_id = ?2, updated_at = ?3
         WHERE delivery_id = ?4 AND state = 'leased'",
        params![
            run_id,
            session_id.to_string(),
            now.as_unix_nanos(),
            delivery_id
        ],
    )?;
    txn.commit()?;
    Ok(rows > 0)
}

/// Marks a `reserved` delivery as actively running: `reserved` -> `running`.
/// Predecessor-constrained on `state = 'reserved'`.
pub fn mark_delivery_running(
    conn: &mut Connection,
    delivery_id: &str,
    now: Timestamp,
) -> Result<bool, StoreError> {
    let txn = roundhouse_store::begin_immediate(conn)?;
    let rows = txn.execute(
        "UPDATE trigger_delivery SET state = 'running', updated_at = ?1
         WHERE delivery_id = ?2 AND state = 'reserved'",
        params![now.as_unix_nanos(), delivery_id],
    )?;
    txn.commit()?;
    Ok(rows > 0)
}

/// Completes a `running` delivery: `running` -> `delivered`.
/// Predecessor-constrained on `state = 'running'`.
pub fn complete_delivery(
    conn: &mut Connection,
    delivery_id: &str,
    now: Timestamp,
) -> Result<bool, StoreError> {
    let txn = roundhouse_store::begin_immediate(conn)?;
    let rows = txn.execute(
        "UPDATE trigger_delivery SET state = 'delivered', updated_at = ?1
         WHERE delivery_id = ?2 AND state = 'running'",
        params![now.as_unix_nanos(), delivery_id],
    )?;
    txn.commit()?;
    Ok(rows > 0)
}

/// Fails a `running` or `reserved` delivery: -> `failed`, recording
/// `last_error` and incrementing `attempts`. Predecessor-constrained on
/// `state IN ('running', 'reserved')` — a `reserved` delivery can fail
/// before ever reaching `running` (e.g. the run never actually started).
pub fn fail_delivery(
    conn: &mut Connection,
    delivery_id: &str,
    error: &str,
    now: Timestamp,
) -> Result<bool, StoreError> {
    let txn = roundhouse_store::begin_immediate(conn)?;
    let rows = txn.execute(
        "UPDATE trigger_delivery
         SET state = 'failed', last_error = ?1, attempts = attempts + 1, updated_at = ?2
         WHERE delivery_id = ?3 AND state IN ('running', 'reserved')",
        params![error, now.as_unix_nanos(), delivery_id],
    )?;
    txn.commit()?;
    Ok(rows > 0)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::CancellationOutcome;
    use crate::trigger::{OverlapPolicy, StoredBinding};
    use roundhouse_core::{JobId, WorkspaceId};
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    /// A minimal in-memory `RunRegistry`, deliberately separate from
    /// `admission.rs`'s own private `FakeRegistry` (that one is not `pub`,
    /// and this module wants its own, test-controllable
    /// `cancel_active`/failure behavior per test).
    #[derive(Default)]
    struct FakeRegistry {
        active: StdMutex<HashMap<BindingId, u32>>,
        queued: StdMutex<HashMap<BindingId, u32>>,
        cancel_outcome: StdMutex<Option<CancellationOutcome>>,
    }

    impl FakeRegistry {
        fn with_cancel_outcome(outcome: CancellationOutcome) -> Self {
            FakeRegistry {
                cancel_outcome: StdMutex::new(Some(outcome)),
                ..Default::default()
            }
        }
    }

    impl RunRegistry for FakeRegistry {
        fn active_run_count(&self, binding_id: BindingId) -> Result<u32, RegistryError> {
            Ok(*self.active.lock().unwrap().get(&binding_id).unwrap_or(&0))
        }
        fn queued_count(&self, binding_id: BindingId) -> Result<u32, RegistryError> {
            Ok(*self.queued.lock().unwrap().get(&binding_id).unwrap_or(&0))
        }
        fn cancel_active(
            &self,
            binding_id: BindingId,
        ) -> Result<CancellationOutcome, RegistryError> {
            let outcome = self
                .cancel_outcome
                .lock()
                .unwrap()
                .unwrap_or(CancellationOutcome::Confirmed);
            if outcome == CancellationOutcome::Confirmed {
                self.active.lock().unwrap().insert(binding_id, 0);
            }
            Ok(outcome)
        }
        fn note_admitted(&self, binding_id: BindingId) -> Result<(), RegistryError> {
            let mut active = self.active.lock().unwrap();
            let slot = active.entry(binding_id).or_insert(0);
            *slot = slot
                .checked_add(1)
                .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
            Ok(())
        }
        fn note_queued(&self, binding_id: BindingId) -> Result<(), RegistryError> {
            let mut queued = self.queued.lock().unwrap();
            let slot = queued.entry(binding_id).or_insert(0);
            *slot = slot
                .checked_add(1)
                .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
            Ok(())
        }
        fn note_finished(&self, binding_id: BindingId) -> Result<(), RegistryError> {
            let mut active = self.active.lock().unwrap();
            let slot = active.entry(binding_id).or_insert(0);
            *slot = slot
                .checked_sub(1)
                .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
            Ok(())
        }
        fn note_dequeued(&self, binding_id: BindingId) -> Result<(), RegistryError> {
            let mut queued = self.queued.lock().unwrap();
            let slot = queued.entry(binding_id).or_insert(0);
            *slot = slot
                .checked_sub(1)
                .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
            Ok(())
        }
        fn note_promoted(&self, binding_id: BindingId) -> Result<(), RegistryError> {
            {
                let mut queued = self.queued.lock().unwrap();
                let slot = queued.entry(binding_id).or_insert(0);
                *slot = slot
                    .checked_sub(1)
                    .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
            }
            {
                let mut active = self.active.lock().unwrap();
                let slot = active.entry(binding_id).or_insert(0);
                *slot = slot
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
            }
            Ok(())
        }
    }

    fn test_binding(overlap: OverlapPolicy) -> StoredBinding {
        let mut binding =
            Binding::new_cron(JobId::new(), "0 0 * * * *".to_string(), chrono_tz::Tz::UTC);
        binding.overlap = overlap;
        StoredBinding {
            workspace: WorkspaceId::new(),
            binding,
        }
    }

    fn occurrence_at(binding_id: BindingId, minute: i64) -> ScheduledOccurrence {
        ScheduledOccurrence {
            binding_id,
            scheduled_for: DateTime::from_timestamp(minute * 60, 0).unwrap(),
            is_catch_up: false,
        }
    }

    fn ts(secs: i64) -> Timestamp {
        Timestamp::from_unix_nanos(secs * 1_000_000_000)
    }

    fn fired_at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    #[test]
    fn identity_mismatch_is_rejected_before_any_write() {
        let mut conn = open_test_db();
        let binding = test_binding(OverlapPolicy::Skip);
        let mismatched_occurrence = occurrence_at(BindingId::new(), 1);
        let registry = FakeRegistry::default();

        let err = accept_occurrence(
            &mut conn,
            &binding,
            &mismatched_occurrence,
            fired_at(60),
            &registry,
        )
        .unwrap_err();
        assert!(matches!(err, StoreError::BindingIdentityMismatch { .. }));

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM trigger_event", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "a mismatched call must not write anything");
    }

    #[test]
    fn admit_creates_a_ready_delivery_and_admitted_outcome() {
        let mut conn = open_test_db();
        let binding = test_binding(OverlapPolicy::Skip);
        let occurrence = occurrence_at(binding.binding.id, 1);
        let registry = FakeRegistry::default();

        let acceptance =
            accept_occurrence(&mut conn, &binding, &occurrence, fired_at(60), &registry).unwrap();

        match acceptance {
            Acceptance::New {
                decision,
                outcome,
                delivery,
                ..
            } => {
                assert_eq!(decision, AdmissionDecision::Admit);
                assert_eq!(outcome, TriggerEventOutcome::Admitted);
                let delivery = delivery.expect("Admit must create a delivery");
                assert_eq!(delivery.state, DeliveryState::Ready);
                assert_eq!(delivery.attempts, 0);
                assert!(delivery.lease_expires_at.is_none());
            }
            Acceptance::Duplicate { .. } => panic!("expected a new acceptance"),
        }
    }

    #[test]
    fn skip_due_to_overlap_creates_no_delivery() {
        let mut conn = open_test_db();
        let binding = test_binding(OverlapPolicy::Skip);
        let registry = FakeRegistry::default();

        let first = occurrence_at(binding.binding.id, 1);
        accept_occurrence(&mut conn, &binding, &first, fired_at(60), &registry).unwrap();

        let second = occurrence_at(binding.binding.id, 2);
        let acceptance =
            accept_occurrence(&mut conn, &binding, &second, fired_at(120), &registry).unwrap();

        match acceptance {
            Acceptance::New {
                decision,
                outcome,
                delivery,
                ..
            } => {
                assert_eq!(decision, AdmissionDecision::SkipDueToOverlap);
                assert_eq!(outcome, TriggerEventOutcome::SkippedDueToOverlap);
                assert!(delivery.is_none());
            }
            Acceptance::Duplicate { .. } => panic!("expected a new acceptance"),
        }
    }

    #[test]
    fn queue_at_creates_a_ready_delivery_and_queued_outcome() {
        let mut conn = open_test_db();
        let binding = test_binding(OverlapPolicy::Queue { depth: 4 });
        let registry = FakeRegistry::default();

        let first = occurrence_at(binding.binding.id, 1);
        accept_occurrence(&mut conn, &binding, &first, fired_at(60), &registry).unwrap();

        let second = occurrence_at(binding.binding.id, 2);
        let acceptance =
            accept_occurrence(&mut conn, &binding, &second, fired_at(120), &registry).unwrap();

        match acceptance {
            Acceptance::New {
                decision,
                outcome,
                delivery,
                ..
            } => {
                assert_eq!(decision, AdmissionDecision::QueueAt(0));
                assert_eq!(outcome, TriggerEventOutcome::Queued);
                let delivery = delivery.expect("QueueAt must create a delivery");
                assert_eq!(delivery.state, DeliveryState::Ready);
            }
            Acceptance::Duplicate { .. } => panic!("expected a new acceptance"),
        }
    }

    #[test]
    fn queue_full_creates_no_delivery() {
        let mut conn = open_test_db();
        let binding = test_binding(OverlapPolicy::Queue { depth: 1 });
        let registry = FakeRegistry::default();

        accept_occurrence(
            &mut conn,
            &binding,
            &occurrence_at(binding.binding.id, 1),
            fired_at(60),
            &registry,
        )
        .unwrap(); // Admit
        accept_occurrence(
            &mut conn,
            &binding,
            &occurrence_at(binding.binding.id, 2),
            fired_at(120),
            &registry,
        )
        .unwrap(); // QueueAt(0), fills depth 1

        let acceptance = accept_occurrence(
            &mut conn,
            &binding,
            &occurrence_at(binding.binding.id, 3),
            fired_at(180),
            &registry,
        )
        .unwrap();

        match acceptance {
            Acceptance::New {
                decision,
                outcome,
                delivery,
                ..
            } => {
                assert_eq!(decision, AdmissionDecision::SkippedQueueFull { depth: 1 });
                assert_eq!(outcome, TriggerEventOutcome::SkippedQueueFull);
                assert!(delivery.is_none());
            }
            Acceptance::Duplicate { .. } => panic!("expected a new acceptance"),
        }
    }

    #[test]
    fn cancel_previous_and_admit_creates_a_new_delivery_and_requests_cancellation_on_the_old_one() {
        let mut conn = open_test_db();
        let binding = test_binding(OverlapPolicy::CancelPrevious);
        let registry = FakeRegistry::with_cancel_outcome(CancellationOutcome::Confirmed);

        let first_acceptance = accept_occurrence(
            &mut conn,
            &binding,
            &occurrence_at(binding.binding.id, 1),
            fired_at(60),
            &registry,
        )
        .unwrap();
        let first_delivery = match first_acceptance {
            Acceptance::New {
                delivery: Some(d), ..
            } => d,
            other => panic!("expected a new delivery, got {other:?}"),
        };

        let second_acceptance = accept_occurrence(
            &mut conn,
            &binding,
            &occurrence_at(binding.binding.id, 2),
            fired_at(120),
            &registry,
        )
        .unwrap();

        match second_acceptance {
            Acceptance::New {
                decision,
                outcome,
                delivery,
                ..
            } => {
                assert_eq!(decision, AdmissionDecision::CancelledPreviousAndAdmit);
                assert_eq!(outcome, TriggerEventOutcome::CancelledPreviousAndAdmitted);
                let new_delivery = delivery.expect("must create a new delivery");
                assert_ne!(new_delivery.delivery_id, first_delivery.delivery_id);
                assert_eq!(new_delivery.state, DeliveryState::Ready);
            }
            Acceptance::Duplicate { .. } => panic!("expected a new acceptance"),
        }

        // Task 3 constraint: the OLD delivery is now `cancellation_requested`
        // — never marked terminal (`cancelled`/`failed`) from this crate.
        let old_delivery = fetch_delivery(&conn, &first_delivery.delivery_id)
            .unwrap()
            .unwrap();
        assert_eq!(old_delivery.state, DeliveryState::CancellationRequested);
    }

    #[test]
    fn cancellation_unconfirmed_creates_no_delivery_and_does_not_touch_the_previous_one() {
        let mut conn = open_test_db();
        let binding = test_binding(OverlapPolicy::CancelPrevious);
        let registry = FakeRegistry::with_cancel_outcome(CancellationOutcome::Confirmed);

        let first_acceptance = accept_occurrence(
            &mut conn,
            &binding,
            &occurrence_at(binding.binding.id, 1),
            fired_at(60),
            &registry,
        )
        .unwrap();
        let first_delivery = match first_acceptance {
            Acceptance::New {
                delivery: Some(d), ..
            } => d,
            other => panic!("expected a new delivery, got {other:?}"),
        };

        // From here on, cancellation can no longer be confirmed.
        *registry.cancel_outcome.lock().unwrap() = Some(CancellationOutcome::Unconfirmed);

        let second_acceptance = accept_occurrence(
            &mut conn,
            &binding,
            &occurrence_at(binding.binding.id, 2),
            fired_at(120),
            &registry,
        )
        .unwrap();

        match second_acceptance {
            Acceptance::New {
                decision,
                outcome,
                delivery,
                ..
            } => {
                assert_eq!(decision, AdmissionDecision::SkippedCancellationUnconfirmed);
                assert_eq!(outcome, TriggerEventOutcome::SkippedCancellationUnconfirmed);
                assert!(delivery.is_none());
            }
            Acceptance::Duplicate { .. } => panic!("expected a new acceptance"),
        }

        // The original delivery is untouched — still `ready`, not requested
        // for cancellation, since nothing was actually confirmed cancelled.
        let old_delivery = fetch_delivery(&conn, &first_delivery.delivery_id)
            .unwrap()
            .unwrap();
        assert_eq!(old_delivery.state, DeliveryState::Ready);
    }

    #[test]
    fn duplicate_acceptance_does_not_reevaluate_admission_or_create_a_second_delivery() {
        let mut conn = open_test_db();
        let binding = test_binding(OverlapPolicy::Skip);
        let registry = FakeRegistry::default();
        let occurrence = occurrence_at(binding.binding.id, 1);

        let first =
            accept_occurrence(&mut conn, &binding, &occurrence, fired_at(60), &registry).unwrap();
        let (first_id, first_outcome, first_delivery) = match first {
            Acceptance::New {
                trigger_event_id,
                outcome,
                delivery,
                ..
            } => (trigger_event_id, outcome, delivery),
            Acceptance::Duplicate { .. } => panic!("expected a new acceptance the first time"),
        };
        assert_eq!(registry.active_run_count(binding.binding.id).unwrap(), 1);

        // Re-fire the exact same occurrence (same binding_id + scheduled_for,
        // hence same idempotency key), simulating a crash-and-retry.
        let second =
            accept_occurrence(&mut conn, &binding, &occurrence, fired_at(999), &registry).unwrap();

        match second {
            Acceptance::Duplicate {
                trigger_event_id,
                outcome,
                delivery,
            } => {
                assert_eq!(trigger_event_id, first_id);
                assert_eq!(outcome, Some(first_outcome));
                assert_eq!(delivery, first_delivery);
            }
            Acceptance::New { .. } => panic!("a repeat of the same occurrence must be a duplicate"),
        }

        // If `decide_admission` had been re-run, a `Skip` policy would have
        // called `note_admitted` a second time, bumping this to 2 (or, for a
        // policy that reads `active_run_count > 0`, produced a *different*
        // decision on the "duplicate" than the original — either way,
        // observable here as a registry mutation that must not have
        // happened).
        assert_eq!(registry.active_run_count(binding.binding.id).unwrap(), 1);

        let event_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM trigger_event", [], |r| r.get(0))
            .unwrap();
        assert_eq!(event_count, 1, "no second trigger_event row");
        let delivery_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM trigger_delivery", [], |r| r.get(0))
            .unwrap();
        assert_eq!(delivery_count, 1, "no second trigger_delivery row");
    }

    #[test]
    fn cursor_advances_forward_but_never_regresses() {
        let mut conn = open_test_db();
        let binding = test_binding(OverlapPolicy::Concurrent { max: 10 });
        let registry = FakeRegistry::default();

        accept_occurrence(
            &mut conn,
            &binding,
            &occurrence_at(binding.binding.id, 10),
            fired_at(600),
            &registry,
        )
        .unwrap();
        let cursor_after_first: Option<i64> = conn
            .query_row(
                "SELECT last_fired_for FROM trigger_binding_cursor WHERE binding_id = ?1",
                params![binding.binding.id.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        let expected_first =
            timestamp_from_datetime(occurrence_at(binding.binding.id, 10).scheduled_for)
                .as_unix_nanos();
        assert_eq!(cursor_after_first, Some(expected_first));

        // A genuinely new, but *earlier*, occurrence (distinct idempotency
        // key, so it is not a duplicate) must not move the cursor backward.
        accept_occurrence(
            &mut conn,
            &binding,
            &occurrence_at(binding.binding.id, 5),
            fired_at(300),
            &registry,
        )
        .unwrap();
        let cursor_after_second: Option<i64> = conn
            .query_row(
                "SELECT last_fired_for FROM trigger_binding_cursor WHERE binding_id = ?1",
                params![binding.binding.id.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            cursor_after_second,
            Some(expected_first),
            "cursor must not regress to the earlier occurrence"
        );

        // A later occurrence still moves it forward.
        accept_occurrence(
            &mut conn,
            &binding,
            &occurrence_at(binding.binding.id, 20),
            fired_at(1200),
            &registry,
        )
        .unwrap();
        let cursor_after_third: Option<i64> = conn
            .query_row(
                "SELECT last_fired_for FROM trigger_binding_cursor WHERE binding_id = ?1",
                params![binding.binding.id.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        let expected_third =
            timestamp_from_datetime(occurrence_at(binding.binding.id, 20).scheduled_for)
                .as_unix_nanos();
        assert_eq!(cursor_after_third, Some(expected_third));
    }

    fn create_ready_delivery(conn: &mut Connection, binding_id: BindingId) -> TriggerDelivery {
        let binding = StoredBinding {
            workspace: WorkspaceId::new(),
            binding: {
                let mut b =
                    Binding::new_cron(JobId::new(), "0 0 * * * *".to_string(), chrono_tz::Tz::UTC);
                b.id = binding_id;
                b.overlap = OverlapPolicy::Skip;
                b
            },
        };
        let registry = FakeRegistry::default();
        let occurrence = occurrence_at(binding_id, 1);
        let acceptance =
            accept_occurrence(conn, &binding, &occurrence, fired_at(60), &registry).unwrap();
        match acceptance {
            Acceptance::New {
                delivery: Some(d), ..
            } => d,
            other => panic!("expected a new ready delivery, got {other:?}"),
        }
    }

    #[test]
    fn lease_transitions_ready_to_leased_and_is_a_no_op_on_an_already_leased_delivery() {
        let mut conn = open_test_db();
        let delivery = create_ready_delivery(&mut conn, BindingId::new());

        let applied =
            lease_delivery(&mut conn, &delivery.delivery_id, ts(1_100), ts(1_000)).unwrap();
        assert!(applied);
        let leased = fetch_delivery(&conn, &delivery.delivery_id)
            .unwrap()
            .unwrap();
        assert_eq!(leased.state, DeliveryState::Leased);
        assert_eq!(leased.lease_expires_at, Some(ts(1_100)));

        // Predecessor mismatch: already `leased`, not `ready`.
        let second_applied =
            lease_delivery(&mut conn, &delivery.delivery_id, ts(2_000), ts(1_500)).unwrap();
        assert!(
            !second_applied,
            "leasing an already-leased delivery must be a no-op"
        );
        let still_leased = fetch_delivery(&conn, &delivery.delivery_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            still_leased.lease_expires_at,
            Some(ts(1_100)),
            "the no-op must not clobber the original lease"
        );
    }

    #[test]
    fn reclaim_expired_lease_only_fires_once_now_is_past_expiry() {
        let mut conn = open_test_db();
        let delivery = create_ready_delivery(&mut conn, BindingId::new());
        lease_delivery(&mut conn, &delivery.delivery_id, ts(1_100), ts(1_000)).unwrap();

        // Not yet expired: no-op, driven entirely by an explicit `now`, never
        // a real clock/sleep.
        let too_early = reclaim_expired_lease(&mut conn, &delivery.delivery_id, ts(1_050)).unwrap();
        assert!(!too_early);
        let still_leased = fetch_delivery(&conn, &delivery.delivery_id)
            .unwrap()
            .unwrap();
        assert_eq!(still_leased.state, DeliveryState::Leased);

        // Exactly at expiry: reclaimed.
        let reclaimed = reclaim_expired_lease(&mut conn, &delivery.delivery_id, ts(1_100)).unwrap();
        assert!(reclaimed);
        let ready_again = fetch_delivery(&conn, &delivery.delivery_id)
            .unwrap()
            .unwrap();
        assert_eq!(ready_again.state, DeliveryState::Ready);
        assert!(ready_again.lease_expires_at.is_none());
    }

    #[test]
    fn reserve_mark_running_complete_happy_path() {
        let mut conn = open_test_db();
        let delivery = create_ready_delivery(&mut conn, BindingId::new());
        lease_delivery(&mut conn, &delivery.delivery_id, ts(1_100), ts(1_000)).unwrap();

        let session_id = SessionId::new();
        let reserved = reserve_delivery(
            &mut conn,
            &delivery.delivery_id,
            "run-1",
            session_id,
            ts(1_010),
        )
        .unwrap();
        assert!(reserved);
        let after_reserve = fetch_delivery(&conn, &delivery.delivery_id)
            .unwrap()
            .unwrap();
        assert_eq!(after_reserve.state, DeliveryState::Reserved);
        assert_eq!(after_reserve.run_id.as_deref(), Some("run-1"));
        assert_eq!(after_reserve.session_id, Some(session_id));

        // Predecessor mismatch: already `reserved`, not `leased`.
        let reserve_again = reserve_delivery(
            &mut conn,
            &delivery.delivery_id,
            "run-2",
            SessionId::new(),
            ts(1_020),
        )
        .unwrap();
        assert!(!reserve_again);

        let running = mark_delivery_running(&mut conn, &delivery.delivery_id, ts(1_030)).unwrap();
        assert!(running);
        assert_eq!(
            fetch_delivery(&conn, &delivery.delivery_id)
                .unwrap()
                .unwrap()
                .state,
            DeliveryState::Running
        );

        // Predecessor mismatch: `complete_delivery` from `reserved` (already
        // moved past it) must be a no-op, not applied twice.
        let complete_from_wrong_state =
            complete_delivery(&mut conn, &delivery.delivery_id, ts(1_040)).unwrap();
        assert!(
            complete_from_wrong_state,
            "delivery is `running`, so this must apply"
        );

        let delivered = fetch_delivery(&conn, &delivery.delivery_id)
            .unwrap()
            .unwrap();
        assert_eq!(delivered.state, DeliveryState::Delivered);

        // A second `complete_delivery` call is now a no-op (already terminal).
        let complete_again =
            complete_delivery(&mut conn, &delivery.delivery_id, ts(1_050)).unwrap();
        assert!(!complete_again);
    }

    #[test]
    fn fail_delivery_from_running_or_reserved_sets_error_and_increments_attempts() {
        let mut conn = open_test_db();

        // Fail from `running`.
        let d1 = create_ready_delivery(&mut conn, BindingId::new());
        lease_delivery(&mut conn, &d1.delivery_id, ts(1_100), ts(1_000)).unwrap();
        reserve_delivery(
            &mut conn,
            &d1.delivery_id,
            "run-1",
            SessionId::new(),
            ts(1_010),
        )
        .unwrap();
        mark_delivery_running(&mut conn, &d1.delivery_id, ts(1_020)).unwrap();
        let failed = fail_delivery(&mut conn, &d1.delivery_id, "boom", ts(1_030)).unwrap();
        assert!(failed);
        let after = fetch_delivery(&conn, &d1.delivery_id).unwrap().unwrap();
        assert_eq!(after.state, DeliveryState::Failed);
        assert_eq!(after.last_error.as_deref(), Some("boom"));
        assert_eq!(after.attempts, 1);

        // A delivery already `ready` cannot fail directly (predecessor
        // mismatch) — a no-op, not an error.
        let d2 = create_ready_delivery(&mut conn, BindingId::new());
        let not_applied = fail_delivery(&mut conn, &d2.delivery_id, "boom", ts(1_000)).unwrap();
        assert!(!not_applied);
        assert_eq!(
            fetch_delivery(&conn, &d2.delivery_id)
                .unwrap()
                .unwrap()
                .state,
            DeliveryState::Ready
        );

        // Fail from `reserved` (never reached `running`).
        let d3 = create_ready_delivery(&mut conn, BindingId::new());
        lease_delivery(&mut conn, &d3.delivery_id, ts(1_100), ts(1_000)).unwrap();
        reserve_delivery(
            &mut conn,
            &d3.delivery_id,
            "run-3",
            SessionId::new(),
            ts(1_010),
        )
        .unwrap();
        let failed_reserved =
            fail_delivery(&mut conn, &d3.delivery_id, "never started", ts(1_020)).unwrap();
        assert!(failed_reserved);
        let after3 = fetch_delivery(&conn, &d3.delivery_id).unwrap().unwrap();
        assert_eq!(after3.state, DeliveryState::Failed);
        assert_eq!(after3.attempts, 1);
    }

    #[test]
    fn request_cancellation_lost_race_is_a_no_op_not_an_error() {
        let mut conn = open_test_db();
        let delivery = create_ready_delivery(&mut conn, BindingId::new());

        // The delivery is `ready`, but we (wrongly) expect `leased` — a
        // lost-race style predecessor mismatch.
        let applied = request_cancellation(
            &mut conn,
            &delivery.delivery_id,
            DeliveryState::Leased,
            ts(10),
        )
        .unwrap();
        assert!(!applied);
        let unchanged = fetch_delivery(&conn, &delivery.delivery_id)
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.state, DeliveryState::Ready);

        // Matching the real predecessor succeeds.
        let applied2 = request_cancellation(
            &mut conn,
            &delivery.delivery_id,
            DeliveryState::Ready,
            ts(20),
        )
        .unwrap();
        assert!(applied2);
        let cancelled = fetch_delivery(&conn, &delivery.delivery_id)
            .unwrap()
            .unwrap();
        assert_eq!(cancelled.state, DeliveryState::CancellationRequested);
    }
}
