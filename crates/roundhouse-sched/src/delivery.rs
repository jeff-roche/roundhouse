//! The delivery outbox's Rust-side types (Phase 8, Task 2 of the
//! trigger-delivery rebuild).
//!
//! `trigger_delivery` (store migration
//! `MIGRATION_0013_TRIGGER_BINDINGS_AND_DELIVERIES`, in
//! `roundhouse-store/src/migrations.rs` per Ruling P4 — a per-crate
//! migrations file would never reach the daemon's actual database) is the
//! durable outbox row behind one admitted (or queued, or otherwise decided)
//! occurrence. This module only defines the shape of that row and its state
//! vocabulary; the read/write functions that actually populate
//! `trigger_delivery` (`accept_occurrence` and friends) are Task 3's, not
//! this one's.
use roundhouse_core::{BindingId, SessionId, Timestamp};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from this module's fallible discriminant decoding
/// ([`DeliveryState::from_sql_str`]). Same shape as
/// `roundhouse_flow::durability::DurabilityError::UnrecognizedDiscriminant`
/// and `crate::trigger::TriggerError::UnrecognizedDiscriminant`: the `CHECK`
/// constraint on `trigger_delivery.state` is the insert-time enforcement
/// leg, this is the read-back leg, and a hand-edited or corrupted row must
/// be refused rather than silently mapped onto a plausible variant.
#[derive(Debug, Error)]
pub enum DeliveryError {
    #[error("column {column} holds {value:?}, which is not a recognised discriminant")]
    UnrecognizedDiscriminant { column: &'static str, value: String },
}

/// One `trigger_delivery` row's lifecycle state. All nine variants exist now
/// — even though Task 3 does not write every one of them yet — because
/// SQLite has no `ALTER TABLE ... DROP/MODIFY CONSTRAINT`: a `CHECK` that
/// omitted a state a later task needs would force that task to rebuild this
/// table via the 12-step create-copy-drop-rename dance instead of writing a
/// new value into an already-declared vocabulary. See migration 0013's own
/// doc comment (`roundhouse-store/src/migrations.rs`) for the full
/// reasoning, which mirrors migration 0007's `workflow_step_run.state`
/// `'skipped'` precedent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryState {
    /// Admitted and waiting to be claimed by a delivery worker.
    Ready,
    /// Claimed by a worker; `lease_expires_at` bounds how long the claim is
    /// honored before another worker may reclaim it.
    Leased,
    /// The claim was converted into a reservation the run/session layer is
    /// about to act on.
    Reserved,
    /// A run/session exists for this delivery and is actively executing.
    Running,
    /// The run completed and the delivery is done.
    Delivered,
    /// The run failed.
    Failed,
    /// A cancellation has been requested but not yet confirmed.
    CancellationRequested,
    /// The delivery's run was cancelled and confirmed stopped.
    Cancelled,
    /// The occurrence was decided not to be delivered at all (e.g. an
    /// overlap-policy skip) without ever starting a run.
    Skipped,
}

impl DeliveryState {
    /// The column name this discriminant is stored under, for
    /// [`DeliveryError::UnrecognizedDiscriminant`]'s `column` field.
    const COLUMN: &'static str = "trigger_delivery.state";

    pub fn as_sql_str(self) -> &'static str {
        match self {
            DeliveryState::Ready => "ready",
            DeliveryState::Leased => "leased",
            DeliveryState::Reserved => "reserved",
            DeliveryState::Running => "running",
            DeliveryState::Delivered => "delivered",
            DeliveryState::Failed => "failed",
            DeliveryState::CancellationRequested => "cancellation_requested",
            DeliveryState::Cancelled => "cancelled",
            DeliveryState::Skipped => "skipped",
        }
    }

    /// The read-back leg of migration 0013's `CHECK` constraint. Deliberately
    /// **not** a lossy `_ => ...` catch-all — see [`DeliveryError`]'s doc
    /// comment.
    pub fn from_sql_str(s: &str) -> Result<Self, DeliveryError> {
        match s {
            "ready" => Ok(DeliveryState::Ready),
            "leased" => Ok(DeliveryState::Leased),
            "reserved" => Ok(DeliveryState::Reserved),
            "running" => Ok(DeliveryState::Running),
            "delivered" => Ok(DeliveryState::Delivered),
            "failed" => Ok(DeliveryState::Failed),
            "cancellation_requested" => Ok(DeliveryState::CancellationRequested),
            "cancelled" => Ok(DeliveryState::Cancelled),
            "skipped" => Ok(DeliveryState::Skipped),
            other => Err(DeliveryError::UnrecognizedDiscriminant {
                column: Self::COLUMN,
                value: other.to_string(),
            }),
        }
    }
}

/// One row of the `trigger_delivery` outbox table.
///
/// No read/write DB functions live here yet — Task 3's `store.rs` owns
/// `accept_occurrence` and the rest of the claim/lease/complete machinery.
/// This struct only mirrors the table's shape so that type is available to
/// write against.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TriggerDelivery {
    /// A UUID string minted by the writer (`Uuid::new_v4().to_string()`,
    /// Task 3) — deliberately a raw `String`, not a new id newtype, per this
    /// task's own scope.
    pub delivery_id: String,
    /// The `trigger_event.id` rowid (`INTEGER PRIMARY KEY AUTOINCREMENT`,
    /// store migration 0006) this delivery was created for.
    pub trigger_event_id: i64,
    pub binding_id: BindingId,
    pub state: DeliveryState,
    pub attempts: u32,
    /// Unix nanos; `None` until a worker leases this delivery.
    pub lease_expires_at: Option<Timestamp>,
    /// Kept as a raw string, not `roundhouse_flow::RunId` — `roundhouse-sched`
    /// must stay independent of `roundhouse-flow` (see this crate's
    /// dependency table in `docs/architecture/02-system-architecture.md`
    /// §5.2). The daemon converts with `RunId::from_uuid` when it needs the
    /// typed form.
    pub run_id: Option<String>,
    /// `roundhouse-sched` already depends on `roundhouse-core`, so this one
    /// can be the real typed id.
    pub session_id: Option<SessionId>,
    pub last_error: Option<String>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_STATES: [DeliveryState; 9] = [
        DeliveryState::Ready,
        DeliveryState::Leased,
        DeliveryState::Reserved,
        DeliveryState::Running,
        DeliveryState::Delivered,
        DeliveryState::Failed,
        DeliveryState::CancellationRequested,
        DeliveryState::Cancelled,
        DeliveryState::Skipped,
    ];

    /// Every `DeliveryState` variant round-trips through its SQL spelling —
    /// exercising both `as_sql_str` and `from_sql_str` together, and pinning
    /// that the Rust-side vocabulary matches migration 0013's `CHECK` list
    /// exactly (the `CHECK` itself is separately tested against a real
    /// SQLite connection in `roundhouse-store`'s `tests/migration_0013.rs`).
    #[test]
    fn every_delivery_state_round_trips_through_its_sql_spelling() {
        for state in ALL_STATES {
            let sql = state.as_sql_str();
            let decoded = DeliveryState::from_sql_str(sql)
                .unwrap_or_else(|e| panic!("{sql:?} must decode back: {e}"));
            assert_eq!(decoded, state, "round-trip must be lossless for {sql:?}");
        }
    }

    /// An unrecognized column value must be reported through
    /// [`DeliveryError::UnrecognizedDiscriminant`], never panic and never
    /// silently coerce onto some default variant.
    #[test]
    fn an_unrecognized_state_string_is_reported_not_defaulted() {
        let err = DeliveryState::from_sql_str("bogus").unwrap_err();
        match err {
            DeliveryError::UnrecognizedDiscriminant { column, value } => {
                assert_eq!(column, "trigger_delivery.state");
                assert_eq!(value, "bogus");
            }
        }
    }

    /// Every SQL spelling is unique — a duplicate would mean two variants
    /// are indistinguishable on read-back.
    #[test]
    fn every_sql_spelling_is_distinct() {
        let mut spellings: Vec<&'static str> = ALL_STATES.iter().map(|s| s.as_sql_str()).collect();
        let before = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), before, "expected all spellings distinct");
    }
}
