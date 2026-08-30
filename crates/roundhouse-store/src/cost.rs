//! Cost attribution as a derived view over `(usage, pricing_snapshot_id)` — never a
//! stored column (§9.7). A task's/session's dollar cost is always computed on demand
//! from the recorded token `Usage` (folded from the event log) plus a caller-supplied
//! `PricingSnapshot`, never persisted anywhere. This is what makes a historical task
//! retroactively "backfillable" the moment real pricing data lands: `task_cost_view`
//! run twice, once against an old `PricingSnapshot` and once against a newer one
//! supplied after the fact, recomputes over the exact same immutable event without
//! ever touching the event log.
//!
//! **Deliberate, tracked deviation from the frozen crate dependency table:** this
//! module needs `Cost`/`PricingLookup` (`roundhouse_provider::fallback`) and `ModelId`/
//! `ProviderId` (`roundhouse_provider::ir`), so `roundhouse-store` now depends on
//! `roundhouse-provider` — see the comment on that dependency edge in this crate's
//! `Cargo.toml` for the full ruling. `roundhouse-provider` depends only on
//! `roundhouse-core`, so this introduces no dependency cycle.

use std::collections::HashMap;

use roundhouse_core::{EventPayload, SessionId, TaskId, TaskOutput, Timestamp, Usage};
use roundhouse_provider::fallback::{Cost, PricingLookup};
use roundhouse_provider::{ModelId, ProviderId};

use crate::replay::StoredEvent;
use crate::{pool::StorePool, StoreError};

/// One raw `events` row, scoped to a single task: `(seq, ts_nanos, session_id, payload_json,
/// schema_v)`.
type TaskEventRow = (i64, i64, String, String, u16);

/// Every event recorded for `task_id`, ordered by `seq` ascending — the task-scoped
/// counterpart to `session_events` (`session_events.rs`), built following the identical
/// `conn.interact` + raw-SQL pattern, filtered by `task_id` instead of `session_id`.
pub async fn task_events(
    store: &StorePool,
    task_id: TaskId,
) -> Result<Vec<StoredEvent>, StoreError> {
    let conn = store.pool.get().await?;
    let task_id_str = task_id.to_string();

    let rows_result = conn
        .interact(move |c| -> Result<Vec<TaskEventRow>, rusqlite::Error> {
            let mut stmt = c.prepare(
                "SELECT seq, ts, session_id, payload, schema_v FROM events \
                 WHERE task_id = ?1 ORDER BY seq ASC",
            )?;
            let rows = stmt
                .query_map([&task_id_str], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, u16>(4)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
        .map_err(|e| StoreError::Interact(e.to_string()))?;

    let rows = rows_result.map_err(StoreError::Sqlite)?;

    let mut events = Vec::with_capacity(rows.len());
    for (seq, ts_nanos, session_id_str, payload_json, schema_v) in rows {
        let session_id = uuid::Uuid::parse_str(&session_id_str)
            .map(roundhouse_core::SessionId::from_uuid)
            .map_err(|e| {
                StoreError::Interact(format!("corrupt session_id in events table: {e}"))
            })?;
        let payload = serde_json::from_str(&payload_json).map_err(|e| {
            StoreError::Interact(format!("corrupt payload for task {task_id}: {e}"))
        })?;

        events.push(StoredEvent {
            session_id,
            seq: seq as u64,
            ts: Timestamp::from_unix_nanos(ts_nanos),
            task_id: Some(task_id),
            payload,
            schema_v,
        });
    }

    Ok(events)
}

/// Every `TaskId` currently in state `Completed` for `session_id`, read from the
/// materialized `tasks` cache table (not replayed from the event log) — modeled on
/// `suspended_tasks` (`suspended.rs`), which queries the same table by `state` for the
/// analogous `Suspended` case.
pub async fn completed_task_ids_for_session(
    store: &StorePool,
    session_id: SessionId,
) -> Result<Vec<TaskId>, StoreError> {
    let conn = store.pool.get().await?;
    let session_id_str = session_id.to_string();

    let rows_result = conn
        .interact(move |c| -> Result<Vec<String>, rusqlite::Error> {
            let mut stmt = c.prepare(
                "SELECT task_id FROM tasks WHERE session_id = ?1 AND state = 'Completed'",
            )?;
            let rows = stmt
                .query_map([&session_id_str], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
        .map_err(|e| StoreError::Interact(e.to_string()))?;

    let rows = rows_result.map_err(StoreError::Sqlite)?;

    rows.into_iter()
        .map(|task_id_str| {
            uuid::Uuid::parse_str(&task_id_str)
                .map(TaskId::from_uuid)
                .map_err(|e| StoreError::Interact(format!("corrupt task_id in tasks table: {e}")))
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PricingSnapshotId(pub u32);

pub struct PriceEntry {
    pub input_pico_usd_per_token: u64,
    pub output_pico_usd_per_token: u64,
    pub cache_write_pico_usd_per_token: Option<u64>,
}

/// A caller-supplied pricing table, keyed by `(ProviderId, ModelId)` — deliberately
/// supplied fresh at query time rather than ever stored alongside `Usage` (§9.7; see
/// `roundhouse_core::task_meta::Usage`'s doc comment for the same rationale applied to
/// why `Usage` itself carries no `pricing_snapshot_id` field).
pub struct PricingSnapshot {
    pub id: PricingSnapshotId,
    pub table: HashMap<(ProviderId, ModelId), PriceEntry>,
}

impl PricingLookup for PricingSnapshot {
    fn cost_for(&self, usage: &Usage, provider: &ProviderId, model: &ModelId) -> Cost {
        match self.table.get(&(provider.clone(), model.clone())) {
            Some(entry) => {
                let pico = usage.input_tokens * entry.input_pico_usd_per_token
                    + usage.output_tokens * entry.output_pico_usd_per_token;
                Cost::Known(pico)
            }
            // Unknown pricing yields Cost::Unknown; the recorded token counts are
            // returned unchanged by task_cost_view regardless (§9.7).
            None => Cost::Unknown,
        }
    }
}

/// Pulls `(provider, model)` out of a `TaskCompleted` event's `TaskOutput`. Real
/// production `TaskOutput`s for completed infer/chat attempts are constructed as
/// `TaskOutput::Json(json!({"provider": ..., "model": ...}))` (see
/// `roundhouse_provider::fallback`) — anything else (a non-`Json` output, or a `Json`
/// output missing either field) is a genuine domain-level error, not something to
/// unwrap or default around.
fn provider_and_model_from_output(
    task_id: TaskId,
    output: &TaskOutput,
) -> Result<(ProviderId, ModelId), StoreError> {
    let TaskOutput::Json(value) = output else {
        return Err(StoreError::NotFound(format!(
            "task {task_id}: TaskCompleted output is not TaskOutput::Json, cannot recover \
             provider/model for cost attribution"
        )));
    };
    let provider = value
        .get("provider")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            StoreError::NotFound(format!(
                "task {task_id}: TaskCompleted output JSON has no string \"provider\" field"
            ))
        })?;
    let model = value.get("model").and_then(|v| v.as_str()).ok_or_else(|| {
        StoreError::NotFound(format!(
            "task {task_id}: TaskCompleted output JSON has no string \"model\" field"
        ))
    })?;
    Ok((ProviderId(provider.to_string()), ModelId(model.to_string())))
}

/// Recomputes `task_id`'s cost from its recorded `Usage` plus `snapshot`. Never reads or
/// writes a stored cost column — see this module's doc comment for why. Returns
/// `StoreError::NotFound` if `task_id` has no `TaskCompleted` event.
pub async fn task_cost_view(
    store: &StorePool,
    task_id: TaskId,
    snapshot: &PricingSnapshot,
) -> Result<(Usage, Cost), StoreError> {
    let events = task_events(store, task_id).await?;
    let (usage, output) = events
        .iter()
        .rev()
        .find_map(|e| match &e.payload {
            EventPayload::TaskCompleted { output, usage } => Some((usage.clone(), output)),
            _ => None,
        })
        .ok_or_else(|| {
            StoreError::NotFound(format!("no TaskCompleted event found for task {task_id}"))
        })?;

    let (provider, model) = provider_and_model_from_output(task_id, output)?;
    let cost = snapshot.cost_for(&usage, &provider, &model);
    Ok((usage, cost))
}

/// A session-level cost rollup: the sum of every completed task's known cost, plus a
/// count of tasks whose cost could not be determined against `snapshot`. Computed fresh
/// on every call, never stored, so it cannot drift from what a current `PricingSnapshot`
/// would say (S-OBS-1).
pub struct RollupCost {
    pub known_pico_usd: u64,
    pub unknown_task_count: u32,
}

pub async fn session_cost_rollup(
    store: &StorePool,
    session_id: SessionId,
    snapshot: &PricingSnapshot,
) -> Result<RollupCost, StoreError> {
    let task_ids = completed_task_ids_for_session(store, session_id).await?;
    let mut known_pico_usd = 0u64;
    let mut unknown_task_count = 0u32;
    for task_id in task_ids {
        match task_cost_view(store, task_id, snapshot).await? {
            (_, Cost::Known(p)) => known_pico_usd += p,
            (_, Cost::Unknown) => unknown_task_count += 1,
        }
    }
    Ok(RollupCost {
        known_pico_usd,
        unknown_task_count,
    })
}
