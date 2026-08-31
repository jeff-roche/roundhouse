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

/// Identifies one `PricingSnapshot` — an opaque caller-assigned id, not interpreted by
/// this crate. Exists so a `PricingSnapshot` can be named/referenced (e.g. logged
/// alongside a computed `Cost`) without this crate needing to know anything about how
/// pricing snapshots are versioned or where they come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PricingSnapshotId(pub u32);

/// One model's per-token prices, in **pico-USD** (10^-12 USD) per token — not
/// cents/micro-USD — specifically so the cost arithmetic in `cost_for` below can stay
/// exact integer math (`u64` multiply/add) rather than floating point, which would
/// reintroduce the exact kind of silently-wrong-number risk this whole module exists to
/// avoid (§9.7).
///
/// `cache_read_pico_usd_per_token` prices `Usage::cache_read_tokens` (the only cache
/// token class `Usage` actually records — there is no corresponding
/// `cache_write_tokens` field to price). It is `Option` because not every caller-supplied
/// snapshot is guaranteed to carry a cache-read rate; `cost_for` treats a `None` rate
/// against a nonzero `cache_read_tokens` count as `Cost::Unknown` rather than silently
/// pricing those tokens at zero (see `cost_for`'s doc comment).
pub struct PriceEntry {
    pub input_pico_usd_per_token: u64,
    pub output_pico_usd_per_token: u64,
    pub cache_read_pico_usd_per_token: Option<u64>,
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
    /// Computes `Cost::Known` only when every priced component is actually known and the
    /// arithmetic provably didn't overflow — otherwise `Cost::Unknown`, never a silently
    /// wrong or truncated number (§9.7). Three ways this can fall back to `Unknown`,
    /// deliberately:
    /// 1. No `PriceEntry` at all for `(provider, model)`.
    /// 2. A `PriceEntry` exists but `usage.cache_read_tokens > 0` while
    ///    `cache_read_pico_usd_per_token` is `None` — pricing input/output but silently
    ///    treating unpriced cache-read tokens as free would understate the real cost,
    ///    the same failure class this module exists to prevent.
    /// 3. Any `checked_mul`/`checked_add` in the sum overflows `u64` — a fully caller-
    ///    supplied, unvalidated price table (e.g. a mis-scaled pico-vs-nano unit
    ///    confusion) combined with ordinary token counts could realistically reach this;
    ///    folding to `Unknown` beats panicking (debug builds) or silently wrapping to a
    ///    fabricated number (release builds, since this workspace doesn't enable
    ///    `overflow-checks` in its release profile).
    fn cost_for(&self, usage: &Usage, provider: &ProviderId, model: &ModelId) -> Cost {
        let Some(entry) = self.table.get(&(provider.clone(), model.clone())) else {
            return Cost::Unknown;
        };

        let Some(input_cost) = usage
            .input_tokens
            .checked_mul(entry.input_pico_usd_per_token)
        else {
            return Cost::Unknown;
        };
        let Some(output_cost) = usage
            .output_tokens
            .checked_mul(entry.output_pico_usd_per_token)
        else {
            return Cost::Unknown;
        };
        let cache_cost = if usage.cache_read_tokens == 0 {
            Some(0)
        } else {
            entry
                .cache_read_pico_usd_per_token
                .and_then(|rate| usage.cache_read_tokens.checked_mul(rate))
        };
        let Some(cache_cost) = cache_cost else {
            return Cost::Unknown;
        };

        match input_cost
            .checked_add(output_cost)
            .and_then(|sum| sum.checked_add(cache_cost))
        {
            Some(total) => Cost::Known(total),
            None => Cost::Unknown,
        }
    }
}

/// Pulls `(provider, model)` out of a `TaskCompleted` event's `TaskOutput`. Real
/// production `TaskOutput`s for completed infer attempts are constructed as
/// `TaskOutput::Json(json!({"provider": ..., "model": ...}))` (see
/// `roundhouse_provider::fallback`) — but this is an **implicit, untyped cross-crate
/// contract**, not something the compiler enforces: nothing pins this exact JSON shape
/// at the type level, so if `roundhouse-provider::fallback` ever renames or restructures
/// what it writes into that `TaskOutput::Json` value, cost attribution breaks (loudly,
/// via a real `StoreError::Unattributable` at query time — never silently — but with no
/// compile-time signal) unless this function is updated in lockstep. Anyone touching
/// `fallback.rs`'s completed-output shape should know this crate depends on it exactly.
///
/// A non-`Json` output, or a `Json` output missing either field, is the **normal,
/// expected** case for most completed tasks in a real session — not an anomaly. The
/// other real production completion call site, `roundhouse-engine`'s `chat.rs`
/// (`append_completed`), completes chat tasks with `TaskOutput::Text(String::new())`,
/// which carries no provider/model attribution at all. Returns
/// `StoreError::Unattributable` (not `StoreError::NotFound`) for exactly this reason:
/// callers that need to tolerate it across many tasks (`session_cost_rollup`) match on
/// this variant specifically to treat it as non-fatal, while single-task callers
/// (`task_cost_view` used directly) still see it as a real `Err`.
fn provider_and_model_from_output(
    task_id: TaskId,
    output: &TaskOutput,
) -> Result<(ProviderId, ModelId), StoreError> {
    let TaskOutput::Json(value) = output else {
        return Err(StoreError::Unattributable(format!(
            "task {task_id}: TaskCompleted output is not TaskOutput::Json, cannot recover \
             provider/model for cost attribution"
        )));
    };
    let provider = value
        .get("provider")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            StoreError::Unattributable(format!(
                "task {task_id}: TaskCompleted output JSON has no string \"provider\" field"
            ))
        })?;
    let model = value.get("model").and_then(|v| v.as_str()).ok_or_else(|| {
        StoreError::Unattributable(format!(
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

/// A session-level cost rollup: the sum of every completed task's known cost, plus two
/// separate counters for the two distinct reasons a completed task might not contribute
/// a known dollar figure — deliberately told apart rather than merged into one bucket,
/// since they mean different things to a caller deciding how much to trust the total:
/// - `unknown_task_count`: the task *is* attributable to a `(provider, model)`, but
///   `snapshot` has no `PriceEntry` for that pair (or the arithmetic overflowed) — a
///   pricing-coverage gap.
/// - `unattributable_task_count`: the task's `TaskOutput` doesn't carry provider/model
///   attribution at all (e.g. a real chat task, `TaskOutput::Text(String::new())`) — not
///   a gap, just a task shape this cost view has no way to price, ever, as things stand.
///
/// Computed fresh on every call, never stored, so it cannot drift from what a current
/// `PricingSnapshot` would say (S-OBS-1).
pub struct RollupCost {
    pub known_pico_usd: u64,
    pub unknown_task_count: u32,
    pub unattributable_task_count: u32,
}

/// Sums `task_cost_view` over every `Completed` task in `session_id`. A single task
/// whose cost can't be determined does **not** abort the whole rollup — see
/// `RollupCost`'s doc comment for the two non-fatal dispositions
/// (`unknown_task_count`/`unattributable_task_count`) this folds those cases into.
/// `StoreError::Unattributable` specifically is expected to be common (most completed
/// tasks in a real session are plain chat tasks with no provider/model attribution at
/// all — see `provider_and_model_from_output`'s doc comment), so it is caught and
/// counted here rather than propagated. Any other error (a real database read failure,
/// or `StoreError::NotFound` — a genuine data-consistency error, since
/// `completed_task_ids_for_session` already filtered to tasks the `tasks` cache table
/// says are `Completed`) still fails the whole rollup, on the theory that those really
/// are unexpected and the caller should know the total is untrustworthy rather than
/// silently getting a partial number.
pub async fn session_cost_rollup(
    store: &StorePool,
    session_id: SessionId,
    snapshot: &PricingSnapshot,
) -> Result<RollupCost, StoreError> {
    let task_ids = completed_task_ids_for_session(store, session_id).await?;
    let mut known_pico_usd = 0u64;
    let mut unknown_task_count = 0u32;
    let mut unattributable_task_count = 0u32;
    for task_id in task_ids {
        match task_cost_view(store, task_id, snapshot).await {
            Ok((_, Cost::Known(p))) => known_pico_usd += p,
            Ok((_, Cost::Unknown)) => unknown_task_count += 1,
            Err(StoreError::Unattributable(_)) => unattributable_task_count += 1,
            Err(e) => return Err(e),
        }
    }
    Ok(RollupCost {
        known_pico_usd,
        unknown_task_count,
        unattributable_task_count,
    })
}
