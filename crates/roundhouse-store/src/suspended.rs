//! Enumerates tasks left `Suspended` in the live `tasks` materialized-cache
//! table (Task 0.5), with their REAL `SuspendReason` — read back from the
//! `suspend_reason_json` column, never from
//! `roundhouse_core::TaskState::from_sql_str`'s
//! `AwaitingApproval { rule: None, params_digest: [0u8; 32] }` placeholder
//! sentinel (see that function's doc comment: it exists only to
//! validate/round-trip the bare `state` discriminant, not to reconstruct
//! real suspend detail).
//!
//! This module only makes suspended tasks *enumerable* again after a
//! restart — see `roundhouse_daemon::boot::BootReport` for what does and
//! does not happen with the result.

use roundhouse_core::{SessionId, SuspendReason, TaskId};

use crate::{pool::StorePool, StoreError};

/// A task found `Suspended` in the `tasks` table, with its real, fully
/// detailed `SuspendReason` (not `TaskState::from_sql_str`'s placeholder).
pub struct SuspendedTask {
    pub task_id: TaskId,
    pub session_id: SessionId,
    pub reason: SuspendReason,
}

/// One row read back from the `tasks` table for a `Suspended` task:
/// `(task_id, session_id, suspend_reason_json)`.
type SuspendedRow = (String, String, Option<String>);

/// Enumerates every `Suspended` task from the live `tasks` table.
///
/// `suspend_reason_json` is populated in the same transaction as the `state`
/// column itself (`tasks_view::upsert_for_event`/`backfill_tasks_table`), so
/// it should never be `NULL` on a row whose `state = 'Suspended'` — a `NULL`
/// there is treated as a genuine data-consistency error (`StoreError`),
/// not a value to default around.
pub async fn suspended_tasks(store: &StorePool) -> Result<Vec<SuspendedTask>, StoreError> {
    let conn = store.pool.get().await?;

    let rows_result = conn
        .interact(|c| -> Result<Vec<SuspendedRow>, rusqlite::Error> {
            let mut stmt = c.prepare(
                "SELECT task_id, session_id, suspend_reason_json FROM tasks
                 WHERE state = 'Suspended'",
            )?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
        .map_err(|e| StoreError::Interact(e.to_string()))?;

    let rows = rows_result.map_err(StoreError::Sqlite)?;

    let mut suspended = Vec::with_capacity(rows.len());
    for (task_id_str, session_id_str, reason_json) in rows {
        let task_id =
            TaskId::from_uuid(uuid::Uuid::parse_str(&task_id_str).map_err(|e| {
                StoreError::Interact(format!("corrupt task_id in tasks table: {e}"))
            })?);
        let session_id =
            SessionId::from_uuid(uuid::Uuid::parse_str(&session_id_str).map_err(|e| {
                StoreError::Interact(format!("corrupt session_id in tasks table: {e}"))
            })?);

        let Some(reason_json) = reason_json else {
            return Err(StoreError::Interact(format!(
                "data inconsistency: tasks row for task {task_id} has state = 'Suspended' \
                 but suspend_reason_json is NULL (Task 0.5 sets both together — this should \
                 never happen)"
            )));
        };
        let reason: SuspendReason = serde_json::from_str(&reason_json).map_err(|e| {
            StoreError::Interact(format!(
                "corrupt suspend_reason_json for task {task_id}: {e}"
            ))
        })?;

        suspended.push(SuspendedTask {
            task_id,
            session_id,
            reason,
        });
    }

    Ok(suspended)
}
