//! Crash recovery: reclassify tasks interrupted by daemon restart.
//!
//! On daemon startup, any task found in `Created`, `Decided`, or `Running` state
//! (with no terminal event and never suspended) is reclassified as `Interrupted`
//! by appending a synthetic `TaskCancelled { reason: DaemonRestart }` event.
//! `Suspended` tasks are left untouched — they are re-armed through the
//! attention-queue path instead (see `docs/architecture/README.md`).

use std::collections::HashMap;

use roundhouse_core::{CancelReason, EventFields, Origin, SessionId, TaskId, Timestamp};

use crate::{
    fold::fold_task, pool::StorePool, replay::StoredEvent, writer::EventWriter, StoreError,
    TaskState,
};

/// One raw row read back from the `events` table, before it's parsed into a
/// `StoredEvent`: `(session_id, seq, ts_nanos, task_id, payload, schema_v)`.
/// Named here so the closure signature and the later `Vec<EventRow>` binding
/// don't repeat this six-tuple inline (clippy's `type_complexity`).
type EventRow = (String, i64, i64, Option<String>, String, i64);

/// Scans all events grouped by task_id, folds each group to determine task state,
/// and for every task whose state is `Created`, `Decided`, or `Running` (never
/// suspended or terminated), appends a synthetic `TaskCancelled { reason: DaemonRestart }`
/// event that folds to `TaskState::Interrupted`. `Suspended` tasks are left untouched.
///
/// Returns the `TaskId`s of the tasks that were interrupted.
///
/// `runner` is the only sanctioned way to mint the synthetic `TaskCancelled` event.
/// `TaskRunner::bootstrap()` can only be called once per process by roundhouse-engine
/// at daemon startup — this function receives an already-bootstrapped instance rather
/// than trying to obtain its own.
pub async fn recover_interrupted_tasks(
    store: &StorePool,
    writer: &EventWriter,
    runner: &roundhouse_core::TaskRunner,
) -> Result<Vec<TaskId>, StoreError> {
    let conn = store.pool.get().await?;

    let rows_result = conn
        .interact(|c| -> Result<Vec<EventRow>, rusqlite::Error> {
            let mut stmt = c.prepare(
                "SELECT session_id, seq, ts, task_id, payload, schema_v
                 FROM events WHERE task_id IS NOT NULL ORDER BY task_id, seq",
            )?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
        .map_err(|e| StoreError::Interact(e.to_string()))?;

    let rows: Vec<EventRow> = rows_result.map_err(StoreError::Sqlite)?;

    let mut by_task: HashMap<TaskId, Vec<StoredEvent>> = HashMap::new();
    for (session_id, seq, ts_nanos, task_id_opt, payload, schema_v) in rows {
        let Some(task_id_str) = task_id_opt else {
            continue;
        };
        let task_id =
            TaskId::from_uuid(uuid::Uuid::parse_str(&task_id_str).map_err(|e| {
                StoreError::Interact(format!("corrupt task_id in events table: {e}"))
            })?);
        let session_id_parsed =
            SessionId::from_uuid(uuid::Uuid::parse_str(&session_id).map_err(|e| {
                StoreError::Interact(format!("corrupt session_id in events table: {e}"))
            })?);
        let seq_u64 = u64::try_from(seq)
            .map_err(|e| StoreError::Interact(format!("corrupt seq in events table: {e}")))?;
        let payload_parsed: roundhouse_core::EventPayload = serde_json::from_str(&payload)
            .map_err(|e| StoreError::Interact(format!("corrupt payload in events table: {e}")))?;
        let schema_v_u16 = u16::try_from(schema_v)
            .map_err(|e| StoreError::Interact(format!("corrupt schema_v in events table: {e}")))?;

        // StoredEvent is the read-model DTO for replayed events already on disk (see replay.rs).
        let event = StoredEvent {
            session_id: session_id_parsed,
            seq: seq_u64,
            ts: Timestamp::from_unix_nanos(ts_nanos),
            task_id: Some(task_id),
            payload: payload_parsed,
            schema_v: schema_v_u16,
        };
        by_task.entry(task_id).or_default().push(event);
    }

    let mut interrupted = Vec::new();
    for (task_id, events) in &by_task {
        let Some(task) = fold_task(events) else {
            continue;
        };
        // Only a task that never reached a terminal *or suspended* event gets
        // reclassified. `Suspended` (any reason) is deliberately excluded — see this
        // task's Interfaces note (audit finding 3): it is re-armed through the
        // attention-queue path instead, never wiped to `Interrupted`.
        if matches!(
            task.state,
            TaskState::Created | TaskState::Decided | TaskState::Running
        ) {
            let last = events.iter().max_by_key(|e| e.seq()).unwrap();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock before UNIX epoch")
                .as_nanos() as i64;
            let ts = Timestamp::from_unix_nanos(nanos);
            let event = runner.record_task_cancelled(
                last.session_id,
                0, // seq reassigned by the writer
                ts,
                *task_id,
                Origin::System,
                CancelReason::DaemonRestart,
                1, // schema_v
            );
            writer.append(event).await?;
            interrupted.push(*task_id);
        }
    }

    interrupted.sort_by_key(|id| id.to_string());
    Ok(interrupted)
}
