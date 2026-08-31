//! Crash recovery: reclassify tasks interrupted by daemon restart.
//!
//! On daemon startup, any task found in `Created`, `Decided`, or `Running` state
//! (with no terminal event and never suspended) is reclassified as `Interrupted`
//! by appending a synthetic `TaskCancelled { reason: DaemonRestart }` event.
//! `Suspended` tasks are left untouched — they are re-armed through the
//! attention-queue path instead (see `docs/architecture/README.md`).
//!
//! **Rewritten (Task 2)** to query the live `tasks` materialized-cache table
//! (Task 0.5) directly — `SELECT task_id, session_id FROM tasks WHERE state IN
//! ('Created', 'Decided', 'Running')` — instead of replaying every event ever
//! written. The old algorithm read the ENTIRE `events` table on every boot
//! (unbounded in the log's total size, not the number of in-flight tasks) and
//! issued one individual writer round-trip per interrupted task; this version
//! is O(in-flight tasks) to read and commits every synthetic `TaskCancelled`
//! event in a single transaction via `EventWriter::append_batch`, which is
//! what actually meets S-SESS-4's "500 sessions × 200 tasks recovers within
//! 5s" budget (see `tests/recovery_scale.rs`).

use roundhouse_core::{CancelReason, Origin, SessionId, TaskId, Timestamp};

use crate::{pool::StorePool, writer::EventWriter, StoreError};

/// One row read back from the `tasks` table: `(task_id, session_id)`, both
/// stored as `TEXT` (UUID string form).
type NonTerminalRow = (String, String);

/// Queries `tasks` for every row whose `state` is `Created`, `Decided`, or
/// `Running` (never `Suspended` or terminal), and for each one appends a
/// synthetic `TaskCancelled { reason: DaemonRestart }` event that folds to
/// `TaskState::Interrupted` — batched into a single transaction via
/// `EventWriter::append_batch`. `Suspended` tasks are left untouched.
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
        .interact(|c| -> Result<Vec<NonTerminalRow>, rusqlite::Error> {
            let mut stmt = c.prepare(
                "SELECT task_id, session_id FROM tasks
                 WHERE state IN ('Created', 'Decided', 'Running')",
            )?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
        .map_err(|e| StoreError::Interact(e.to_string()))?;

    let rows = rows_result.map_err(StoreError::Sqlite)?;

    // One timestamp for the whole batch: these synthetic events are all
    // minted "now", at the moment recovery runs, not backdated to anything
    // in the original event history.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    let ts = Timestamp::from_unix_nanos(nanos);

    let mut interrupted = Vec::with_capacity(rows.len());
    let mut events = Vec::with_capacity(rows.len());
    for (task_id_str, session_id_str) in &rows {
        let task_id =
            TaskId::from_uuid(uuid::Uuid::parse_str(task_id_str).map_err(|e| {
                StoreError::Interact(format!("corrupt task_id in tasks table: {e}"))
            })?);
        let session_id =
            SessionId::from_uuid(uuid::Uuid::parse_str(session_id_str).map_err(|e| {
                StoreError::Interact(format!("corrupt session_id in tasks table: {e}"))
            })?);

        let event = runner.record_task_cancelled(
            session_id,
            0, // seq reassigned by the writer
            ts,
            task_id,
            Origin::System,
            CancelReason::DaemonRestart,
            1, // schema_v
        );
        events.push(event);
        interrupted.push(task_id);
    }

    // One transaction for the whole batch, not one per task — see
    // `EventWriter::append_batch`'s doc comment for the per-session
    // seq-assignment design that makes this safe when several interrupted
    // tasks share a session_id.
    if !events.is_empty() {
        writer.append_batch(events).await?;
    }

    // Sorted by the raw `Uuid` value, not `.to_string()`: `sort_by_key`'s key
    // function may run more than once per element during the sort (unlike
    // `sort_by_cached_key`), so a `String`-allocating key here is O(n log n)
    // allocations — confirmed empirically to cost over a second of this
    // function's own budget at `tests/recovery_scale.rs`'s 100,000-task
    // scale. `Uuid: Copy + Ord` sorts identically (a UUID's hyphenated string
    // form is a fixed-width, position-for-position hex encoding of the same
    // bytes, so string order and byte order agree) at a fraction of the cost.
    interrupted.sort_by_key(|id| id.as_uuid());
    Ok(interrupted)
}
