//! Every event for a session, in sequence order — the session-scoped
//! counterpart to `suspended_tasks` (`suspended.rs`) for reads (like
//! startup `Degradation` notes) that aren't scoped to one task.

use roundhouse_core::{SessionId, Timestamp};

use crate::replay::StoredEvent;
use crate::{pool::StorePool, StoreError};

/// One raw `events` row: `(seq, ts_nanos, task_id, payload_json, schema_v)`.
type SessionEventRow = (i64, i64, Option<String>, String, u16);

/// Every event recorded for `session_id`, ordered by `seq` ascending.
///
/// Returns `roundhouse_store::StoredEvent` (a plain, unsealed DTO), not
/// `roundhouse_core::Event` — `Event` can only be minted inside
/// `roundhouse-core` via `TaskRunner`, so a read path like this one, which
/// reconstructs already-durable rows rather than minting new events, uses
/// the read-model counterpart instead. See `replay.rs`'s doc comment for
/// why the two types exist separately.
pub async fn session_events(
    store: &StorePool,
    session_id: SessionId,
) -> Result<Vec<StoredEvent>, StoreError> {
    let conn = store.pool.get().await?;
    let session_id_str = session_id.to_string();

    let rows_result = conn
        .interact(move |c| -> Result<Vec<SessionEventRow>, rusqlite::Error> {
            let mut stmt = c.prepare(
                "SELECT seq, ts, task_id, payload, schema_v FROM events \
                 WHERE session_id = ?1 ORDER BY seq ASC",
            )?;
            let rows = stmt
                .query_map([&session_id_str], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<String>>(2)?,
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
    for (seq, ts_nanos, task_id_str, payload_json, schema_v) in rows {
        let task_id = task_id_str
            .map(|s| {
                uuid::Uuid::parse_str(&s)
                    .map(roundhouse_core::TaskId::from_uuid)
                    .map_err(|e| {
                        StoreError::Interact(format!("corrupt task_id in events table: {e}"))
                    })
            })
            .transpose()?;
        let payload = serde_json::from_str(&payload_json).map_err(|e| {
            StoreError::Interact(format!("corrupt payload for session {session_id}: {e}"))
        })?;

        events.push(StoredEvent {
            session_id,
            seq: seq as u64,
            ts: Timestamp::from_unix_nanos(ts_nanos),
            task_id,
            payload,
            schema_v,
        });
    }

    Ok(events)
}
