//! Every event for a session, in sequence order — the session-scoped
//! counterpart to `suspended_tasks` (`suspended.rs`) for reads (like
//! startup `Degradation` notes) that aren't scoped to one task. Also home to
//! `events_after`/`session_head` (Phase 8 Task 21, Task 1): the sync, paged counterpart
//! `roundhouse-web`'s SSE/UDS followers use to catch up and re-read after a `CommitFeed`
//! wake, since `session_events` itself is unpaged and async (unusable from inside an
//! `interact` closure).

use roundhouse_core::{SessionId, Timestamp};

use crate::replay::StoredEvent;
use crate::{pool::StorePool, StoreError};

/// One raw `events` row: `(seq, ts_nanos, task_id, payload_json, schema_v)`.
type SessionEventRow = (i64, i64, Option<String>, String, u16);

/// Decodes one raw `events` row into a `StoredEvent` — the exact per-row decode
/// `session_events` and `events_after` both need (task_id UUID parsing, payload JSON
/// deserialization), factored out so `events_after` reuses it rather than copying it.
fn stored_event_from_row(
    session_id: SessionId,
    seq: i64,
    ts_nanos: i64,
    task_id_str: Option<String>,
    payload_json: String,
    schema_v: u16,
) -> Result<StoredEvent, StoreError> {
    let task_id = task_id_str
        .map(|s| {
            uuid::Uuid::parse_str(&s)
                .map(roundhouse_core::TaskId::from_uuid)
                .map_err(|e| StoreError::Interact(format!("corrupt task_id in events table: {e}")))
        })
        .transpose()?;
    let payload = serde_json::from_str(&payload_json).map_err(|e| {
        StoreError::Interact(format!("corrupt payload for session {session_id}: {e}"))
    })?;

    Ok(StoredEvent {
        session_id,
        seq: seq as u64,
        ts: Timestamp::from_unix_nanos(ts_nanos),
        task_id,
        payload,
        schema_v,
    })
}

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
        events.push(stored_event_from_row(
            session_id,
            seq,
            ts_nanos,
            task_id_str,
            payload_json,
            schema_v,
        )?);
    }

    Ok(events)
}

/// Every event for `session_id` with `seq` strictly greater than `after`, ascending, up to
/// `limit` rows — the paged, sync counterpart to `session_events` a follower re-reads with
/// after a `CommitFeed` wake. Sync (takes a live `&rusqlite::Connection`, not a
/// `StorePool`) so `roundhouse-web` can call it from inside `StoreConnection::interact`
/// without a nested `.await`.
///
/// `after: None` means "from the start" — `seq 0` is a real, valid event (assigned by
/// `EventWriter::append`'s own per-session sequence), so `None` cannot be represented as
/// `Some(0)` without excluding it; the query instead widens to `seq >= 0` in that case.
pub fn events_after(
    conn: &rusqlite::Connection,
    session_id: SessionId,
    after: Option<u64>,
    limit: usize,
) -> Result<Vec<StoredEvent>, StoreError> {
    let session_id_str = session_id.to_string();
    // `seq >= 0` for `None` is the same predicate as `seq > -1` — every real `seq` is
    // non-negative, so this is exactly "from the start" with no special-cased SQL branch.
    let after_seq: i64 = after.map_or(-1, |seq| seq as i64);
    let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);

    let mut stmt = conn.prepare(
        "SELECT seq, ts, task_id, payload, schema_v FROM events \
         WHERE session_id = ?1 AND seq > ?2 ORDER BY seq ASC LIMIT ?3",
    )?;
    let rows: Vec<SessionEventRow> = stmt
        .query_map(
            rusqlite::params![session_id_str, after_seq, limit_i64],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, u16>(4)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;

    let mut events = Vec::with_capacity(rows.len());
    for (seq, ts_nanos, task_id_str, payload_json, schema_v) in rows {
        events.push(stored_event_from_row(
            session_id,
            seq,
            ts_nanos,
            task_id_str,
            payload_json,
            schema_v,
        )?);
    }

    Ok(events)
}

/// The highest committed `seq` for `session_id`, or `None` if it has no events at all.
/// Sync, for the same reason as `events_after`. `SELECT MAX(seq)` always returns exactly
/// one row even when nothing matches (a NULL, not zero rows), so this reads a
/// `Option<i64>` directly rather than needing `OptionalExtension`.
pub fn session_head(
    conn: &rusqlite::Connection,
    session_id: SessionId,
) -> Result<Option<u64>, StoreError> {
    let session_id_str = session_id.to_string();
    let head: Option<i64> = conn.query_row(
        "SELECT MAX(seq) FROM events WHERE session_id = ?1",
        [session_id_str],
        |row| row.get(0),
    )?;
    Ok(head.map(|seq| seq as u64))
}
