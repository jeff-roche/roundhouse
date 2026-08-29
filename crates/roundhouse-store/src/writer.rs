use std::time::Duration;

use roundhouse_core::Event;
use tokio::sync::{mpsc, oneshot};

use crate::{pool::StorePool, StoreError};

pub(crate) enum WriteCmd {
    Append {
        event: Event,
        reply: oneshot::Sender<Result<u64, StoreError>>,
    },
}

/// A handle to the single-writer event-append task. Cloneable; multiple
/// callers can share the same `EventWriter` and append events concurrently
/// — all appends are serialized by the writer task, not the client.
#[derive(Clone)]
pub struct EventWriter {
    tx: mpsc::Sender<WriteCmd>,
}

/// Serialize an `EventPayload` to JSON.
///
/// Does *not* return `Err` for non-finite floating-point values (NaN/Infinity):
/// `serde_json` silently writes those as JSON `null` and returns `Ok` (verified
/// empirically — `serde_json::to_string` never errors on a non-finite `f32`/`f64`,
/// it only errors on genuinely non-serializable inputs, e.g. a map with
/// non-string keys). So a non-finite value here is a lossy round-trip
/// (`Some(NaN)` -> `null` -> `None` on replay), not a rejected write. This is
/// benign in this codebase today because the only float field on any
/// `EventPayload` variant is `Progress.fraction: Option<f32>`, where losing a
/// NaN/Infinity to `None` is an acceptable degradation, not data corruption.
/// The `Result` return type is kept for whatever `serde_json::to_string` *can*
/// still fail on (and as a stable signature for callers), not because
/// non-finite floats trigger it.
pub fn serialize_payload(
    payload: &roundhouse_core::EventPayload,
) -> Result<String, serde_json::Error> {
    serde_json::to_string(payload)
}

/// Spawn a dedicated async task that owns the event-append write transaction
/// and channel-receives `Append` commands from multiple callers. Returns an
/// `EventWriter` handle for sending append requests. The writer task runs until
/// the last `EventWriter` handle is dropped (the channel closes).
///
/// **Why a channel-actor pattern:** One dedicated task owns all writes serially.
/// Callers send append commands through the channel and await replies, rather than
/// each caller attempting to acquire its own DB connection and racing for the write lock.
/// This enforces single-writer discipline structurally (S-LOG-4/5) and makes the retry loop
/// recoverable from transient `SQLITE_BUSY` — the writer task survives client failures.
pub async fn spawn_writer(store: StorePool) -> EventWriter {
    let (tx, mut rx) = mpsc::channel::<WriteCmd>(1024);

    tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                WriteCmd::Append { event, reply } => {
                    let result = append_one(&store, event).await;
                    let _ = reply.send(result);
                }
            }
        }
    });

    EventWriter { tx }
}

/// S-LOG-4/5: bounded exponential backoff around the single-writer transaction. A
/// `SQLITE_BUSY`/`SQLITE_BUSY_SNAPSHOT` collision (another connection holding a
/// competing `BEGIN IMMEDIATE`, or — in WAL mode — a reader whose snapshot predates a
/// concurrent commit) is retried transparently; every other `rusqlite::Error` propagates
/// immediately, unretried.
///
/// Backoff: 5ms initial, doubles on each retry attempt (5, 10, 20, 40, 80, 160, 320, 640ms).
/// With 8 max retries, worst-case total wait is ~1.3s before giving up and surfacing the error.
const MAX_BUSY_RETRIES: u32 = 8;
const INITIAL_BACKOFF: Duration = Duration::from_millis(5);

fn is_sqlite_busy(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(ffi_err, _) if ffi_err.code == rusqlite::ErrorCode::DatabaseBusy
    )
}

async fn append_one(store: &StorePool, event: Event) -> Result<u64, StoreError> {
    let conn = store.pool.get().await?;
    let payload_json =
        serialize_payload(&event.payload).map_err(|e| StoreError::Interact(e.to_string()))?;
    let session_id = event.session_id.to_string();
    let task_id = event.task_id.map(|t| t.to_string());
    let ts_nanos = event.ts.as_unix_nanos();
    let schema_v = event.schema_v;

    let mut attempt: u32 = 0;
    let seq = loop {
        attempt += 1;
        let session_id = session_id.clone();
        let task_id = task_id.clone();
        let payload_json = payload_json.clone();
        let payload = event.payload.clone();

        let write_result = conn
            .interact(move |c| -> Result<u64, rusqlite::Error> {
                // BEGIN IMMEDIATE: acquire the write lock immediately rather than deferring it.
                // This enforces single-writer discipline: a writer holds the lock for its entire
                // transaction, so no two writers can execute concurrently. Deferred transactions
                // would allow multiple writers to run in parallel and race to the lock at commit
                // time, which would be both unfair to clients and incompatible with S-LOG-4/5's
                // retry guarantees.
                let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let next_seq: i64 = tx.query_row(
                    "SELECT COALESCE(MAX(seq), -1) + 1 FROM events WHERE session_id = ?1",
                    [&session_id],
                    |row| row.get(0),
                )?;
                tx.execute(
                    "INSERT INTO events (session_id, seq, ts, task_id, payload, schema_v)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![
                        session_id,
                        next_seq,
                        ts_nanos,
                        task_id,
                        payload_json,
                        schema_v
                    ],
                )?;
                // Same transaction as the events insert above (§6.10's pattern): a
                // `tasks` row is never inconsistent with the event that produced it.
                // Session-level events (`task_id: None`) have no `tasks` row to touch.
                if let Some(task_id) = &task_id {
                    crate::tasks_view::upsert_for_event(
                        &tx,
                        task_id,
                        &session_id,
                        next_seq,
                        ts_nanos,
                        &payload,
                    )?;
                }
                tx.commit()?;
                Ok(next_seq as u64)
            })
            .await
            .map_err(|e| StoreError::Interact(e.to_string()))?;

        match write_result {
            Ok(seq) => break seq,
            Err(err) if is_sqlite_busy(&err) && attempt < MAX_BUSY_RETRIES => {
                tokio::time::sleep(INITIAL_BACKOFF * 2u32.pow(attempt - 1)).await;
                continue;
            }
            Err(err) => return Err(StoreError::Sqlite(err)),
        }
    };

    Ok(seq)
}

impl EventWriter {
    /// Append an event to the log. The event's `seq` field is ignored (the writer
    /// assigns a monotonic sequence number per session). Returns the assigned `seq`,
    /// or an error if serialization, database locking, or the writer task fails.
    ///
    /// The `SQLITE_BUSY` retries (S-LOG-4/5) are transparent to the caller — the
    /// function blocks internally until the lock is acquired or max retries are exceeded.
    pub async fn append(&self, event: Event) -> Result<u64, StoreError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(WriteCmd::Append { event, reply })
            .await
            .map_err(|_| StoreError::Interact("writer task shut down".into()))?;
        rx.await
            .map_err(|_| StoreError::Interact("writer task dropped reply".into()))?
    }
}
