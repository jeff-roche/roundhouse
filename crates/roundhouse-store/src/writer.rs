use std::collections::HashMap;
use std::time::Duration;

use roundhouse_core::{Event, EventPayload};
use tokio::sync::{mpsc, oneshot};

use crate::{pool::StorePool, StoreError};

pub(crate) enum WriteCmd {
    Append {
        event: Event,
        reply: oneshot::Sender<Result<u64, StoreError>>,
    },
    AppendBatch {
        events: Vec<Event>,
        reply: oneshot::Sender<Result<Vec<u64>, StoreError>>,
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
                WriteCmd::AppendBatch { events, reply } => {
                    let result = append_batch(&store, events).await;
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

/// One batch member, pre-serialized once (outside the retry loop, same reason
/// `append_one` precomputes `payload_json`/`session_id`/`task_id` strings before
/// its own loop): a retried attempt reuses this pre-serialized form (behind an
/// `Arc`, see below) rather than re-serializing on every `SQLITE_BUSY` retry.
struct PreparedEvent {
    session_id: String,
    task_id: Option<String>,
    ts_nanos: i64,
    payload_json: String,
    payload: EventPayload,
    schema_v: u16,
}

/// Batched counterpart to `append_one`: applies every event in `events` inside
/// ONE `BEGIN IMMEDIATE` transaction, committing once for the whole batch
/// instead of once per event — that single commit is the entire point of
/// batching (see `recovery.rs`, the only production caller today).
///
/// **The seq-assignment trap this function exists to avoid:** `events.seq` is
/// scoped per `session_id` (`PRIMARY KEY (session_id, seq)`), and a batch can
/// easily contain multiple events for the same `session_id` (e.g. a session
/// with several tasks in flight when the daemon crashed). Querying
/// `SELECT COALESCE(MAX(seq), -1) + 1 FROM events WHERE session_id = ?1` fresh
/// for every event risks two events for the same session both computing the
/// same "next" value and colliding on insert. Instead, this function maintains
/// an in-memory `next_seq_by_session: HashMap<String, i64>`: the FIRST time a
/// given `session_id` is seen in this batch, its starting value is seeded via
/// that `MAX(seq)+1` query; every subsequent event for that same `session_id`
/// within the same batch reuses and increments the in-memory value instead of
/// re-querying the database. This is safe because `BEGIN IMMEDIATE` holds the
/// exclusive write lock for the whole transaction, so no other writer can
/// insert into the same session concurrently while this runs.
///
/// Same `SQLITE_BUSY`-retrying pattern as `append_one`: on a busy collision,
/// the ENTIRE batch is retried from scratch, not resumed partway.
async fn append_batch(store: &StorePool, events: Vec<Event>) -> Result<Vec<u64>, StoreError> {
    if events.is_empty() {
        return Ok(Vec::new());
    }

    let conn = store.pool.get().await?;

    // `Arc`, not a plain `Vec` cloned per retry attempt: at crash-recovery
    // scale (S-SESS-4's 500 sessions x 200 tasks — up to 100,000 events in one
    // batch) a deep `Vec<PreparedEvent>::clone()` before every attempt (paid
    // even on the common, never-retried path) was a measurable share of the
    // wall-clock budget in `tests/recovery_scale.rs`. Every attempt after the
    // first only happens on a genuine `SQLITE_BUSY` collision (rare), so
    // cloning the `Arc` (one atomic increment) instead of the `Vec` (100,000
    // owned `String`/`EventPayload` clones) costs nothing on the fast path
    // and is still correct on a retry, since nothing here ever mutates the
    // shared data.
    let prepared: std::sync::Arc<Vec<PreparedEvent>> = std::sync::Arc::new(
        events
            .iter()
            .map(|event| {
                let payload_json = serialize_payload(&event.payload)
                    .map_err(|e| StoreError::Interact(e.to_string()))?;
                Ok(PreparedEvent {
                    session_id: event.session_id.to_string(),
                    task_id: event.task_id.map(|t| t.to_string()),
                    ts_nanos: event.ts.as_unix_nanos(),
                    payload_json,
                    payload: event.payload.clone(),
                    schema_v: event.schema_v,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?,
    );

    let mut attempt: u32 = 0;
    let seqs = loop {
        attempt += 1;
        let batch = std::sync::Arc::clone(&prepared);

        let write_result = conn
            .interact(move |c| -> Result<Vec<u64>, rusqlite::Error> {
                // Same BEGIN IMMEDIATE discipline as append_one: acquire the
                // exclusive write lock for the whole transaction up front.
                let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let mut next_seq_by_session: HashMap<String, i64> = HashMap::new();
                let mut seqs = Vec::with_capacity(batch.len());

                // `prepare_cached`, not `tx.execute`/`tx.query_row` (which each
                // reparse and recompile the SQL text from scratch on every
                // call — negligible for `append_one`'s single call, but the
                // dominant cost at this loop's scale, confirmed empirically
                // against the 100k-task scale test in
                // `tests/recovery_scale.rs`): both statements below are
                // identical text on every iteration, so SQLite's per-connection
                // statement cache turns each repeat call into a cheap
                // lookup-and-rebind instead of a fresh parse.
                for item in batch.iter() {
                    let next_seq = match next_seq_by_session.get(&item.session_id) {
                        Some(&seq) => seq,
                        None => {
                            let mut select_max_seq = tx.prepare_cached(
                                "SELECT COALESCE(MAX(seq), -1) + 1 FROM events WHERE session_id = ?1",
                            )?;
                            select_max_seq.query_row([&item.session_id], |row| row.get(0))?
                        }
                    };

                    let mut insert_event = tx.prepare_cached(
                        "INSERT INTO events (session_id, seq, ts, task_id, payload, schema_v)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    )?;
                    insert_event.execute(rusqlite::params![
                        item.session_id,
                        next_seq,
                        item.ts_nanos,
                        item.task_id,
                        item.payload_json,
                        item.schema_v
                    ])?;
                    // Returns this cached statement to the connection's
                    // statement cache before the next iteration (and before
                    // `upsert_for_event` below runs its own `prepare_cached`
                    // calls on the same `tx`) rather than waiting for
                    // end-of-scope.
                    drop(insert_event);
                    // Same transaction as the events insert above, for every
                    // batch member — not just the first — so the `tasks` cache
                    // never falls behind for a batch-appended event (Task 0.5's
                    // invariant, extended to the batched path).
                    if let Some(task_id) = &item.task_id {
                        crate::tasks_view::upsert_for_event(
                            &tx,
                            task_id,
                            &item.session_id,
                            next_seq,
                            item.ts_nanos,
                            &item.payload,
                        )?;
                    }

                    next_seq_by_session.insert(item.session_id.clone(), next_seq + 1);
                    seqs.push(next_seq as u64);
                }

                tx.commit()?;
                Ok(seqs)
            })
            .await
            .map_err(|e| StoreError::Interact(e.to_string()))?;

        match write_result {
            Ok(seqs) => break seqs,
            Err(err) if is_sqlite_busy(&err) && attempt < MAX_BUSY_RETRIES => {
                tokio::time::sleep(INITIAL_BACKOFF * 2u32.pow(attempt - 1)).await;
                continue;
            }
            Err(err) => return Err(StoreError::Sqlite(err)),
        }
    };

    Ok(seqs)
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

    /// Append a batch of events in one transaction, one commit for the whole
    /// batch rather than one per event. Returns each event's assigned `seq`,
    /// in the same order as the input `events`. An empty `events` is a
    /// harmless no-op (`Ok(vec![])`) — recovery legitimately calls this with
    /// zero events on a clean boot.
    ///
    /// Per-session sequence assignment across the batch is handled correctly
    /// even when the batch contains multiple events for the same
    /// `session_id` — see `append_batch`'s (the free function's) doc comment
    /// for the seq-assignment design this depends on.
    pub async fn append_batch(&self, events: Vec<Event>) -> Result<Vec<u64>, StoreError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(WriteCmd::AppendBatch { events, reply })
            .await
            .map_err(|_| StoreError::Interact("writer task shut down".into()))?;
        rx.await
            .map_err(|_| StoreError::Interact("writer task dropped reply".into()))?
    }
}
