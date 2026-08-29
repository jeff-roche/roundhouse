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

#[derive(Clone)]
pub struct EventWriter {
    tx: mpsc::Sender<WriteCmd>,
}

pub fn serialize_payload(payload: &roundhouse_core::EventPayload) -> String {
    serde_json::to_string(payload).expect("EventPayload must always serialize")
}

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
const MAX_BUSY_RETRIES: u32 = 8;
const INITIAL_BACKOFF: Duration = Duration::from_millis(5);

fn is_sqlite_busy(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(ffi_err, _) if ffi_err.code == rusqlite::ErrorCode::DatabaseBusy
    )
}

async fn append_one(store: &StorePool, mut event: Event) -> Result<u64, StoreError> {
    let conn = store.pool.get().await?;
    let payload_json = serialize_payload(&event.payload);
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

        let write_result = conn
            .interact(move |c| -> Result<u64, rusqlite::Error> {
                let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let next_seq: i64 = tx.query_row(
                    "SELECT COALESCE(MAX(seq), -1) + 1 FROM events WHERE session_id = ?1",
                    [&session_id],
                    |row| row.get(0),
                )?;
                tx.execute(
                    "INSERT INTO events (session_id, seq, ts, task_id, payload, schema_v)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![session_id, next_seq, ts_nanos, task_id, payload_json, schema_v],
                )?;
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

    event.seq = seq;
    Ok(seq)
}

impl EventWriter {
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
