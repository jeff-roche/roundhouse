//! The read-model counterpart to `roundhouse_core::Event` (the sealed
//! write-model). `StoredEvent` represents a row already read back from the
//! append-only `events` table (S-LOG-2) — it is NOT minted, carries no
//! authority, and anyone can construct one from data that came out of
//! storage. Use this for folding/replay (`fold_task`, crash recovery); use
//! `roundhouse_core::Event` (minted only via `TaskRunner`) for anything
//! that represents a new action being recorded.

/// A row already read back from the append-only `events` table. Unlike
/// `roundhouse_core::Event`, this type is a plain, unsealed DTO: it derives
/// `Deserialize` and can be struct-literal-constructed from any crate. It
/// carries no minting authority — it exists purely to let fold/replay code
/// reconstruct event data that is already durably written, not to fabricate
/// new events.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredEvent {
    pub session_id: roundhouse_core::SessionId,
    pub seq: u64,
    pub ts: roundhouse_core::Timestamp,
    pub task_id: Option<roundhouse_core::TaskId>,
    pub payload: roundhouse_core::EventPayload,
    pub schema_v: u16,
}

impl roundhouse_core::EventFields for StoredEvent {
    fn session_id(&self) -> roundhouse_core::SessionId {
        self.session_id
    }
    fn seq(&self) -> u64 {
        self.seq
    }
    fn ts(&self) -> roundhouse_core::Timestamp {
        self.ts
    }
    fn task_id(&self) -> Option<roundhouse_core::TaskId> {
        self.task_id
    }
    fn payload(&self) -> &roundhouse_core::EventPayload {
        &self.payload
    }
    fn schema_v(&self) -> u16 {
        self.schema_v
    }
}
