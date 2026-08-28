use roundhouse_core::{EventPayload, SessionId, TaskId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// S-CFG-5 (§12.7) — API versioning, frozen in Phase 0 alongside the wire
/// types themselves so later phases never have to retrofit it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ApiVersion(pub u32);

impl ApiVersion {
    pub const CURRENT: ApiVersion = ApiVersion(0);
}

/// Client-to-daemon requests over the NDJSON/UDS transport (§5.1). This is a
/// deliberately small Phase 0 seed — later phases add variants (attach,
/// approve, cancel, ...) without breaking existing ones, since consumers
/// must already match non-exhaustively per `#[non_exhaustive]`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub enum ClientRequest {
    CreateSession { workspace_name: String },
    Attach { session_id: SessionId },
}

/// Daemon-to-client events over the NDJSON/SSE transport — a thin,
/// versioned envelope around `roundhouse_core::EventPayload` plus routing
/// metadata the client needs that isn't part of the log itself.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub enum ClientEvent {
    TaskEvent { session_id: SessionId, task_id: Option<TaskId>, payload: EventPayload },
    Ack { api_version: ApiVersion },
}
