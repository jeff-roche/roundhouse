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
    CreateSession {
        workspace_name: String,
    },
    Attach {
        session_id: SessionId,
    },
    /// Phase 7, Task 8 (ruling W1-R116): submit one user turn to an
    /// already-established session, so a model-issued tool call can
    /// actually be dispatched. This is the first variant that names "do
    /// something inside a session already established on this connection"
    /// rather than "establish one" — it is only ever valid AFTER the
    /// handshake, never as a connection's first frame.
    ///
    /// **A new variant, deliberately, rather than a new field on
    /// `CreateSession`.** The doc comment above pre-authorizes exactly
    /// this: a new field would change `CreateSession`'s wire shape for
    /// every existing client and every recorded fixture, whereas a new
    /// variant is genuinely additive because `#[non_exhaustive]` already
    /// forces every consumer to carry a catch-all arm.
    ///
    /// `session_id` is carried (rather than implied by the connection)
    /// so the daemon can reject a frame naming a session other than the
    /// one this connection established — see
    /// `roundhouse_daemon::socket_server::drive_session`, which honors
    /// this variant **only** from the connection that created the
    /// session (rulings W1-R37/W1-R52) and refuses it from an attached,
    /// read-only connection.
    ///
    /// `text` is the minimal payload that lets a turn run end to end: the
    /// user message the provider is called with. Everything else the turn
    /// needs (model, system prompt, tool catalog, policy) is already
    /// per-session daemon state; putting any of it on the wire would let a
    /// client choose its own tool catalog or model, which is a policy
    /// decision, not a client one.
    SubmitTurn {
        session_id: SessionId,
        text: String,
    },
}

/// Daemon-to-client events over the NDJSON/SSE transport — a thin,
/// versioned envelope around `roundhouse_core::EventPayload` plus routing
/// metadata the client needs that isn't part of the log itself.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub enum ClientEvent {
    TaskEvent {
        session_id: SessionId,
        task_id: Option<TaskId>,
        payload: Box<EventPayload>,
    },
    Ack {
        api_version: ApiVersion,
    },
}
