use roundhouse_core::{CancelReason, EventPayload, SessionId, TaskId};
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
    /// Phase 8, T19a Task 8: ask the daemon to durably close an
    /// already-established session — the wire counterpart of
    /// `roundhouse_engine::SessionActor::close`. A new variant, for the same
    /// reason `SubmitTurn`'s own doc comment gives: `ClientRequest` is
    /// `#[non_exhaustive]`, so adding one is additive, and every existing
    /// consumer already carries the catch-all arm `#[non_exhaustive]`
    /// requires.
    ///
    /// `session_id` is carried, not implied by the connection, for the same
    /// reason `SubmitTurn::session_id` is: it lets the daemon refuse a frame
    /// naming a session other than the one this connection established. See
    /// `roundhouse_daemon::socket_server::drive_established_session`, which
    /// honors this variant only from the connection that created the
    /// session, the same creator-only rule `SubmitTurn` already enforces.
    CloseSession {
        session_id: SessionId,
    },
    /// Phase 8 Task 21: attach and replay from just after `after_seq` (the
    /// `(session_id, seq)` cursor a client last saw in a
    /// [`ClientEvent::Committed`]). A plain `Attach` replays from the start.
    ///
    /// Handshake-only, like `Attach`: valid only as a connection's first
    /// frame, and read-only for the same reason `Attach` is. If `after_seq`
    /// is past the session's head the daemon answers
    /// [`ClientEvent::ResyncRequired`] instead of `Ack`.
    Resume {
        session_id: SessionId,
        after_seq: u64,
    },
}

/// Daemon-to-client events over the NDJSON/SSE transport — a thin,
/// versioned envelope around `roundhouse_core::EventPayload` plus routing
/// metadata the client needs that isn't part of the log itself.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub enum ClientEvent {
    /// One log event without its `seq`. `roundhouse-web`'s SSE transport
    /// still sends this as its `data:` payload, since the cursor already
    /// travels in the SSE `id:` field. The UDS transport no longer emits it
    /// (Phase 8 Task 21): it sends [`ClientEvent::Committed`] instead, since
    /// NDJSON has no `id:` field to carry the cursor.
    TaskEvent {
        session_id: SessionId,
        task_id: Option<TaskId>,
        payload: Box<EventPayload>,
    },
    Ack {
        api_version: ApiVersion,
    },
    /// One committed log event, with the seq that serves as the client's
    /// cursor. Sent in `seq` order with no gaps; `payload` is the stored,
    /// already-redacted row.
    Committed {
        session_id: SessionId,
        seq: u64,
        task_id: Option<TaskId>,
        payload: Box<EventPayload>,
    },
    /// The outcome of this connection's own `SubmitTurn`. It is sent only
    /// after every event the turn committed (`seq <= through_seq`) has
    /// already been sent on this connection. `through_seq` is `None` for a
    /// [`TurnOutcome::Rejected`] turn, which committed nothing.
    TurnFinished {
        session_id: SessionId,
        outcome: TurnOutcome,
        through_seq: Option<u64>,
    },
    /// The resume cursor is ahead of this session's head. The client must
    /// discard its state and replay from the start. Terminal: the
    /// connection closes after it.
    ResyncRequired {
        session_id: SessionId,
        head: Option<u64>,
    },
}

/// How one `SubmitTurn` ended, reported in [`ClientEvent::TurnFinished`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub enum TurnOutcome {
    Completed,
    /// The turn ran and failed. `category` names the failure class
    /// (`provider`, `store`, `too_many_tool_calls`, `max_turns_exceeded`);
    /// `message` is the error text after the session's own redactor has run
    /// over it.
    Failed {
        category: String,
        message: String,
    },
    Cancelled {
        reason: CancelReason,
    },
    /// The daemon refused the SubmitTurn (not the creator, wrong session, too long,
    /// a turn already in flight, closing, or actor gone). No task was created.
    Rejected {
        reason: String,
    },
}
