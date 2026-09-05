use crate::delta::Delta;
use crate::ids::TaskId;
use crate::session::{SessionOutcome, SessionPatch, SessionSpec, SessionState};
use crate::task_kind::TaskKind;
use crate::task_meta::{
    CancelReason, Envelope, Handle, IsolationAttestation, NoteLevel, Origin, PolicyDecision,
    Progress, RuleId, SuspendReason, TaskError, TaskInput, TaskOutput, Usage,
};
use crate::timestamp::Timestamp;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// §4.1 — the only thing ever written. Append-only. No UPDATE, no DELETE.
/// `Event` cannot be struct-literal-constructed outside `roundhouse-core`
/// (see Task 4's `Seal`); every field below stays `pub` so any crate can
/// still *read* and pattern-match an `Event` freely.
///
/// Deliberately drops `Deserialize` from the derive list (kept only
/// `Serialize`) — see `seal.rs` and `task_runner.rs` for why: a derived
/// `Deserialize` would let any crate fabricate a valid `Event` via
/// `serde_json::from_str`, bypassing the seal below entirely.
#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub session_id: crate::ids::SessionId,
    pub seq: u64,
    pub ts: Timestamp,
    pub task_id: Option<TaskId>,
    pub payload: EventPayload,
    pub schema_v: u16,
    #[serde(skip)]
    pub(crate) _seal: crate::seal::Seal,
}

impl Event {
    /// Crate-internal constructor. `TaskRunner` (in `task_runner.rs`, same
    /// crate) is the only public-facing caller of this.
    pub(crate) fn new_sealed(
        session_id: crate::ids::SessionId,
        seq: u64,
        ts: Timestamp,
        task_id: Option<TaskId>,
        payload: EventPayload,
        schema_v: u16,
    ) -> Self {
        Event {
            session_id,
            seq,
            ts,
            task_id,
            payload,
            schema_v,
            _seal: crate::seal::Seal::mint(),
        }
    }
}

/// Shared read-only accessors over the six fields common to `Event` (the
/// write-model, sealed, mint-only via `TaskRunner`) and `roundhouse_store`'s
/// `StoredEvent` (the read-model, for rows already read back from durable
/// storage — never minted). Lets fold/replay code (e.g. `roundhouse_store::
/// fold_task`) work generically over `&[impl EventFields]`, so the same fold
/// logic runs over live in-memory events and replayed-from-storage ones
/// without either type needing to become the other.
pub trait EventFields {
    fn session_id(&self) -> crate::ids::SessionId;
    fn seq(&self) -> u64;
    fn ts(&self) -> Timestamp;
    fn task_id(&self) -> Option<TaskId>;
    fn payload(&self) -> &EventPayload;
    fn schema_v(&self) -> u16;
}

impl EventFields for Event {
    fn session_id(&self) -> crate::ids::SessionId {
        self.session_id
    }
    fn seq(&self) -> u64 {
        self.seq
    }
    fn ts(&self) -> Timestamp {
        self.ts
    }
    fn task_id(&self) -> Option<TaskId> {
        self.task_id
    }
    fn payload(&self) -> &EventPayload {
        &self.payload
    }
    fn schema_v(&self) -> u16 {
        self.schema_v
    }
}

/// Compile-time tripwire: if `Event` ever grows a field, this exhaustive
/// destructure (only possible inside `roundhouse-core`, since it names the
/// private `_seal` field) fails to compile — a signal to update
/// `EventFields` and `roundhouse_store::StoredEvent` to match.
#[allow(dead_code)]
fn _event_shape_is_exhaustive(e: Event) {
    let Event {
        session_id: _,
        seq: _,
        ts: _,
        task_id: _,
        payload: _,
        schema_v: _,
        _seal: _,
    } = e;
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum EventPayload {
    // ── session lifecycle ─────────────────────────────────────────────
    SessionCreated {
        spec: Box<SessionSpec>,
    },
    SessionConfigured {
        patch: SessionPatch,
    },
    SessionStateChanged {
        state: SessionState,
        reason: Option<String>,
    },
    SessionClosed {
        outcome: SessionOutcome,
    },

    // ── task lifecycle ────────────────────────────────────────────────
    TaskCreated {
        kind: TaskKind,
        parent: Option<TaskId>,
        origin: Origin,
        input: TaskInput,
    },
    TaskDecided {
        decision: PolicyDecision,
        rule: Option<RuleId>,
    },
    /// `handle` is `Some` only for long-running/non-terminating tasks
    /// (§4.3 — e.g. `shell` running `npm run dev`): the pty/process id the
    /// engine needs for a `read_output`/`kill` affordance while the task
    /// stays `Running`. `None` for tasks that simply run to completion.
    TaskStarted {
        isolation: IsolationAttestation,
        handle: Option<Handle>,
    },
    TaskDelta {
        delta: Delta,
    },
    TaskProgress {
        progress: Progress,
    },
    TaskSuspended {
        reason: SuspendReason,
    },
    TaskResumed {
        by: Origin,
    },
    TaskCompleted {
        output: TaskOutput,
        usage: Usage,
    },
    TaskFailed {
        error: TaskError,
        retryable: bool,
    },
    TaskCancelled {
        by: Origin,
        reason: CancelReason,
    },

    // ── cross-cutting ─────────────────────────────────────────────────
    Message {
        envelope: Envelope,
    },
    Note {
        level: NoteLevel,
        text: String,
    },
    /// A recorded loss: information that could not be carried forward
    /// faithfully (e.g. a provider truncating/rejecting context). `kind` is
    /// a short machine-stable tag, `description` is free text (a provider
    /// error message may land here), and `blocks_affected` counts how many
    /// logical blocks the loss touched.
    ///
    /// Nothing constructs this variant yet — Phase 7 Task 13b adds the
    /// provider-codec emit sites.
    Loss {
        kind: String,
        description: String,
        blocks_affected: u32,
    },
}
