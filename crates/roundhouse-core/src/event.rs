use crate::delta::Delta;
use crate::ids::TaskId;
use crate::session::{SessionOutcome, SessionPatch, SessionSpec, SessionState};
use crate::task_kind::TaskKind;
use crate::task_meta::{
    CancelReason, Envelope, Handle, IsolationAttestation, NoteLevel, Origin, PolicyDecision,
    Progress, RuleId, SuspendReason, TaskError, TaskInput, TaskOutput, Usage,
};
use crate::timestamp::Timestamp;
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
        Event { session_id, seq, ts, task_id, payload, schema_v, _seal: crate::seal::Seal::mint() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventPayload {
    // ── session lifecycle ─────────────────────────────────────────────
    SessionCreated { spec: Box<SessionSpec> },
    SessionConfigured { patch: SessionPatch },
    SessionStateChanged { state: SessionState, reason: Option<String> },
    SessionClosed { outcome: SessionOutcome },

    // ── task lifecycle ────────────────────────────────────────────────
    TaskCreated { kind: TaskKind, parent: Option<TaskId>, origin: Origin, input: TaskInput },
    TaskDecided { decision: PolicyDecision, rule: Option<RuleId> },
    /// `handle` is `Some` only for long-running/non-terminating tasks
    /// (§4.3 — e.g. `shell` running `npm run dev`): the pty/process id the
    /// engine needs for a `read_output`/`kill` affordance while the task
    /// stays `Running`. `None` for tasks that simply run to completion.
    TaskStarted { isolation: IsolationAttestation, handle: Option<Handle> },
    TaskDelta { delta: Delta },
    TaskProgress { progress: Progress },
    TaskSuspended { reason: SuspendReason },
    TaskResumed { by: Origin },
    TaskCompleted { output: TaskOutput, usage: Usage },
    TaskFailed { error: TaskError, retryable: bool },
    TaskCancelled { by: Origin, reason: CancelReason },

    // ── cross-cutting ─────────────────────────────────────────────────
    Message { envelope: Envelope },
    Note { level: NoteLevel, text: String },
}
