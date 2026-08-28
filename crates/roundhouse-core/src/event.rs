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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub session_id: crate::ids::SessionId,
    pub seq: u64,
    pub ts: Timestamp,
    pub task_id: Option<TaskId>,
    pub payload: EventPayload,
    pub schema_v: u16,
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
