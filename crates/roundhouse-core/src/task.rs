use crate::event::EventPayload;
use crate::ids::{SessionId, TaskId};
use crate::task_kind::TaskKind;
use crate::task_meta::{IsolationAttestation, Origin, PolicyDecision, SuspendReason, Usage};
use serde::{Deserialize, Serialize};

/// §4.1's fold states, named 1:1 with the task-lifecycle `EventPayload`
/// variants that produce them, plus `Interrupted` (S-SESS-4), which no
/// event carries — it is assigned explicitly by crash-recovery logic
/// (Phase 2, §13.2), never derived by `fold_task_state` below. Per the
/// resolved semantics `docs/architecture/README.md` records: `Interrupted`
/// only ever replaces `Created`/`Decided`/`Running` on an unclean shutdown;
/// `Suspended*` tasks are re-armed through the attention-queue path
/// instead, never wiped to `Interrupted`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskState {
    Created,
    Decided,
    Running,
    Suspended(SuspendReason),
    Completed,
    Failed,
    Cancelled,
    Interrupted,
}

impl TaskState {
    /// The `tasks.state` column stores only the discriminant (Task 10's
    /// `CHECK` constraint enumerates exactly these eight strings) — the
    /// detail inside a data-carrying variant like `Suspended` lives in the
    /// event log, which is the source of truth; the `tasks` table is only
    /// ever a derived cache (§4.1).
    pub fn as_sql_str(&self) -> &'static str {
        match self {
            TaskState::Created => "Created",
            TaskState::Decided => "Decided",
            TaskState::Running => "Running",
            TaskState::Suspended(_) => "Suspended",
            TaskState::Completed => "Completed",
            TaskState::Failed => "Failed",
            TaskState::Cancelled => "Cancelled",
            TaskState::Interrupted => "Interrupted",
        }
    }

    /// The read-back half of Task 10's `CHECK` constraint: rejection of an
    /// unrecognized state happens at *fold time* here (as well as at
    /// *insert time* via the SQL `CHECK`) — both legs enforce the same
    /// taxonomy so a hand-edited or corrupted row can't silently produce a
    /// `Task` in a state that doesn't exist. Note this only reconstructs
    /// the fieldless discriminant; a caller that needs a real
    /// `Suspended(SuspendReason)` must fold it from the event log instead
    /// (this function exists for validating/round-tripping the cache
    /// column, not as a full inverse of `as_sql_str`).
    pub fn from_sql_str(s: &str) -> Result<TaskState, crate::error::CoreError> {
        match s {
            "Created" => Ok(TaskState::Created),
            "Decided" => Ok(TaskState::Decided),
            "Running" => Ok(TaskState::Running),
            "Suspended" => Ok(TaskState::Suspended(SuspendReason::AwaitingApproval)),
            "Completed" => Ok(TaskState::Completed),
            "Failed" => Ok(TaskState::Failed),
            "Cancelled" => Ok(TaskState::Cancelled),
            "Interrupted" => Ok(TaskState::Interrupted),
            other => Err(crate::error::CoreError::InvalidTaskState(other.to_string())),
        }
    }
}

/// §4.4 — a span of a task's serialized input/output that was replaced by a
/// secrets scrubber before being written to the log. Minimal Phase 0 shape;
/// the scrubbing engine itself is Phase 2 work (§13.2, secrets/taint).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactedSpan {
    pub field: String,
    pub start: usize,
    pub end: usize,
}

/// §4.1 — "a Task is the materialised fold of the events bearing its
/// `task_id`." This is that fold's target shape: everything `roundhouse-store`
/// keeps in the `tasks` derived-cache table for one task, plus the §4.4
/// identity/provenance fields. Building a full `Task` from a raw event
/// slice (populating `origin`/`actor`/`policy_decision`/`isolation`/`usage`/
/// `redactions` alongside `state`) is straightforward field-by-field
/// extraction using the same match arms as `fold_task_state` below, and is
/// Phase 1's `roundhouse-store` materialized-view work (§13.2) — Task 3
/// freezes the shape now so `roundhouse-store`'s schema (Task 10) and every
/// later phase can depend on it without a retrofit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: TaskId,
    pub session_id: SessionId,
    pub kind: TaskKind,
    pub parent: Option<TaskId>,
    pub state: TaskState,
    pub origin: Origin,
    /// Which session/agent is driving this task (§4.4's "actor").
    pub actor: SessionId,
    pub policy_decision: Option<PolicyDecision>,
    pub isolation: Option<IsolationAttestation>,
    pub usage: Usage,
    pub redactions: Vec<RedactedSpan>,
}

/// The state-fold half of §4.1's "materialised fold" definition: given every
/// `EventPayload` bearing one `task_id`, in log order, derive the current
/// `TaskState`. Session-level and cross-cutting payloads (`Session*`,
/// `Message`, `Note`, `TaskDelta`, `TaskProgress`) don't change task state
/// and are ignored. Returns `None` if the slice contains no task-lifecycle
/// event at all (nothing to fold yet).
pub fn fold_task_state(events: &[EventPayload]) -> Option<TaskState> {
    let mut state = None;
    for payload in events {
        state = match payload {
            EventPayload::TaskCreated { .. } => Some(TaskState::Created),
            EventPayload::TaskDecided { .. } => Some(TaskState::Decided),
            EventPayload::TaskStarted { .. } => Some(TaskState::Running),
            EventPayload::TaskSuspended { reason } => Some(TaskState::Suspended(reason.clone())),
            EventPayload::TaskResumed { .. } => Some(TaskState::Running),
            EventPayload::TaskCompleted { .. } => Some(TaskState::Completed),
            EventPayload::TaskFailed { .. } => Some(TaskState::Failed),
            EventPayload::TaskCancelled { .. } => Some(TaskState::Cancelled),
            _ => state,
        };
    }
    state
}
