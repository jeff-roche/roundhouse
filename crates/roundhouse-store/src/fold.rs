//! Fold-to-Task materialized view. Every task is the fold of events bearing its
//! `task_id`, in ascending `seq` order. Phase 1 (crash recovery, Task 4) uses
//! this to rebuild in-memory task state from the durable event log.

use roundhouse_core::{EventFields, EventPayload, Origin, SessionId, TaskId, TaskKind};

/// The state of a task as of a point in the event log.
/// Deliberately narrower than `roundhouse_core::TaskState` (which exists, but
/// for Phase 0 contracts) — this local `TaskState` only needs to distinguish
/// "has a terminal or `Suspended` event" from "still `Running`", for crash
/// recovery purposes (Task 4). Task 0.5 reconciled the one input the two folds
/// used to disagree on (`TaskCancelled { reason: DaemonRestart }` -> `Interrupted`
/// — see the `TaskCancelled` arm in `fold_task` below); they remain two distinct
/// types, since this one still only needs Created/Decided/Running detail for
/// recovery and carries no `SuspendReason` detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Task was created but not yet decided.
    Created,
    /// Task was decided (ready to start).
    Decided,
    /// Task is currently running.
    Running,
    /// Task is suspended (waiting for external action).
    Suspended,
    /// Task completed successfully.
    Completed,
    /// Task failed.
    Failed,
    /// Task was cancelled.
    Cancelled,
    /// Task was interrupted.
    Interrupted,
}

/// A task reconstructed from the event log. The fold of all events bearing
/// a task_id, in ascending seq order, yields one Task.
#[derive(Debug, Clone)]
pub struct Task {
    /// The task ID.
    pub id: TaskId,
    /// The session ID this task belongs to.
    pub session_id: SessionId,
    /// The kind of task (e.g. Shell, Http, etc.).
    pub kind: TaskKind,
    /// The parent task ID, if this is a child task.
    pub parent: Option<TaskId>,
    /// The current state of the task.
    pub state: TaskState,
    /// The origin of the task (who/what initiated it).
    pub origin: Origin,
}

/// Folds every event sharing one `task_id`, in ascending `seq` order, into a `Task`.
/// Returns `None` if `events` is empty or contains no `TaskCreated` event.
///
/// This function is generic over `EventFields` so it works with both
/// `roundhouse_core::Event` (for testing/minting) and `roundhouse_store::StoredEvent`
/// (for replay/crash recovery from stored data).
pub fn fold_task<E: EventFields>(events: &[E]) -> Option<Task> {
    // Sort events by sequence number (should already be sorted in practice,
    // but defensive sort ensures correctness)
    let mut sorted: Vec<&E> = events.iter().collect();
    sorted.sort_by_key(|e| e.seq());

    // Find the TaskCreated event — if missing, return None
    let created = sorted.iter().find_map(|e| match e.payload() {
        EventPayload::TaskCreated {
            kind,
            parent,
            origin,
            ..
        } => Some((e.task_id()?, e.session_id(), kind.clone(), *parent, *origin)),
        // Phase 7 Task 13b (sanctioned lane-boundary exception, see the commit message):
        // a `Loss` event never carries `TaskCreated`'s identity fields, so it can never
        // be the event this search is looking for. Written down deliberately rather
        // than silently absorbed by the wildcard below.
        EventPayload::Loss { .. } => None,
        _ => None,
    })?;

    let (id, session_id, kind, parent, origin) = created;
    let mut state = TaskState::Created;

    // Fold through all events to determine the final state
    for event in &sorted {
        state = match event.payload() {
            EventPayload::TaskCreated { .. } => TaskState::Created,
            EventPayload::TaskDecided { .. } => TaskState::Decided,
            EventPayload::TaskStarted { .. } => TaskState::Running,
            EventPayload::TaskDelta { .. } => state, // deltas don't change state
            EventPayload::TaskProgress { .. } => state, // progress doesn't change state
            EventPayload::TaskSuspended { .. } => TaskState::Suspended,
            EventPayload::TaskResumed { .. } => TaskState::Running,
            EventPayload::TaskCompleted { .. } => TaskState::Completed,
            EventPayload::TaskFailed { .. } => TaskState::Failed,
            // Reconciled (Task 0.5): this special-cases `CancelReason::DaemonRestart`
            // into `Interrupted`, and `roundhouse_core::fold_task_state`
            // (`crates/roundhouse-core/src/task.rs`) now does the same, so the same
            // event row yields the same answer from either fold on this input. The two
            // folds remain distinct types otherwise (this one carries no
            // `SuspendReason` detail — it only needs enough state for recovery's
            // Created/Decided/Running detection).
            EventPayload::TaskCancelled { reason, .. } => match reason {
                roundhouse_core::CancelReason::DaemonRestart => TaskState::Interrupted,
                _ => TaskState::Cancelled,
            },
            // Phase 7 Task 13b (sanctioned lane-boundary exception, see the commit
            // message): a recorded `Loss` doesn't change whether the task is
            // created/running/terminal — it's a side-band annotation about fidelity,
            // not a lifecycle transition. Genuinely a no-op, but written down
            // deliberately rather than silently absorbed by the wildcard below.
            EventPayload::Loss { .. } => state,
            // Session-level and message/note events don't affect task state
            _ => state,
        };
    }

    Some(Task {
        id,
        session_id,
        kind,
        parent,
        state,
        origin,
    })
}
