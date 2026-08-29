use crate::delta::Delta as DeltaAlias;
use crate::event::{Event, EventPayload};
use crate::ids::{SessionId, TaskId};
use crate::session::{SessionOutcome, SessionSpec, SessionState};
use crate::task_kind::TaskKind;
use crate::task_meta::{
    CancelReason, Handle, IsolationAttestation, NoteLevel, Origin, PolicyDecision, Progress,
    RuleId, SuspendReason, TaskError, TaskInput, TaskOutput, Usage,
};
use crate::timestamp::Timestamp;
use std::sync::atomic::{AtomicBool, Ordering};

static BOOTSTRAPPED: AtomicBool = AtomicBool::new(false);

/// S-LOG-1's structural enforcement point: "every action an agent takes
/// produces exactly one Task record, enforced structurally... not by
/// convention." No task executor anywhere in the codebase can build an
/// `Event` for a task-lifecycle payload except through one of the
/// `record_*` methods below, because `Event`'s constructor lives in this
/// same crate and is not exposed (see `event.rs`'s `new_sealed`).
///
/// `TaskRunner` itself has a `pub(crate)` constructor — it cannot be
/// struct-literal-constructed from outside `roundhouse-core` either. The
/// one sanctioned way to obtain one from another crate is `bootstrap()`,
/// intended to be called exactly once, by `roundhouse-engine`, at daemon
/// startup, and threaded through the supervisor from there. A second call
/// panics rather than silently handing out a second authority.
pub struct TaskRunner {
    _priv: (),
}

impl TaskRunner {
    pub(crate) fn new() -> Self {
        TaskRunner { _priv: () }
    }

    /// The one public entry point. Panics if called more than once per
    /// process — see the module doc comment.
    pub fn bootstrap() -> Self {
        if BOOTSTRAPPED.swap(true, Ordering::SeqCst) {
            panic!(
                "TaskRunner::bootstrap() called more than once in this process — \
                 exactly one authority may mint Task records (S-LOG-1)"
            );
        }
        Self::new()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_task_created(
        &self,
        session_id: SessionId,
        seq: u64,
        ts: Timestamp,
        task_id: TaskId,
        kind: TaskKind,
        parent: Option<TaskId>,
        origin: Origin,
        input: TaskInput,
        schema_v: u16,
    ) -> Event {
        Event::new_sealed(
            session_id,
            seq,
            ts,
            Some(task_id),
            EventPayload::TaskCreated {
                kind,
                parent,
                origin,
                input,
            },
            schema_v,
        )
    }

    pub fn record_task_decided(
        &self,
        session_id: SessionId,
        seq: u64,
        ts: Timestamp,
        task_id: TaskId,
        decision: PolicyDecision,
        rule: Option<RuleId>,
        schema_v: u16,
    ) -> Event {
        Event::new_sealed(
            session_id,
            seq,
            ts,
            Some(task_id),
            EventPayload::TaskDecided { decision, rule },
            schema_v,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_task_started(
        &self,
        session_id: SessionId,
        seq: u64,
        ts: Timestamp,
        task_id: TaskId,
        isolation: IsolationAttestation,
        handle: Option<Handle>,
        schema_v: u16,
    ) -> Event {
        Event::new_sealed(
            session_id,
            seq,
            ts,
            Some(task_id),
            EventPayload::TaskStarted { isolation, handle },
            schema_v,
        )
    }

    pub fn record_task_delta(
        &self,
        session_id: SessionId,
        seq: u64,
        ts: Timestamp,
        task_id: TaskId,
        delta: DeltaAlias,
        schema_v: u16,
    ) -> Event {
        Event::new_sealed(
            session_id,
            seq,
            ts,
            Some(task_id),
            EventPayload::TaskDelta { delta },
            schema_v,
        )
    }

    pub fn record_task_progress(
        &self,
        session_id: SessionId,
        seq: u64,
        ts: Timestamp,
        task_id: TaskId,
        progress: Progress,
        schema_v: u16,
    ) -> Event {
        Event::new_sealed(
            session_id,
            seq,
            ts,
            Some(task_id),
            EventPayload::TaskProgress { progress },
            schema_v,
        )
    }

    pub fn record_task_suspended(
        &self,
        session_id: SessionId,
        seq: u64,
        ts: Timestamp,
        task_id: TaskId,
        reason: SuspendReason,
        schema_v: u16,
    ) -> Event {
        Event::new_sealed(
            session_id,
            seq,
            ts,
            Some(task_id),
            EventPayload::TaskSuspended { reason },
            schema_v,
        )
    }

    pub fn record_task_resumed(
        &self,
        session_id: SessionId,
        seq: u64,
        ts: Timestamp,
        task_id: TaskId,
        by: Origin,
        schema_v: u16,
    ) -> Event {
        Event::new_sealed(
            session_id,
            seq,
            ts,
            Some(task_id),
            EventPayload::TaskResumed { by },
            schema_v,
        )
    }

    pub fn record_task_completed(
        &self,
        session_id: SessionId,
        seq: u64,
        ts: Timestamp,
        task_id: TaskId,
        output: TaskOutput,
        usage: Usage,
        schema_v: u16,
    ) -> Event {
        Event::new_sealed(
            session_id,
            seq,
            ts,
            Some(task_id),
            EventPayload::TaskCompleted { output, usage },
            schema_v,
        )
    }

    pub fn record_task_failed(
        &self,
        session_id: SessionId,
        seq: u64,
        ts: Timestamp,
        task_id: TaskId,
        error: TaskError,
        retryable: bool,
        schema_v: u16,
    ) -> Event {
        Event::new_sealed(
            session_id,
            seq,
            ts,
            Some(task_id),
            EventPayload::TaskFailed { error, retryable },
            schema_v,
        )
    }

    pub fn record_task_cancelled(
        &self,
        session_id: SessionId,
        seq: u64,
        ts: Timestamp,
        task_id: TaskId,
        by: Origin,
        reason: CancelReason,
        schema_v: u16,
    ) -> Event {
        Event::new_sealed(
            session_id,
            seq,
            ts,
            Some(task_id),
            EventPayload::TaskCancelled { by, reason },
            schema_v,
        )
    }

    pub fn record_session_created(
        &self,
        session_id: SessionId,
        seq: u64,
        ts: Timestamp,
        spec: Box<SessionSpec>,
        schema_v: u16,
    ) -> Event {
        Event::new_sealed(
            session_id,
            seq,
            ts,
            None,
            EventPayload::SessionCreated { spec },
            schema_v,
        )
    }

    pub fn record_session_state_changed(
        &self,
        session_id: SessionId,
        seq: u64,
        ts: Timestamp,
        state: SessionState,
        reason: Option<String>,
        schema_v: u16,
    ) -> Event {
        Event::new_sealed(
            session_id,
            seq,
            ts,
            None,
            EventPayload::SessionStateChanged { state, reason },
            schema_v,
        )
    }

    pub fn record_session_closed(
        &self,
        session_id: SessionId,
        seq: u64,
        ts: Timestamp,
        outcome: SessionOutcome,
        schema_v: u16,
    ) -> Event {
        Event::new_sealed(
            session_id,
            seq,
            ts,
            None,
            EventPayload::SessionClosed { outcome },
            schema_v,
        )
    }

    pub fn record_note(
        &self,
        session_id: SessionId,
        seq: u64,
        ts: Timestamp,
        task_id: Option<TaskId>,
        level: NoteLevel,
        text: String,
        schema_v: u16,
    ) -> Event {
        Event::new_sealed(
            session_id,
            seq,
            ts,
            task_id,
            EventPayload::Note { level, text },
            schema_v,
        )
    }
}
