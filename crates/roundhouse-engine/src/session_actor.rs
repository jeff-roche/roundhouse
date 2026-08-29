//! Cooperative cancellation (Phase 2, Task 3): a `SessionActor` tracks one
//! session's `SessionState` and refuses admission of new, non-`finally:`
//! tasks once that session has moved to `SessionState::Cancelling`.
//!
//! **Scope note — read before wiring this in anywhere:** this is a correct,
//! fully unit-tested, standalone unit, *not* wired into any real dispatch
//! chokepoint. As of this task, `roundhouse-engine` has no unified
//! task-execution entry point — the only real driver is
//! [`crate::run_chat_turn`] in `chat.rs`, and tool executors are invoked ad
//! hoc from `roundhouse-daemon`'s demo wiring with no policy/sandbox gate in
//! front of the real executors yet. Threading `admit_task` in front of those
//! real call sites (chat turns, tool calls) is deferred to a later
//! integration task ("Task 25" — "Integration — wire the sealed floor and
//! network policy into the real task-admission path"), which already exists
//! specifically to thread multiple Phase 2 policy/admission mechanisms into
//! real call sites; cancellation admission-refusal fits the same umbrella.
//! Don't assume more integration happened here than did.

use roundhouse_core::{
    CancelReason, Origin, SessionId, SessionState, TaskKind, TaskRunner, Timestamp,
};
use roundhouse_store::{EventWriter, StoreError};

/// `Timestamp` has no `now()` — read the wall clock ourselves and convert.
/// Matches the identical helper in `chat.rs`/`roundhouse-store/tests/recovery.rs`.
fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

/// A request to admit a new task for execution, checked against the owning
/// session's current cancellation state by [`SessionActor::admit_task`].
#[derive(Debug, Clone)]
pub struct TaskCreateRequest {
    pub kind: TaskKind,
    pub origin: Origin,
    /// `true` for a workflow/session `finally:` cleanup step. Cooperative
    /// cancellation (§8) must still let these run even while the owning
    /// session is `Cancelling` — that's the entire point of admission
    /// refusal being scoped to *new*, non-cleanup work.
    pub is_finally_step: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum AdmitError {
    #[error("session is Cancelling; only finally: steps are admitted")]
    SessionCancelling,
}

/// Tracks one session's `SessionState` and gates new-task admission on it.
///
/// Deliberately does not hold a `TaskRunner` field: `TaskRunner` is not
/// `Clone` and is meant to be a single process-wide singleton obtained once
/// via `TaskRunner::bootstrap()`. Wiring a shared `TaskRunner` into every
/// `SessionActor` instance is real production-wiring work left to Task 25;
/// for now `cancel` takes `runner: &TaskRunner` as a parameter, matching the
/// existing convention elsewhere in this codebase (e.g.
/// `recover_interrupted_tasks(store, writer, runner)`).
pub struct SessionActor {
    session_id: SessionId,
    writer: EventWriter,
    state_tx: tokio::sync::watch::Sender<SessionState>,
}

impl SessionActor {
    pub fn new(session_id: SessionId, writer: EventWriter, initial_state: SessionState) -> Self {
        let (state_tx, _rx) = tokio::sync::watch::channel(initial_state);
        SessionActor {
            session_id,
            writer,
            state_tx,
        }
    }

    /// The session's current state, as of the last `cancel()` call (or
    /// whatever `initial_state` was constructed with, if none yet).
    pub fn state(&self) -> SessionState {
        self.state_tx.borrow().clone()
    }

    /// A clone-able observer of session-state transitions. Exposed now so a
    /// later task (Task 4's shell cancellation, or Task 25's integration)
    /// can subscribe to cancellation without this task needing to know who
    /// its future consumers are.
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<SessionState> {
        self.state_tx.subscribe()
    }

    /// Mint and append a `SessionStateChanged { state: Cancelling, .. }`
    /// event through `runner` (the sole authority that may mint
    /// session-lifecycle events — see `roundhouse_core::TaskRunner`'s doc
    /// comment), then publish the new state to `state_tx` once the append
    /// has durably succeeded. Publishing only after a successful append
    /// means a caller who observes `state() == Cancelling` is guaranteed the
    /// event is already in the log, not just in memory.
    pub async fn cancel(
        &self,
        runner: &TaskRunner,
        reason: CancelReason,
    ) -> Result<(), StoreError> {
        let event = runner.record_session_state_changed(
            self.session_id,
            0,
            now_ts(),
            SessionState::Cancelling,
            Some(format!("{reason:?}")),
            1,
        );
        self.writer.append(event).await?;
        self.state_tx.send_replace(SessionState::Cancelling);
        Ok(())
    }

    /// Refuse admission of new tasks once the session is `Cancelling`,
    /// except `finally:` cleanup steps, which must still run to completion
    /// (§8's cooperative-cancellation model).
    pub fn admit_task(&self, req: &TaskCreateRequest) -> Result<(), AdmitError> {
        if self.state() == SessionState::Cancelling && !req.is_finally_step {
            return Err(AdmitError::SessionCancelling);
        }
        Ok(())
    }
}
