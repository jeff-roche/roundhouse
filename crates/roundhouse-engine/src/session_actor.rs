//! Cooperative cancellation (Phase 2, Task 3): a `SessionActor` tracks one
//! session's `SessionState` and, via an allowlist, refuses admission of new,
//! non-`finally:` tasks once that session has left `Created`/`Running`
//! (i.e. `Suspended`, `Cancelling`, or `Closed`).
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
//!
//! Phase 2, Task 4 adds [`SessionActor::run_finally_steps`] to this same
//! file (not a separate `cancel.rs` — this module is `SessionActor`'s home).
//! It reuses `admit_task` for real, but same as above, still doesn't reach
//! into a real dispatch chokepoint for *executing* a step — that's injected
//! by the caller, for the same "Task 25 doesn't exist yet" reason.

use roundhouse_core::{
    CancelReason, Origin, SessionId, SessionState, TaskInput, TaskKind, TaskRunner, Timestamp,
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
    #[error("session is Cancelling; only a trusted finally: step is admitted")]
    SessionCancelling,
    #[error("session is Suspended; only a trusted finally: step is admitted")]
    SessionSuspended,
    #[error("session is Closed; only a trusted finally: step is admitted")]
    SessionClosed,
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

    /// Flip the in-memory admission gate to `Cancelling`, then mint and
    /// append a `SessionStateChanged { state: Cancelling, .. }` event
    /// through `runner` (the sole authority that may mint session-lifecycle
    /// events — see `roundhouse_core::TaskRunner`'s doc comment).
    ///
    /// **Fail-closed, not fail-open:** the gate (`state_tx`) is flipped
    /// *before* the durable append is even attempted, not after. If the
    /// append below fails (writer task shut down, pool exhaustion, a
    /// non-busy sqlite error surviving the retry loop), `admit_task` is
    /// already refusing new non-finally work by the time this function
    /// returns `Err` — the error still propagates to the caller (so failed
    /// persistence is loud, never silently swallowed), but a persistence
    /// failure can never leave the gate open. The same ordering also closes
    /// a narrower window that existed under the old (fail-open)
    /// append-then-signal ordering: the append is a cross-task channel
    /// round-trip plus a SQLite transaction (with possible busy-retry
    /// backoff) that can take anywhere from microseconds to seconds, during
    /// which a signal-after-append design would have let `admit_task` keep
    /// admitting new work even on the eventual success path. Note this is
    /// SQLite in WAL mode with `synchronous=NORMAL` (see `roundhouse_store::
    /// open`'s doc comment) — not fsync'd on every write — so "appended"
    /// here means "written to the write-ahead log," not "survives an
    /// OS-level power loss"; it is not a claim of strict durability.
    pub async fn cancel(
        &self,
        runner: &TaskRunner,
        reason: CancelReason,
    ) -> Result<(), StoreError> {
        self.state_tx.send_replace(SessionState::Cancelling);

        let event = runner.record_session_state_changed(
            self.session_id,
            0, // ignored — EventWriter::append assigns the real per-session seq
            now_ts(),
            SessionState::Cancelling,
            // `CancelReason` has no `Display` impl and no established
            // stringification convention exists elsewhere in this codebase
            // for this free-text field, so its `Debug` rendering (e.g.
            // "User") is used deliberately here — NOT a placeholder. This is
            // distinct from `TaskCancelled.reason`, which stores the typed
            // `CancelReason` itself rather than a string. Because this value
            // is written into the append-only event log, renaming a
            // `CancelReason` variant will silently change the text of
            // already-persisted historical events' `reason` field.
            Some(format!("{reason:?}")),
            1,
        );
        self.writer.append(event).await?;
        Ok(())
    }

    /// Admit or refuse a new task, gated on the session's current state.
    ///
    /// Deliberately an **allowlist**, not a denylist: only `Created` and
    /// `Running` admit an ordinary (non-finally-step) task. Every other
    /// state — `Suspended`, `Cancelling`, `Closed`, and any variant added to
    /// `SessionState` in the future — refuses one by default, so a new
    /// variant this match doesn't yet know about fails closed rather than
    /// silently admitting work into (for example) a terminated session.
    ///
    /// A `finally:` cleanup step is only honored as a trusted bypass of that
    /// refusal when `req.origin == Origin::System` — `is_finally_step` is a
    /// caller-asserted boolean with nothing else tying it to provenance, so
    /// honoring it regardless of origin would make cancellation merely
    /// advisory the moment any model-influenced caller sets it. A
    /// `finally_step` claim from any other origin is evaluated as an
    /// ordinary task for gating purposes — the bypass simply doesn't apply,
    /// it is not a hard error.
    pub fn admit_task(&self, req: &TaskCreateRequest) -> Result<(), AdmitError> {
        let trusted_finally_step = req.is_finally_step && req.origin == Origin::System;

        match self.state() {
            SessionState::Created | SessionState::Running => Ok(()),
            _ if trusted_finally_step => Ok(()),
            SessionState::Cancelling => Err(AdmitError::SessionCancelling),
            SessionState::Suspended => Err(AdmitError::SessionSuspended),
            SessionState::Closed => Err(AdmitError::SessionClosed),
        }
    }

    /// Runs each `finally:` step in order, even while this session is
    /// `Cancelling` (or `Suspended`/`Closed`) — `admit_task` (above)
    /// special-cases `is_finally_step: true` + `Origin::System` precisely so
    /// this path is legal, and every step here is admitted through that
    /// real check, not a bypass around it.
    ///
    /// `execute` is injected rather than hardcoded against a real dispatch
    /// chokepoint: as of this task, `roundhouse-engine` still has no unified
    /// task-execution entry point (see this module's doc comment — the same
    /// gap Task 3 already documented and worked around). Inventing a fake
    /// one here (e.g. a `TaskRunner::execute`/`executor_for` pair that
    /// doesn't exist anywhere in this codebase) would paper over that gap
    /// instead of leaving it honestly for the later integration task that
    /// owns wiring a real executor in ("Task 25" in the Phase 2 plan).
    ///
    /// Stops at the first step whose admission or execution fails — later
    /// steps are never attempted once an earlier one has failed, so a
    /// partially-run `finally:` sequence is always reported as an error
    /// rather than silently treated as complete.
    pub async fn run_finally_steps<F, Fut>(
        &self,
        steps: Vec<FinallySpec>,
        execute: F,
    ) -> Result<(), FinallyStepError>
    where
        F: Fn(FinallySpec) -> Fut,
        Fut: std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>,
    {
        for step in steps {
            let req = TaskCreateRequest {
                kind: step.kind.clone(),
                origin: Origin::System,
                is_finally_step: true,
            };
            self.admit_task(&req)?;
            execute(step).await.map_err(FinallyStepError::Execute)?;
        }
        Ok(())
    }
}

/// One `finally:`/cleanup step to be run by [`SessionActor::run_finally_steps`].
#[derive(Debug, Clone)]
pub struct FinallySpec {
    pub kind: TaskKind,
    pub input: TaskInput,
}

/// Failure modes for [`SessionActor::run_finally_steps`].
#[derive(Debug, thiserror::Error)]
pub enum FinallyStepError {
    #[error("finally step refused by admission gate: {0}")]
    Admit(#[from] AdmitError),
    #[error("finally step execution failed: {0}")]
    Execute(Box<dyn std::error::Error + Send + Sync>),
}
