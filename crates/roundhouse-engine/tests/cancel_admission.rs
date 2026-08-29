//! Task 3: cooperative-cancellation admission refusal.
//!
//! `SessionActor` is a standalone, fully unit-tested unit — see its doc
//! comment in `crates/roundhouse-engine/src/session_actor.rs` for why this
//! task deliberately does NOT wire `admit_task` into any real dispatch
//! chokepoint (there isn't one yet).

use roundhouse_core::{CancelReason, EventPayload, Origin, SessionId, SessionState, TaskKind};
use roundhouse_engine::{AdmitError, SessionActor, TaskCreateRequest};
use roundhouse_store::{open, spawn_writer};

/// `TaskRunner::bootstrap()` panics on a second call per-process, and every
/// test in this binary shares one process — one shared `&'static TaskRunner`
/// for all tests here, matching `crates/roundhouse-store/tests/recovery.rs`.
static RUNNER: once_cell::sync::Lazy<roundhouse_core::TaskRunner> =
    once_cell::sync::Lazy::new(roundhouse_core::TaskRunner::bootstrap);

/// Spins up a fresh on-disk store + writer for one test, returning the
/// `SessionActor` under test plus the DB path so the test can open a second,
/// independent connection to verify what actually landed in the log.
async fn spawn_test_actor(
    initial_state: SessionState,
) -> (
    SessionActor,
    SessionId,
    std::path::PathBuf,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();
    let actor = SessionActor::new(session_id, writer, initial_state);

    (actor, session_id, db_path, dir)
}

#[tokio::test]
async fn cancelling_session_refuses_new_non_finally_tasks() {
    let (actor, _session_id, _db_path, _dir) = spawn_test_actor(SessionState::Running).await;

    actor.cancel(&RUNNER, CancelReason::User).await.unwrap();

    let normal = TaskCreateRequest {
        kind: TaskKind::Shell,
        origin: Origin::Model,
        is_finally_step: false,
    };
    let err = actor.admit_task(&normal).unwrap_err();
    assert!(matches!(err, AdmitError::SessionCancelling));

    let finally_step = TaskCreateRequest {
        kind: TaskKind::Shell,
        origin: Origin::System,
        is_finally_step: true,
    };
    assert!(
        actor.admit_task(&finally_step).is_ok(),
        "finally steps must still be admitted while Cancelling"
    );
}

#[tokio::test]
async fn admit_task_allows_everything_before_cancel_is_called() {
    let (actor, _session_id, _db_path, _dir) = spawn_test_actor(SessionState::Running).await;

    let normal = TaskCreateRequest {
        kind: TaskKind::Shell,
        origin: Origin::Model,
        is_finally_step: false,
    };
    assert!(
        actor.admit_task(&normal).is_ok(),
        "a session that hasn't been cancelled must admit ordinary tasks"
    );

    let finally_step = TaskCreateRequest {
        kind: TaskKind::Shell,
        origin: Origin::System,
        is_finally_step: true,
    };
    assert!(actor.admit_task(&finally_step).is_ok());
}

#[tokio::test]
async fn cancel_transitions_state_to_cancelling() {
    let (actor, _session_id, _db_path, _dir) = spawn_test_actor(SessionState::Running).await;

    assert_eq!(actor.state(), SessionState::Running);

    actor.cancel(&RUNNER, CancelReason::User).await.unwrap();

    assert_eq!(actor.state(), SessionState::Cancelling);
}

#[tokio::test]
async fn cancel_persists_session_state_changed_event_to_the_store() {
    let (actor, session_id, db_path, _dir) = spawn_test_actor(SessionState::Running).await;

    actor.cancel(&RUNNER, CancelReason::User).await.unwrap();

    // Open an independent connection to the same on-disk DB to verify the
    // event actually landed — not just that in-memory state changed. This
    // would catch a bug where `state_tx.send_replace` runs but
    // `writer.append` silently failed or was skipped.
    let query_store = open(&db_path).await.unwrap();
    let conn = query_store.pool.get().await.unwrap();
    let rows: Vec<String> = conn
        .interact(move |c| {
            let mut stmt = c
                .prepare("SELECT payload FROM events WHERE session_id = ?1 ORDER BY seq")
                .unwrap();
            stmt.query_map([session_id.to_string()], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        })
        .await
        .unwrap();

    assert_eq!(rows.len(), 1, "cancel() must append exactly one event");

    let payload: EventPayload = serde_json::from_str(&rows[0]).unwrap();
    match payload {
        EventPayload::SessionStateChanged { state, .. } => {
            assert_eq!(state, SessionState::Cancelling);
        }
        other => panic!("expected SessionStateChanged, got {other:?}"),
    }
}

/// Security-audit fix: `cancel()` must fail CLOSED, not open — the
/// in-memory gate flips to `Cancelling` *before* the durable append is even
/// attempted, so a failed (or merely slow) append can never leave
/// `admit_task` still admitting new work. This is proven structurally, not
/// by injecting a fake `StoreError`: `cancel`'s body calls
/// `state_tx.send_replace` as its first statement, then `runner.record_session_state_changed`
/// (pure, synchronous), and only then `.await`s the actual append — so a
/// SINGLE manual `poll()` of the returned future executes every synchronous
/// statement up to (but not including) that first real suspension point
/// inside `writer.append` (the oneshot reply from the writer task, which
/// genuinely cannot be ready on the first poll since the separate writer
/// task hasn't run yet). If the future is still `Pending` after exactly one
/// poll, `state()` reading `Cancelling` at that point proves the gate closed
/// strictly before the append could possibly have completed — success,
/// failure, or otherwise.
#[tokio::test]
async fn cancel_flips_the_admission_gate_before_the_append_can_possibly_complete() {
    use std::future::Future;
    use std::task::{Context, Poll};

    let (actor, _session_id, _db_path, _dir) = spawn_test_actor(SessionState::Running).await;

    let mut fut = Box::pin(actor.cancel(&RUNNER, CancelReason::User));

    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let poll_result = fut.as_mut().poll(&mut cx);

    assert_eq!(
        actor.state(),
        SessionState::Cancelling,
        "the admission gate must already be closed after a single poll of cancel(), \
         strictly before the durable append can have completed"
    );

    // Drive the future to completion so the test doesn't leave a half-driven
    // append dangling against the shared writer task.
    match poll_result {
        Poll::Pending => fut.await.unwrap(),
        Poll::Ready(result) => result.unwrap(),
    }
}

/// Security-audit fix: `admit_task` is now an allowlist. A `Closed` session
/// must refuse an ordinary task exactly like a `Cancelling` one — the old
/// denylist (`if state == Cancelling`) let every other terminal/paused state
/// admit anything, including a session rehydrated as already `Closed`.
#[tokio::test]
async fn closed_session_refuses_ordinary_tasks() {
    let (actor, _session_id, _db_path, _dir) = spawn_test_actor(SessionState::Closed).await;

    let normal = TaskCreateRequest {
        kind: TaskKind::Shell,
        origin: Origin::Model,
        is_finally_step: false,
    };
    let err = actor.admit_task(&normal).unwrap_err();
    assert!(matches!(err, AdmitError::SessionClosed));
}

/// Same allowlist fix, for `Suspended`.
#[tokio::test]
async fn suspended_session_refuses_ordinary_tasks() {
    let (actor, _session_id, _db_path, _dir) = spawn_test_actor(SessionState::Suspended).await;

    let normal = TaskCreateRequest {
        kind: TaskKind::Shell,
        origin: Origin::Model,
        is_finally_step: false,
    };
    let err = actor.admit_task(&normal).unwrap_err();
    assert!(matches!(err, AdmitError::SessionSuspended));
}

/// Security-audit fix: `is_finally_step: true` is only a trusted bypass when
/// `origin == Origin::System` — a claimed finally-step from any other origin
/// (e.g. `Origin::Model`) is evaluated as an ordinary task and refused just
/// like one, even though the boolean itself is set.
#[tokio::test]
async fn finally_step_bypass_is_refused_unless_origin_is_system() {
    let (actor, _session_id, _db_path, _dir) = spawn_test_actor(SessionState::Closed).await;

    let untrusted_finally_step = TaskCreateRequest {
        kind: TaskKind::Shell,
        origin: Origin::Model,
        is_finally_step: true,
    };
    let err = actor.admit_task(&untrusted_finally_step).unwrap_err();
    assert!(
        matches!(err, AdmitError::SessionClosed),
        "a finally-step claim from a non-System origin must not bypass the gate"
    );

    let trusted_finally_step = TaskCreateRequest {
        kind: TaskKind::Shell,
        origin: Origin::System,
        is_finally_step: true,
    };
    assert!(
        actor.admit_task(&trusted_finally_step).is_ok(),
        "a genuine (Origin::System) finally-step must still be admitted even when Closed"
    );
}
