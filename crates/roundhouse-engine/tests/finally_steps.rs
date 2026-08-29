//! Phase 2, Task 4: `SessionActor::run_finally_steps` — runs cleanup steps
//! through the real `admit_task` admission gate (Task 3) even while a
//! session is `Cancelling`/`Suspended`/`Closed`, with the actual
//! step-execution logic injected by the caller. There is still no unified
//! task-dispatch chokepoint in this codebase for `run_finally_steps` to call
//! into directly — see `session_actor.rs`'s module doc comment (Task 3) for
//! why that's a deliberate, documented gap rather than an oversight here.

use std::sync::{Arc, Mutex};

use roundhouse_core::{Origin, SessionId, SessionState, TaskInput, TaskKind};
use roundhouse_engine::{FinallySpec, FinallyStepError, SessionActor, TaskCreateRequest};
use roundhouse_store::{open, spawn_writer};

async fn spawn_test_actor(initial_state: SessionState) -> (SessionActor, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    let actor = SessionActor::new(SessionId::new(), writer, initial_state);
    (actor, dir)
}

fn spec(kind: TaskKind) -> FinallySpec {
    FinallySpec {
        kind,
        input: TaskInput::Text(String::new()),
    }
}

#[tokio::test]
async fn runs_steps_in_order_via_the_injected_executor() {
    let (actor, _dir) = spawn_test_actor(SessionState::Running).await;

    let seen: Arc<Mutex<Vec<TaskKind>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_for_exec = seen.clone();

    let steps = vec![
        spec(TaskKind::Shell),
        spec(TaskKind::Write),
        spec(TaskKind::Read),
    ];

    actor
        .run_finally_steps(steps, move |step: FinallySpec| {
            let seen = seen_for_exec.clone();
            async move {
                seen.lock().unwrap().push(step.kind);
                Ok(())
            }
        })
        .await
        .unwrap();

    assert_eq!(
        *seen.lock().unwrap(),
        vec![TaskKind::Shell, TaskKind::Write, TaskKind::Read],
        "steps must be admitted and executed in the order given"
    );
}

#[tokio::test]
async fn finally_steps_still_run_when_the_session_would_refuse_an_ordinary_task() {
    for state in [
        SessionState::Cancelling,
        SessionState::Closed,
        SessionState::Suspended,
    ] {
        let (actor, _dir) = spawn_test_actor(state.clone()).await;

        // Sanity: this is genuinely a state that refuses ordinary work —
        // otherwise this test wouldn't be proving the bypass does anything.
        let ordinary = TaskCreateRequest {
            kind: TaskKind::Shell,
            origin: Origin::Model,
            is_finally_step: false,
        };
        assert!(
            actor.admit_task(&ordinary).is_err(),
            "test setup bug: {state:?} should refuse ordinary tasks"
        );

        let executed = Arc::new(Mutex::new(false));
        let executed_for_exec = executed.clone();

        actor
            .run_finally_steps(vec![spec(TaskKind::Shell)], move |_step| {
                let executed = executed_for_exec.clone();
                async move {
                    *executed.lock().unwrap() = true;
                    Ok(())
                }
            })
            .await
            .unwrap_or_else(|e| panic!("finally step must be admitted while {state:?}: {e}"));

        assert!(
            *executed.lock().unwrap(),
            "finally step must actually execute while {state:?}"
        );
    }
}

#[tokio::test]
async fn stops_at_the_first_step_whose_execution_fails() {
    let (actor, _dir) = spawn_test_actor(SessionState::Running).await;

    let seen: Arc<Mutex<Vec<TaskKind>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_for_exec = seen.clone();

    let steps = vec![
        spec(TaskKind::Shell),
        spec(TaskKind::Write),
        spec(TaskKind::Read),
    ];

    let err = actor
        .run_finally_steps(steps, move |step: FinallySpec| {
            let seen = seen_for_exec.clone();
            async move {
                if step.kind == TaskKind::Write {
                    return Err("boom".into());
                }
                seen.lock().unwrap().push(step.kind);
                Ok(())
            }
        })
        .await
        .unwrap_err();

    assert!(matches!(err, FinallyStepError::Execute(_)));
    assert_eq!(
        *seen.lock().unwrap(),
        vec![TaskKind::Shell],
        "execution must stop at the first failing step, not continue to later ones"
    );
}
