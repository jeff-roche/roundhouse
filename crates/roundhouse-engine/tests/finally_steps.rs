//! Phase 2, Task 4: `SessionActor::run_finally_steps` — runs cleanup steps
//! through the real `admit_task` admission gate (Task 3) even while a
//! session is `Cancelling`/`Suspended`/`Closed`, with the actual
//! step-execution logic injected by the caller. There is still no unified
//! task-dispatch chokepoint in this codebase for `run_finally_steps` to call
//! into directly — see `session_actor.rs`'s module doc comment (Task 3) for
//! why that's a deliberate, documented gap rather than an oversight here.

use std::sync::{Arc, Mutex};

use roundhouse_core::{
    OnDegrade, Origin, SessionId, SessionSpec, SessionState, TaskInput, TaskKind, Tier,
};
use roundhouse_engine::{FinallySpec, FinallyStepError, SessionActor, TaskCreateRequest};
use roundhouse_policy::engine::{
    CompiledRule, Outcome as PolicyOutcome, PolicyEngine, Predicate, Scope,
};
use roundhouse_policy::{ParsedCommand, TaskParams};
use roundhouse_sandbox::isolate::BwrapLandlockIsolate;
use roundhouse_sandbox::probe::{MechanismProbeReport, MechanismStatus};
use roundhouse_sandbox::Isolate;
use roundhouse_store::{open, spawn_writer};

/// `TaskRunner::bootstrap()` panics on a second call per-process — one
/// shared `&'static TaskRunner` for all tests here, matching
/// `cancel_admission.rs`.
static RUNNER: once_cell::sync::Lazy<roundhouse_core::TaskRunner> =
    once_cell::sync::Lazy::new(roundhouse_core::TaskRunner::bootstrap);

/// Permissive `TaskParams` for a finally-step/ordinary shell request — see
/// `cancel_admission.rs`'s identically-purposed helper for why this file's
/// pre-existing `SessionState`-gate tests use a placeholder that Task 25's
/// new policy gate always `Outcome::Allow`s.
fn permissive_params() -> TaskParams {
    TaskParams::Shell(ParsedCommand {
        program: "true".to_string(),
        argv: vec![],
    })
}

async fn spawn_test_actor(initial_state: SessionState) -> (SessionActor, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    // See `cancel_admission.rs`'s identical helper for why a single
    // permissive rule (rather than zero rules) is needed here: with zero
    // rules, `PolicyEngine::decide`'s unmatched-task default is `Ask`, not
    // `Allow`.
    let policy = Arc::new(PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Builtin,
        PolicyOutcome::Allow,
        Predicate::program("true"),
    )]));
    let isolate: Arc<dyn Isolate> = Arc::new(BwrapLandlockIsolate::test_with_probe(
        MechanismProbeReport {
            landlock: MechanismStatus::Available,
            bwrap: MechanismStatus::Available,
            seccomp: MechanismStatus::Available,
            seatbelt: MechanismStatus::Unavailable {
                reason: "n/a".into(),
            },
        },
    ));
    let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
    let handle = isolate.prepare(&spec).await.unwrap();
    // `SessionActor::new` fail-closed asserts these are absolute, non-empty
    // paths — see `cancel_admission.rs`'s identical helper for why.
    let actor = SessionActor::new(
        SessionId::new(),
        writer,
        initial_state,
        &RUNNER,
        policy,
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        isolate,
        handle,
        spec,
    );
    (actor, dir)
}

fn spec(kind: TaskKind) -> FinallySpec {
    FinallySpec {
        kind,
        input: TaskInput::Text(String::new()),
        params: permissive_params(),
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
            params: permissive_params(),
        };
        assert!(
            actor.admit_task(&ordinary).await.is_err(),
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
