//! §6.8's taint-gated autonomy, wired into the real admission gate — Phase 8
//! Task 25.5 (#62) Task 4. `roundhouse-policy`'s own
//! `taint_gated_grants.rs` proves the downgrade in isolation
//! (`PolicyEngine::decide_sealed`); this proves `SessionActor::admit_task`
//! actually reaches it with a real, live, session-scoped taint value rather
//! than a hardcoded one.

use std::sync::Arc;

use roundhouse_core::{OnDegrade, Origin, SessionId, SessionSpec, SessionState, Tier};
use roundhouse_engine::{AdmitError, SessionActor, TaskCreateRequest};
use roundhouse_policy::engine::{CompiledRule, Outcome, PolicyEngine, Predicate, Scope};
use roundhouse_policy::TaskParams;
use roundhouse_sandbox::{
    Attestation, Child, CommandSpec, Handle, Isolate, IsolationError, ProbeResult,
};
use roundhouse_store::{open, spawn_writer};

static RUNNER: once_cell::sync::Lazy<roundhouse_core::TaskRunner> =
    once_cell::sync::Lazy::new(roundhouse_core::TaskRunner::bootstrap);

struct TestIsolate;

#[async_trait::async_trait]
impl Isolate for TestIsolate {
    fn declared(&self) -> Tier {
        Tier::Sandbox
    }
    async fn probe(&self) -> ProbeResult {
        ProbeResult {
            achieved: Tier::Sandbox,
            degradations: vec![],
        }
    }
    async fn prepare(&self, _spec: &SessionSpec) -> Result<Handle, IsolationError> {
        Ok(Handle {
            id: "test-isolate".into(),
        })
    }
    async fn spawn(
        &self,
        _handle: &Handle,
        _command: CommandSpec,
    ) -> Result<Child, IsolationError> {
        unreachable!("this fixture never dispatches a real task")
    }
    fn attest(&self, _handle: &Handle) -> Attestation {
        Attestation {
            tier: Tier::Sandbox,
            digest: "test-isolate".into(),
            net_enforced: false,
        }
    }
    async fn teardown(&self, _handle: Handle) -> Result<(), IsolationError> {
        Ok(())
    }
}

/// A standing grant for `git push` — shaped exactly like
/// `approval::synthesize_grant`'s real output (`id: "grant:..."`), which is
/// the only shape §6.8's downgrade recognizes.
fn git_push_grant() -> CompiledRule {
    CompiledRule::test_new_with_id(
        Scope::Grant,
        Outcome::Allow,
        Predicate::git("push", &[]),
        "grant:session-1:task-1",
    )
}

fn git_push_request() -> TaskCreateRequest {
    TaskCreateRequest {
        kind: roundhouse_core::TaskKind::Git,
        origin: Origin::Model,
        is_finally_step: false,
        params: TaskParams::Git {
            subcommand: "push".into(),
            argv: vec!["origin".into(), "main".into()],
            remote: Some("origin".into()),
        },
    }
}

async fn actor(dir: &std::path::Path) -> SessionActor {
    let store = open(&dir.join("events.db")).await.unwrap();
    let writer = spawn_writer(store).await;
    let policy = Arc::new(PolicyEngine::from_rules(vec![git_push_grant()]));
    let isolate: Arc<dyn Isolate> = Arc::new(TestIsolate);
    let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
    let handle = isolate.prepare(&spec).await.unwrap();
    SessionActor::new_with_workspace_root(
        SessionId::new(),
        writer,
        SessionState::Running,
        &RUNNER,
        policy,
        dir.join("state"),
        dir.join("daemon-binary"),
        std::env::current_dir().unwrap(),
        isolate,
        handle,
        spec,
        vec![],
    )
}

#[tokio::test]
async fn a_fresh_session_is_untainted_and_its_standing_grant_is_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let actor = actor(dir.path()).await;
    let result = actor.admit_task(&git_push_request()).await;
    assert!(
        result.is_ok(),
        "a fresh session's standing git-push grant must be admitted, got {result:?}"
    );
}

#[tokio::test]
async fn a_tainted_session_downgrades_its_own_standing_grant_to_requires_approval() {
    let dir = tempfile::tempdir().unwrap();
    let actor = actor(dir.path()).await;
    actor.mark_tainted();
    let result = actor.admit_task(&git_push_request()).await;
    assert!(
        matches!(result, Err(AdmitError::RequiresApproval)),
        "a tainted session's standing grant must downgrade to Ask, got {result:?}"
    );
}

#[tokio::test]
async fn resetting_for_a_human_turn_clears_a_prior_taint_mark() {
    let dir = tempfile::tempdir().unwrap();
    let actor = actor(dir.path()).await;
    actor.mark_tainted();
    actor.reset_taint_for_human_turn();
    let result = actor.admit_task(&git_push_request()).await;
    assert!(
        result.is_ok(),
        "a reset session's standing grant must be admitted again, got {result:?}"
    );
}
