//! §6.8, Phase 8 Task 25.5 (#62) Task 4 — "a child session's taint is seeded
//! from its parent's current `TaintSet` at spawn time," proven against the
//! **real** `DaemonSubAgentHost` (`sub_agent_host::wire_sub_agent_host`),
//! not a test double: `roundhouse-engine`'s own `agent_tool_spawn.rs` proves
//! the *request* the implementor receives carries the parent's real taint;
//! this proves the real implementor actually applies it to the child
//! `SessionActor` it constructs.

mod common;

use std::sync::Arc;

use roundhouse_core::{SessionId, SessionSpec, SessionState, Tier};
use roundhouse_daemon::session_bootstrap::PolicyRuleSource;
use roundhouse_daemon::session_registry::SessionRegistry;
use roundhouse_daemon::sub_agent_host::wire_sub_agent_host;
use roundhouse_engine::tools::agent_spawn_tool::dispatch_agent;
use roundhouse_engine::SessionActor;
use roundhouse_policy::engine::{CompiledRule, Outcome, PolicyEngine, Predicate, Scope};

fn allow_agent_rules() -> PolicyRuleSource {
    Arc::new(|| {
        vec![CompiledRule::test_new(
            Scope::Project,
            Outcome::Allow,
            Predicate::agent(None, None, Tier::None),
        )]
    })
}

async fn parent_actor(dir: &std::path::Path) -> Arc<SessionActor> {
    let store = roundhouse_store::open(&dir.join("events.db"))
        .await
        .unwrap();
    let writer = roundhouse_store::spawn_writer(store).await;
    let policy = Arc::new(PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Project,
        Outcome::Allow,
        Predicate::agent(None, None, Tier::None),
    )]));
    let isolate = common::available_isolate();
    let spec = SessionSpec::test_requesting(Tier::Sandbox, roundhouse_core::OnDegrade::Refuse);
    let handle = isolate.prepare(&spec).await.unwrap();
    Arc::new(SessionActor::new_with_workspace_root(
        SessionId::new(),
        writer,
        SessionState::Running,
        common::runner(),
        policy,
        dir.join("state"),
        dir.join("daemon-binary"),
        dir.canonicalize().unwrap(),
        isolate,
        handle,
        spec,
        roundhouse_engine::tool_catalog::builtin_tool_defs(),
    ))
}

fn agent_args() -> serde_json::Value {
    serde_json::json!({
        "prompt": "review the diff",
        "provider": "anthropic",
        "budget_tokens": 10,
    })
}

async fn spawn_one_child(tainted_parent: bool) -> Arc<SessionActor> {
    let dir = tempfile::tempdir().unwrap();
    let resources = common::resources_with(
        dir.path(),
        common::available_isolate(),
        Arc::new(common::NoopProvider),
        allow_agent_rules(),
    )
    .await;
    let registry = Arc::new(SessionRegistry::new());
    let actor = parent_actor(dir.path()).await;
    let parent = actor.session_id();
    if tainted_parent {
        actor.mark_tainted();
    }
    wire_sub_agent_host(&actor, &resources, &registry);
    let host = actor
        .sub_agent_host()
        .expect("the host was just registered");

    dispatch_agent(
        &actor,
        actor.writer(),
        common::runner(),
        Some(&host),
        &agent_args(),
        roundhouse_core::TaskId::new(),
    )
    .await
    .expect("the spawn must succeed under an allow rule");

    let child = resources
        .spawn_tree
        .descendants(parent)
        .into_iter()
        .next()
        .expect("exactly one real child was spawned");
    registry
        .actor(child)
        .expect("the real child session must be registered")
}

#[tokio::test]
async fn a_tainted_parent_seeds_its_real_child_sessions_taint() {
    let child_actor = spawn_one_child(true).await;
    assert_eq!(
        child_actor.current_taint(),
        roundhouse_policy::Taint::Tainted,
        "a tainted parent's real spawned child must start tainted too"
    );
}

#[tokio::test]
async fn a_clean_parent_seeds_an_untainted_real_child_session() {
    let child_actor = spawn_one_child(false).await;
    assert_eq!(
        child_actor.current_taint(),
        roundhouse_policy::Taint::Trusted,
        "a clean parent's real spawned child must start untainted"
    );
}
