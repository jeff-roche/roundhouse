//! The daemon-level seam for the spawn tree's boot recovery
//! (`roundhouse_daemon::boot::reconcile_spawn_tree_at_boot`): a real store on
//! disk, opened the way `main.rs` opens it, read back through the real pool.
//!
//! The scan's own behaviour — both child kinds, the terminal filter, the
//! documented sub-agent gap — is covered where it lives, in
//! `roundhouse-daemon`'s `workflow_host` and `sub_agent_host` unit tests. This
//! file proves only that the boot seam wires it to the daemon's one shared
//! tree and reports what it restored.

mod common;

use std::sync::Arc;

use roundhouse_bus::spawn_tree::SpawnTree;
use roundhouse_core::{
    OnDegrade, SessionId, SessionOutcome, SessionSpec, SessionState, TaskId, Tier, Timestamp,
};
use roundhouse_daemon::boot::reconcile_spawn_tree_at_boot;
use roundhouse_daemon::session_bootstrap::PolicyRuleSource;
use roundhouse_daemon::session_registry::SessionRegistry;
use roundhouse_daemon::sub_agent_host::wire_sub_agent_host;
use roundhouse_engine::tools::agent_spawn_tool::dispatch_agent;
use roundhouse_engine::SessionActor;
use roundhouse_policy::engine::{CompiledRule, Outcome, PolicyEngine, Predicate, Scope};
use roundhouse_store::{open, spawn_writer};

fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

/// The ordering `main.rs` depends on, pinned directly rather than inferred —
/// the same source-scan idiom `tests/real_boot_smoke.rs` already uses for
/// assertions about the boot path that only a running daemon would otherwise
/// exercise.
///
/// The spawn tree must be rebuilt **before** `background_services.start(...)`:
/// the scheduler driver those services start admits `call:` children against
/// the very tree this pass is filling, and a consumer that saw it
/// half-reconstructed would admit past the ceiling. Nothing about that
/// ordering is enforced by a type, so it is enforced here.
#[test]
fn boot_recovery_runs_before_the_background_services_that_consume_the_tree() {
    let main_rs = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"))
        .expect("read src/main.rs");

    let reconcile = main_rs
        .find("reconcile_spawn_tree_at_boot(")
        .expect("main.rs must call reconcile_spawn_tree_at_boot at boot");
    // `rfind`, because `.start(` also appears inside the prose of the comment
    // *above* the reconcile call explaining this very ordering; the real call
    // is the last one. Matching on the method call alone keeps this robust to
    // reformatting of the builder chain.
    let services = main_rs
        .rfind(".start(")
        .expect("main.rs must still start the background services");

    assert!(
        reconcile < services,
        "the spawn tree must be reconciled BEFORE background_services.start(...), \
         which starts the scheduler driver that admits children against it"
    );
}

/// `TaskRunner::bootstrap()` panics on a second call per process, and both
/// `#[tokio::test]`s in this file need one — `common::runner()`'s `OnceLock`
/// (Phase 8, T19a Task 9) is what lets them share one instance safely,
/// rather than each calling `bootstrap()` directly the way a single-runner
/// file like `tests/boot.rs` still does.
#[tokio::test]
async fn boot_recovery_rebuilds_the_daemons_spawn_tree_from_the_store() {
    let runner = common::runner();

    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir.path().join("events.db")).await.unwrap();
    let writer = spawn_writer(store.clone()).await;

    let parent = SessionId::new();
    let live_child = SessionId::new();
    let ended_child = SessionId::new();

    for child in [live_child, ended_child] {
        let mut spec = SessionSpec::test_default();
        spec.parent = Some(parent);
        writer
            .append(runner.record_session_created(child, 0, now_ts(), Box::new(spec), 1))
            .await
            .unwrap();
    }
    writer
        .append(runner.record_session_closed(
            ended_child,
            0,
            now_ts(),
            SessionOutcome::Completed,
            1,
        ))
        .await
        .unwrap();

    // The restart: the tree a new daemon process starts with is empty.
    let tree = Arc::new(SpawnTree::new());
    let restored = reconcile_spawn_tree_at_boot(&store, &tree).await.unwrap();

    assert_eq!(restored, 1, "one edge restored, and it is reported");
    assert_eq!(
        tree.descendants(parent),
        vec![live_child],
        "the live child is back under its parent; the closed one is not"
    );
    assert_eq!(tree.direct_children(parent), 1);
}

/// Phase 8, T19a Task 9 (plan item (d)): unlike the hand-written events
/// above, this drives the real production close path — `SessionActor::close`
/// (this lane's own Task 4/7) cascading through `DaemonSubAgentHost::
/// close_children` (Task 6) — for a real sub-agent child spawned through the
/// real `agent` dispatcher, then rebuilds the tree from the same store and
/// confirms the closed child's edge does not come back.
///
/// This is a materially different proof from
/// `sub_agent_host.rs`'s own `a_retired_sub_agent_child_does_not_reappear_
/// after_a_restart` (which retires a child directly via `SubAgentSessions::
/// retire_child`, never through a parent's own close): here the PARENT is
/// what gets closed, and the child's own `SessionClosed` is a side effect of
/// that close cascading down, not of anything called on the child directly.
fn allow_agent_rules() -> PolicyRuleSource {
    Arc::new(|| {
        vec![CompiledRule::test_new(
            Scope::Project,
            Outcome::Allow,
            Predicate::agent(None, None, Tier::None),
        )]
    })
}

#[tokio::test]
async fn a_cascade_closed_sub_agent_childs_edge_is_not_restored_after_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let resources = common::resources_with(
        dir.path(),
        common::available_isolate(),
        Arc::new(common::NoopProvider),
        allow_agent_rules(),
    )
    .await;
    let registry = Arc::new(SessionRegistry::new());

    let store = open(&dir.path().join("events.db")).await.unwrap();
    let writer = spawn_writer(store).await;
    let policy = Arc::new(PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Project,
        Outcome::Allow,
        Predicate::agent(None, None, Tier::None),
    )]));
    let isolate = common::available_isolate();
    let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
    let handle = isolate.prepare(&spec).await.unwrap();
    let actor = Arc::new(SessionActor::new_with_workspace_root(
        SessionId::new(),
        writer,
        SessionState::Running,
        common::runner(),
        policy,
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        dir.path().canonicalize().unwrap(),
        isolate,
        handle,
        spec,
        roundhouse_engine::tool_catalog::builtin_tool_defs(),
    ));
    let parent = actor.session_id();
    wire_sub_agent_host(&actor, &resources, &registry);
    let host = actor
        .sub_agent_host()
        .expect("the host was just registered");

    dispatch_agent(
        &actor,
        actor.writer(),
        common::runner(),
        Some(&host),
        &serde_json::json!({
            "prompt": "review the diff",
            "provider": "anthropic",
            "budget_tokens": 250,
        }),
        TaskId::new(),
    )
    .await
    .expect("the spawn must succeed under an allow rule");

    let child = resources
        .spawn_tree
        .descendants(parent)
        .into_iter()
        .next()
        .expect("exactly one real child was spawned");

    // The real close path: closing the PARENT must cascade down and close
    // the CHILD too (`close_children`), never called on the child directly.
    actor
        .close(SessionOutcome::Completed)
        .await
        .expect("closing the parent must cascade-close its real child too");

    let query_store = open(&dir.path().join("events.db")).await.unwrap();
    let child_events = roundhouse_store::session_events(&query_store, child)
        .await
        .unwrap();
    assert!(
        child_events.iter().any(|e| matches!(
            e.payload,
            roundhouse_core::EventPayload::SessionClosed { .. }
        )),
        "close_children's cascade must have durably closed the real child too, got {:?}",
        child_events.iter().map(|e| &e.payload).collect::<Vec<_>>()
    );

    // The restart: a brand-new tree, rebuilt from durable state alone.
    let after_restart = Arc::new(SpawnTree::new());
    reconcile_spawn_tree_at_boot(&resources.store, &after_restart)
        .await
        .unwrap();

    assert!(
        after_restart.descendants(parent).is_empty(),
        "the cascade-closed child's edge must not be restored after a restart, got {:?}",
        after_restart.descendants(parent)
    );
}
