//! Phase 8, L5 Task 7 — §7.7's two spawn limits, end to end over real
//! daemon resources: the **mixed** fan-out ceiling (sub-agent children and
//! workflow `call:` children draw from ONE ceiling, per parent session) and
//! the **depth** ceiling, walked down a chain of genuinely nested real
//! sessions.
//!
//! Every earlier task in this plan proved one half of this in isolation —
//! `sub_agent_host::tests::a_retired_sub_agent_frees_exactly_one_of_its_parents_fan_out_slots`
//! saturates a parent with eight real sub-agents, and
//! `workflow_host::tests::a_terminated_child_frees_exactly_one_of_its_parents_fan_out_slots`
//! saturates one with eight `call:` children — but neither could show that the
//! two kinds *share* the same eight slots, because no single task had both
//! spawn paths landed at once. That claim is load-bearing: `DaemonResources`
//! holds exactly one `SpawnTree`, and
//! `roundhouse_flow::compose::MAX_DIRECT_CHILD_CALLS` is literally
//! `roundhouse_bus::limits::MAX_FAN_OUT`, so a parent that spent all eight on
//! sub-agents has none left for `call:` children and vice versa. If the two
//! kinds ever counted separately, a session could hold sixteen live children
//! while both ceilings still read "under the limit".
//!
//! # What "the real path" means here, and why it stops where it does
//!
//! The sub-agent half runs the **real** `roundhouse-engine` dispatcher
//! (`dispatch_agent`) against a **real** `DaemonSubAgentHost` wired by the
//! production `wire_sub_agent_host`, over real `DaemonResources` — real
//! sessions, really registered, with real `SessionCreated` rows.
//!
//! The workflow half calls `WorkflowSessionTree`'s `SessionTree` methods
//! directly. Those are the exact methods `roundhouse-flow`'s
//! `Executor::dispatch_call` calls for a `call:` child, and calling them
//! directly is how this codebase already tests them — because **nothing in
//! this workspace drives a workflow `call:` child run**, a fact established
//! at length in this plan's Task 4 and unchanged since: `DeliveryExecutor`'s
//! two `run_workflow_from_storage` callers both build root runs
//! (`parent_run_id: None`), so no child run is ever driven, and no child run
//! ever reaches a terminal state in production. Likewise, nothing terminates
//! a sub-agent session: `SessionState::Closed` has no production writer. So
//! "drive the child to a terminal state" means calling the termination seams
//! themselves — `SessionTree::child_terminated` and
//! `SubAgentSessions::retire_child` — which is what a future run-driver will
//! call, and what this test calls.

mod common;

use std::sync::Arc;

use roundhouse_bus::limits::MAX_FAN_OUT;
use roundhouse_core::{
    JobId, OnDegrade, SessionId, SessionOutcome, SessionSpec, SessionState, Tier,
};
use roundhouse_daemon::session_bootstrap::{DaemonResources, PolicyRuleSource};
use roundhouse_daemon::session_registry::SessionRegistry;
use roundhouse_daemon::sub_agent_host::wire_sub_agent_host;
use roundhouse_daemon::workflow_host::WorkflowSessionTree;
use roundhouse_engine::tools::agent_spawn_tool::dispatch_agent;
use roundhouse_engine::SessionActor;
use roundhouse_flow::compose::MAX_DIRECT_CHILD_CALLS;
use roundhouse_flow::exec::run_loop::SessionTree;
use roundhouse_policy::engine::{CompiledRule, Outcome, PolicyEngine, Predicate, Scope};

/// The operator rule that permits sub-agent spawning at all. Without it
/// `PolicyEngine::decide` falls through to `Ask`, every `agent` call is refused
/// at admission, and no slot is ever consumed — correct behaviour, but it would
/// make every count below trivially zero.
fn allow_agent_rules() -> PolicyRuleSource {
    Arc::new(|| {
        vec![CompiledRule::test_new(
            Scope::Project,
            Outcome::Allow,
            Predicate::agent(None, None, Tier::None),
        )]
    })
}

/// A real parent `SessionActor` carrying the same `agent`-allowing rule and the
/// real builtin tool catalog.
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
    let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
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
    agent_args_with_budget(10)
}

fn agent_args_with_budget(budget_tokens: u64) -> serde_json::Value {
    serde_json::json!({
        "prompt": "review the diff",
        "provider": "anthropic",
        "budget_tokens": budget_tokens,
    })
}

async fn resources(dir: &std::path::Path) -> Arc<DaemonResources> {
    common::resources_with(
        dir,
        common::available_isolate(),
        Arc::new(common::NoopProvider),
        allow_agent_rules(),
    )
    .await
}

/// **The two ceilings are one ceiling.** Asserted first and by itself, because
/// every count in the test below is only meaningful if it holds: if these ever
/// diverge, "eight children of mixed kinds saturate a parent" stops being a
/// statement about one shared limit.
#[test]
fn the_two_child_kinds_are_checked_against_the_same_constant() {
    assert_eq!(
        MAX_DIRECT_CHILD_CALLS, MAX_FAN_OUT,
        "workflow `call:` children and sub-agent children must be limited by the same \
         number, or a parent could hold twice the intended live children"
    );
}

/// Eight children of **mixed** kinds against one parent saturate it; the ninth
/// is refused **through whichever path asks**; and a termination of either kind
/// frees a slot the **other** kind can then spend.
///
/// The cross-kind release is the half no earlier test could reach: a `call:`
/// child ending must hand its slot to a sub-agent spawn, and a sub-agent being
/// retired must hand its slot to a `call:` child, or the "one shared ceiling"
/// claim only holds while nothing ever ends.
#[tokio::test]
async fn agent_and_call_children_share_one_parents_fan_out_ceiling() {
    let dir = tempfile::tempdir().unwrap();
    let resources = resources(dir.path()).await;
    let registry = Arc::new(SessionRegistry::new());
    let actor = parent_actor(dir.path()).await;
    let parent = actor.session_id();
    wire_sub_agent_host(&actor, &resources, &registry);
    let host = actor
        .sub_agent_host()
        .expect("the host was just registered");

    // The `call:` half, over the SAME `DaemonResources::spawn_tree` the
    // sub-agent host reads — that shared instance is the whole mechanism.
    let mut workflow_tree = WorkflowSessionTree::new(
        Arc::clone(&resources.spawn_tree),
        common::runner(),
        SessionSpec::test_default(),
    );

    let spawn_sub_agent = |args: serde_json::Value| {
        let actor = Arc::clone(&actor);
        let host = host.clone();
        async move {
            dispatch_agent(
                &actor,
                actor.writer(),
                common::runner(),
                Some(&host),
                &args,
                roundhouse_core::TaskId::new(),
            )
            .await
        }
    };

    let admit_call_child = |tree: &mut WorkflowSessionTree, child: SessionId| {
        tree.reserve_child(parent, child)?;
        tree.register_child(parent, child, JobId::new())
    };

    // Half the ceiling in real sub-agent children ...
    let sub_agents = MAX_FAN_OUT / 2;
    // ... and the REST — `MAX_FAN_OUT - sub_agents`, not a second `/ 2` — in
    // `call:` children, against the same parent session. Splitting it this way
    // keeps the two groups summing to exactly the ceiling even if `MAX_FAN_OUT`
    // ever becomes odd, so the saturation assertion below stays true for the
    // right reason.
    let calls = MAX_FAN_OUT - sub_agents;
    for _ in 0..sub_agents {
        spawn_sub_agent(agent_args())
            .await
            .expect("a sub-agent under the shared ceiling");
    }
    let call_children: Vec<SessionId> = (0..calls)
        .map(|_| {
            let child = SessionId::new();
            admit_call_child(&mut workflow_tree, child)
                .expect("a `call:` child under the shared ceiling");
            child
        })
        .collect();

    assert_eq!(
        resources.spawn_tree.direct_children(parent),
        MAX_FAN_OUT,
        "sub-agent children plus `call:` children saturate ONE parent between them — they are \
         counted together, not once per kind"
    );
    let sub_agent_children: Vec<SessionId> = resources
        .spawn_tree
        .descendants(parent)
        .into_iter()
        .filter(|session| resources.sub_agents.parent_of(*session) == Some(parent))
        .collect();
    assert_eq!(
        sub_agent_children.len() as u32,
        sub_agents,
        "and the committed edges really are a MIX: exactly the sub-agent half is tracked as \
         such, so the other half came from the `call:` path"
    );

    // The ninth is refused whichever path asks for it.
    assert!(
        spawn_sub_agent(agent_args()).await.is_err(),
        "a parent saturated by a MIX of children must refuse a ninth sub-agent"
    );
    assert!(
        workflow_tree
            .reserve_child(parent, SessionId::new())
            .is_err(),
        "... and must refuse a ninth `call:` child, for the same reason"
    );
    assert_eq!(
        resources.spawn_tree.direct_children(parent),
        MAX_FAN_OUT,
        "neither refusal may consume or leak a slot"
    );
    assert_eq!(resources.spawn_tree.reserved_children(parent), 0);

    // A `call:` child ends -> a SUB-AGENT spawn gets the slot. The freed slot
    // is not reserved to the kind that freed it.
    workflow_tree.child_terminated(parent, call_children[0]);
    assert_eq!(
        resources.spawn_tree.direct_children(parent),
        MAX_FAN_OUT - 1,
        "the ended `call:` child's slot goes back"
    );
    spawn_sub_agent(agent_args())
        .await
        .expect("a sub-agent may spend the slot a terminated `call:` child gave back");
    assert_eq!(resources.spawn_tree.direct_children(parent), MAX_FAN_OUT);

    // A sub-agent is retired -> a `call:` child gets the slot.
    let retired = *sub_agent_children
        .first()
        .expect("at least one tracked sub-agent");
    assert!(
        resources
            .sub_agents
            .retire_child(
                retired,
                SessionOutcome::Cancelled,
                &resources.spawn_tree,
                &registry,
                &resources.proxy
            )
            .await,
        "retiring a live sub-agent reports that it found one"
    );
    assert_eq!(
        resources.spawn_tree.direct_children(parent),
        MAX_FAN_OUT - 1,
        "the retired sub-agent's slot goes back"
    );
    let replacement = SessionId::new();
    admit_call_child(&mut workflow_tree, replacement)
        .expect("a `call:` child may spend the slot a retired sub-agent gave back");
    assert_eq!(resources.spawn_tree.direct_children(parent), MAX_FAN_OUT);
    assert!(
        spawn_sub_agent(agent_args()).await.is_err(),
        "and the parent is saturated again, so the two releases handed out exactly two slots"
    );

    for session in resources.spawn_tree.descendants(parent) {
        resources
            .sub_agents
            .retire_child(
                session,
                SessionOutcome::Cancelled,
                &resources.spawn_tree,
                &registry,
                &resources.proxy,
            )
            .await;
    }
}

/// **§7.7's depth ceiling, walked down a chain of real nested sessions.**
///
/// `roundhouse-engine`'s
/// `agent_tool_spawn::a_spawn_refused_by_the_depth_limit_releases_its_reservation`
/// already drives the real loop against a host that *reports* `MAX_DEPTH`, and
/// proves the refusal releases its reservation. What it cannot show is that a
/// real daemon ever gets there: the depth a host reports is threaded by
/// `DaemonSubAgentHost::for_child` from the depth `agent_spawn` admitted, and
/// past depth 1 nothing checked that it keeps incrementing. A chain that
/// silently reported `1` at every level would pass every existing test and
/// never refuse anything.
///
/// So this builds the chain for real — each level is a registered session
/// spawned through the real `agent` dispatcher by the level above it — asserts
/// the reported depth at each step, and asserts the session at `MAX_DEPTH` is
/// refused because its child would be `MAX_DEPTH + 1`.
///
/// Budgets halve down the chain so every level has more than it needs: §7.7's
/// order checks depth **before** budget, so a too-small transfer would refuse
/// for the wrong reason while still looking green.
#[tokio::test]
async fn a_real_chain_of_nested_sub_agents_is_refused_at_the_depth_ceiling() {
    let dir = tempfile::tempdir().unwrap();
    let resources = resources(dir.path()).await;
    let registry = Arc::new(SessionRegistry::new());
    let root = parent_actor(dir.path()).await;
    wire_sub_agent_host(&root, &resources, &registry);

    let mut current = Arc::clone(&root);
    let mut budget = 10_000u64;
    for expected_child_depth in 1..=roundhouse_bus::limits::MAX_DEPTH {
        let host = current
            .sub_agent_host()
            .expect("every session in the chain must be able to spawn");
        assert_eq!(
            host.depth(),
            expected_child_depth - 1,
            "the spawning session sits one level above the child it is about to mint"
        );

        dispatch_agent(
            &current,
            current.writer(),
            common::runner(),
            Some(&host),
            &agent_args_with_budget(budget),
            roundhouse_core::TaskId::new(),
        )
        .await
        .unwrap_or_else(|err| panic!("depth {expected_child_depth} is legal, got {err:?}"));

        // Stated rather than relied on: each level spawns exactly once, so
        // `descendants` holds exactly one session and indexing it is
        // unambiguous. An index panic would report "out of bounds" for what is
        // really "this level spawned the wrong number of children".
        let children = resources.spawn_tree.descendants(current.session_id());
        assert_eq!(
            children.len(),
            1,
            "each level of the chain has exactly one child, so the next `current` is unambiguous"
        );
        current = registry
            .actor(children[0])
            .expect("each spawned child is a real, registered session");
        budget /= 2;
    }

    // `current` is now the session at `MAX_DEPTH`; its child would be
    // `MAX_DEPTH + 1`, which §7.7 refuses.
    let deepest = current.session_id();
    let host = current.sub_agent_host().unwrap();
    assert_eq!(host.depth(), roundhouse_bus::limits::MAX_DEPTH);

    let refused = dispatch_agent(
        &current,
        current.writer(),
        common::runner(),
        Some(&host),
        &agent_args_with_budget(1),
        roundhouse_core::TaskId::new(),
    )
    .await;

    let message = refused.expect_err("a child one level below MAX_DEPTH must be refused");
    assert!(
        message.contains("nested any deeper"),
        "the refusal must be the DEPTH limit, not the budget or the fan-out one — §7.7 \
         checks depth first, so a wrong-reason refusal here would still look green; got \
         {message:?}"
    );
    assert_eq!(
        resources.spawn_tree.direct_children(deepest),
        0,
        "a refused spawn leaves no committed edge"
    );
    assert_eq!(
        resources.spawn_tree.reserved_children(deepest),
        0,
        "and no dangling reservation: the release-on-refusal edge runs here too"
    );
}
