use roundhouse_core::Tier;
use roundhouse_policy::engine::{CompiledRule, Outcome, PolicyEngine, Predicate, Scope};
use roundhouse_policy::sealed::{home_dir, SealedContext};
use roundhouse_policy::{FsOp, ServerId, TaskParams};
use std::collections::HashSet;
use std::path::PathBuf;

fn ctx() -> SealedContext {
    SealedContext {
        state_dir: PathBuf::from("/tmp/roundhouse-test-state"),
        daemon_binary: PathBuf::from("/usr/libexec/roundhouse/round-daemon"),
        resolved_mcp_servers: HashSet::new(),
        requested_tier: Tier::Sandbox,
        attested_tier: Tier::Sandbox,
    }
}

#[test]
fn sealed_floor_denies_ssh_write_even_with_an_explicit_config_allow_rule() {
    let home = home_dir().expect("HOME must be set for this test");
    let params = TaskParams::Fs {
        op: FsOp::Write,
        path: PathBuf::from("~/.ssh/authorized_keys"),
        canonical: Ok(home.join(".ssh/authorized_keys")),
    };
    // an agent-writable config file explicitly allows this — sealed floor must still win
    let policy = PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Project,
        Outcome::Allow,
        Predicate::fs_write_prefix(home.join(".ssh").to_str().unwrap()),
    )]);

    let decision = policy.decide_sealed(&params, /* unsealed */ false, &ctx());
    assert_eq!(decision.outcome, Outcome::Deny);
    assert_eq!(decision.rule.unwrap().0, "sealed:ssh-write");
}

#[test]
fn unsealed_flag_falls_through_to_config_and_is_recorded() {
    let home = home_dir().expect("HOME must be set for this test");
    let params = TaskParams::Fs {
        op: FsOp::Write,
        path: PathBuf::from("~/.ssh/authorized_keys"),
        canonical: Ok(home.join(".ssh/authorized_keys")),
    };
    let policy = PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Project,
        Outcome::Allow,
        Predicate::fs_write_prefix(home.join(".ssh").to_str().unwrap()),
    )]);

    let decision = policy.decide_sealed(&params, /* unsealed */ true, &ctx());
    assert_eq!(
        decision.outcome,
        Outcome::Allow,
        "--unsealed is the one documented escape (§6.2)"
    );
}

#[test]
fn state_dir_write_is_sealed() {
    let c = ctx();
    let params = TaskParams::Fs {
        op: FsOp::Write,
        path: c.state_dir.join("store.db"),
        canonical: Ok(c.state_dir.join("store.db")),
    };
    let policy = PolicyEngine::from_rules(vec![]);
    assert_eq!(
        policy.decide_sealed(&params, false, &c).outcome,
        Outcome::Deny,
        "§6.2 lists the state dir on the sealed floor, not just dotfiles"
    );
}

#[test]
fn daemon_binary_write_is_sealed() {
    let c = ctx();
    let params = TaskParams::Fs {
        op: FsOp::Write,
        path: c.daemon_binary.clone(),
        canonical: Ok(c.daemon_binary.clone()),
    };
    let policy = PolicyEngine::from_rules(vec![]);
    assert_eq!(
        policy.decide_sealed(&params, false, &c).outcome,
        Outcome::Deny,
        "§6.2 lists the daemon binary on the sealed floor"
    );
}

#[test]
fn mcp_tool_on_an_unresolved_server_is_sealed_denied() {
    let c = ctx(); // resolved_mcp_servers is empty
    let params = TaskParams::Mcp {
        server: ServerId("never-connected".into()),
        tool: "read_file".into(),
        args: serde_json::json!({}),
    };
    let policy = PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Project,
        Outcome::Allow,
        Predicate::mcp(ServerId("never-connected".into()), None),
    )]);
    assert_eq!(
        policy.decide_sealed(&params, false, &c).outcome,
        Outcome::Deny,
        "§6.2: MCP tools on unresolved servers are sealed, even with an explicit allow rule"
    );
}

#[test]
fn tier_shortfall_seals_every_task_kind_not_just_agent() {
    let mut c = ctx();
    c.requested_tier = Tier::Sandbox;
    c.attested_tier = Tier::Worktree; // the sandbox degraded mid-session
    let params = TaskParams::Fs {
        op: FsOp::Read,
        path: PathBuf::from("/workspace/x"),
        canonical: Ok(PathBuf::from("/workspace/x")),
    };
    let policy = PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Project,
        Outcome::Allow,
        Predicate::fs_write_prefix("/workspace"),
    )]);
    assert_eq!(
        policy.decide_sealed(&params, false, &c).outcome,
        Outcome::Deny,
        "attested_tier < requested_tier seals EVERY task in the session, not only Agent spawns (previous stub was hardcoded to Agent-only and `&& false`)"
    );
}

#[test]
fn ssh_write_sibling_prefix_does_not_seal_match() {
    let home = home_dir().expect("HOME must be set for this test");
    let params = TaskParams::Fs {
        op: FsOp::Write,
        path: home.join(".sshfoo/authorized_keys"),
        canonical: Ok(home.join(".sshfoo/authorized_keys")),
    };
    let policy = PolicyEngine::from_rules(vec![]);
    let decision = policy.decide_sealed(&params, false, &ctx());
    assert_eq!(
        decision.outcome,
        Outcome::Ask,
        "a sibling prefix like ~/.sshfoo must not match the .ssh sealed rule"
    );
}
