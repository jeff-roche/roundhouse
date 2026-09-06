use roundhouse_core::Tier;
use roundhouse_policy::engine::{CompiledRule, Outcome, PolicyEngine, Predicate, Scope};
use roundhouse_policy::{FsOp, Method, PathErr, ProviderId, ServerId, TaskParams};
use std::path::PathBuf;

#[test]
fn deny_wins_unconditionally_even_at_lower_scope_than_a_matching_allow() {
    let params = TaskParams::Fs {
        op: FsOp::Write,
        path: PathBuf::from("/workspace/notes.txt"),
        canonical: Ok(PathBuf::from("/workspace/notes.txt")),
    };
    let policy = PolicyEngine::from_rules(vec![
        CompiledRule::test_new(
            Scope::Project,
            Outcome::Deny,
            Predicate::fs_write_prefix("/workspace"),
        ),
        CompiledRule::test_new(
            Scope::Grant,
            Outcome::Allow,
            Predicate::fs_write_exact("/workspace/notes.txt"),
        ),
    ]);

    let decision = policy.decide(&params);
    assert_eq!(
        decision.outcome,
        Outcome::Deny,
        "no allow overrides a deny at any scope (§6.2)"
    );
}

#[test]
fn no_matching_rule_denies_in_unattended_mode() {
    let params = TaskParams::Fs {
        op: FsOp::Write,
        path: PathBuf::from("/workspace/unmentioned.txt"),
        canonical: Ok(PathBuf::from("/workspace/unmentioned.txt")),
    };
    let policy = PolicyEngine::from_rules(vec![]);
    let decision = policy.decide_unattended(&params);
    assert_eq!(
        decision.outcome,
        Outcome::Deny,
        "S-PERM-1: no matching rule -> Deny in unattended mode"
    );
}

#[test]
fn uncanonicalizable_path_is_deny_never_ask() {
    let params = TaskParams::Fs {
        op: FsOp::Read,
        path: PathBuf::from("/workspace/dangling-symlink"),
        canonical: Err(PathErr("dangling symlink".into())),
    };
    let policy = PolicyEngine::from_rules(vec![]);
    let decision = policy.decide(&params);
    assert_eq!(
        decision.outcome,
        Outcome::Deny,
        "a human cannot evaluate an uncanonicalizable path (§6.2)"
    );
}

#[test]
fn http_rule_can_allow_a_get_to_an_allowlisted_registry() {
    // Regression for the audit finding that only Fs*/Shell predicates ever matched —
    // an Http rule must be able to reach Allow, not just fall through to Ask/Deny.
    let params = TaskParams::Http {
        method: Method::Get,
        url: "https://crates.io/api/v1/x".into(),
        body_len: 0,
    };
    let policy = PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Project,
        Outcome::Allow,
        Predicate::http_prefix(Some(Method::Get), "https://crates.io/"),
    )]);
    assert_eq!(policy.decide(&params).outcome, Outcome::Allow);
}

#[test]
fn mcp_rule_can_allow_a_named_tool_on_a_resolved_server() {
    let params = TaskParams::Mcp {
        server: ServerId("filesystem".into()),
        tool: "read_file".into(),
        args: serde_json::json!({}),
    };
    let policy = PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Project,
        Outcome::Allow,
        Predicate::mcp(ServerId("filesystem".into()), Some("read_file".into())),
    )]);
    assert_eq!(policy.decide(&params).outcome, Outcome::Allow);
}

#[test]
fn git_rule_can_allow_a_read_only_subcommand() {
    let params = TaskParams::Git {
        subcommand: "status".into(),
        argv: vec![],
        remote: None,
    };
    let policy = PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Project,
        Outcome::Allow,
        Predicate::git("status", &[]),
    )]);
    assert_eq!(policy.decide(&params).outcome, Outcome::Allow);
}

#[test]
fn agent_rule_can_allow_a_spawn_at_or_above_a_tier_floor() {
    // Task 21 (W4) flipped `Predicate::Agent`'s tier comparison from a
    // (backwards) ceiling to a floor: a grant approved at `max_tier: X`
    // covers a request only if `tier_request >= X`. This test used to
    // construct `tier_request: Worktree` against a `max_tier: Sandbox` rule
    // — i.e. a request for *less* isolation than what was "approved" — which
    // only passed under the old, backwards `<=` comparison; it was
    // unknowingly relying on the exact direction the security fix corrects.
    // Flipped here: the rule's floor (`Sandbox`) is now at or below the
    // request's tier (`Remote`), which is what "covers" is supposed to mean.
    let params = TaskParams::Agent {
        provider: ProviderId("anthropic".into()),
        model: "claude".into(),
        tier_request: Tier::Remote,
    };
    let policy = PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Project,
        Outcome::Allow,
        Predicate::agent(None, None, Tier::Sandbox),
    )]);
    assert_eq!(
        policy.decide(&params).outcome,
        Outcome::Allow,
        "an Agent task must be matchable by a rule at all — previously no rule could ever Allow one"
    );
}

#[test]
fn fs_edit_rule_can_match_an_edit_request() {
    // Proactive ruling from the controller addendum: matches_op must cover all
    // FsOp variants, not just Read/Write.
    let params = TaskParams::Fs {
        op: FsOp::Edit,
        path: PathBuf::from("/workspace/src/lib.rs"),
        canonical: Ok(PathBuf::from("/workspace/src/lib.rs")),
    };
    let policy = PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Project,
        Outcome::Allow,
        Predicate::fs_edit_prefix("/workspace/src"),
    )]);
    assert_eq!(policy.decide(&params).outcome, Outcome::Allow);
}
