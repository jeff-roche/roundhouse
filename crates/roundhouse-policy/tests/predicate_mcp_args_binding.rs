//! Task 22 (W4): `Predicate::Mcp` gains an `args: Option<ArgsPattern>` field.
//! Before this, `Predicate::Mcp { server, tool }` had no way to bind
//! arguments even though `TaskParams::Mcp` already carries real
//! `args: serde_json::Value` — approving one call with specific arguments
//! silently granted every future call to that tool regardless of arguments.
//!
//! Driven through the real `PolicyEngine::decide`, per Ruling W4-4 — there
//! is no `matches_args` method on `Predicate` to call directly.

use roundhouse_policy::engine::{
    ArgsPattern, CompiledRule, Outcome, PolicyEngine, Predicate, Scope,
};
use roundhouse_policy::{ServerId, TaskParams};

fn mcp_params(args: serde_json::Value) -> TaskParams {
    TaskParams::Mcp {
        server: ServerId("github".into()),
        tool: "write_file".into(),
        args,
    }
}

fn policy_with(predicate: Predicate) -> PolicyEngine {
    PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Grant,
        Outcome::Allow,
        predicate,
    )])
}

fn mcp_predicate(args: Option<ArgsPattern>) -> Predicate {
    Predicate::Mcp {
        server: ServerId("github".into()),
        tool: Some("write_file".into()),
        args,
    }
}

#[test]
fn approving_one_mcp_call_does_not_auto_allow_the_same_tool_with_different_arguments() {
    let approved_args = serde_json::json!({"path": "/tmp/a.txt"});
    let policy = policy_with(mcp_predicate(Some(ArgsPattern::Exact(
        approved_args.clone(),
    ))));

    assert_eq!(
        policy.decide(&mcp_params(approved_args)).outcome,
        Outcome::Allow,
        "the exact approved args must still match"
    );
    assert_eq!(
        policy
            .decide(&mcp_params(serde_json::json!({"path": "/etc/passwd"})))
            .outcome,
        Outcome::Ask,
        "different arguments to the same tool must not be silently covered"
    );
}

#[test]
fn none_args_pattern_matches_any_arguments_as_an_explicit_opt_in() {
    let policy = policy_with(mcp_predicate(None));

    assert_eq!(
        policy
            .decide(&mcp_params(serde_json::json!({"anything": "goes"})))
            .outcome,
        Outcome::Allow
    );
    assert_eq!(
        policy.decide(&mcp_params(serde_json::json!(null))).outcome,
        Outcome::Allow
    );
}

#[test]
fn prefix_pattern_matches_an_object_superset_of_the_required_keys() {
    let mut required = serde_json::Map::new();
    required.insert("path".to_string(), serde_json::json!("/tmp/a.txt"));
    let policy = policy_with(mcp_predicate(Some(ArgsPattern::Prefix(required))));

    let superset = serde_json::json!({"path": "/tmp/a.txt", "mode": "w"});
    assert_eq!(
        policy.decide(&mcp_params(superset)).outcome,
        Outcome::Allow,
        "extra keys in the candidate beyond the required pattern must still match"
    );
}

#[test]
fn prefix_pattern_rejects_a_differing_value_for_a_required_key() {
    let mut required = serde_json::Map::new();
    required.insert("path".to_string(), serde_json::json!("/tmp/a.txt"));
    let policy = policy_with(mcp_predicate(Some(ArgsPattern::Prefix(required))));

    let differing = serde_json::json!({"path": "/etc/passwd", "mode": "w"});
    assert_eq!(
        policy.decide(&mcp_params(differing)).outcome,
        Outcome::Ask,
        "a required key present with a different value must not match"
    );
}

#[test]
fn prefix_pattern_against_a_non_object_candidate_fails_closed() {
    let mut required = serde_json::Map::new();
    required.insert("path".to_string(), serde_json::json!("/tmp/a.txt"));
    let policy = policy_with(mcp_predicate(Some(ArgsPattern::Prefix(required))));

    assert_eq!(
        policy
            .decide(&mcp_params(serde_json::json!(["not", "an", "object"])))
            .outcome,
        Outcome::Ask,
        "a Prefix pattern must never match a non-object candidate — fail closed"
    );
}
