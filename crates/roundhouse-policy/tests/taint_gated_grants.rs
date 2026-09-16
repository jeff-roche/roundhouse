//! §6.8's taint-gated autonomy, enforced — Phase 8 Task 25.5 (#62) Task 4:
//! "All `Always`/`Session` allow-grants for irreversible or exfiltrating
//! kinds (`http` non-GET, `git push`, writes outside the workspace, `agent`
//! spawn, `message`) implicitly carry `MaxTaint(Trusted)`."
//!
//! A synthesized grant is identified by its `RuleId`'s `"grant:"` prefix
//! (`approval::synthesize_grant`'s own id format,
//! `"grant:<session>:<task>"`) — the only kind of `Allow`-outcome
//! `CompiledRule` this downgrade ever touches. An author-configured
//! project/workspace policy rule is never a grant and is never downgraded
//! by taint, matching §6.8's literal "allow-**grants**," not "every Allow
//! rule."

use roundhouse_policy::engine::{CompiledRule, Outcome, PolicyEngine, Predicate, Scope};
use roundhouse_policy::{FsOp, Method, ProviderId, Taint, TaskParams};

fn git_push() -> TaskParams {
    TaskParams::Git {
        subcommand: "push".into(),
        argv: vec!["origin".into(), "main".into()],
        remote: Some("origin".into()),
    }
}

fn grant_rule(outcome: Outcome, predicate: Predicate) -> CompiledRule {
    CompiledRule::test_new_with_id(Scope::Grant, outcome, predicate, "grant:session-1:task-1")
}

#[test]
fn a_tainted_session_downgrades_a_standing_git_push_grant_from_allow_to_ask() {
    let policy = PolicyEngine::from_rules(vec![grant_rule(
        Outcome::Allow,
        Predicate::git("push", &[]),
    )]);
    let decision = policy.decide_sealed(
        &git_push(),
        &roundhouse_policy::sealed::default_context(),
        Taint::Tainted,
    );
    assert_eq!(
        decision.outcome,
        Outcome::Ask,
        "a tainted session's standing git-push grant must downgrade to Ask, not stay Allow"
    );
}

#[test]
fn a_clean_session_keeps_the_same_standing_git_push_grant_at_allow() {
    let policy = PolicyEngine::from_rules(vec![grant_rule(
        Outcome::Allow,
        Predicate::git("push", &[]),
    )]);
    let decision = policy.decide_sealed(
        &git_push(),
        &roundhouse_policy::sealed::default_context(),
        Taint::Trusted,
    );
    assert_eq!(
        decision.outcome,
        Outcome::Allow,
        "an untainted session's standing grant must stay Allow"
    );
}

#[test]
fn a_tainted_session_does_not_downgrade_an_author_configured_non_grant_allow_rule() {
    // Same predicate/outcome as the grant test above, but `Scope::Project`
    // with an ordinary (non-"grant:"-prefixed) id — an admin's own policy
    // file, not a human's standing approval. §6.8 names "allow-grants"
    // specifically; this must be unaffected by taint.
    let policy = PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Project,
        Outcome::Allow,
        Predicate::git("push", &[]),
    )]);
    let decision = policy.decide_sealed(
        &git_push(),
        &roundhouse_policy::sealed::default_context(),
        Taint::Tainted,
    );
    assert_eq!(
        decision.outcome,
        Outcome::Allow,
        "an author-configured project rule is not a grant and must not be downgraded by taint"
    );
}

#[test]
fn a_tainted_session_does_not_downgrade_a_grant_for_a_reversible_kind() {
    // A grant to READ is not irreversible/exfiltrating — taint must not
    // touch it.
    let policy = PolicyEngine::from_rules(vec![grant_rule(
        Outcome::Allow,
        Predicate::FsPrefix {
            op: FsOp::Read,
            prefix: std::path::PathBuf::from("/"),
        },
    )]);
    let decision = policy.decide_sealed(
        &TaskParams::Fs {
            op: FsOp::Read,
            path: std::path::PathBuf::from("/tmp/x"),
            canonical: Ok(std::path::PathBuf::from("/tmp/x")),
        },
        &roundhouse_policy::sealed::default_context(),
        Taint::Tainted,
    );
    assert_eq!(
        decision.outcome,
        Outcome::Allow,
        "a grant for a reversible kind (read) must not be downgraded by taint"
    );
}

#[test]
fn a_tainted_session_downgrades_a_standing_http_post_grant_but_not_a_get_grant() {
    let policy = PolicyEngine::from_rules(vec![
        grant_rule(
            Outcome::Allow,
            Predicate::Http {
                method: Some(Method::Post),
                url_prefix: "https://example.com".into(),
                exact: false,
            },
        ),
        grant_rule(
            Outcome::Allow,
            Predicate::Http {
                method: Some(Method::Get),
                url_prefix: "https://example.com".into(),
                exact: false,
            },
        ),
    ]);
    let post = TaskParams::Http {
        method: Method::Post,
        url: "https://example.com/x".into(),
        body_len: 0,
    };
    let get = TaskParams::Http {
        method: Method::Get,
        url: "https://example.com/x".into(),
        body_len: 0,
    };
    assert_eq!(
        policy
            .decide_sealed(
                &post,
                &roundhouse_policy::sealed::default_context(),
                Taint::Tainted
            )
            .outcome,
        Outcome::Ask,
        "a tainted session's standing POST grant must downgrade to Ask"
    );
    assert_eq!(
        policy
            .decide_sealed(
                &get,
                &roundhouse_policy::sealed::default_context(),
                Taint::Tainted
            )
            .outcome,
        Outcome::Allow,
        "a GET grant is reversible/non-exfiltrating and must stay Allow even tainted"
    );
}

#[test]
fn a_tainted_session_downgrades_a_standing_agent_spawn_grant() {
    let policy = PolicyEngine::from_rules(vec![grant_rule(
        Outcome::Allow,
        Predicate::agent(None, None, roundhouse_core::Tier::None),
    )]);
    let decision = policy.decide_sealed(
        &TaskParams::Agent {
            provider: ProviderId("anthropic".into()),
            model: "claude-sonnet-5".into(),
            tier_request: roundhouse_core::Tier::Sandbox,
        },
        &roundhouse_policy::sealed::default_context(),
        Taint::Tainted,
    );
    assert_eq!(
        decision.outcome,
        Outcome::Ask,
        "a tainted session's standing agent-spawn grant must downgrade to Ask"
    );
}

#[test]
fn a_deny_decision_is_unaffected_by_taint() {
    let policy = PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Project,
        Outcome::Deny,
        Predicate::git("push", &[]),
    )]);
    let decision = policy.decide_sealed(
        &git_push(),
        &roundhouse_policy::sealed::default_context(),
        Taint::Tainted,
    );
    assert_eq!(
        decision.outcome,
        Outcome::Deny,
        "there is nothing to downgrade further from Deny"
    );
}
