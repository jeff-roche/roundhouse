//! Task 21 (W4): `Predicate::Agent`'s tier comparison ran backwards against
//! `Tier`'s ascending-isolation ordering (`None < Worktree < Sandbox <
//! Container < Remote`, `roundhouse-core/src/tier.rs`) — a grant approved at
//! `max_tier: Remote` also covered `tier_request: None`, so approving the
//! *most*-isolated request silently also permitted the *least*-isolated one.
//!
//! Driven through the real `PolicyEngine::decide` + `Predicate::Agent`, per
//! Ruling W4-4 — there is no `matches_tier_request` helper to call directly.

use roundhouse_core::Tier;
use roundhouse_policy::engine::{CompiledRule, Outcome, PolicyEngine, Predicate, Scope};
use roundhouse_policy::{ProviderId, TaskParams};

fn agent_request(tier_request: Tier) -> TaskParams {
    TaskParams::Agent {
        provider: ProviderId("anthropic".into()),
        model: "claude".into(),
        tier_request,
    }
}

#[test]
fn a_remote_tier_grant_does_not_cover_a_none_tier_request() {
    let policy = PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Project,
        Outcome::Allow,
        Predicate::agent(None, None, Tier::Remote),
    )]);

    let decision = policy.decide(&agent_request(Tier::None));

    assert_eq!(
        decision.outcome,
        Outcome::Ask,
        "approving the most-isolated request (Remote) must not also permit \
         the least-isolated one (None) — no rule should match, so the \
         request must fall through to the default Ask"
    );
}

#[test]
fn a_sandbox_tier_grant_does_cover_a_remote_tier_request() {
    let policy = PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Project,
        Outcome::Allow,
        Predicate::agent(None, None, Tier::Sandbox),
    )]);

    let decision = policy.decide(&agent_request(Tier::Remote));

    assert_eq!(
        decision.outcome,
        Outcome::Allow,
        "a grant approved with a floor of Sandbox must cover a request \
         asking for at least as much isolation (Remote)"
    );
}
