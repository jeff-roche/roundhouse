//! Task 20 (W4): drives `PolicyEngine::decide`'s `TaskParams::Memory` arm
//! through the real public surface — `PolicyEngine::from_rules(...)`,
//! `.with_team_membership(...)`, `.decide(&params)` — never a test-only
//! `decide_for_test` shortcut (orchestrator Ruling W4-4: the plan's snippet
//! is a sketch of the assertion, not of the API).

use roundhouse_core::{MemoryScope, SessionId, TaskId, TeamId, Timestamp};
use roundhouse_policy::approval::{synthesize_grant, GrantProvenance, GrantScope};
use roundhouse_policy::engine::{CompiledRule, Outcome, PolicyEngine, Predicate, Scope};
use roundhouse_policy::{MemoryOp, TaskParams, TeamMembership};
use std::sync::Arc;

/// `can_read` true, `can_write` false — the asymmetric membership the plan's
/// own sketch describes.
struct ReadOnlyMembership;
impl TeamMembership for ReadOnlyMembership {
    fn can_read(&self, _team: TeamId, _session: SessionId) -> bool {
        true
    }
    fn can_write(&self, _team: TeamId, _session: SessionId) -> bool {
        false
    }
}

/// Neither read nor write membership — a non-member session.
struct NoMembership;
impl TeamMembership for NoMembership {
    fn can_read(&self, _team: TeamId, _session: SessionId) -> bool {
        false
    }
    fn can_write(&self, _team: TeamId, _session: SessionId) -> bool {
        false
    }
}

fn memory_params(scope: MemoryScope, op: MemoryOp, session: SessionId) -> TaskParams {
    TaskParams::Memory { scope, op, session }
}

#[test]
fn team_membership_grants_read_but_never_write_without_an_explicit_grant() {
    let engine =
        PolicyEngine::from_rules(vec![]).with_team_membership(Arc::new(ReadOnlyMembership));
    let team = TeamId::new();
    let session = SessionId::new();

    let read_decision = engine.decide(&memory_params(
        MemoryScope::Team { team },
        MemoryOp::Read,
        session,
    ));
    let write_decision = engine.decide(&memory_params(
        MemoryScope::Team { team },
        MemoryOp::Write,
        session,
    ));

    assert_eq!(read_decision.outcome, Outcome::Allow);
    assert_ne!(write_decision.outcome, Outcome::Allow);
}

#[test]
fn team_scope_denies_every_op_when_no_team_membership_is_configured() {
    // Fail-closed: an engine with no `TeamMembership` wired must never Allow
    // a Team-scoped memory op, including Read. Unverifiable membership is
    // not a reason to allow.
    let engine = PolicyEngine::from_rules(vec![]);
    let team = TeamId::new();
    let session = SessionId::new();

    for op in [
        MemoryOp::Read,
        MemoryOp::Write,
        MemoryOp::Append,
        MemoryOp::Delete,
    ] {
        let decision = engine.decide(&memory_params(MemoryScope::Team { team }, op, session));
        assert_eq!(
            decision.outcome,
            Outcome::Deny,
            "op {op:?} must Deny with no TeamMembership configured"
        );
    }
}

#[test]
fn append_and_delete_route_through_can_write_not_can_read() {
    // A fixture with read=true/write=false must deny all three write-shaped
    // ops (Write, Append, Delete), not just Write.
    let engine =
        PolicyEngine::from_rules(vec![]).with_team_membership(Arc::new(ReadOnlyMembership));
    let team = TeamId::new();
    let session = SessionId::new();

    for op in [MemoryOp::Write, MemoryOp::Append, MemoryOp::Delete] {
        let decision = engine.decide(&memory_params(MemoryScope::Team { team }, op, session));
        assert_ne!(
            decision.outcome,
            Outcome::Allow,
            "write-shaped op {op:?} must not Allow when can_write is false"
        );
    }
}

#[test]
fn non_member_session_is_denied_read() {
    let engine = PolicyEngine::from_rules(vec![]).with_team_membership(Arc::new(NoMembership));
    let team = TeamId::new();
    let session = SessionId::new();

    let decision = engine.decide(&memory_params(
        MemoryScope::Team { team },
        MemoryOp::Read,
        session,
    ));
    assert_eq!(decision.outcome, Outcome::Deny);
}

/// Fix round 1, item 5: both fixtures above ignore their `team`/`session`
/// arguments, so a bug that dropped or swapped `*team`/`*session` at the
/// `can_read`/`can_write` call sites in `PolicyEngine::decide` would pass
/// every test above. This fixture discriminates on the exact
/// `(team, session)` pair, proving the engine actually threads the
/// *request's own* team and session through to `TeamMembership` rather than
/// some other value.
struct ExactPairMembership {
    team: TeamId,
    session: SessionId,
}
impl TeamMembership for ExactPairMembership {
    fn can_read(&self, team: TeamId, session: SessionId) -> bool {
        team == self.team && session == self.session
    }
    fn can_write(&self, team: TeamId, session: SessionId) -> bool {
        team == self.team && session == self.session
    }
}

#[test]
fn engine_threads_the_requests_own_team_and_session_into_team_membership() {
    let team = TeamId::new();
    let session = SessionId::new();
    let engine = PolicyEngine::from_rules(vec![])
        .with_team_membership(Arc::new(ExactPairMembership { team, session }));

    // The exact (team, session) pair the fixture was built for: Allow.
    let matching = engine.decide(&memory_params(
        MemoryScope::Team { team },
        MemoryOp::Read,
        session,
    ));
    assert_eq!(matching.outcome, Outcome::Allow);

    // A different session on the same team: Deny.
    let other_session = SessionId::new();
    let wrong_session = engine.decide(&memory_params(
        MemoryScope::Team { team },
        MemoryOp::Read,
        other_session,
    ));
    assert_eq!(wrong_session.outcome, Outcome::Deny);

    // A different team with the same session: Deny.
    let other_team = TeamId::new();
    let wrong_team = engine.decide(&memory_params(
        MemoryScope::Team { team: other_team },
        MemoryOp::Read,
        session,
    ));
    assert_eq!(wrong_team.outcome, Outcome::Deny);
}

// ---------------------------------------------------------------------
// Fix round 1, item 6: `Predicate::Memory` coverage. Nothing exercised
// `synthesize_grant`'s new arm, `Predicate::matches`'s new arm, or the
// `User`/`Project` fall-through this predicate enables before this point —
// `approval.rs`'s own doc comments stake real weight on `synthesize_grant`'s
// totality (audit finding 5 was exactly a variant panicking the moment
// anyone exercised it).
// ---------------------------------------------------------------------

/// A config-authored `Predicate::Memory` rule for `User` scope: `Allow` for
/// a matching request, and the engine's ordinary default (`Ask`, since
/// nothing else matches and this is a non-`Team` scope with no other rules)
/// for a request that does not match.
#[test]
fn predicate_memory_matches_user_scope_and_falls_through_to_the_default_otherwise() {
    let session = SessionId::new();
    let rule = CompiledRule::test_new(
        Scope::Project,
        Outcome::Allow,
        Predicate::Memory {
            scope: MemoryScope::User,
            op: MemoryOp::Read,
            session: Some(session),
        },
    );
    let engine = PolicyEngine::from_rules(vec![rule]);

    let matching = engine.decide(&memory_params(MemoryScope::User, MemoryOp::Read, session));
    assert_eq!(matching.outcome, Outcome::Allow);

    // Same scope+session, different op: no rule matches -> engine default (Ask).
    let unmatched = engine.decide(&memory_params(MemoryScope::User, MemoryOp::Write, session));
    assert_eq!(unmatched.outcome, Outcome::Ask);
}

/// `synthesize_grant` must not panic on `TaskParams::Memory` and must
/// produce a `Predicate::Memory` (audit finding 5's totality property,
/// re-verified for the new variant).
#[test]
fn synthesize_grant_handles_task_params_memory_without_panicking() {
    let workspace = roundhouse_core::WorkspaceId::new();
    let session = SessionId::new();
    let params = TaskParams::Memory {
        scope: MemoryScope::Project { workspace },
        op: MemoryOp::Write,
        session,
    };
    let provenance = GrantProvenance {
        session_id: session,
        task_id: TaskId::new(),
        ts: Timestamp::from_unix_nanos(0),
    };

    let grant = synthesize_grant(&params, GrantScope::Once, provenance);
    // Task 23 (W4): `Grant.rule` is `pub(crate)` now — inspect the
    // synthesized predicate through `Grant::predicate()` instead of reading
    // `.rule.predicate` directly.
    match grant.predicate() {
        Predicate::Memory {
            scope,
            op,
            session: bound_session,
        } => {
            assert_eq!(*scope, MemoryScope::Project { workspace });
            assert_eq!(*op, MemoryOp::Write);
            assert_eq!(*bound_session, Some(session));
        }
        other => panic!("expected Predicate::Memory, got {other:?}"),
    }
}

/// The regression test for fix round 1, item 1: a grant synthesized from
/// session A's `User`-scope request must not also match session B's
/// otherwise-identical request. Before `Predicate::Memory` bound `session`,
/// this rule would have matched both sessions.
#[test]
fn a_grant_synthesized_for_one_session_does_not_match_a_different_session() {
    let session_a = SessionId::new();
    let session_b = SessionId::new();
    let params_a = TaskParams::Memory {
        scope: MemoryScope::User,
        op: MemoryOp::Delete,
        session: session_a,
    };
    let provenance = GrantProvenance {
        session_id: session_a,
        task_id: TaskId::new(),
        ts: Timestamp::from_unix_nanos(0),
    };
    let grant = synthesize_grant(&params_a, GrantScope::Always, provenance);
    let engine = PolicyEngine::from_rules(vec![grant
        .into_rule_for_installation()
        .expect("Always scope installs cleanly")]);

    // Session A's exact approved request: Allow.
    let decision_a = engine.decide(&params_a);
    assert_eq!(decision_a.outcome, Outcome::Allow);

    // Session B's otherwise-identical request: must NOT be Allow.
    let params_b = TaskParams::Memory {
        scope: MemoryScope::User,
        op: MemoryOp::Delete,
        session: session_b,
    };
    let decision_b = engine.decide(&params_b);
    assert_ne!(
        decision_b.outcome,
        Outcome::Allow,
        "a grant synthesized from session A's request must not also cover session B's identical request"
    );
}

/// Fix round 1, item 4a: an operator-authored `Deny` rule for `Team` scope
/// must still win, even though this arm otherwise decides `Team` entirely
/// via `TeamMembership` and normally never consults rules. Without this
/// check, an operator's explicit `Deny` on team memory would be silently
/// inert the moment membership says `Allow`.
#[test]
fn operator_deny_rule_wins_over_a_team_membership_allow() {
    let team = TeamId::new();
    let session = SessionId::new();
    let deny_rule = CompiledRule::test_new(
        Scope::Project,
        Outcome::Deny,
        Predicate::Memory {
            scope: MemoryScope::Team { team },
            op: MemoryOp::Read,
            session: None,
        },
    );
    let engine = PolicyEngine::from_rules(vec![deny_rule])
        .with_team_membership(Arc::new(ReadOnlyMembership));

    let decision = engine.decide(&memory_params(
        MemoryScope::Team { team },
        MemoryOp::Read,
        session,
    ));
    assert_eq!(
        decision.outcome,
        Outcome::Deny,
        "an operator-authored Deny must win even though TeamMembership would say Allow"
    );
}
