//! Task 20 (W4): drives `PolicyEngine::decide`'s `TaskParams::Memory` arm
//! through the real public surface — `PolicyEngine::from_rules(...)`,
//! `.with_team_membership(...)`, `.decide(&params)` — never a test-only
//! `decide_for_test` shortcut (orchestrator Ruling W4-4: the plan's snippet
//! is a sketch of the assertion, not of the API).

use roundhouse_core::{MemoryScope, SessionId, TeamId};
use roundhouse_policy::engine::{Outcome, PolicyEngine};
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
