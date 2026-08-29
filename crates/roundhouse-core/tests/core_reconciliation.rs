//! Task 0 (controller-authored prerequisite to Phase 2): reconciles a
//! handful of `roundhouse-core` primitives the frozen spec calls for but
//! Phase 0/1 never delivered — additive only (new variants/fields/methods),
//! nothing renamed or removed. See
//! `.superpowers/sdd/2026-08-27-phase2-robustness/task-0-brief.md`.

use roundhouse_core::{
    Event, EventPayload, NoteLevel, OnDegrade, RuleId, SessionOutcome, SessionSpec, SessionState,
    SuspendReason, TaskId, TaskRunner, Tier, Timestamp,
};

// ── NoteLevel::Degradation ──────────────────────────────────────────────

#[test]
fn note_level_degradation_round_trips_through_json() {
    let level = NoteLevel::Degradation;
    let json = serde_json::to_string(&level).unwrap();
    let back: NoteLevel = serde_json::from_str(&json).unwrap();
    assert_eq!(back, NoteLevel::Degradation);
}

// ── SuspendReason: data-carrying AwaitingApproval/AwaitingElicitation, new WorkflowGate ──

#[test]
fn suspend_reason_awaiting_approval_carries_rule_and_params_digest() {
    let reason = SuspendReason::AwaitingApproval {
        rule: Some(RuleId(7)),
        params_digest: [9u8; 32],
    };
    let json = serde_json::to_string(&reason).unwrap();
    let back: SuspendReason = serde_json::from_str(&json).unwrap();
    match back {
        SuspendReason::AwaitingApproval {
            rule: Some(RuleId(7)),
            params_digest,
        } => assert_eq!(params_digest, [9u8; 32]),
        other => panic!("expected AwaitingApproval{{rule: Some(RuleId(7)), ..}}, got {other:?}"),
    }
}

#[test]
fn suspend_reason_awaiting_approval_rule_is_optional() {
    let reason = SuspendReason::AwaitingApproval {
        rule: None,
        params_digest: [0u8; 32],
    };
    let json = serde_json::to_string(&reason).unwrap();
    let back: SuspendReason = serde_json::from_str(&json).unwrap();
    match back {
        SuspendReason::AwaitingApproval {
            rule: None,
            params_digest,
        } => assert_eq!(params_digest, [0u8; 32]),
        other => panic!("expected AwaitingApproval{{rule: None, ..}}, got {other:?}"),
    }
}

#[test]
fn suspend_reason_awaiting_elicitation_carries_schema() {
    let schema = serde_json::json!({"type": "object", "properties": {"ok": {"type": "boolean"}}});
    let reason = SuspendReason::AwaitingElicitation {
        schema: schema.clone(),
    };
    let json = serde_json::to_string(&reason).unwrap();
    let back: SuspendReason = serde_json::from_str(&json).unwrap();
    match back {
        SuspendReason::AwaitingElicitation { schema: got } => assert_eq!(got, schema),
        other => panic!("expected AwaitingElicitation{{..}}, got {other:?}"),
    }
}

#[test]
fn suspend_reason_workflow_gate_carries_step_ref() {
    let reason = SuspendReason::WorkflowGate {
        step_ref: "deploy.approve".into(),
    };
    let json = serde_json::to_string(&reason).unwrap();
    let back: SuspendReason = serde_json::from_str(&json).unwrap();
    match back {
        SuspendReason::WorkflowGate { step_ref } => assert_eq!(step_ref, "deploy.approve"),
        other => panic!("expected WorkflowGate{{..}}, got {other:?}"),
    }
}

#[test]
fn suspend_reason_awaiting_reply_and_peer_are_untouched() {
    let reply = SuspendReason::AwaitingReply;
    let reply_json = serde_json::to_string(&reply).unwrap();
    let reply_back: SuspendReason = serde_json::from_str(&reply_json).unwrap();
    assert_eq!(reply_back, SuspendReason::AwaitingReply);

    let peer = SuspendReason::AwaitingPeer {
        session: roundhouse_core::SessionId::new(),
    };
    let peer_json = serde_json::to_string(&peer).unwrap();
    let _peer_back: SuspendReason = serde_json::from_str(&peer_json).unwrap();
}

// ── SessionState::Cancelling ─────────────────────────────────────────────

#[test]
fn session_state_cancelling_round_trips_through_json() {
    let state = SessionState::Cancelling;
    let json = serde_json::to_string(&state).unwrap();
    let back: SessionState = serde_json::from_str(&json).unwrap();
    assert_eq!(back, SessionState::Cancelling);
}

// ── SessionSpec: requested_tier/on_degrade + OnDegrade + test helpers ────

#[test]
fn session_spec_carries_requested_tier_and_on_degrade() {
    let spec = SessionSpec {
        workspace: roundhouse_core::WorkspaceId::new(),
        name: Some("s".into()),
        requested_tier: Tier::Container,
        on_degrade: OnDegrade::AllowDownTo(Tier::Sandbox),
    };
    let json = serde_json::to_string(&spec).unwrap();
    let back: SessionSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(back.requested_tier, Tier::Container);
    assert_eq!(back.on_degrade, OnDegrade::AllowDownTo(Tier::Sandbox));
}

#[test]
fn on_degrade_refuse_round_trips_through_json() {
    let on_degrade = OnDegrade::Refuse;
    let json = serde_json::to_string(&on_degrade).unwrap();
    let back: OnDegrade = serde_json::from_str(&json).unwrap();
    assert_eq!(back, OnDegrade::Refuse);
}

#[test]
fn session_spec_test_default_is_constructible_and_stable() {
    let spec = SessionSpec::test_default();
    // Just needs to exist and be usable — no particular tier/on_degrade
    // guarantee beyond "a sensible test placeholder".
    let _ = spec.workspace;
    let _ = spec.name;
}

#[test]
fn session_spec_test_requesting_sets_tier_and_on_degrade() {
    let spec = SessionSpec::test_requesting(Tier::Worktree, OnDegrade::Refuse);
    assert_eq!(spec.requested_tier, Tier::Worktree);
    assert_eq!(spec.on_degrade, OnDegrade::Refuse);

    let spec2 = SessionSpec::test_requesting(Tier::Remote, OnDegrade::AllowDownTo(Tier::Sandbox));
    assert_eq!(spec2.requested_tier, Tier::Remote);
    assert_eq!(spec2.on_degrade, OnDegrade::AllowDownTo(Tier::Sandbox));
}

// ── TaskRunner: four new record_* methods ────────────────────────────────

#[test]
fn task_runner_records_session_lifecycle_and_note_events() {
    let runner = TaskRunner::bootstrap();
    let session_id = roundhouse_core::SessionId::new();
    let ts = Timestamp::from_unix_nanos(0);

    // record_session_created
    let spec = Box::new(SessionSpec::test_default());
    let created: Event = runner.record_session_created(session_id, 1, ts, spec.clone(), 1);
    assert_eq!(created.session_id, session_id);
    assert_eq!(created.seq, 1);
    assert_eq!(created.task_id, None);
    assert_eq!(created.schema_v, 1);
    match created.payload {
        EventPayload::SessionCreated { spec: got } => {
            assert_eq!(got.name, spec.name);
        }
        other => panic!("expected SessionCreated, got {other:?}"),
    }

    // record_session_state_changed
    let state_changed: Event = runner.record_session_state_changed(
        session_id,
        2,
        ts,
        SessionState::Cancelling,
        Some("user requested cancel".into()),
        1,
    );
    assert_eq!(state_changed.task_id, None);
    match state_changed.payload {
        EventPayload::SessionStateChanged { state, reason } => {
            assert_eq!(state, SessionState::Cancelling);
            assert_eq!(reason.as_deref(), Some("user requested cancel"));
        }
        other => panic!("expected SessionStateChanged, got {other:?}"),
    }

    // record_session_closed
    let closed: Event =
        runner.record_session_closed(session_id, 3, ts, SessionOutcome::Completed, 1);
    assert_eq!(closed.task_id, None);
    match closed.payload {
        EventPayload::SessionClosed { outcome } => {
            assert!(matches!(outcome, SessionOutcome::Completed));
        }
        other => panic!("expected SessionClosed, got {other:?}"),
    }

    // record_note — session-scoped (task_id: None)
    let session_note: Event = runner.record_note(
        session_id,
        4,
        ts,
        None,
        NoteLevel::Degradation,
        "isolation degraded to Worktree".into(),
        1,
    );
    assert_eq!(session_note.task_id, None);
    match session_note.payload {
        EventPayload::Note { level, text } => {
            assert_eq!(level, NoteLevel::Degradation);
            assert_eq!(text, "isolation degraded to Worktree");
        }
        other => panic!("expected Note, got {other:?}"),
    }

    // record_note — task-scoped (task_id: Some(..))
    let task_id = TaskId::new();
    let task_note: Event = runner.record_note(
        session_id,
        5,
        ts,
        Some(task_id),
        NoteLevel::Warn,
        "retrying".into(),
        1,
    );
    assert_eq!(task_note.task_id, Some(task_id));
    match task_note.payload {
        EventPayload::Note { level, text } => {
            assert_eq!(level, NoteLevel::Warn);
            assert_eq!(text, "retrying");
        }
        other => panic!("expected Note, got {other:?}"),
    }
}
