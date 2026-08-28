use roundhouse_core::{
    CancelReason, EventPayload, Origin, PolicyDecision, SuspendReason, TaskKind, TaskState,
};

#[test]
fn fold_task_state_derives_each_state_from_a_realistic_event_sequence() {
    use roundhouse_core::{IsolationAttestation, Tier};

    // Created -> Decided -> Running -> Completed
    let happy_path = vec![
        EventPayload::TaskCreated {
            kind: TaskKind::Shell,
            parent: None,
            origin: Origin::Model,
            input: roundhouse_core::TaskInput::Text("ls".into()),
        },
        EventPayload::TaskDecided { decision: PolicyDecision::Allow, rule: None },
        EventPayload::TaskStarted {
            isolation: IsolationAttestation { tier: Tier::Worktree, digest: "d".into(), net_enforced: true },
            handle: None,
        },
        EventPayload::TaskCompleted {
            output: roundhouse_core::TaskOutput::Text("done".into()),
            usage: roundhouse_core::Usage::default(),
        },
    ];
    assert_eq!(roundhouse_core::fold_task_state(&happy_path), Some(TaskState::Completed));

    // Created -> Decided -> Running -> Suspended (awaiting approval)
    let suspended_path = vec![
        EventPayload::TaskCreated {
            kind: TaskKind::Shell,
            parent: None,
            origin: Origin::Model,
            input: roundhouse_core::TaskInput::Text("rm -rf /".into()),
        },
        EventPayload::TaskDecided { decision: PolicyDecision::Ask, rule: None },
        EventPayload::TaskStarted {
            isolation: IsolationAttestation { tier: Tier::Worktree, digest: "d".into(), net_enforced: true },
            handle: None,
        },
        EventPayload::TaskSuspended { reason: SuspendReason::AwaitingApproval },
    ];
    assert_eq!(
        roundhouse_core::fold_task_state(&suspended_path),
        Some(TaskState::Suspended(SuspendReason::AwaitingApproval))
    );

    // A cancelled task.
    let cancelled_path = vec![
        EventPayload::TaskCreated {
            kind: TaskKind::Shell,
            parent: None,
            origin: Origin::User,
            input: roundhouse_core::TaskInput::Text("sleep 100".into()),
        },
        EventPayload::TaskCancelled { by: Origin::User, reason: CancelReason::User },
    ];
    assert_eq!(roundhouse_core::fold_task_state(&cancelled_path), Some(TaskState::Cancelled));

    // No task-lifecycle events at all: no state to derive.
    assert_eq!(roundhouse_core::fold_task_state(&[]), None);
}

#[test]
fn task_state_rejects_an_unrecognized_sql_string_at_fold_time() {
    // §4.1's `tasks` table is a derived cache; TaskState::from_sql_str is
    // the read-back half of the CHECK constraint Task 10 adds to the
    // `state` column — both legs must reject the same invalid values.
    assert!(TaskState::from_sql_str("Completed").is_ok());
    assert!(
        TaskState::from_sql_str("bogus").is_err(),
        "an unrecognized state string must be rejected, not silently accepted"
    );
}
