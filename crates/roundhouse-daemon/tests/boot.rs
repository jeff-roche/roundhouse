//! Tests for `roundhouse_daemon::boot::run_boot_sequence` (Task 2): wires
//! `roundhouse_store::recover_interrupted_tasks` and
//! `roundhouse_store::suspended_tasks` together into one `BootReport`. The
//! store-level tests (`roundhouse-store/tests/recovery.rs`,
//! `tests/append_batch.rs`, `tests/suspended.rs`, `tests/recovery_scale.rs`)
//! already cover the underlying logic in depth; this file only proves the
//! daemon-level seam wires both halves together correctly into one report.

use roundhouse_core::{
    IsolationAttestation, Origin, SessionId, SuspendReason, TaskId, TaskInput, TaskKind,
    TaskRunner, Tier, Timestamp,
};
use roundhouse_daemon::boot::run_boot_sequence;
use roundhouse_policy::registry::ApprovalRegistry;
use roundhouse_store::{open, spawn_writer};

fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

/// `TaskRunner::bootstrap()` panics on a second call per process, and each
/// integration-test binary is its own process — this file holds exactly one
/// test, so a plain local binding is safe (same posture as
/// `exit_criterion_demo.rs`).
#[tokio::test]
async fn run_boot_sequence_reports_both_interrupted_and_suspended_tasks() {
    let runner = TaskRunner::bootstrap();

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();

    // A task left running when the (simulated) previous daemon process died.
    let interrupted_task = TaskId::new();
    writer
        .append(runner.record_task_created(
            session_id,
            0,
            now_ts(),
            interrupted_task,
            TaskKind::Shell,
            None,
            Origin::Model,
            TaskInput::Text("still running at crash time".into()),
            1,
        ))
        .await
        .unwrap();
    writer
        .append(runner.record_task_started(
            session_id,
            0,
            now_ts(),
            interrupted_task,
            IsolationAttestation {
                tier: Tier::None,
                digest: "test".to_string(),
                net_enforced: false,
            },
            None,
            1,
        ))
        .await
        .unwrap();

    // A task left suspended, awaiting a reply, when the previous process died.
    let suspended_task = TaskId::new();
    writer
        .append(runner.record_task_created(
            session_id,
            0,
            now_ts(),
            suspended_task,
            TaskKind::Shell,
            None,
            Origin::Model,
            TaskInput::Text("waiting on the human".into()),
            1,
        ))
        .await
        .unwrap();
    writer
        .append(runner.record_task_suspended(
            session_id,
            0,
            now_ts(),
            suspended_task,
            SuspendReason::AwaitingReply,
            1,
        ))
        .await
        .unwrap();

    // Simulate a fresh daemon process reopening the same database.
    let reopened_store = open(&db_path).await.unwrap();
    let reopened_writer = spawn_writer(reopened_store).await;
    let store_for_boot = open(&db_path).await.unwrap();
    let registry = ApprovalRegistry::new();

    let report = run_boot_sequence(&store_for_boot, &reopened_writer, &runner, &registry)
        .await
        .unwrap();

    assert_eq!(report.interrupted, vec![interrupted_task]);
    assert_eq!(report.suspended.len(), 1);
    assert_eq!(report.suspended[0].task_id, suspended_task);
    assert_eq!(report.suspended[0].session_id, session_id);
    assert_eq!(report.suspended[0].reason, SuspendReason::AwaitingReply);

    // This task's reason is AwaitingReply, not AwaitingApproval, so it must
    // NOT be re-armed into the approval registry (that registry only tracks
    // AwaitingApproval — other suspend kinds re-arm through their own
    // subsystems).
    assert!(registry.list().is_empty());
}
