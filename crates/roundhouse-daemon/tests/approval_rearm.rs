//! Tests for Task 15's boot-time re-arm: simulates the exact scenario the
//! README credits this plan for — a `Suspended{AwaitingApproval}` task
//! persisted before a restart must be re-armed through the attention-queue
//! path (`roundhouse_policy::registry::ApprovalRegistry`), not just sit
//! correctly in SQLite with nothing live pointing at it (audit finding 6).

use roundhouse_core::{Origin, SessionId, TaskId, TaskInput, TaskKind, TaskRunner, Timestamp};
use roundhouse_daemon::boot::run_boot_sequence;
use roundhouse_policy::approval::suspend_for_approval;
use roundhouse_policy::registry::ApprovalRegistry;
use roundhouse_policy::{FsOp, TaskParams};
use roundhouse_store::{open, spawn_writer};
use std::path::PathBuf;

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
/// `crates/roundhouse-daemon/tests/boot.rs`).
#[tokio::test]
async fn boot_rearms_a_previously_persisted_approval_into_a_live_registry() {
    let runner = TaskRunner::bootstrap();

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    // The "old" daemon process's registry.
    let boot_time_registry = ApprovalRegistry::new();
    let session_id = SessionId::new();
    let task_id = TaskId::new();
    let params = TaskParams::Fs {
        op: FsOp::Write,
        path: PathBuf::from("/workspace/x"),
        canonical: Ok(PathBuf::from("/workspace/x")),
    };

    writer
        .append(runner.record_task_created(
            session_id,
            0,
            now_ts(),
            task_id,
            TaskKind::Write,
            None,
            Origin::Model,
            TaskInput::Text("write /workspace/x".into()),
            1,
        ))
        .await
        .unwrap();

    suspend_for_approval(
        &writer,
        &runner,
        &boot_time_registry,
        session_id,
        task_id,
        None,
        &params,
    )
    .await
    .unwrap();
    drop(boot_time_registry); // simulate the daemon process exiting — the registry is gone

    // The restarted daemon's registry, empty, plus fresh handles onto the
    // same on-disk database (a real restart opens new pool/writer handles).
    let fresh_registry = ApprovalRegistry::new();
    let reopened_store = open(&db_path).await.unwrap();
    let reopened_writer = spawn_writer(reopened_store).await;
    let store_for_boot = open(&db_path).await.unwrap();

    let report = run_boot_sequence(&store_for_boot, &reopened_writer, &runner, &fresh_registry)
        .await
        .unwrap();
    assert_eq!(report.suspended.len(), 1);

    let pending = fresh_registry.list();
    assert_eq!(
        pending.len(),
        1,
        "boot must re-register every persisted Suspended{{AwaitingApproval}} task, not leave \
         the registry empty"
    );
    assert_eq!(pending[0].task_id, task_id);
    assert_eq!(pending[0].session_id, session_id);
}
