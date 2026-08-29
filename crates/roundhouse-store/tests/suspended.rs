//! Tests for `roundhouse_store::suspended_tasks` (Task 2): enumerates tasks
//! left `Suspended` in the live `tasks` table, with their REAL `SuspendReason`
//! read back from `suspend_reason_json` — never `TaskState::from_sql_str`'s
//! `AwaitingApproval { rule: None, params_digest: [0u8; 32] }` placeholder
//! sentinel (see that function's doc comment in `roundhouse-core/src/task.rs`).

use roundhouse_core::{
    IsolationAttestation, Origin, RuleId, SessionId, SuspendReason, TaskId, TaskInput, TaskKind,
    Tier, Timestamp,
};
use roundhouse_store::{open, spawn_writer, suspended_tasks};

static RUNNER: once_cell::sync::Lazy<roundhouse_core::TaskRunner> =
    once_cell::sync::Lazy::new(roundhouse_core::TaskRunner::bootstrap);

fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

/// The round-trip test: a task suspended with a data-carrying `SuspendReason`
/// variant (`AwaitingApproval` with a real `rule`/`params_digest`, not the
/// placeholder's `None`/`[0u8; 32]`) must come back byte-for-byte identical
/// through `suspended_tasks`, proving the real reason is read from
/// `suspend_reason_json` and not reconstructed from the bare `state` discriminant.
#[tokio::test]
async fn suspended_tasks_round_trips_the_real_suspend_reason() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();
    let task_id = TaskId::new();

    writer
        .append(RUNNER.record_task_created(
            session_id,
            0,
            now_ts(),
            task_id,
            TaskKind::Shell,
            None,
            Origin::Model,
            TaskInput::Text("rm -rf /tmp/scratch".into()),
            1,
        ))
        .await
        .unwrap();

    writer
        .append(RUNNER.record_task_started(
            session_id,
            0,
            now_ts(),
            task_id,
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

    let real_reason = SuspendReason::AwaitingApproval {
        rule: Some(RuleId(3)),
        params_digest: [7u8; 32],
    };

    writer
        .append(RUNNER.record_task_suspended(
            session_id,
            0,
            now_ts(),
            task_id,
            real_reason.clone(),
            1,
        ))
        .await
        .unwrap();

    let query_store = open(&db_path).await.unwrap();
    let suspended = suspended_tasks(&query_store).await.unwrap();

    assert_eq!(suspended.len(), 1);
    assert_eq!(suspended[0].task_id, task_id);
    assert_eq!(suspended[0].session_id, session_id);
    assert_eq!(
        suspended[0].reason, real_reason,
        "must be the real reason from suspend_reason_json, not from_sql_str's placeholder \
         (AwaitingApproval {{ rule: None, params_digest: [0u8; 32] }})"
    );

    // Guard the negative: the returned reason must specifically NOT be the
    // placeholder sentinel `from_sql_str` would have produced.
    let placeholder = SuspendReason::AwaitingApproval {
        rule: None,
        params_digest: [0u8; 32],
    };
    assert_ne!(suspended[0].reason, placeholder);
}

/// Only `Suspended` tasks are returned — `Created`/`Running`/`Completed`/etc.
/// tasks must not appear, and a suspended task among several unrelated ones
/// must be picked out correctly.
#[tokio::test]
async fn suspended_tasks_excludes_non_suspended_tasks() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();

    let running_task = TaskId::new();
    writer
        .append(RUNNER.record_task_created(
            session_id,
            0,
            now_ts(),
            running_task,
            TaskKind::Shell,
            None,
            Origin::Model,
            TaskInput::Text("still running".into()),
            1,
        ))
        .await
        .unwrap();

    let suspended_task = TaskId::new();
    writer
        .append(RUNNER.record_task_created(
            session_id,
            0,
            now_ts(),
            suspended_task,
            TaskKind::Shell,
            None,
            Origin::Model,
            TaskInput::Text("waiting on approval".into()),
            1,
        ))
        .await
        .unwrap();
    writer
        .append(RUNNER.record_task_suspended(
            session_id,
            0,
            now_ts(),
            suspended_task,
            SuspendReason::AwaitingReply,
            1,
        ))
        .await
        .unwrap();

    let query_store = open(&db_path).await.unwrap();
    let suspended = suspended_tasks(&query_store).await.unwrap();

    assert_eq!(suspended.len(), 1);
    assert_eq!(suspended[0].task_id, suspended_task);
    assert_eq!(suspended[0].reason, SuspendReason::AwaitingReply);
}

/// No suspended tasks at all is the common case (most boots) — must return an
/// empty `Vec`, not error.
#[tokio::test]
async fn suspended_tasks_is_empty_when_nothing_is_suspended() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    writer
        .append(RUNNER.record_task_created(
            SessionId::new(),
            0,
            now_ts(),
            TaskId::new(),
            TaskKind::Shell,
            None,
            Origin::Model,
            TaskInput::Text("ls".into()),
            1,
        ))
        .await
        .unwrap();

    let query_store = open(&db_path).await.unwrap();
    let suspended = suspended_tasks(&query_store).await.unwrap();
    assert!(suspended.is_empty());
}
