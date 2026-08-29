use roundhouse_core::{
    IsolationAttestation, Origin, SessionId, SuspendReason, TaskId, TaskInput, TaskKind, Tier,
    Timestamp,
};
use roundhouse_store::{
    fold_task, open, recover_interrupted_tasks, spawn_writer, StoredEvent, TaskState,
};

static RUNNER: once_cell::sync::Lazy<roundhouse_core::TaskRunner> =
    once_cell::sync::Lazy::new(roundhouse_core::TaskRunner::bootstrap);

/// Timestamp has no `now()` (see Resolved Ambiguity #5 / audit finding X4) — read the
/// wall clock ourselves and convert.
fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

#[tokio::test]
async fn running_task_with_no_terminal_event_becomes_interrupted_on_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir.path().join("events.db")).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();
    let task_id = TaskId::new();

    let event_created = RUNNER.record_task_created(
        session_id,
        0,
        now_ts(),
        task_id,
        TaskKind::Shell,
        None,
        Origin::Model,
        TaskInput::Text("ls".into()),
        1,
    );

    writer.append(event_created).await.unwrap();

    let event_started = RUNNER.record_task_started(
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
    );

    writer.append(event_started).await.unwrap();

    // Simulate a fresh daemon process reopening the same database after a crash.
    let dir_path = dir.path().join("events.db");
    let reopened_store = open(&dir_path).await.unwrap();
    let reopened_writer = spawn_writer(reopened_store).await;
    let reopened_store_for_recovery = open(&dir_path).await.unwrap();

    let interrupted =
        recover_interrupted_tasks(&reopened_store_for_recovery, &reopened_writer, &RUNNER)
            .await
            .unwrap();

    assert_eq!(interrupted, vec![task_id]);

    let conn = reopened_store_for_recovery.pool.get().await.unwrap();
    let rows: Vec<(Option<String>, String)> = conn
        .interact(move |c| {
            let mut stmt = c
                .prepare("SELECT task_id, payload FROM events WHERE task_id = ?1 ORDER BY seq")
                .unwrap();
            stmt.query_map([task_id.to_string()], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        })
        .await
        .unwrap();

    assert_eq!(
        rows.len(),
        3,
        "created + started + synthetic interrupt event"
    );

    let stored_events: Vec<StoredEvent> = rows
        .iter()
        .enumerate()
        .map(|(i, (_, payload))| StoredEvent {
            session_id,
            seq: i as u64,
            ts: now_ts(),
            task_id: Some(task_id),
            payload: serde_json::from_str(payload).unwrap(),
            schema_v: 1,
        })
        .collect();

    let task = fold_task(&stored_events).unwrap();
    assert_eq!(task.state, TaskState::Interrupted);
}

/// Audit finding 3: a task left `Suspended` (e.g. `AwaitingApproval`, mid-approval-flow)
/// at "crash" time must NOT be reclassified as `Interrupted` on recovery — the resolved
/// semantics (`docs/architecture/README.md`) re-arm it through the attention-queue path
/// instead, never wipe it.
#[tokio::test]
async fn suspended_task_is_not_reclassified_as_interrupted_on_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir.path().join("events.db")).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();
    let task_id = TaskId::new();

    let event_created = RUNNER.record_task_created(
        session_id,
        0,
        now_ts(),
        task_id,
        TaskKind::Shell,
        None,
        Origin::Model,
        TaskInput::Text("rm -rf /tmp/scratch".into()),
        1,
    );

    writer.append(event_created).await.unwrap();

    let event_started = RUNNER.record_task_started(
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
    );

    writer.append(event_started).await.unwrap();

    let event_suspended = RUNNER.record_task_suspended(
        session_id,
        0,
        now_ts(),
        task_id,
        SuspendReason::AwaitingApproval,
        1,
    );

    writer.append(event_suspended).await.unwrap();

    // Simulate a fresh daemon process reopening the same database after a crash.
    let dir_path = dir.path().join("events.db");
    let reopened_store = open(&dir_path).await.unwrap();
    let reopened_writer = spawn_writer(reopened_store).await;
    let reopened_store_for_recovery = open(&dir_path).await.unwrap();

    let interrupted =
        recover_interrupted_tasks(&reopened_store_for_recovery, &reopened_writer, &RUNNER)
            .await
            .unwrap();

    assert_eq!(
        interrupted,
        Vec::<TaskId>::new(),
        "a Suspended task must not be interrupted"
    );

    let conn = reopened_store_for_recovery.pool.get().await.unwrap();
    let rows: Vec<String> = conn
        .interact(move |c| {
            let mut stmt = c
                .prepare("SELECT payload FROM events WHERE task_id = ?1 ORDER BY seq")
                .unwrap();
            stmt.query_map([task_id.to_string()], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        })
        .await
        .unwrap();

    assert_eq!(
        rows.len(),
        3,
        "recovery must not append a synthetic event for a Suspended task"
    );

    let stored_events: Vec<StoredEvent> = rows
        .iter()
        .enumerate()
        .map(|(i, payload)| StoredEvent {
            session_id,
            seq: i as u64,
            ts: now_ts(),
            task_id: Some(task_id),
            payload: serde_json::from_str(payload).unwrap(),
            schema_v: 1,
        })
        .collect();

    let task = fold_task(&stored_events).unwrap();
    assert_eq!(task.state, TaskState::Suspended);
}
