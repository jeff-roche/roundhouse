//! Task 4 (Phase 7): `EngineTaskSpawner` is the production
//! `roundhouse_mcp::executor::TaskSpawner`. The whole point of that trait
//! over a bare `TaskId::new()` is that the minted id must actually resolve
//! through the real event-sourced task view (S-LOG-1) — a fabricated id is
//! precisely the bug this closes. This test proves that end to end: it
//! calls `spawn_task`, then re-opens the store fresh (a brand new
//! `StorePool`, not the one the writer already holds) and folds the task
//! straight out of its replayed events, the same way
//! `chat_infer_tree.rs`'s own follow-on assertion does.

use once_cell::sync::Lazy;
use roundhouse_core::{Origin, SessionId, TaskId, TaskKind, TaskRunner};
use roundhouse_engine::mcp_spawner::EngineTaskSpawner;
use roundhouse_mcp::executor::{TaskInput as McpTaskInput, TaskSpawner};
use roundhouse_policy::ServerId;
use roundhouse_store::{fold_task, open, spawn_writer, StoredEvent};

/// `TaskRunner::bootstrap()` panics if called more than once per process
/// (S-LOG-1's single-authority guarantee) — this test binary is one
/// process, so every test in it shares one bootstrapped instance, matching
/// `chat_infer_tree.rs`/`admission_integration.rs`'s own pattern.
static RUNNER: Lazy<TaskRunner> = Lazy::new(TaskRunner::bootstrap);

/// Reads every event row for `task_id` back out of the append-only `events`
/// table and deserializes each into a `StoredEvent`, so `fold_task` can run
/// over data that actually round-tripped through storage — mirrors
/// `chat_infer_tree.rs`'s identical helper.
async fn load_task_events(
    store: &roundhouse_store::StorePool,
    task_id: TaskId,
) -> Vec<StoredEvent> {
    let conn = store.pool.get().await.expect("pool connection");
    let task_id_str = task_id.to_string();
    let rows: Vec<(String, i64, i64, Option<String>, String, i64)> = conn
        .interact(move |c| {
            let mut stmt = c
                .prepare(
                    "SELECT session_id, seq, ts, task_id, payload, schema_v
                     FROM events WHERE task_id = ?1 ORDER BY seq",
                )
                .expect("prepare statement");
            stmt.query_map([task_id_str], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })
            .expect("query_map")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect rows")
        })
        .await
        .expect("interact");

    rows.into_iter()
        .map(
            |(session_id, seq, ts_nanos, task_id_opt, payload, schema_v)| StoredEvent {
                session_id: roundhouse_core::SessionId::from_uuid(
                    uuid::Uuid::parse_str(&session_id).expect("valid session_id uuid"),
                ),
                seq: u64::try_from(seq).expect("non-negative seq"),
                ts: roundhouse_core::Timestamp::from_unix_nanos(ts_nanos),
                task_id: task_id_opt.map(|s| {
                    roundhouse_core::TaskId::from_uuid(
                        uuid::Uuid::parse_str(&s).expect("valid task_id uuid"),
                    )
                }),
                payload: serde_json::from_str(&payload).expect("valid EventPayload JSON"),
                schema_v: schema_v as u16,
            },
        )
        .collect()
}

#[tokio::test]
async fn engine_task_spawner_mints_a_real_queryable_task_not_a_bare_taskid() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    let session_id = SessionId::new();
    let spawner = EngineTaskSpawner::new(&RUNNER, writer, session_id);

    let task_id = spawner
        .spawn_task(
            session_id,
            None,
            TaskKind::Mcp,
            Origin::System,
            McpTaskInput::Mcp {
                server: ServerId("github".into()),
                tool: "server/discover".into(),
                args: serde_json::json!({}),
            },
        )
        .await;

    // Re-open the store fresh (a brand-new `StorePool`, independent of the
    // writer's own pool) and fold the task straight out of its replayed
    // events — proving the id resolves through the real store, not just
    // through the same in-process writer that minted it.
    let reopened = open(&db_path).await.unwrap();
    let events = load_task_events(&reopened, task_id).await;
    let task = fold_task(&events)
        .expect("TaskCreated event present — the minted id must be queryable, not fabricated");
    assert_eq!(task.kind, TaskKind::Mcp);
    assert_eq!(task.id, task_id);
}

#[tokio::test]
async fn suspend_decision_and_terminal_are_all_recorded_durably() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    let session_id = SessionId::new();
    let spawner = EngineTaskSpawner::new(&RUNNER, writer, session_id);

    let task_id = spawner
        .spawn_task(
            session_id,
            None,
            TaskKind::Mcp,
            Origin::System,
            McpTaskInput::Mcp {
                server: ServerId("github".into()),
                tool: "search".into(),
                args: serde_json::json!({"q": "roundhouse"}),
            },
        )
        .await;

    spawner
        .record_decision(task_id, roundhouse_core::PolicyDecision::Allow)
        .await;

    spawner
        .suspend_task(
            task_id,
            roundhouse_core::SuspendReason::AwaitingElicitation {
                schema: serde_json::json!({}),
            },
        )
        .await;

    spawner
        .record_terminal(
            task_id,
            roundhouse_mcp::executor::TerminalOutcome::Completed {
                output: roundhouse_core::TaskOutput::Json(serde_json::json!({"ok": true})),
                usage: roundhouse_core::Usage::default(),
            },
        )
        .await;

    let reopened = open(&db_path).await.unwrap();
    let events = load_task_events(&reopened, task_id).await;
    let task = fold_task(&events).expect("task must be queryable after every record_* call");
    assert_eq!(task.state, roundhouse_store::TaskState::Completed);

    // Every payload kind this test drove actually landed in the append-only
    // log, not just the terminal one.
    assert!(events.iter().any(|e| matches!(
        &e.payload,
        roundhouse_core::EventPayload::TaskDecided { .. }
    )));
    assert!(events.iter().any(|e| matches!(
        &e.payload,
        roundhouse_core::EventPayload::TaskSuspended { .. }
    )));
    assert!(events.iter().any(|e| matches!(
        &e.payload,
        roundhouse_core::EventPayload::TaskCompleted { .. }
    )));
}
