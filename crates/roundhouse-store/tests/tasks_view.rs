use roundhouse_core::{
    Delta, EventPayload, NoteLevel, Origin, Progress, RuleId, SessionId, SuspendReason, TaskId,
    TaskInput, TaskKind, Timestamp,
};
use roundhouse_store::{open, spawn_writer, StorePool};

static RUNNER: once_cell::sync::Lazy<roundhouse_core::TaskRunner> =
    once_cell::sync::Lazy::new(roundhouse_core::TaskRunner::bootstrap);

/// `Timestamp` (Phase 0, frozen) exposes only `from_unix_nanos`/`as_unix_nanos` — no
/// `now()` (see Resolved Ambiguity #5 / audit finding X4). Read the wall clock
/// ourselves and convert, matching every other test in this crate.
fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

struct TasksRow {
    session_id: String,
    kind: String,
    state: String,
    parent: Option<String>,
    created_seq: i64,
    updated_seq: i64,
    suspended_since: Option<i64>,
    suspend_reason_json: Option<String>,
}

/// `spawn_writer` moves the `StorePool` it's given into the writer task, so tests that
/// both append (through the writer) and read back the materialized `tasks` row need a
/// second `StorePool` opened against the same path (`open()` is idempotent — migrations
/// are already applied) — the same pattern `tests/recovery.rs` uses.
async fn fetch_tasks_row(store: &StorePool, task_id: TaskId) -> TasksRow {
    let conn = store.pool.get().await.unwrap();
    let task_id_str = task_id.to_string();
    conn.interact(move |c| {
        c.query_row(
            "SELECT session_id, kind, state, parent, created_seq, updated_seq, \
             suspended_since, suspend_reason_json FROM tasks WHERE task_id = ?1",
            [task_id_str],
            |row| {
                Ok(TasksRow {
                    session_id: row.get(0)?,
                    kind: row.get(1)?,
                    state: row.get(2)?,
                    parent: row.get(3)?,
                    created_seq: row.get(4)?,
                    updated_seq: row.get(5)?,
                    suspended_since: row.get(6)?,
                    suspend_reason_json: row.get(7)?,
                })
            },
        )
        .unwrap()
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn task_created_event_populates_a_tasks_row() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    let query_store = open(&db_path).await.unwrap();

    let session_id = SessionId::new();
    let task_id = TaskId::new();

    let seq = writer
        .append(RUNNER.record_task_created(
            session_id,
            0,
            now_ts(),
            task_id,
            TaskKind::Shell,
            None,
            Origin::Model,
            TaskInput::Text("ls".into()),
            1,
        ))
        .await
        .unwrap();

    let row = fetch_tasks_row(&query_store, task_id).await;
    assert_eq!(row.session_id, session_id.to_string());
    assert_eq!(row.kind, "Shell");
    assert_eq!(row.state, "Created");
    assert_eq!(row.parent, None);
    assert_eq!(row.created_seq, seq as i64);
    assert_eq!(
        row.updated_seq, row.created_seq,
        "a freshly created task's created_seq and updated_seq must match"
    );
    assert_eq!(row.suspended_since, None);
    assert_eq!(row.suspend_reason_json, None);
}

#[tokio::test]
async fn task_created_event_records_its_parent() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    let query_store = open(&db_path).await.unwrap();

    let session_id = SessionId::new();
    let parent_id = TaskId::new();
    let child_id = TaskId::new();

    writer
        .append(RUNNER.record_task_created(
            session_id,
            0,
            now_ts(),
            parent_id,
            TaskKind::Chat,
            None,
            Origin::Model,
            TaskInput::Text("chat".into()),
            1,
        ))
        .await
        .unwrap();
    writer
        .append(RUNNER.record_task_created(
            session_id,
            0,
            now_ts(),
            child_id,
            TaskKind::Infer,
            Some(parent_id),
            Origin::Model,
            TaskInput::Text("infer".into()),
            1,
        ))
        .await
        .unwrap();

    let row = fetch_tasks_row(&query_store, child_id).await;
    assert_eq!(row.parent, Some(parent_id.to_string()));
}

#[tokio::test]
async fn task_suspended_event_sets_suspended_since_and_a_reason_that_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    let query_store = open(&db_path).await.unwrap();

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

    let reason = SuspendReason::AwaitingApproval {
        rule: Some(RuleId(1)),
        params_digest: [1u8; 32],
    };
    let before_nanos = now_ts().as_unix_nanos();
    writer
        .append(RUNNER.record_task_suspended(session_id, 0, now_ts(), task_id, reason.clone(), 1))
        .await
        .unwrap();
    let after_nanos = now_ts().as_unix_nanos();

    let row = fetch_tasks_row(&query_store, task_id).await;
    assert_eq!(row.state, "Suspended");
    let suspended_since = row
        .suspended_since
        .expect("suspended_since must be set once a task is Suspended");
    assert!(
        (before_nanos..=after_nanos).contains(&suspended_since),
        "suspended_since ({suspended_since}) must be the real event timestamp, \
         not a placeholder like `seq` — expected it within [{before_nanos}, {after_nanos}]"
    );

    let stored_reason: SuspendReason = serde_json::from_str(
        &row.suspend_reason_json
            .expect("suspend_reason_json must be set once a task is Suspended"),
    )
    .expect("suspend_reason_json must deserialize back into a SuspendReason");
    assert_eq!(stored_reason, reason);
}

#[tokio::test]
async fn resuming_a_suspended_task_clears_suspension_fields() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    let query_store = open(&db_path).await.unwrap();

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
            TaskInput::Text("ls".into()),
            1,
        ))
        .await
        .unwrap();
    writer
        .append(RUNNER.record_task_suspended(
            session_id,
            0,
            now_ts(),
            task_id,
            SuspendReason::AwaitingReply,
            1,
        ))
        .await
        .unwrap();
    writer
        .append(RUNNER.record_task_resumed(session_id, 0, now_ts(), task_id, Origin::User, 1))
        .await
        .unwrap();

    let row = fetch_tasks_row(&query_store, task_id).await;
    assert_eq!(row.state, "Running");
    assert_eq!(
        row.suspended_since, None,
        "resuming must clear suspended_since back to NULL"
    );
    assert_eq!(
        row.suspend_reason_json, None,
        "resuming must clear suspend_reason_json back to NULL"
    );
}

#[tokio::test]
async fn completing_a_suspended_task_clears_suspension_fields() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    let query_store = open(&db_path).await.unwrap();

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
            TaskInput::Text("ls".into()),
            1,
        ))
        .await
        .unwrap();
    writer
        .append(RUNNER.record_task_suspended(
            session_id,
            0,
            now_ts(),
            task_id,
            SuspendReason::AwaitingReply,
            1,
        ))
        .await
        .unwrap();
    writer
        .append(RUNNER.record_task_completed(
            session_id,
            0,
            now_ts(),
            task_id,
            roundhouse_core::TaskOutput::Text("done".into()),
            roundhouse_core::Usage::default(),
            1,
        ))
        .await
        .unwrap();

    let row = fetch_tasks_row(&query_store, task_id).await;
    assert_eq!(row.state, "Completed");
    assert_eq!(row.suspended_since, None);
    assert_eq!(row.suspend_reason_json, None);
}

#[tokio::test]
async fn task_delta_progress_and_note_events_do_not_touch_the_tasks_row() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    let query_store = open(&db_path).await.unwrap();

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
            TaskInput::Text("ls".into()),
            1,
        ))
        .await
        .unwrap();

    let row_before = fetch_tasks_row(&query_store, task_id).await;

    writer
        .append(RUNNER.record_task_delta(
            session_id,
            0,
            now_ts(),
            task_id,
            Delta::Text { text: "hi".into() },
            1,
        ))
        .await
        .unwrap();
    writer
        .append(RUNNER.record_task_progress(
            session_id,
            0,
            now_ts(),
            task_id,
            Progress {
                message: "working".into(),
                fraction: Some(0.5),
            },
            1,
        ))
        .await
        .unwrap();
    writer
        .append(RUNNER.record_note(
            session_id,
            0,
            now_ts(),
            Some(task_id),
            NoteLevel::Info,
            "a note".into(),
            1,
        ))
        .await
        .unwrap();

    let row_after = fetch_tasks_row(&query_store, task_id).await;
    assert_eq!(
        row_after.updated_seq, row_before.updated_seq,
        "TaskDelta/TaskProgress/Note must be a genuine no-op on the tasks row, \
         not merely 'doesn't crash' — updated_seq must not advance"
    );
    assert_eq!(row_after.state, row_before.state);
    assert_eq!(row_after.suspended_since, row_before.suspended_since);
    assert_eq!(
        row_after.suspend_reason_json,
        row_before.suspend_reason_json
    );
}

/// Security fix (post-review): a state-changing event whose `task_id` has no existing
/// `tasks` row (the `UPDATE` branch of `upsert_for_event` matches zero rows) must be a
/// hard, loud error — not a silent no-op. Before the fix, `tx.execute(...)`'s
/// rows-affected count was discarded and `Ok(())` returned unconditionally, so the event
/// would commit to `events` while the `tasks` cache silently failed to reflect it.
#[tokio::test]
async fn a_state_changing_event_for_an_unknown_task_id_is_a_hard_error_not_a_silent_noop() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();
    let task_id = TaskId::new(); // never created — no `tasks` row exists for it

    let result = writer
        .append(RUNNER.record_task_started(
            session_id,
            0,
            now_ts(),
            task_id,
            roundhouse_core::IsolationAttestation {
                tier: roundhouse_core::Tier::None,
                digest: "test".into(),
                net_enforced: false,
            },
            None,
            1,
        ))
        .await;

    assert!(
        result.is_err(),
        "a state-changing event for a task_id with no existing tasks row must be a hard \
         error, not silently Ok — got {result:?}"
    );
}

/// Security fix (post-review): reproduces the audit's exact scenario. Migration 0003 only
/// adds columns — it never backfills `tasks` rows for tasks that already existed in the
/// event log before this migration ran. Combined with the hard-error fix above, every
/// subsequent lifecycle event for such a pre-existing task would otherwise become a hard
/// failure (not just a silent gap) unless something backfills it first. `open()` now runs
/// that backfill automatically, right after migrations apply.
#[tokio::test]
async fn reopening_the_store_backfills_a_tasks_row_for_a_task_that_predates_this_migration() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");

    // First open: applies migrations (including migration 0003's new columns). The
    // backfill this fix adds also runs here, but is a no-op — no events exist yet.
    open(&db_path).await.unwrap();

    // Seed events directly against the `events` table via a raw connection, bypassing
    // `tasks_view`/`writer.rs` entirely — simulating a task that was created and
    // suspended before `roundhouse_store::open()` ever ran a backfill pass (i.e. every
    // task in every database this daemon has ever written to before this fix).
    let session_id = SessionId::new();
    let task_id = TaskId::new();
    let reason = SuspendReason::AwaitingApproval {
        rule: Some(RuleId(7)),
        params_digest: [9u8; 32],
    };
    {
        let seed_conn = rusqlite::Connection::open(&db_path).unwrap();
        let seeded_events = [
            (
                0i64,
                1_000i64,
                serde_json::to_string(&EventPayload::TaskCreated {
                    kind: TaskKind::Shell,
                    parent: None,
                    origin: Origin::Model,
                    input: TaskInput::Text("rm -rf /tmp/scratch".into()),
                })
                .unwrap(),
            ),
            (
                1i64,
                2_000i64,
                serde_json::to_string(&EventPayload::TaskStarted {
                    isolation: roundhouse_core::IsolationAttestation {
                        tier: roundhouse_core::Tier::None,
                        digest: "d".into(),
                        net_enforced: false,
                    },
                    handle: None,
                })
                .unwrap(),
            ),
            (
                2i64,
                3_000i64,
                serde_json::to_string(&EventPayload::TaskSuspended {
                    reason: reason.clone(),
                })
                .unwrap(),
            ),
        ];
        for (seq, ts, payload) in seeded_events {
            seed_conn
                .execute(
                    "INSERT INTO events (session_id, seq, ts, task_id, payload, schema_v) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![
                        session_id.to_string(),
                        seq,
                        ts,
                        task_id.to_string(),
                        payload,
                        1i64
                    ],
                )
                .unwrap();
        }

        // Sanity check, on the same raw connection, before any backfill-triggering
        // open(): the seeded task genuinely has no tasks row yet.
        let exists_before: i64 = seed_conn
            .query_row(
                "SELECT COUNT(*) FROM tasks WHERE task_id = ?1",
                [task_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            exists_before, 0,
            "sanity check: the seeded task must have no tasks row before backfill runs"
        );
    }

    // Simulate a fresh daemon process reopening the same database — this is where the
    // fix's backfill runs (inside open(), right after migrations apply).
    let reopened_store = open(&db_path).await.unwrap();
    let row = fetch_tasks_row(&reopened_store, task_id).await;

    assert_eq!(row.session_id, session_id.to_string());
    assert_eq!(row.kind, "Shell");
    assert_eq!(row.state, "Suspended");
    assert_eq!(row.parent, None);
    assert_eq!(row.created_seq, 0);
    assert_eq!(
        row.updated_seq, 2,
        "updated_seq must be the seq of the event that produced the current state \
         (TaskSuspended), matching the live path's semantics"
    );
    assert_eq!(
        row.suspended_since,
        Some(3_000),
        "backfilled suspended_since must be the real TaskSuspended event's own timestamp"
    );
    let stored_reason: SuspendReason = serde_json::from_str(
        &row.suspend_reason_json
            .expect("backfilled suspend_reason_json must be set"),
    )
    .expect("suspend_reason_json must deserialize back into a SuspendReason");
    assert_eq!(
        stored_reason, reason,
        "backfill must recover the real SuspendReason, not a placeholder"
    );
}
