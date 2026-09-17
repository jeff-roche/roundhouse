//! Task 19a Task 1: `EventWriter::close_session` (the durable-store half of session close)
//! and the tail guard it depends on (`StoreError::SessionClosed`, rejecting any append
//! whose session log already ends in `SessionClosed`).
//!
//! Ruling P1 (binding, see `.superpowers/sdd/2026-09-17-phase8-t19a-session-close/
//! global-constraints.md`): the sweep this file exercises covers open tasks in
//! `Created`, `Decided`, `Running` **and `Suspended`** — deliberately wider than
//! `recover_interrupted_tasks` (`recovery.rs`), which skips `Suspended` because a
//! daemon restart re-arms a suspended task through the attention-queue path. A session
//! close has no "later" to re-arm into once the session itself is gone, so every open
//! task, including one merely waiting on an approval/elicitation/reply, is cancelled.

use roundhouse_core::{
    CancelReason, IsolationAttestation, Origin, SessionId, SessionOutcome, SuspendReason, TaskId,
    TaskInput, TaskKind, Tier, Timestamp, Trust, Usage,
};
use roundhouse_store::{fold_task, open, spawn_writer, CloseReceipt, StoreError, StoredEvent};

static RUNNER: once_cell::sync::Lazy<roundhouse_core::TaskRunner> =
    once_cell::sync::Lazy::new(roundhouse_core::TaskRunner::bootstrap);

/// `Timestamp` (Phase 0, frozen) exposes only `from_unix_nanos`/`as_unix_nanos` — no
/// `now()` (see Resolved Ambiguity #5 / audit finding X4).
fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

fn isolation() -> IsolationAttestation {
    IsolationAttestation {
        tier: Tier::None,
        digest: "test".to_string(),
        net_enforced: false,
    }
}

/// One row read back from `events`/`tasks` for assertions: `(seq, payload_json)`.
async fn session_events_ordered(
    store: &roundhouse_store::StorePool,
    session_id: SessionId,
) -> Vec<(i64, String)> {
    let session_id_str = session_id.to_string();
    let conn = store.pool.get().await.unwrap();
    conn.interact(move |c| {
        let mut stmt = c
            .prepare("SELECT seq, payload FROM events WHERE session_id = ?1 ORDER BY seq")
            .unwrap();
        stmt.query_map([session_id_str], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    })
    .await
    .unwrap()
}

async fn task_state_in_tasks_view(store: &roundhouse_store::StorePool, task_id: TaskId) -> String {
    let task_id_str = task_id.to_string();
    let conn = store.pool.get().await.unwrap();
    conn.interact(move |c| {
        c.query_row(
            "SELECT state FROM tasks WHERE task_id = ?1",
            [task_id_str],
            |row| row.get(0),
        )
        .unwrap()
    })
    .await
    .unwrap()
}

/// Creates a task and drives it to `Created` (just the `TaskCreated` event).
async fn task_left_created(
    writer: &roundhouse_store::EventWriter,
    session_id: SessionId,
) -> TaskId {
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
    task_id
}

/// Drives a task to `Running` (`TaskCreated` + `TaskStarted`).
async fn task_left_running(
    writer: &roundhouse_store::EventWriter,
    session_id: SessionId,
) -> TaskId {
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
            TaskInput::Text("sleep 100".into()),
            1,
        ))
        .await
        .unwrap();
    writer
        .append(RUNNER.record_task_started(session_id, 0, now_ts(), task_id, isolation(), None, 1))
        .await
        .unwrap();
    task_id
}

/// Drives a task to `Suspended` (`TaskCreated` + `TaskStarted` + `TaskSuspended`).
async fn task_left_suspended(
    writer: &roundhouse_store::EventWriter,
    session_id: SessionId,
) -> TaskId {
    let task_id = task_left_running(writer, session_id).await;
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
    task_id
}

/// Drives a task all the way to `Completed` — this task must survive a close untouched.
async fn task_left_completed(
    writer: &roundhouse_store::EventWriter,
    session_id: SessionId,
) -> TaskId {
    let task_id = task_left_running(writer, session_id).await;
    writer
        .append(RUNNER.record_task_completed(
            session_id,
            0,
            now_ts(),
            task_id,
            roundhouse_core::TaskOutput::Text("done".into()),
            Usage::default(),
            Trust::Trusted,
            1,
        ))
        .await
        .unwrap();
    task_id
}

#[tokio::test]
async fn close_sweeps_open_tasks_and_appends_the_terminator_last_in_one_call() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir.path().join("events.db")).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();
    let created = task_left_created(&writer, session_id).await;
    let running = task_left_running(&writer, session_id).await;
    let suspended = task_left_suspended(&writer, session_id).await;
    let completed = task_left_completed(&writer, session_id).await;

    let receipt = writer
        .close_session(&RUNNER, session_id, now_ts(), SessionOutcome::Cancelled)
        .await
        .unwrap();

    assert_eq!(
        receipt,
        CloseReceipt::Closed { swept: 3 },
        "created/running/suspended are open; completed must not be swept"
    );

    let query_store = open(&dir.path().join("events.db")).await.unwrap();
    let rows = session_events_ordered(&query_store, session_id).await;
    let payloads: Vec<roundhouse_core::EventPayload> = rows
        .iter()
        .map(|(_, payload)| serde_json::from_str(payload).unwrap())
        .collect();

    // Sweep events first, terminator last: the very last row in seq order is the one and
    // only SessionClosed, and it's strictly after every TaskCancelled the sweep minted.
    assert!(
        matches!(
            payloads.last(),
            Some(roundhouse_core::EventPayload::SessionClosed { .. })
        ),
        "terminator must be the last event by seq: {payloads:?}"
    );
    let session_closed_count = payloads
        .iter()
        .filter(|payload| matches!(payload, roundhouse_core::EventPayload::SessionClosed { .. }))
        .count();
    assert_eq!(session_closed_count, 1);

    let cancelled: Vec<&roundhouse_core::EventPayload> = payloads
        .iter()
        .filter(|payload| matches!(payload, roundhouse_core::EventPayload::TaskCancelled { .. }))
        .collect();
    assert_eq!(cancelled.len(), 3, "one TaskCancelled per open task");
    for event in &cancelled {
        assert!(matches!(
            event,
            roundhouse_core::EventPayload::TaskCancelled {
                by: Origin::System,
                reason: CancelReason::SessionClosed,
            }
        ));
    }

    for task_id in [created, running, suspended] {
        assert_eq!(
            task_state_in_tasks_view(&query_store, task_id).await,
            "Cancelled"
        );
    }
    assert_eq!(
        task_state_in_tasks_view(&query_store, completed).await,
        "Completed"
    );
}

#[tokio::test]
async fn second_close_returns_already_closed_and_appends_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir.path().join("events.db")).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();
    let _open_task = task_left_running(&writer, session_id).await;

    let first = writer
        .close_session(&RUNNER, session_id, now_ts(), SessionOutcome::Cancelled)
        .await
        .unwrap();
    assert_eq!(first, CloseReceipt::Closed { swept: 1 });

    let query_store = open(&dir.path().join("events.db")).await.unwrap();
    let rows_after_first = session_events_ordered(&query_store, session_id).await;

    let second = writer
        .close_session(&RUNNER, session_id, now_ts(), SessionOutcome::Completed)
        .await
        .unwrap();
    assert_eq!(second, CloseReceipt::AlreadyClosed);

    let rows_after_second = session_events_ordered(&query_store, session_id).await;
    assert_eq!(
        rows_after_first, rows_after_second,
        "a second close must append nothing"
    );
}

#[tokio::test]
async fn append_after_close_is_rejected_with_session_closed_error() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir.path().join("events.db")).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();
    writer
        .close_session(&RUNNER, session_id, now_ts(), SessionOutcome::Completed)
        .await
        .unwrap();

    let task_id = TaskId::new();
    let event = RUNNER.record_task_created(
        session_id,
        0,
        now_ts(),
        task_id,
        TaskKind::Shell,
        None,
        Origin::Model,
        TaskInput::Text("too late".into()),
        1,
    );

    let err = writer.append(event).await.unwrap_err();
    assert!(
        matches!(err, StoreError::SessionClosed(_)),
        "expected StoreError::SessionClosed, got {err:?}"
    );
}

#[tokio::test]
async fn append_batch_after_close_is_rejected_and_commits_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir.path().join("events.db")).await.unwrap();
    let writer = spawn_writer(store).await;

    let closed_session = SessionId::new();
    writer
        .close_session(&RUNNER, closed_session, now_ts(), SessionOutcome::Completed)
        .await
        .unwrap();

    // A second, still-open session shares this batch — proving a rejected batch commits
    // NOTHING, not just skipping the closed session's own member.
    let open_session = SessionId::new();
    let open_task_id = TaskId::new();
    let closed_task_id = TaskId::new();

    let events = vec![
        RUNNER.record_task_created(
            open_session,
            0,
            now_ts(),
            open_task_id,
            TaskKind::Shell,
            None,
            Origin::Model,
            TaskInput::Text("fine".into()),
            1,
        ),
        RUNNER.record_task_created(
            closed_session,
            0,
            now_ts(),
            closed_task_id,
            TaskKind::Shell,
            None,
            Origin::Model,
            TaskInput::Text("too late".into()),
            1,
        ),
    ];

    let err = writer.append_batch(events).await.unwrap_err();
    assert!(
        matches!(err, StoreError::SessionClosed(_)),
        "expected StoreError::SessionClosed, got {err:?}"
    );

    let query_store = open(&dir.path().join("events.db")).await.unwrap();
    let open_session_rows = session_events_ordered(&query_store, open_session).await;
    assert!(
        open_session_rows.is_empty(),
        "a rejected batch must commit nothing, including for a session that was itself still open"
    );
}

#[tokio::test]
async fn fold_task_over_stored_events_equals_the_tasks_view_after_the_sweep() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir.path().join("events.db")).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();
    let created = task_left_created(&writer, session_id).await;
    let running = task_left_running(&writer, session_id).await;
    let suspended = task_left_suspended(&writer, session_id).await;
    let completed = task_left_completed(&writer, session_id).await;

    writer
        .close_session(&RUNNER, session_id, now_ts(), SessionOutcome::Cancelled)
        .await
        .unwrap();

    let query_store = open(&dir.path().join("events.db")).await.unwrap();

    for task_id in [created, running, suspended, completed] {
        let task_id_str = task_id.to_string();
        let conn = query_store.pool.get().await.unwrap();
        let rows: Vec<(i64, Option<String>, String, i64)> = conn
            .interact(move |c| {
                let mut stmt = c
                    .prepare(
                        "SELECT seq, task_id, payload, schema_v FROM events \
                         WHERE task_id = ?1 ORDER BY seq",
                    )
                    .unwrap();
                stmt.query_map([task_id_str], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
            })
            .await
            .unwrap();

        let stored_events: Vec<StoredEvent> = rows
            .into_iter()
            .map(|(seq, task_id_col, payload, schema_v)| StoredEvent {
                session_id,
                seq: seq as u64,
                ts: now_ts(),
                task_id: task_id_col.map(|_| task_id),
                payload: serde_json::from_str(&payload).unwrap(),
                schema_v: schema_v as u16,
            })
            .collect();

        let folded_state = fold_task(&stored_events).unwrap().state;
        let folded_state_str = match folded_state {
            roundhouse_store::TaskState::Created => "Created",
            roundhouse_store::TaskState::Decided => "Decided",
            roundhouse_store::TaskState::Running => "Running",
            roundhouse_store::TaskState::Suspended => "Suspended",
            roundhouse_store::TaskState::Completed => "Completed",
            roundhouse_store::TaskState::Failed => "Failed",
            roundhouse_store::TaskState::Cancelled => "Cancelled",
            roundhouse_store::TaskState::Interrupted => "Interrupted",
        };

        let tasks_view_state = task_state_in_tasks_view(&query_store, task_id).await;
        assert_eq!(
            folded_state_str, tasks_view_state,
            "fold_task and the tasks view must agree for {task_id:?} after the sweep"
        );
    }

    // And, concretely: every swept task folds/views as Cancelled (reason SessionClosed,
    // which is not the DaemonRestart special case), never Interrupted.
    for task_id in [created, running, suspended] {
        assert_eq!(
            task_state_in_tasks_view(&query_store, task_id).await,
            "Cancelled"
        );
    }
    assert_eq!(
        task_state_in_tasks_view(&query_store, completed).await,
        "Completed"
    );
}

/// Direct coverage of `append_event_in_transaction`'s own tail guard (not just the
/// `EventWriter`-mediated paths above) — the "composable form" other crates call directly
/// inside their own transactions (`workflow_host.rs`, `sub_agent_host.rs`,
/// `scheduler_driver.rs`).
#[test]
fn append_event_in_transaction_rejects_after_a_session_closed_tail() {
    let mut conn = rusqlite::Connection::open_in_memory().unwrap();
    roundhouse_store::migrations().to_latest(&mut conn).unwrap();
    let redactor = roundhouse_store::redact::Redactor::build(&[]);
    let session_id = SessionId::new();

    {
        let txn = roundhouse_store::begin_immediate(&mut conn).unwrap();
        let closed =
            RUNNER.record_session_closed(session_id, 0, now_ts(), SessionOutcome::Completed, 1);
        roundhouse_store::append_event_in_transaction(&txn, &closed, &redactor).unwrap();
        txn.commit().unwrap();
    }

    let txn = roundhouse_store::begin_immediate(&mut conn).unwrap();
    let task_id = TaskId::new();
    let event = RUNNER.record_task_created(
        session_id,
        0,
        now_ts(),
        task_id,
        TaskKind::Shell,
        None,
        Origin::Model,
        TaskInput::Text("too late".into()),
        1,
    );
    let err = roundhouse_store::append_event_in_transaction(&txn, &event, &redactor).unwrap_err();
    assert!(matches!(err, StoreError::SessionClosed(_)));
}

/// `CancelReason::SessionClosed` sanity check — used above only through string matching
/// on the persisted JSON; this pins the enum variant actually exists and round-trips, so a
/// rename of the variant fails this test rather than silently degrading the string checks
/// above into false negatives.
#[test]
fn cancel_reason_session_closed_round_trips() {
    let json = serde_json::to_string(&CancelReason::SessionClosed).unwrap();
    let back: CancelReason = serde_json::from_str(&json).unwrap();
    assert!(matches!(back, CancelReason::SessionClosed));
}
