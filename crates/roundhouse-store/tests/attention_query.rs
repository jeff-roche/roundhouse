//! Tests for `roundhouse_store::blocked_anywhere` (Task 21, S-OBS-4): the
//! one indexed query that finds every suspended task — approvals, elicits,
//! workflow gates alike — across every session in the whole daemon.
//!
//! `finds_approvals_elicits_and_workflow_gates_across_every_session` follows
//! `tests/suspended.rs`'s real construction pattern (`open`/`spawn_writer`/
//! `TaskRunner::record_*`, not a fictional `Store` type).
//!
//! `query_completes_within_50ms_over_10000_sessions` follows
//! `tests/recovery_scale.rs`'s real seeding pattern: raw bulk SQL against a
//! plain `rusqlite::Connection`, in one transaction, so seeding cost doesn't
//! dominate and mask the real query performance under test — only the call
//! to `blocked_anywhere` itself is timed.

use roundhouse_core::{Origin, RuleId, SessionId, SuspendReason, TaskId, TaskInput, TaskKind};
use roundhouse_store::{blocked_anywhere, open, spawn_writer};

static RUNNER: once_cell::sync::Lazy<roundhouse_core::TaskRunner> =
    once_cell::sync::Lazy::new(roundhouse_core::TaskRunner::bootstrap);

fn now_ts() -> roundhouse_core::Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    roundhouse_core::Timestamp::from_unix_nanos(nanos)
}

#[tokio::test]
async fn finds_approvals_elicits_and_workflow_gates_across_every_session() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let s1 = SessionId::new();
    let t1 = TaskId::new();
    seed_suspended(
        &writer,
        s1,
        t1,
        TaskKind::Shell,
        SuspendReason::AwaitingApproval {
            rule: Some(RuleId(1)),
            params_digest: [1u8; 32],
        },
    )
    .await;

    let s2 = SessionId::new();
    let t2 = TaskId::new();
    seed_suspended(
        &writer,
        s2,
        t2,
        TaskKind::Elicit,
        SuspendReason::AwaitingElicitation {
            schema: serde_json::json!({}),
        },
    )
    .await;

    let s3 = SessionId::new();
    let t3 = TaskId::new();
    seed_suspended(
        &writer,
        s3,
        t3,
        TaskKind::Flow,
        SuspendReason::WorkflowGate {
            step_ref: "deploy-approval".into(),
        },
    )
    .await;

    // A plugin-kinded suspended task too, to pin the Plugin{vendor, verb}
    // Debug-format round-trip (Ruling 4) as a real reader, not just unit variants.
    let s4 = SessionId::new();
    let t4 = TaskId::new();
    seed_suspended(
        &writer,
        s4,
        t4,
        TaskKind::Plugin {
            vendor: "acme".into(),
            verb: "deploy".into(),
        },
        SuspendReason::AwaitingReply,
    )
    .await;

    let query_store = open(&db_path).await.unwrap();
    let blocked = blocked_anywhere(&query_store).await.unwrap();

    let found_ids: Vec<_> = blocked.iter().map(|b| b.task_id).collect();
    assert!(
        found_ids.contains(&t1) && found_ids.contains(&t2) && found_ids.contains(&t3),
        "one query must surface approvals, elicit tasks, and workflow gates alike (S-OBS-4)"
    );

    let plugin_task = blocked
        .iter()
        .find(|b| b.task_id == t4)
        .expect("plugin-kinded suspended task must be found too");
    assert_eq!(
        plugin_task.kind,
        TaskKind::Plugin {
            vendor: "acme".into(),
            verb: "deploy".into(),
        },
        "tasks.kind's Debug-formatted Plugin{{vendor, verb}} must round-trip exactly"
    );

    let approval_task = blocked.iter().find(|b| b.task_id == t1).unwrap();
    assert_eq!(
        approval_task.reason,
        SuspendReason::AwaitingApproval {
            rule: Some(RuleId(1)),
            params_digest: [1u8; 32],
        }
    );
    assert_eq!(approval_task.session_id, s1);
}

/// Fix-round-1 regression test: end-to-end, through the real public API against a
/// real database, two DIFFERENT `TaskKind::Plugin` values whose `vendor`s differ
/// only by a Debug escape sequence (one a real control character, one the literal
/// escaped text) must come back as two DIFFERENT, correct `kind`s — not collide,
/// and not silently mangle either one. This is the security auditor's exact
/// reproduction shape (a real BEL character `vendor: "\u{7}"` vs. the literal
/// four-character `vendor: "u{7}"`), run through `seed_suspended` (real
/// `TaskRunner`/`EventWriter` writes, so `tasks.kind` is genuinely
/// Debug-formatted by the real write path) and `blocked_anywhere` (the real read
/// path), not just the parser unit tests in `attention.rs`.
#[tokio::test]
async fn plugin_vendor_with_control_char_and_literal_escape_text_do_not_collide_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let s_control = SessionId::new();
    let t_control = TaskId::new();
    seed_suspended(
        &writer,
        s_control,
        t_control,
        TaskKind::Plugin {
            vendor: "\u{7}".into(), // one real BEL control character
            verb: "v".into(),
        },
        SuspendReason::AwaitingReply,
    )
    .await;

    let s_literal = SessionId::new();
    let t_literal = TaskId::new();
    seed_suspended(
        &writer,
        s_literal,
        t_literal,
        TaskKind::Plugin {
            vendor: "u{7}".into(), // four literal ASCII characters
            verb: "v".into(),
        },
        SuspendReason::AwaitingReply,
    )
    .await;

    let query_store = open(&db_path).await.unwrap();
    let blocked = blocked_anywhere(&query_store).await.unwrap();

    let control_task = blocked
        .iter()
        .find(|b| b.task_id == t_control)
        .expect("control-char-vendor task must be found");
    let literal_task = blocked
        .iter()
        .find(|b| b.task_id == t_literal)
        .expect("literal-escape-text-vendor task must be found");

    assert_eq!(
        control_task.kind,
        TaskKind::Plugin {
            vendor: "\u{7}".into(),
            verb: "v".into(),
        },
        "the real control character must round-trip exactly, not collide with the literal text"
    );
    assert_eq!(
        literal_task.kind,
        TaskKind::Plugin {
            vendor: "u{7}".into(),
            verb: "v".into(),
        },
        "the literal escaped text must round-trip exactly, not collide with the control character"
    );
    assert_ne!(control_task.kind, literal_task.kind);
}

#[tokio::test]
async fn excludes_non_suspended_tasks() {
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

    let query_store = open(&db_path).await.unwrap();
    let blocked = blocked_anywhere(&query_store).await.unwrap();
    assert!(blocked.is_empty());
}

#[tokio::test]
async fn is_empty_when_nothing_is_suspended_anywhere() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let _writer = spawn_writer(store).await;

    let query_store = open(&db_path).await.unwrap();
    let blocked = blocked_anywhere(&query_store).await.unwrap();
    assert!(blocked.is_empty());
}

/// Fail-closed guard (Ruling 1/Task's constraint): a corrupt `suspend_reason_json`
/// on a `state = 'Suspended'` row must be a real, surfaced error — never silently
/// skipped, never defaulted.
#[tokio::test]
async fn errors_on_unparseable_suspend_reason_json_instead_of_defaulting() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();
    let task_id = TaskId::new();
    seed_suspended(
        &writer,
        session_id,
        task_id,
        TaskKind::Shell,
        SuspendReason::AwaitingReply,
    )
    .await;

    {
        let task_id_str = task_id.to_string();
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let rows_affected = conn
            .execute(
                "UPDATE tasks SET suspend_reason_json = '{\"NotAVariant\":{}}' WHERE task_id = ?1",
                [task_id_str],
            )
            .unwrap();
        assert_eq!(rows_affected, 1);
    }

    let query_store = open(&db_path).await.unwrap();
    let result = blocked_anywhere(&query_store).await;
    assert!(
        result.is_err(),
        "unparseable suspend_reason_json must be a hard error, not a silent default"
    );
}

/// Fail-closed guard for `tasks.kind` (Ruling 4): a corrupt/unrecognized `kind`
/// value on a `Suspended` row must also be a hard error, never a silent skip or a
/// panic.
#[tokio::test]
async fn errors_on_unparseable_kind_instead_of_defaulting() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();
    let task_id = TaskId::new();
    seed_suspended(
        &writer,
        session_id,
        task_id,
        TaskKind::Shell,
        SuspendReason::AwaitingReply,
    )
    .await;

    {
        let task_id_str = task_id.to_string();
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let rows_affected = conn
            .execute(
                "UPDATE tasks SET kind = 'NotARealKind' WHERE task_id = ?1",
                [task_id_str],
            )
            .unwrap();
        assert_eq!(rows_affected, 1);
    }

    let query_store = open(&db_path).await.unwrap();
    let result = blocked_anywhere(&query_store).await;
    assert!(
        result.is_err(),
        "unparseable tasks.kind must be a hard error, not a silent default"
    );
}

const SESSIONS: usize = 10_000;
const TASKS_PER_SESSION: usize = 20;

#[tokio::test]
async fn query_completes_within_50ms_over_10000_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");

    // `open()` applies migrations; do this once before touching the schema with a
    // raw connection (matches `recovery_scale.rs`'s own precedent).
    drop(open(&db_path).await.unwrap());

    let expected_suspended = seed_scale_data(&db_path);

    let query_store = open(&db_path).await.unwrap();

    let started = std::time::Instant::now();
    let blocked = blocked_anywhere(&query_store).await.unwrap();
    let elapsed = started.elapsed();

    eprintln!(
        "blocked_anywhere over {SESSIONS} sessions x {TASKS_PER_SESSION} tasks \
         ({expected_suspended} suspended) took {elapsed:?}"
    );

    assert_eq!(blocked.len(), expected_suspended);
    assert!(
        elapsed.as_millis() <= 50,
        "S-OBS-4 budget is 50ms over 10,000 sessions, took {elapsed:?}"
    );
}

/// Bulk-seeds `SESSIONS * TASKS_PER_SESSION` tasks via raw SQL in one transaction,
/// with 1-in-5 sessions contributing exactly one `Suspended` task (its first task)
/// and every other task terminal (`Completed`) — matching the brief's own
/// 10,000/20/"1 in 5" math, adapted to real raw-SQL seeding per Ruling 6. Returns
/// the number of rows that end up `Suspended` (for the test's assertion).
fn seed_scale_data(db_path: &std::path::Path) -> usize {
    let mut conn = rusqlite::Connection::open(db_path).unwrap();
    let tx = conn.transaction().unwrap();
    let mut suspended_count = 0usize;
    {
        let mut insert_event = tx
            .prepare(
                "INSERT INTO events (session_id, seq, ts, task_id, payload, schema_v) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .unwrap();
        let mut insert_task = tx
            .prepare(
                "INSERT INTO tasks (task_id, session_id, kind, state, parent, created_seq, \
                 updated_seq, suspended_since, suspend_reason_json) \
                 VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?5, ?6, ?7)",
            )
            .unwrap();

        let created_payload = EventPayloadShim::task_created();
        let reason = SuspendReason::AwaitingApproval {
            rule: None,
            params_digest: [0u8; 32],
        };
        let reason_json = serde_json::to_string(&reason).unwrap();

        for session_idx in 0..SESSIONS {
            let session_id_str = SessionId::new().to_string();
            let suspend_this_session = session_idx % 5 == 0;
            for task_idx in 0..TASKS_PER_SESSION {
                let task_id_str = TaskId::new().to_string();
                let seq = task_idx as i64;

                insert_event
                    .execute(rusqlite::params![
                        session_id_str,
                        seq,
                        0i64,
                        task_id_str,
                        created_payload,
                        1i64
                    ])
                    .unwrap();

                if task_idx == 0 && suspend_this_session {
                    insert_task
                        .execute(rusqlite::params![
                            task_id_str,
                            session_id_str,
                            "Shell",
                            "Suspended",
                            seq,
                            1i64,
                            reason_json
                        ])
                        .unwrap();
                    suspended_count += 1;
                } else {
                    insert_task
                        .execute(rusqlite::params![
                            task_id_str,
                            session_id_str,
                            "Shell",
                            "Completed",
                            seq,
                            Option::<i64>::None,
                            Option::<String>::None
                        ])
                        .unwrap();
                }
            }
        }
    }
    tx.commit().unwrap();
    suspended_count
}

/// A minimal, valid `EventPayload::TaskCreated` JSON string for seeding — the
/// `events` row's payload content doesn't matter to `blocked_anywhere` (which
/// never reads `events` directly), only that `events` stays populated
/// consistently with `tasks`, matching `recovery_scale.rs`'s own seeding shape.
struct EventPayloadShim;
impl EventPayloadShim {
    fn task_created() -> String {
        let payload = roundhouse_core::EventPayload::TaskCreated {
            kind: TaskKind::Shell,
            parent: None,
            origin: Origin::Model,
            input: TaskInput::Text("scale test".into()),
        };
        serde_json::to_string(&payload).unwrap()
    }
}

async fn seed_suspended(
    writer: &roundhouse_store::EventWriter,
    session_id: SessionId,
    task_id: TaskId,
    kind: TaskKind,
    reason: SuspendReason,
) {
    writer
        .append(RUNNER.record_session_created(
            session_id,
            0,
            now_ts(),
            Box::new(roundhouse_core::SessionSpec::test_default()),
            1,
        ))
        .await
        .unwrap();
    writer
        .append(RUNNER.record_task_created(
            session_id,
            0,
            now_ts(),
            task_id,
            kind,
            None,
            Origin::Model,
            TaskInput::Text("test input".into()),
            1,
        ))
        .await
        .unwrap();
    writer
        .append(RUNNER.record_task_decided(
            session_id,
            0,
            now_ts(),
            task_id,
            roundhouse_core::PolicyDecision::Ask,
            None,
            1,
        ))
        .await
        .unwrap();
    writer
        .append(RUNNER.record_task_suspended(session_id, 0, now_ts(), task_id, reason, 1))
        .await
        .unwrap();
}
