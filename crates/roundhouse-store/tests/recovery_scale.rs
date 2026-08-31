//! S-SESS-4's stated performance budget: "500 sessions × 200 tasks recovers
//! within 5s." Verified directly rather than taken on faith — a verification
//! pass on Task 1's original `recover_interrupted_tasks` (full `events` table
//! scan, one `writer.append()` per interrupted task) found it both an
//! unbounded-memory risk and very unlikely to meet this budget; this test
//! pins the rewritten, `tasks`-table-driven, batched version against the real
//! number.
//!
//! Seeding is done via **raw bulk SQL against a plain `rusqlite::Connection`**
//! in one transaction — not via 100,000+ individual `EventWriter::append()`
//! calls, which would make the test's own setup the bottleneck rather than
//! what's actually being measured (`recover_interrupted_tasks` itself). Only
//! the call to `recover_interrupted_tasks` is inside the timed section.

use roundhouse_core::{EventPayload, Origin, SessionId, TaskId, TaskInput, TaskKind};
use roundhouse_store::{open, recover_interrupted_tasks, spawn_writer};

const SESSIONS: usize = 500;
const TASKS_PER_SESSION: usize = 200;
const TOTAL_TASKS: usize = SESSIONS * TASKS_PER_SESSION;

static RUNNER: once_cell::sync::Lazy<roundhouse_core::TaskRunner> =
    once_cell::sync::Lazy::new(roundhouse_core::TaskRunner::bootstrap);

#[tokio::test]
async fn recovers_500_sessions_times_200_tasks_within_five_seconds() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");

    // `open()` applies migrations; do this once before touching the schema
    // with a raw connection.
    drop(open(&db_path).await.unwrap());

    seed_non_terminal_tasks(&db_path);

    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    let recovery_store = open(&db_path).await.unwrap();

    let started = std::time::Instant::now();
    let interrupted = recover_interrupted_tasks(&recovery_store, &writer, &RUNNER)
        .await
        .unwrap();
    let elapsed = started.elapsed();

    eprintln!("recover_interrupted_tasks over {TOTAL_TASKS} non-terminal tasks took {elapsed:?}");

    assert_eq!(interrupted.len(), TOTAL_TASKS);
    assert!(
        elapsed <= std::time::Duration::from_secs(5),
        "S-SESS-4 budget: 500 sessions x 200 tasks must recover within 5s, took {elapsed:?}"
    );

    // Spot-check a handful of tasks rows now show state = 'Interrupted'.
    let conn = recovery_store.pool.get().await.unwrap();
    for task_id in interrupted.iter().take(10) {
        let task_id_str = task_id.to_string();
        let state: String = conn
            .interact(move |c| {
                c.query_row(
                    "SELECT state FROM tasks WHERE task_id = ?1",
                    [task_id_str],
                    |row| row.get(0),
                )
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state, "Interrupted");
    }
}

/// Bulk-seeds `SESSIONS * TASKS_PER_SESSION` tasks, each with one `TaskCreated`
/// event and a matching `tasks` row left in a non-terminal state (`Created`,
/// `Decided`, or `Running`, rotated so the query's `IN (...)` clause is
/// genuinely exercised) — no terminal or suspended event, matching the crash
/// scenario. All in one transaction on a raw connection.
fn seed_non_terminal_tasks(db_path: &std::path::Path) {
    let mut conn = rusqlite::Connection::open(db_path).unwrap();
    let tx = conn.transaction().unwrap();
    {
        let mut insert_event = tx
            .prepare(
                "INSERT INTO events (session_id, seq, ts, task_id, payload, schema_v) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .unwrap();
        let mut insert_task = tx
            .prepare(
                "INSERT INTO tasks (task_id, session_id, kind, state, parent, created_seq, updated_seq) \
                 VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?5)",
            )
            .unwrap();

        let payload = EventPayload::TaskCreated {
            kind: TaskKind::Shell,
            parent: None,
            origin: Origin::Model,
            input: TaskInput::Text("scale test".into()),
        };
        let payload_json = serde_json::to_string(&payload).unwrap();

        for _session_idx in 0..SESSIONS {
            let session_id_str = SessionId::new().to_string();
            for task_idx in 0..TASKS_PER_SESSION {
                let task_id_str = TaskId::new().to_string();
                let seq = task_idx as i64;

                insert_event
                    .execute(rusqlite::params![
                        session_id_str,
                        seq,
                        0i64,
                        task_id_str,
                        payload_json,
                        1i64
                    ])
                    .unwrap();

                let state = match task_idx % 3 {
                    0 => "Created",
                    1 => "Decided",
                    _ => "Running",
                };
                insert_task
                    .execute(rusqlite::params![
                        task_id_str,
                        session_id_str,
                        "Shell",
                        state,
                        seq
                    ])
                    .unwrap();
            }
        }
    }
    tx.commit().unwrap();
}
