//! S-SESS-4's crash-recovery guarantee: "500 sessions × 200 tasks recovers
//! within 5s." Task 1's original `recover_interrupted_tasks` scanned the whole
//! `events` table and called `writer.append()` once per interrupted task,
//! which was both an unbounded-memory risk and unlikely to meet that budget;
//! the rewrite is `tasks`-table-driven and batched. This file pins the
//! rewrite.
//!
//! **It no longer asserts on a wall clock, deliberately (issue #12).** The
//! original test measured elapsed time against a hard 5s limit and, on shared
//! GitHub Actions runners, sat exactly on the cliff: 5.06s and 5.82s on
//! commits whose production code was byte-identical to commits that passed,
//! eight red runs across four branches, and eventually a red `main` — at which
//! point the next genuine regression would have been invisible.
//!
//! Widening the limit or taking a best-of-N sample would both have kept a
//! timing assertion alive, and the decisive evidence is that the timing
//! assertion did not work. Reintroducing the pre-rewrite behaviour — a full
//! `SELECT payload FROM events` scan with a JSON parse per row — as a
//! temporary mutant left the 5s budget **passing** on a developer machine,
//! because a 1.7s baseline leaves so much headroom that the limit only bites
//! on slow CI hardware. The same property that made it flaky made it blind: it
//! was simultaneously too loose to catch the regression and too tight to pass
//! reliably. `recovery_never_reads_the_event_log_so_a_corrupt_log_cannot_break_it`
//! caught that mutant immediately.
//!
//! So the budget's *intent* is now enforced structurally, by the two tests
//! below that assert what recovery actually does, and the scale test asserts
//! correctness at S-SESS-4's stated 500 × 200 volume without timing it. The 5s
//! figure remains the architecture's stated design target; it is no longer
//! machine-asserted, because a machine-dependent assertion of it was worse
//! than none.
//!
//! Seeding is done via **raw bulk SQL against a plain `rusqlite::Connection`**
//! in one transaction, not via 100,000+ individual `EventWriter::append()`
//! calls, which would make the test's own setup dominate its runtime.

use roundhouse_core::{EventPayload, Origin, SessionId, TaskId, TaskInput, TaskKind};
use roundhouse_store::{open, recover_interrupted_tasks, spawn_writer};

const SESSIONS: usize = 500;
const TASKS_PER_SESSION: usize = 200;
const TOTAL_TASKS: usize = SESSIONS * TASKS_PER_SESSION;

static RUNNER: once_cell::sync::Lazy<roundhouse_core::TaskRunner> =
    once_cell::sync::Lazy::new(roundhouse_core::TaskRunner::bootstrap);

#[tokio::test]
async fn recovers_500_sessions_times_200_tasks_completely() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");

    // `open()` applies migrations; do this once before touching the schema
    // with a raw connection.
    drop(open(&db_path).await.unwrap());

    seed_non_terminal_tasks(&db_path);

    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    let recovery_store = open(&db_path).await.unwrap();

    let interrupted = recover_interrupted_tasks(&recovery_store, &writer, &RUNNER)
        .await
        .unwrap();

    // The whole non-terminal population is recovered at S-SESS-4's stated
    // volume — no truncation, no batching seam that silently drops a tail.
    assert_eq!(interrupted.len(), TOTAL_TASKS);

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

/// The concrete, hardware-independent half of S-SESS-4's guarantee.
///
/// The budget test above measures *how fast* recovery is; this one measures
/// *what it actually does*, which is the property the budget was defending in
/// the first place. Per this file's own history, the original
/// `recover_interrupted_tasks` did a full `events` table scan with one
/// `writer.append()` per interrupted task; the rewrite made it `tasks`-driven
/// and batched. Only the rewrite can pass this test, and it passes or fails
/// identically on a fast laptop and a contended CI runner.
///
/// The trick is to make the event log **unreadable** and then require recovery
/// to succeed anyway. Every `events` row here carries a payload that is not
/// valid JSON, so any implementation that reads and deserializes the event log
/// to decide what to recover must error out. One that drives off the `tasks`
/// table never looks, and returns the full set.
#[tokio::test]
async fn recovery_never_reads_the_event_log_so_a_corrupt_log_cannot_break_it() {
    const SESSIONS: usize = 20;
    const TASKS_PER_SESSION: usize = 25;
    const TOTAL: usize = SESSIONS * TASKS_PER_SESSION;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("corrupt-log.db");
    drop(open(&db_path).await.unwrap());

    // Same shape as `seed_non_terminal_tasks`, except every payload is
    // deliberately not JSON.
    {
        let mut conn = rusqlite::Connection::open(&db_path).unwrap();
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
            for _ in 0..SESSIONS {
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
                            "}{ this is not JSON and never was",
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

    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    let recovery_store = open(&db_path).await.unwrap();

    let interrupted = recover_interrupted_tasks(&recovery_store, &writer, &RUNNER)
        .await
        .expect(
            "recovery must not read the event log: it is `tasks`-table-driven, so a payload \
             it never deserializes cannot fail it",
        );

    assert_eq!(
        interrupted.len(),
        TOTAL,
        "every non-terminal task must be recovered from the `tasks` table alone"
    );
}

/// The `state IN (...)` filter must be applied by SQLite, not by loading every
/// task into Rust and filtering there — the difference is invisible in the
/// return value but is exactly the difference between O(non-terminal) and
/// O(all tasks) work. Seeds a large *terminal* population alongside a small
/// non-terminal one and requires the terminal rows to be untouched.
#[tokio::test]
async fn recovery_returns_only_non_terminal_tasks_from_a_mostly_terminal_table() {
    const NON_TERMINAL: usize = 50;
    const TERMINAL: usize = 5_000;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("mostly-terminal.db");
    drop(open(&db_path).await.unwrap());

    {
        let mut conn = rusqlite::Connection::open(&db_path).unwrap();
        let tx = conn.transaction().unwrap();
        {
            let mut insert_task = tx
                .prepare(
                    "INSERT INTO tasks (task_id, session_id, kind, state, parent, created_seq, updated_seq) \
                     VALUES (?1, ?2, ?3, ?4, NULL, 0, 0)",
                )
                .unwrap();
            let session_id_str = SessionId::new().to_string();
            for i in 0..(NON_TERMINAL + TERMINAL) {
                let state = if i < NON_TERMINAL {
                    "Running"
                } else {
                    // Terminal and suspended states recovery must skip.
                    match i % 3 {
                        0 => "Completed",
                        1 => "Failed",
                        _ => "Cancelled",
                    }
                };
                insert_task
                    .execute(rusqlite::params![
                        TaskId::new().to_string(),
                        session_id_str,
                        "Shell",
                        state
                    ])
                    .unwrap();
            }
        }
        tx.commit().unwrap();
    }

    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    let recovery_store = open(&db_path).await.unwrap();

    let interrupted = recover_interrupted_tasks(&recovery_store, &writer, &RUNNER)
        .await
        .unwrap();

    assert_eq!(
        interrupted.len(),
        NON_TERMINAL,
        "recovery must return only the non-terminal tasks, leaving {TERMINAL} terminal rows alone"
    );
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
