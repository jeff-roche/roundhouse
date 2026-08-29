use roundhouse_core::{SessionId, Timestamp, TaskId, TaskKind, Origin, TaskInput};
use roundhouse_store::{open, spawn_writer};

static RUNNER: once_cell::sync::Lazy<roundhouse_core::TaskRunner> =
    once_cell::sync::Lazy::new(roundhouse_core::TaskRunner::bootstrap);

/// `Timestamp` (Phase 0, frozen) exposes only `from_unix_nanos`/`as_unix_nanos` — no
/// `now()` (see Resolved Ambiguity #5 / audit finding X4). Every test in this crate that
/// needs "now" reads the wall clock itself and converts, rather than assuming a method
/// that doesn't exist on the frozen type.
fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

#[tokio::test]
async fn appends_two_events_with_monotonic_seq() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir.path().join("events.db")).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();

    let task_id_1 = TaskId::new();
    let event1 = RUNNER.record_task_created(
        session_id,
        0, // seq — assigned by the writer, input value ignored
        now_ts(),
        task_id_1,
        TaskKind::Shell,
        None,   // parent
        Origin::Model,
        TaskInput::Text("test".into()),
        1, // schema_v
    );

    let seq0 = writer.append(event1).await.unwrap();

    let task_id_2 = TaskId::new();
    let event2 = RUNNER.record_task_created(
        session_id,
        0,
        now_ts(),
        task_id_2,
        TaskKind::Shell,
        None,
        Origin::Model,
        TaskInput::Text("test".into()),
        1,
    );

    let seq1 = writer.append(event2).await.unwrap();

    assert_eq!(seq0, 0);
    assert_eq!(seq1, 1);
}

/// S-LOG-4/5's acceptance criterion is 100/100 real `kill -9` trials — an
/// operational/manual verification step, not something a unit test can exercise (no
/// process is actually killed here). This is the bounded-retry unit-test stand-in:
/// a second raw connection opens its own `BEGIN IMMEDIATE` write transaction and holds
/// it open on a background thread, guaranteeing the writer's own `BEGIN IMMEDIATE`
/// collides with a real `SQLITE_BUSY` from a concurrent writer — the same condition
/// `kill -9` recovery ultimately depends on the writer surviving — and asserts the
/// writer's retry loop waits it out and eventually succeeds rather than failing the
/// caller.
#[tokio::test]
async fn append_retries_through_a_real_sqlite_busy_and_eventually_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let db_path_for_blocker = db_path.clone();
    let (unblock_tx, unblock_rx) = std::sync::mpsc::channel::<()>();
    let (locked_tx, locked_rx) = std::sync::mpsc::channel::<()>();
    let blocker = std::thread::spawn(move || {
        let mut conn = rusqlite::Connection::open(&db_path_for_blocker).unwrap();
        conn.pragma_update(None, "busy_timeout", 0).unwrap(); // fail fast instead of blocking, so our writer's own retry loop is what's under test
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).unwrap();
        locked_tx.send(()).unwrap(); // signal: the write lock is now held
        unblock_rx.recv().unwrap(); // hold it until the test tells us to release
        tx.commit().unwrap();
    });

    locked_rx.recv().unwrap(); // don't race: wait until the blocker really holds the lock

    let session_id = SessionId::new();
    let task_id = TaskId::new();
    let event = RUNNER.record_task_created(
        session_id,
        0,
        now_ts(),
        task_id,
        TaskKind::Shell,
        None,
        Origin::Model,
        TaskInput::Text("under contention".into()),
        1,
    );

    let append_fut = writer.append(event);

    // Release the competing write lock shortly after the writer's first BEGIN IMMEDIATE
    // attempt has had a chance to collide with it and start backing off.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    unblock_tx.send(()).unwrap();
    blocker.join().unwrap();

    let seq = append_fut.await.expect("retry loop must absorb SQLITE_BUSY, never surface it to the caller");
    assert_eq!(seq, 0);
}
