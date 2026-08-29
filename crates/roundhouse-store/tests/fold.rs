use roundhouse_core::{
    EventPayload, IsolationAttestation, Origin, SessionId, TaskId, TaskInput, TaskKind, TaskOutput,
    Tier, Timestamp,
};
use roundhouse_store::{fold_task, StoredEvent, TaskState};

// Timestamp has no `now()` (see Resolved Ambiguity #5 / audit finding X4) — read the
// wall clock ourselves and convert.
fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

fn created(session_id: SessionId, task_id: TaskId, seq: u64) -> StoredEvent {
    StoredEvent {
        session_id,
        seq,
        ts: now_ts(),
        task_id: Some(task_id),
        payload: EventPayload::TaskCreated {
            kind: TaskKind::Shell,
            parent: None,
            origin: Origin::Model,
            // TaskInput has no Default (audit finding X4) — a Json/Text/Blob enum with
            // no stated Default impl; construct an explicit placeholder value instead.
            input: TaskInput::Text("ls".into()),
        },
        schema_v: 1,
    }
}

#[test]
fn task_with_started_and_no_terminal_event_is_running() {
    let session_id = SessionId::new();
    let task_id = TaskId::new();

    let events = vec![
        created(session_id, task_id, 0),
        StoredEvent {
            session_id,
            seq: 1,
            ts: now_ts(),
            task_id: Some(task_id),
            payload: EventPayload::TaskStarted {
                isolation: IsolationAttestation {
                    tier: Tier::None,
                    digest: "test".to_string(),
                    net_enforced: false,
                },
                handle: None,
            },
            schema_v: 1,
        },
    ];

    let task = fold_task(&events).unwrap();
    assert_eq!(task.state, TaskState::Running);
}

#[test]
fn task_with_completed_event_is_completed() {
    let session_id = SessionId::new();
    let task_id = TaskId::new();

    let events = vec![
        created(session_id, task_id, 0),
        StoredEvent {
            session_id,
            seq: 1,
            ts: now_ts(),
            task_id: Some(task_id),
            payload: EventPayload::TaskStarted {
                isolation: IsolationAttestation {
                    tier: Tier::None,
                    digest: "test".to_string(),
                    net_enforced: false,
                },
                handle: None,
            },
            schema_v: 1,
        },
        StoredEvent {
            session_id,
            seq: 2,
            ts: now_ts(),
            task_id: Some(task_id),
            payload: EventPayload::TaskCompleted {
                // TaskOutput has no Default either (audit finding X4) — same fix.
                output: TaskOutput::Text("ok".into()),
                usage: Default::default(), // Usage does derive Default (Phase 0 confirmed)
            },
            schema_v: 1,
        },
    ];

    let task = fold_task(&events).unwrap();
    assert_eq!(task.state, TaskState::Completed);
}
