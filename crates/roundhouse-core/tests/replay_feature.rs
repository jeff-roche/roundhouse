//! Proves `Event::from_persisted` (gated behind the `replay` feature) can
//! reconstruct an `Event` from parts, for `roundhouse-store`'s crash-recovery
//! / fold-from-log use case. Only compiled/run with `--features replay`.

use roundhouse_core::{Event, EventPayload, NoteLevel, SessionId, TaskId, Timestamp};

#[test]
fn from_persisted_reconstructs_an_event_from_parts() {
    let session_id = SessionId::new();
    let task_id = TaskId::new();
    let ts = Timestamp::from_unix_nanos(1_735_000_000_000_000_000);
    let payload = EventPayload::Note { level: NoteLevel::Info, text: "replayed from log".into() };

    let event = Event::from_persisted(session_id, 42, ts, Some(task_id), payload, 1);

    assert_eq!(event.session_id.as_uuid(), session_id.as_uuid());
    assert_eq!(event.seq, 42);
    assert_eq!(event.ts.as_unix_nanos(), ts.as_unix_nanos());
    assert_eq!(event.task_id.map(|t| t.as_uuid()), Some(task_id.as_uuid()));
    assert_eq!(event.schema_v, 1);
    match event.payload {
        EventPayload::Note { level, text } => {
            assert_eq!(level, NoteLevel::Info);
            assert_eq!(text, "replayed from log");
        }
        other => panic!("expected Note payload, got {other:?}"),
    }
}
