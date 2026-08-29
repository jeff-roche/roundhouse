//! `StoredEvent` is the CQRS read-model counterpart to the sealed
//! `roundhouse_core::Event` write-model. These tests prove the properties
//! that make it safe to use for replay/fold without reintroducing the
//! bypass the sealed `Event` type exists to prevent:
//!
//! - it is a genuinely unsealed, struct-literal-constructible DTO;
//! - it really does derive `Deserialize` (unlike `Event`, which deliberately
//!   does not — see `roundhouse_core::event`'s module docs);
//! - `EventFields` works generically over it, matching `Event`'s impl.

use roundhouse_core::{EventFields, EventPayload, NoteLevel, SessionId, Timestamp};
use roundhouse_store::StoredEvent;

fn sample_event() -> StoredEvent {
    StoredEvent {
        session_id: SessionId::new(),
        seq: 7,
        ts: Timestamp::from_unix_nanos(1_234_567_890),
        task_id: None,
        payload: EventPayload::Note {
            level: NoteLevel::Warn,
            text: "hello".to_string(),
        },
        schema_v: 1,
    }
}

#[test]
fn stored_event_is_plain_struct_literal_constructible() {
    // This is the whole point: no sealed field, no crate-internal
    // constructor required. If this doesn't compile, the design is broken.
    let event = sample_event();
    assert_eq!(event.seq, 7);
}

#[test]
fn stored_event_round_trips_through_json() {
    let event = sample_event();

    let json = serde_json::to_string(&event).expect("StoredEvent must serialize");
    let restored: StoredEvent =
        serde_json::from_str(&json).expect("StoredEvent must deserialize (unlike Event)");

    assert_eq!(restored.session_id, event.session_id);
    assert_eq!(restored.seq, event.seq);
    assert_eq!(restored.ts, event.ts);
    assert_eq!(restored.task_id, event.task_id);
    assert_eq!(restored.schema_v, event.schema_v);
    match (&restored.payload, &event.payload) {
        (
            EventPayload::Note {
                level: restored_level,
                text: restored_text,
            },
            EventPayload::Note { level, text },
        ) => {
            assert_eq!(restored_level, level);
            assert_eq!(restored_text, text);
        }
        _ => panic!("payload variant did not round-trip"),
    }
}

#[test]
fn event_fields_trait_exposes_payload() {
    let event = sample_event();

    match EventFields::payload(&event) {
        EventPayload::Note { level, text } => {
            assert_eq!(*level, NoteLevel::Warn);
            assert_eq!(text, "hello");
        }
        other => panic!("unexpected payload: {other:?}"),
    }
}
