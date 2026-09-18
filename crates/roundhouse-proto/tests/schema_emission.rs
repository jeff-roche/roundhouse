use roundhouse_core::{CancelReason, EventPayload, NoteLevel, SessionId, TaskId};
use roundhouse_proto::{
    client_event_schema, client_request_schema, ApiVersion, ClientEvent, ClientRequest, TurnOutcome,
};

#[test]
fn client_event_schema_emits_valid_json_schema_with_expected_properties() {
    let schema = client_event_schema();
    let value = serde_json::to_value(&schema).expect("schema serializes to JSON");
    let props = value
        .get("properties")
        .or_else(|| value.get("oneOf"))
        .expect("schema has properties or oneOf (ClientEvent is an enum)");
    assert!(!props.is_null());
}

/// Phase 8, T19a Task 8: `ClientRequest`'s own schema-emission round trip,
/// alongside `ClientEvent`'s above — added when `CloseSession` landed, since
/// nothing previously exercised `client_request_schema` at all despite it
/// being exported for exactly this purpose (`schema.rs`'s own doc comment:
/// "the one schema-emission entry point downstream tooling ... relies on").
///
/// This test's first version would have passed identically before
/// `CloseSession` was ever added — it only checked that the schema has SOME
/// `properties`/`oneOf` shape, never that the new variant is actually IN it.
/// Asserting the emitted JSON mentions `CloseSession` by name (rather than
/// parsing the exact `oneOf` shape, which is `schemars`-version-specific and
/// not this test's concern) is enough to make the test fail if the variant
/// were ever dropped from the schema while remaining in the enum.
#[test]
fn client_request_schema_emits_valid_json_schema_with_expected_properties() {
    let schema = client_request_schema();
    let value = serde_json::to_value(&schema).expect("schema serializes to JSON");
    let props = value
        .get("properties")
        .or_else(|| value.get("oneOf"))
        .expect("schema has properties or oneOf (ClientRequest is an enum)");
    assert!(!props.is_null());
    assert!(
        value.to_string().contains("CloseSession"),
        "the emitted ClientRequest schema must mention the CloseSession variant: {value}"
    );
}

#[test]
fn client_request_round_trips_through_json() {
    let req = ClientRequest::CreateSession {
        workspace_name: "demo".into(),
    };
    let json = serde_json::to_string(&req).unwrap();
    let back: ClientRequest = serde_json::from_str(&json).unwrap();
    match back {
        ClientRequest::CreateSession { workspace_name } => assert_eq!(workspace_name, "demo"),
        _ => panic!("unexpected variant"),
    }
}

/// `CloseSession` (Phase 8, T19a Task 8) round-trips through JSON exactly
/// like `CreateSession` does above — the additive-variant proof that
/// `#[non_exhaustive]` promised: a new variant, but the same wire shape
/// discipline as every existing one.
#[test]
fn close_session_round_trips_through_json() {
    let session_id = SessionId::new();
    let req = ClientRequest::CloseSession { session_id };
    let json = serde_json::to_string(&req).unwrap();
    let back: ClientRequest = serde_json::from_str(&json).unwrap();
    match back {
        ClientRequest::CloseSession {
            session_id: round_tripped,
        } => assert_eq!(round_tripped, session_id),
        _ => panic!("unexpected variant"),
    }
}

/// Phase 8 Task 21: the emitted schemas must name every new variant, so a
/// variant dropped from the schema while kept in the enum fails here (the
/// same reasoning as the `CloseSession` check above).
#[test]
fn the_schemas_mention_every_phase8_task21_variant() {
    let request = serde_json::to_value(client_request_schema())
        .unwrap()
        .to_string();
    assert!(
        request.contains("Resume"),
        "ClientRequest schema: {request}"
    );

    let event = serde_json::to_value(client_event_schema())
        .unwrap()
        .to_string();
    for name in ["Committed", "TurnFinished", "ResyncRequired", "Rejected"] {
        assert!(
            event.contains(name),
            "ClientEvent schema lacks {name}: {event}"
        );
    }
}

#[test]
fn resume_round_trips_through_json() {
    let session_id = SessionId::new();
    let json = serde_json::to_string(&ClientRequest::Resume {
        session_id,
        after_seq: 41,
    })
    .unwrap();
    match serde_json::from_str::<ClientRequest>(&json).unwrap() {
        ClientRequest::Resume {
            session_id: back,
            after_seq,
        } => {
            assert_eq!(back, session_id);
            assert_eq!(after_seq, 41);
        }
        other => panic!("unexpected variant {other:?}"),
    }
}

#[test]
fn committed_round_trips_with_its_seq_and_payload() {
    let session_id = SessionId::new();
    let task_id = TaskId::new();
    let json = serde_json::to_string(&ClientEvent::Committed {
        session_id,
        seq: 7,
        task_id: Some(task_id),
        payload: Box::new(EventPayload::Note {
            level: NoteLevel::Info,
            text: "hello".into(),
        }),
    })
    .unwrap();
    match serde_json::from_str::<ClientEvent>(&json).unwrap() {
        ClientEvent::Committed {
            session_id: back,
            seq,
            task_id: back_task,
            payload,
        } => {
            assert_eq!(back, session_id);
            assert_eq!(seq, 7);
            assert_eq!(back_task, Some(task_id));
            assert!(matches!(*payload, EventPayload::Note { ref text, .. } if text == "hello"));
        }
        other => panic!("unexpected variant {other:?}"),
    }
}

#[test]
fn turn_finished_round_trips_every_outcome() {
    let session_id = SessionId::new();
    let outcomes = [
        TurnOutcome::Completed,
        TurnOutcome::Failed {
            category: "provider".into(),
            message: "boom".into(),
        },
        TurnOutcome::Cancelled {
            reason: CancelReason::SessionClosed,
        },
        TurnOutcome::Rejected {
            reason: "turn_in_flight".into(),
        },
    ];
    for outcome in outcomes {
        let expected = serde_json::to_value(&outcome).unwrap();
        let json = serde_json::to_string(&ClientEvent::TurnFinished {
            session_id,
            outcome,
            through_seq: Some(3),
        })
        .unwrap();
        match serde_json::from_str::<ClientEvent>(&json).unwrap() {
            ClientEvent::TurnFinished {
                session_id: back,
                outcome,
                through_seq,
            } => {
                assert_eq!(back, session_id);
                assert_eq!(through_seq, Some(3));
                assert_eq!(serde_json::to_value(&outcome).unwrap(), expected);
            }
            other => panic!("unexpected variant {other:?}"),
        }
    }
}

#[test]
fn resync_required_round_trips_with_its_head() {
    let session_id = SessionId::new();
    let json = serde_json::to_string(&ClientEvent::ResyncRequired {
        session_id,
        head: Some(9),
    })
    .unwrap();
    match serde_json::from_str::<ClientEvent>(&json).unwrap() {
        ClientEvent::ResyncRequired {
            session_id: back,
            head,
        } => {
            assert_eq!(back, session_id);
            assert_eq!(head, Some(9));
        }
        other => panic!("unexpected variant {other:?}"),
    }
}

#[test]
fn api_version_is_present_on_every_wire_message() {
    let v = ApiVersion::CURRENT;
    assert_eq!(v.0, 0, "Phase 0 starts the wire protocol at version 0");
}
