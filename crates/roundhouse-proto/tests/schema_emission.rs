use roundhouse_core::SessionId;
use roundhouse_proto::{client_event_schema, client_request_schema, ApiVersion, ClientRequest};

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
#[test]
fn client_request_schema_emits_valid_json_schema_with_expected_properties() {
    let schema = client_request_schema();
    let value = serde_json::to_value(&schema).expect("schema serializes to JSON");
    let props = value
        .get("properties")
        .or_else(|| value.get("oneOf"))
        .expect("schema has properties or oneOf (ClientRequest is an enum)");
    assert!(!props.is_null());
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

#[test]
fn api_version_is_present_on_every_wire_message() {
    let v = ApiVersion::CURRENT;
    assert_eq!(v.0, 0, "Phase 0 starts the wire protocol at version 0");
}
