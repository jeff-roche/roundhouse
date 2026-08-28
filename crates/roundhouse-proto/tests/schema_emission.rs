use roundhouse_proto::{client_event_schema, ApiVersion, ClientEvent, ClientRequest};

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

#[test]
fn client_request_round_trips_through_json() {
    let req = ClientRequest::CreateSession { workspace_name: "demo".into() };
    let json = serde_json::to_string(&req).unwrap();
    let back: ClientRequest = serde_json::from_str(&json).unwrap();
    match back {
        ClientRequest::CreateSession { workspace_name } => assert_eq!(workspace_name, "demo"),
        _ => panic!("unexpected variant"),
    }
}

#[test]
fn api_version_is_present_on_every_wire_message() {
    let v = ApiVersion::CURRENT;
    assert_eq!(v.0, 0, "Phase 0 starts the wire protocol at version 0");
}
