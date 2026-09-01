use roundhouse_core::{Origin, Provenance, TaskId, Trust};

#[test]
fn trust_has_exactly_two_variants_that_round_trip_through_json() {
    for trust in [Trust::Trusted, Trust::Untrusted] {
        let json = serde_json::to_string(&trust).unwrap();
        let back: Trust = serde_json::from_str(&json).unwrap();
        assert_eq!(trust, back);
    }

    // Exact variant-name serialization: downstream consumers (CBOR frames,
    // JSON schema, persisted events) depend on these stable spellings.
    assert_eq!(
        serde_json::to_string(&Trust::Trusted).unwrap(),
        "\"Trusted\""
    );
    assert_eq!(
        serde_json::to_string(&Trust::Untrusted).unwrap(),
        "\"Untrusted\""
    );
}

#[test]
fn provenance_fields_serialize_and_deserialize() {
    let provenance = Provenance {
        origin: Origin::Client,
        trust: Trust::Untrusted,
        task: TaskId::new(),
    };

    let json = serde_json::to_value(&provenance).unwrap();
    assert_eq!(json["origin"], "Client");
    assert_eq!(json["trust"], "Untrusted");
    assert!(json["task"].is_string());

    let back: Provenance = serde_json::from_value(json).unwrap();
    assert_eq!(back.origin, provenance.origin);
    assert_eq!(back.trust, provenance.trust);
    assert_eq!(back.task, provenance.task);
}
