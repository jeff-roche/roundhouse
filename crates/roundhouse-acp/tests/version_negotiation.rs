use roundhouse_acp::version::{
    cache_hint, lookup_hint, negotiate, negotiate_response, AcpVersion, VersionHint,
    VersionHintCache,
};

#[test]
fn negotiation_selects_version_from_the_declared_integer_never_a_static_table() {
    assert_eq!(negotiate(1), AcpVersion::V1);
    assert_eq!(negotiate(2), AcpVersion::V2);
    // Unknown/future integers fall back to the last stable surface, v1 —
    // never guessed forward to an unstabilized v2+ surface.
    assert_eq!(negotiate(3), AcpVersion::V1);
}

#[test]
fn observed_result_is_cached_as_a_hint_only_reused_to_skip_a_redundant_round() {
    let mut cache = VersionHintCache::new();
    assert_eq!(lookup_hint(&cache, "claude-agent-acp", "1.4.0"), None);
    cache_hint(
        &mut cache,
        VersionHint {
            agent_binary: "claude-agent-acp".to_string(),
            agent_version: "1.4.0".to_string(),
            observed: AcpVersion::V1,
        },
    );
    assert_eq!(
        lookup_hint(&cache, "claude-agent-acp", "1.4.0"),
        Some(AcpVersion::V1)
    );
    // A different version of the same binary is a cache miss — the hint is
    // never assumed to generalize across versions.
    assert_eq!(lookup_hint(&cache, "claude-agent-acp", "1.5.0"), None);
}

#[test]
fn negotiate_response_reads_the_real_sdk_initialize_response() {
    use agent_client_protocol::schema::v1::InitializeResponse;
    use agent_client_protocol::schema::ProtocolVersion;

    let v1_response = InitializeResponse::new(ProtocolVersion::V1);
    assert_eq!(negotiate_response(&v1_response), AcpVersion::V1);
}
