use roundhouse_acp::peer_text::escape_and_cap_peer_str;
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
        "claude-agent-acp",
        "1.4.0",
        VersionHint {
            agent_binary: escape_and_cap_peer_str("claude-agent-acp"),
            agent_version: escape_and_cap_peer_str("1.4.0"),
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
fn hint_cache_stays_bounded_when_an_agent_self_reports_unbounded_distinct_versions() {
    let mut cache = VersionHintCache::new();
    // A single self-reporting agent that mints a fresh "version" per
    // connection (accidentally or adversarially) must not grow the cache
    // without bound: insert far more distinct (binary, version) keys than
    // any plausible cap, then assert the cache size never exceeded it.
    for i in 0..1_000 {
        let version = format!("v{i}");
        cache_hint(
            &mut cache,
            "self-reporting-agent",
            &version,
            VersionHint {
                agent_binary: escape_and_cap_peer_str("self-reporting-agent"),
                agent_version: escape_and_cap_peer_str(&version),
                observed: AcpVersion::V1,
            },
        );
        assert!(
            cache.len() <= 256,
            "cache grew past its bound after {} inserts: len={}",
            i + 1,
            cache.len()
        );
    }
    assert_eq!(cache.len(), 256);

    // The earliest-inserted hint is the one evicted under FIFO; the most
    // recent one is still present.
    assert_eq!(lookup_hint(&cache, "self-reporting-agent", "v0"), None);
    assert_eq!(
        lookup_hint(&cache, "self-reporting-agent", "v999"),
        Some(AcpVersion::V1)
    );
}

#[test]
fn two_identities_differing_only_past_the_escape_cap_do_not_collide() {
    // Fix round 2 (Item 6): before this round, cache_hint/lookup_hint keyed
    // on `EscapedPeerStr::as_str()` — escaped *and* capped to
    // roundhouse_acp::peer_text::PEER_STR_MAX_LEN (128) bytes. Two distinct
    // raw identities that happen to share their first ~128 escaped bytes
    // then collided into the same cache slot, and lookup_hint could return
    // a stale hint observed for a *different* agent identity — a wrong
    // answer, not merely a lost one.
    let mut cache = VersionHintCache::new();
    let shared_prefix = "x".repeat(200);
    let binary_a = format!("{shared_prefix}-A");
    let binary_b = format!("{shared_prefix}-B");

    // Test premise: these two raw strings really do share the same
    // escaped-and-capped form — otherwise this test would not be
    // exercising the bug at all.
    assert_eq!(
        escape_and_cap_peer_str(&binary_a).as_str(),
        escape_and_cap_peer_str(&binary_b).as_str(),
        "test premise: these two raw identities must share one escaped-and-capped form"
    );
    assert_ne!(
        binary_a, binary_b,
        "test premise: the raw identities themselves must be genuinely distinct"
    );

    cache_hint(
        &mut cache,
        &binary_a,
        "1.0.0",
        VersionHint {
            agent_binary: escape_and_cap_peer_str(&binary_a),
            agent_version: escape_and_cap_peer_str("1.0.0"),
            observed: AcpVersion::V1,
        },
    );
    cache_hint(
        &mut cache,
        &binary_b,
        "1.0.0",
        VersionHint {
            agent_binary: escape_and_cap_peer_str(&binary_b),
            agent_version: escape_and_cap_peer_str("1.0.0"),
            observed: AcpVersion::V2,
        },
    );

    assert_eq!(
        lookup_hint(&cache, &binary_a, "1.0.0"),
        Some(AcpVersion::V1),
        "identity A's hint must not be shadowed by identity B's"
    );
    assert_eq!(
        lookup_hint(&cache, &binary_b, "1.0.0"),
        Some(AcpVersion::V2),
        "identity B's hint must not be shadowed by identity A's"
    );
    assert_eq!(
        cache.len(),
        2,
        "two distinct raw identities must occupy two distinct cache slots, not collide into one"
    );
}

#[test]
fn negotiate_response_reads_the_real_sdk_initialize_response() {
    use agent_client_protocol::schema::v1::InitializeResponse;
    use agent_client_protocol::schema::ProtocolVersion;

    let v1_response = InitializeResponse::new(ProtocolVersion::V1);
    assert_eq!(negotiate_response(&v1_response), AcpVersion::V1);
}
