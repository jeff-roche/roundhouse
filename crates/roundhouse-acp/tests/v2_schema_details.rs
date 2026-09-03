//! Tests for the `acp-v2`-gated schema details: the tri-state `MaybeUndefined`
//! merge (re-exported from the pinned SDK, not reimplemented — Ruling C-P7)
//! and the open-enum `StopReason` (flat SDK idiom with the real six
//! variants — Ruling C-P8).
//!
//! Split out from `mcp_over_acp.rs`'s tests (Ruling C-P9) because everything
//! in this file imports `roundhouse_acp::schema`, which only exists when the
//! `acp-v2` feature is enabled — without this guard, `cargo test --workspace`
//! (default features) would fail to compile this file at all.
#![cfg(feature = "acp-v2")]

use roundhouse_acp::schema::v2::maybe_undefined::{append_chunk, apply_patch, MaybeUndefined};
use roundhouse_acp::schema::v2::open_enum::StopReason;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct SessionPatch {
    #[serde(default, skip_serializing_if = "MaybeUndefined::is_undefined")]
    title: MaybeUndefined<String>,
}

#[test]
fn maybe_undefined_distinguishes_omitted_null_and_value() {
    // §10.1: "omitted = unchanged, null = clear, value = replace" — a plain
    // Option<T> collapses omitted and null to the same None, which is
    // exactly the distinction this type exists to preserve.
    let omitted: SessionPatch = serde_json::from_value(json!({})).unwrap();
    assert_eq!(omitted.title, MaybeUndefined::Undefined);

    let explicit_null: SessionPatch = serde_json::from_value(json!({"title": null})).unwrap();
    assert_eq!(explicit_null.title, MaybeUndefined::Null);

    let with_value: SessionPatch = serde_json::from_value(json!({"title": "new title"})).unwrap();
    assert_eq!(
        with_value.title,
        MaybeUndefined::Value("new title".to_string())
    );

    // Round-trip: Undefined must vanish from the JSON entirely, not
    // serialize as `"title": null` (that would be indistinguishable from
    // an explicit clear on the wire).
    let ser = serde_json::to_value(&omitted).unwrap();
    assert!(ser.get("title").is_none());
    let ser_null = serde_json::to_value(&explicit_null).unwrap();
    assert_eq!(ser_null["title"], json!(null));
}

#[test]
fn apply_patch_implements_the_real_three_way_merge() {
    let mut current = Some("old".to_string());
    apply_patch(&mut current, &MaybeUndefined::Undefined);
    assert_eq!(
        current,
        Some("old".to_string()),
        "omitted leaves the field unchanged"
    );

    apply_patch(&mut current, &MaybeUndefined::Null);
    assert_eq!(current, None, "null clears the field");

    apply_patch(&mut current, &MaybeUndefined::Value("new".to_string()));
    assert_eq!(
        current,
        Some("new".to_string()),
        "a value replaces the field"
    );
}

#[test]
fn chunks_append_a_deliberately_different_semantics_from_the_tri_state_patch() {
    let mut buf = String::from("hello ");
    append_chunk(&mut buf, "world");
    assert_eq!(
        buf, "hello world",
        "chunks append; they are never routed through apply_patch's replace/clear/unchanged logic"
    );
}

#[test]
fn unrecognized_enum_values_round_trip_through_other_unchanged() {
    let known: StopReason = serde_json::from_value(json!("end_turn")).unwrap();
    assert_eq!(known, StopReason::EndTurn);
    assert_eq!(serde_json::to_value(&known).unwrap(), json!("end_turn"));

    // §10.1: "Every enum is open; unknown values must round-trip." A future
    // protocol revision's new stop reason must never error or get dropped.
    let unknown: StopReason = serde_json::from_value(json!("future_stop_reason_v3")).unwrap();
    assert_eq!(
        unknown,
        StopReason::Other("future_stop_reason_v3".to_string())
    );
    assert_eq!(
        serde_json::to_value(&unknown).unwrap(),
        json!("future_stop_reason_v3"),
        "re-serializes unchanged, byte for byte"
    );
}

#[test]
fn all_real_variants_round_trip() {
    for (wire, expected) in [
        ("end_turn", StopReason::EndTurn),
        ("max_tokens", StopReason::MaxTokens),
        ("max_turn_requests", StopReason::MaxTurnRequests),
        ("refusal", StopReason::Refusal),
        ("cancelled", StopReason::Cancelled),
    ] {
        let parsed: StopReason = serde_json::from_value(json!(wire)).unwrap();
        assert_eq!(parsed, expected);
        assert_eq!(serde_json::to_value(&parsed).unwrap(), json!(wire));
    }
}

#[test]
fn from_the_real_sdk_v2_stop_reason_matches_the_compiler_proven_conversion() {
    use agent_client_protocol::schema::v2::StopReason as SdkStopReason;

    assert_eq!(
        StopReason::from(SdkStopReason::EndTurn),
        StopReason::EndTurn
    );
    assert_eq!(
        StopReason::from(SdkStopReason::MaxTokens),
        StopReason::MaxTokens
    );
    assert_eq!(
        StopReason::from(SdkStopReason::MaxTurnRequests),
        StopReason::MaxTurnRequests
    );
    assert_eq!(
        StopReason::from(SdkStopReason::Refusal),
        StopReason::Refusal
    );
    assert_eq!(
        StopReason::from(SdkStopReason::Cancelled),
        StopReason::Cancelled
    );
    assert_eq!(
        StopReason::from(SdkStopReason::Other("future_stop_reason_v3".to_string())),
        StopReason::Other("future_stop_reason_v3".to_string())
    );
}
