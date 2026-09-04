//! The 16-case golden corpus for the `openai-responses` codec's `encode`
//! (§9.10/§13.3): each snapshot is the review artifact a human reads instead
//! of the Rust, so every wire shape claimed in
//! `docs/decisions/2026-08-27-open-responses-spec-verification.md` is pinned
//! here, not just asserted in prose.
//!
//! Snapshots are accepted via `INSTA_UPDATE=always cargo test` since the
//! `cargo-insta` CLI is not installed in this environment (matches
//! `openai_chat_encode.rs`'s existing note).

use roundhouse_provider::codec::openai_responses::encode::encode;
use roundhouse_provider::codec::openai_responses::OpenAiResponsesProvider;
use roundhouse_provider::profile::ProviderProfile;
use roundhouse_provider::{
    ChatRequest, ContentBlock, IdOrigin, MediaSource, Message, Params, Provider, ProviderError,
    ReasoningIntent, ReasoningRequest, Role, SystemBlock, ToolCallId, ToolResultPart,
};
use serde_json::json;
use std::collections::BTreeMap;

#[path = "support/openai_responses_fixtures.rs"]
mod fixtures;
use fixtures::{base_request, user_text};

fn fixture_profile() -> ProviderProfile {
    toml::from_str(include_str!("../profiles/openai-responses.toml")).unwrap()
}

#[test]
fn golden_single_turn_text() {
    let req = fixtures::single_turn_text();
    insta::assert_json_snapshot!(
        "openai_responses_single_turn_text",
        encode(&req, &fixture_profile()).expect("encode must succeed for this fixture profile")
    );
}

#[test]
fn golden_parallel_tool_calls() {
    let req = fixtures::parallel_tool_calls();
    insta::assert_json_snapshot!(
        "openai_responses_parallel_tool_calls",
        encode(&req, &fixture_profile()).expect("encode must succeed for this fixture profile")
    );
}

#[test]
fn golden_reasoning_on() {
    let req = fixtures::reasoning_on();
    let body =
        encode(&req, &fixture_profile()).expect("encode must succeed for this fixture profile");
    assert_eq!(body["reasoning"]["effort"], "high");
    insta::assert_json_snapshot!("openai_responses_reasoning_on", body);
}

#[test]
fn golden_multi_turn_text() {
    let req = ChatRequest {
        messages: vec![
            user_text("What is the capital of France?"),
            Message {
                role: Role::Assistant,
                content: vec![ContentBlock::Text {
                    text: "Paris.".into(),
                    cache: None,
                    citations: vec![],
                }],
            },
            user_text("And its population?"),
        ],
        ..base_request(vec![])
    };
    insta::assert_json_snapshot!(
        "openai_responses_multi_turn_text",
        encode(&req, &fixture_profile()).expect("encode must succeed for this fixture profile")
    );
}

#[test]
fn golden_system_prompt_with_cache_breakpoint() {
    // Open Responses has no per-block cache breakpoint wire representation
    // (it caches automatically via `prompt_cache_key`) -- `cache` is dropped,
    // matching the sibling `openai_chat` codec's existing precedent.
    let req = ChatRequest {
        system: vec![SystemBlock {
            text: "You are a careful assistant.".into(),
            cache: Some(roundhouse_provider::CacheBreakpoint),
        }],
        ..base_request(vec![user_text("Hello.")])
    };
    let body =
        encode(&req, &fixture_profile()).expect("encode must succeed for this fixture profile");
    assert_eq!(body["instructions"], "You are a careful assistant.");
    insta::assert_json_snapshot!("openai_responses_system_prompt_with_cache_breakpoint", body);
}

#[test]
fn golden_forced_tool_choice() {
    let req = fixtures::forced_tool_choice();
    let body =
        encode(&req, &fixture_profile()).expect("encode must succeed for this fixture profile");
    assert_eq!(
        body["tool_choice"],
        json!({"type": "function", "name": "get_weather"})
    );
    insta::assert_json_snapshot!("openai_responses_forced_tool_choice", body);
}

#[test]
fn golden_tool_result_is_error() {
    // Spec-verification finding: `FunctionCallOutputItemParam` has no
    // `is_error` field at all -- it must never appear on the wire.
    let req = ChatRequest {
        messages: vec![Message {
            role: Role::User,
            content: vec![ContentBlock::ToolResult {
                tool_use_id: ToolCallId("call_1".into()),
                content: vec![ToolResultPart {
                    text: "permission denied".into(),
                }],
                is_error: true,
                cache: None,
            }],
        }],
        ..base_request(vec![])
    };
    let body =
        encode(&req, &fixture_profile()).expect("encode must succeed for this fixture profile");
    assert!(
        body["input"][0].get("is_error").is_none(),
        "function_call_output has no is_error field in the real spec"
    );
    insta::assert_json_snapshot!("openai_responses_tool_result_is_error", body);
}

#[test]
fn golden_reasoning_off() {
    let req = ChatRequest {
        reasoning: ReasoningRequest {
            intent: Some(ReasoningIntent::Off),
        },
        ..base_request(vec![user_text("Hello.")])
    };
    let body =
        encode(&req, &fixture_profile()).expect("encode must succeed for this fixture profile");
    assert!(body.get("reasoning").is_none());
    insta::assert_json_snapshot!("openai_responses_reasoning_off", body);
}

#[test]
fn golden_reasoning_budget_variant() {
    // Open Responses only has effort-tiered reasoning, not a numeric token
    // budget -- this case exercises a different effort tier (Medium) than
    // `golden_reasoning_on`'s High, to cover the reasoning-map path more than
    // once.
    let req = ChatRequest {
        reasoning: ReasoningRequest {
            intent: Some(ReasoningIntent::Medium),
        },
        ..base_request(vec![user_text("Summarize this briefly.")])
    };
    let body =
        encode(&req, &fixture_profile()).expect("encode must succeed for this fixture profile");
    assert_eq!(body["reasoning"]["effort"], "medium");
    insta::assert_json_snapshot!("openai_responses_reasoning_budget_variant", body);
}

#[test]
fn golden_unicode_content() {
    let req = base_request(vec![user_text("こんにちは 🌍 — café naïve")]);
    insta::assert_json_snapshot!(
        "openai_responses_unicode_content",
        encode(&req, &fixture_profile()).expect("encode must succeed for this fixture profile")
    );
}

#[test]
fn golden_image_content_block() {
    // Fix-round-2 D1: `encode` itself now refuses to silently drop an Image
    // block -- `encode_block` returns `Err(EncodeError::UnencodableMedia)`
    // for it, not `Ok(None)` -- so there is no successful wire body left to
    // snapshot here. `resolve()`'s cheap pre-flight check is exercised too,
    // but the guarantee that matters is `encode` itself: fix-round-1 C6 put
    // the ONLY guard on `resolve`, which the review found has zero
    // production callers, so it never actually protected the path
    // `stream_chat` (every real caller) takes. A `stream_chat`-level test
    // proving THAT path rejects the request lives in
    // `conformance_openai_responses.rs`
    // (`stream_chat_rejects_image_content_before_any_transport_call`).
    let req = ChatRequest {
        messages: vec![Message {
            role: Role::User,
            content: vec![
                ContentBlock::Text {
                    text: "What's in this image?".into(),
                    cache: None,
                    citations: vec![],
                },
                ContentBlock::Image {
                    source: MediaSource {
                        mime_type: "image/png".into(),
                        data: vec![0, 1, 2, 3],
                    },
                    cache: None,
                },
            ],
        }],
        ..base_request(vec![])
    };

    let provider = OpenAiResponsesProvider::new(fixture_profile());
    assert!(
        matches!(provider.resolve(&req), Err(ProviderError::Unsupported(_))),
        "resolve() must reject a request containing an Image block, not silently drop it later"
    );

    let err = encode(&req, &fixture_profile())
        .expect_err("encode() must refuse to silently drop an Image block");
    insta::assert_snapshot!("openai_responses_image_content_block", err.to_string());
}

#[test]
fn golden_document_content_block() {
    let req = ChatRequest {
        messages: vec![Message {
            role: Role::User,
            content: vec![
                ContentBlock::Text {
                    text: "Summarize this document.".into(),
                    cache: None,
                    citations: vec![],
                },
                ContentBlock::Document {
                    source: MediaSource {
                        mime_type: "application/pdf".into(),
                        data: vec![0, 1, 2, 3],
                    },
                    title: Some("report.pdf".into()),
                    cache: None,
                },
            ],
        }],
        ..base_request(vec![])
    };

    let provider = OpenAiResponsesProvider::new(fixture_profile());
    assert!(
        matches!(provider.resolve(&req), Err(ProviderError::Unsupported(_))),
        "resolve() must reject a request containing a Document block, not silently drop it later"
    );

    let err = encode(&req, &fixture_profile())
        .expect_err("encode() must refuse to silently drop a Document block");
    insta::assert_snapshot!("openai_responses_document_content_block", err.to_string());
}

/// A request that contains neither an `Image` nor a `Document` block must
/// resolve cleanly -- fix-round-1 C6's fail-closed check must be specific to
/// unencodable media, not an accidental blanket rejection.
#[test]
fn resolve_accepts_a_request_with_no_unencodable_media() {
    let provider = OpenAiResponsesProvider::new(fixture_profile());
    assert!(provider.resolve(&fixtures::single_turn_text()).is_ok());
}

#[test]
fn golden_temperature_forbidden_model() {
    // Fix-round-1 C4: gated on this MODEL having a `[model.reasoning]` entry
    // in the profile, not hardcoded off for every model. "gpt-5.4" matches
    // this profile's `gpt-5*` `[[model]]` entry, which declares a reasoning
    // control -- so temperature/top_p are omitted for it specifically, not
    // because this codec can never send them at all (see the companion test
    // below).
    let req = ChatRequest {
        params: Params {
            temperature: Some(0.7),
            top_p: Some(0.9),
            max_output_tokens: None,
            stop: None,
        },
        ..base_request(vec![user_text("Hello.")])
    };
    let body =
        encode(&req, &fixture_profile()).expect("encode must succeed for this fixture profile");
    assert!(body.get("temperature").is_none());
    assert!(body.get("top_p").is_none());
    insta::assert_json_snapshot!("openai_responses_temperature_forbidden_model", body);
}

/// Fix-round-1 C4's other half: a model with NO matching `[[model]]` entry at
/// all (so, in particular, none carrying a `[model.reasoning]` control) must
/// have `temperature`/`top_p` forwarded -- proving the omission above is
/// genuinely profile-driven data, not encode.rs silently hardcoding "never
/// send these" for every model this codec's `encode`/`decode` will ever be
/// reused against (Task 16 reuses this exact pair for non-reasoning
/// `openai-responses` providers).
#[test]
fn temperature_and_top_p_are_forwarded_for_a_model_with_no_reasoning_control() {
    let req = ChatRequest {
        model: roundhouse_provider::ModelId("some-non-reasoning-model".into()),
        params: Params {
            temperature: Some(0.7),
            top_p: Some(0.9),
            max_output_tokens: None,
            stop: None,
        },
        ..base_request(vec![user_text("Hello.")])
    };
    let body =
        encode(&req, &fixture_profile()).expect("encode must succeed for this fixture profile");
    // `Params.temperature`/`top_p` are `f32`; compare against the same
    // f32->f64 widening `json!` performs on the encoded value, rather than
    // an f64 literal that doesn't bit-for-bit match a widened f32.
    assert_eq!(body["temperature"].as_f64(), Some(0.7_f32 as f64));
    assert_eq!(body["top_p"].as_f64(), Some(0.9_f32 as f64));
}

#[test]
fn golden_empty_tool_argument_buffer() {
    let req = ChatRequest {
        messages: vec![Message {
            role: Role::Assistant,
            content: vec![ContentBlock::ToolUse {
                id: ToolCallId("call_1".into()),
                id_origin: IdOrigin::Provider,
                name: "ping".into(),
                input: json!({}),
                cache: None,
            }],
        }],
        ..base_request(vec![])
    };
    let body =
        encode(&req, &fixture_profile()).expect("encode must succeed for this fixture profile");
    assert_eq!(body["input"][0]["arguments"], "{}");
    insta::assert_json_snapshot!("openai_responses_empty_tool_argument_buffer", body);
}

#[test]
fn golden_long_stop_sequence_list() {
    // Spec-verification finding: Open Responses has no `stop` field at all.
    let stop: Vec<String> = (0..50).map(|i| format!("STOP_{i}")).collect();
    let req = ChatRequest {
        params: Params {
            temperature: None,
            top_p: None,
            max_output_tokens: None,
            stop: Some(stop),
        },
        ..base_request(vec![user_text("Hello.")])
    };
    let body =
        encode(&req, &fixture_profile()).expect("encode must succeed for this fixture profile");
    assert!(body.get("stop").is_none());
    insta::assert_json_snapshot!("openai_responses_long_stop_sequence_list", body);
}

#[test]
fn golden_raw_extra_passthrough_denied() {
    // openai-responses.toml declares allow_raw_extra = false.
    let mut extra = BTreeMap::new();
    extra.insert("custom_vendor_field".to_string(), json!(true));
    let req = ChatRequest {
        extra,
        ..base_request(vec![user_text("Hello.")])
    };
    let body =
        encode(&req, &fixture_profile()).expect("encode must succeed for this fixture profile");
    assert!(body.get("custom_vendor_field").is_none());
    insta::assert_json_snapshot!("openai_responses_raw_extra_passthrough_denied", body);
}

/// Fix-round-1 minor: a profile whose `[model.reasoning]` map is internally
/// inconsistent (here: no entry at all for `high`) must surface as an
/// `Err`, not silently omit `reasoning` from the wire body while reporting
/// success -- a caller who asked for high-effort reasoning would otherwise
/// never learn the request was actually sent as if reasoning were off.
#[test]
fn encode_surfaces_a_broken_reasoning_map_instead_of_silently_omitting_reasoning() {
    let broken_profile: ProviderProfile = toml::from_str(
        r#"
        id = "broken-fixture"
        codec = "openai-responses"

        [defaults]
        allow_raw_extra = false
        base_url = "https://example.invalid"

        [defaults.params]
        mode = "deny_list"
        fields = []

        [defaults.auth]
        kind = "bearer"

        [[model]]
        match = ["gpt-5.4*"]

        [model.reasoning]
        kind = "effort"
        field = "/reasoning/effort"
        vocabulary = ["none", "low", "medium", "high"]

        [model.reasoning.map]
        off = "none"
        low = "low"
        medium = "medium"
        # "high" is deliberately missing.
        "#,
    )
    .expect("fixture profile must deserialize");

    let req = ChatRequest {
        reasoning: ReasoningRequest {
            intent: Some(ReasoningIntent::High),
        },
        ..base_request(vec![user_text("Prove sqrt(2) is irrational.")])
    };

    assert!(
        encode(&req, &broken_profile).is_err(),
        "a reasoning map with no entry for the requested intent must be a hard error, \
         not a silently-dropped reasoning field"
    );
}
