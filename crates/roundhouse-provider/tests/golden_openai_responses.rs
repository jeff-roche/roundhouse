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
use roundhouse_provider::profile::ProviderProfile;
use roundhouse_provider::{
    ChatRequest, ContentBlock, IdOrigin, MediaSource, Message, Params, ReasoningIntent,
    ReasoningRequest, Role, SystemBlock, ToolCallId, ToolResultPart,
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
        encode(&req, &fixture_profile())
    );
}

#[test]
fn golden_parallel_tool_calls() {
    let req = fixtures::parallel_tool_calls();
    insta::assert_json_snapshot!(
        "openai_responses_parallel_tool_calls",
        encode(&req, &fixture_profile())
    );
}

#[test]
fn golden_reasoning_on() {
    let req = fixtures::reasoning_on();
    let body = encode(&req, &fixture_profile());
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
        encode(&req, &fixture_profile())
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
    let body = encode(&req, &fixture_profile());
    assert_eq!(body["instructions"], "You are a careful assistant.");
    insta::assert_json_snapshot!("openai_responses_system_prompt_with_cache_breakpoint", body);
}

#[test]
fn golden_forced_tool_choice() {
    let req = fixtures::forced_tool_choice();
    let body = encode(&req, &fixture_profile());
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
    let body = encode(&req, &fixture_profile());
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
    let body = encode(&req, &fixture_profile());
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
    let body = encode(&req, &fixture_profile());
    assert_eq!(body["reasoning"]["effort"], "medium");
    insta::assert_json_snapshot!("openai_responses_reasoning_budget_variant", body);
}

#[test]
fn golden_unicode_content() {
    let req = base_request(vec![user_text("こんにちは 🌍 — café naïve")]);
    insta::assert_json_snapshot!(
        "openai_responses_unicode_content",
        encode(&req, &fixture_profile())
    );
}

#[test]
fn golden_image_content_block() {
    // Scope decision (not a spec divergence): Image/Document blocks are
    // dropped in this task, matching the sibling codecs' existing precedent
    // -- see the spec-verification note.
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
    let body = encode(&req, &fixture_profile());
    assert_eq!(
        body["input"].as_array().unwrap().len(),
        1,
        "the Image block is dropped, only the Text block is encoded"
    );
    insta::assert_json_snapshot!("openai_responses_image_content_block", body);
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
    let body = encode(&req, &fixture_profile());
    assert_eq!(
        body["input"].as_array().unwrap().len(),
        1,
        "the Document block is dropped, only the Text block is encoded"
    );
    insta::assert_json_snapshot!("openai_responses_document_content_block", body);
}

#[test]
fn golden_temperature_forbidden_model() {
    // This profile's [[model]] entries only ever match gpt-5* reasoning
    // models, which OpenAI's real API rejects temperature/top_p for --
    // temperature is never encoded, unconditionally.
    let req = ChatRequest {
        params: Params {
            temperature: Some(0.7),
            top_p: Some(0.9),
            max_output_tokens: None,
            stop: None,
        },
        ..base_request(vec![user_text("Hello.")])
    };
    let body = encode(&req, &fixture_profile());
    assert!(body.get("temperature").is_none());
    assert!(body.get("top_p").is_none());
    insta::assert_json_snapshot!("openai_responses_temperature_forbidden_model", body);
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
    let body = encode(&req, &fixture_profile());
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
    let body = encode(&req, &fixture_profile());
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
    let body = encode(&req, &fixture_profile());
    assert!(body.get("custom_vendor_field").is_none());
    insta::assert_json_snapshot!("openai_responses_raw_extra_passthrough_denied", body);
}
