//! The golden snapshot corpus for the `bedrock-converse` codec's `encode`
//! (§9.10/§13.3): each snapshot is the review artifact a human reads instead
//! of the Rust, pinning every wire shape claimed in this codec's `mod.rs`
//! doc comment (fetch record) against actual encoder output.
//!
//! Snapshots are accepted via `INSTA_UPDATE=always cargo test` (matches this
//! crate's established precedent — `cargo-insta` is not installed here).

use roundhouse_provider::codec::bedrock_converse::encode::{encode, try_encode};
use roundhouse_provider::profile::ProviderProfile;
use roundhouse_provider::{
    ChatRequest, ContentBlock, IdOrigin, MediaSource, Message, Params, Provider, ProviderError,
    ReasoningIntent, ReasoningRequest, Role, SystemBlock, ToolCallId, ToolChoice, ToolResultPart,
};
use serde_json::json;
use std::collections::BTreeMap;

#[path = "support/bedrock_converse_fixtures.rs"]
mod fixtures;
use fixtures::{base_request, user_text};

fn fixture_profile() -> ProviderProfile {
    toml::from_str(include_str!("../profiles/bedrock-converse.toml")).unwrap()
}

#[test]
fn golden_single_turn_text() {
    let req = fixtures::single_turn_text();
    insta::assert_json_snapshot!(
        "bedrock_converse_single_turn_text",
        encode(&req, &fixture_profile())
    );
}

#[test]
fn golden_parallel_tool_calls() {
    let req = fixtures::parallel_tool_calls();
    insta::assert_json_snapshot!(
        "bedrock_converse_parallel_tool_calls",
        encode(&req, &fixture_profile())
    );
}

/// meta.llama4 has no reasoning control entry in the profile at all -- the
/// encoder must return `Unsupported`, and that `Unsupported` must be
/// traceable to the absence of a `[[model]]` entry, per the definition-of-
/// done rule "every Unsupported return is justified by a profile field."
#[test]
fn golden_reasoning_on_is_unsupported_and_justified_by_profile() {
    let req = fixtures::reasoning_on();
    let result = try_encode(&req, &fixture_profile());
    assert!(
        matches!(&result, Err(ProviderError::Unsupported(reason)) if reason.contains("no reasoning control declared in profile")),
        "expected an Unsupported error naming the missing reasoning control, got {result:?}"
    );
}

#[test]
fn golden_forced_tool_choice() {
    let req = fixtures::forced_tool_choice();
    let body = encode(&req, &fixture_profile());
    assert_eq!(
        body["toolConfig"]["toolChoice"],
        json!({"tool": {"name": "get_weather"}})
    );
    insta::assert_json_snapshot!("bedrock_converse_forced_tool_choice", body);
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
        "bedrock_converse_multi_turn_text",
        encode(&req, &fixture_profile())
    );
}

#[test]
fn golden_system_prompt() {
    let req = ChatRequest {
        system: vec![SystemBlock {
            text: "You are a careful assistant.".into(),
            cache: None,
        }],
        ..base_request(vec![user_text("Hello.")])
    };
    let body = encode(&req, &fixture_profile());
    assert_eq!(
        body["system"],
        json!([{"text": "You are a careful assistant."}])
    );
    insta::assert_json_snapshot!("bedrock_converse_system_prompt", body);
}

#[test]
fn golden_tool_result_is_error() {
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
    assert_eq!(
        body["messages"][0]["content"][0]["toolResult"]["status"],
        "error"
    );
    insta::assert_json_snapshot!("bedrock_converse_tool_result_is_error", body);
}

#[test]
fn golden_reasoning_off_succeeds_normally() {
    let req = ChatRequest {
        reasoning: ReasoningRequest {
            intent: Some(ReasoningIntent::Off),
        },
        ..base_request(vec![user_text("Hello.")])
    };
    let body = encode(&req, &fixture_profile());
    assert!(body.get("additionalModelRequestFields").is_none());
    insta::assert_json_snapshot!("bedrock_converse_reasoning_off", body);
}

#[test]
fn golden_unicode_content() {
    let req = base_request(vec![user_text("こんにちは 🌍 — café naïve")]);
    insta::assert_json_snapshot!(
        "bedrock_converse_unicode_content",
        encode(&req, &fixture_profile())
    );
}

#[test]
fn golden_image_content_block() {
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
    let err = try_encode(&req, &fixture_profile()).expect_err("Image must be rejected");
    insta::assert_snapshot!("bedrock_converse_image_content_block", err.to_string());
}

#[test]
fn golden_document_content_block() {
    let req = ChatRequest {
        messages: vec![Message {
            role: Role::User,
            content: vec![ContentBlock::Document {
                source: MediaSource {
                    mime_type: "application/pdf".into(),
                    data: vec![0, 1, 2, 3],
                },
                title: Some("report.pdf".into()),
                cache: None,
            }],
        }],
        ..base_request(vec![])
    };
    let err = try_encode(&req, &fixture_profile()).expect_err("Document must be rejected");
    insta::assert_snapshot!("bedrock_converse_document_content_block", err.to_string());
}

#[test]
fn golden_thinking_content_block() {
    let req = ChatRequest {
        messages: vec![Message {
            role: Role::Assistant,
            content: vec![ContentBlock::Thinking {
                text: "reasoning...".into(),
                signature: None,
                redacted: false,
            }],
        }],
        ..base_request(vec![])
    };
    let err = try_encode(&req, &fixture_profile()).expect_err("Thinking must be rejected");
    insta::assert_snapshot!("bedrock_converse_thinking_content_block", err.to_string());
}

/// Verified real divergence: `ToolChoice::None` has no member in the real
/// `ToolChoice` union (only `auto`/`any`/`tool` exist) -- see this codec's
/// `mod.rs` doc comment.
#[test]
fn golden_tool_choice_none_is_unsupported() {
    let req = ChatRequest {
        tools: vec![roundhouse_provider::tool_def_from_schema::<
            fixtures::NoParams,
        >("get_weather", "Get the current weather")],
        tool_choice: ToolChoice::None,
        ..base_request(vec![user_text("Weather in Tokyo?")])
    };
    let err = try_encode(&req, &fixture_profile()).expect_err("ToolChoice::None must be rejected");
    insta::assert_snapshot!(
        "bedrock_converse_tool_choice_none_unsupported",
        err.to_string()
    );
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
    assert_eq!(
        body["messages"][0]["content"][0]["toolUse"]["input"],
        json!({})
    );
    insta::assert_json_snapshot!("bedrock_converse_empty_tool_argument_buffer", body);
}

#[test]
fn golden_stop_sequences_are_forwarded() {
    // Verified divergence from Open Responses (Task 5): Bedrock's
    // `inferenceConfig.stopSequences` is a real field.
    let req = ChatRequest {
        params: Params {
            temperature: None,
            top_p: None,
            max_output_tokens: None,
            stop: Some(vec!["STOP_1".into(), "STOP_2".into()]),
        },
        ..base_request(vec![user_text("Hello.")])
    };
    let body = encode(&req, &fixture_profile());
    assert_eq!(
        body["inferenceConfig"]["stopSequences"],
        json!(["STOP_1", "STOP_2"])
    );
    insta::assert_json_snapshot!("bedrock_converse_stop_sequences_are_forwarded", body);
}

#[test]
fn golden_raw_extra_passthrough_denied() {
    // bedrock-converse.toml declares allow_raw_extra = false.
    let mut extra = BTreeMap::new();
    extra.insert("custom_vendor_field".to_string(), json!(true));
    let req = ChatRequest {
        extra,
        ..base_request(vec![user_text("Hello.")])
    };
    let body = encode(&req, &fixture_profile());
    assert!(body.get("custom_vendor_field").is_none());
    insta::assert_json_snapshot!("bedrock_converse_raw_extra_passthrough_denied", body);
}

#[test]
fn golden_temperature_and_top_p_and_max_tokens() {
    let req = ChatRequest {
        params: Params {
            temperature: Some(0.7),
            top_p: Some(0.9),
            max_output_tokens: Some(256),
            stop: None,
        },
        ..base_request(vec![user_text("Hello.")])
    };
    let body = encode(&req, &fixture_profile());
    assert_eq!(
        body["inferenceConfig"]["temperature"].as_f64(),
        Some(0.7_f32 as f64)
    );
    assert_eq!(
        body["inferenceConfig"]["topP"].as_f64(),
        Some(0.9_f32 as f64)
    );
    assert_eq!(body["inferenceConfig"]["maxTokens"], json!(256));
    insta::assert_json_snapshot!(
        "bedrock_converse_temperature_and_top_p_and_max_tokens",
        body
    );
}

#[test]
fn golden_assistant_tool_use_and_prior_result_round_trip() {
    let req = ChatRequest {
        messages: vec![
            user_text("What's the weather in Tokyo?"),
            Message {
                role: Role::Assistant,
                content: vec![ContentBlock::ToolUse {
                    id: ToolCallId("call_1".into()),
                    id_origin: IdOrigin::Provider,
                    name: "get_weather".into(),
                    input: json!({"location": "Tokyo"}),
                    cache: None,
                }],
            },
            Message {
                role: Role::User,
                content: vec![ContentBlock::ToolResult {
                    tool_use_id: ToolCallId("call_1".into()),
                    content: vec![ToolResultPart {
                        text: "sunny, 22C".into(),
                    }],
                    is_error: false,
                    cache: None,
                }],
            },
        ],
        ..base_request(vec![])
    };
    insta::assert_json_snapshot!(
        "bedrock_converse_assistant_tool_use_and_prior_result_round_trip",
        encode(&req, &fixture_profile())
    );
}

#[test]
fn golden_opaque_content_block() {
    let req = ChatRequest {
        messages: vec![Message {
            role: Role::Assistant,
            content: vec![ContentBlock::Opaque {
                provider: roundhouse_provider::ProviderId("bedrock-converse".into()),
                kind: "vendor_specific".into(),
                raw: json!({"whatever": true}),
            }],
        }],
        ..base_request(vec![])
    };
    let err = try_encode(&req, &fixture_profile()).expect_err("Opaque must be rejected");
    insta::assert_snapshot!("bedrock_converse_opaque_content_block", err.to_string());
}

#[test]
fn resolve_accepts_a_request_with_no_unencodable_content() {
    let provider = roundhouse_provider::codec::bedrock_converse::BedrockConverseProvider::new(
        fixture_profile(),
    );
    assert!(provider.resolve(&fixtures::single_turn_text()).is_ok());
}

#[test]
fn resolve_rejects_an_image_bearing_request() {
    let provider = roundhouse_provider::codec::bedrock_converse::BedrockConverseProvider::new(
        fixture_profile(),
    );
    let req = ChatRequest {
        messages: vec![Message {
            role: Role::User,
            content: vec![ContentBlock::Image {
                source: MediaSource {
                    mime_type: "image/png".into(),
                    data: vec![0, 1, 2, 3],
                },
                cache: None,
            }],
        }],
        ..base_request(vec![])
    };
    assert!(matches!(
        provider.resolve(&req),
        Err(ProviderError::Unsupported(_))
    ));
}
