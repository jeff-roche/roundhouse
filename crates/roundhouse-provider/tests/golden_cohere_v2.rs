//! The golden corpus for the `cohere-v2` codec's `encode` (§9.10/§13.3).
//! Verified against the real, fetched Cohere API reference -- see
//! `src/codec/cohere_v2/mod.rs`'s module doc comment for the fetch record.
//!
//! Snapshots are accepted via `INSTA_UPDATE=always cargo test` (`cargo-insta`
//! CLI is not installed in this environment -- matches every sibling
//! codec's established note).

use roundhouse_provider::codec::cohere_v2::encode::encode;
use roundhouse_provider::codec::cohere_v2::CohereV2Provider;
use roundhouse_provider::profile::{Intent, ProviderProfile};
use roundhouse_provider::{
    ChatRequest, ContentBlock, IdOrigin, MediaSource, Message, Params, Provider, ProviderError,
    ReasoningIntent, ReasoningRequest, Role, ToolCallId, ToolChoice, ToolResultPart,
};
use serde_json::json;
use std::collections::BTreeMap;

#[path = "support/cohere_v2_fixtures.rs"]
mod fixtures;
use fixtures::{base_request, user_text};

fn fixture_profile() -> ProviderProfile {
    toml::from_str(include_str!("../profiles/cohere-v2.toml")).unwrap()
}

fn enc(req: &ChatRequest) -> serde_json::Value {
    encode(req, &fixture_profile()).expect("encode must succeed for this fixture profile")
}

#[test]
fn golden_single_turn_text() {
    let req = fixtures::single_turn_text();
    insta::assert_json_snapshot!("cohere_v2_single_turn_text", enc(&req));
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
    insta::assert_json_snapshot!("cohere_v2_multi_turn_text", enc(&req));
}

#[test]
fn golden_system_prompt() {
    let req = ChatRequest {
        system: vec![roundhouse_provider::SystemBlock {
            text: "You are a careful assistant.".into(),
            cache: None,
        }],
        ..base_request(vec![user_text("Hello.")])
    };
    let body = enc(&req);
    assert_eq!(body["messages"][0]["role"], "system");
    assert_eq!(
        body["messages"][0]["content"],
        "You are a careful assistant."
    );
    insta::assert_json_snapshot!("cohere_v2_system_prompt", body);
}

#[test]
fn golden_parallel_tool_calls() {
    let req = fixtures::parallel_tool_calls();
    insta::assert_json_snapshot!("cohere_v2_parallel_tool_calls", enc(&req));
}

#[test]
fn golden_tool_choice_required() {
    let req = fixtures::forced_tool_choice();
    let body = enc(&req);
    assert_eq!(body["tool_choice"], json!("REQUIRED"));
    insta::assert_json_snapshot!("cohere_v2_tool_choice_required", body);
}

#[test]
fn golden_tool_choice_none() {
    let req = ChatRequest {
        tools: vec![roundhouse_provider::tool_def_from_schema::<
            fixtures::NoParams,
        >("get_weather", "Get the current weather")],
        tool_choice: ToolChoice::None,
        ..base_request(vec![user_text("Hello.")])
    };
    let body = enc(&req);
    assert_eq!(body["tool_choice"], json!("NONE"));
    insta::assert_json_snapshot!("cohere_v2_tool_choice_none", body);
}

/// Verified: Cohere v2 has no mechanism to force one SPECIFIC named tool --
/// `Named` degrades to the closest honest wire-expressible shape
/// (`"REQUIRED"`, forcing *a* tool call), matching
/// `anthropic_messages::encode_tool_choice`'s identical documented-degrade
/// precedent for `ToolChoice::None`.
#[test]
fn golden_named_tool_choice_degrades_to_required() {
    let req = ChatRequest {
        tools: vec![roundhouse_provider::tool_def_from_schema::<
            fixtures::NoParams,
        >("get_weather", "Get the current weather")],
        tool_choice: ToolChoice::Named("get_weather".into()),
        ..base_request(vec![user_text("What's the weather?")])
    };
    let body = enc(&req);
    assert_eq!(body["tool_choice"], json!("REQUIRED"));
}

#[test]
fn golden_tool_result_forwarded_as_a_tool_role_message() {
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
    let body = enc(&req);
    assert_eq!(body["messages"][0]["role"], "tool");
    assert_eq!(body["messages"][0]["tool_call_id"], "call_1");
    assert_eq!(body["messages"][0]["content"], "permission denied");
    insta::assert_json_snapshot!("cohere_v2_tool_result_is_error", body);
}

#[test]
fn golden_reasoning_on() {
    let req = fixtures::reasoning_on();
    let body = enc(&req);
    assert_eq!(body["thinking"], json!({ "type": "enabled" }));
    insta::assert_json_snapshot!("cohere_v2_reasoning_on", body);
}

#[test]
fn golden_reasoning_off() {
    let req = ChatRequest {
        model: roundhouse_provider::ModelId("command-a-reasoning-03-2026".into()),
        reasoning: ReasoningRequest {
            intent: Some(ReasoningIntent::Off),
        },
        ..base_request(vec![user_text("Hello.")])
    };
    let body = enc(&req);
    assert!(body.get("thinking").is_none());
    insta::assert_json_snapshot!("cohere_v2_reasoning_off", body);
}

/// A non-reasoning model matching no `[[model]]` entry never gets a
/// `thinking` field, even when the caller asks for one -- there is no
/// profile-declared `ReasoningControl` to resolve it through.
#[test]
fn golden_reasoning_requested_on_a_non_reasoning_model_is_a_silent_no_op() {
    let req = ChatRequest {
        reasoning: ReasoningRequest {
            intent: Some(ReasoningIntent::High),
        },
        ..base_request(vec![user_text("Hello.")])
    };
    let body = enc(&req);
    assert!(body.get("thinking").is_none());
}

#[test]
fn golden_unicode_content() {
    let req = base_request(vec![user_text("こんにちは 🌍 — café naïve")]);
    insta::assert_json_snapshot!("cohere_v2_unicode_content", enc(&req));
}

#[test]
fn golden_image_content_block_fails_closed() {
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

    let provider = CohereV2Provider::new(fixture_profile());
    assert!(
        matches!(provider.resolve(&req), Err(ProviderError::Unsupported(_))),
        "resolve() must reject a request containing an Image block, not silently drop it later"
    );

    let err = encode(&req, &fixture_profile())
        .expect_err("encode() must refuse to silently drop an Image block");
    insta::assert_snapshot!("cohere_v2_image_content_block", err.to_string());
}

#[test]
fn golden_document_content_block_fails_closed() {
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

    let provider = CohereV2Provider::new(fixture_profile());
    assert!(
        matches!(provider.resolve(&req), Err(ProviderError::Unsupported(_))),
        "resolve() must reject a request containing a Document block, not silently drop it later"
    );

    let err = encode(&req, &fixture_profile())
        .expect_err("encode() must refuse to silently drop a Document block");
    insta::assert_snapshot!("cohere_v2_document_content_block", err.to_string());
}

#[test]
fn golden_opaque_content_block_fails_closed() {
    let req = ChatRequest {
        messages: vec![Message {
            role: Role::Assistant,
            content: vec![ContentBlock::Opaque {
                provider: roundhouse_provider::ProviderId("some-other-provider".into()),
                kind: "vendor_specific".into(),
                raw: json!({ "anything": true }),
            }],
        }],
        ..base_request(vec![])
    };

    let provider = CohereV2Provider::new(fixture_profile());
    assert!(
        matches!(provider.resolve(&req), Err(ProviderError::Unsupported(_))),
        "resolve() must reject a request containing an Opaque block, not silently drop it later"
    );

    let err = encode(&req, &fixture_profile())
        .expect_err("encode() must refuse to silently drop an Opaque block");
    insta::assert_snapshot!("cohere_v2_opaque_content_block", err.to_string());
}

/// The three error messages above must be distinguishable (matches
/// `google_genai`'s carried-forward review fix for the same class of bug).
#[test]
fn unencodable_media_errors_are_distinguishable() {
    fn err_for(block: ContentBlock) -> String {
        encode(
            &ChatRequest {
                messages: vec![Message {
                    role: Role::User,
                    content: vec![block],
                }],
                ..base_request(vec![])
            },
            &fixture_profile(),
        )
        .unwrap_err()
        .to_string()
    }
    let image_err = err_for(ContentBlock::Image {
        source: MediaSource {
            mime_type: "image/png".into(),
            data: vec![],
        },
        cache: None,
    });
    let doc_err = err_for(ContentBlock::Document {
        source: MediaSource {
            mime_type: "application/pdf".into(),
            data: vec![],
        },
        title: None,
        cache: None,
    });
    let opaque_err = err_for(ContentBlock::Opaque {
        provider: roundhouse_provider::ProviderId("x".into()),
        kind: "y".into(),
        raw: json!({}),
    });
    assert_ne!(image_err, doc_err);
    assert_ne!(image_err, opaque_err);
    assert_ne!(doc_err, opaque_err);
}

/// Cohere v2's assistant content array DOES support a real `"thinking"`
/// block (verified -- see `mod.rs`'s fetch record), so this codec, unlike
/// `google_genai`/`openai_responses`, actually round-trips it rather than
/// failing closed.
#[test]
fn golden_thinking_content_block_round_trips() {
    let req = ChatRequest {
        messages: vec![Message {
            role: Role::Assistant,
            content: vec![
                ContentBlock::Thinking {
                    text: "Let me work through this step by step.".into(),
                    signature: None,
                    redacted: false,
                },
                ContentBlock::Text {
                    text: "The answer is 4.".into(),
                    cache: None,
                    citations: vec![],
                },
            ],
        }],
        ..base_request(vec![user_text("What is 2+2?")])
    };
    let body = enc(&req);
    assert_eq!(
        body["messages"][0]["content"],
        json!([
            {"type": "thinking", "thinking": "Let me work through this step by step."},
            {"type": "text", "text": "The answer is 4."},
        ])
    );
    insta::assert_json_snapshot!("cohere_v2_thinking_content_block", body);
}

#[test]
fn resolve_accepts_a_request_with_no_unencodable_media() {
    let provider = CohereV2Provider::new(fixture_profile());
    assert!(provider.resolve(&fixtures::single_turn_text()).is_ok());
}

#[test]
fn golden_temperature_and_p_and_max_tokens_forwarded() {
    let req = ChatRequest {
        params: Params {
            temperature: Some(0.7),
            top_p: Some(0.9),
            max_output_tokens: Some(512),
            stop: None,
        },
        ..base_request(vec![user_text("Hello.")])
    };
    let body = enc(&req);
    assert_eq!(body["temperature"].as_f64(), Some(0.7_f32 as f64));
    assert_eq!(body["p"].as_f64(), Some(0.9_f32 as f64));
    assert_eq!(body["max_tokens"], json!(512));
    insta::assert_json_snapshot!("cohere_v2_temperature_and_p_and_max_tokens", body);
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
    let body = enc(&req);
    assert!(body["messages"][0]["content"].is_null());
    assert_eq!(
        body["messages"][0]["tool_calls"][0]["function"]["arguments"],
        json!("{}")
    );
    insta::assert_json_snapshot!("cohere_v2_empty_tool_argument_buffer", body);
}

#[test]
fn golden_long_stop_sequence_list() {
    let stop: Vec<String> = (0..50).map(|i| format!("STOP_{i}")).collect();
    let req = ChatRequest {
        params: Params {
            temperature: None,
            top_p: None,
            max_output_tokens: None,
            stop: Some(stop.clone()),
        },
        ..base_request(vec![user_text("Hello.")])
    };
    let body = enc(&req);
    assert_eq!(body["stop_sequences"], json!(stop));
    insta::assert_json_snapshot!("cohere_v2_long_stop_sequence_list", body);
}

#[test]
fn golden_raw_extra_passthrough_denied() {
    // cohere-v2.toml declares allow_raw_extra = false.
    let mut extra = BTreeMap::new();
    extra.insert("custom_vendor_field".to_string(), json!(true));
    let req = ChatRequest {
        extra,
        ..base_request(vec![user_text("Hello.")])
    };
    let body = enc(&req);
    assert!(body.get("custom_vendor_field").is_none());
    insta::assert_json_snapshot!("cohere_v2_raw_extra_passthrough_denied", body);
}

/// A reasoning map with no entry for the requested intent must be a hard
/// error, not a silently dropped reasoning field -- mirrors
/// `google_genai`'s identical fix-round-1 minor.
#[test]
fn encode_surfaces_a_broken_reasoning_map_instead_of_silently_omitting_reasoning() {
    let broken_profile: ProviderProfile = toml::from_str(
        r#"
        id = "broken-fixture"
        codec = "cohere-v2"

        [defaults]
        allow_raw_extra = false
        base_url = "https://example.invalid"
        auth = { kind = "bearer" }

        [defaults.params]
        mode = "allow_only"
        fields = ["temperature", "p", "k", "max_tokens", "stop_sequences"]

        [[model]]
        match = ["command-a-reasoning*"]

        [model.reasoning]
        kind = "effort"
        field = "/thinking/type"
        vocabulary = ["disabled", "enabled"]

        [model.reasoning.map]
        off = "disabled"
        low = "enabled"
        medium = "enabled"
        # "high" is deliberately missing.
        "#,
    )
    .expect("fixture profile must deserialize");

    let req = ChatRequest {
        model: roundhouse_provider::ModelId("command-a-reasoning-03-2026".into()),
        reasoning: ReasoningRequest {
            intent: Some(ReasoningIntent::High),
        },
        ..base_request(vec![user_text("Prove sqrt(2) is irrational.")])
    };

    assert!(
        encode(&req, &broken_profile).is_err(),
        "a reasoning map with no entry for the requested intent must be a hard error"
    );
}

/// Sanity: `Intent` is the crate-root re-export of `ReasoningIntent` (§7 of
/// REALITY-CORRECTIONS) -- used by the brief's own golden test sketch.
#[test]
fn intent_re_export_matches_reasoning_intent() {
    assert_eq!(Intent::High, ReasoningIntent::High);
}
