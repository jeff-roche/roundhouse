//! The golden corpus for the `google-genai` codec's `encode` (§9.10/§13.3).
//! Several cases here deliberately diverge from the task brief's unverified
//! sketch and from the sibling `openai_responses` codec's findings -- see
//! `docs/decisions/2026-08-27-google-genai-spec-verification.md` for why each
//! one is real, verified behaviour rather than a mistake:
//!
//! - `golden_single_turn_text_generate_content_mode_matches_content_shape`'s
//!   assertion is rewritten: the brief's `interactions["contents"][0]["parts"]
//!   == legacy["contents"][0]["parts"]` premise is false (Interactions mode
//!   has no `contents` key at all, Divergence 1) -- replaced with an
//!   assertion that is actually true and meaningful.
//! - `reasoning_on`/`reasoning_off`/`reasoning_budget_variant` run under
//!   `EndpointMode::GenerateContent`, the only mode where this profile's
//!   Budget-kind `ReasoningControl` is real (Divergence 2); one extra case
//!   covers the verified, real Interactions-mode `thinking_level` path.
//! - `temperature_forbidden_model` is real for every model under Interactions
//!   mode (the field doesn't exist on that surface at all, Divergence 3), not
//!   a per-model policy gate.
//! - `tool_result_is_error`/`long_stop_sequence_list` forward what they
//!   describe (Divergence 5) -- Gemini's real spec supports both, unlike Open
//!   Responses (Task 5's opposite finding for the same case names).
//!
//! Snapshots are accepted via `INSTA_UPDATE=always cargo test` (matches
//! `golden_openai_responses.rs`'s existing note: `cargo-insta` CLI is not
//! installed in this environment).

use roundhouse_provider::codec::google_genai::encode::encode;
use roundhouse_provider::codec::google_genai::{EndpointMode, GoogleGenAiProvider};
use roundhouse_provider::profile::ProviderProfile;
use roundhouse_provider::{
    ChatRequest, ContentBlock, IdOrigin, MediaSource, Message, Params, Provider, ProviderError,
    ReasoningIntent, ReasoningRequest, Role, SystemBlock, ToolCallId, ToolResultPart,
};
use serde_json::json;
use std::collections::BTreeMap;

#[path = "support/google_genai_fixtures.rs"]
mod fixtures;
use fixtures::{base_request, user_text};

fn fixture_profile() -> ProviderProfile {
    toml::from_str(include_str!("../profiles/google-genai.toml")).unwrap()
}

fn enc(req: &ChatRequest, mode: EndpointMode) -> serde_json::Value {
    encode(req, &fixture_profile(), mode).expect("encode must succeed for this fixture profile")
}

#[test]
fn golden_single_turn_text_interactions_mode() {
    let req = fixtures::single_turn_text();
    insta::assert_json_snapshot!(
        "google_genai_single_turn_text_interactions",
        enc(&req, EndpointMode::Interactions)
    );
}

#[test]
fn golden_single_turn_text_generate_content_mode_matches_content_shape() {
    let req = fixtures::single_turn_text();
    let interactions = enc(&req, EndpointMode::Interactions);
    let legacy = enc(&req, EndpointMode::GenerateContent);
    // Divergence 1: the brief's working bet ("only the envelope differs") is
    // false -- Interactions mode has no `contents` key at all. What IS true
    // and worth pinning: both encodings carry the same input text through to
    // their own real wire shape.
    assert_eq!(
        interactions["input"][0]["content"][0]["text"],
        legacy["contents"][0]["parts"][0]["text"]
    );
    insta::assert_json_snapshot!("google_genai_single_turn_text_generate_content", legacy);
}

#[test]
fn golden_parallel_tool_calls() {
    let req = fixtures::parallel_tool_calls();
    insta::assert_json_snapshot!(
        "google_genai_parallel_tool_calls",
        enc(&req, EndpointMode::Interactions)
    );
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
        "google_genai_multi_turn_text",
        enc(&req, EndpointMode::Interactions)
    );
}

#[test]
fn golden_system_prompt_with_cache_breakpoint() {
    // Gemini has no per-block cache breakpoint wire representation on either
    // surface (it caches automatically) -- `cache` is dropped.
    let req = ChatRequest {
        system: vec![SystemBlock {
            text: "You are a careful assistant.".into(),
            cache: Some(roundhouse_provider::CacheBreakpoint),
        }],
        ..base_request(vec![user_text("Hello.")])
    };
    let body = enc(&req, EndpointMode::Interactions);
    assert_eq!(body["system_instruction"], "You are a careful assistant.");
    insta::assert_json_snapshot!("google_genai_system_prompt_with_cache_breakpoint", body);
}

#[test]
fn golden_forced_tool_choice() {
    let req = fixtures::forced_tool_choice();
    let body = enc(&req, EndpointMode::Interactions);
    assert_eq!(
        body["generation_config"]["tool_choice"],
        json!({"allowed_tools": {"mode": "any", "tools": ["get_weather"]}})
    );
    insta::assert_json_snapshot!("google_genai_forced_tool_choice", body);
}

#[test]
fn golden_tool_result_is_error() {
    // Divergence 5: `FunctionResultStep.is_error` is a real field -- unlike
    // Open Responses' `function_call_output` (Task 5's finding of no such
    // field at all), it must appear on the wire here.
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
    let body = enc(&req, EndpointMode::Interactions);
    assert_eq!(body["input"][0]["is_error"], true);
    insta::assert_json_snapshot!("google_genai_tool_result_is_error", body);
}

#[test]
fn golden_reasoning_on() {
    // Divergence 2: Budget-kind reasoning is only real under GenerateContent
    // mode (`generationConfig.thinkingConfig.thinkingBudget`).
    let req = fixtures::reasoning_on();
    let body = enc(&req, EndpointMode::GenerateContent);
    assert_eq!(
        body["generationConfig"]["thinkingConfig"]["thinkingBudget"],
        24576
    );
    insta::assert_json_snapshot!("google_genai_reasoning_on", body);
}

#[test]
fn golden_reasoning_off() {
    let req = ChatRequest {
        reasoning: ReasoningRequest {
            intent: Some(ReasoningIntent::Off),
        },
        ..base_request(vec![user_text("Hello.")])
    };
    let body = enc(&req, EndpointMode::Interactions);
    assert!(body.pointer("/generation_config/thinking_level").is_none());
    insta::assert_json_snapshot!("google_genai_reasoning_off", body);
}

#[test]
fn golden_reasoning_budget_variant() {
    let req = ChatRequest {
        reasoning: ReasoningRequest {
            intent: Some(ReasoningIntent::Medium),
        },
        ..base_request(vec![user_text("Summarize this briefly.")])
    };
    let body = enc(&req, EndpointMode::GenerateContent);
    assert_eq!(
        body["generationConfig"]["thinkingConfig"]["thinkingBudget"],
        8192
    );
    insta::assert_json_snapshot!("google_genai_reasoning_budget_variant", body);
}

/// Extra case (beyond the brief's named three): proves the OTHER real
/// reasoning path this codec has to support -- Interactions mode's verified
/// `thinking_level` enum, which the brief's Budget-only sketch never
/// anticipated at all (Divergence 2).
#[test]
fn golden_reasoning_on_interactions_thinking_level() {
    let req = fixtures::reasoning_on();
    let body = enc(&req, EndpointMode::Interactions);
    assert_eq!(body["generation_config"]["thinking_level"], "high");
    insta::assert_json_snapshot!(
        "google_genai_reasoning_on_interactions_thinking_level",
        body
    );
}

#[test]
fn golden_unicode_content() {
    let req = base_request(vec![user_text("こんにちは 🌍 — café naïve")]);
    insta::assert_json_snapshot!(
        "google_genai_unicode_content",
        enc(&req, EndpointMode::Interactions)
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

    let provider = GoogleGenAiProvider::new(fixture_profile(), EndpointMode::Interactions);
    assert!(
        matches!(provider.resolve(&req), Err(ProviderError::Unsupported(_))),
        "resolve() must reject a request containing an Image block, not silently drop it later"
    );

    let err = encode(&req, &fixture_profile(), EndpointMode::Interactions)
        .expect_err("encode() must refuse to silently drop an Image block");
    insta::assert_snapshot!("google_genai_image_content_block", err.to_string());
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

    let provider = GoogleGenAiProvider::new(fixture_profile(), EndpointMode::Interactions);
    assert!(
        matches!(provider.resolve(&req), Err(ProviderError::Unsupported(_))),
        "resolve() must reject a request containing a Document block, not silently drop it later"
    );

    let err = encode(&req, &fixture_profile(), EndpointMode::Interactions)
        .expect_err("encode() must refuse to silently drop a Document block");
    insta::assert_snapshot!("google_genai_document_content_block", err.to_string());
}

/// The two error messages above must be distinguishable (a carried-forward
/// fix from Task 5's review, applied here from the start).
#[test]
fn image_and_document_unencodable_media_errors_are_distinguishable() {
    let image_err = encode(
        &ChatRequest {
            messages: vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Image {
                    source: MediaSource {
                        mime_type: "image/png".into(),
                        data: vec![],
                    },
                    cache: None,
                }],
            }],
            ..base_request(vec![])
        },
        &fixture_profile(),
        EndpointMode::Interactions,
    )
    .unwrap_err();
    let doc_err = encode(
        &ChatRequest {
            messages: vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Document {
                    source: MediaSource {
                        mime_type: "application/pdf".into(),
                        data: vec![],
                    },
                    title: None,
                    cache: None,
                }],
            }],
            ..base_request(vec![])
        },
        &fixture_profile(),
        EndpointMode::Interactions,
    )
    .unwrap_err();
    assert_ne!(image_err.to_string(), doc_err.to_string());
}

#[test]
fn resolve_accepts_a_request_with_no_unencodable_media() {
    let provider = GoogleGenAiProvider::new(fixture_profile(), EndpointMode::Interactions);
    assert!(provider.resolve(&fixtures::single_turn_text()).is_ok());
}

#[test]
fn golden_temperature_forbidden_model() {
    // Divergence 3: verified structural fact -- temperature/top_p do not
    // exist anywhere in the Interactions API's request schema, for ANY
    // model, unlike OpenAI's per-model reasoning-family gate (Task 5).
    let req = ChatRequest {
        params: Params {
            temperature: Some(0.7),
            top_p: Some(0.9),
            max_output_tokens: None,
            stop: None,
        },
        ..base_request(vec![user_text("Hello.")])
    };
    let body = enc(&req, EndpointMode::Interactions);
    assert!(body.get("temperature").is_none());
    assert!(body.get("top_p").is_none());
    assert!(body.pointer("/generation_config/temperature").is_none());
    insta::assert_json_snapshot!("google_genai_temperature_forbidden_model", body);
}

/// The companion half of the finding above: the SAME request's
/// temperature/top_p ARE forwarded once encoded under
/// `EndpointMode::GenerateContent`, proving the omission above is about
/// which wire endpoint supports the field at all, not a hardcoded
/// "never send this" policy baked into the codec.
#[test]
fn temperature_and_top_p_are_forwarded_under_generate_content_mode() {
    let req = ChatRequest {
        params: Params {
            temperature: Some(0.7),
            top_p: Some(0.9),
            max_output_tokens: None,
            stop: None,
        },
        ..base_request(vec![user_text("Hello.")])
    };
    let body = enc(&req, EndpointMode::GenerateContent);
    assert_eq!(
        body["generationConfig"]["temperature"].as_f64(),
        Some(0.7_f32 as f64)
    );
    assert_eq!(
        body["generationConfig"]["topP"].as_f64(),
        Some(0.9_f32 as f64)
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
    let body = enc(&req, EndpointMode::Interactions);
    assert_eq!(body["input"][0]["arguments"], json!({}));
    insta::assert_json_snapshot!("google_genai_empty_tool_argument_buffer", body);
}

#[test]
fn golden_long_stop_sequence_list() {
    // Divergence 5: verified `stop_sequences` DOES exist on this surface --
    // unlike Open Responses (Task 5's opposite finding), so it must be
    // forwarded, not dropped.
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
    let body = enc(&req, EndpointMode::Interactions);
    assert_eq!(body["generation_config"]["stop_sequences"], json!(stop));
    insta::assert_json_snapshot!("google_genai_long_stop_sequence_list", body);
}

#[test]
fn golden_raw_extra_passthrough_denied() {
    // google-genai.toml declares allow_raw_extra = false.
    let mut extra = BTreeMap::new();
    extra.insert("custom_vendor_field".to_string(), json!(true));
    let req = ChatRequest {
        extra,
        ..base_request(vec![user_text("Hello.")])
    };
    let body = enc(&req, EndpointMode::Interactions);
    assert!(body.get("custom_vendor_field").is_none());
    insta::assert_json_snapshot!("google_genai_raw_extra_passthrough_denied", body);
}

/// Mirrors `openai_responses`' fix-round-1 minor: a reasoning map with no
/// entry for the requested intent must be a hard error, not a silently
/// dropped reasoning field. Exercised under `GenerateContent` mode, the only
/// mode that consults the profile's `ReasoningControl` at all.
#[test]
fn encode_surfaces_a_broken_reasoning_map_instead_of_silently_omitting_reasoning() {
    let broken_profile: ProviderProfile = toml::from_str(
        r#"
        id = "broken-fixture"
        codec = "google-genai"

        [defaults]
        allow_raw_extra = false
        base_url = "https://example.invalid"

        [defaults.params]
        mode = "deny_list"
        fields = []

        [defaults.auth]
        kind = "header_key"
        header = "x-goog-api-key"

        [[model]]
        match = ["gemini-3.0*"]

        [model.reasoning]
        kind = "budget"
        field = "/generationConfig/thinkingConfig/thinkingBudget"
        vocabulary = ["0", "1024", "8192"]

        [model.reasoning.map]
        off = "0"
        low = "1024"
        medium = "8192"
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
        encode(&req, &broken_profile, EndpointMode::GenerateContent).is_err(),
        "a reasoning map with no entry for the requested intent must be a hard error"
    );
}
