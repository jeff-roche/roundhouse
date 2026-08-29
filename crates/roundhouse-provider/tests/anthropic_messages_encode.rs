use roundhouse_provider::codec::anthropic_messages::encode_anthropic_messages;
use roundhouse_provider::{
    tool_def_from_schema, CacheBreakpoint, ChatRequest, ContentBlock, IdOrigin, MediaSource,
    Message, ModelId, Params, ProviderExt, ReasoningIntent, ReasoningRequest, RequestPolicy,
    ResponseFormat, Role, Signature, SystemBlock, ToolCallId, ToolChoice,
};
use serde_json::json;
use std::collections::BTreeMap;

// Note: Snapshots in this crate are accepted via `INSTA_UPDATE=always cargo test` since
// `cargo-insta` CLI is not installed in this environment (update: cargo-insta v1.48.0 is now available).

/// Test params struct for the "read" tool.
#[derive(schemars::JsonSchema)]
struct ReadParams {
    #[allow(dead_code)]
    path: String,
}

#[test]
fn encodes_cache_breakpoint_and_thinking_block() {
    let req = ChatRequest {
        model: ModelId("claude-sonnet-5".into()),
        system: vec![SystemBlock {
            text: "You are a careful coding agent.".into(),
            cache: Some(CacheBreakpoint),
        }],
        messages: vec![
            Message {
                role: Role::User,
                content: vec![ContentBlock::Text {
                    text: "Edit main.rs".into(),
                    cache: None,
                    citations: vec![],
                }],
            },
            Message {
                role: Role::Assistant,
                content: vec![
                    ContentBlock::Thinking {
                        text: "I should read the file first.".into(),
                        signature: Some(Signature("sig-abc123".into())),
                        redacted: false,
                    },
                    ContentBlock::ToolUse {
                        id: ToolCallId("toolu_1".into()),
                        id_origin: IdOrigin::Provider,
                        name: "read".into(),
                        input: json!({ "path": "main.rs" }),
                        cache: None,
                    },
                ],
            },
        ],
        tools: vec![tool_def_from_schema::<ReadParams>("read", "Read a file")],
        tool_choice: ToolChoice::Auto,
        params: Params {
            temperature: None,
            top_p: None,
            max_output_tokens: Some(2048),
            stop: None,
        },
        reasoning: ReasoningRequest {
            intent: Some(ReasoningIntent::Medium),
        },
        response_format: ResponseFormat::default(),
        ext: ProviderExt::None,
        extra: BTreeMap::new(),
        policy: RequestPolicy::Error,
    };

    let body = encode_anthropic_messages(&req);

    insta::assert_json_snapshot!("anthropic_messages_encode__cache_and_thinking", body);
}

#[test]
fn skips_messages_with_only_phase1_filtered_content() {
    // Test that a message containing only Image blocks (which Phase 1 does not emit)
    // does not appear in the encoded messages array. This prevents the empty-content-array
    // bug class (Anthropic rejects content: []).
    let req = ChatRequest {
        model: ModelId("claude-sonnet-5".into()),
        system: vec![],
        messages: vec![
            Message {
                role: Role::User,
                content: vec![ContentBlock::Text {
                    text: "What's in the image?".into(),
                    cache: None,
                    citations: vec![],
                }],
            },
            Message {
                role: Role::Assistant,
                content: vec![ContentBlock::Image {
                    source: MediaSource {
                        mime_type: "image/png".into(),
                        data: vec![0x89, 0x50, 0x4E, 0x47],
                    },
                    cache: None,
                }],
            },
            Message {
                role: Role::User,
                content: vec![ContentBlock::Text {
                    text: "OK, I see it.".into(),
                    cache: None,
                    citations: vec![],
                }],
            },
        ],
        tools: vec![],
        tool_choice: ToolChoice::None,
        params: Params {
            temperature: None,
            top_p: None,
            max_output_tokens: None,
            stop: None,
        },
        reasoning: ReasoningRequest::default(),
        response_format: ResponseFormat::default(),
        ext: ProviderExt::None,
        extra: BTreeMap::new(),
        policy: RequestPolicy::Error,
    };

    let body = encode_anthropic_messages(&req);

    // Verify that the assistant message with only Image content is skipped entirely,
    // so the messages array has exactly 2 entries (user → assistant → user), not 3.
    let messages = &body["messages"];
    assert_eq!(
        messages.as_array().unwrap().len(),
        2,
        "Expected 2 messages (assistant image-only message skipped)"
    );
    assert_eq!(messages[0]["role"], "user");
    assert_eq!(messages[0]["content"][0]["text"], "What's in the image?");
    assert_eq!(messages[1]["role"], "user");
    assert_eq!(messages[1]["content"][0]["text"], "OK, I see it.");
}
