use roundhouse_provider::codec::anthropic_messages::encode_anthropic_messages;
use roundhouse_provider::{
    CacheBreakpoint, ChatRequest, ContentBlock, IdOrigin, Message, ModelId, Params, ProviderExt,
    ReasoningIntent, ReasoningRequest, RequestPolicy, ResponseFormat, Role, Signature, SystemBlock,
    ToolCallId, ToolChoice, tool_def_from_schema,
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
                content: vec![ContentBlock::Text { text: "Edit main.rs".into(), cache: None, citations: vec![] }],
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
        params: Params { temperature: None, top_p: None, max_output_tokens: Some(2048), stop: None },
        reasoning: ReasoningRequest { intent: Some(ReasoningIntent::Medium) },
        response_format: ResponseFormat::default(),
        ext: ProviderExt::None,
        extra: BTreeMap::new(),
        policy: RequestPolicy::Error,
    };

    let body = encode_anthropic_messages(&req);

    insta::assert_json_snapshot!("anthropic_messages_encode__cache_and_thinking", body);
}
