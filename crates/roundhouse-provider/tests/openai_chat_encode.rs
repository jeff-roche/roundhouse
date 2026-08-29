use roundhouse_provider::codec::openai_chat::encode_openai_chat;
use roundhouse_provider::{
    ChatRequest, ContentBlock, IdOrigin, Message, ModelId, Params, ProviderExt, ReasoningRequest,
    RequestPolicy, ResponseFormat, Role, SystemBlock, ToolCallId, ToolChoice, ToolResultPart,
    tool_def_from_schema,
};
use serde_json::json;
use std::collections::BTreeMap;

// Note: Snapshots in this crate are accepted via `INSTA_UPDATE=always cargo test` since
// `cargo-insta` CLI is not installed in this environment.

/// Test params struct for the "read" tool.
#[derive(schemars::JsonSchema)]
struct ReadParams {
    #[allow(dead_code)]
    path: String,
}

#[test]
fn encodes_basic_tool_call_request() {
    let req = ChatRequest {
        model: ModelId("gpt-5.4".into()),
        system: vec![SystemBlock { text: "You are a careful coding agent.".into(), cache: None }],
        messages: vec![
            Message {
                role: Role::User,
                content: vec![ContentBlock::Text { text: "Read main.rs".into(), cache: None, citations: vec![] }],
            },
            Message {
                role: Role::Assistant,
                content: vec![ContentBlock::ToolUse {
                    id: ToolCallId("call_1".into()),
                    id_origin: IdOrigin::Provider,
                    name: "read".into(),
                    input: json!({ "path": "main.rs" }),
                    cache: None,
                }],
            },
        ],
        tools: vec![tool_def_from_schema::<ReadParams>("read", "Read a file")],
        tool_choice: ToolChoice::Auto,
        // Params.stop is Option<Vec<String>> (audit finding 5 — the frozen "every field
        // Option" rule) and the max-tokens field is named max_output_tokens.
        params: Params { temperature: None, top_p: None, max_output_tokens: Some(1024), stop: None },
        reasoning: ReasoningRequest::default(),
        // response_format/ext/extra/policy: unpopulated in Phase 1 (see Task 6's
        // deliberate-scoping note) — the type carries them since it's frozen/shared.
        response_format: ResponseFormat::default(),
        ext: ProviderExt::None,
        extra: BTreeMap::new(),
        policy: RequestPolicy::Error,
    };

    let body = encode_openai_chat(&req);

    insta::assert_json_snapshot!("openai_chat_encode__basic_tool_call_request", body);
}

#[test]
fn encodes_tool_result_only_message() {
    // Test that a message containing only ToolResult blocks (no text, no tool calls)
    // produces exactly one message (the tool message), with no spurious empty role message.
    let req = ChatRequest {
        model: ModelId("gpt-5.4".into()),
        system: vec![],
        messages: vec![
            Message {
                role: Role::User,
                content: vec![ContentBlock::Text { text: "What's the time?".into(), cache: None, citations: vec![] }],
            },
            Message {
                role: Role::Assistant,
                content: vec![ContentBlock::ToolUse {
                    id: ToolCallId("call_42".into()),
                    id_origin: IdOrigin::Provider,
                    name: "get_time".into(),
                    input: json!({}),
                    cache: None,
                }],
            },
            Message {
                role: Role::User,
                content: vec![ContentBlock::ToolResult {
                    tool_use_id: ToolCallId("call_42".into()),
                    content: vec![ToolResultPart { text: "It is 3:45 PM".into() }],
                    is_error: false,
                    cache: None,
                }],
            },
        ],
        tools: vec![],
        tool_choice: ToolChoice::None,
        params: Params { temperature: None, top_p: None, max_output_tokens: None, stop: None },
        reasoning: ReasoningRequest::default(),
        response_format: ResponseFormat::default(),
        ext: ProviderExt::None,
        extra: BTreeMap::new(),
        policy: RequestPolicy::Error,
    };

    let body = encode_openai_chat(&req);

    insta::assert_json_snapshot!("openai_chat_encode__tool_result_only_message", body);
}
