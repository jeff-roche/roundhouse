//! Shared request fixtures for `golden_bedrock_converse.rs` and
//! `conformance_bedrock_converse.rs` (REALITY-CORRECTIONS §12e): included by
//! `#[path]` into both integration-test binaries, so there is exactly one
//! definition of each fixture request.
#![allow(dead_code)]

use roundhouse_provider::{
    tool_def_from_schema, ChatRequest, ContentBlock, Message, ModelId, Params, ProviderExt,
    ReasoningIntent, ReasoningRequest, RequestPolicy, ResponseFormat, Role, ToolChoice,
};
use std::collections::BTreeMap;

// A deliberately field-less tool-params struct (matches
// `openai_responses_fixtures.rs`'s identical precedent), so the
// `schemars`-generated `input_schema` has the smallest possible key
// surface. A plain `//` comment (not `///`), so schemars emits no
// root-level `description` key from a struct doc comment either.
#[derive(schemars::JsonSchema)]
pub struct NoParams {}

pub fn base_request(messages: Vec<Message>) -> ChatRequest {
    ChatRequest {
        model: ModelId("meta.llama4-70b-instruct-v1:0".into()),
        system: vec![],
        messages,
        tools: vec![],
        tool_choice: ToolChoice::Auto,
        params: Params::default(),
        reasoning: ReasoningRequest::default(),
        response_format: ResponseFormat::default(),
        ext: ProviderExt::None,
        extra: BTreeMap::new(),
        policy: RequestPolicy::Drop,
    }
}

pub fn user_text(text: &str) -> Message {
    Message {
        role: Role::User,
        content: vec![ContentBlock::Text {
            text: text.to_string(),
            cache: None,
            citations: vec![],
        }],
    }
}

pub fn single_turn_text() -> ChatRequest {
    base_request(vec![user_text("What is 2+2?")])
}

pub fn forced_tool_choice() -> ChatRequest {
    ChatRequest {
        tools: vec![tool_def_from_schema::<NoParams>(
            "get_weather",
            "Get the current weather",
        )],
        tool_choice: ToolChoice::Named("get_weather".into()),
        ..base_request(vec![user_text("What's the weather in Tokyo?")])
    }
}

pub fn parallel_tool_calls() -> ChatRequest {
    ChatRequest {
        tools: vec![
            tool_def_from_schema::<NoParams>("get_weather", "Get the current weather"),
            tool_def_from_schema::<NoParams>("get_time", "Get the current time"),
        ],
        tool_choice: ToolChoice::Auto,
        ..base_request(vec![user_text("Weather and time in Tokyo?")])
    }
}

/// `meta.llama4` has no `[[model]]` entry in the profile at all, so this
/// request's `encode` must fail with `Unsupported` -- there is no way to
/// build a wire body for it. Used by the golden test that proves the
/// rejection is profile-justified, not by any cassette (a cassette exercises
/// `stream_chat`, which would never even reach the transport for this
/// request).
pub fn reasoning_on() -> ChatRequest {
    ChatRequest {
        reasoning: ReasoningRequest {
            intent: Some(ReasoningIntent::High),
        },
        ..base_request(vec![user_text("hi")])
    }
}
