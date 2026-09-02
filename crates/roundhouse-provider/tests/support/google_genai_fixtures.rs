//! Shared request fixtures for `golden_google_genai.rs` and
//! `conformance_google_genai.rs` (REALITY-CORRECTIONS §12e), included by
//! `#[path]` into both integration-test binaries -- one definition of each
//! fixture request. Mirrors `openai_responses_fixtures.rs`.
#![allow(dead_code)]

use roundhouse_provider::{
    tool_def_from_schema, ChatRequest, ContentBlock, Message, ModelId, Params, ProviderExt,
    ReasoningIntent, ReasoningRequest, RequestPolicy, ResponseFormat, Role, ToolChoice,
};
use std::collections::BTreeMap;

// A field-less tool-params struct (see `openai_responses_fixtures.rs`'s
// identical rationale: a plain `//` comment so `schemars` emits no root
// `description` key either).
#[derive(schemars::JsonSchema)]
pub struct NoParams {}

pub fn base_request(messages: Vec<Message>) -> ChatRequest {
    ChatRequest {
        model: ModelId("gemini-3.0-pro".into()),
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

pub fn reasoning_on() -> ChatRequest {
    ChatRequest {
        reasoning: ReasoningRequest {
            intent: Some(ReasoningIntent::High),
        },
        ..base_request(vec![user_text("Prove sqrt(2) is irrational.")])
    }
}
