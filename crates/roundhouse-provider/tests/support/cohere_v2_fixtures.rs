//! Shared request fixtures for `golden_cohere_v2.rs` and
//! `conformance_cohere_v2.rs` (REALITY-CORRECTIONS §12e), included by
//! `#[path]` into both integration-test binaries -- one definition of each
//! fixture request. Mirrors `google_genai_fixtures.rs`/`openai_responses_fixtures.rs`.
#![allow(dead_code)]

use roundhouse_provider::{
    tool_def_from_schema, ChatRequest, ContentBlock, Message, ModelId, Params, ProviderExt,
    ReasoningIntent, ReasoningRequest, RequestPolicy, ResponseFormat, Role, ToolChoice,
};
use std::collections::BTreeMap;

// A field-less tool-params struct (see `google_genai_fixtures.rs`'s identical
// rationale: a plain `//` comment so `schemars` emits no root `description`
// key either).
#[derive(schemars::JsonSchema)]
pub struct NoParams {}

pub fn base_request(messages: Vec<Message>) -> ChatRequest {
    ChatRequest {
        model: ModelId("command-a-03-2026".into()),
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
        // Cohere v2's `tool_choice` has no mechanism to force one SPECIFIC
        // named tool (verified: only `REQUIRED`/`NONE` are documented enum
        // values) -- `Required` is the honest wire-expressible shape here,
        // unlike the sibling codecs' `ToolChoice::Named` fixture.
        tool_choice: ToolChoice::Required,
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
        model: ModelId("command-a-reasoning-03-2026".into()),
        reasoning: ReasoningRequest {
            intent: Some(ReasoningIntent::High),
        },
        ..base_request(vec![user_text("Prove sqrt(2) is irrational.")])
    }
}
