//! Shared request fixtures for `conformance_openai_chat_batch_a.rs`
//! (REALITY-CORRECTIONS §12e: the brief references this module in prose and
//! in its `git add` list but never lists the file itself -- created here,
//! mirroring `cohere_v2_fixtures.rs`'s/`google_genai_fixtures.rs`'s
//! identical one-definition-per-fixture pattern).
#![allow(dead_code)]

use roundhouse_provider::{
    ChatRequest, ContentBlock, Message, ModelId, Params, ProviderExt, ReasoningRequest,
    RequestPolicy, ResponseFormat, Role, ToolChoice,
};
use std::collections::BTreeMap;

/// A single user turn with a plain text prompt, no tools, no reasoning --
/// `model_id` is passed in by the caller so each profile subject can label
/// its own case with its own profile id (the openai-chat wire body has no
/// model-family-specific validation this codec enforces, so the exact
/// string doesn't matter for what gets exercised here).
pub fn single_turn_text(model_id: &str) -> ChatRequest {
    ChatRequest {
        model: ModelId(model_id.to_string()),
        system: vec![],
        messages: vec![Message {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "What is 2+2?".into(),
                cache: None,
                citations: vec![],
            }],
        }],
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
