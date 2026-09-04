//! Shared request fixtures for `conformance_openai_responses_batch.rs`
//! (REALITY-CORRECTIONS §12e: this task's `git add` list references this
//! module but never lists the file itself -- created here, mirroring
//! `anthropic_messages_batch_fixtures.rs`'s identical one-definition-per-
//! fixture pattern).
#![allow(dead_code)]

use roundhouse_provider::{
    ChatRequest, ContentBlock, Message, ModelId, Params, ProviderExt, ReasoningRequest,
    RequestPolicy, ResponseFormat, Role, ToolChoice,
};
use std::collections::BTreeMap;

/// A single user turn with a plain text prompt, no tools, no reasoning --
/// `model_id` is passed in by the caller so each profile subject can label
/// its own case with a model id that matches that profile's own `[[model]]`
/// glob (every profile in this batch declares `match = ["*"]`, so any
/// non-empty id works, but a vendor-shaped one keeps the fixture readable).
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
