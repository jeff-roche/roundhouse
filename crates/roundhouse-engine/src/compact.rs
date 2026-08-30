//! `compact` task kind — strategy + budget in, context state + summary out (Task 8).
//!
//! Drives a summarization provider call over the summarizable portion of a
//! `WorkingContext`, folds the streamed text response into a summary, and
//! commits a new context state that preserves pinned memory verbatim.

use futures::StreamExt;
use roundhouse_provider::{
    BlockDelta, ChatRequest, ChatStream, Message, ModelId, Params, Provider, ProviderError,
    ProviderExt, ReasoningRequest, RequestCtx, RequestPolicy, ResponseFormat, StreamEvent,
    SystemBlock, ToolChoice,
};
use std::collections::BTreeMap;
use thiserror::Error;

use crate::working_context::{ContextStateId, TokenBudget, WorkingContext};

/// How to summarize the summarizable portion of the working context.
#[derive(Debug, Clone)]
pub enum CompactStrategy {
    /// Summarize the oldest turns, keeping a retained window if any.
    SummarizeOldest,
    /// Summarize the entire summarizable history.
    SummarizeAll,
}

/// Input to `execute_compact`.
#[derive(Debug, Clone)]
pub struct CompactInput {
    pub strategy: CompactStrategy,
    pub target_budget: TokenBudget,
}

/// Output from a successful compaction.
#[derive(Debug, Clone)]
pub struct CompactOutput {
    pub new_context_state: ContextStateId,
    pub summary: String,
}

/// Errors that can occur during compaction.
#[derive(Debug, Error)]
pub enum CompactError {
    /// The provider failed to produce a summary.
    #[error("provider error: {0}")]
    Provider(#[from] ProviderError),
}

/// Executes a compaction: sends the summarizable conversation history to the
/// provider, folds the streamed text into a summary, commits a new context
/// state that preserves pinned memory verbatim, and rejects the result if it
/// exceeds the target budget.
pub async fn execute_compact(
    provider: &dyn Provider,
    ctx: &RequestCtx,
    working: &WorkingContext,
    input: CompactInput,
) -> Result<CompactOutput, CompactError> {
    let (summarizable, pinned) = working.split_pinned();
    let req = build_summarization_request(&summarizable, &input.strategy);

    let mut stream = provider
        .stream_chat(&req, ctx)
        .await
        .map_err(CompactError::Provider)?;

    let summary = fold_stream_text(&mut stream)
        .await
        .map_err(CompactError::Provider)?;
    let new_context_state = working.commit_compaction(&summary, pinned, input.target_budget);

    let rendered = working
        .materialize(new_context_state)
        .expect("state was just created by commit_compaction");
    if rendered.token_count() > input.target_budget.0 {
        return Err(CompactError::Provider(ProviderError::Unsupported(format!(
            "compaction exceeded target budget: {} > {}",
            rendered.token_count(),
            input.target_budget.0
        ))));
    }

    Ok(CompactOutput {
        new_context_state,
        summary,
    })
}

fn build_summarization_request(
    summarizable: &[Message],
    strategy: &CompactStrategy,
) -> ChatRequest {
    let system_text = match strategy {
        CompactStrategy::SummarizeOldest => {
            "Summarize the oldest portion of the following conversation, keeping key facts and decisions. Be concise."
        }
        CompactStrategy::SummarizeAll => {
            "Summarize the following conversation history, keeping key facts and decisions. Be concise."
        }
    };

    ChatRequest {
        model: ModelId("claude-sonnet-5".into()),
        system: vec![SystemBlock {
            text: system_text.into(),
            cache: None,
        }],
        messages: summarizable.to_vec(),
        tools: vec![],
        tool_choice: ToolChoice::Auto,
        params: Params::default(),
        reasoning: ReasoningRequest::default(),
        response_format: ResponseFormat::default(),
        ext: ProviderExt::None,
        extra: BTreeMap::new(),
        policy: RequestPolicy::Error,
    }
}

/// Folds a `ChatStream` into a single owned `String` from `BlockDelta::Text`
/// events, terminating at `MessageStop`.
///
/// Returns `Ok(summary)` only if `MessageStop` was observed and the folded text
/// is non-empty. Otherwise returns `Err(ProviderError::StreamInterrupted)` with
/// the partial text seen so far.
async fn fold_stream_text(stream: &mut ChatStream) -> Result<String, ProviderError> {
    let mut text = String::new();
    let mut saw_message_stop = false;
    while let Some(event) = stream.0.next().await {
        match event {
            StreamEvent::BlockDelta {
                delta: BlockDelta::Text(t),
                ..
            } => text.push_str(&t),
            StreamEvent::MessageStop => {
                saw_message_stop = true;
                break;
            }
            _ => {}
        }
    }

    if saw_message_stop && !text.is_empty() {
        Ok(text)
    } else {
        Err(ProviderError::StreamInterrupted { partial: text })
    }
}
