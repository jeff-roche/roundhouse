//! Test helpers shared by `roundhouse-engine` integration tests and later tasks.
//!
//! This module is `pub` so downstream crates and future phase tasks can build
//! deterministic, offline test setups without reimplementing fake providers.

use crate::working_context::WorkingContext;
use futures::future::BoxFuture;
use futures::stream;
use roundhouse_provider::{
    BlockDelta, BlockKind, Capabilities, ChatRequest, ChatStream, ContentBlock, HttpRequest,
    HttpResponseStream, HttpTransport, Message, MessageRole, ModelId, ModelInfo, Plan, Provider,
    ProviderError, RequestCtx, StreamEvent, TokenCount, TransportError,
};
use std::sync::{Arc, Mutex};

/// Builds a `RequestCtx` backed by a `NoopTransport`, matching the real test
/// pattern in `tests/chat_infer_tree.rs`.
pub fn sample_ctx() -> RequestCtx {
    struct NoopTransport;

    impl HttpTransport for NoopTransport {
        fn send<'a>(
            &'a self,
            _req: HttpRequest,
        ) -> BoxFuture<'a, Result<HttpResponseStream, TransportError>> {
            unreachable!("fake provider never calls the transport directly")
        }
    }

    RequestCtx {
        trace_id: None,
        transport: Arc::new(NoopTransport),
        api_key: "test".into(),
        credentials: None,
    }
}

/// Creates a `WorkingContext` with `turns` synthetic user/assistant pairs and a
/// single pinned memory line.
pub fn working_context_with_turns_and_pinned_memory(
    turns: usize,
    pinned_line: &str,
) -> WorkingContext {
    let mut messages = Vec::with_capacity(turns * 2);
    for i in 0..turns {
        messages.push(Message {
            role: MessageRole::User,
            content: vec![ContentBlock::Text {
                text: format!("user turn {i}"),
                cache: None,
                citations: vec![],
            }],
        });
        messages.push(Message {
            role: MessageRole::Assistant,
            content: vec![ContentBlock::Text {
                text: format!("assistant turn {i}"),
                cache: None,
                citations: vec![],
            }],
        });
    }
    WorkingContext::new(messages, vec![pinned_line.to_string()])
}

/// Returns a fake provider that captures the last summarization request it
/// receives and emits the given `summary` as the only text block.
pub fn fake_provider_summarizing_to(summary: &str) -> FakeProvider {
    FakeProvider {
        summary: summary.to_string(),
        last_request: Arc::new(Mutex::new(None)),
        events: Arc::new(Mutex::new(None)),
    }
}

/// Returns a fake provider that captures the last summarization request and
/// emits the provided stream events.
pub fn fake_provider_streaming(events: Vec<StreamEvent>) -> FakeProvider {
    FakeProvider {
        summary: String::new(),
        last_request: Arc::new(Mutex::new(None)),
        events: Arc::new(Mutex::new(Some(events))),
    }
}

/// Fake `Provider` for compaction tests.
pub struct FakeProvider {
    summary: String,
    last_request: Arc<Mutex<Option<ChatRequest>>>,
    events: Arc<Mutex<Option<Vec<StreamEvent>>>>,
}

impl FakeProvider {
    /// Returns the most recent `ChatRequest` passed to `stream_chat`, if any.
    pub fn last_request(&self) -> Option<ChatRequest> {
        self.last_request.lock().unwrap().clone()
    }
}

impl Provider for FakeProvider {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        Capabilities::default()
    }

    fn resolve(&self, _req: &ChatRequest) -> Result<Plan, ProviderError> {
        Ok(Plan {
            endpoint: "fake".into(),
        })
    }

    fn stream_chat<'a>(
        &'a self,
        req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> roundhouse_provider::BoxFut<'a, Result<ChatStream, ProviderError>> {
        *self.last_request.lock().unwrap() = Some(req.clone());

        let events = self.events.lock().unwrap().take();
        let summary = self.summary.clone();
        Box::pin(async move {
            let events = events.unwrap_or_else(|| {
                vec![
                    StreamEvent::BlockStart {
                        index: 0,
                        kind: BlockKind::Text,
                    },
                    StreamEvent::BlockDelta {
                        index: 0,
                        delta: BlockDelta::Text(summary),
                    },
                    StreamEvent::BlockStop { index: 0 },
                    StreamEvent::MessageStop,
                ]
            });
            Ok(ChatStream(Box::pin(stream::iter(events))))
        })
    }

    fn count_tokens<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> roundhouse_provider::BoxFut<'a, Result<TokenCount, ProviderError>> {
        Box::pin(async { Ok(TokenCount::default()) })
    }

    fn list_models<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
    ) -> roundhouse_provider::BoxFut<'a, Result<Vec<ModelInfo>, ProviderError>> {
        Box::pin(async { Ok(vec![]) })
    }
}
