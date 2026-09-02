//! Test fixtures shared by this crate's own self-test
//! (`tests/self_test.rs`) — fake `ChatStream`s and a minimal
//! [`crate::ConformanceCase`] a fake `Provider` can be run against without
//! ever touching a cassette's actual bytes.

use roundhouse_provider::{
    BlockDelta, BlockKind, ChatRequest, ChatStream, ContentBlock, Message, MessageRole, ModelId,
    Params, ProviderExt, ReasoningRequest, RequestPolicy, ResponseFormat, StreamEvent, ToolChoice,
};
use std::collections::BTreeMap;

use crate::mask::SerializeOnlyMask;
use crate::ConformanceCase;

/// A `ChatStream` emitting one well-formed text block and usage figures
/// that satisfy `input_tokens >= cache_read_tokens` (§9.3's invariant).
pub fn good_stream() -> ChatStream {
    ChatStream(Box::pin(futures::stream::iter(text_block_events(
        /* input_tokens */ 10, /* cache_read_tokens */ 2,
    ))))
}

/// The same content-block shape as [`good_stream`], but with
/// `input_tokens < cache_read_tokens` — a deliberate usage-invariant
/// violation for `tests/self_test.rs`'s `BrokenSubject` to be caught by.
pub fn broken_usage_stream() -> ChatStream {
    ChatStream(Box::pin(futures::stream::iter(text_block_events(
        /* input_tokens */ 1, /* cache_read_tokens */ 2,
    ))))
}

fn text_block_events(input_tokens: u64, cache_read_tokens: u64) -> Vec<StreamEvent> {
    vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::Text,
        },
        StreamEvent::BlockDelta {
            index: 0,
            delta: BlockDelta::Text("hello ".into()),
        },
        StreamEvent::BlockDelta {
            index: 0,
            delta: BlockDelta::Text("world".into()),
        },
        StreamEvent::BlockStop { index: 0 },
        StreamEvent::UsageDelta {
            input_tokens: Some(input_tokens),
            output_tokens: Some(5),
            cache_read_tokens: Some(cache_read_tokens),
        },
        StreamEvent::MessageStop,
    ]
}

/// A minimal one-message `ChatRequest`: a single user `Text` block.
pub fn simple_request() -> ChatRequest {
    ChatRequest {
        model: ModelId("conformance-test-model".into()),
        system: vec![],
        messages: vec![Message {
            role: MessageRole::User,
            content: vec![ContentBlock::Text {
                text: "hi".into(),
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
        policy: RequestPolicy::Error,
    }
}

/// The cassette this crate's own self-test replays. Its bytes are never
/// actually read by the self-test's fake providers (they return a
/// hardcoded stream regardless of `ctx.transport`), but
/// `checks::check_fold_determinism` always loads a real cassette file en
/// route to building each replay's `RequestCtx`, so a valid one must exist
/// on disk.
fn simple_cassette_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/cassettes/simple.cassette")
}

/// A single [`ConformanceCase`] built around [`simple_request`], with the
/// given mask and no declared loss events.
pub fn simple_case(mask: SerializeOnlyMask) -> ConformanceCase {
    ConformanceCase {
        name: "simple",
        request: simple_request(),
        cassette_path: simple_cassette_path(),
        mask,
        declared_loss_events: Vec::new(),
    }
}
