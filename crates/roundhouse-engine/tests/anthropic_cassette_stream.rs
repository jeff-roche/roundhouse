//! I7 (Phase 1 final review): no test previously crossed the codec↔engine seam —
//! every other test either hand-built `StreamEvent`s (`chat_infer_tree.rs`) or
//! stopped at the decoder (`roundhouse-provider/tests/anthropic_messages_decode.rs`).
//! That seam is exactly where audit-finding-1 lived (a thinking block's signature
//! silently dropped on fold), so this test runs a *real* SSE fixture through the
//! whole chain: `CassetteTransport` -> `AnthropicMessagesProvider::stream_chat`
//! (Task 9's encoder / Task 10's decoder) -> `run_chat_turn` (which calls
//! `fold_stream_to_blocks` internally) -> the returned `ContentBlock`s.

use roundhouse_core::{SessionId, TaskRunner};
use roundhouse_engine::run_chat_turn;
use roundhouse_provider::{
    AnthropicMessagesProvider, CassetteTransport, ChatRequest, ContentBlock, ModelId, Params,
    ProviderExt, ReasoningRequest, RequestCtx, RequestPolicy, ResponseFormat, ToolChoice,
};
use roundhouse_store::{open, spawn_writer};
use std::collections::BTreeMap;
use std::sync::Arc;

/// `TaskRunner::bootstrap()` panics if called more than once per process
/// (S-LOG-1's single-authority guarantee) — this test binary is one process.
static RUNNER: once_cell::sync::Lazy<TaskRunner> =
    once_cell::sync::Lazy::new(TaskRunner::bootstrap);

/// The exact fixture `roundhouse-provider`'s own decoder test
/// (`anthropic_messages_decode.rs`) uses to prove a thinking block's signature
/// survives decode — reused here to prove it also survives the *fold*.
fn thinking_cassette() -> Vec<u8> {
    include_bytes!("../../roundhouse-provider/tests/fixtures/anthropic_thinking.sse").to_vec()
}

fn sample_request() -> ChatRequest {
    ChatRequest {
        model: ModelId("claude-sonnet-5".into()),
        system: vec![],
        messages: vec![],
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

#[tokio::test]
async fn anthropic_thinking_cassette_folds_to_a_thinking_block_with_signature_intact() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let transport = Arc::new(CassetteTransport {
        status: 200,
        headers: vec![],
        body: thinking_cassette(),
        chunk_size: 0,
    });
    let ctx = RequestCtx {
        trace_id: None,
        transport,
        api_key: "test-key".into(),
        credentials: None,
    };

    let provider = AnthropicMessagesProvider::new();
    let session_id = SessionId::new();

    let (_chat_task_id, blocks) = run_chat_turn(
        &writer,
        &RUNNER,
        &provider,
        &ctx,
        session_id,
        sample_request(),
    )
    .await
    .expect("real SSE cassette must decode and fold without error");

    let thinking = blocks
        .iter()
        .find(|b| matches!(b, ContentBlock::Thinking { .. }))
        .expect("a ContentBlock::Thinking must come out the far end of decode -> fold");

    match thinking {
        ContentBlock::Thinking {
            text,
            signature,
            redacted,
        } => {
            assert_eq!(text, "Let me check the file.");
            assert_eq!(
                signature.as_ref().map(|s| s.0.as_str()),
                Some("sig-xyz"),
                "the thinking block's signature must survive decode -> fold byte-for-byte"
            );
            assert!(!redacted);
        }
        other => panic!("expected ContentBlock::Thinking, got {other:?}"),
    }

    // The fixture also carries a trailing text block ("Done.") after the
    // thinking block — confirms the fold processes the whole real stream,
    // not just the first block.
    assert!(
        blocks
            .iter()
            .any(|b| matches!(b, ContentBlock::Text { text, .. } if text == "Done.")),
        "expected the fixture's trailing text block to also come through: {blocks:?}"
    );
}
