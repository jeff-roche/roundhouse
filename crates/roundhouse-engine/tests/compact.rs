use roundhouse_engine::compact::{execute_compact, CompactError, CompactInput, CompactStrategy};
use roundhouse_engine::test_support::{
    fake_provider_streaming, fake_provider_summarizing_to, sample_ctx,
    working_context_with_turns_and_pinned_memory,
};
use roundhouse_engine::TokenBudget;
use roundhouse_provider::{BlockDelta, BlockKind, ProviderError, StreamEvent};

#[tokio::test]
async fn compaction_respects_budget_and_preserves_pinned_memory_verbatim() {
    let working =
        working_context_with_turns_and_pinned_memory(50, "PINNED: never summarize this line");
    let provider = fake_provider_summarizing_to("condensed summary of 50 turns");

    let output = execute_compact(
        &provider,
        &sample_ctx(),
        &working,
        CompactInput {
            strategy: CompactStrategy::SummarizeOldest,
            target_budget: TokenBudget(2_000),
        },
    )
    .await
    .unwrap();

    assert_eq!(output.summary, "condensed summary of 50 turns");
    let new_ctx = working
        .materialize(output.new_context_state)
        .expect("state exists");
    assert!(
        new_ctx.token_count() <= 2_000,
        "compacted context must fit target budget"
    );
    assert!(
        new_ctx
            .render()
            .contains("PINNED: never summarize this line"),
        "pinned memory blocks survive compaction verbatim (§15.4)"
    );
}

#[tokio::test]
async fn summarize_all_uses_same_flow() {
    let working = working_context_with_turns_and_pinned_memory(10, "PINNED: keep");
    let provider = fake_provider_summarizing_to("all turns summary");

    let output = execute_compact(
        &provider,
        &sample_ctx(),
        &working,
        CompactInput {
            strategy: CompactStrategy::SummarizeAll,
            target_budget: TokenBudget(1_000),
        },
    )
    .await
    .unwrap();

    assert_eq!(output.summary, "all turns summary");
    let new_ctx = working.materialize(output.new_context_state).unwrap();
    assert!(new_ctx.render().contains("PINNED: keep"));
}

#[tokio::test]
async fn provider_request_excludes_pinned_memory() {
    let pinned = "SECRET PINNED LINE";
    let working = working_context_with_turns_and_pinned_memory(5, pinned);
    let provider = fake_provider_summarizing_to("summary");

    let _ = execute_compact(
        &provider,
        &sample_ctx(),
        &working,
        CompactInput {
            strategy: CompactStrategy::SummarizeOldest,
            target_budget: TokenBudget(1_000),
        },
    )
    .await
    .unwrap();

    let req = provider
        .last_request()
        .expect("provider received a request");
    let req_json = serde_json::to_string(&req).unwrap();
    assert!(
        !req_json.contains(pinned),
        "pinned memory must not appear in the summarization request"
    );
}

#[tokio::test]
async fn stream_without_message_stop_is_interrupted() {
    let working = working_context_with_turns_and_pinned_memory(3, "PINNED: keep");
    let provider = fake_provider_streaming(vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::Text,
        },
        StreamEvent::BlockDelta {
            index: 0,
            delta: BlockDelta::Text("partial text".into()),
        },
        StreamEvent::BlockStop { index: 0 },
    ]);

    let err = execute_compact(
        &provider,
        &sample_ctx(),
        &working,
        CompactInput {
            strategy: CompactStrategy::SummarizeAll,
            target_budget: TokenBudget(1_000),
        },
    )
    .await
    .unwrap_err();

    match err {
        CompactError::Provider(ProviderError::StreamInterrupted { partial }) => {
            assert_eq!(partial, "partial text")
        }
        other => panic!("expected StreamInterrupted, got {other:?}"),
    }
}

#[tokio::test]
async fn stream_with_no_text_is_interrupted() {
    let working = working_context_with_turns_and_pinned_memory(3, "PINNED: keep");
    let provider = fake_provider_streaming(vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::Text,
        },
        StreamEvent::BlockStop { index: 0 },
        StreamEvent::MessageStop,
    ]);

    let err = execute_compact(
        &provider,
        &sample_ctx(),
        &working,
        CompactInput {
            strategy: CompactStrategy::SummarizeAll,
            target_budget: TokenBudget(1_000),
        },
    )
    .await
    .unwrap_err();

    assert!(
        matches!(
            err,
            CompactError::Provider(ProviderError::StreamInterrupted { .. })
        ),
        "expected StreamInterrupted for empty stream, got {err:?}"
    );
}

#[tokio::test]
async fn over_budget_summary_is_rejected() {
    let working = working_context_with_turns_and_pinned_memory(3, "PINNED: keep");
    // 40 bytes of summary + rendering overhead easily exceeds a budget of 5 tokens.
    let provider = fake_provider_summarizing_to("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let err = execute_compact(
        &provider,
        &sample_ctx(),
        &working,
        CompactInput {
            strategy: CompactStrategy::SummarizeAll,
            target_budget: TokenBudget(5),
        },
    )
    .await
    .unwrap_err();

    match err {
        CompactError::BudgetExceeded { budget, actual } => {
            assert_eq!(budget, 5);
            assert!(
                actual > 5,
                "actual token count {actual} should exceed budget"
            );
        }
        other => panic!("expected BudgetExceeded, got {other:?}"),
    }
}

#[tokio::test]
async fn over_budget_compaction_leaves_original_turns_intact() {
    let working = working_context_with_turns_and_pinned_memory(5, "PINNED: keep");
    let provider = fake_provider_summarizing_to("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let err = execute_compact(
        &provider,
        &sample_ctx(),
        &working,
        CompactInput {
            strategy: CompactStrategy::SummarizeAll,
            target_budget: TokenBudget(5),
        },
    )
    .await
    .unwrap_err();

    assert!(
        matches!(
            err,
            CompactError::BudgetExceeded {
                budget: 5,
                actual: _,
            }
        ),
        "expected BudgetExceeded, got {err:?}"
    );

    // The original conversation history must survive the rejected compaction.
    let (turns, pinned) = working.split_pinned();
    assert_eq!(turns.len(), 10, "all 5 user/assistant pairs preserved");
    assert_eq!(pinned, vec!["PINNED: keep".to_string()]);
    let rendered = format!("{:?}", turns);
    assert!(
        rendered.contains("user turn 0"),
        "pre-compaction history text still present"
    );
}
