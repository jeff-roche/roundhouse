use roundhouse_engine::compact::{execute_compact, CompactInput, CompactStrategy};
use roundhouse_engine::test_support::{
    fake_provider_summarizing_to, sample_ctx, working_context_with_turns_and_pinned_memory,
};
use roundhouse_engine::TokenBudget;

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
    let new_ctx = working.materialize(output.new_context_state);
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
    let new_ctx = working.materialize(output.new_context_state);
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
