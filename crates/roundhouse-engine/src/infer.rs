//! Folds a provider's normalized `StreamEvent` stream into final `ContentBlock`s
//! (§9.3's narrow waist). Tool-argument JSON fragments are concatenated and
//! parsed exactly once, at `BlockStop` — never incrementally, per §9.3's
//! normative streaming rule.

use futures::StreamExt;
use roundhouse_provider::{
    BlockDelta, BlockKind, ChatStream, ContentBlock, IdOrigin, Signature, StreamEvent, ToolCallId,
};
use std::collections::BTreeMap;

/// Folds a provider's normalized `StreamEvent` stream into final `ContentBlock`s.
///
/// A `Thinking` block folds to `ContentBlock::Thinking`, never `ContentBlock::Text` —
/// its text and signature are tracked in their own map, separate from plain `Text`
/// deltas, so a provider that requires its own prior signed thinking block to be
/// echoed back verbatim on the next turn (e.g. Anthropic extended thinking) gets a
/// real `ContentBlock::Thinking` with the signature intact, not a `Text` block with
/// the signature silently dropped.
///
/// **Corrected 2026-08-28 (audit finding 1).** An earlier draft accumulated `Thinking`
/// deltas into the *same* `text_by_index` map as plain `Text` deltas, and the final
/// mapping had no `BlockKind::Thinking` arm at all — every non-tool-use block,
/// including a genuine thinking block, fell through to a catch-all and was emitted as
/// `ContentBlock::Text`, discarding the block's kind and silently dropping its
/// signature. That is exactly §1.1 bug #1 ("bricked sessions on resume") reintroduced
/// structurally: a provider that requires its own prior signed thinking block to be
/// echoed back verbatim on the next turn (Anthropic extended thinking) would receive a
/// plain `Text` block with no signature instead, and resuming the session would fail
/// or be rejected by the provider. This function tracks thinking text and signature in
/// their own map (`thinking_by_index`), keyed separately from plain text, and the
/// final mapping below has an explicit `BlockKind::Thinking` arm — plus an exhaustive
/// (not catch-all) `BlockKind::Text`/`None` arm, so a future `BlockKind` variant that
/// isn't explicitly handled here fails to compile instead of silently falling through
/// to `ContentBlock::Text` the same way.
pub async fn fold_stream_to_blocks(mut stream: ChatStream) -> Vec<ContentBlock> {
    let mut text_by_index: BTreeMap<u32, String> = BTreeMap::new();
    let mut thinking_by_index: BTreeMap<u32, (String, Option<String>)> = BTreeMap::new();
    let mut tool_args_by_index: BTreeMap<u32, String> = BTreeMap::new();
    let mut tool_meta_by_index: BTreeMap<u32, (String, Option<String>)> = BTreeMap::new();
    let mut order: Vec<u32> = Vec::new();
    let mut kinds: BTreeMap<u32, BlockKind> = BTreeMap::new();

    while let Some(event) = stream.next().await {
        match event {
            StreamEvent::BlockStart { index, kind } => {
                order.push(index);
                if let BlockKind::ToolUse { name, provider_id } = &kind {
                    tool_meta_by_index.insert(index, (name.clone(), provider_id.clone()));
                }
                kinds.insert(index, kind);
            }
            StreamEvent::BlockDelta { index, delta } => match delta {
                BlockDelta::Text(t) => *text_by_index.entry(index).or_default() += &t,
                BlockDelta::ToolArgsFragment(f) => *tool_args_by_index.entry(index).or_default() += &f,
                BlockDelta::Thinking { text, signature } => {
                    let entry = thinking_by_index.entry(index).or_default();
                    entry.0 += &text;
                    // A signature fragment arrives as its own zero-text delta (Task
                    // 10's decoder) after the thinking text is complete; once set,
                    // later `None` fragments must never clobber it.
                    if signature.is_some() {
                        entry.1 = signature;
                    }
                }
            },
            StreamEvent::BlockStop { .. } => {}
            StreamEvent::UsageDelta { .. } => {}
            StreamEvent::MessageStop => break,
        }
    }

    order
        .into_iter()
        .map(|index| match kinds.get(&index) {
            Some(BlockKind::ToolUse { .. }) => {
                let (name, provider_id) = tool_meta_by_index.remove(&index).unwrap_or_default();
                let raw_args = tool_args_by_index.remove(&index).unwrap_or_default();
                let input = if raw_args.is_empty() {
                    serde_json::json!({})
                } else {
                    serde_json::from_str(&raw_args).unwrap_or(serde_json::Value::Null)
                };
                // A provider-issued id gets `IdOrigin::Provider`; a locally synthesized
                // one (the provider never assigned a tool-call id) gets
                // `IdOrigin::Synthesized`, so downstream consumers can tell the two
                // apart instead of both being reported as provider-issued.
                let (id, id_origin) = match provider_id {
                    Some(p) => (ToolCallId(p), IdOrigin::Provider),
                    None => (ToolCallId(format!("synth_{index}")), IdOrigin::Synthesized),
                };
                ContentBlock::ToolUse { id, id_origin, name, input, cache: None }
            }
            Some(BlockKind::Thinking) => {
                let (text, signature) = thinking_by_index.remove(&index).unwrap_or_default();
                ContentBlock::Thinking { text, signature: signature.map(Signature), redacted: false }
            }
            // Exhaustive, not a catch-all: `BlockKind` isn't `#[non_exhaustive]` today,
            // but a future variant added here must fail to compile instead of silently
            // downgrading to `ContentBlock::Text` the way `Thinking` used to (see this
            // function's doc comment, audit finding 1).
            Some(BlockKind::Text) | None => ContentBlock::Text {
                text: text_by_index.remove(&index).unwrap_or_default(),
                cache: None,
                citations: vec![],
            },
        })
        .collect()
}
