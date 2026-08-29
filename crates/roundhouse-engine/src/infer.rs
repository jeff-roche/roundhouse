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
                ContentBlock::ToolUse {
                    id: ToolCallId(provider_id.unwrap_or_else(|| format!("synth_{index}"))),
                    id_origin: IdOrigin::Provider,
                    name,
                    input,
                    cache: None,
                }
            }
            Some(BlockKind::Thinking) => {
                let (text, signature) = thinking_by_index.remove(&index).unwrap_or_default();
                ContentBlock::Thinking { text, signature: signature.map(Signature), redacted: false }
            }
            _ => ContentBlock::Text {
                text: text_by_index.remove(&index).unwrap_or_default(),
                cache: None,
                citations: vec![],
            },
        })
        .collect()
}
