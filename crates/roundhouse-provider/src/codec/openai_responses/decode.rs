//! Decodes an Open Responses `/v1/responses` streaming response body
//! (Server-Sent Events) into normalized [`StreamEvent`]s. Verified against
//! the real spec before being written -- see
//! `docs/decisions/2026-08-27-open-responses-spec-verification.md`.
//!
//! Spec-verification finding: unlike the brief's sketch (which assumed every
//! event carries a flat top-level `item_id`), the real schemas split into two
//! shapes: `response.output_item.added`/`response.output_item.done` carry
//! `{output_index, item}` with the id nested at `item.id` (and `item.type`
//! determining the block kind); the three delta events
//! (`response.output_text.delta`, `response.function_call_arguments.delta`,
//! `response.reasoning_summary.delta`) carry a genuine top-level `item_id`.
//! Both shapes are funneled through the same [`DeltaKeyer::index_for`] call so
//! downstream code sees one normalized `index: u32` regardless of which shape
//! produced it (REALITY-CORRECTIONS §14e).
//!
//! `FunctionCall`'s real shape also separates `id` (the item's stream
//! identity, used for keying) from `call_id` (the correlation token a later
//! `function_call_output` must reference) -- `BlockKind::ToolUse.provider_id`
//! is sourced from `call_id`, falling back to `id` if `call_id` is absent.

use bytes::Bytes;
use futures::{Stream, StreamExt};
use serde_json::Value;
use sse_stream::SseStream;

use crate::stream_event::{BlockDelta, BlockKind, DeltaKeyer, StreamEvent};
use crate::TransportError;

/// Decodes an Open Responses SSE response body into normalized
/// [`StreamEvent`]s. Malformed or unrecognized frames are skipped rather than
/// treated as fatal, matching the precedent both existing codecs in this
/// crate already establish.
pub async fn decode_openai_responses_stream(
    body: impl Stream<Item = Result<Bytes, TransportError>> + Send + Unpin,
) -> Vec<StreamEvent> {
    let mut sse = SseStream::from_bytes_stream(body);
    let mut keyer = DeltaKeyer::new();
    let mut events = Vec::new();

    while let Some(frame) = sse.next().await {
        let Ok(frame) = frame else { continue };
        // SSE keep-alive/comment frames carry no `data` field at all -- not
        // an error, just skip and wait for the next frame.
        let Some(data) = frame.data else { continue };
        let data = data.trim();
        if data.is_empty() {
            continue;
        }
        events.extend(decode_stream_event(data, &mut keyer));
    }

    events
}

/// Decodes one `data: {...}` frame's JSON payload into zero, one, or two
/// normalized [`StreamEvent`]s (`response.completed` carries both a usage
/// figure and the terminal `MessageStop`). Returns an empty `Vec` for
/// malformed JSON, a payload with no `type` field, or a `type` this codec
/// does not recognize -- never panics on unexpected wire shapes.
///
/// `keyer` maps this event's provider-native item id onto a stable `index:
/// u32` via [`DeltaKeyer::index_for`] (REALITY-CORRECTIONS §14e) -- callers
/// share one `DeltaKeyer` across every frame of a single stream.
pub fn decode_stream_event(raw: &str, keyer: &mut DeltaKeyer) -> Vec<StreamEvent> {
    let Ok(payload) = serde_json::from_str::<Value>(raw) else {
        return Vec::new();
    };
    let Some(event_type) = payload.get("type").and_then(Value::as_str) else {
        return Vec::new();
    };

    match event_type {
        "response.output_item.added" => decode_output_item_added(&payload, keyer)
            .into_iter()
            .collect(),
        "response.output_text.delta" => decode_item_delta(&payload, keyer, BlockDelta::Text)
            .into_iter()
            .collect(),
        "response.function_call_arguments.delta" => {
            decode_item_delta(&payload, keyer, BlockDelta::ToolArgsFragment)
                .into_iter()
                .collect()
        }
        "response.reasoning_summary.delta" => {
            decode_item_delta(&payload, keyer, |text| BlockDelta::Thinking {
                text,
                signature: None,
            })
            .into_iter()
            .collect()
        }
        "response.output_item.done" => decode_output_item_done(&payload, keyer)
            .into_iter()
            .collect(),
        "response.completed" => decode_completed(&payload),
        _ => Vec::new(),
    }
}

/// `response.output_item.added`: the item's id and kind live nested under
/// `item.{id,type}`, not at the event's top level (spec-verification
/// finding).
fn decode_output_item_added(payload: &Value, keyer: &mut DeltaKeyer) -> Option<StreamEvent> {
    let item = payload.get("item")?;
    let item_id = item.get("id").and_then(Value::as_str)?;
    let index = keyer.index_for(item_id);
    let kind = match item.get("type").and_then(Value::as_str)? {
        "message" => BlockKind::Text,
        "function_call" => BlockKind::ToolUse {
            name: item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            // `call_id` (not `id`) is the token a `function_call_output` must
            // echo back -- see this module's doc comment.
            provider_id: Some(
                item.get("call_id")
                    .and_then(Value::as_str)
                    .unwrap_or(item_id)
                    .to_string(),
            ),
        },
        "reasoning" => BlockKind::Thinking,
        _ => return None,
    };
    Some(StreamEvent::BlockStart { index, kind })
}

/// `response.output_item.done`: same nested-`item.id` shape as `added`.
fn decode_output_item_done(payload: &Value, keyer: &mut DeltaKeyer) -> Option<StreamEvent> {
    let item = payload.get("item")?;
    let item_id = item.get("id").and_then(Value::as_str)?;
    let index = keyer.index_for(item_id);
    Some(StreamEvent::BlockStop { index })
}

/// The three delta event types share one shape: a top-level `item_id` and a
/// `delta` string, differing only in which `BlockDelta` variant the string
/// becomes.
fn decode_item_delta(
    payload: &Value,
    keyer: &mut DeltaKeyer,
    to_delta: impl FnOnce(String) -> BlockDelta,
) -> Option<StreamEvent> {
    let item_id = payload.get("item_id").and_then(Value::as_str)?;
    let index = keyer.index_for(item_id);
    let text = payload.get("delta").and_then(Value::as_str)?.to_string();
    Some(StreamEvent::BlockDelta {
        index,
        delta: to_delta(text),
    })
}

/// `response.completed` carries the final `response` snapshot, whose `usage`
/// field (when present) becomes a `UsageDelta`; the event is always terminal,
/// so a `MessageStop` follows regardless of whether usage was present.
fn decode_completed(payload: &Value) -> Vec<StreamEvent> {
    let mut events = Vec::new();
    if let Some(usage_json) = payload.pointer("/response/usage") {
        let usage = decode_usage(usage_json);
        events.push(StreamEvent::UsageDelta {
            input_tokens: Some(usage.input_tokens),
            output_tokens: Some(usage.output_tokens),
            cache_read_tokens: Some(usage.cache_read_tokens),
        });
    }
    events.push(StreamEvent::MessageStop);
    events
}

/// Normalizes an Open Responses `Usage` object into `roundhouse_core::Usage`.
///
/// Spec-verification finding (§9.3's "#1 source of silent cost bugs"): OpenAI-
/// family `input_tokens` already reports the TOTAL prompt size, with cache
/// reads broken out separately under `input_tokens_details.cached_tokens` --
/// unlike Anthropic, whose `input_tokens` excludes cache reads and needs them
/// added back (see `anthropic_messages::decode::normalize_anthropic_usage`).
/// This decoder just relabels the nested shape into the flat `Usage` struct,
/// confirmed byte-for-byte against the fetched `Usage` schema.
pub fn decode_usage(data: &Value) -> roundhouse_core::Usage {
    let input_tokens = data
        .get("input_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let output_tokens = data
        .get("output_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let cache_read_tokens = data
        .pointer("/input_tokens_details/cached_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    roundhouse_core::Usage {
        input_tokens,
        output_tokens,
        cache_read_tokens,
    }
}

#[cfg(test)]
mod usage_tests {
    use super::decode_usage;

    #[test]
    fn decode_usage_satisfies_the_input_tokens_invariant() {
        // Real Open Responses usage shape (confirmed against the fetched
        // 2026-04-24 `Usage` schema): `input_tokens` is the flat total that
        // ALREADY includes `input_tokens_details.cached_tokens`.
        let usage_json = serde_json::json!({
            "input_tokens": 1200,
            "output_tokens": 340,
            "total_tokens": 1540,
            "input_tokens_details": { "cached_tokens": 800 },
            "output_tokens_details": { "reasoning_tokens": 0 },
        });
        let usage = decode_usage(&usage_json);
        assert_eq!(usage.input_tokens, 1200);
        assert_eq!(usage.output_tokens, 340);
        assert_eq!(usage.cache_read_tokens, 800);
        assert!(
            usage.input_tokens >= usage.cache_read_tokens,
            "§9.3 conformance invariant: input_tokens must be total tokens presented, including cache reads"
        );
    }

    #[test]
    fn decode_usage_defaults_missing_fields_to_zero_rather_than_panicking() {
        let usage = decode_usage(&serde_json::json!({}));
        assert_eq!(usage.input_tokens, 0);
        assert_eq!(usage.output_tokens, 0);
        assert_eq!(usage.cache_read_tokens, 0);
    }
}
