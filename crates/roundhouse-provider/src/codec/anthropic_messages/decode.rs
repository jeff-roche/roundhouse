//! Decodes an Anthropic `/v1/messages` streaming response body (Server-Sent Events)
//! into normalized [`StreamEvent`]s, per §9.3's normative decode rules: Anthropic's wire
//! format already carries explicit block-boundary markers (`content_block_start`/
//! `content_block_stop`), so — unlike the OpenAI decoder — this decoder never synthesizes
//! them; it forwards the provider's own indices and ordering as-is. Thinking blocks carry
//! a `signature_delta` used to authenticate replayed thinking content on a later turn (see
//! `encode.rs`'s `ContentBlock::Thinking` handling), and usage accounting is split across
//! two separate events (`message_start` for input/cache tokens, `message_delta` for output
//! tokens) that this decoder combines into a single normalized [`StreamEvent::UsageDelta`].

use bytes::Bytes;
use futures::{Stream, StreamExt};
use serde_json::Value;
use sse_stream::SseStream;

use crate::stream_event::{BlockDelta, BlockKind, StreamEvent};
use crate::TransportError;

/// Normalizes Anthropic's `input_tokens` usage figure by adding back `cache_read_input_tokens`.
///
/// Anthropic reports `input_tokens` as the count of *freshly processed* prompt tokens,
/// excluding any tokens served from the prompt cache (`cache_read_input_tokens`) — unlike
/// most other providers, whose `input_tokens`/`prompt_tokens` figure is the *total* prompt
/// size. This function restores that total so downstream cost/usage accounting is
/// consistent across providers (§9.3). The invariant `result >= cache_read_input_tokens`
/// holds by construction, since this is a sum of two non-negative `u64` values.
///
/// Uses a saturating add: on real API responses these are both small integers (token
/// counts, not byte counts), so overflow is practically unreachable, but a saturating add
/// costs nothing here and avoids ever panicking on malformed/adversarial upstream data.
pub fn normalize_anthropic_usage(input_tokens: u64, cache_read_input_tokens: u64) -> u64 {
    input_tokens.saturating_add(cache_read_input_tokens)
}

/// Decodes an Anthropic Messages SSE response body into normalized [`StreamEvent`]s.
///
/// Parses `data: {...}` frames and dispatches on the payload's `type` field. Malformed or
/// unparseable frames (bad JSON, a missing `data` field on an SSE comment/keep-alive frame,
/// an unrecognized `type`) are skipped rather than treated as fatal — this decoder will
/// eventually process live bytes from Anthropic's network API, so it never panics on
/// unexpected shapes.
///
/// `message_start`'s `usage.input_tokens`/`usage.cache_read_input_tokens` and
/// `message_delta`'s `usage.output_tokens` are two halves of one logical usage update
/// (Anthropic splits them across the start and end of the stream); this decoder buffers the
/// `message_start` half and emits a single combined `UsageDelta` when `message_delta`
/// arrives, rather than emitting a partial `UsageDelta` immediately at `message_start`. This
/// also keeps `events[0]` as the first real content event (`BlockStart`) rather than a
/// usage bookkeeping event that arrives before any content — the natural place for
/// consumers to look for "did the stream produce anything yet".
pub async fn decode_anthropic_messages_stream(
    body: impl Stream<Item = Result<Bytes, TransportError>> + Send + Unpin,
) -> Vec<StreamEvent> {
    let mut sse = SseStream::from_bytes_stream(body);
    let mut events = Vec::new();
    // Buffered from `message_start`; combined with `message_delta`'s `output_tokens` into
    // one `UsageDelta` (see doc comment above).
    let mut initial_input_tokens: Option<u64> = None;
    let mut initial_cache_read_tokens: Option<u64> = None;

    while let Some(frame) = sse.next().await {
        let Ok(frame) = frame else { continue };
        // SSE keep-alive/comment frames carry no `data` field at all — not an error,
        // just skip and wait for the next frame (matches the OpenAI decoder's handling
        // of the same real `sse-stream` API shape).
        let Some(data) = frame.data else { continue };
        let Ok(payload) = serde_json::from_str::<Value>(data.trim()) else { continue };
        let Some(kind) = payload.get("type").and_then(Value::as_str) else { continue };

        match kind {
            "message_start" => {
                if let Some(usage) = payload.pointer("/message/usage") {
                    initial_input_tokens = usage.get("input_tokens").and_then(Value::as_u64);
                    initial_cache_read_tokens = usage.get("cache_read_input_tokens").and_then(Value::as_u64);
                }
            }
            "content_block_start" => {
                let index = payload.get("index").and_then(Value::as_u64).unwrap_or(0) as u32;
                let block_type = payload
                    .pointer("/content_block/type")
                    .and_then(Value::as_str)
                    .unwrap_or("text");
                let block_kind = match block_type {
                    "thinking" => BlockKind::Thinking,
                    "tool_use" => BlockKind::ToolUse {
                        name: payload.pointer("/content_block/name").and_then(Value::as_str).unwrap_or_default().to_string(),
                        provider_id: payload.pointer("/content_block/id").and_then(Value::as_str).map(str::to_string),
                    },
                    _ => BlockKind::Text,
                };
                events.push(StreamEvent::BlockStart { index, kind: block_kind });
            }
            "content_block_delta" => {
                let index = payload.get("index").and_then(Value::as_u64).unwrap_or(0) as u32;
                let delta_type = payload.pointer("/delta/type").and_then(Value::as_str).unwrap_or("");
                let delta = match delta_type {
                    "text_delta" => Some(BlockDelta::Text(
                        payload.pointer("/delta/text").and_then(Value::as_str).unwrap_or_default().to_string(),
                    )),
                    "input_json_delta" => Some(BlockDelta::ToolArgsFragment(
                        payload.pointer("/delta/partial_json").and_then(Value::as_str).unwrap_or_default().to_string(),
                    )),
                    "thinking_delta" => Some(BlockDelta::Thinking {
                        text: payload.pointer("/delta/thinking").and_then(Value::as_str).unwrap_or_default().to_string(),
                        signature: None,
                    }),
                    "signature_delta" => Some(BlockDelta::Thinking {
                        text: String::new(),
                        signature: payload.pointer("/delta/signature").and_then(Value::as_str).map(str::to_string),
                    }),
                    _ => None,
                };
                if let Some(delta) = delta {
                    events.push(StreamEvent::BlockDelta { index, delta });
                }
            }
            "content_block_stop" => {
                let index = payload.get("index").and_then(Value::as_u64).unwrap_or(0) as u32;
                events.push(StreamEvent::BlockStop { index });
            }
            "message_delta" => {
                let output_tokens = payload.pointer("/usage/output_tokens").and_then(Value::as_u64);
                // Only emit a combined UsageDelta if there's something to report — either
                // half (message_start's input/cache figures, or this message_delta's
                // output figure) may legitimately be absent on a malformed/partial stream.
                if initial_input_tokens.is_some() || initial_cache_read_tokens.is_some() || output_tokens.is_some() {
                    let input_tokens = initial_input_tokens.map(|input| {
                        normalize_anthropic_usage(input, initial_cache_read_tokens.unwrap_or(0))
                    });
                    events.push(StreamEvent::UsageDelta {
                        input_tokens,
                        output_tokens,
                        cache_read_tokens: initial_cache_read_tokens,
                    });
                }
            }
            "message_stop" => events.push(StreamEvent::MessageStop),
            _ => {}
        }
    }

    events
}
