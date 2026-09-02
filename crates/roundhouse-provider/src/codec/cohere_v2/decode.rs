//! Decodes a Cohere v2 `/v2/chat` streaming response body into normalized
//! [`StreamEvent`]s. Verified against the real, fetched Cohere API reference
//! -- see `mod.rs`'s module doc comment for the fetch record. Malformed or
//! genuinely unrecognized frames are skipped, matching this crate's
//! established precedent -- but every spec-verified terminal/failure signal
//! this module recognizes (a `finish_reason` other than the three real
//! success values) is enumerated explicitly and never falls into that "skip"
//! bucket (REALITY-CORRECTIONS §13b item 4).

use bytes::Bytes;
use futures::{Stream, StreamExt};
use serde_json::Value;
use sse_stream::SseStream;
use std::collections::HashSet;

use crate::stream_event::{BlockDelta, BlockKind, DeltaKeyer, StreamEvent};
use crate::TransportError;

/// A terminal, spec-verified failure signaled mid-stream. Deliberately not a
/// `ProviderError` -- this module has no `ProviderProfile` to classify
/// through; `provider.rs` maps this into the real `ProviderError` once
/// decoding stops. Mirrors `google_genai::decode::StreamFailure`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFailure {
    /// The provider's `finish_reason` value, when the event carried one.
    pub code: Option<String>,
    /// A human-readable description of the failure.
    pub message: String,
}

/// Tracks which wire `index` values were opened by a RECOGNIZED
/// block-opening event (`content-start`/`tool-call-start`) -- mirrors
/// `google_genai::decode`'s `StepKeyer` for the identical reason: a
/// `content-end`/`tool-call-end` for an index this decoder never opened must
/// not fabricate a `BlockStop`, and `citation-start`/`citation-end` (which
/// reuse a CONTENT block's own index -- verified: the fetched `citation-start`
/// example carries the same `"index":0` as the content block it annotates,
/// not a fresh one) must never consume a keyer slot.
struct IndexKeyer {
    keyer: DeltaKeyer,
    recognized: HashSet<u64>,
}

impl IndexKeyer {
    fn new() -> Self {
        Self {
            keyer: DeltaKeyer::new(),
            recognized: HashSet::new(),
        }
    }

    /// Opens a new recognized block at `wire_index`, returning its stable
    /// normalized index.
    fn open(&mut self, wire_index: u64) -> u32 {
        self.recognized.insert(wire_index);
        self.keyer.index_for(&wire_index.to_string())
    }

    /// The stable normalized index for `wire_index`, but only if it was
    /// previously `open`ed -- `None` otherwise, without ever calling
    /// `index_for` (which would burn a slot).
    fn existing(&mut self, wire_index: u64) -> Option<u32> {
        if self.recognized.contains(&wire_index) {
            Some(self.keyer.index_for(&wire_index.to_string()))
        } else {
            None
        }
    }
}

/// Decodes `body`, Cohere v2's SSE stream: `type`-discriminated events
/// (`message-start`, `content-start`, `content-delta`, `content-end`,
/// `citation-start`, `citation-end`, `tool-plan-delta`, `tool-call-start`,
/// `tool-call-delta`, `tool-call-end`, `message-end` -- the full, verified
/// set from the fetched reference; see `mod.rs`'s module doc comment).
pub async fn decode_cohere_v2_stream(
    body: impl Stream<Item = Result<Bytes, TransportError>> + Send + Unpin,
) -> Result<Vec<StreamEvent>, StreamFailure> {
    let mut sse = SseStream::from_bytes_stream(body);
    let mut keyer = IndexKeyer::new();
    let mut events = Vec::new();

    while let Some(frame) = sse.next().await {
        // A mid-stream transport/SSE-framing error must not be swallowed as
        // benign -- mirrors `google_genai::decode`'s identical fix.
        let frame = match frame {
            Ok(f) => f,
            Err(e) => {
                return Err(StreamFailure {
                    code: None,
                    message: format!(
                        "SSE transport error while decoding the cohere-v2 chat stream: {e}"
                    ),
                })
            }
        };
        let Some(data) = frame.data else { continue };
        let data = data.trim();
        if data.is_empty() {
            continue;
        }
        let Ok(payload) = serde_json::from_str::<Value>(data) else {
            continue;
        };
        let Some(event_type) = payload.get("type").and_then(Value::as_str) else {
            continue;
        };

        match event_type {
            // Echoes the model back with no content of its own -- nothing to
            // decode.
            "message-start" => {}
            "content-start" => {
                if let Some(ev) = decode_content_start(&payload, &mut keyer) {
                    events.push(ev);
                }
            }
            "content-delta" => {
                if let Some(ev) = decode_content_delta(&payload, &mut keyer) {
                    events.push(ev);
                }
            }
            "content-end" | "tool-call-end" => {
                if let Some(ev) = decode_block_end(&payload, &mut keyer) {
                    events.push(ev);
                }
            }
            "tool-call-start" => {
                if let Some(ev) = decode_tool_call_start(&payload, &mut keyer) {
                    events.push(ev);
                }
            }
            "tool-call-delta" => {
                if let Some(ev) = decode_tool_call_delta(&payload, &mut keyer) {
                    events.push(ev);
                }
            }
            // Citations annotate an ALREADY-open content block by reusing its
            // own index (verified) -- they never open or close a block of
            // their own, and this crate's `Citation` IR type is a fieldless
            // marker with no stream event to populate it through.
            "citation-start" | "citation-end" => {}
            // Chain-of-thought tool-planning text: verified to carry no
            // `index` and no paired open/close event of its own (there is no
            // `tool-plan-start`/`tool-plan-end` in the real event set) -- no
            // clean block boundary to synthesize one from, and no IR
            // equivalent to route it to. Dropped, matching
            // `google_genai::decode`'s precedent for step types with no IR
            // equivalent (its `user_input`/built-in-tool step kinds).
            "tool-plan-delta" => {}
            "message-end" => return decode_message_end(&payload, events),
            // Genuinely unrecognized frame shape (a future event type this
            // spec revision doesn't document) -- skipped, matching this
            // crate's established malformed-frame precedent.
            _ => {}
        }
    }

    Ok(events)
}

/// `message-end`: `{type, delta: {finish_reason, usage}}`. Verified
/// `finish_reason` enum (docs.cohere.com/reference/chat): `COMPLETE`,
/// `STOP_SEQUENCE`, `MAX_TOKENS`, `TOOL_CALL`, `ERROR`, `TIMEOUT` -- all six
/// enumerated explicitly here (REALITY-CORRECTIONS §13b item 4), not folded
/// into a catch-all, so a spec revision adding a seventh value fails loudly
/// (the `other` arm below) rather than silently defaulting to success or
/// failure. `COMPLETE`/`STOP_SEQUENCE` are ordinary clean endings.
/// `TOOL_CALL` is ALSO a successful, non-failure ending -- the model is
/// waiting for a tool result, not erroring (mirrors `google_genai::decode`'s
/// identical treatment of Interactions' `requires_action` status).
/// `MAX_TOKENS`/`ERROR`/`TIMEOUT` must never read as a clean completion (the
/// `MAX_TOKENS`-as-silent-success defect REALITY-CORRECTIONS §13b names
/// explicitly).
fn decode_message_end(
    payload: &Value,
    mut events: Vec<StreamEvent>,
) -> Result<Vec<StreamEvent>, StreamFailure> {
    if let Some(usage) = payload.pointer("/delta/usage") {
        events.push(usage_delta(usage));
    }
    let finish_reason = payload
        .pointer("/delta/finish_reason")
        .and_then(Value::as_str)
        .unwrap_or("");

    match finish_reason {
        "COMPLETE" | "STOP_SEQUENCE" | "TOOL_CALL" => {
            events.push(StreamEvent::MessageStop);
            Ok(events)
        }
        "MAX_TOKENS" | "ERROR" | "TIMEOUT" => Err(StreamFailure {
            code: Some(finish_reason.to_string()),
            message: format!("cohere-v2 chat generation stopped: {finish_reason}"),
        }),
        "" => Err(StreamFailure {
            code: None,
            message: "cohere-v2 chat stream's message-end event carried no finish_reason".into(),
        }),
        other => Err(StreamFailure {
            code: Some(other.to_string()),
            message: format!(
                "cohere-v2 chat stream ended with an unrecognized finish_reason `{other}`"
            ),
        }),
    }
}

/// `content-start`: `{type, index, delta: {message: {content: {type, ...}}}}`.
/// Verified content `type` values: `"text"` and `"thinking"` (the assistant
/// content array's two real block kinds -- see `mod.rs`'s fetch record). Any
/// other content type has no IR equivalent and is skipped without consuming
/// a keyer slot.
fn decode_content_start(payload: &Value, keyer: &mut IndexKeyer) -> Option<StreamEvent> {
    let wire_index = payload.get("index").and_then(Value::as_u64)?;
    let content_type = payload
        .pointer("/delta/message/content/type")
        .and_then(Value::as_str)?;
    let kind = match content_type {
        "text" => BlockKind::Text,
        "thinking" => BlockKind::Thinking,
        _ => return None,
    };
    let index = keyer.open(wire_index);
    Some(StreamEvent::BlockStart { index, kind })
}

/// `content-delta`: `{type, index, delta: {message: {content: {text}}}}` for
/// a text block, or `{... content: {thinking}}` for a thinking block
/// (verified: the field name changes with the block kind rather than always
/// being `text`).
fn decode_content_delta(payload: &Value, keyer: &mut IndexKeyer) -> Option<StreamEvent> {
    let wire_index = payload.get("index").and_then(Value::as_u64)?;
    let index = keyer.existing(wire_index)?;
    let content = payload.pointer("/delta/message/content")?;
    if let Some(text) = content.get("text").and_then(Value::as_str) {
        return Some(StreamEvent::BlockDelta {
            index,
            delta: BlockDelta::Text(text.to_string()),
        });
    }
    if let Some(thinking) = content.get("thinking").and_then(Value::as_str) {
        return Some(StreamEvent::BlockDelta {
            index,
            delta: BlockDelta::Thinking {
                text: thinking.to_string(),
                signature: None,
            },
        });
    }
    None
}

/// `content-end`/`tool-call-end`: `{type, index}` -- both close whichever
/// block `index` refers to, so one function serves both event types.
fn decode_block_end(payload: &Value, keyer: &mut IndexKeyer) -> Option<StreamEvent> {
    let wire_index = payload.get("index").and_then(Value::as_u64)?;
    let index = keyer.existing(wire_index)?;
    Some(StreamEvent::BlockStop { index })
}

/// `tool-call-start`: `{type, index, delta: {message: {tool_calls: {id,
/// type, function: {name, arguments}}}}}` -- verified: `tool_calls` here is
/// an OBJECT, not an array (unlike OpenAI's per-response `tool_calls[]`).
/// `id` becomes `BlockKind::ToolUse.provider_id`, echoed back by a later
/// `function_result`/`tool` message's `tool_call_id`.
fn decode_tool_call_start(payload: &Value, keyer: &mut IndexKeyer) -> Option<StreamEvent> {
    let wire_index = payload.get("index").and_then(Value::as_u64)?;
    let tool_call = payload.pointer("/delta/message/tool_calls")?;
    let name = tool_call
        .pointer("/function/name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let provider_id = tool_call
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_string);
    let index = keyer.open(wire_index);
    Some(StreamEvent::BlockStart {
        index,
        kind: BlockKind::ToolUse { name, provider_id },
    })
}

/// `tool-call-delta`: `{type, index, delta: {message: {tool_calls: {function:
/// {arguments}}}}}` -- verified: arguments arrive as progressively-built raw
/// JSON-string fragments, concatenated verbatim (never parsed mid-stream),
/// matching this crate's §9.3 normative rule.
fn decode_tool_call_delta(payload: &Value, keyer: &mut IndexKeyer) -> Option<StreamEvent> {
    let wire_index = payload.get("index").and_then(Value::as_u64)?;
    let index = keyer.existing(wire_index)?;
    let fragment = payload
        .pointer("/delta/message/tool_calls/function/arguments")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    Some(StreamEvent::BlockDelta {
        index,
        delta: BlockDelta::ToolArgsFragment(fragment),
    })
}

/// Normalizes `message-end`'s `usage` object (verified field names:
/// `billed_units.input_tokens`/`billed_units.output_tokens`). Cohere v2's
/// streaming reference documents no cache-read/cache-hit token count
/// anywhere -- unlike Gemini/Anthropic, this API has no documented
/// prompt-cache mechanism at all, so `cache_read_tokens` is always `0`, a
/// documented fact about the wire format rather than an undecoded field
/// (REALITY-CORRECTIONS §13b item 6's "assert something that is false when a
/// field fails to decode" lesson: `decode_usage`'s own unit tests below pin
/// nonzero `input_tokens`/`output_tokens` values through this function, so a
/// regression that stopped decoding usage entirely would fail those tests,
/// not hide behind the degenerate `0 >= 0` case).
pub fn decode_usage(data: &Value) -> roundhouse_core::Usage {
    roundhouse_core::Usage {
        input_tokens: data
            .pointer("/billed_units/input_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        output_tokens: data
            .pointer("/billed_units/output_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        cache_read_tokens: 0,
    }
}

fn usage_delta(data: &Value) -> StreamEvent {
    let usage = decode_usage(data);
    StreamEvent::UsageDelta {
        input_tokens: Some(usage.input_tokens),
        output_tokens: Some(usage.output_tokens),
        cache_read_tokens: Some(usage.cache_read_tokens),
    }
}

#[cfg(test)]
mod usage_tests {
    use super::decode_usage;

    /// REALITY-CORRECTIONS §13b item 6: pins EXACT, nonzero values through
    /// the real decode path -- not the degenerate `0 >= 0` case a broken
    /// decoder could pass vacuously.
    #[test]
    fn decodes_the_real_fetched_example_usage_shape() {
        let usage_json = serde_json::json!({
            "billed_units": { "input_tokens": 5, "output_tokens": 26 },
            "tokens": { "input_tokens": 71, "output_tokens": 26 }
        });
        let usage = decode_usage(&usage_json);
        assert_eq!(usage.input_tokens, 5);
        assert_eq!(usage.output_tokens, 26);
        assert_eq!(usage.cache_read_tokens, 0);
        assert!(usage.input_tokens >= usage.cache_read_tokens);
    }

    #[test]
    fn defaults_missing_fields_to_zero() {
        let usage = decode_usage(&serde_json::json!({}));
        assert_eq!(usage.input_tokens, 0);
        assert_eq!(usage.output_tokens, 0);
        assert_eq!(usage.cache_read_tokens, 0);
    }
}

#[cfg(test)]
mod terminal_tests {
    use super::{decode_block_end, decode_content_start, decode_message_end, IndexKeyer};
    use crate::stream_event::{BlockKind, StreamEvent};

    /// Mirrors `google_genai::decode`'s `an_unrecognized_step_type_never_
    /// consumes_an_index_and_its_stop_is_ignored`: an unrecognized
    /// content-block type must not consume a keyer slot, and its
    /// `content-end` must not fabricate a `BlockStop`.
    #[test]
    fn an_unrecognized_content_type_never_consumes_an_index_and_its_end_is_ignored() {
        let mut keyer = IndexKeyer::new();

        let unrecognized = serde_json::json!({
            "type": "content-start",
            "index": 0,
            "delta": { "message": { "content": { "type": "audio" } } }
        });
        assert!(decode_content_start(&unrecognized, &mut keyer).is_none());

        let unrecognized_end = serde_json::json!({ "type": "content-end", "index": 0 });
        assert!(
            decode_block_end(&unrecognized_end, &mut keyer).is_none(),
            "a content-end for a content type this decoder never opened must not \
             fabricate a BlockStop"
        );

        let recognized = serde_json::json!({
            "type": "content-start",
            "index": 1,
            "delta": { "message": { "content": { "type": "text" } } }
        });
        let event = decode_content_start(&recognized, &mut keyer)
            .expect("a text content-start must produce a BlockStart");
        assert!(
            matches!(
                event,
                StreamEvent::BlockStart {
                    index: 0,
                    kind: BlockKind::Text
                }
            ),
            "the first REAL block must land on index 0, not 1 -- the earlier \
             unrecognized content type must not have consumed an index"
        );
    }

    fn expect_failure(
        result: Result<Vec<StreamEvent>, super::StreamFailure>,
    ) -> super::StreamFailure {
        match result {
            Ok(_) => panic!("expected a StreamFailure, got a successful decode"),
            Err(failure) => failure,
        }
    }

    #[test]
    fn max_tokens_finish_reason_is_a_stream_failure_not_a_silent_success() {
        let payload = serde_json::json!({
            "type": "message-end",
            "delta": { "finish_reason": "MAX_TOKENS" }
        });
        let err = expect_failure(decode_message_end(&payload, Vec::new()));
        assert!(err.message.contains("MAX_TOKENS"));
    }

    #[test]
    fn error_finish_reason_is_a_stream_failure() {
        let payload = serde_json::json!({
            "type": "message-end",
            "delta": { "finish_reason": "ERROR" }
        });
        let err = expect_failure(decode_message_end(&payload, Vec::new()));
        assert!(err.message.contains("ERROR"));
    }

    #[test]
    fn timeout_finish_reason_is_a_stream_failure() {
        let payload = serde_json::json!({
            "type": "message-end",
            "delta": { "finish_reason": "TIMEOUT" }
        });
        let err = expect_failure(decode_message_end(&payload, Vec::new()));
        assert!(err.message.contains("TIMEOUT"));
    }

    #[test]
    fn complete_finish_reason_emits_message_stop() {
        let payload = serde_json::json!({
            "type": "message-end",
            "delta": { "finish_reason": "COMPLETE" }
        });
        let events = decode_message_end(&payload, Vec::new()).expect("must succeed");
        assert!(events.iter().any(|e| matches!(e, StreamEvent::MessageStop)));
    }

    #[test]
    fn tool_call_finish_reason_is_a_successful_ending_not_a_failure() {
        let payload = serde_json::json!({
            "type": "message-end",
            "delta": { "finish_reason": "TOOL_CALL" }
        });
        let events = decode_message_end(&payload, Vec::new()).expect("must succeed");
        assert!(events.iter().any(|e| matches!(e, StreamEvent::MessageStop)));
    }

    #[test]
    fn stop_sequence_finish_reason_is_a_successful_ending() {
        let payload = serde_json::json!({
            "type": "message-end",
            "delta": { "finish_reason": "STOP_SEQUENCE" }
        });
        let events = decode_message_end(&payload, Vec::new()).expect("must succeed");
        assert!(events.iter().any(|e| matches!(e, StreamEvent::MessageStop)));
    }

    #[test]
    fn a_missing_finish_reason_is_a_stream_failure_not_a_silent_success() {
        let payload = serde_json::json!({ "type": "message-end", "delta": {} });
        let err = expect_failure(decode_message_end(&payload, Vec::new()));
        assert!(err.code.is_none());
    }
}

#[cfg(test)]
mod stream_tests {
    //! End-to-end coverage of `decode_cohere_v2_stream` itself (not just its
    //! helper functions), against synthetic SSE bytes shaped from the real
    //! fetched verbatim examples in `mod.rs`'s module doc comment.
    use super::decode_cohere_v2_stream;
    use crate::stream_event::{BlockDelta, BlockKind, StreamEvent};
    use futures::stream;

    fn sse_body(
        frames: &[&str],
    ) -> impl futures::Stream<Item = Result<bytes::Bytes, crate::TransportError>> {
        let mut raw = String::new();
        for frame in frames {
            raw.push_str("data: ");
            raw.push_str(frame);
            raw.push_str("\n\n");
        }
        stream::iter(vec![Ok(bytes::Bytes::from(raw))])
    }

    #[tokio::test]
    async fn decodes_a_full_text_turn() {
        let body = sse_body(&[
            r#"{"id":"r1","type":"message-start","delta":{"message":{"role":"assistant"}}}"#,
            r#"{"type":"content-start","index":0,"delta":{"message":{"content":{"type":"text","text":""}}}}"#,
            r#"{"type":"content-delta","index":0,"delta":{"message":{"content":{"text":"4"}}}}"#,
            r#"{"type":"content-delta","index":0,"delta":{"message":{"content":{"text":"."}}}}"#,
            r#"{"type":"content-end","index":0}"#,
            r#"{"type":"message-end","delta":{"finish_reason":"COMPLETE","usage":{"billed_units":{"input_tokens":9,"output_tokens":3}}}}"#,
        ]);
        let events = decode_cohere_v2_stream(body)
            .await
            .expect("must decode successfully");

        let mut texts = Vec::new();
        let mut saw_stop = false;
        let mut saw_usage = false;
        let mut saw_message_stop = false;
        for event in events {
            match event {
                StreamEvent::BlockDelta {
                    delta: BlockDelta::Text(t),
                    ..
                } => texts.push(t),
                StreamEvent::BlockStop { .. } => saw_stop = true,
                StreamEvent::UsageDelta { input_tokens, .. } => {
                    saw_usage = true;
                    assert_eq!(input_tokens, Some(9));
                }
                StreamEvent::MessageStop => saw_message_stop = true,
                _ => {}
            }
        }
        assert_eq!(texts.join(""), "4.");
        assert!(saw_stop);
        assert!(saw_usage);
        assert!(saw_message_stop);
    }

    #[tokio::test]
    async fn decodes_a_tool_call_with_incremental_arguments() {
        let body = sse_body(&[
            r#"{"id":"r2","type":"message-start","delta":{"message":{"role":"assistant"}}}"#,
            r#"{"type":"tool-plan-delta","delta":{"message":{"tool_plan":"I will check."}}}"#,
            r#"{"type":"tool-call-start","index":0,"delta":{"message":{"tool_calls":{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}}}}"#,
            r#"{"type":"tool-call-delta","index":0,"delta":{"message":{"tool_calls":{"function":{"arguments":"{\"location\": \"Tokyo\"}"}}}}}"#,
            r#"{"type":"tool-call-end","index":0}"#,
            r#"{"type":"message-end","delta":{"finish_reason":"TOOL_CALL","usage":{"billed_units":{"input_tokens":20,"output_tokens":12}}}}"#,
        ]);
        let events = decode_cohere_v2_stream(body)
            .await
            .expect("must decode successfully");

        let mut saw_start = false;
        let mut args = String::new();
        let mut saw_stop = false;
        let mut saw_message_stop = false;
        for event in events {
            match event {
                StreamEvent::BlockStart {
                    kind: BlockKind::ToolUse { name, provider_id },
                    ..
                } => {
                    assert_eq!(name, "get_weather");
                    assert_eq!(provider_id.as_deref(), Some("call_1"));
                    saw_start = true;
                }
                StreamEvent::BlockDelta {
                    delta: BlockDelta::ToolArgsFragment(f),
                    ..
                } => args.push_str(&f),
                StreamEvent::BlockStop { .. } => saw_stop = true,
                StreamEvent::MessageStop => saw_message_stop = true,
                StreamEvent::UsageDelta { .. } => {}
                StreamEvent::BlockStart { .. } | StreamEvent::BlockDelta { .. } => {
                    panic!("unexpected block kind")
                }
            }
        }
        assert!(saw_start && saw_stop && saw_message_stop);
        assert_eq!(args, r#"{"location": "Tokyo"}"#);
    }

    /// A stream that ends without ever carrying a `message-end` event (a
    /// connection reset, a proxy cut) must NOT fabricate `MessageStop`.
    #[tokio::test]
    async fn a_stream_with_no_message_end_does_not_fabricate_message_stop() {
        let body = sse_body(&[
            r#"{"id":"r3","type":"message-start","delta":{"message":{"role":"assistant"}}}"#,
            r#"{"type":"content-start","index":0,"delta":{"message":{"content":{"type":"text","text":""}}}}"#,
            r#"{"type":"content-delta","index":0,"delta":{"message":{"content":{"text":"partial"}}}}"#,
        ]);
        let events = decode_cohere_v2_stream(body)
            .await
            .expect("an unterminated stream is not itself an error -- just unterminated");
        assert!(
            !events.iter().any(|e| matches!(e, StreamEvent::MessageStop)),
            "a stream with no observed message-end must not fabricate MessageStop"
        );
    }

    /// Round-trips a `thinking` content block through the real decode path
    /// (the assistant-content-array "thinking" block this codec, unlike its
    /// siblings, actually supports -- see `mod.rs`'s fetch record).
    #[tokio::test]
    async fn decodes_a_thinking_block_distinct_from_visible_text() {
        let body = sse_body(&[
            r#"{"id":"r4","type":"message-start","delta":{"message":{"role":"assistant"}}}"#,
            r#"{"type":"content-start","index":0,"delta":{"message":{"content":{"type":"thinking","thinking":""}}}}"#,
            r#"{"type":"content-delta","index":0,"delta":{"message":{"content":{"thinking":"Let me think."}}}}"#,
            r#"{"type":"content-end","index":0}"#,
            r#"{"type":"content-start","index":1,"delta":{"message":{"content":{"type":"text","text":""}}}}"#,
            r#"{"type":"content-delta","index":1,"delta":{"message":{"content":{"text":"Answer."}}}}"#,
            r#"{"type":"content-end","index":1}"#,
            r#"{"type":"message-end","delta":{"finish_reason":"COMPLETE"}}"#,
        ]);
        let events = decode_cohere_v2_stream(body)
            .await
            .expect("must decode successfully");

        let mut thinking_texts = Vec::new();
        let mut visible_texts = Vec::new();
        for event in events {
            match event {
                StreamEvent::BlockDelta {
                    delta: BlockDelta::Thinking { text, .. },
                    ..
                } => thinking_texts.push(text),
                StreamEvent::BlockDelta {
                    delta: BlockDelta::Text(text),
                    ..
                } => visible_texts.push(text),
                _ => {}
            }
        }
        assert_eq!(thinking_texts, vec!["Let me think.".to_string()]);
        assert_eq!(visible_texts, vec!["Answer.".to_string()]);
    }
}
