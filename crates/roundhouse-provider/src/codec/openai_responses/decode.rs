//! Decodes an Open Responses `/v1/responses` streaming response body
//! (Server-Sent Events) into normalized [`StreamEvent`]s. Verified against
//! the real spec before being written -- see
//! `docs/decisions/2026-08-27-open-responses-spec-verification.md`.
//!
//! Spec-verification finding: unlike the brief's sketch (which assumed every
//! event carries a flat top-level `item_id`), the real schemas split into two
//! shapes: `response.output_item.added`/`response.output_item.done` carry
//! `{output_index, item}` with the id nested at `item.id` (and `item.type`
//! determining the block kind); the delta events (`response.output_text.delta`,
//! `response.function_call_arguments.delta`, `response.reasoning_summary_text.delta`,
//! `response.refusal.delta`) carry a genuine top-level `item_id`. Both shapes
//! are funneled through the same [`DeltaKeyer::index_for`] call so downstream
//! code sees one normalized `index: u32` regardless of which shape produced
//! it (REALITY-CORRECTIONS §14e).
//!
//! `FunctionCall`'s real shape also separates `id` (the item's stream
//! identity, used for keying) from `call_id` (the correlation token a later
//! `function_call_output` must reference) -- `BlockKind::ToolUse.provider_id`
//! is sourced from `call_id`, falling back to `id` if `call_id` is absent.
//!
//! **Fix-round-1 C1**: the event-type string this file matches for reasoning
//! summary deltas was originally `"response.reasoning_summary.delta"` --
//! that is the spec's own stale prose `description` for
//! `ResponseReasoningSummaryDeltaStreamingEvent`, not its authoritative
//! `type.enum`/`type.default` value, which is
//! `"response.reasoning_summary_text.delta"`. The Step 0 gate had verified
//! that the *schema* existed in `components.schemas`, not that the *value*
//! matched here was the real enum member -- a gap now closed structurally by
//! `tests/openai_responses_event_type_tripwire.rs`, which checks every
//! event-type literal this file matches against a vendored copy of the real
//! spec's `type` values.
//!
//! **Fix-round-1 C2**: `response.failed`, `response.incomplete`, and a bare
//! `error` event are well-formed, spec-mandated, semantically load-bearing
//! terminal events that arrive IN-BAND after an HTTP 200 -- unlike a
//! malformed or merely-unrecognized frame, silently skipping them would let
//! `Provider::stream_chat` return `Ok` for a failed, truncated, or
//! content-filtered inference, indistinguishable from a real success on a
//! physically-immutable event log. [`decode_openai_responses_stream`]
//! surfaces these as an `Err(StreamFailure)` instead of a `StreamEvent`,
//! since the frozen `StreamEvent` enum has no error variant to carry one
//! through the stream itself (REALITY-CORRECTIONS §1) -- the failure has to
//! be detected before the decoded events are ever wrapped into a
//! `ChatStream`, which is exactly the point at which this function is
//! called from `provider.rs`.

use bytes::Bytes;
use futures::{Stream, StreamExt};
use serde_json::Value;
use sse_stream::SseStream;

use crate::stream_event::{BlockDelta, BlockKind, DeltaKeyer, StreamEvent};
use crate::TransportError;

/// A terminal, spec-mandated failure signaled mid-stream (after a 200 OK):
/// `response.failed`, `response.incomplete`, or a bare `error` event.
/// Deliberately not a `ProviderError` -- this module has no `ProviderProfile`
/// to classify through (`errors::classify` needs one); `provider.rs` maps
/// this into the real `ProviderError` once decoding stops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFailure {
    /// The provider's machine-readable error/reason code, when the event
    /// carried one (`response.failed`'s `response.error.code`; absent for
    /// `response.incomplete`, which carries only a `reason` string).
    pub code: Option<String>,
    /// A human-readable description of the failure -- the `error.message`,
    /// the `incomplete_details.reason`, or a fallback naming the event type
    /// when the payload carried neither.
    pub message: String,
}

/// Decodes an Open Responses SSE response body into normalized
/// [`StreamEvent`]s, or a [`StreamFailure`] if the stream terminates with
/// `response.failed`/`response.incomplete`/`error` instead of
/// `response.completed`. Malformed or genuinely unrecognized frames are
/// skipped rather than treated as fatal, matching the precedent both
/// existing codecs in this crate already establish -- but the three
/// spec-mandated terminal-failure events are never in that "skip" bucket
/// (fix-round-1 C2).
pub async fn decode_openai_responses_stream(
    body: impl Stream<Item = Result<Bytes, TransportError>> + Send + Unpin,
) -> Result<Vec<StreamEvent>, StreamFailure> {
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

        if let Some(failure) = terminal_failure(data) {
            return Err(failure);
        }

        events.extend(decode_stream_event(data, &mut keyer));
    }

    Ok(events)
}

/// Recognizes `response.failed`, `response.incomplete`, and a bare `error`
/// event and extracts a [`StreamFailure`] from each's real (spec-verified)
/// shape:
///
/// - `response.failed` carries `response.error: {code, message}`.
/// - `response.incomplete` carries `response.incomplete_details: {reason}`
///   (its `response.error` is null in this case -- `incomplete_details` is
///   the field that actually explains it).
/// - `error` carries `error: {type, code, message, param, headers}`
///   (`ErrorPayload` -- note `type` here, not `code`, is the field this
///   schema actually uses as its own error-code text).
fn terminal_failure(raw: &str) -> Option<StreamFailure> {
    let payload: Value = serde_json::from_str(raw).ok()?;
    let event_type = payload.get("type").and_then(Value::as_str)?;
    match event_type {
        "response.failed" => {
            let error = payload.pointer("/response/error");
            Some(StreamFailure {
                code: error
                    .and_then(|e| e.get("code"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
                message: error
                    .and_then(|e| e.get("message"))
                    .and_then(Value::as_str)
                    .unwrap_or("response.failed with no error detail in the response body")
                    .to_string(),
            })
        }
        "response.incomplete" => {
            let reason = payload
                .pointer("/response/incomplete_details/reason")
                .and_then(Value::as_str)
                .unwrap_or("response.incomplete with no reason given");
            Some(StreamFailure {
                code: None,
                message: reason.to_string(),
            })
        }
        "error" => {
            let error = payload.get("error");
            Some(StreamFailure {
                code: error
                    .and_then(|e| e.get("type"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
                message: error
                    .and_then(|e| e.get("message"))
                    .and_then(Value::as_str)
                    .unwrap_or("openai-responses stream emitted an error event with no message")
                    .to_string(),
            })
        }
        _ => None,
    }
}

/// Decodes one `data: {...}` frame's JSON payload into zero or more
/// normalized [`StreamEvent`]s (`response.completed` carries both a usage
/// figure and the terminal `MessageStop`, so it can produce two). Returns an
/// empty `Vec` for malformed JSON, a payload with no `type` field, or a
/// `type` this codec does not recognize -- never panics on unexpected wire
/// shapes. Does **not** handle the terminal-failure event types
/// (`response.failed`/`response.incomplete`/`error`) -- callers check
/// [`terminal_failure`] first (see [`decode_openai_responses_stream`]).
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
        // Fix-round-1 C1: the real enum/default value is
        // "response.reasoning_summary_text.delta" -- see this module's doc
        // comment and `tests/openai_responses_event_type_tripwire.rs`.
        "response.reasoning_summary_text.delta" => {
            decode_item_delta(&payload, keyer, |text| BlockDelta::Thinking {
                text,
                signature: None,
            })
            .into_iter()
            .collect()
        }
        // Fix-round-1 C2: refusal text is real assistant-visible content the
        // model produced instead of an answer -- the IR has no dedicated
        // "refusal" concept, so it's carried as `BlockDelta::Text` (the
        // closest existing bucket) rather than silently dropped.
        "response.refusal.delta" => decode_item_delta(&payload, keyer, BlockDelta::Text)
            .into_iter()
            .collect(),
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
///
/// Fix-round-1 minor: `keyer.index_for` is called only once `item.type` is
/// known to be a recognized kind -- calling it unconditionally would burn an
/// index on an unrecognized item type, and every later delta/done event for
/// that same `item.id` would then decode against an index whose `BlockStart`
/// was never emitted, silently dropping content with no signal.
fn decode_output_item_added(payload: &Value, keyer: &mut DeltaKeyer) -> Option<StreamEvent> {
    let item = payload.get("item")?;
    let item_id = item.get("id").and_then(Value::as_str)?;
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
    let index = keyer.index_for(item_id);
    Some(StreamEvent::BlockStart { index, kind })
}

/// `response.output_item.done`: same nested-`item.id` shape as `added`.
fn decode_output_item_done(payload: &Value, keyer: &mut DeltaKeyer) -> Option<StreamEvent> {
    let item = payload.get("item")?;
    let item_id = item.get("id").and_then(Value::as_str)?;
    let index = keyer.index_for(item_id);
    Some(StreamEvent::BlockStop { index })
}

/// The delta event types share one shape: a top-level `item_id` and a
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

#[cfg(test)]
mod terminal_failure_tests {
    use super::terminal_failure;

    #[test]
    fn response_failed_extracts_the_error_code_and_message() {
        let raw = serde_json::json!({
            "type": "response.failed",
            "sequence_number": 9,
            "response": {
                "id": "resp_1",
                "status": "failed",
                "error": { "code": "server_error", "message": "the model overloaded" }
            }
        })
        .to_string();
        let failure = terminal_failure(&raw).expect("response.failed must be a terminal failure");
        assert_eq!(failure.code.as_deref(), Some("server_error"));
        assert_eq!(failure.message, "the model overloaded");
    }

    #[test]
    fn response_incomplete_extracts_the_reason_with_no_code() {
        let raw = serde_json::json!({
            "type": "response.incomplete",
            "sequence_number": 9,
            "response": {
                "id": "resp_1",
                "status": "incomplete",
                "incomplete_details": { "reason": "max_output_tokens" }
            }
        })
        .to_string();
        let failure =
            terminal_failure(&raw).expect("response.incomplete must be a terminal failure");
        assert_eq!(failure.code, None);
        assert_eq!(failure.message, "max_output_tokens");
    }

    #[test]
    fn bare_error_event_extracts_type_as_code_and_message() {
        let raw = serde_json::json!({
            "type": "error",
            "sequence_number": 3,
            "error": { "type": "rate_limit_exceeded", "code": null, "message": "slow down", "param": null }
        })
        .to_string();
        let failure = terminal_failure(&raw).expect("error must be a terminal failure");
        assert_eq!(failure.code.as_deref(), Some("rate_limit_exceeded"));
        assert_eq!(failure.message, "slow down");
    }

    #[test]
    fn ordinary_events_are_not_terminal_failures() {
        let raw = serde_json::json!({
            "type": "response.output_text.delta",
            "sequence_number": 1,
            "item_id": "item_1",
            "output_index": 0,
            "content_index": 0,
            "delta": "hi"
        })
        .to_string();
        assert_eq!(terminal_failure(&raw), None);
    }
}

#[cfg(test)]
mod index_ordering_tests {
    use super::{decode_output_item_added, decode_output_item_done};
    use crate::stream_event::{BlockKind, DeltaKeyer, StreamEvent};

    /// Fix-round-1 minor: an `output_item.added` for an unrecognized
    /// `item.type` must not burn an index. Before this fix,
    /// `keyer.index_for` ran unconditionally, so a genuinely recognized item
    /// that arrived AFTER an unrecognized one would land on index 1, not 0 --
    /// and worse, if any later delta/done event referenced the unrecognized
    /// item's `item_id`, it would decode against an index whose
    /// `BlockStart` was never emitted (a silently orphaned delta).
    #[test]
    fn an_unrecognized_item_type_never_consumes_an_index() {
        let mut keyer = DeltaKeyer::new();

        let unrecognized = serde_json::json!({
            "type": "response.output_item.added",
            "sequence_number": 1,
            "output_index": 0,
            "item": { "id": "item_unknown", "type": "some_future_item_type" }
        });
        assert!(
            decode_output_item_added(&unrecognized, &mut keyer).is_none(),
            "an unrecognized item.type must not produce a BlockStart"
        );

        let recognized = serde_json::json!({
            "type": "response.output_item.added",
            "sequence_number": 2,
            "output_index": 1,
            "item": { "id": "item_1", "type": "message" }
        });
        let event = decode_output_item_added(&recognized, &mut keyer)
            .expect("a message item must produce a BlockStart");
        // `StreamEvent` derives no `Debug` (REALITY-CORRECTIONS §14c), so
        // this is asserted by matching rather than formatted into the
        // failure message.
        assert!(
            matches!(
                event,
                StreamEvent::BlockStart {
                    index: 0,
                    kind: BlockKind::Text
                }
            ),
            "the first REAL block must land on index 0, not 1 -- the earlier \
             unrecognized item must not have consumed an index"
        );

        // And its later `output_item.done` must resolve to that same index
        // 0, proving `item_1` was never accidentally aliased to the
        // unrecognized item's slot.
        let done = serde_json::json!({
            "type": "response.output_item.done",
            "sequence_number": 3,
            "output_index": 1,
            "item": { "id": "item_1", "type": "message" }
        });
        assert!(matches!(
            decode_output_item_done(&done, &mut keyer),
            Some(StreamEvent::BlockStop { index: 0 })
        ));
    }
}
