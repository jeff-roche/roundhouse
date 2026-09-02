//! Decodes a Gemini streaming response body into normalized [`StreamEvent`]s,
//! for either endpoint mode. Verified against the real fetched spec before
//! being written -- see
//! `docs/decisions/2026-08-27-google-genai-spec-verification.md`. The two
//! modes' streaming envelopes are unrelated (Divergence 1: one is an
//! `event_type`-discriminated SSE event union over a `steps[]` timeline, the
//! other is a sequence of complete, partial `GenerateContentResponse` JSON
//! objects with no event-type discriminator at all), so
//! `decode_interactions_stream`/`decode_generate_content_stream` are
//! independent functions, not two branches of one shared decode loop.

use bytes::Bytes;
use futures::{Stream, StreamExt};
use serde_json::Value;
use sse_stream::SseStream;
use std::collections::HashSet;

use super::EndpointMode;
use crate::audit::redact_transport_error_text;
use crate::stream_event::{BlockDelta, BlockKind, DeltaKeyer, StreamEvent};
use crate::TransportError;

/// A terminal, spec-mandated failure signaled mid-stream. Deliberately not a
/// `ProviderError` -- this module has no `ProviderProfile` to classify
/// through; `provider.rs` maps this into the real `ProviderError` once
/// decoding stops. Mirrors `openai_responses::decode::StreamFailure`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFailure {
    /// The provider's machine-readable error/reason code, when the event
    /// carried one.
    pub code: Option<String>,
    /// A human-readable description of the failure.
    pub message: String,
}

/// Decodes `body` for the given `mode`. Malformed or genuinely unrecognized
/// frames are skipped rather than treated as fatal, matching this crate's
/// established precedent -- but every spec-mandated terminal-failure signal
/// this module recognizes is enumerated explicitly and never falls into that
/// "skip" bucket (REALITY-CORRECTIONS §13b item 4).
pub async fn decode_google_genai_stream(
    body: impl Stream<Item = Result<Bytes, TransportError>> + Send + Unpin,
    mode: EndpointMode,
) -> Result<Vec<StreamEvent>, StreamFailure> {
    match mode {
        EndpointMode::Interactions => decode_interactions_stream(body).await,
        EndpointMode::GenerateContent => decode_generate_content_stream(body).await,
    }
}

// ============================================================================
// Interactions API (default, §9.2)
// ============================================================================

/// Wraps the shared [`DeltaKeyer`] with a record of which wire step-indices
/// were confirmed, via a recognized `step.start`, to open a block this
/// decoder understands -- so a `step.delta`/`step.stop` for a step kind this
/// decoder doesn't model (`user_input`, a built-in tool call/result, ...)
/// never consumes a keyer slot. Mirrors `openai_responses::decode`'s
/// fix-round-1 minor fix for the identical failure mode (there: an
/// `output_item.added` for an unrecognized `item.type`); here it also has to
/// cover `step.delta`/`step.stop`, since a `DeltaKeyer::index_for` call from
/// either would otherwise silently burn the next global slot for an index
/// nothing ever opened.
struct StepKeyer {
    keyer: DeltaKeyer,
    recognized: HashSet<u64>,
}

impl StepKeyer {
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

/// Decodes the Interactions API's SSE stream: `event_type`-discriminated
/// events (`interaction.created`, `step.start`, `step.delta`, `step.stop`,
/// `interaction.status_update`, `interaction.completed`, `error` -- verified
/// `const` values from `interactions.openapi.json`'s `InteractionSseEvent`
/// oneOf).
async fn decode_interactions_stream(
    body: impl Stream<Item = Result<Bytes, TransportError>> + Send + Unpin,
) -> Result<Vec<StreamEvent>, StreamFailure> {
    let mut sse = SseStream::from_bytes_stream(body);
    let mut keyer = StepKeyer::new();
    let mut events = Vec::new();

    while let Some(frame) = sse.next().await {
        // Fix-round-1 F2: a mid-stream transport/SSE-framing error must not
        // be swallowed as a benign "nothing to see here" -- it's currently
        // benign here (the loop simply ends and `Ok(events)` is returned
        // either way, since this decoder never fabricates a `MessageStop`),
        // but surfacing it explicitly avoids relying on that being true
        // forever, and matches the sibling `GenerateContent` decoder where
        // swallowing it was the actual defect.
        let frame = match frame {
            Ok(f) => f,
            Err(e) => {
                return Err(StreamFailure {
                    code: None,
                    message: redact_transport_error_text(&format!(
                        "SSE transport error while decoding the interaction stream: {e}"
                    )),
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
        let Some(event_type) = payload.get("event_type").and_then(Value::as_str) else {
            continue;
        };

        match event_type {
            "error" => return Err(interactions_error_failure(&payload)),
            "interaction.completed" => {
                let status = payload
                    .pointer("/interaction/status")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                // "completed": normal end. "requires_action": the normal,
                // successful end of a tool-call turn -- the model is waiting
                // for a `function_result`, not failing (verified: a distinct
                // status from "failed"/"cancelled"/"incomplete" in the
                // fetched `InteractionSseEventInteraction.status` enum).
                if status == "completed" || status == "requires_action" {
                    if let Some(usage) = payload.pointer("/interaction/usage") {
                        events.push(interactions_usage_delta(usage));
                    }
                    events.push(StreamEvent::MessageStop);
                    return Ok(events);
                }
                // "failed" | "cancelled" | "incomplete": the lifecycle event
                // envelope (`InteractionSseEventInteraction`) carries no
                // error detail of its own (verified: no `errors` field on
                // that partial resource, unlike the full `Interaction`
                // resource) -- name the status itself rather than inventing
                // detail that was never on the wire.
                return Err(StreamFailure {
                    code: None,
                    message: format!("interaction ended with status `{status}`"),
                });
            }
            // Progress pings, not terminal: `interaction.completed` is the
            // authoritative end-of-stream signal.
            "interaction.created" | "interaction.status_update" => {}
            "step.start" => {
                if let Some(ev) = decode_step_start(&payload, &mut keyer) {
                    events.push(ev);
                }
            }
            "step.delta" => events.extend(decode_step_delta(&payload, &mut keyer)),
            "step.stop" => {
                if let Some(ev) = decode_step_stop(&payload, &mut keyer) {
                    events.push(ev);
                }
            }
            // `content.start`/`content.delta`/`content.stop` schemas exist in
            // the spec but are NOT members of `InteractionSseEvent`'s
            // documented oneOf (verified) -- genuinely unrecognized per this
            // spec revision, so they fall here like any other unknown frame.
            _ => {}
        }
    }

    Ok(events)
}

fn interactions_error_failure(payload: &Value) -> StreamFailure {
    let error = payload.get("error");
    StreamFailure {
        code: error
            .and_then(|e| e.get("code"))
            .and_then(Value::as_str)
            .map(str::to_string),
        message: error
            .and_then(|e| e.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("google-genai interactions stream emitted an error event with no message")
            .to_string(),
    }
}

/// `step.start`: `{event_type, index, step}`. `step.type` decides the block
/// kind; a `function_call` step's `id` (verified: the same field a later
/// `function_result.call_id` echoes back -- unlike Open Responses, there is
/// no separate stream-identity-vs-correlation-token split here) becomes
/// `BlockKind::ToolUse.provider_id`.
fn decode_step_start(payload: &Value, keyer: &mut StepKeyer) -> Option<StreamEvent> {
    let wire_index = payload.get("index").and_then(Value::as_u64)?;
    let step = payload.get("step")?;
    let kind = match step.get("type").and_then(Value::as_str)? {
        "model_output" => BlockKind::Text,
        "function_call" => BlockKind::ToolUse {
            name: step
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            provider_id: step.get("id").and_then(Value::as_str).map(str::to_string),
        },
        "thought" => BlockKind::Thinking,
        // `user_input`, and every built-in-tool call/result step: no IR
        // equivalent -- recognized as a real step type, not a malformed
        // frame, but this decoder has nothing to open for it.
        _ => return None,
    };
    let index = keyer.open(wire_index);
    Some(StreamEvent::BlockStart { index, kind })
}

fn decode_step_stop(payload: &Value, keyer: &mut StepKeyer) -> Option<StreamEvent> {
    let wire_index = payload.get("index").and_then(Value::as_u64)?;
    let index = keyer.existing(wire_index)?;
    Some(StreamEvent::BlockStop { index })
}

/// `step.delta`: `{event_type, index, delta}`, `delta` itself discriminated
/// by its own `type` (verified `StepDeltaData` oneOf members): `"text"`
/// (`TextDelta`), `"arguments_delta"` (`ArgumentsDelta`, field named
/// `arguments` not `delta`), `"thought_signature"` (`ThoughtSignatureDelta`,
/// the whole signature value, not an incremental fragment), `"thought_summary"`
/// (`ThoughtSummaryDelta`, wraps a nested `Content` item). Every other delta
/// kind (audio/image/document/built-in-tool deltas) has no IR equivalent and
/// is skipped.
fn decode_step_delta(payload: &Value, keyer: &mut StepKeyer) -> Vec<StreamEvent> {
    let Some(wire_index) = payload.get("index").and_then(Value::as_u64) else {
        return Vec::new();
    };
    let Some(index) = keyer.existing(wire_index) else {
        return Vec::new();
    };
    let Some(delta) = payload.get("delta") else {
        return Vec::new();
    };
    let Some(delta_type) = delta.get("type").and_then(Value::as_str) else {
        return Vec::new();
    };

    match delta_type {
        "text" => {
            let Some(text) = delta.get("text").and_then(Value::as_str) else {
                return Vec::new();
            };
            vec![StreamEvent::BlockDelta {
                index,
                delta: BlockDelta::Text(text.to_string()),
            }]
        }
        "arguments_delta" => {
            let fragment = delta
                .get("arguments")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            vec![StreamEvent::BlockDelta {
                index,
                delta: BlockDelta::ToolArgsFragment(fragment),
            }]
        }
        "thought_signature" => {
            let signature = delta
                .get("signature")
                .and_then(Value::as_str)
                .map(str::to_string);
            vec![StreamEvent::BlockDelta {
                index,
                delta: BlockDelta::Thinking {
                    text: String::new(),
                    signature,
                },
            }]
        }
        "thought_summary" => {
            let text = delta
                .pointer("/content/text")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            vec![StreamEvent::BlockDelta {
                index,
                delta: BlockDelta::Thinking {
                    text,
                    signature: None,
                },
            }]
        }
        _ => Vec::new(),
    }
}

/// Normalizes the Interactions API's `Usage` object (verified field names,
/// from a real example payload in the fetched spec: `total_input_tokens`,
/// `total_output_tokens`, `total_cached_tokens` -- distinct names from both
/// Open Responses' and legacy `generateContent`'s `Usage`/`UsageMetadata`
/// shapes). `total_input_tokens` is documented as the prompt's total token
/// count, so this satisfies the same `input_tokens >= cache_read_tokens`
/// invariant Open Responses' `input_tokens` does.
pub fn decode_interactions_usage(data: &Value) -> roundhouse_core::Usage {
    roundhouse_core::Usage {
        input_tokens: data
            .get("total_input_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        output_tokens: data
            .get("total_output_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        cache_read_tokens: data
            .get("total_cached_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    }
}

fn interactions_usage_delta(usage_json: &Value) -> StreamEvent {
    let usage = decode_interactions_usage(usage_json);
    StreamEvent::UsageDelta {
        input_tokens: Some(usage.input_tokens),
        output_tokens: Some(usage.output_tokens),
        cache_read_tokens: Some(usage.cache_read_tokens),
    }
}

// ============================================================================
// Legacy generateContent / streamGenerateContent
// ============================================================================

/// Which kind of block is currently open while decoding
/// [`decode_generate_content_stream`]'s `text`/`thought` parts -- fix-round-1
/// F8 (a `thought: true` part is a SIBLING of `text`, not an alternative to
/// it, so both are handled by the same "does a part carry `text`?" branch;
/// this distinguishes which normalized block that text belongs to).
#[derive(Clone, Copy, PartialEq, Eq)]
enum OpenTextPartKind {
    Text,
    Thinking,
}

/// Decodes the legacy surface's stream: a sequence of complete, partial
/// `GenerateContentResponse` JSON objects with no `event_type` discriminator
/// at all (verified -- requires `?alt=sse` on the URL to be framed as SSE in
/// the first place). Function calls arrive as one complete `Part` per chunk
/// (verified: `FunctionCall.args` has no delta/fragment counterpart in the
/// fetched schema), so each `functionCall` part becomes an immediate
/// `BlockStart`+`BlockDelta`+`BlockStop` triple; `text` parts are treated as
/// continuations of the currently-open text/thinking block (REALITY-
/// CORRECTIONS' "Gemini's positional-no-key parts" description, for this
/// endpoint specifically).
///
/// Fix-round-1 F2 (the one real defect this round found, and the reason it
/// went unnoticed: this path has no cassette): `StreamEvent::MessageStop` is
/// pushed ONLY when a `finishReason: "STOP"` was actually observed on some
/// chunk -- never unconditionally at end-of-body. `roundhouse-engine`'s
/// `compact.rs` detects a truncated inference *solely* by the absence of a
/// `MessageStop`; fabricating one for a connection reset, a proxy cut, or a
/// stream that simply ends without ever carrying a terminal `finishReason`
/// would have made a truncated turn persist as a completed one on an
/// immutable log -- Task 5's `response.failed`-fell-through-a-`_`-arm defect,
/// reproduced on this path. A mid-stream SSE/transport read error (`frame`
/// itself being `Err`) is likewise surfaced as a `StreamFailure` now, not
/// silently `continue`d.
async fn decode_generate_content_stream(
    body: impl Stream<Item = Result<Bytes, TransportError>> + Send + Unpin,
) -> Result<Vec<StreamEvent>, StreamFailure> {
    let mut sse = SseStream::from_bytes_stream(body);
    let mut keyer = DeltaKeyer::new();
    let mut events = Vec::new();
    let mut open_block: Option<(OpenTextPartKind, u32)> = None;
    let mut next_block_slot: u32 = 0;
    let mut next_call_slot: u32 = 0;
    let mut saw_stop = false;

    while let Some(frame) = sse.next().await {
        let frame = match frame {
            Ok(f) => f,
            Err(e) => {
                return Err(StreamFailure {
                    code: None,
                    message: redact_transport_error_text(&format!(
                        "SSE transport error while decoding the response stream: {e}"
                    )),
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

        // The prompt itself was blocked -- zero candidates returned, checked
        // before indexing into `candidates[0]` for exactly that reason.
        if let Some(reason) = payload
            .pointer("/promptFeedback/blockReason")
            .and_then(Value::as_str)
        {
            return Err(StreamFailure {
                code: None,
                message: format!("prompt blocked: {reason}"),
            });
        }

        let candidate = payload.pointer("/candidates/0");
        if let Some(finish_reason) = candidate
            .and_then(|c| c.get("finishReason"))
            .and_then(Value::as_str)
        {
            // "" / absent: "the model has not stopped generating tokens" per
            // the fetched spec -- a genuinely non-terminal, mid-stream chunk.
            // "STOP": the only success-shaped terminal reason -- recorded via
            // `saw_stop`, not acted on immediately, since usage/remaining
            // parts on this same chunk still need decoding below. Every
            // other documented `FinishReason` (`MAX_TOKENS` included -- a
            // truncated generation must not read as a clean success,
            // matching Task 5's `response.incomplete` precedent) is a
            // `StreamFailure`.
            if finish_reason == "STOP" {
                saw_stop = true;
            } else if !finish_reason.is_empty() {
                return Err(StreamFailure {
                    code: None,
                    message: format!("generation stopped: {finish_reason}"),
                });
            }
        }

        if let Some(parts) = candidate
            .and_then(|c| c.pointer("/content/parts"))
            .and_then(Value::as_array)
        {
            for part in parts {
                // Fix-round-1 F8: `thought` (verified `Part.thought: boolean`)
                // is a SIBLING field alongside `text`, not an alternative
                // union member -- a part can be `{"thought": true, "text":
                // "..."}`. Folding thought-flagged text into the visible
                // `Text` block (the original bug) leaks the model's internal
                // reasoning into the assistant-visible message and re-feeds
                // it as context on the next turn.
                let is_thought = part
                    .get("thought")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if let Some(text) = part.get("text").and_then(Value::as_str) {
                    let desired_kind = if is_thought {
                        OpenTextPartKind::Thinking
                    } else {
                        OpenTextPartKind::Text
                    };
                    let index = match open_block {
                        Some((kind, idx)) if kind == desired_kind => idx,
                        _ => {
                            if let Some((_, idx)) = open_block.take() {
                                events.push(StreamEvent::BlockStop { index: idx });
                            }
                            let idx = keyer.index_for(&format!("block-{next_block_slot}"));
                            next_block_slot += 1;
                            let block_kind = match desired_kind {
                                OpenTextPartKind::Text => BlockKind::Text,
                                OpenTextPartKind::Thinking => BlockKind::Thinking,
                            };
                            events.push(StreamEvent::BlockStart {
                                index: idx,
                                kind: block_kind,
                            });
                            open_block = Some((desired_kind, idx));
                            idx
                        }
                    };
                    let delta = match desired_kind {
                        OpenTextPartKind::Text => BlockDelta::Text(text.to_string()),
                        OpenTextPartKind::Thinking => BlockDelta::Thinking {
                            text: text.to_string(),
                            signature: part
                                .get("thoughtSignature")
                                .and_then(Value::as_str)
                                .map(str::to_string),
                        },
                    };
                    events.push(StreamEvent::BlockDelta { index, delta });
                } else if let Some(fc) = part.get("functionCall") {
                    if let Some((_, idx)) = open_block.take() {
                        events.push(StreamEvent::BlockStop { index: idx });
                    }
                    let name = fc
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    let provider_id = fc.get("id").and_then(Value::as_str).map(str::to_string);
                    let idx = keyer.index_for(&format!("call-{next_call_slot}"));
                    next_call_slot += 1;
                    events.push(StreamEvent::BlockStart {
                        index: idx,
                        kind: BlockKind::ToolUse { name, provider_id },
                    });
                    let args = fc.get("args").map(|v| v.to_string()).unwrap_or_default();
                    events.push(StreamEvent::BlockDelta {
                        index: idx,
                        delta: BlockDelta::ToolArgsFragment(args),
                    });
                    events.push(StreamEvent::BlockStop { index: idx });
                }
                // Every other part kind (`inlineData`, `executableCode`, ...):
                // no IR equivalent, skipped.
            }
        }

        if let Some(usage_json) = payload.get("usageMetadata") {
            events.push(generate_content_usage_delta(usage_json));
        }
    }

    // Fix-round-1 F2: only a genuinely observed `finishReason: "STOP"` earns
    // a `MessageStop` (and the closing `BlockStop` for whatever was still
    // open). A stream that ends without one is left unterminated on purpose
    // -- `fold_stream` records a loss event for the still-open block, and
    // `compact.rs`'s absent-`MessageStop` check correctly reports it as
    // interrupted rather than completed.
    if saw_stop {
        if let Some((_, idx)) = open_block.take() {
            events.push(StreamEvent::BlockStop { index: idx });
        }
        events.push(StreamEvent::MessageStop);
    }
    Ok(events)
}

/// Normalizes legacy `UsageMetadata` (verified field names:
/// `promptTokenCount`, `candidatesTokenCount`, `cachedContentTokenCount`).
/// `promptTokenCount` is documented as "still the total effective prompt
/// size" when `cachedContent` is set, i.e. total-inclusive-of-cache, the same
/// convention Open Responses uses (`decode_usage`'s doc comment in the
/// sibling `openai_responses` codec).
pub fn decode_generate_content_usage(data: &Value) -> roundhouse_core::Usage {
    roundhouse_core::Usage {
        input_tokens: data
            .get("promptTokenCount")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        output_tokens: data
            .get("candidatesTokenCount")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        cache_read_tokens: data
            .get("cachedContentTokenCount")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    }
}

fn generate_content_usage_delta(usage_json: &Value) -> StreamEvent {
    let usage = decode_generate_content_usage(usage_json);
    StreamEvent::UsageDelta {
        input_tokens: Some(usage.input_tokens),
        output_tokens: Some(usage.output_tokens),
        cache_read_tokens: Some(usage.cache_read_tokens),
    }
}

#[cfg(test)]
mod usage_tests {
    use super::{decode_generate_content_usage, decode_interactions_usage};

    #[test]
    fn interactions_usage_satisfies_the_input_tokens_invariant() {
        let usage_json = serde_json::json!({
            "total_input_tokens": 50,
            "total_output_tokens": 500,
            "total_cached_tokens": 20,
            "total_tokens": 570,
        });
        let usage = decode_interactions_usage(&usage_json);
        assert_eq!(usage.input_tokens, 50);
        assert_eq!(usage.output_tokens, 500);
        assert_eq!(usage.cache_read_tokens, 20);
        assert!(usage.input_tokens >= usage.cache_read_tokens);
    }

    #[test]
    fn interactions_usage_defaults_missing_fields_to_zero() {
        let usage = decode_interactions_usage(&serde_json::json!({}));
        assert_eq!(usage.input_tokens, 0);
        assert_eq!(usage.output_tokens, 0);
        assert_eq!(usage.cache_read_tokens, 0);
    }

    #[test]
    fn generate_content_usage_satisfies_the_input_tokens_invariant() {
        let usage_json = serde_json::json!({
            "promptTokenCount": 100,
            "candidatesTokenCount": 40,
            "cachedContentTokenCount": 30,
            "totalTokenCount": 140,
        });
        let usage = decode_generate_content_usage(&usage_json);
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.output_tokens, 40);
        assert_eq!(usage.cache_read_tokens, 30);
        assert!(usage.input_tokens >= usage.cache_read_tokens);
    }
}

#[cfg(test)]
mod generate_content_stream_tests {
    //! Direct unit-test coverage for `decode_generate_content_stream` --
    //! flagged in the decision doc as not covered by any required cassette
    //! (the brief runs conformance against `EndpointMode::Interactions`
    //! only). These exercise the real decode loop end to end against
    //! synthetic SSE bytes shaped like the fetched spec's real examples,
    //! not just the smaller helper functions.
    use super::decode_generate_content_stream;
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
    async fn decodes_incremental_text_into_one_block() {
        let body = sse_body(&[
            r#"{"candidates":[{"content":{"role":"model","parts":[{"text":"4"}]}}]}"#,
            r#"{"candidates":[{"content":{"role":"model","parts":[{"text":"."}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":9,"candidatesTokenCount":3,"cachedContentTokenCount":0}}"#,
        ]);
        let events = decode_generate_content_stream(body)
            .await
            .expect("must decode successfully");

        let mut texts = Vec::new();
        let mut saw_stop = false;
        let mut saw_usage = false;
        let mut saw_message_stop = false;
        for event in events {
            match event {
                StreamEvent::BlockStart {
                    kind: BlockKind::Text,
                    ..
                } => {}
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
        assert!(saw_stop, "the open text block must be closed");
        assert!(saw_usage);
        assert!(saw_message_stop);
    }

    #[tokio::test]
    async fn decodes_a_complete_function_call_as_one_atomic_triple() {
        let body = sse_body(&[
            r#"{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"id":"call_1","name":"get_weather","args":{"location":"Tokyo"}}}]},"finishReason":"STOP"}]}"#,
        ]);
        let events = decode_generate_content_stream(body)
            .await
            .expect("must decode successfully");

        let mut saw_start = false;
        let mut saw_args = false;
        let mut saw_stop = false;
        for event in events {
            match event {
                StreamEvent::BlockStart {
                    kind: BlockKind::ToolUse { name, .. },
                    ..
                } => {
                    assert_eq!(name, "get_weather");
                    saw_start = true;
                }
                StreamEvent::BlockDelta {
                    delta: BlockDelta::ToolArgsFragment(args),
                    ..
                } => {
                    assert!(args.contains("Tokyo"));
                    saw_args = true;
                }
                StreamEvent::BlockStop { .. } => saw_stop = true,
                StreamEvent::MessageStop => {}
                // `StreamEvent` derives no `Debug` (REALITY-CORRECTIONS
                // §14c), so an unexpected variant is named by kind, not
                // formatted.
                StreamEvent::BlockStart { .. } => panic!("unexpected BlockStart kind"),
                StreamEvent::BlockDelta { .. } => panic!("unexpected BlockDelta kind"),
                StreamEvent::UsageDelta { .. } => panic!("unexpected UsageDelta"),
            }
        }
        assert!(saw_start && saw_args && saw_stop);
    }

    /// `Result::expect_err` needs `T: Debug`, and `Vec<StreamEvent>` isn't
    /// (`StreamEvent` derives none, REALITY-CORRECTIONS §14c) -- matches
    /// `conformance_google_genai.rs`'s identical `expect_err` helper.
    fn expect_stream_failure(
        result: Result<Vec<StreamEvent>, super::StreamFailure>,
    ) -> super::StreamFailure {
        match result {
            Ok(_) => panic!("expected a StreamFailure, got a successful decode"),
            Err(failure) => failure,
        }
    }

    #[tokio::test]
    async fn max_tokens_finish_reason_is_a_stream_failure_not_a_silent_success() {
        let body = sse_body(&[
            r#"{"candidates":[{"content":{"role":"model","parts":[{"text":"partial"}]},"finishReason":"MAX_TOKENS"}]}"#,
        ]);
        let err = expect_stream_failure(decode_generate_content_stream(body).await);
        assert!(err.message.contains("MAX_TOKENS"));
    }

    #[tokio::test]
    async fn a_blocked_prompt_is_a_stream_failure() {
        let body = sse_body(&[r#"{"promptFeedback":{"blockReason":"SAFETY"},"candidates":[]}"#]);
        let err = expect_stream_failure(decode_generate_content_stream(body).await);
        assert!(err.message.contains("SAFETY"));
    }

    /// Fix-round-1 F2 (the one real defect this round found): a stream that
    /// ends without ever carrying a terminal `finishReason` -- a connection
    /// reset, a proxy cut, or simply a truncated body -- must NOT fabricate
    /// `StreamEvent::MessageStop`. `roundhouse-engine`'s `compact.rs` detects
    /// truncation solely by that event's absence; fabricating it here would
    /// have made a truncated inference read as a completed one.
    #[tokio::test]
    async fn a_stream_with_no_observed_finish_reason_does_not_fabricate_message_stop() {
        let body = sse_body(&[
            r#"{"candidates":[{"content":{"role":"model","parts":[{"text":"partial"}]}}]}"#,
        ]);
        let events = decode_generate_content_stream(body)
            .await
            .expect("an unterminated stream is not itself an error -- just unterminated");
        assert!(
            !events.iter().any(|e| matches!(e, StreamEvent::MessageStop)),
            "a stream that ends with no observed finishReason must not fabricate a terminal \
             MessageStop"
        );
    }

    /// The success-path complement: a real `finishReason: \"STOP\"` DOES
    /// still earn a `MessageStop` (proves the fix didn't just delete the
    /// event unconditionally).
    #[tokio::test]
    async fn a_stream_that_actually_observes_stop_does_emit_message_stop() {
        let body = sse_body(&[
            r#"{"candidates":[{"content":{"role":"model","parts":[{"text":"done"}]},"finishReason":"STOP"}]}"#,
        ]);
        let events = decode_generate_content_stream(body)
            .await
            .expect("must decode successfully");
        assert!(
            events.iter().any(|e| matches!(e, StreamEvent::MessageStop)),
            "a stream that genuinely observed finishReason: STOP must still emit MessageStop"
        );
    }

    /// Fix-round-1 F8: `{"thought": true, "text": "..."}` is a SIBLING shape
    /// (verified `Part.thought: boolean`, not an alternative union member) --
    /// it must open a `Thinking` block, not fold into the visible `Text`
    /// block the way the original code did.
    #[tokio::test]
    async fn a_thought_flagged_part_opens_a_thinking_block_not_visible_text() {
        let body = sse_body(&[
            r#"{"candidates":[{"content":{"role":"model","parts":[{"thought":true,"text":"Let me reason about this."},{"text":"The answer is 4."}]},"finishReason":"STOP"}]}"#,
        ]);
        let events = decode_generate_content_stream(body)
            .await
            .expect("must decode successfully");

        let mut thinking_texts = Vec::new();
        let mut visible_texts = Vec::new();
        let mut saw_thinking_start = false;
        let mut saw_text_start = false;
        for event in events {
            match event {
                StreamEvent::BlockStart {
                    kind: BlockKind::Thinking,
                    ..
                } => saw_thinking_start = true,
                StreamEvent::BlockStart {
                    kind: BlockKind::Text,
                    ..
                } => saw_text_start = true,
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
        assert!(
            saw_thinking_start,
            "a thought-flagged part must open a Thinking block"
        );
        assert!(
            saw_text_start,
            "the following non-thought part must open a separate Text block"
        );
        assert_eq!(
            thinking_texts,
            vec!["Let me reason about this.".to_string()]
        );
        assert_eq!(
            visible_texts,
            vec!["The answer is 4.".to_string()],
            "the model's internal reasoning must not leak into the visible assistant text"
        );
    }
}

#[cfg(test)]
mod interactions_terminal_tests {
    use super::{decode_step_start, decode_step_stop, StepKeyer};
    use crate::stream_event::{BlockKind, StreamEvent};

    /// Mirrors `openai_responses::decode`'s `an_unrecognized_item_type_never_
    /// consumes_an_index`, extended to also cover `step.stop` (that codec's
    /// fix only needed to cover `output_item.added`, since it has no
    /// separate `.stop` event using the same shared index space the way this
    /// one does).
    #[test]
    fn an_unrecognized_step_type_never_consumes_an_index_and_its_stop_is_ignored() {
        let mut keyer = StepKeyer::new();

        let unrecognized = serde_json::json!({
            "event_type": "step.start",
            "index": 0,
            "step": { "type": "user_input" }
        });
        assert!(decode_step_start(&unrecognized, &mut keyer).is_none());

        let unrecognized_stop = serde_json::json!({
            "event_type": "step.stop",
            "index": 0
        });
        assert!(
            decode_step_stop(&unrecognized_stop, &mut keyer).is_none(),
            "a step.stop for a step type this decoder never opened must not \
             fabricate a BlockStop"
        );

        let recognized = serde_json::json!({
            "event_type": "step.start",
            "index": 1,
            "step": { "type": "model_output" }
        });
        let event = decode_step_start(&recognized, &mut keyer)
            .expect("a model_output step must produce a BlockStart");
        assert!(
            matches!(
                event,
                StreamEvent::BlockStart {
                    index: 0,
                    kind: BlockKind::Text
                }
            ),
            "the first REAL block must land on index 0, not 1 -- the earlier \
             unrecognized step must not have consumed an index"
        );
    }
}

#[cfg(test)]
mod transport_error_redaction_tests {
    //! Fix round 6, J3: `decode_interactions_stream`/
    //! `decode_generate_content_stream` build `StreamFailure.message` from a
    //! bare `{e}` interpolation of the underlying `TransportError`. That
    //! leaked nothing in production only because `errors.rs::classify`
    //! hardcodes `body_snippet: String::new()` -- a field documented as
    //! empty "only because no redaction pass existed yet" -- so the
    //! guarantee must live at the source, not rest on that downstream dead
    //! end. Both sites now wrap the message in `redact_transport_error_text`.
    use super::{decode_generate_content_stream, decode_interactions_stream};
    use crate::TransportError;
    use futures::stream;

    fn failing_body(
        message: &str,
    ) -> impl futures::Stream<Item = Result<bytes::Bytes, TransportError>> {
        stream::iter(vec![Err(TransportError::Io(message.to_string()))])
    }

    #[tokio::test]
    async fn interactions_stream_redacts_a_transport_error_carrying_a_credentialed_url() {
        let body = failing_body(
            "error sending request for url \
             (https://gwuser:gwpass@gateway.example.invalid/v1?key=gw-live-9f2b8c1d4e6a7b3c)",
        );
        let failure = match decode_interactions_stream(body).await {
            Ok(_) => panic!("a transport error must surface as a StreamFailure"),
            Err(failure) => failure,
        };
        assert!(
            !failure.message.contains("gw-live-9f2b8c1d4e6a7b3c"),
            "the key-shaped query value leaked unredacted: {}",
            failure.message
        );
        assert!(
            !failure.message.contains("gwuser:gwpass"),
            "URL userinfo leaked unredacted: {}",
            failure.message
        );
        assert!(
            failure.message.contains("gateway.example.invalid"),
            "the host itself is not secret and should survive for diagnosability: {}",
            failure.message
        );
    }

    #[tokio::test]
    async fn generate_content_stream_redacts_a_transport_error_carrying_a_credentialed_url() {
        let body = failing_body(
            "error sending request for url \
             (https://gwuser:gwpass@gateway.example.invalid/v1?key=gw-live-9f2b8c1d4e6a7b3c)",
        );
        let failure = match decode_generate_content_stream(body).await {
            Ok(_) => panic!("a transport error must surface as a StreamFailure"),
            Err(failure) => failure,
        };
        assert!(
            !failure.message.contains("gw-live-9f2b8c1d4e6a7b3c"),
            "the key-shaped query value leaked unredacted: {}",
            failure.message
        );
        assert!(
            !failure.message.contains("gwuser:gwpass"),
            "URL userinfo leaked unredacted: {}",
            failure.message
        );
        assert!(
            failure.message.contains("gateway.example.invalid"),
            "the host itself is not secret and should survive for diagnosability: {}",
            failure.message
        );
    }
}
