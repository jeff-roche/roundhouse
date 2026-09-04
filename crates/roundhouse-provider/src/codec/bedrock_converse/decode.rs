//! Decodes a Bedrock `ConverseStream` response body -- binary
//! `application/vnd.amazon.eventstream` framing, not SSE -- into normalized
//! [`StreamEvent`]s. Field names and wire literals verified against the real
//! fetched AWS API Reference; see this codec's `mod.rs` doc comment for the
//! fetch record.
//!
//! Framing itself is decoded by [`crate::transport::eventstream::EventStreamDecoder`]
//! (the `sigv4-eventstream` shim), which owns every byte of prelude/CRC/
//! header handling via `aws-smithy-eventstream`. This module's job is
//! narrower: given a decoded [`Message`], read its `:message-type` /
//! `:event-type` / `:exception-type` headers and its JSON payload, and
//! produce the right [`StreamEvent`]s or the right [`StreamFailure`].
//!
//! **Every one of the wire format's failure/terminal signals is enumerated
//! explicitly** (REALITY-CORRECTIONS §13b item 4): the 5 in-band
//! `ConverseStreamOutput` exception members
//! (`internalServerException`/`modelStreamErrorException`/
//! `serviceUnavailableException`/`throttlingException`/`validationException`,
//! confirmed from the fetched `ConverseStream` response syntax) and a bare
//! `:message-type: error` frame (the protocol's own generic/unmodeled error
//! frame, per <https://smithy.io/2.0/aws/amazon-eventstream.html>) both
//! become an `Err(StreamFailure)`, never a silently-skipped frame. Nothing
//! here fabricates a `MessageStop` it did not actually observe on the wire.

use bytes::Bytes;
use futures::{Stream, StreamExt};
use serde_json::Value;
use std::collections::HashMap;

use crate::audit::redact_transport_error_text;
use crate::stream_event::{BlockDelta, BlockKind, DeltaKeyer, StreamEvent};
use crate::transport::eventstream::{EventStreamDecodeError, EventStreamDecoder};
use crate::TransportError;
use aws_smithy_types::event_stream::Message;

/// A terminal failure signaled by the wire, mirroring
/// `openai_responses`/`google_genai`'s `StreamFailure` -- deliberately not a
/// `ProviderError` (this module has no `ProviderProfile` to classify
/// through); `provider.rs` maps this into the real `ProviderError` once
/// decoding stops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFailure {
    /// The exception/error shape name, when the frame carried one
    /// (`ThrottlingException`, `ValidationException`, ...; `None` for a
    /// transport/framing-level failure that never reached a well-formed
    /// frame at all).
    pub code: Option<String>,
    pub message: String,
}

/// The 5 real `ConverseStreamOutput` exception union members (verified,
/// case-normalized to PascalCase to match the shape-name convention every
/// other Bedrock exception in this codec uses -- see
/// `is_recognized_exception_type`'s doc comment for why this decoder
/// compares case-insensitively rather than betting on one exact casing).
const KNOWN_EXCEPTION_SHAPES: [&str; 5] = [
    "InternalServerException",
    "ModelStreamErrorException",
    "ServiceUnavailableException",
    "ThrottlingException",
    "ValidationException",
];

/// True if `exception_type` (whatever casing the wire actually used for the
/// `:exception-type` header) names one of the 5 real, fetched
/// `ConverseStreamOutput` exception members.
///
/// Compared case-insensitively rather than against one fixed casing: the
/// fetched `ConverseStream` API Reference documents these as camelCase JSON
/// union member names (`throttlingException`, ...) for its own response-body
/// documentation purposes, while AWS's eventstream protocol convention
/// (verified at the smithy.io spec) is for `:exception-type` to carry the
/// exception *shape's* name, which for every other Bedrock exception in this
/// same family is PascalCase (`ThrottlingException`, matching the profile's
/// own `[errors]` table and the `Converse`/`ConverseStream` "Errors" section
/// this codec's tripwire test vendors). This crate has no live capture of an
/// actual wire byte sequence to pin the exact casing with certainty --
/// comparing case-insensitively means a real frame is recognized as the
/// exception it is either way, rather than this decoder silently treating a
/// genuine, well-formed exception as an unrecognized frame to skip over
/// because of a casing guess.
fn is_recognized_exception_type(exception_type: &str) -> Option<&'static str> {
    KNOWN_EXCEPTION_SHAPES
        .iter()
        .find(|known| known.eq_ignore_ascii_case(exception_type))
        .copied()
}

fn header_str<'a>(message: &'a Message, name: &str) -> Option<&'a str> {
    message
        .headers()
        .iter()
        .find(|h| h.name().as_str().eq_ignore_ascii_case(name))
        .and_then(|h| h.value().as_string().ok())
        .map(|s| s.as_str())
}

fn parse_payload(message: &Message) -> Option<Value> {
    serde_json::from_slice(message.payload().as_ref()).ok()
}

fn payload_message_field(payload: &Value) -> Option<&str> {
    payload.get("message").and_then(Value::as_str)
}

/// Decodes `body` into normalized [`StreamEvent`]s, or a [`StreamFailure`]
/// if the eventstream itself fails to frame correctly, or if a modeled
/// exception / generic error frame arrives. Malformed or genuinely
/// unrecognized `:event-type` values are skipped (matching this crate's
/// established precedent), but the failure/terminal signals enumerated in
/// this module's doc comment are never in that "skip" bucket.
pub async fn decode_bedrock_converse_stream(
    mut body: impl Stream<Item = Result<Bytes, TransportError>> + Send + Unpin,
) -> Result<Vec<StreamEvent>, StreamFailure> {
    let mut decoder = EventStreamDecoder::new();
    let mut keyer = DeltaKeyer::new();
    let mut opened_kinds: HashMap<u32, BlockKind> = HashMap::new();
    let mut events = Vec::new();

    while let Some(chunk) = body.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            Err(e) => {
                return Err(StreamFailure {
                    code: None,
                    message: redact_transport_error_text(&format!(
                        "transport error while decoding the bedrock-converse eventstream: {e}"
                    )),
                })
            }
        };

        let messages = match decoder.feed(&chunk) {
            Ok(messages) => messages,
            // Fix-round-1 H4: dead today (this loop always returns on the
            // very first `Err` from `feed`, so a *second* call that could
            // observe `Poisoned` never happens) -- but "abandon the stream,
            // report success" is exactly the shape that produced this
            // phase's two prior Criticals in the SSE codecs, and it stops
            // being dead the moment this decoder is ever hoisted or reused
            // across calls. Must never silently fall through to `Ok`.
            Err(EventStreamDecodeError::Poisoned) => {
                return Err(StreamFailure {
                    code: None,
                    message: "eventstream decoder already poisoned by a previous framing error"
                        .to_string(),
                })
            }
            Err(e) => {
                return Err(StreamFailure {
                    code: None,
                    message: redact_transport_error_text(&format!(
                        "eventstream framing error: {e}"
                    )),
                })
            }
        };

        for message in &messages {
            if let Some(failure) = terminal_failure(message) {
                return Err(failure);
            }
            decode_event(message, &mut keyer, &mut opened_kinds, &mut events);
        }
    }

    // Fix-round-1 H2: binary framing makes truncation POSITIVELY detectable
    // in a way SSE cannot be -- the decoder knows exactly when it is sitting
    // on a partial, not-yet-complete frame. A transport stream that ends
    // while that is true means the underlying connection was cut mid-frame
    // (e.g. mid-generation), not that the model cleanly finished producing
    // events; persisting the events decoded so far as `Ok` would let a
    // truncated inference read as a normally-completed one on a
    // physically-immutable event log. This is distinct from -- and must not
    // be conflated with -- a body that ends cleanly at a frame boundary but
    // never sent `messageStop` at all, which is handled by that event's own
    // absence (no `StreamEvent::MessageStop` is ever fabricated) rather than
    // as a hard decode error here.
    if decoder.is_mid_frame() {
        return Err(StreamFailure {
            code: None,
            message: "eventstream body ended mid-frame".to_string(),
        });
    }

    Ok(events)
}

/// Recognizes a `:message-type: exception` frame (one of the 5 modeled
/// `ConverseStreamOutput` exceptions) or a `:message-type: error` frame (the
/// protocol's generic/unmodeled error, per the smithy.io spec) as a terminal
/// [`StreamFailure`]. Returns `None` for a `:message-type: event` frame (or
/// anything else) -- those are handled by [`decode_event`] instead.
fn terminal_failure(message: &Message) -> Option<StreamFailure> {
    let message_type = header_str(message, ":message-type")?;
    match message_type {
        "exception" => {
            let exception_type = header_str(message, ":exception-type").unwrap_or("");
            let code = is_recognized_exception_type(exception_type)
                .map(str::to_string)
                .or_else(|| {
                    if exception_type.is_empty() {
                        None
                    } else {
                        Some(exception_type.to_string())
                    }
                });
            let payload = parse_payload(message);
            let text_message = payload
                .as_ref()
                .and_then(payload_message_field)
                .map(str::to_string)
                .unwrap_or_else(|| {
                    format!(
                        "bedrock-converse eventstream exception frame with no `message` field \
                         (exception-type: {exception_type:?})"
                    )
                });
            Some(StreamFailure {
                code,
                message: text_message,
            })
        }
        "error" => {
            let code = header_str(message, ":error-code").map(str::to_string);
            let text_message = header_str(message, ":error-message")
                .map(str::to_string)
                .unwrap_or_else(|| {
                    "bedrock-converse eventstream emitted a generic :message-type: error frame \
                     with no :error-message header"
                        .to_string()
                });
            Some(StreamFailure {
                code,
                message: text_message,
            })
        }
        _ => None,
    }
}

/// Decodes a `:message-type: event` frame's `:event-type` header and JSON
/// payload into zero or more [`StreamEvent`]s.
///
/// `opened_kinds` tracks which wire `contentBlockIndex` values have already
/// been opened (and what kind) -- necessary because, per this codec's
/// `mod.rs` doc comment (divergence 2), text and reasoning-content blocks
/// have NO `contentBlockStart` event at all: they begin implicitly with
/// their first `contentBlockDelta`. A `BlockStart` is synthesized here on
/// first sight of such a delta, rather than waiting for an event Bedrock
/// never sends for these two block kinds.
fn decode_event(
    message: &Message,
    keyer: &mut DeltaKeyer,
    opened_kinds: &mut HashMap<u32, BlockKind>,
    events: &mut Vec<StreamEvent>,
) {
    let Some(event_type) = header_str(message, ":event-type") else {
        return;
    };
    let Some(payload) = parse_payload(message) else {
        return;
    };

    match event_type {
        "contentBlockStart" => decode_content_block_start(&payload, keyer, opened_kinds, events),
        "contentBlockDelta" => decode_content_block_delta(&payload, keyer, opened_kinds, events),
        "contentBlockStop" => decode_content_block_stop(&payload, keyer, opened_kinds, events),
        "messageStop" => events.push(StreamEvent::MessageStop),
        "metadata" => {
            if let Some(usage) = payload.get("usage") {
                events.push(usage_delta(usage));
            }
        }
        // `messageStart` carries only `role`, which the IR has nowhere to
        // put (REALITY-CORRECTIONS §1: no `MessageStart` variant exists) --
        // a recognized, real event with genuinely nothing for this decoder
        // to do with it, same as every sibling codec's precedent for the
        // wire's own message-start echo.
        "messageStart" => {}
        _ => {}
    }
}

fn wire_index(payload: &Value) -> Option<u32> {
    payload
        .get("contentBlockIndex")
        .and_then(Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
}

/// `contentBlockStart`: `{contentBlockIndex, start}`, `start` a one-member
/// union in practice for this codec's scope -- only `toolUse` (`image`/
/// `toolResult` starts are model-output shapes this codec has no IR
/// equivalent to open; skipped, matching the "no IR equivalent" convention
/// every sibling decoder already uses for e.g. Gemini's built-in-tool steps).
fn decode_content_block_start(
    payload: &Value,
    keyer: &mut DeltaKeyer,
    opened_kinds: &mut HashMap<u32, BlockKind>,
    events: &mut Vec<StreamEvent>,
) {
    let Some(index) = wire_index(payload) else {
        return;
    };
    let Some(tool_use) = payload.pointer("/start/toolUse") else {
        return;
    };
    let name = tool_use
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let provider_id = tool_use
        .get("toolUseId")
        .and_then(Value::as_str)
        .map(str::to_string);
    let kind = BlockKind::ToolUse { name, provider_id };
    open_block(index, kind, keyer, opened_kinds, events);
}

fn open_block(
    wire_index: u32,
    kind: BlockKind,
    keyer: &mut DeltaKeyer,
    opened_kinds: &mut HashMap<u32, BlockKind>,
    events: &mut Vec<StreamEvent>,
) -> u32 {
    let normalized = keyer.index_for(&wire_index.to_string());
    opened_kinds.insert(wire_index, kind.clone());
    events.push(StreamEvent::BlockStart {
        index: normalized,
        kind,
    });
    normalized
}

/// `contentBlockDelta`: `{contentBlockIndex, delta}`, `delta` discriminated
/// by which of the real `ContentBlockDelta` union's keys is present:
/// `text` (String), `toolUse.input` (String, a JSON-fragment accumulator),
/// `reasoningContent.text` / `.signature` (both String; `.redactedContent`
/// is base64 opaque data with no IR field to carry it and is skipped, same
/// "no IR equivalent" convention as above). `citation`/`image`/`toolResult`
/// deltas are model-output shapes with no IR equivalent either.
fn decode_content_block_delta(
    payload: &Value,
    keyer: &mut DeltaKeyer,
    opened_kinds: &mut HashMap<u32, BlockKind>,
    events: &mut Vec<StreamEvent>,
) {
    let Some(wire_idx) = wire_index(payload) else {
        return;
    };
    let Some(delta) = payload.get("delta") else {
        return;
    };

    if let Some(text) = delta.get("text").and_then(Value::as_str) {
        let index = index_for_implicit_open(wire_idx, BlockKind::Text, keyer, opened_kinds, events);
        events.push(StreamEvent::BlockDelta {
            index,
            delta: BlockDelta::Text(text.to_string()),
        });
        return;
    }

    if let Some(input) = delta.pointer("/toolUse/input").and_then(Value::as_str) {
        // A tool-use delta can only legitimately follow a `contentBlockStart`
        // that already opened this index with the tool's name/id -- unlike
        // text/reasoning, there is no implicit-open fallback here (matches
        // `openai_responses`' precedent: a delta with no matching open index
        // is dropped, not fabricated into a nameless tool call).
        let Some(index) = existing_index(wire_idx, keyer, opened_kinds) else {
            return;
        };
        events.push(StreamEvent::BlockDelta {
            index,
            delta: BlockDelta::ToolArgsFragment(input.to_string()),
        });
        return;
    }

    if let Some(text) = delta
        .pointer("/reasoningContent/text")
        .and_then(Value::as_str)
    {
        let index =
            index_for_implicit_open(wire_idx, BlockKind::Thinking, keyer, opened_kinds, events);
        events.push(StreamEvent::BlockDelta {
            index,
            delta: BlockDelta::Thinking {
                text: text.to_string(),
                signature: None,
            },
        });
        return;
    }

    if let Some(signature) = delta
        .pointer("/reasoningContent/signature")
        .and_then(Value::as_str)
    {
        let index =
            index_for_implicit_open(wire_idx, BlockKind::Thinking, keyer, opened_kinds, events);
        events.push(StreamEvent::BlockDelta {
            index,
            delta: BlockDelta::Thinking {
                text: String::new(),
                signature: Some(signature.to_string()),
            },
        });
    }
    // `reasoningContent.redactedContent`, `citation`, `image`, `toolResult`:
    // no IR equivalent, skipped.
}

/// The wire index for a delta kind that has NO explicit `contentBlockStart`
/// on this wire format (text, reasoning content -- see this codec's `mod.rs`
/// doc comment) -- opens it on first sight if not already open, otherwise
/// returns the existing normalized index. Never re-opens (and never
/// re-inserts into `opened_kinds`) an index that's already open, so a block
/// that mixes multiple reasoning-delta shapes (`text` then `signature`)
/// still maps to one stable index.
fn index_for_implicit_open(
    wire_idx: u32,
    kind: BlockKind,
    keyer: &mut DeltaKeyer,
    opened_kinds: &mut HashMap<u32, BlockKind>,
    events: &mut Vec<StreamEvent>,
) -> u32 {
    if opened_kinds.contains_key(&wire_idx) {
        keyer.index_for(&wire_idx.to_string())
    } else {
        open_block(wire_idx, kind, keyer, opened_kinds, events)
    }
}

/// The normalized index for `wire_idx`, but only if it was previously opened
/// -- `None` otherwise, without ever calling `index_for` (which would burn a
/// slot for a delta that arrived with no matching open block). Mirrors
/// `google_genai::decode::StepKeyer::existing`.
fn existing_index(
    wire_idx: u32,
    keyer: &mut DeltaKeyer,
    opened_kinds: &HashMap<u32, BlockKind>,
) -> Option<u32> {
    if opened_kinds.contains_key(&wire_idx) {
        Some(keyer.index_for(&wire_idx.to_string()))
    } else {
        None
    }
}

fn decode_content_block_stop(
    payload: &Value,
    keyer: &mut DeltaKeyer,
    opened_kinds: &mut HashMap<u32, BlockKind>,
    events: &mut Vec<StreamEvent>,
) {
    let Some(wire_idx) = wire_index(payload) else {
        return;
    };
    let Some(index) = existing_index(wire_idx, keyer, opened_kinds) else {
        return;
    };
    opened_kinds.remove(&wire_idx);
    events.push(StreamEvent::BlockStop { index });
}

/// Normalizes `metadata.usage` (verified `TokenUsage`: `inputTokens`,
/// `outputTokens`, `cacheReadInputTokens`, `cacheWriteInputTokens`,
/// `totalTokens`).
///
/// `inputTokens` is documented ("the number of tokens sent in the request to
/// the model") without stating explicitly whether it already includes cache
/// reads. This decoder treats it as EXCLUDING them (adding
/// `cacheReadInputTokens` back in, mirroring
/// `anthropic_messages::decode::normalize_anthropic_usage`'s identical
/// pattern for Anthropic's own native API) on the strength of two
/// corroborating community sources rather than an explicit AWS sentence:
/// LiteLLM's cross-provider usage normalization
/// (`fix(bedrock): include cacheWriteInputTokens in prompt_tokens`) treats
/// `inputTokens` as needing cache figures added back for a true prompt-size
/// total, and Bedrock's own Anthropic-family models are documented elsewhere
/// to follow Anthropic's native convention (input_tokens excludes cache
/// reads) end to end. Flagged here, and in the task report, as the one usage
/// fact this codec could not pin down from an explicit first-party AWS
/// sentence.
pub fn decode_usage(data: &Value) -> roundhouse_core::Usage {
    let input_tokens = data.get("inputTokens").and_then(Value::as_u64).unwrap_or(0);
    let cache_read_tokens = data
        .get("cacheReadInputTokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    roundhouse_core::Usage {
        input_tokens: input_tokens.saturating_add(cache_read_tokens),
        output_tokens: data
            .get("outputTokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        cache_read_tokens,
    }
}

fn usage_delta(usage_json: &Value) -> StreamEvent {
    let usage = decode_usage(usage_json);
    StreamEvent::UsageDelta {
        input_tokens: Some(usage.input_tokens),
        output_tokens: Some(usage.output_tokens),
        cache_read_tokens: Some(usage.cache_read_tokens),
    }
}

#[cfg(test)]
mod usage_tests {
    use super::decode_usage;

    /// Asserts something that is FALSE if `cacheReadInputTokens` fails to
    /// decode (REALITY-CORRECTIONS §13b item 6: "assert something that is
    /// false when a field fails to decode, not something vacuously true at
    /// zero") -- `10 >= 10` only holds because `cache_read_tokens` was
    /// genuinely added into `input_tokens`; a decoder that dropped
    /// `cacheReadInputTokens` entirely would produce `input_tokens: 40`,
    /// still satisfying `>=` vacuously, so this also pins the EXACT summed
    /// value, not just the inequality.
    #[test]
    fn usage_adds_cache_read_tokens_into_input_tokens() {
        let usage_json = serde_json::json!({
            "inputTokens": 40,
            "outputTokens": 25,
            "totalTokens": 75,
            "cacheReadInputTokens": 10,
            "cacheWriteInputTokens": 0,
        });
        let usage = decode_usage(&usage_json);
        assert_eq!(usage.input_tokens, 50, "40 base + 10 cache-read");
        assert_eq!(usage.output_tokens, 25);
        assert_eq!(usage.cache_read_tokens, 10);
        assert!(usage.input_tokens >= usage.cache_read_tokens);
    }

    #[test]
    fn usage_defaults_missing_fields_to_zero_rather_than_panicking() {
        let usage = decode_usage(&serde_json::json!({}));
        assert_eq!(usage.input_tokens, 0);
        assert_eq!(usage.output_tokens, 0);
        assert_eq!(usage.cache_read_tokens, 0);
    }
}

#[cfg(test)]
mod exception_recognition_tests {
    use super::is_recognized_exception_type;

    #[test]
    fn recognizes_the_five_real_exception_shapes_case_insensitively() {
        for (pascal, camel) in [
            ("InternalServerException", "internalServerException"),
            ("ModelStreamErrorException", "modelStreamErrorException"),
            ("ServiceUnavailableException", "serviceUnavailableException"),
            ("ThrottlingException", "throttlingException"),
            ("ValidationException", "validationException"),
        ] {
            assert_eq!(is_recognized_exception_type(pascal), Some(pascal));
            assert_eq!(is_recognized_exception_type(camel), Some(pascal));
        }
    }

    #[test]
    fn an_unrecognized_exception_type_is_not_silently_accepted_as_a_known_one() {
        assert_eq!(is_recognized_exception_type("SomeFutureException"), None);
    }
}

#[cfg(test)]
mod stream_decode_tests {
    //! Direct unit coverage for `decode_bedrock_converse_stream`, encoding
    //! real eventstream frames in-process (same `aws_smithy_eventstream::
    //! frame::write_message_to` this module decodes with -- see
    //! `examples/gen_bedrock_cassettes.rs`'s doc comment for why that's not
    //! a hand-computed-CRC fixture) rather than only exercising this logic
    //! indirectly through a `.cassette` file.
    use super::decode_bedrock_converse_stream;
    use crate::stream_event::{BlockDelta, BlockKind, StreamEvent};
    use aws_smithy_eventstream::frame::write_message_to;
    use aws_smithy_types::event_stream::{Header, HeaderValue, Message};
    use futures::stream;

    fn event(event_type: &str, payload: serde_json::Value) -> Message {
        Message::new(serde_json::to_vec(&payload).unwrap())
            .add_header(Header::new(
                ":message-type",
                HeaderValue::String("event".into()),
            ))
            .add_header(Header::new(
                ":event-type",
                HeaderValue::String(event_type.to_string().into()),
            ))
    }

    fn exception(exception_type: &str, payload: serde_json::Value) -> Message {
        Message::new(serde_json::to_vec(&payload).unwrap())
            .add_header(Header::new(
                ":message-type",
                HeaderValue::String("exception".into()),
            ))
            .add_header(Header::new(
                ":exception-type",
                HeaderValue::String(exception_type.to_string().into()),
            ))
    }

    fn body(
        messages: &[Message],
    ) -> impl futures::Stream<Item = Result<bytes::Bytes, crate::TransportError>> {
        let mut raw = Vec::new();
        for m in messages {
            write_message_to(m, &mut raw).unwrap();
        }
        stream::iter(vec![Ok(bytes::Bytes::from(raw))])
    }

    fn raw_body(
        raw: Vec<u8>,
    ) -> impl futures::Stream<Item = Result<bytes::Bytes, crate::TransportError>> {
        stream::iter(vec![Ok(bytes::Bytes::from(raw))])
    }

    /// Mirrors `google_genai`/`openai_responses`' identical fix-round-1
    /// finding: a stream that ends with no observed `messageStop` must NOT
    /// fabricate one. `roundhouse-engine`'s `compact.rs` detects a truncated
    /// inference solely by that event's absence.
    #[tokio::test]
    async fn a_stream_with_no_messagestop_event_does_not_fabricate_one() {
        let messages = [
            event("messageStart", serde_json::json!({ "role": "assistant" })),
            event(
                "contentBlockDelta",
                serde_json::json!({ "contentBlockIndex": 0, "delta": { "text": "partial" } }),
            ),
        ];
        let events = decode_bedrock_converse_stream(body(&messages))
            .await
            .expect("an unterminated stream is not itself an error");
        assert!(
            !events.iter().any(|e| matches!(e, StreamEvent::MessageStop)),
            "must not fabricate MessageStop when the wire never sent messageStop"
        );
    }

    /// Fix-round-1 H2: unlike an SSE codec, binary framing makes truncation
    /// POSITIVELY detectable -- the decoder knows it is sitting on a
    /// partial, not-yet-complete frame. Cuts a well-formed message's
    /// encoded bytes in half (never at a frame boundary) after a prior,
    /// fully complete message, and asserts the whole decode is an `Err`
    /// naming "mid-frame" -- not a silent `Ok` carrying only the events from
    /// the complete message that preceded it.
    #[tokio::test]
    async fn a_body_that_ends_mid_frame_is_an_error_not_a_silent_partial_success() {
        let complete = event("messageStart", serde_json::json!({ "role": "assistant" }));
        let truncated = event(
            "contentBlockDelta",
            serde_json::json!({ "contentBlockIndex": 0, "delta": { "text": "partial" } }),
        );

        let mut raw = Vec::new();
        write_message_to(&complete, &mut raw).unwrap();
        let mut truncated_bytes = Vec::new();
        write_message_to(&truncated, &mut truncated_bytes).unwrap();
        // Cut the second message's bytes in half -- well past its 12-byte
        // prelude, so this is genuinely mid-frame, not merely "prelude not
        // yet readable."
        raw.extend_from_slice(&truncated_bytes[..truncated_bytes.len() / 2]);

        let failure = expect_stream_failure(decode_bedrock_converse_stream(raw_body(raw)).await);
        assert!(
            failure.message.contains("mid-frame"),
            "expected a mid-frame truncation message, got: {failure:?}"
        );
    }

    /// A 12-byte prelude claiming a plausible `total_length`, matching
    /// `transport::eventstream::tests::plausible_prelude_bytes` -- the
    /// vendored decoder never validates the prelude CRC on the `Incomplete`
    /// path, so the trailing 4 bytes are never checked and can be anything.
    fn plausible_prelude_bytes(claimed_total_len: u32) -> [u8; 12] {
        let mut prelude = [0u8; 12];
        prelude[0..4].copy_from_slice(&claimed_total_len.to_be_bytes());
        prelude[4..8].copy_from_slice(&0u32.to_be_bytes());
        prelude[8..12].copy_from_slice(&0u32.to_be_bytes());
        prelude
    }

    /// Fix-round-2 J1, CASE A through the full pipeline: a cut at
    /// `len()/2` (the pre-existing test above) cannot see this bug --
    /// `MessageFrameDecoder::decode_frame` consumes a frame's 12-byte
    /// prelude out of the buffer as soon as it's available, so a body
    /// ending in exactly a complete frame plus the next frame's bare
    /// 12-byte prelude leaves the accumulator buffer EMPTY while the
    /// decoder is still squarely mid-frame.
    #[tokio::test]
    async fn a_body_ending_in_exactly_a_bare_next_prelude_is_mid_frame() {
        let complete = event("messageStart", serde_json::json!({ "role": "assistant" }));
        let mut raw = Vec::new();
        write_message_to(&complete, &mut raw).unwrap();
        raw.extend_from_slice(&plausible_prelude_bytes(1000));

        let failure = expect_stream_failure(decode_bedrock_converse_stream(raw_body(raw)).await);
        assert!(
            failure.message.contains("mid-frame"),
            "expected a mid-frame truncation message, got: {failure:?}"
        );
    }

    /// Fix-round-2 J1, CASE C through the full pipeline -- the sharp one: a
    /// body consisting of NOTHING but 12 bytes must not decode as a clean,
    /// empty success (no events, no `MessageStop`, no error) with the
    /// prelude CRC never checked.
    #[tokio::test]
    async fn a_body_of_exactly_twelve_bytes_and_nothing_else_is_mid_frame_not_a_clean_success() {
        let raw = plausible_prelude_bytes(1000).to_vec();
        let failure = expect_stream_failure(decode_bedrock_converse_stream(raw_body(raw)).await);
        assert!(
            failure.message.contains("mid-frame"),
            "expected a mid-frame truncation message, got: {failure:?}"
        );
    }

    #[tokio::test]
    async fn a_genuine_messagestop_event_does_produce_message_stop() {
        let messages = [
            event("messageStart", serde_json::json!({ "role": "assistant" })),
            event(
                "contentBlockDelta",
                serde_json::json!({ "contentBlockIndex": 0, "delta": { "text": "done" } }),
            ),
            event(
                "contentBlockStop",
                serde_json::json!({ "contentBlockIndex": 0 }),
            ),
            event(
                "messageStop",
                serde_json::json!({ "stopReason": "end_turn" }),
            ),
        ];
        let events = decode_bedrock_converse_stream(body(&messages))
            .await
            .expect("must decode successfully");
        assert!(events.iter().any(|e| matches!(e, StreamEvent::MessageStop)));
    }

    /// Divergence 2 (this codec's `mod.rs` doc comment): a text block has no
    /// `contentBlockStart` event at all -- the first delta must synthesize
    /// its own `BlockStart`.
    #[tokio::test]
    async fn a_text_delta_with_no_prior_content_block_start_synthesizes_one() {
        let messages = [event(
            "contentBlockDelta",
            serde_json::json!({ "contentBlockIndex": 0, "delta": { "text": "hi" } }),
        )];
        let events = decode_bedrock_converse_stream(body(&messages))
            .await
            .expect("must decode successfully");
        assert!(matches!(
            events.first(),
            Some(StreamEvent::BlockStart {
                index: 0,
                kind: BlockKind::Text
            })
        ));
        assert!(matches!(
            events.get(1),
            Some(StreamEvent::BlockDelta {
                index: 0,
                delta: BlockDelta::Text(t)
            }) if t == "hi"
        ));
    }

    /// A `toolUse` delta with no matching prior `contentBlockStart` has no
    /// name/id to attach to -- must be dropped, not fabricated into a
    /// nameless tool call (mirrors `openai_responses`'
    /// `an_unrecognized_item_type_never_consumes_an_index` precedent).
    #[tokio::test]
    async fn a_tool_use_delta_with_no_prior_content_block_start_is_dropped() {
        let messages = [event(
            "contentBlockDelta",
            serde_json::json!({ "contentBlockIndex": 0, "delta": { "toolUse": { "input": "{}" } } }),
        )];
        let events = decode_bedrock_converse_stream(body(&messages))
            .await
            .expect("must decode successfully");
        assert!(
            events.is_empty(),
            "a tool-use delta with no matching BlockStart must not produce any event, got \
             {} events",
            events.len()
        );
    }

    /// `Result::expect_err` needs `T: Debug`, and `Vec<StreamEvent>` isn't
    /// (`StreamEvent` derives none, REALITY-CORRECTIONS §14c) -- matches
    /// `google_genai`/`conformance_openai_responses.rs`'s identical
    /// `expect_err`/`expect_stream_failure` helper precedent.
    fn expect_stream_failure(
        result: Result<Vec<StreamEvent>, super::StreamFailure>,
    ) -> super::StreamFailure {
        match result {
            Ok(_) => panic!("expected a StreamFailure, got a successful decode"),
            Err(failure) => failure,
        }
    }

    /// A modeled exception frame must surface as an `Err`, never silently
    /// skipped -- even one this decoder doesn't specifically recognize by
    /// name (REALITY-CORRECTIONS §13b item 4: the "skip malformed frames"
    /// convention covers garbage, not well-formed events this decoder just
    /// doesn't implement).
    #[tokio::test]
    async fn an_unrecognized_exception_type_is_still_an_error_not_a_skip() {
        let messages = [exception(
            "SomeFutureBedrockException",
            serde_json::json!({ "message": "a new exception kind" }),
        )];
        let failure = expect_stream_failure(decode_bedrock_converse_stream(body(&messages)).await);
        assert_eq!(failure.code.as_deref(), Some("SomeFutureBedrockException"));
    }

    /// A bare `:message-type: error` frame (the protocol's generic,
    /// unmodeled error -- distinct from a modeled exception) must also
    /// surface as an error.
    #[tokio::test]
    async fn a_generic_message_type_error_frame_is_an_error() {
        let message = Message::new(Vec::new())
            .add_header(Header::new(
                ":message-type",
                HeaderValue::String("error".into()),
            ))
            .add_header(Header::new(
                ":error-code",
                HeaderValue::String("InternalError".into()),
            ))
            .add_header(Header::new(
                ":error-message",
                HeaderValue::String("something broke".into()),
            ));
        let failure = expect_stream_failure(decode_bedrock_converse_stream(body(&[message])).await);
        assert_eq!(failure.code.as_deref(), Some("InternalError"));
        assert_eq!(failure.message, "something broke");
    }

    /// Fix round 6, J3: the transport-error branch built `StreamFailure.message`
    /// from a bare `{e}` interpolation. That leaked nothing in production only
    /// because `errors.rs::classify` hardcodes `body_snippet: String::new()` --
    /// a downstream dead end, not a guarantee at the source. Now wrapped in
    /// `redact_transport_error_text`.
    #[tokio::test]
    async fn a_transport_error_redacts_a_credentialed_url() {
        let failing = stream::iter(vec![Err(crate::TransportError::Io(
            "error sending request for url \
             (https://gwuser:gwpass@gateway.example.invalid/v1?key=gw-live-9f2b8c1d4e6a7b3c)"
                .to_string(),
        ))]);
        let failure = expect_stream_failure(decode_bedrock_converse_stream(failing).await);
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
