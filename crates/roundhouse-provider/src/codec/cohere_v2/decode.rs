//! Decodes a Cohere v2 `/v2/chat` streaming response body into normalized
//! [`StreamEvent`]s. Verified against the real, fetched Cohere API reference
//! -- see `mod.rs`'s module doc comment for the fetch record. Malformed or
//! genuinely unrecognized frames are skipped, matching this crate's
//! established precedent -- but every spec-verified terminal/failure signal
//! this module recognizes (a `finish_reason` other than the three real
//! success values) is enumerated explicitly and never falls into that "skip"
//! bucket (REALITY-CORRECTIONS §13b item 4).
//!
//! Fix round 1, L1/L2: a clean EOF with no `message-end` ever observed is a
//! FAILURE (a truncated generation), not `Ok(events)` -- the earlier version
//! of this module returned `Ok` unconditionally at the bottom of the loop,
//! which `roundhouse-engine::infer` cannot distinguish from a real
//! `MessageStop`, so a truncated inference persisted as `TaskCompleted` on a
//! physically-immutable row. `provider.rs` maps every [`StreamFailure`] here
//! directly onto a `ProviderError` by [`StreamFailureKind`] rather than
//! laundering it through `crate::errors::classify` at the enclosing HTTP
//! response's (always 200, since this is an in-band failure) status --
//! doing so would land everything in `BadRequest{200, ""}` (permanently
//! fatal, per `retry.rs`'s disposition table) and discard every diagnostic
//! message this module builds.

use bytes::Bytes;
use futures::{Stream, StreamExt};
use serde_json::Value;
use sse_stream::SseStream;
use std::collections::HashSet;

// Fix round 2, N2: `redact_transport_error_text` used to live in `mod.rs` so
// `provider.rs`'s three other transport-error sinks could share it too.
// Fix round 4, R4: hoisted again, to `crate::audit`, so `openai_chat` can
// share the same real implementation instead of its own weaker one.
use crate::audit::redact_transport_error_text;
use crate::stream_event::{BlockDelta, BlockKind, DeltaKeyer, StreamEvent};
use crate::TransportError;

/// How `provider.rs` should map a [`StreamFailure`] onto a `ProviderError` --
/// computed here, at decode time, since this module (not `provider.rs`) is
/// the one that actually knows which real, verified wire condition produced
/// the failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamFailureKind {
    /// The stream ended (a clean EOF) without ever observing a `message-end`
    /// event at all -- a proxy terminating gracefully mid-generation, an
    /// HTTP/2 `END_STREAM`, or a final frame missing the blank-line
    /// terminator `sse-stream` requires (dropped silently by that library).
    /// Distinct from a reset connection, which surfaces as `Transport`
    /// below via the SSE frame's own `Err`.
    Truncated,
    /// `finish_reason: "MAX_TOKENS"` -- generation was cut short by a length
    /// limit; there is real partial output.
    MaxTokens,
    /// `finish_reason: "ERROR"` -- Cohere's own "the generation failed due
    /// to an internal error" (verified enum value).
    Error,
    /// `finish_reason: "TIMEOUT"` -- verified enum value; maps directly onto
    /// this crate's existing `ProviderError::Timeout`.
    Timeout,
    /// `message-end` arrived with a missing or genuinely unrecognized
    /// `finish_reason` (a future spec revision's value this decoder doesn't
    /// know about) -- an unknown terminal condition, not assumed to be any
    /// specific known failure kind.
    UnrecognizedFinishReason,
    /// A mid-stream SSE/transport read error (a reset connection, a
    /// malformed frame at the transport layer).
    Transport,
}

/// A terminal, spec-verified failure signaled mid-stream. Deliberately not a
/// `ProviderError` -- this module has no `ProviderProfile` to classify
/// through; `provider.rs` maps this into the real `ProviderError` directly,
/// by `kind`, per this module's doc comment. Mirrors
/// `google_genai::decode::StreamFailure`, extended with `kind` and
/// `partial_text` (fix round 1, L1/L2).
///
/// Fix round 2, N3: this originally also carried a `code: Option<String>`
/// (the raw or sanitized `finish_reason` string). Its only reader was
/// `stream_failure_body`, deleted along with the `classify`-at-200 path L2
/// removed -- after that, `code` was write-only outside a single test
/// assertion, AND inconsistent (raw for a known value, `{:?}`-quoted for the
/// sanitized unknown arm). Dropped rather than given a reader that doesn't
/// exist yet; `message` already carries the same information, consistently
/// formatted, for every arm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFailure {
    /// How `provider.rs` should map this into a `ProviderError`.
    pub kind: StreamFailureKind,
    /// A human-readable description of the failure. Redacted (fix round 1,
    /// L3) for the `Transport` kind, since a mid-stream transport error's
    /// text can embed the full request URL, query string and all.
    pub message: String,
    /// Text decoded before the failure occurred (`BlockDelta::Text`
    /// fragments, concatenated in first-seen order) -- lets `provider.rs`
    /// construct `ProviderError::StreamInterrupted { partial }` without
    /// re-deriving it from the (already-consumed) event list.
    pub partial_text: String,
}

/// Caps how much of an untrusted `finish_reason` string is echoed into a
/// diagnostic message (fix round 1, L10) -- Cohere's documented values are
/// all well under this, so it never truncates a real one; only an attacker-
/// or bug-supplied arbitrary-length string is capped.
const MAX_FINISH_REASON_ECHO_LEN: usize = 64;

/// Truncates `raw` to [`MAX_FINISH_REASON_ECHO_LEN`] chars and renders it via
/// `{:?}` (fix round 1, L10) -- `Debug` on `&str` escapes control characters
/// and quotes, so a value containing e.g. a newline can't inject fake log
/// lines into a persisted diagnostic message. Mirrors
/// `google_genai::provider::build_endpoint_url`'s identical `{:?}`-escaping
/// precedent for an untrusted string reaching the same kind of sink.
fn sanitize_finish_reason_for_message(raw: &str) -> String {
    let truncated: String = raw.chars().take(MAX_FINISH_REASON_ECHO_LEN).collect();
    format!("{truncated:?}")
}

/// Concatenates every `BlockDelta::Text` fragment in `events`, in order --
/// the best-effort "partial output" `provider.rs` attaches to a
/// `ProviderError::StreamInterrupted`. Mirrors
/// `roundhouse-engine::compact::fold_stream_text`'s identical text-folding
/// logic, but over an already-materialized `&[StreamEvent]` rather than a
/// live stream.
fn partial_text_from_events(events: &[StreamEvent]) -> String {
    let mut text = String::new();
    for event in events {
        if let StreamEvent::BlockDelta {
            delta: BlockDelta::Text(t),
            ..
        } = event
        {
            text.push_str(t);
        }
    }
    text
}

/// Which wire index namespace a `wire_index` belongs to (fix round 2, N1).
/// Cohere v2 indexes `message.content[]` and `message.tool_calls[]` from
/// INDEPENDENT counters (verified; also visible in this codec's own
/// `reasoning.cassette` -- content indexes 0,1 -- and `parallel_tools.cassette`
/// -- tool indexes 0,1, each starting its own count from 0). A codec
/// advertising `thinking = true` AND `tools = true` (this one) can receive a
/// thinking block and a tool call that both carry wire index 0 in the same
/// turn; treating that as one namespace collides them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IndexFamily {
    /// `content-start`/`content-delta`/`content-end`'s `index`.
    Content,
    /// `tool-call-start`/`tool-call-delta`/`tool-call-end`'s `index`.
    Tool,
}

/// Tracks which `(family, wire index)` pairs were opened by a RECOGNIZED
/// block-opening event (`content-start`/`tool-call-start`) -- mirrors
/// `google_genai::decode`'s `StepKeyer` for the identical reason: a
/// `content-end`/`tool-call-end` for an index this decoder never opened must
/// not fabricate a `BlockStop`, and `citation-start`/`citation-end` (which
/// reuse a CONTENT block's own index -- verified: the fetched `citation-start`
/// example carries the same `"index":0` as the content block it annotates,
/// not a fresh one) must never consume a keyer slot. Keyed on `(IndexFamily,
/// u64)`, not bare `u64` (fix round 2, N1): the two families are independent
/// wire-index namespaces that legitimately reuse the same numbers, and
/// deduping on the raw number alone silently dropped whichever block opened
/// second -- worse than the duplicate-`BlockStart` bug L8 fixed, since the
/// lost block never surfaces at all.
struct IndexKeyer {
    keyer: DeltaKeyer,
    recognized: HashSet<(IndexFamily, u64)>,
}

impl IndexKeyer {
    fn new() -> Self {
        Self {
            keyer: DeltaKeyer::new(),
            recognized: HashSet::new(),
        }
    }

    /// The `DeltaKeyer` key for `(family, wire_index)` -- prefixed by family
    /// so a content-index and a tool-index of the same number never collide
    /// onto the same normalized index either.
    fn keyer_key(family: IndexFamily, wire_index: u64) -> String {
        match family {
            IndexFamily::Content => format!("content:{wire_index}"),
            IndexFamily::Tool => format!("tool:{wire_index}"),
        }
    }

    /// Opens a new recognized block at `(family, wire_index)`, returning its
    /// stable normalized index -- but only if that pair was not already
    /// open. `None` for a repeat (fix round 1, L8): a second `content-start`/
    /// `tool-call-start` for an index this decoder already opened, WITHIN
    /// THE SAME FAMILY, must not fabricate a second `BlockStart` for the
    /// same normalized index (which `roundhouse-engine::infer`'s fold would
    /// otherwise materialize as a phantom second block). A cross-family
    /// reuse of the same number is not a repeat and correctly opens a second
    /// block (fix round 2, N1).
    fn open(&mut self, family: IndexFamily, wire_index: u64) -> Option<u32> {
        if self.recognized.contains(&(family, wire_index)) {
            return None;
        }
        self.recognized.insert((family, wire_index));
        Some(self.keyer.index_for(&Self::keyer_key(family, wire_index)))
    }

    /// The stable normalized index for `(family, wire_index)`, but only if
    /// it was previously `open`ed -- `None` otherwise, without ever calling
    /// `index_for` (which would burn a slot).
    fn existing(&mut self, family: IndexFamily, wire_index: u64) -> Option<u32> {
        if self.recognized.contains(&(family, wire_index)) {
            Some(self.keyer.index_for(&Self::keyer_key(family, wire_index)))
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
                // Fix round 1, L3: `e`'s `Display` can embed the full
                // request URL (query string, userinfo) verbatim --
                // redacted before it ever reaches this `pub` field.
                return Err(StreamFailure {
                    kind: StreamFailureKind::Transport,
                    message: redact_transport_error_text(&format!(
                        "SSE transport error while decoding the cohere-v2 chat stream: {e}"
                    )),
                    partial_text: partial_text_from_events(&events),
                });
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
            // Fix round 2, N1: `content-end` and `tool-call-end` close a
            // block in DIFFERENT index namespaces -- routed through the
            // matching `IndexFamily` rather than one shared arm, so a
            // content-index and a tool-index of the same wire value never
            // resolve to the same normalized block.
            "content-end" => {
                if let Some(ev) = decode_block_end(&payload, &mut keyer, IndexFamily::Content) {
                    events.push(ev);
                }
            }
            "tool-call-end" => {
                if let Some(ev) = decode_block_end(&payload, &mut keyer, IndexFamily::Tool) {
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

    // Fix round 1, L1: the loop above only ever returns via the
    // "message-end" arm's early `return`. Reaching here means the frame
    // stream ended (a clean EOF) WITHOUT ever observing a `message-end`
    // event -- a truncated generation, not a completed one. Returning
    // `Ok(events)` here (the original defect) is indistinguishable
    // downstream from a real `MessageStop`, and `roundhouse-engine::infer`
    // persists it as `TaskCompleted` with partial output on an immutable
    // row. This must never be conflated with the `Err` branch above (a
    // genuinely reset connection, already caught): a graceful proxy
    // termination or a final frame missing its blank-line terminator (which
    // `sse-stream` drops silently) never surfaces there.
    Err(StreamFailure {
        kind: StreamFailureKind::Truncated,
        message: "cohere-v2 chat stream ended without ever observing a message-end event -- \
                   the generation was truncated"
            .into(),
        partial_text: partial_text_from_events(&events),
    })
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
        "MAX_TOKENS" => Err(StreamFailure {
            kind: StreamFailureKind::MaxTokens,
            message: format!("cohere-v2 chat generation stopped: {finish_reason}"),
            partial_text: partial_text_from_events(&events),
        }),
        "ERROR" => Err(StreamFailure {
            kind: StreamFailureKind::Error,
            message: format!("cohere-v2 chat generation stopped: {finish_reason}"),
            partial_text: partial_text_from_events(&events),
        }),
        "TIMEOUT" => Err(StreamFailure {
            kind: StreamFailureKind::Timeout,
            message: format!("cohere-v2 chat generation stopped: {finish_reason}"),
            partial_text: partial_text_from_events(&events),
        }),
        "" => Err(StreamFailure {
            kind: StreamFailureKind::UnrecognizedFinishReason,
            message: "cohere-v2 chat stream's message-end event carried no finish_reason".into(),
            partial_text: partial_text_from_events(&events),
        }),
        other => {
            // Fix round 1, L10: `other` is an untrusted, unbounded-length
            // string from the wire -- capped and escaped before it reaches
            // the diagnostic message (fix round 2, N3 dropped the separate
            // `code` field this comment used to also mention).
            let safe = sanitize_finish_reason_for_message(other);
            Err(StreamFailure {
                kind: StreamFailureKind::UnrecognizedFinishReason,
                message: format!(
                    "cohere-v2 chat stream ended with an unrecognized finish_reason {safe}"
                ),
                partial_text: partial_text_from_events(&events),
            })
        }
    }
}

/// `content-start`: `{type, index, delta: {message: {content: {type, ...}}}}`.
/// Verified content `type` values: `"text"` and `"thinking"` (the assistant
/// content array's two real block kinds -- see `mod.rs`'s fetch record). Any
/// other content type has no IR equivalent and is skipped without consuming
/// a keyer slot. A REPEATED `content-start` for an already-open index
/// (fix round 1, L8) is `None` too -- `IndexKeyer::open` refuses to
/// fabricate a second `BlockStart` for the same normalized index.
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
    let index = keyer.open(IndexFamily::Content, wire_index)?;
    Some(StreamEvent::BlockStart { index, kind })
}

/// `content-delta`: `{type, index, delta: {message: {content: {text}}}}` for
/// a text block, or `{... content: {thinking}}` for a thinking block
/// (verified: the field name changes with the block kind rather than always
/// being `text`).
fn decode_content_delta(payload: &Value, keyer: &mut IndexKeyer) -> Option<StreamEvent> {
    let wire_index = payload.get("index").and_then(Value::as_u64)?;
    let index = keyer.existing(IndexFamily::Content, wire_index)?;
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
/// block `index` refers to, so one function serves both event types, but
/// `family` (fix round 2, N1) picks the right namespace so a content-index
/// and a tool-index of the same wire value don't resolve to the same block.
fn decode_block_end(
    payload: &Value,
    keyer: &mut IndexKeyer,
    family: IndexFamily,
) -> Option<StreamEvent> {
    let wire_index = payload.get("index").and_then(Value::as_u64)?;
    let index = keyer.existing(family, wire_index)?;
    Some(StreamEvent::BlockStop { index })
}

/// `tool-call-start`: `{type, index, delta: {message: {tool_calls: {id,
/// type, function: {name, arguments}}}}}` -- verified: `tool_calls` here is
/// an OBJECT, not an array (unlike OpenAI's per-response `tool_calls[]`).
/// `id` becomes `BlockKind::ToolUse.provider_id`, echoed back by a later
/// `function_result`/`tool` message's `tool_call_id`. A REPEATED
/// `tool-call-start` for an already-open index (fix round 1, L8) is `None`
/// too, for the identical reason `decode_content_start` is.
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
    let index = keyer.open(IndexFamily::Tool, wire_index)?;
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
    let index = keyer.existing(IndexFamily::Tool, wire_index)?;
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

/// Normalizes `message-end`'s `usage` object. The verified example carries
/// TWO usage shapes -- `billed_units.{input,output}_tokens` and
/// `tokens.{input,output}_tokens` -- and they disagree substantially: the
/// fetched reference's own example shows `billed_units.input_tokens: 5`
/// against `tokens.input_tokens: 71`, a >14x gap (`tokens` presumably
/// includes cached/system/tool-schema tokens Cohere doesn't bill for).
///
/// **Deliberate choice (fix round 1, L9): this function reads `billed_units`,
/// not `tokens`.** `Usage` feeds this crate's cost-accounting path
/// (`fallback::PricingLookup::cost_for`), and billed tokens are the correct
/// input for a dollar figure -- reading `tokens` here would overstate cost.
/// The trade-off: anything that treats `Usage.input_tokens` as a *context or
/// budget* measure (how much of the model's context window this turn
/// consumed) will see a large UNDERCOUNT relative to `tokens`. No consumer
/// in this workspace does that today; if one is added for this provider,
/// it needs `tokens`, not this field.
///
/// Cohere v2's streaming reference documents no cache-read/cache-hit token
/// count anywhere -- unlike Gemini/Anthropic, this API has no documented
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
    use super::{
        decode_block_end, decode_content_start, decode_message_end, IndexFamily, IndexKeyer,
    };
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
            decode_block_end(&unrecognized_end, &mut keyer, IndexFamily::Content).is_none(),
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
        assert_eq!(err.kind, super::StreamFailureKind::MaxTokens);
    }

    #[test]
    fn error_finish_reason_is_a_stream_failure() {
        let payload = serde_json::json!({
            "type": "message-end",
            "delta": { "finish_reason": "ERROR" }
        });
        let err = expect_failure(decode_message_end(&payload, Vec::new()));
        assert!(err.message.contains("ERROR"));
        assert_eq!(err.kind, super::StreamFailureKind::Error);
    }

    #[test]
    fn timeout_finish_reason_is_a_stream_failure() {
        let payload = serde_json::json!({
            "type": "message-end",
            "delta": { "finish_reason": "TIMEOUT" }
        });
        let err = expect_failure(decode_message_end(&payload, Vec::new()));
        assert!(err.message.contains("TIMEOUT"));
        assert_eq!(err.kind, super::StreamFailureKind::Timeout);
    }

    /// Fix round 1, L1: `MAX_TOKENS`'s partial output must be recoverable --
    /// `provider.rs` attaches this to `ProviderError::StreamInterrupted`.
    #[test]
    fn max_tokens_failure_carries_the_partial_text_decoded_so_far() {
        let events = vec![
            StreamEvent::BlockDelta {
                index: 0,
                delta: crate::stream_event::BlockDelta::Text("partial ans".into()),
            },
            StreamEvent::BlockDelta {
                index: 0,
                delta: crate::stream_event::BlockDelta::Text("wer".into()),
            },
        ];
        let payload = serde_json::json!({
            "type": "message-end",
            "delta": { "finish_reason": "MAX_TOKENS" }
        });
        let err = expect_failure(decode_message_end(&payload, events));
        assert_eq!(err.partial_text, "partial answer");
    }

    /// Fix round 1, L10: an unbounded, attacker-controlled `finish_reason`
    /// string must be capped and escaped, never interpolated raw.
    #[test]
    fn an_unrecognized_finish_reason_is_capped_and_escaped_in_the_message() {
        let huge = "X".repeat(10_000);
        let payload = serde_json::json!({
            "type": "message-end",
            "delta": { "finish_reason": huge }
        });
        let err = expect_failure(decode_message_end(&payload, Vec::new()));
        assert!(
            err.message.len() < 200,
            "message must be capped, got {} bytes",
            err.message.len()
        );
        assert_eq!(err.kind, super::StreamFailureKind::UnrecognizedFinishReason);
    }

    /// A newline embedded in an unrecognized `finish_reason` must not reach
    /// the diagnostic message unescaped (it could otherwise forge fake log
    /// lines in a persisted error field).
    #[test]
    fn a_newline_in_an_unrecognized_finish_reason_is_escaped_not_raw() {
        let payload = serde_json::json!({
            "type": "message-end",
            "delta": { "finish_reason": "weird\nvalue" }
        });
        let err = expect_failure(decode_message_end(&payload, Vec::new()));
        assert!(!err.message.contains('\n'));
        assert!(err.message.contains("\\n"));
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
        assert_eq!(err.kind, super::StreamFailureKind::UnrecognizedFinishReason);
    }

    /// Fix round 1, L8: a repeated `content-start` on an already-open index
    /// must not fabricate a second `BlockStart` -- `roundhouse-engine::infer`
    /// would otherwise materialize a phantom second block.
    #[test]
    fn a_repeated_content_start_on_an_open_index_does_not_reopen_the_block() {
        let mut keyer = IndexKeyer::new();
        let first = serde_json::json!({
            "type": "content-start",
            "index": 0,
            "delta": { "message": { "content": { "type": "text" } } }
        });
        assert!(decode_content_start(&first, &mut keyer).is_some());

        let repeat = serde_json::json!({
            "type": "content-start",
            "index": 0,
            "delta": { "message": { "content": { "type": "text" } } }
        });
        assert!(
            decode_content_start(&repeat, &mut keyer).is_none(),
            "a second content-start for an already-open index must not fabricate \
             a second BlockStart"
        );
    }

    /// Same guard, for `tool-call-start` (fix round 1, L8).
    #[test]
    fn a_repeated_tool_call_start_on_an_open_index_does_not_reopen_the_block() {
        use super::decode_tool_call_start;
        let mut keyer = IndexKeyer::new();
        let first = serde_json::json!({
            "type": "tool-call-start",
            "index": 0,
            "delta": { "message": { "tool_calls": {
                "id": "call_1", "type": "function",
                "function": { "name": "get_weather", "arguments": "" }
            } } }
        });
        assert!(decode_tool_call_start(&first, &mut keyer).is_some());

        let repeat = serde_json::json!({
            "type": "tool-call-start",
            "index": 0,
            "delta": { "message": { "tool_calls": {
                "id": "call_2", "type": "function",
                "function": { "name": "get_time", "arguments": "" }
            } } }
        });
        assert!(
            decode_tool_call_start(&repeat, &mut keyer).is_none(),
            "a second tool-call-start for an already-open index must not fabricate \
             a phantom second block with an empty name and a synthesized id"
        );
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

    /// Fix round 1, L1 (inverted): a stream that ends -- a clean EOF, not a
    /// reset connection -- without ever carrying a `message-end` event is a
    /// FAILURE (`StreamFailureKind::Truncated`), not `Ok(events)`. The
    /// original version of this test enshrined the opposite ("an
    /// unterminated stream is not itself an error -- just unterminated"),
    /// which is exactly the gap that let a truncated generation persist as
    /// `TaskCompleted` downstream.
    #[tokio::test]
    async fn a_stream_with_no_message_end_is_a_truncated_stream_failure() {
        let body = sse_body(&[
            r#"{"id":"r3","type":"message-start","delta":{"message":{"role":"assistant"}}}"#,
            r#"{"type":"content-start","index":0,"delta":{"message":{"content":{"type":"text","text":""}}}}"#,
            r#"{"type":"content-delta","index":0,"delta":{"message":{"content":{"text":"partial"}}}}"#,
        ]);
        let failure = match decode_cohere_v2_stream(body).await {
            Ok(_) => panic!(
                "a stream with no observed message-end must not decode as a success -- \
                 it must never fabricate MessageStop"
            ),
            Err(f) => f,
        };
        assert_eq!(failure.kind, super::StreamFailureKind::Truncated);
        assert_eq!(failure.partial_text, "partial");
    }

    /// Fix round 1, L6: citations reuse an already-open block's own index
    /// (verified) and must not be mistaken for a new block, nor interfere
    /// with `content-delta` tracking on that same index. Nothing drove this
    /// through the real decode loop before this fix round -- only the
    /// encode-side tripwire counted the `citation-start`/`citation-end`
    /// literal.
    #[tokio::test]
    async fn a_citation_pair_interleaved_with_content_delta_does_not_disturb_the_block() {
        let body = sse_body(&[
            r#"{"id":"r5","type":"message-start","delta":{"message":{"role":"assistant"}}}"#,
            r#"{"type":"content-start","index":0,"delta":{"message":{"content":{"type":"text","text":""}}}}"#,
            r#"{"type":"content-delta","index":0,"delta":{"message":{"content":{"text":"Nsync"}}}}"#,
            r#"{"type":"citation-start","index":0,"delta":{"message":{"citations":{"start":0,"end":5,"text":"Nsync","sources":[],"type":"TEXT_CONTENT"}}}}"#,
            r#"{"type":"citation-end","index":0}"#,
            r#"{"type":"content-delta","index":0,"delta":{"message":{"content":{"text":" was popular."}}}}"#,
            r#"{"type":"content-end","index":0}"#,
            r#"{"type":"message-end","delta":{"finish_reason":"COMPLETE"}}"#,
        ]);
        let events = decode_cohere_v2_stream(body)
            .await
            .expect("citations must not break decoding of the block they annotate");

        let mut texts = Vec::new();
        let mut block_starts = 0u32;
        let mut block_stops = 0u32;
        for event in events {
            match event {
                StreamEvent::BlockStart { index, .. } => {
                    assert_eq!(index, 0, "the citation pair must not open a second block");
                    block_starts += 1;
                }
                StreamEvent::BlockStop { index } => {
                    assert_eq!(index, 0, "the citation pair must not close a phantom block");
                    block_stops += 1;
                }
                StreamEvent::BlockDelta {
                    delta: BlockDelta::Text(t),
                    index,
                } => {
                    assert_eq!(index, 0);
                    texts.push(t);
                }
                _ => {}
            }
        }
        assert_eq!(block_starts, 1, "exactly one real block was opened");
        assert_eq!(block_stops, 1, "exactly one real block was closed");
        assert_eq!(texts.join(""), "Nsync was popular.");
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

    /// Fix round 1, L11: the codec's own claim ("fragments concatenated
    /// verbatim, never parsed mid-stream") was never exercised across more
    /// than one fragment by any existing cassette or unit test -- every one
    /// delivered a tool call's complete arguments JSON in a SINGLE
    /// `tool-call-delta`. This drives three fragments, none individually
    /// valid JSON on its own, through the real decode loop.
    #[tokio::test]
    async fn tool_call_arguments_concatenate_correctly_across_multiple_fragments() {
        let body = sse_body(&[
            r#"{"id":"r6","type":"message-start","delta":{"message":{"role":"assistant"}}}"#,
            r#"{"type":"tool-call-start","index":0,"delta":{"message":{"tool_calls":{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}}}}"#,
            r#"{"type":"tool-call-delta","index":0,"delta":{"message":{"tool_calls":{"function":{"arguments":"{\"locat"}}}}}"#,
            r#"{"type":"tool-call-delta","index":0,"delta":{"message":{"tool_calls":{"function":{"arguments":"ion\": \"T"}}}}}"#,
            r#"{"type":"tool-call-delta","index":0,"delta":{"message":{"tool_calls":{"function":{"arguments":"okyo\"}"}}}}}"#,
            r#"{"type":"tool-call-end","index":0}"#,
            r#"{"type":"message-end","delta":{"finish_reason":"TOOL_CALL"}}"#,
        ]);
        let events = decode_cohere_v2_stream(body)
            .await
            .expect("must decode successfully");

        let mut args = String::new();
        for event in events {
            if let StreamEvent::BlockDelta {
                delta: BlockDelta::ToolArgsFragment(f),
                ..
            } = event
            {
                args.push_str(&f);
            }
        }
        assert_eq!(args, r#"{"location": "Tokyo"}"#);
        let parsed: serde_json::Value =
            serde_json::from_str(&args).expect("concatenated fragments must form valid JSON");
        assert_eq!(parsed["location"], "Tokyo");
    }

    /// Fix round 2, N1: `message.content[]` and `message.tool_calls[]` are
    /// independent wire index namespaces (verified; also visible in this
    /// codec's own `reasoning.cassette` and `parallel_tools.cassette`, each
    /// of which independently starts counting from 0). A thinking block at
    /// content-index 0 followed by a tool call at tool-index 0 must NOT
    /// collide: before this fix, `IndexKeyer` keyed both families on the raw
    /// wire index, so the tool-call-start's `open` call saw content-index 0
    /// already `recognized` and returned `None` -- silently dropping the
    /// tool call's `BlockStart` entirely, after which its `tool-call-delta`
    /// fell through `existing`'s lookup onto the THINKING block's normalized
    /// index (the only one ever opened), and its `tool-call-end` fired a
    /// second, phantom `BlockStop` on that same already-stopped block.
    #[tokio::test]
    async fn a_thinking_block_and_a_tool_call_sharing_wire_index_zero_do_not_collide() {
        let body = sse_body(&[
            r#"{"id":"r7","type":"message-start","delta":{"message":{"role":"assistant"}}}"#,
            r#"{"type":"content-start","index":0,"delta":{"message":{"content":{"type":"thinking","thinking":""}}}}"#,
            r#"{"type":"content-delta","index":0,"delta":{"message":{"content":{"thinking":"I should call a tool."}}}}"#,
            r#"{"type":"content-end","index":0}"#,
            r#"{"type":"tool-call-start","index":0,"delta":{"message":{"tool_calls":{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}}}}"#,
            r#"{"type":"tool-call-delta","index":0,"delta":{"message":{"tool_calls":{"function":{"arguments":"{\"location\": \"Tokyo\"}"}}}}}"#,
            r#"{"type":"tool-call-end","index":0}"#,
            r#"{"type":"message-end","delta":{"finish_reason":"TOOL_CALL"}}"#,
        ]);
        let events = decode_cohere_v2_stream(body)
            .await
            .expect("must decode successfully");

        let mut block_starts: Vec<(u32, &'static str)> = Vec::new();
        let mut block_stops: Vec<u32> = Vec::new();
        let mut tool_args = String::new();
        let mut thinking_text = String::new();
        for event in &events {
            match event {
                StreamEvent::BlockStart {
                    index,
                    kind: BlockKind::Thinking,
                } => block_starts.push((*index, "thinking")),
                StreamEvent::BlockStart {
                    index,
                    kind: BlockKind::ToolUse { name, .. },
                } => {
                    assert_eq!(name, "get_weather");
                    block_starts.push((*index, "tool"));
                }
                StreamEvent::BlockStart { .. } => panic!("unexpected block kind"),
                StreamEvent::BlockStop { index } => block_stops.push(*index),
                StreamEvent::BlockDelta {
                    delta: BlockDelta::ToolArgsFragment(f),
                    ..
                } => tool_args.push_str(f),
                StreamEvent::BlockDelta {
                    delta: BlockDelta::Thinking { text, .. },
                    ..
                } => thinking_text.push_str(text),
                _ => {}
            }
        }

        assert_eq!(
            block_starts.len(),
            2,
            "both the thinking block and the tool call must open distinct blocks, got {block_starts:?}"
        );
        let thinking_index = block_starts
            .iter()
            .find(|(_, kind)| *kind == "thinking")
            .map(|(i, _)| *i)
            .expect("thinking block must have opened");
        let tool_index = block_starts
            .iter()
            .find(|(_, kind)| *kind == "tool")
            .map(|(i, _)| *i)
            .expect("tool block must not have been silently dropped");
        assert_ne!(
            thinking_index, tool_index,
            "a content-index and a tool-index of the same wire value must not collide \
             onto the same normalized block"
        );
        assert_eq!(
            block_stops.len(),
            2,
            "exactly one stop per real block, got {block_stops:?}"
        );
        assert_eq!(thinking_text, "I should call a tool.");
        assert_eq!(
            tool_args, r#"{"location": "Tokyo"}"#,
            "tool arguments must land on the tool block, not the thinking block"
        );
    }
}

// Fix round 2, N2: `redaction_tests` moved to `mod.rs`, next to
// `redact_transport_error_text` itself.
