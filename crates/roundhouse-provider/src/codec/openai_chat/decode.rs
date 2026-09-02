//! Decodes an OpenAI `/v1/chat/completions` streaming response body (Server-Sent Events)
//! into normalized [`StreamEvent`]s, per §9.3's normative decode rules: block structure
//! (`BlockStart`/`BlockStop`) is always synthesized by the decoder — OpenAI's wire format
//! has no explicit block-boundary markers — and tool-argument JSON fragments are
//! concatenated verbatim, never parsed, until the block closes.
//!
//! Fix round 3, Q1: before this fix round, EVERY failure signal this stream can carry was
//! discarded before it could matter, and the loop returned `Ok(events)` (via a bare
//! `Vec<StreamEvent>`, with no error channel at all) regardless. A truncated or failed
//! generation therefore persisted as a completed turn with plausible-looking partial text —
//! the exact defect class REALITY-CORRECTIONS §13b item 4 names ("failure events must reach
//! the caller as errors"). Mirrors `cohere_v2::decode`'s [`StreamFailure`]/`StreamFailureKind`
//! shape: malformed/genuinely unrecognized frames are still skipped (this crate's established
//! precedent), but every spec-verified terminal/failure signal is enumerated explicitly and
//! never falls into that "skip" bucket.

use bytes::Bytes;
use futures::{Stream, StreamExt};
use serde::Deserialize;
use serde_json::Value;
use sse_stream::SseStream;
use std::collections::HashSet;

use crate::audit::redact_transport_error_text;
use crate::stream_event::{BlockDelta, BlockKind, DeltaKeyer, StreamEvent};
use crate::TransportError;

/// One `data: {...}` chunk of an OpenAI chat-completions stream.
#[derive(Deserialize)]
struct Chunk {
    /// Per-choice deltas. OpenAI always sends exactly one choice for non-`n>1` requests;
    /// Phase 1 scope only reads `choices[0]`-equivalent (all choices are folded together,
    /// since the IR has no concept of multiple parallel completions).
    ///
    /// Fix round 3, Q1: `#[serde(default)]` added -- OpenAI's own final "usage" chunk sends
    /// `"choices": []` explicitly, but some OpenAI-*compatible* gateways omit the key
    /// entirely on that same chunk shape; without a default, such a chunk failed to
    /// deserialize as a `Chunk` at all and fell into the same "skip as garbage" bucket as a
    /// genuinely malformed frame, silently discarding whatever else it carried (e.g. usage).
    #[serde(default)]
    choices: Vec<Choice>,
    /// Token usage, present only on the final chunk (when `stream_options.include_usage`
    /// is requested, or always for some OpenAI-compatible backends).
    #[serde(default)]
    usage: Option<Usage>,
}

/// A single choice's incremental delta within a [`Chunk`].
#[derive(Deserialize)]
struct Choice {
    /// The incremental content for this choice.
    #[serde(default)]
    delta: Delta,
    /// Non-`null` only on the final content-carrying chunk for this choice.
    /// Verified OpenAI values: `"stop"`, `"tool_calls"` (clean endings),
    /// `"length"` (truncated by a token/context limit -- real partial
    /// output exists), `"content_filter"` (moderation cut the response
    /// short). `"function_call"` (the deprecated pre-tool-calls shape) and
    /// any other value fall through to [`StreamFailureKind::UnrecognizedFinishReason`]
    /// rather than being silently treated as success (fix round 3, Q1: this
    /// field previously wasn't deserialized at all).
    #[serde(default)]
    finish_reason: Option<String>,
}

/// Incremental content for a choice.
///
/// Fix round 1, P1: this struct previously deserialized only `tool_calls`
/// -- `decode_openai_chat_stream` was the sole codec decoder in this
/// workspace that never read `delta.content` at all, so any plain-text
/// (no tool calls) streaming response decoded to ZERO content blocks.
/// `content` is additive (`#[serde(default)]`, no `deny_unknown_fields` on
/// this struct), so it cannot disturb the tool-call path.
#[derive(Deserialize, Default)]
struct Delta {
    /// An incremental fragment of the assistant's plain-text reply, present
    /// only on choices that aren't emitting a tool call.
    #[serde(default)]
    content: Option<String>,
    /// Incremental tool-call fragments, keyed by `index` (see [`ToolCallDelta`]).
    #[serde(default)]
    tool_calls: Vec<ToolCallDelta>,
}

/// One tool call's incremental delta, keyed by its `index` within the response.
#[derive(Deserialize)]
struct ToolCallDelta {
    /// OpenAI's per-response tool-call slot index (not a global block index — remapped
    /// through [`DeltaKeyer`] to a stable `u32`).
    index: u32,
    /// The tool call's provider-assigned ID, present only on the first delta for this index.
    #[serde(default)]
    id: Option<String>,
    /// The function name/arguments delta.
    #[serde(default)]
    function: Option<FunctionDelta>,
}

/// The function-call portion of a [`ToolCallDelta`].
#[derive(Deserialize)]
struct FunctionDelta {
    /// The tool's name, present only on the first delta for this index.
    #[serde(default)]
    name: Option<String>,
    /// An incremental fragment of the JSON-encoded arguments string.
    #[serde(default)]
    arguments: Option<String>,
}

/// Token usage reported on the final chunk of a stream.
#[derive(Deserialize)]
struct Usage {
    /// Tokens consumed by the prompt.
    prompt_tokens: u64,
    /// Tokens generated in the completion.
    completion_tokens: u64,
}

/// How `provider.rs` should map a [`StreamFailure`] onto a `ProviderError` --
/// computed here, at decode time, since this module (not `provider.rs`) is
/// the one that actually knows which real, verified wire condition produced
/// the failure. Mirrors `cohere_v2::decode::StreamFailureKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamFailureKind {
    /// A mid-stream SSE/transport read error (a reset connection, a
    /// malformed frame at the transport layer).
    Transport,
    /// The stream ended (a clean EOF) without ever observing a `data:
    /// [DONE]` terminator -- a proxy terminating gracefully mid-generation,
    /// or a final frame missing the blank-line terminator `sse-stream`
    /// requires (dropped silently by that library).
    Truncated,
    /// `finish_reason: "length"` -- generation was cut short by a
    /// token/context limit; there is real partial output.
    Length,
    /// `finish_reason: "content_filter"` -- moderation cut the response
    /// short.
    ContentFilter,
    /// An in-band `data: {"error": {...}}` frame -- the shape
    /// OpenAI-*compatible* gateways emit for a failure that arrives after
    /// the initial 200 response has already started streaming.
    Error,
    /// `[DONE]` arrived without ever observing a `finish_reason` at all, or
    /// with a `finish_reason` value this decoder doesn't recognize (a
    /// future API revision's value, or the deprecated `function_call`
    /// shape).
    UnrecognizedFinishReason,
}

/// A terminal, spec-verified failure signaled mid-stream. Deliberately not a
/// `ProviderError` -- this module has no `ProviderProfile` to classify
/// through; `provider.rs` maps this into the real `ProviderError` directly,
/// by `kind`. Mirrors `cohere_v2::decode::StreamFailure` exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFailure {
    /// How `provider.rs` should map this into a `ProviderError`.
    pub kind: StreamFailureKind,
    /// A human-readable description of the failure. Redacted for the
    /// `Transport` kind via the shared `crate::audit::redact_transport_error_text`
    /// (fix round 4, R4 -- not merely `crate::audit::redact_error_body`, which
    /// strips only labeled token/key-shaped secrets, not an embedded URL's
    /// query string or userinfo), since a mid-stream transport error's text
    /// can embed the full request URL verbatim.
    pub message: String,
    /// Text decoded before the failure occurred (`BlockDelta::Text`
    /// fragments, concatenated in first-seen order) -- lets `provider.rs`
    /// construct `ProviderError::StreamInterrupted { partial }` without
    /// re-deriving it from the (already-consumed) event list.
    pub partial_text: String,
}

/// Caps how much of an untrusted wire string (a `finish_reason` value, or an
/// in-band error's `message` field) is echoed into a diagnostic message --
/// mirrors `cohere_v2::decode`'s identical guard. OpenAI's documented
/// values are all well under this, so it never truncates a real one; only
/// an attacker- or bug-supplied arbitrary-length string is capped.
const MAX_UNTRUSTED_STRING_ECHO_LEN: usize = 200;

/// Truncates `raw` to [`MAX_UNTRUSTED_STRING_ECHO_LEN`] chars and renders it
/// via `{:?}` -- `Debug` on `&str` escapes control characters and quotes, so
/// a value containing e.g. a newline can't inject fake log lines into a
/// persisted diagnostic message.
fn sanitize_untrusted_wire_string(raw: &str) -> String {
    let truncated: String = raw.chars().take(MAX_UNTRUSTED_STRING_ECHO_LEN).collect();
    format!("{truncated:?}")
}

/// Concatenates every `BlockDelta::Text` fragment in `events`, in order --
/// the best-effort "partial output" `provider.rs` attaches to a
/// `ProviderError::StreamInterrupted`. Mirrors `cohere_v2::decode`'s
/// identical helper.
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

/// Decides the stream's outcome once `data: [DONE]` (or a clean EOF, via the
/// `Truncated` path in the caller) is reached, from the LAST `finish_reason`
/// observed across every chunk. `started` closes every still-open block
/// (`BlockStop`, first-seen order) only on the success path -- a failure
/// carries no events back to the caller, only `partial_text`.
fn finalize(
    mut events: Vec<StreamEvent>,
    started: &[u32],
    finish_reason: Option<String>,
) -> Result<Vec<StreamEvent>, StreamFailure> {
    match finish_reason.as_deref() {
        // `"stop"`: an ordinary clean ending. `"tool_calls"`: ALSO a
        // successful, non-failure ending -- the model is waiting for a tool
        // result, not erroring.
        Some("stop") | Some("tool_calls") => {
            for &index in started {
                events.push(StreamEvent::BlockStop { index });
            }
            events.push(StreamEvent::MessageStop);
            Ok(events)
        }
        Some("length") => Err(StreamFailure {
            kind: StreamFailureKind::Length,
            message: "openai-chat generation stopped: length (a token/context limit was reached \
                       before the model finished)"
                .into(),
            partial_text: partial_text_from_events(&events),
        }),
        Some("content_filter") => Err(StreamFailure {
            kind: StreamFailureKind::ContentFilter,
            message: "openai-chat generation stopped: content_filter".into(),
            partial_text: partial_text_from_events(&events),
        }),
        Some(other) => {
            let safe = sanitize_untrusted_wire_string(other);
            Err(StreamFailure {
                kind: StreamFailureKind::UnrecognizedFinishReason,
                message: format!(
                    "openai-chat chat stream reached [DONE] with an unrecognized \
                     finish_reason {safe}"
                ),
                partial_text: partial_text_from_events(&events),
            })
        }
        None => Err(StreamFailure {
            kind: StreamFailureKind::UnrecognizedFinishReason,
            message: "openai-chat chat stream reached [DONE] without ever observing a \
                       finish_reason on any chunk"
                .into(),
            partial_text: partial_text_from_events(&events),
        }),
    }
}

/// Decodes an OpenAI chat-completions SSE response body into normalized [`StreamEvent`]s.
///
/// Parses `data: {...}` frames (terminated by `data: [DONE]`), keys each
/// `choices[0].delta.tool_calls[].index` (an integer) through [`DeltaKeyer::index_for`]
/// (stringified) to obtain a stable block index, and synthesizes `BlockStart`/`BlockDelta`/
/// `BlockStop` events per §9.3's normative rules.
///
/// `BlockStop` events are emitted in first-seen (`BlockStart`) order, never in an
/// unspecified iteration order — see audit finding 4 in the task-8 brief: an earlier draft
/// used a `HashSet<u32>` to track started blocks and iterated it to emit `BlockStop`, which
/// is nondeterministic with multiple concurrent tool calls and violates §9.3's "block order
/// is established at `BlockStart` and never reordered." This implementation tracks
/// started-block order in a `Vec<u32>` (fix round 3, Q6: membership is checked via a
/// companion `HashSet<u32>` so a stream with many distinct tool-call indices doesn't cost
/// O(n²) -- the `Vec` alone still owns emission order).
pub async fn decode_openai_chat_stream(
    body: impl Stream<Item = Result<Bytes, TransportError>> + Send + Unpin,
) -> Result<Vec<StreamEvent>, StreamFailure> {
    let mut sse = SseStream::from_bytes_stream(body);
    let mut keyer = DeltaKeyer::new();
    let mut started_order: Vec<u32> = Vec::new();
    let mut started_set: HashSet<u32> = HashSet::new();
    let mut events = Vec::new();
    let mut finish_reason: Option<String> = None;

    while let Some(frame) = sse.next().await {
        // Fix round 3, Q1: a mid-stream transport/SSE-framing error must
        // not be swallowed as benign -- mirrors `cohere_v2::decode`'s
        // identical fix. `e`'s `Display` can embed the full request URL
        // (query string, userinfo) verbatim, so it is redacted before it
        // ever reaches this `pub` field.
        //
        // Fix round 4, R4: redacted via the shared
        // `crate::audit::redact_transport_error_text`, not
        // `crate::audit::redact_error_body` alone -- the latter strips only
        // labeled token/key-shaped secrets, not a URL's query string or
        // userinfo, so the claim above was false until this codec started
        // sharing `cohere_v2`'s real implementation of it.
        let frame = match frame {
            Ok(f) => f,
            Err(e) => {
                return Err(StreamFailure {
                    kind: StreamFailureKind::Transport,
                    message: redact_transport_error_text(&format!(
                        "SSE transport error while decoding the openai-chat stream: {e}"
                    )),
                    partial_text: partial_text_from_events(&events),
                });
            }
        };
        // SSE keep-alive/comment frames (e.g. a bare `:` comment line, used by some
        // proxies/backends to hold the connection open) legitimately carry no `data`
        // field at all. That's not an error condition — just skip and wait for the
        // next frame.
        let Some(data) = frame.data else { continue };
        let data = data.trim();
        if data == "[DONE]" {
            return finalize(events, &started_order, finish_reason);
        }
        let Ok(value) = serde_json::from_str::<Value>(data) else {
            continue;
        };
        // Fix round 3, Q1: an in-band `{"error": {...}}` frame -- the shape
        // OpenAI-*compatible* gateways emit for a failure arriving after
        // the initial 200 -- has no `choices` field at all. Checked BEFORE
        // the generic `Chunk` parse below (which would otherwise
        // deserialize it as a harmless-looking, entirely empty `Chunk` now
        // that `choices` has `#[serde(default)]`, silently discarding the
        // error).
        //
        // Fix round 4, R1: `value.get("error")` returns `Some(&Value::Null)`
        // for a chunk that explicitly serializes `"error": null` -- the
        // default shape an SDK-generated OpenAI-*compatible* gateway emits
        // on every normal chunk. Without the `is_null()` guard, EVERY such
        // chunk was misclassified as an in-band failure and the model's
        // real output was thrown away. Only a present, non-null `error`
        // value is a genuine failure signal.
        if let Some(err_obj) = value.get("error").filter(|v| !v.is_null()) {
            let message = err_obj
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("(no message field on the in-band error frame)");
            return Err(StreamFailure {
                kind: StreamFailureKind::Error,
                message: format!(
                    "openai-chat stream carried an in-band error frame: {}",
                    sanitize_untrusted_wire_string(message)
                ),
                partial_text: partial_text_from_events(&events),
            });
        }
        let Ok(chunk) = serde_json::from_value::<Chunk>(value) else {
            continue;
        };

        for choice in &chunk.choices {
            if let Some(reason) = &choice.finish_reason {
                finish_reason = Some(reason.clone());
            }
            // Fix round 1, P1: text deltas are keyed through the SAME
            // `DeltaKeyer` as tool calls, but via a non-numeric sentinel key
            // (`"content"`) rather than a stringified integer -- tool-call
            // indices are always `tc.index.to_string()` (e.g. `"0"`, `"1"`),
            // so `"content"` can never collide with one. A shared keyer
            // namespace where a text and a tool-call index DID collide is
            // exactly what silently dropped a tool call in `cohere_v2` two
            // tasks ago; this sentinel avoids reproducing that.
            if let Some(content) = &choice.delta.content {
                if !content.is_empty() {
                    let index = keyer.index_for("content");
                    if started_set.insert(index) {
                        started_order.push(index);
                        events.push(StreamEvent::BlockStart {
                            index,
                            kind: BlockKind::Text,
                        });
                    }
                    events.push(StreamEvent::BlockDelta {
                        index,
                        delta: BlockDelta::Text(content.clone()),
                    });
                }
            }
            for tc in &choice.delta.tool_calls {
                let index = keyer.index_for(&tc.index.to_string());
                if started_set.insert(index) {
                    started_order.push(index);
                    events.push(StreamEvent::BlockStart {
                        index,
                        kind: BlockKind::ToolUse {
                            name: tc
                                .function
                                .as_ref()
                                .and_then(|f| f.name.clone())
                                .unwrap_or_default(),
                            provider_id: tc.id.clone(),
                        },
                    });
                }
                if let Some(function) = &tc.function {
                    if let Some(args) = &function.arguments {
                        if !args.is_empty() {
                            // §9.3 normative rule: tool-argument JSON fragments are
                            // concatenated as raw, opaque strings here — never parsed
                            // as JSON mid-stream. A single fragment (e.g. `{"path":`)
                            // is not valid JSON on its own; only the full string,
                            // concatenated across every `BlockDelta` for this index up
                            // to `BlockStop`, is guaranteed to parse. Parsing eagerly
                            // per-fragment would fail on most chunks and gains nothing,
                            // since the arguments aren't needed until the tool call is
                            // dispatched at `BlockStop`.
                            events.push(StreamEvent::BlockDelta {
                                index,
                                delta: BlockDelta::ToolArgsFragment(args.clone()),
                            });
                        }
                    }
                }
            }
        }

        if let Some(usage) = chunk.usage {
            events.push(StreamEvent::UsageDelta {
                input_tokens: Some(usage.prompt_tokens),
                output_tokens: Some(usage.completion_tokens),
                cache_read_tokens: None,
            });
        }
    }

    // Fix round 3, Q1: reaching here means the frame stream ended (a clean
    // EOF) WITHOUT ever observing a `[DONE]` terminator -- a truncated
    // generation, not a completed one. Returning `Ok(events)` here (the
    // pre-fix-round-3 behavior) is indistinguishable downstream from a real
    // `MessageStop`, and `roundhouse-engine::chat::run_chat_turn` persists
    // it as `TaskCompleted` with plausible-looking partial output on an
    // immutable row. Mirrors `cohere_v2::decode`'s identical `Truncated`
    // fix.
    Err(StreamFailure {
        kind: StreamFailureKind::Truncated,
        message: "openai-chat chat stream ended without ever observing a [DONE] terminator -- \
                   the generation was truncated"
            .into(),
        partial_text: partial_text_from_events(&events),
    })
}

#[cfg(test)]
mod decode_streaming_tests {
    //! End-to-end coverage of `decode_openai_chat_stream` itself, against
    //! synthetic SSE bytes -- not just the two pre-existing fixture-file
    //! tests in `tests/openai_chat_decode.rs`.
    use super::decode_openai_chat_stream;
    use crate::stream_event::StreamEvent;
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

    fn expect_failure(
        result: Result<Vec<StreamEvent>, super::StreamFailure>,
    ) -> super::StreamFailure {
        match result {
            Ok(_) => panic!("expected a StreamFailure, got a successful decode"),
            Err(failure) => failure,
        }
    }

    /// Fix round 3, Q1: a clean EOF with no `[DONE]` ever observed must be
    /// a failure, not a silent `Ok(events)` -- the exact gap that let a
    /// truncated generation persist as `TaskCompleted` downstream.
    #[tokio::test]
    async fn a_stream_with_no_done_terminator_is_a_truncated_stream_failure() {
        let body =
            sse_body(&[r#"{"choices":[{"delta":{"role":"assistant","content":"partial"}}]}"#]);
        let failure = expect_failure(decode_openai_chat_stream(body).await);
        assert_eq!(failure.kind, super::StreamFailureKind::Truncated);
        assert_eq!(failure.partial_text, "partial");
    }

    /// `finish_reason: "length"` must map to a failure carrying the partial
    /// text decoded so far, not a silent success.
    #[tokio::test]
    async fn length_finish_reason_is_a_stream_failure_with_partial_text() {
        let body = sse_body(&[
            r#"{"choices":[{"delta":{"role":"assistant","content":"cut off"}}]}"#,
            r#"{"choices":[{"delta":{},"finish_reason":"length"}]}"#,
            "[DONE]",
        ]);
        let failure = expect_failure(decode_openai_chat_stream(body).await);
        assert_eq!(failure.kind, super::StreamFailureKind::Length);
        assert_eq!(failure.partial_text, "cut off");
    }

    #[tokio::test]
    async fn content_filter_finish_reason_is_a_stream_failure() {
        let body = sse_body(&[
            r#"{"choices":[{"delta":{},"finish_reason":"content_filter"}]}"#,
            "[DONE]",
        ]);
        let failure = expect_failure(decode_openai_chat_stream(body).await);
        assert_eq!(failure.kind, super::StreamFailureKind::ContentFilter);
    }

    /// The exact shape OpenAI-*compatible* gateways use to signal an
    /// in-band failure after the initial 200 has already started
    /// streaming -- must not be silently treated as an empty, harmless
    /// chunk now that `Chunk.choices` has `#[serde(default)]`.
    #[tokio::test]
    async fn an_in_band_error_frame_is_a_stream_failure() {
        let body = sse_body(&[
            r#"{"choices":[{"delta":{"role":"assistant","content":"before "}}]}"#,
            r#"{"error":{"message":"the upstream model is overloaded","type":"overloaded_error"}}"#,
        ]);
        let failure = expect_failure(decode_openai_chat_stream(body).await);
        assert_eq!(failure.kind, super::StreamFailureKind::Error);
        assert!(failure.message.contains("overloaded"));
        assert_eq!(failure.partial_text, "before ");
    }

    #[tokio::test]
    async fn a_missing_finish_reason_before_done_is_a_stream_failure_not_a_silent_success() {
        let body = sse_body(&[
            r#"{"choices":[{"delta":{"role":"assistant","content":"hi"}}]}"#,
            "[DONE]",
        ]);
        let failure = expect_failure(decode_openai_chat_stream(body).await);
        assert_eq!(
            failure.kind,
            super::StreamFailureKind::UnrecognizedFinishReason
        );
    }

    #[tokio::test]
    async fn an_unrecognized_finish_reason_is_a_stream_failure() {
        let body = sse_body(&[
            r#"{"choices":[{"delta":{},"finish_reason":"some_future_value"}]}"#,
            "[DONE]",
        ]);
        let failure = expect_failure(decode_openai_chat_stream(body).await);
        assert_eq!(
            failure.kind,
            super::StreamFailureKind::UnrecognizedFinishReason
        );
    }

    /// Fix round 4, R1: `value.get("error")` matches `Some(Value::Null)` --
    /// serde_json's representation of an explicitly-`null` JSON key -- so an
    /// OpenAI-*compatible* gateway that always serializes an optional
    /// `error` field (`null` on every normal chunk, the default shape for
    /// SDK-generated servers) had every one of its successful turns
    /// misclassified as a `StreamFailureKind::Error` and thrown away, with
    /// the model's actual output discarded. Only a non-null `error` value is
    /// an in-band failure.
    #[tokio::test]
    async fn an_error_field_explicitly_set_to_null_is_not_treated_as_a_failure() {
        let body = sse_body(&[
            r#"{"error":null,"choices":[{"delta":{"content":"a"},"finish_reason":"stop"}]}"#,
            "[DONE]",
        ]);
        let events = decode_openai_chat_stream(body)
            .await
            .expect("a null `error` field must not fail the decode");

        let mut text = String::new();
        for event in &events {
            if let StreamEvent::BlockDelta {
                delta: crate::stream_event::BlockDelta::Text(t),
                ..
            } = event
            {
                text.push_str(t);
            }
        }
        assert_eq!(text, "a");
    }

    /// Fix round 4: re-check requested alongside R1 -- a normal completion
    /// interleaved with a mid-stream `{"choices":[]}` frame (a legitimate
    /// keep-alive-ish shape some backends send) and a final usage-only
    /// chunk with NO `choices` key at all (relying on `Chunk.choices`'
    /// `#[serde(default)]`) must all still succeed and the usage must still
    /// decode -- proving R1's `is_null()` guard didn't over- or
    /// under-shoot the failure classifier.
    #[tokio::test]
    async fn a_normal_completion_with_an_empty_choices_frame_and_a_choicesless_usage_frame_succeeds(
    ) {
        let body = sse_body(&[
            r#"{"choices":[{"delta":{"role":"assistant","content":"hi there"}}]}"#,
            r#"{"choices":[]}"#,
            r#"{"choices":[{"delta":{},"finish_reason":"stop"}]}"#,
            r#"{"usage":{"prompt_tokens":10,"completion_tokens":2}}"#,
            "[DONE]",
        ]);
        let events = decode_openai_chat_stream(body)
            .await
            .expect("must decode successfully");

        let mut text = String::new();
        let mut usage_seen = None;
        let mut saw_message_stop = false;
        for event in &events {
            match event {
                StreamEvent::BlockDelta {
                    delta: crate::stream_event::BlockDelta::Text(t),
                    ..
                } => text.push_str(t),
                StreamEvent::UsageDelta {
                    input_tokens,
                    output_tokens,
                    ..
                } => usage_seen = Some((*input_tokens, *output_tokens)),
                StreamEvent::MessageStop => saw_message_stop = true,
                _ => {}
            }
        }
        assert_eq!(text, "hi there");
        assert_eq!(usage_seen, Some((Some(10), Some(2))));
        assert!(saw_message_stop);
    }

    /// Fix round 3, Q3: a text preamble before a tool call is the common
    /// real-world shape (the model narrates, then calls a tool), not an
    /// edge case -- `openai_chat_tool_call.sse` has no `content` and
    /// `openai_chat_text_content.sse` has no `tool_calls`, so nothing drove
    /// this interleaved shape through the real decode loop before this fix
    /// round.
    #[tokio::test]
    async fn interleaved_text_preamble_and_tool_call_both_decode_correctly() {
        let body = sse_body(&[
            r#"{"choices":[{"delta":{"role":"assistant","content":"Let me check that."}}]}"#,
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"get_weather","arguments":""}}]}}]}"#,
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"city\":\"Tokyo\"}"}}]}}]}"#,
            r#"{"choices":[{"delta":{},"finish_reason":"tool_calls"}]}"#,
            "[DONE]",
        ]);
        let events = decode_openai_chat_stream(body)
            .await
            .expect("must decode successfully");

        let mut text = String::new();
        let mut tool_args = String::new();
        let mut saw_tool_start = false;
        let mut block_starts = 0u32;
        let mut block_stops = 0u32;
        let mut saw_message_stop = false;
        for event in &events {
            match event {
                StreamEvent::BlockStart {
                    kind: crate::stream_event::BlockKind::Text,
                    ..
                } => block_starts += 1,
                StreamEvent::BlockStart {
                    kind: crate::stream_event::BlockKind::ToolUse { name, .. },
                    ..
                } => {
                    assert_eq!(name, "get_weather");
                    saw_tool_start = true;
                    block_starts += 1;
                }
                StreamEvent::BlockStart { .. } => panic!("unexpected block kind"),
                StreamEvent::BlockStop { .. } => block_stops += 1,
                StreamEvent::BlockDelta {
                    delta: crate::stream_event::BlockDelta::Text(t),
                    ..
                } => text.push_str(t),
                StreamEvent::BlockDelta {
                    delta: crate::stream_event::BlockDelta::ToolArgsFragment(f),
                    ..
                } => tool_args.push_str(f),
                StreamEvent::MessageStop => saw_message_stop = true,
                _ => {}
            }
        }
        assert_eq!(text, "Let me check that.");
        assert!(saw_tool_start);
        assert_eq!(tool_args, r#"{"city":"Tokyo"}"#);
        assert_eq!(
            block_starts, 2,
            "both the text block and the tool call must open distinct blocks"
        );
        assert_eq!(block_stops, 2, "both blocks must be closed");
        assert!(saw_message_stop);
    }
}
