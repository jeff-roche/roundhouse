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
use futures::stream::FusedStream;
use futures::{Stream, StreamExt};
use serde_json::Value;
use sse_stream::SseStream;

use crate::audit::redact_transport_error_text;
use crate::decode_guard::DecodeLoopGuard;
use crate::stream_event::{BlockDelta, BlockKind, StreamEvent};
use crate::TransportError;

/// How `provider.rs` should map a [`StreamFailure`] onto a `ProviderError` —
/// this codec joins the "strict" truncation-signaling group (Ruling R17):
/// its own decode loop returns `Err` when it never observes `message_stop`,
/// mirroring `openai_chat`/`cohere_v2`'s identical `StreamFailureKind`
/// shape (Ruling R1: deliberately NOT unified into one crate-level enum —
/// see `crate::decode_guard`'s module doc for why).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamFailureKind {
    /// The stream ended (a clean EOF) without ever observing a
    /// `message_stop` event — a dropped connection or a graceful proxy
    /// termination mid-generation, not a completed one.
    Truncated,
    /// A mid-stream SSE/transport read error (e.g. a reset connection).
    /// Ruling R17: this codec's `let Ok(frame) = frame else { continue };`
    /// used to silently swallow exactly this, making a reset connection
    /// indistinguishable from a benign skipped keep-alive frame — the last
    /// codec in this crate still doing that.
    Transport,
}

/// A terminal, spec-verified failure signaled mid-stream. Deliberately not
/// a `ProviderError` — this module has no `ProviderProfile` to classify
/// through; `provider.rs` maps this into the real `ProviderError` by
/// `kind`. Mirrors `cohere_v2::decode::StreamFailure`'s shape, `kind` and
/// `partial_text` included (Ruling R17: going strict without `partial_text`
/// would discard partial output today's bare `Vec<StreamEvent>` return
/// preserves).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFailure {
    /// How `provider.rs` should map this into a `ProviderError`.
    pub kind: StreamFailureKind,
    /// A human-readable description of the failure. Redacted for the
    /// `Transport` kind, since a mid-stream transport error's text can
    /// embed the full request URL, query string and all.
    pub message: String,
    /// Text decoded before the failure occurred (`BlockDelta::Text`
    /// fragments, concatenated in first-seen order).
    pub partial_text: String,
}

/// The largest `signature_delta` value this decoder will accept from the
/// wire. A frame carrying more than this is treated as a **wire-protocol
/// violation** and fails the whole stream closed
/// ([`StreamFailureKind::Transport`]); it is never truncated, and never
/// silently dropped.
///
/// **Why a cap at all (Controller ruling R22).** A thinking signature is the
/// one piece of provider output that is (a) taken verbatim off the wire here
/// with no shape validation, (b) deliberately never redacted —
/// `Redactor::redact_event_payload`'s `Delta::Thinking` arm passes
/// `signature` through untouched so it can round-trip — and (c) emitted by
/// `roundhouse_engine::delta_sink::DeltaCoalescer::close_pending` without
/// ever consulting the inline-size limit (its R3 exemption). Nothing on the
/// success path caps total bytes either (`body_cap` covers only the
/// error-classification path, and `sse-stream`'s line buffer is unbounded),
/// so without this ceiling a hostile or compromised endpoint could write
/// unbounded, unredacted rows into the `events` table — which physically
/// rejects `UPDATE`/`DELETE`, so they could never be removed.
///
/// **Why fail closed rather than drop or truncate.** A thinking block whose
/// signature is missing or altered cannot be replayed on the next turn: that
/// is `docs/architecture/01-data-model.md` §1.1's bug #1, the bricked
/// resume, which `Delta::Thinking`'s verbatim round-trip exists to prevent.
/// Failing the turn is recoverable; a silently designature'd thinking block
/// persisted to an append-only log is not.
///
/// **Why 64 KiB.** Real Anthropic signatures run from a few hundred bytes to
/// low kilobytes, so this leaves more than an order of magnitude of headroom
/// for a format change while still bounding a single row to something a log
/// can hold. It is deliberately not tight: the point is to bound the damage,
/// not to police the wire format.
pub const MAX_THINKING_SIGNATURE_BYTES: usize = 64 * 1024;

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

/// Owns everything one decode pass over an Anthropic Messages SSE body
/// accumulates across frames, so both the incremental
/// [`decode_anthropic_messages_events`] loop and (through it)
/// [`decode_anthropic_messages_stream`]'s collect adapter dispatch on exactly
/// the same rules and can never diverge on what a given frame decodes to:
///
/// - the `message_start`/`message_delta` usage halves, buffered until both
///   are available (see [`AnthropicDecodeState::on_frame`]'s doc comment);
/// - [`DecodeLoopGuard`]'s "did we ever see `message_stop`" tracking;
/// - a running concatenation of every `BlockDelta::Text` fragment decoded so
///   far, for `StreamFailure::partial_text` if the stream fails before
///   completing (mirrors the old buffered loop's `partial_text_from_events`
///   helper, computed incrementally instead of by re-scanning `events` at
///   the point of failure).
#[derive(Default)]
struct AnthropicDecodeState {
    guard: DecodeLoopGuard,
    // Buffered from `message_start`; combined with `message_delta`'s `output_tokens` into
    // one `UsageDelta` (see `on_frame`'s doc comment).
    initial_input_tokens: Option<u64>,
    initial_cache_read_tokens: Option<u64>,
    partial_text: String,
}

impl AnthropicDecodeState {
    fn new() -> Self {
        Self::default()
    }

    /// Applies one already-JSON-parsed SSE frame payload, dispatching on its
    /// `type` field exactly as the original buffered loop's `match` did, and
    /// returns the single normalized event it produced, if any. A frame with
    /// no (or a non-string) `type` field produces `None`, same as an
    /// unrecognized `type` — this never treats a malformed frame as fatal,
    /// since this decoder processes live bytes from Anthropic's network API
    /// and must not panic on an unexpected shape.
    ///
    /// `message_start` never produces an event by itself: it only buffers
    /// the input/cache usage halves that `message_delta` later combines into
    /// one [`StreamEvent::UsageDelta`] (Anthropic splits usage reporting
    /// across the start and end of the stream). Buffering rather than
    /// emitting immediately also keeps the first real *content* event
    /// (`BlockStart`) as the first event a consumer sees, rather than a
    /// usage bookkeeping event with no content behind it yet.
    ///
    /// The one `Err` this can return is a `signature_delta` past
    /// [`MAX_THINKING_SIGNATURE_BYTES`] (Controller ruling R22) — a
    /// wire-protocol violation, terminal for the whole stream. Every other
    /// malformed shape stays non-fatal (`Ok(None)`).
    fn on_frame(&mut self, payload: &Value) -> Result<Option<StreamEvent>, StreamFailure> {
        let Some(kind) = payload.get("type").and_then(Value::as_str) else {
            return Ok(None);
        };

        let event = match kind {
            "message_start" => {
                if let Some(usage) = payload.pointer("/message/usage") {
                    self.initial_input_tokens = usage.get("input_tokens").and_then(Value::as_u64);
                    self.initial_cache_read_tokens =
                        usage.get("cache_read_input_tokens").and_then(Value::as_u64);
                }
                None
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
                        name: payload
                            .pointer("/content_block/name")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                        provider_id: payload
                            .pointer("/content_block/id")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                    },
                    _ => BlockKind::Text,
                };
                Some(StreamEvent::BlockStart {
                    index,
                    kind: block_kind,
                })
            }
            "content_block_delta" => {
                let index = payload.get("index").and_then(Value::as_u64).unwrap_or(0) as u32;
                let delta_type = payload
                    .pointer("/delta/type")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let delta = match delta_type {
                    "text_delta" => Some(BlockDelta::Text(
                        payload
                            .pointer("/delta/text")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                    )),
                    "input_json_delta" => Some(BlockDelta::ToolArgsFragment(
                        payload
                            .pointer("/delta/partial_json")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                    )),
                    "thinking_delta" => Some(BlockDelta::Thinking {
                        text: payload
                            .pointer("/delta/thinking")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                        signature: None,
                    }),
                    "signature_delta" => {
                        let signature = payload.pointer("/delta/signature").and_then(Value::as_str);
                        // Ruling R22: cap at DECODE and fail closed. See
                        // `MAX_THINKING_SIGNATURE_BYTES`'s doc comment for why
                        // this one malformed shape is terminal where every
                        // other one is skipped, and why dropping or truncating
                        // the signature would be worse than failing the turn.
                        // The message reports the LENGTH only -- never the
                        // signature bytes themselves, which end up in a
                        // `ProviderError` that gets logged.
                        if let Some(len) = signature.map(str::len) {
                            if len > MAX_THINKING_SIGNATURE_BYTES {
                                return Err(StreamFailure {
                                    kind: StreamFailureKind::Transport,
                                    message: format!(
                                        "anthropic-messages signature_delta carried {len} bytes, \
                                         past the {MAX_THINKING_SIGNATURE_BYTES}-byte ceiling -- \
                                         a wire-protocol violation, so this stream fails rather \
                                         than persisting an unbounded, unredactable thinking \
                                         signature"
                                    ),
                                    partial_text: std::mem::take(&mut self.partial_text),
                                });
                            }
                        }
                        Some(BlockDelta::Thinking {
                            text: String::new(),
                            signature: signature.map(str::to_string),
                        })
                    }
                    _ => None,
                };
                delta.map(|delta| StreamEvent::BlockDelta { index, delta })
            }
            "content_block_stop" => {
                let index = payload.get("index").and_then(Value::as_u64).unwrap_or(0) as u32;
                Some(StreamEvent::BlockStop { index })
            }
            "message_delta" => {
                let output_tokens = payload
                    .pointer("/usage/output_tokens")
                    .and_then(Value::as_u64);
                // Only emit a combined UsageDelta if there's something to report — either
                // half (message_start's input/cache figures, or this message_delta's
                // output figure) may legitimately be absent on a malformed/partial stream.
                if self.initial_input_tokens.is_some()
                    || self.initial_cache_read_tokens.is_some()
                    || output_tokens.is_some()
                {
                    let input_tokens = self.initial_input_tokens.map(|input| {
                        normalize_anthropic_usage(
                            input,
                            self.initial_cache_read_tokens.unwrap_or(0),
                        )
                    });
                    Some(StreamEvent::UsageDelta {
                        input_tokens,
                        output_tokens,
                        cache_read_tokens: self.initial_cache_read_tokens,
                    })
                } else {
                    None
                }
            }
            "message_stop" => Some(StreamEvent::MessageStop),
            _ => None,
        };

        if let Some(event) = &event {
            self.guard.observe(event);
            if let StreamEvent::BlockDelta {
                delta: BlockDelta::Text(text),
                ..
            } = event
            {
                self.partial_text.push_str(text);
            }
        }

        Ok(event)
    }
}

/// Decodes an Anthropic Messages SSE response body into normalized
/// [`StreamEvent`]s incrementally: each item is yielded as soon as its frame
/// has fully arrived and decoded, without waiting for the rest of the body
/// (§9.3 — "streaming is the only path"). `sse_stream::SseStream` already
/// reassembles line/frame boundaries independent of how the underlying
/// transport chunked the bytes, so this only has to drive it frame by frame
/// through [`AnthropicDecodeState::on_frame`] rather than draining it first;
/// see that method's doc comment for the per-`type` dispatch rules and
/// `AnthropicDecodeState`'s for what state carries across frames.
///
/// Built with [`futures::stream::unfold`] over `(SseStream, state, done)`:
/// each poll drives the SSE parser frame by frame, skipping frames that
/// decode to no event (`message_start`, keep-alives, malformed/unrecognized
/// frames), until one produces an event, the body ends, or a transport error
/// arrives. `done` latches once a `StreamFailure` has been yielded, so the
/// underlying body is never polled again after one and a second terminal
/// item can never be produced. A CLEAN end is not latched — the closure
/// simply returns `None` and the whole `(sse, state, done)` tuple is dropped
/// — and `unfold` panics rather than yielding if polled after returning
/// `Poll::Ready(None)`. That is why the returned stream is `.fuse()`d here,
/// making it a [`FusedStream`] that yields `None` forever once ended: the
/// panic is unreachable for any caller, including one that re-polls through
/// a `select!`/`chain`/replay wrapper.
///
/// Ruling R17 (Phase 7, Task 11): joins the "strict" truncation-signaling
/// group (`openai_chat`, `cohere_v2`) — at EOF, yields at most one terminal
/// `Err(StreamFailure { kind: Truncated, .. })` if `message_stop` was never
/// observed ([`DecodeLoopGuard::finish`]), and a mid-stream transport/SSE-
/// framing error yields `Err(StreamFailure { kind: Transport, .. })` and
/// stops rather than being silently swallowed (matching
/// `openai_chat`/`cohere_v2::decode`'s identical fix — this used to be `let
/// Ok(frame) = frame else { continue };`, indistinguishable from a benign
/// skipped keep-alive frame).
pub fn decode_anthropic_messages_events<B>(
    body: B,
) -> impl FusedStream<Item = Result<StreamEvent, StreamFailure>> + Send
where
    B: Stream<Item = Result<Bytes, TransportError>> + Send + Unpin,
{
    let sse = SseStream::from_bytes_stream(body);
    let state = AnthropicDecodeState::new();

    futures::stream::unfold(
        (sse, state, false),
        |(mut sse, mut state, done)| async move {
            if done {
                return None;
            }
            loop {
                match sse.next().await {
                    None => {
                        return match std::mem::take(&mut state.guard).finish() {
                            Ok(()) => None,
                            Err(_) => {
                                let failure = StreamFailure {
                                    kind: StreamFailureKind::Truncated,
                                    message: "anthropic-messages stream ended without ever \
                                          observing a message_stop event -- the generation was \
                                          truncated"
                                        .into(),
                                    partial_text: std::mem::take(&mut state.partial_text),
                                };
                                Some((Err(failure), (sse, state, true)))
                            }
                        };
                    }
                    Some(Err(e)) => {
                        let failure = StreamFailure {
                            kind: StreamFailureKind::Transport,
                            message: redact_transport_error_text(&format!(
                            "SSE transport error while decoding the anthropic-messages stream: {e}"
                        )),
                            partial_text: std::mem::take(&mut state.partial_text),
                        };
                        return Some((Err(failure), (sse, state, true)));
                    }
                    Some(Ok(frame)) => {
                        // SSE keep-alive/comment frames carry no `data` field at all — not an
                        // error, just skip and wait for the next frame (matches the OpenAI
                        // decoder's handling of the same real `sse-stream` API shape).
                        let Some(data) = frame.data else { continue };
                        let Ok(payload) = serde_json::from_str::<Value>(data.trim()) else {
                            continue;
                        };
                        match state.on_frame(&payload) {
                            // A wire-protocol violation (ruling R22's signature
                            // ceiling): terminal, like any other `StreamFailure`.
                            Err(failure) => return Some((Err(failure), (sse, state, true))),
                            Ok(Some(event)) => return Some((Ok(event), (sse, state, false))),
                            // This frame decoded to no event (e.g. `message_start`, or an
                            // unrecognized/malformed shape) — keep polling for the next one
                            // instead of yielding a hole in the item stream.
                            Ok(None) => {}
                        }
                    }
                }
            }
        },
    )
    // Ruling R22's sibling correction: `futures::stream::unfold` PANICS
    // ("Unfold must not be polled after it returned Poll::Ready(None)")
    // rather than yielding `None` again, and the `done` latch above does
    // NOT cover the clean-end case (the closure returns `None` and the
    // whole tuple is dropped, so nothing is left to latch). Fusing here —
    // inside this `pub fn`, not at each call site — makes that hazard
    // unrepresentable for every caller: the returned stream is a
    // [`FusedStream`] that yields `None` forever once it has ended.
    .fuse()
}

/// Decodes an Anthropic Messages SSE response body into normalized
/// [`StreamEvent`]s, collecting the whole body first. A collect adapter over
/// [`decode_anthropic_messages_events`] — kept as its own function, with this
/// exact signature, because `AnthropicMessagesProfileProvider` still consumes
/// a `Vec<StreamEvent>` rather than the stream directly (Phase 8 T19b Task 3
/// is what makes `crate::anthropic_provider::AnthropicMessagesProvider`
/// consume the incremental stream instead). This crate's integration test
/// `tests/anthropic_messages_decode.rs` drives it too; this module itself has
/// no `#[cfg(test)]` module.
pub async fn decode_anthropic_messages_stream(
    body: impl Stream<Item = Result<Bytes, TransportError>> + Send + Unpin,
) -> Result<Vec<StreamEvent>, StreamFailure> {
    let events = decode_anthropic_messages_events(body);
    futures::pin_mut!(events);

    let mut out = Vec::new();
    while let Some(item) = events.next().await {
        out.push(item?);
    }
    Ok(out)
}
