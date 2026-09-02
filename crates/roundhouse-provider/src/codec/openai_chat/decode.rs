//! Decodes an OpenAI `/v1/chat/completions` streaming response body (Server-Sent Events)
//! into normalized [`StreamEvent`]s, per §9.3's normative decode rules: block structure
//! (`BlockStart`/`BlockStop`) is always synthesized by the decoder — OpenAI's wire format
//! has no explicit block-boundary markers — and tool-argument JSON fragments are
//! concatenated verbatim, never parsed, until the block closes.

use bytes::Bytes;
use futures::{Stream, StreamExt};
use serde::Deserialize;
use sse_stream::SseStream;

use crate::stream_event::{BlockDelta, BlockKind, DeltaKeyer, StreamEvent};
use crate::TransportError;

/// One `data: {...}` chunk of an OpenAI chat-completions stream.
#[derive(Deserialize)]
struct Chunk {
    /// Per-choice deltas. OpenAI always sends exactly one choice for non-`n>1` requests;
    /// Phase 1 scope only reads `choices[0]`-equivalent (all choices are folded together,
    /// since the IR has no concept of multiple parallel completions).
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
/// started-block order in a `Vec<u32>` instead.
pub async fn decode_openai_chat_stream(
    body: impl Stream<Item = Result<Bytes, TransportError>> + Send + Unpin,
) -> Vec<StreamEvent> {
    let mut sse = SseStream::from_bytes_stream(body);
    let mut keyer = DeltaKeyer::new();
    // Vec, not HashSet (audit finding 4): iteration order must match first-seen order so
    // BlockStop emits in the same order BlockStart opened the blocks (§9.3: "block order
    // is established at BlockStart and never reordered"). The number of concurrent tool
    // calls in one turn is small, so a linear `contains` scan is fine.
    let mut started: Vec<u32> = Vec::new();
    let mut events = Vec::new();
    let mut done = false;

    while let Some(frame) = sse.next().await {
        let Ok(frame) = frame else { continue };
        // SSE keep-alive/comment frames (e.g. a bare `:` comment line, used by some
        // proxies/backends to hold the connection open) legitimately carry no `data`
        // field at all. That's not an error condition — just skip and wait for the
        // next frame.
        let Some(data) = frame.data else { continue };
        let data = data.trim();
        if data == "[DONE]" {
            done = true;
            break;
        }
        let Ok(chunk) = serde_json::from_str::<Chunk>(data) else {
            continue;
        };

        for choice in &chunk.choices {
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
                    if !started.contains(&index) {
                        started.push(index);
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
                if !started.contains(&index) {
                    started.push(index);
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

    // All blocks close before the message as a whole stops, so `BlockStop`s are always
    // emitted ahead of `MessageStop` — never after it.
    for &index in &started {
        events.push(StreamEvent::BlockStop { index });
    }
    if done {
        events.push(StreamEvent::MessageStop);
    }

    events
}
