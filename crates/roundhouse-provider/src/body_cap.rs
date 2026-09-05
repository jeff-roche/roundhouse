//! Phase 7 Task 15: a shared, capped response-body collector.
//!
//! Every codec's `provider.rs` (`anthropic_messages`, `openai_chat`,
//! `openai_chat::azure_provider`, `openai_responses`, `google_genai`,
//! `cohere_v2`, `bedrock_converse`) hand-rolled an identical
//! `while let Some(chunk) = body.next().await { out.extend_from_slice(&chunk) }`
//! loop to buffer a non-success HTTP response's body before handing it to
//! `errors::classify`. None of the seven capped the total — a peer
//! (malicious, or merely a broken proxy) that kept streaming chunks on a
//! non-success response could make this process buffer without bound.
//! [`collect_body_capped`] is the one implementation all seven now call.
//!
//! This only ever runs on the error-classification path. **The success path
//! is deliberately out of scope for this cap and remains unbounded** (fix
//! round 1, Ruling R26 / security S7 — an earlier version of this comment
//! wrongly claimed the success path "streams and decodes incrementally
//! without ever buffering a whole body"; it does not).
//! `reqwest_transport.rs`'s own doc comment (around its
//! `decode_anthropic_messages_stream` usage) says the opposite: that
//! consumer drains its stream into a `Vec<StreamEvent>` before returning,
//! and `sse-stream`'s internal line buffer is unbounded too.
//! `codec::openai_chat::decode::decode_openai_chat_stream` shows the same
//! shape — it accumulates a `Vec<StreamEvent>` across SSE frames with no
//! byte accounting, and `decode_guard::DecodeLoopGuard` bounds only a
//! `saw_message_stop` flag, not bytes or iterations. A hostile or
//! compromised HTTP-200 endpoint that streams forever is not stopped by
//! anything this module adds; bounding the success path is separate,
//! carry-forward work, not something this cap closes. Bounding the
//! error-classification path here closes only that one gap.
//!
//! **Relationship to `transport::eventstream::MAX_BUFFERED_BYTES` (26 MiB):**
//! that constant bounds a single AWS eventstream *frame* while it's being
//! reassembled from a `total_length` prelude that the sender fully controls
//! — a narrower, more attacker-adjacent quantity than what's bounded here.
//! [`MAX_RESPONSE_BODY_BYTES`] bounds an entire HTTP response body (however
//! many chunks/frames it's split into) on the error-classification path.
//! The two are deliberately different constants for different quantities,
//! not duplicates of each other.
use bytes::Bytes;
use futures::Stream;

use crate::transport::TransportError;

/// A generous ceiling for a single provider HTTP response body. No shipped
/// profile's model has a published max-output-token count that would
/// plausibly produce a body anywhere near this size when rendered as JSON
/// (even a generous 8 bytes/token estimate against the largest published
/// output-token ceilings among this crate's profiles — low hundreds of
/// thousands of tokens — lands in the single-digit megabytes), and this cap
/// only ever applies to the error-classification path, which never carries
/// legitimate large payloads like generated images. Chosen as roughly 2.5x
/// `transport::eventstream::MAX_BUFFERED_BYTES` (26 MiB) — a different
/// quantity (see module doc comment) but a useful order-of-magnitude anchor
/// for "how big does a same-project safety ceiling of this kind get" —
/// rather than picked to fit any one provider's numbers exactly.
pub const MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Collects `body` into a single buffer, rejecting the moment the running
/// total would exceed `cap` — never allocating or buffering past it.
///
/// A chunk-level transport error (`Err` from the stream itself) is silently
/// skipped, matching every per-codec loop this replaces: this collector only
/// ever runs on the error-classification path, building best-effort
/// diagnostic text from whatever chunks did arrive, not a success-path
/// decode where a transport error must be surfaced.
pub async fn collect_body_capped<S>(body: S, cap: usize) -> Result<Vec<u8>, TransportError>
where
    S: Stream<Item = Result<Bytes, TransportError>>,
{
    futures::pin_mut!(body);
    use futures::StreamExt;

    let mut out = Vec::new();
    while let Some(chunk) = body.next().await {
        let Ok(chunk) = chunk else {
            continue;
        };
        if out.len() + chunk.len() > cap {
            return Err(TransportError::ResponseTooLarge { limit: cap });
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}
