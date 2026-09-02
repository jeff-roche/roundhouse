//! The `sigv4-eventstream` transport shim (§9.4): SigV4 signs the whole
//! request up front (`roundhouse_secrets::credential::sigv4::sign`, via the
//! `CredentialProvider::apply` seam — this module has nothing to do with
//! signing), then each binary frame in the response is decoded with
//! [`aws_smithy_eventstream`]'s message parser. Bedrock's legacy non-Claude
//! models are the one place in this crate that isn't SSE: the response body
//! is `application/vnd.amazon.eventstream`, a length-prefixed binary framing
//! with CRC32 checksums, not text.
//!
//! **Framing is not hand-rolled here.** [`aws_smithy_eventstream::frame`]
//! (the AWS-published, independently-tested implementation of the format
//! documented at <https://smithy.io/2.0/aws/amazon-eventstream.html>) owns
//! every byte of prelude parsing, header decoding, and CRC verification.
//! This module's only job is to feed it bytes at whatever chunk boundary the
//! transport actually delivered them (verified against that crate's own
//! vendored source at `aws-smithy-eventstream` 0.60.21 / `aws-smithy-types`
//! 1.6.2 — see [`EventStreamDecoder`]'s doc comment for why a persistent,
//! incrementally-advanced buffer is required, not a fresh one per call).
//!
//! **One gap in the underlying crate this shim closes itself**: reading
//! `aws-smithy-eventstream 0.60.21`'s `MessageFrameDecoder::decode_frame`
//! (`frame.rs`) shows it validates a message's internal length arithmetic
//! (checked subtraction, no panics) but applies **no ceiling** on the
//! attacker-controlled `total_length` prelude field before deciding how many
//! more bytes to wait for — a peer that sends a prelude claiming a
//! multi-gigabyte message would make this decoder buffer indefinitely,
//! genuinely unbounded, waiting for bytes that may never arrive. AWS's own
//! documented real-world ceiling (25,165,824 bytes / 24 MB payload +
//! 131,072 bytes / 128 kB headers, from the fetched Bedrock `ConverseStream`
//! reference) is the basis for [`MAX_BUFFERED_BYTES`] below: this shim
//! refuses to grow its own accumulator past that bound and fails closed
//! instead, regardless of what any individual frame's prelude claims.

use aws_smithy_eventstream::frame::{DecodedFrame, MessageFrameDecoder};
use aws_smithy_types::event_stream::Message;
use bytes::BytesMut;

/// A generous ceiling above AWS's own documented real maximum message size
/// (24 MB payload + 128 kB headers, see the module doc comment) — high
/// enough that no legitimate Bedrock Converse event ever approaches it, low
/// enough that a peer (malicious or merely broken) claiming an
/// absurd `total_length` cannot make this process buffer without bound
/// while waiting for bytes that will never complete a frame.
pub const MAX_BUFFERED_BYTES: usize = 26 * 1024 * 1024;

/// A single feed/decode step failed. Both variants are terminal for this
/// decoder: once framing has gone wrong, subsequent bytes can no longer be
/// trusted to be correctly boundary-aligned, so [`EventStreamDecoder::feed`]
/// poisons itself rather than risk silently mis-framing what comes next.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EventStreamDecodeError {
    /// The accumulated, not-yet-complete bytes for the frame currently being
    /// decoded exceeded [`MAX_BUFFERED_BYTES`] — see the module doc comment.
    #[error(
        "eventstream frame exceeded the {MAX_BUFFERED_BYTES}-byte safety ceiling before completing \
         (attacker-controlled length prefix, or a genuinely oversized/corrupt response)"
    )]
    MessageTooLarge,
    /// `aws_smithy_eventstream`'s own parser rejected the bytes (bad prelude
    /// CRC, bad message CRC, malformed header, invalid length arithmetic,
    /// ...). Its `Error` type has no public, matchable variants at all
    /// (verified against the vendored source: `is_invalid_message()` is its
    /// only public introspection method), so the message is carried as text.
    #[error("eventstream framing error: {0}")]
    Framing(String),
    /// `feed` was called again after a previous call already returned an
    /// error. Once framing has desynchronized there is no safe way to
    /// interpret further bytes as belonging to a subsequent, correctly
    /// aligned frame.
    #[error("eventstream decoder already failed on a previous frame; further bytes are refused")]
    Poisoned,
}

/// Decodes a stream of raw bytes (delivered at whatever chunk boundary the
/// transport chose — this is exactly what the conformance suite's
/// adversarial `ChunkStrategy` replay exercises) into discrete
/// [`aws_smithy_types::event_stream::Message`]s.
///
/// The accumulator is a single [`bytes::BytesMut`], not a hand-rolled
/// multi-chunk queue (fix-round-1 H1: an earlier version kept a
/// `VecDeque<Bytes>` and implemented `bytes::Buf` over it by hand, which made
/// `remaining()` an O(chunks) scan — called ~3× per `feed` (once here, twice
/// more inside the vendored `decode_frame`) — so a peer drip-feeding one byte
/// per chunk turned ~1M attacker chunks into ~10¹² operations, wedging the
/// task long before the byte-count ceiling below could ever fire; each
/// 1-byte `Bytes` entry also cost roughly 50-60× its payload in allocator/
/// struct overhead, so the ceiling bounded wire bytes, not process memory).
/// `BytesMut` gives `remaining()`/`chunk()`/`advance()` all O(1) (verified
/// against its own vendored source: `remaining` is `self.len()`, `advance`
/// is a pointer bump within the existing allocation, `chunk()` returns the
/// single contiguous remaining slice), and `extend_from_slice` amortizes
/// growth the same way `Vec::push` does — no per-chunk allocation at all, so
/// the byte-count ceiling now actually bounds memory, not just a miscounted
/// proxy for it. This still needs to be **one persistent instance reused
/// across calls**, for the same reason a hand-rolled queue did:
/// `aws_smithy_eventstream::frame::MessageFrameDecoder::decode_frame` caches
/// the message prelude *inside itself* the first time it sees enough bytes
/// to read one (`prelude_read: bool` + a fixed-size `prelude` array, per its
/// vendored source), and on every later call it trusts that the bytes it
/// already consumed from the buffer are gone for good — it does not re-read
/// or re-skip them. A fresh buffer reconstructed from scratch on every
/// `feed()` call would desynchronize the decoder the moment a message's
/// prelude and its remaining bytes arrive in different `feed()` calls.
pub struct EventStreamDecoder {
    buf: BytesMut,
    decoder: MessageFrameDecoder,
    poisoned: bool,
}

impl Default for EventStreamDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl EventStreamDecoder {
    pub fn new() -> Self {
        Self {
            buf: BytesMut::new(),
            decoder: MessageFrameDecoder::new(),
            poisoned: false,
        }
    }

    /// Feeds `chunk` and returns every complete frame decoded so far.
    ///
    /// Returns [`EventStreamDecodeError`] and poisons the decoder (every
    /// later `feed` call returns [`EventStreamDecodeError::Poisoned`]
    /// immediately) if: the accumulated bytes for an incomplete frame would
    /// exceed [`MAX_BUFFERED_BYTES`], or the underlying parser rejects the
    /// bytes outright. Either way, framing can no longer be trusted to be
    /// correctly boundary-aligned, so this never tries to keep going.
    ///
    /// Fix-round-1 H8: the size check runs against `chunk.len()` BEFORE any
    /// bytes are copied into the accumulator, so an oversized chunk is
    /// rejected without ever being copied (bounded in practice by the
    /// transport's own read-buffer size, but free to check regardless).
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<Message>, EventStreamDecodeError> {
        if self.poisoned {
            return Err(EventStreamDecodeError::Poisoned);
        }

        if self.buf.len().saturating_add(chunk.len()) > MAX_BUFFERED_BYTES {
            self.poisoned = true;
            return Err(EventStreamDecodeError::MessageTooLarge);
        }
        self.buf.extend_from_slice(chunk);

        let mut messages = Vec::new();
        loop {
            match self.decoder.decode_frame(&mut self.buf) {
                Ok(DecodedFrame::Complete(message)) => messages.push(message),
                Ok(DecodedFrame::Incomplete) => break,
                Err(e) => {
                    self.poisoned = true;
                    return Err(EventStreamDecodeError::Framing(e.to_string()));
                }
            }
        }
        Ok(messages)
    }

    /// True if this decoder is currently holding bytes belonging to a frame
    /// that has not yet completed (fix-round-1 H2). `feed`'s inner loop
    /// always drains every complete frame it can before returning, so any
    /// bytes still buffered afterward are unambiguously partial-frame data,
    /// never "nothing pending yet" -- this is exactly, and only, "positive
    /// truncation detection." A caller whose transport stream ends while
    /// this is true knows the underlying connection was cut mid-frame, not
    /// merely between two logically complete messages (the latter is not an
    /// error on its own -- see `decode_bedrock_converse_stream`'s handling
    /// of a body that ends with no `messageStop` at all).
    pub fn is_mid_frame(&self) -> bool {
        !self.buf.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_smithy_eventstream::frame::write_message_to;
    use aws_smithy_types::event_stream::{Header, HeaderValue};

    fn build_message(headers: &[(&str, &str)], payload: &[u8]) -> Message {
        let mut message = Message::new(payload.to_vec());
        for (name, value) in headers {
            message = message.add_header(Header::new(
                name.to_string(),
                HeaderValue::String(value.to_string().into()),
            ));
        }
        message
    }

    fn encode(message: &Message) -> Vec<u8> {
        let mut buf = Vec::new();
        write_message_to(message, &mut buf).expect("valid message must encode");
        buf
    }

    #[test]
    fn decodes_a_single_message_fed_whole() {
        let message = build_message(
            &[(":message-type", "event"), (":event-type", "messageStart")],
            br#"{"role":"assistant"}"#,
        );
        let bytes = encode(&message);

        let mut decoder = EventStreamDecoder::new();
        let decoded = decoder.feed(&bytes).expect("must decode");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].payload().as_ref(), message.payload().as_ref());
    }

    /// The exact bug this module's `ChunkQueue` doc comment describes: the
    /// prelude (first 12 bytes) arrives in one `feed()` call, and the rest
    /// of the message arrives in later calls, one byte at a time. A fresh
    /// per-call buffer would desynchronize here; a persistent one must not.
    #[test]
    fn decodes_a_message_split_byte_by_byte_across_many_feed_calls() {
        let message = build_message(
            &[
                (":message-type", "event"),
                (":event-type", "contentBlockDelta"),
            ],
            br#"{"contentBlockIndex":0,"delta":{"text":"hi"}}"#,
        );
        let bytes = encode(&message);

        let mut decoder = EventStreamDecoder::new();
        let mut decoded = Vec::new();
        for byte in &bytes {
            decoded.extend(
                decoder
                    .feed(std::slice::from_ref(byte))
                    .expect("must decode"),
            );
        }
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].payload().as_ref(), message.payload().as_ref());
    }

    #[test]
    fn decodes_two_back_to_back_messages_fed_as_one_chunk() {
        let m1 = build_message(&[(":message-type", "event")], b"{}");
        let m2 = build_message(&[(":message-type", "event")], b"{\"a\":1}");
        let mut bytes = encode(&m1);
        bytes.extend(encode(&m2));

        let mut decoder = EventStreamDecoder::new();
        let decoded = decoder.feed(&bytes).expect("must decode");
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].payload().as_ref(), b"{}");
        assert_eq!(decoded[1].payload().as_ref(), b"{\"a\":1}");
    }

    #[test]
    fn an_incomplete_message_returns_no_frames_and_does_not_error() {
        let message = build_message(&[(":message-type", "event")], b"{\"hello\":\"world\"}");
        let bytes = encode(&message);
        let mut decoder = EventStreamDecoder::new();
        // Feed everything except the last 4 bytes (the trailing message CRC).
        let decoded = decoder
            .feed(&bytes[..bytes.len() - 4])
            .expect("an incomplete frame is not itself an error");
        assert!(decoded.is_empty());
    }

    /// A corrupted message CRC must surface as an error, not a panic and not
    /// a silently-accepted frame.
    #[test]
    fn a_bad_message_checksum_is_a_framing_error_not_a_panic() {
        let message = build_message(&[(":message-type", "event")], b"{}");
        let mut bytes = encode(&message);
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF; // corrupt the trailing message CRC byte

        let mut decoder = EventStreamDecoder::new();
        let err = decoder
            .feed(&bytes)
            .expect_err("a corrupted CRC must be rejected");
        assert!(matches!(err, EventStreamDecodeError::Framing(_)));
    }

    /// Once poisoned by a framing error, the decoder must refuse ALL further
    /// input rather than attempt to resynchronize on bytes that might belong
    /// to a different frame boundary than the caller assumes.
    #[test]
    fn a_decoder_stays_poisoned_after_a_framing_error() {
        let message = build_message(&[(":message-type", "event")], b"{}");
        let mut bytes = encode(&message);
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;

        let mut decoder = EventStreamDecoder::new();
        assert!(decoder.feed(&bytes).is_err());
        let err = decoder
            .feed(b"anything at all")
            .expect_err("a poisoned decoder must reject further input");
        assert_eq!(err, EventStreamDecodeError::Poisoned);
    }

    /// The core security property this module adds on top of the vendored
    /// crate (see the module doc comment): a prelude claiming an absurd
    /// `total_length` must fail closed well before this process would ever
    /// buffer anywhere near that many bytes, rather than growing without
    /// bound while waiting for bytes that will never arrive.
    #[test]
    fn a_prelude_claiming_an_oversized_total_length_is_rejected_without_unbounded_buffering() {
        // Prelude: total_length (u32 BE) claiming far more than
        // MAX_BUFFERED_BYTES, headers_length (u32 BE) = 0, then a
        // (deliberately wrong, irrelevant here) prelude CRC placeholder.
        // The point of this test is that this decoder never gets far enough
        // to even validate that CRC — it must reject on size alone.
        let claimed_total_len: u32 = (MAX_BUFFERED_BYTES as u32).saturating_add(1024);
        let mut fake_prelude = Vec::new();
        fake_prelude.extend_from_slice(&claimed_total_len.to_be_bytes());
        fake_prelude.extend_from_slice(&0u32.to_be_bytes());
        fake_prelude.extend_from_slice(&0u32.to_be_bytes()); // bogus prelude_crc

        // Pad the accumulator past MAX_BUFFERED_BYTES with filler bytes,
        // exactly the way a real attacker drip-feeding a connection would --
        // never allocating the full claimed size ourselves.
        let mut decoder = EventStreamDecoder::new();
        let first = decoder.feed(&fake_prelude);
        // The 12-byte prelude alone is well under the cap, so this call
        // alone must not yet error -- the point being tested is that
        // continuing to feed filler never succeeds in growing the buffer
        // past the cap.
        assert!(first.is_ok(), "a bare prelude alone must not itself error");

        let filler = vec![0u8; 1024 * 1024];
        let mut saw_error = false;
        for _ in 0..64 {
            match decoder.feed(&filler) {
                Ok(_) => {}
                Err(EventStreamDecodeError::MessageTooLarge) => {
                    saw_error = true;
                    break;
                }
                Err(other) => panic!("expected MessageTooLarge, got {other:?}"),
            }
        }
        assert!(
            saw_error,
            "feeding filler past MAX_BUFFERED_BYTES must fail closed with MessageTooLarge"
        );
    }

    #[test]
    fn feed_never_panics_on_a_stray_zero_length_chunk() {
        let mut decoder = EventStreamDecoder::new();
        assert!(decoder
            .feed(&[])
            .expect("empty chunk is not an error")
            .is_empty());
    }

    /// Fix-round-1 H1 regression test: a peer drip-feeding one byte per
    /// chunk (e.g. one TLS record per socket read) must not make `feed`
    /// degrade quadratically. Sized at 100,000 one-byte chunks forming a
    /// single still-incomplete message, so almost every call takes the
    /// `Incomplete` branch (the one that used to re-scan the whole
    /// accumulated queue on every call, several times per call). Under the
    /// O(1) `BytesMut`-backed accumulator this completes in well under a
    /// second; under the previous O(chunks) `VecDeque<Bytes>` + hand-rolled
    /// `Buf::remaining()` implementation, this single test took long enough
    /// that a `timeout 15 cargo test` run never printed a result at all (see
    /// the task report's fix-round-1 H1 section for the actual pasted
    /// before/after command output).
    #[test]
    fn feeding_one_byte_at_a_time_does_not_degrade_quadratically() {
        // A payload large enough that 100,000 one-byte feeds still leave the
        // message incomplete for the vast majority of calls.
        let big_payload = vec![b'x'; 150_000];
        let message = build_message(&[(":message-type", "event")], &big_payload);
        let bytes = encode(&message);
        assert!(
            bytes.len() >= 100_000,
            "fixture payload must be large enough to drive 100,000 one-byte feeds"
        );

        let start = std::time::Instant::now();
        let mut decoder = EventStreamDecoder::new();
        let mut decoded = Vec::new();
        for byte in bytes.iter().take(100_000) {
            decoded.extend(
                decoder
                    .feed(std::slice::from_ref(byte))
                    .expect("must decode"),
            );
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "100,000 one-byte feeds took {elapsed:?} -- expected well under 5s under O(1) \
             remaining()/advance(); this is the exact shape of fix-round-1 H1's quadratic \
             blowup if it regresses"
        );
        // The message is 150,000+ bytes but only the first 100,000 were fed,
        // so it must still be incomplete -- this test is about the cost of
        // getting here, not about completing the message.
        assert!(decoded.is_empty());
    }
}
