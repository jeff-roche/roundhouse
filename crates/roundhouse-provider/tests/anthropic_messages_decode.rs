use futures::StreamExt;
use roundhouse_provider::codec::anthropic_messages::{
    decode_anthropic_messages_events, decode_anthropic_messages_stream, StreamFailureKind,
    MAX_THINKING_SIGNATURE_BYTES,
};
use roundhouse_provider::{
    BlockDelta, BlockKind, CassetteTransport, HttpRequest, HttpTransport, StreamEvent,
    TransportError,
};

#[tokio::test]
async fn decodes_thinking_signature_and_normalizes_cache_read_usage() {
    let sse_bytes = include_bytes!("fixtures/anthropic_thinking.sse").to_vec();
    let transport = CassetteTransport {
        status: 200,
        headers: vec![],
        body: sse_bytes,
        chunk_size: 11,
    };

    let resp = transport
        .send(HttpRequest {
            method: "POST".into(),
            url: "https://api.anthropic.com/v1/messages".into(),
            headers: vec![],
            body: vec![],
        })
        .await
        .unwrap();

    let events = decode_anthropic_messages_stream(resp.body)
        .await
        .expect("a well-formed stream ending in message_stop must decode as Ok");

    assert!(matches!(
        events[0],
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::Thinking
        }
    ));

    let signature = events.iter().find_map(|e| match e {
        StreamEvent::BlockDelta {
            index: 0,
            delta:
                BlockDelta::Thinking {
                    signature: Some(sig),
                    ..
                },
        } => Some(sig.clone()),
        _ => None,
    });
    assert_eq!(signature.as_deref(), Some("sig-xyz"));

    // input_tokens normalized to include cache_read_input_tokens (10 + 5 = 15), per §9.3.
    let first_usage = events
        .iter()
        .find_map(|e| match e {
            StreamEvent::UsageDelta {
                input_tokens: Some(t),
                cache_read_tokens: Some(c),
                ..
            } => Some((*t, *c)),
            _ => None,
        })
        .unwrap();
    assert_eq!(first_usage, (15, 5));
    assert!(
        first_usage.0 >= first_usage.1,
        "invariant: input_tokens >= cache_read_tokens"
    );

    assert!(matches!(events.last(), Some(StreamEvent::MessageStop)));
}

/// Task 11 (Ruling R17): `anthropic_messages` joins the strict group
/// (`openai_chat`, `cohere_v2`) -- a stream that ends (a clean EOF) without
/// ever observing a `message_stop` event must be an `Err`, matching every
/// other strict-group codec's fixed behavior, not a silent `Ok` that a
/// caller cannot distinguish from a real completion on a physically-
/// immutable event log.
#[tokio::test]
async fn a_connection_closed_mid_stream_with_no_message_stop_is_an_error_not_a_clean_completion() {
    let body = futures::stream::iter(vec![Ok(bytes::Bytes::from(
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n",
    ))]);
    let result = decode_anthropic_messages_stream(body).await;
    assert!(
        result.is_err(),
        "a stream that never saw message_stop must be an error, matching every other strict-\
         group codec's fixed behavior"
    );
}

/// Ruling R17, item 1: `decode.rs`'s `let Ok(frame) = frame else { continue
/// };` used to silently swallow a mid-stream transport/SSE-framing error,
/// making a reset connection indistinguishable from a benign skipped
/// keep-alive frame. It must now surface as `StreamFailureKind::Transport`,
/// carrying whatever text was already decoded before the failure
/// (`partial_text`) -- mirrors `cohere_v2`/`openai_chat`'s identical fix.
#[tokio::test]
async fn a_mid_stream_transport_error_is_surfaced_not_silently_dropped() {
    let body = futures::stream::iter(vec![
        Ok(bytes::Bytes::from(
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n",
        )),
        Ok(bytes::Bytes::from(
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"cut off here\"}}\n\n",
        )),
        Err(TransportError::Io("connection reset by peer".into())),
    ]);
    let failure = match decode_anthropic_messages_stream(body).await {
        Ok(events) => panic!(
            "a mid-stream transport error must not decode as Ok ({} events decoded)",
            events.len()
        ),
        Err(failure) => failure,
    };
    assert_eq!(failure.kind, StreamFailureKind::Transport);
    assert_eq!(failure.partial_text, "cut off here");
}

/// Task 2: `decode_anthropic_messages_events` must be a genuinely incremental
/// decoder -- it has to yield an already-decoded frame's event the moment
/// that frame is available, without waiting for the body to end. Uses a
/// `futures::channel::mpsc` body under direct manual control (no sleeps): the
/// first poll before anything is sent must be pending (nothing to yield
/// yet), the first frame decodes to `Some(Some(Ok(BlockStart)))` the instant
/// it's sent even though the sender is still open (proving this isn't just a
/// buffered decode masquerading as a stream), and a second poll right after
/// is pending again (proving it doesn't fabricate completion either).
#[test]
fn block_start_arrives_while_the_body_is_still_open() {
    use futures::channel::mpsc;
    use futures::FutureExt;

    let (tx, rx) = mpsc::unbounded::<Result<bytes::Bytes, TransportError>>();
    let events = decode_anthropic_messages_events(rx);
    futures::pin_mut!(events);

    // Nothing sent yet: the body is open and empty, so polling now must be
    // pending, not `None` (end of stream) and not `Some` (a fabricated
    // event).
    assert!(
        events.next().now_or_never().is_none(),
        "polling an events stream with nothing sent yet must be pending"
    );

    tx.unbounded_send(Ok(bytes::Bytes::from(
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n",
    )))
    .unwrap();

    let first = events
        .next()
        .now_or_never()
        .expect("a full frame was already sent -- decoding it must not need another network read")
        .expect("the stream must not end while the sender is still open")
        .expect("a well-formed content_block_start frame must decode without error");
    assert!(matches!(
        first,
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::Text
        }
    ));

    // The sender is still open and nothing further was sent: a second poll
    // must be pending again, not `None` -- this decoder must not treat "no
    // more frames right now" as "the stream ended".
    assert!(
        events.next().now_or_never().is_none(),
        "a second poll while the sender is still open and idle must be pending, not end-of-stream"
    );

    drop(tx);
}

/// Builds one `content_block_delta`/`signature_delta` SSE frame whose
/// signature is `len` ASCII bytes.
fn signature_frame(len: usize) -> bytes::Bytes {
    let signature = "s".repeat(len);
    bytes::Bytes::from(format!(
        "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\
         \"delta\":{{\"type\":\"signature_delta\",\"signature\":\"{signature}\"}}}}\n\n"
    ))
}

/// Controller ruling R22: a `signature_delta` is taken verbatim off the wire,
/// is deliberately never redacted (`Redactor::redact_event_payload` passes
/// `Delta::Thinking.signature` straight through so it round-trips), and is
/// emitted by `DeltaCoalescer::close_pending` without consulting the size
/// limit at all — so an unbounded one would write an unbounded, unredacted
/// row into a table that physically rejects `UPDATE`/`DELETE`. A signature
/// past [`MAX_THINKING_SIGNATURE_BYTES`] is a wire-protocol violation that
/// must FAIL THE STREAM CLOSED, not be dropped or truncated (a thinking
/// block that loses its signature is `01-data-model.md` §1.1 bug #1, the
/// bricked resume, reintroduced).
#[tokio::test]
async fn a_signature_delta_over_the_ceiling_fails_the_stream_instead_of_being_persisted() {
    let body = futures::stream::iter(vec![
        Ok::<_, TransportError>(signature_frame(MAX_THINKING_SIGNATURE_BYTES + 1)),
        // A `message_stop` the decoder must never reach: the violation is
        // terminal, so this stream cannot come back as a clean completion.
        Ok(bytes::Bytes::from(
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        )),
    ]);
    let stream = decode_anthropic_messages_events(body);
    futures::pin_mut!(stream);

    let mut items = Vec::new();
    while let Some(item) = stream.next().await {
        items.push(item);
    }

    assert_eq!(
        items.len(),
        1,
        "the violation is the stream's one and only item -- nothing decoded before it, and \
         nothing (not even the trailing message_stop) after it: {items:?}"
    );
    match &items[0] {
        Err(failure) => {
            assert_eq!(failure.kind, StreamFailureKind::Transport);
            assert!(
                !failure
                    .message
                    .contains('s'.to_string().repeat(64).as_str()),
                "the failure message must report the length, never echo the signature itself: {}",
                failure.message
            );
        }
        Ok(event) => panic!("an oversized signature must not decode to an event: {event:?}"),
    }
}

/// The other half of ruling R22: the ceiling is generous enough that a real
/// signature is untouched. A signature of exactly
/// [`MAX_THINKING_SIGNATURE_BYTES`] is still under the cap and must round-trip
/// verbatim, byte for byte.
#[tokio::test]
async fn a_signature_delta_at_exactly_the_ceiling_still_round_trips_verbatim() {
    let body = futures::stream::iter(vec![
        Ok::<_, TransportError>(signature_frame(MAX_THINKING_SIGNATURE_BYTES)),
        Ok(bytes::Bytes::from(
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        )),
    ]);
    let events = decode_anthropic_messages_stream(body)
        .await
        .expect("a signature at exactly the ceiling is not a violation");

    let signature = events
        .iter()
        .find_map(|e| match e {
            StreamEvent::BlockDelta {
                delta:
                    BlockDelta::Thinking {
                        signature: Some(sig),
                        ..
                    },
                ..
            } => Some(sig.clone()),
            _ => None,
        })
        .expect("the signature must still be decoded");
    assert_eq!(signature, "s".repeat(MAX_THINKING_SIGNATURE_BYTES));
}

/// Splits `bytes` into contiguous chunks at `points` (deduped, sorted,
/// clamped into range), mirroring how a real network body arrives in
/// arbitrarily-sized pieces. An empty `points` list yields the whole body as
/// one chunk.
fn split_at(bytes: &[u8], points: &[usize]) -> Vec<bytes::Bytes> {
    let mut points: Vec<usize> = points.iter().copied().map(|p| p.min(bytes.len())).collect();
    points.sort_unstable();
    points.dedup();

    let mut chunks = Vec::new();
    let mut start = 0;
    for point in points {
        chunks.push(bytes::Bytes::copy_from_slice(&bytes[start..point]));
        start = point;
    }
    chunks.push(bytes::Bytes::copy_from_slice(&bytes[start..]));
    chunks
}

/// Drives `decode_anthropic_messages_events` over `chunks` to completion,
/// collapsing each `StreamFailure` down to its `kind` (whose `message` field
/// isn't required to be split-point-invariant, only `kind` and the events
/// that already decoded are).
async fn decode_chunks(chunks: Vec<bytes::Bytes>) -> Vec<Result<StreamEvent, StreamFailureKind>> {
    let body = futures::stream::iter(chunks.into_iter().map(Ok::<_, TransportError>));
    let stream = decode_anthropic_messages_events(body);
    futures::pin_mut!(stream);
    let mut out = Vec::new();
    while let Some(item) = stream.next().await {
        out.push(item.map_err(|failure| failure.kind));
    }
    out
}

/// The three fixtures this equivalence check runs over: both of the existing
/// well-formed fixtures, plus a new one (`anthropic_multibyte.sse`) whose
/// `text_delta` contains literal multi-byte UTF-8 (an accented Latin letter,
/// two CJK characters, and an astral-plane emoji encoded as a UTF-8
/// surrogate-pair-free 4-byte sequence) -- so that splitting at *every* byte
/// offset necessarily includes splits that land inside a multi-byte
/// sequence, not just at frame/line boundaries.
fn fixtures() -> [&'static [u8]; 3] {
    [
        include_bytes!("fixtures/anthropic_hello.sse").as_slice(),
        include_bytes!("fixtures/anthropic_thinking.sse").as_slice(),
        include_bytes!("fixtures/anthropic_multibyte.sse").as_slice(),
    ]
}

/// Task 2 (b): for every fixture and every single split point (including
/// mid-multibyte-sequence splits in `anthropic_multibyte.sse`), decoding the
/// body split into exactly two chunks at that point must produce the exact
/// same event sequence as decoding it as one whole chunk. `sse_stream`
/// reassembles line/frame boundaries incrementally regardless of where the
/// underlying transport happened to split the bytes, and this decoder must
/// not add any chunk-alignment sensitivity on top of that.
#[tokio::test]
async fn every_single_split_point_matches_the_whole_body_decode() {
    for fixture in fixtures() {
        let whole = decode_chunks(split_at(fixture, &[])).await;
        for split in 0..=fixture.len() {
            let split_result = decode_chunks(split_at(fixture, &[split])).await;
            assert_eq!(
                split_result,
                whole,
                "splitting at byte {split} of {} produced a different event sequence than the \
                 whole-body decode",
                fixture.len()
            );
        }
    }
}

/// Task 2 (b): 200 seeded (deterministic, no wall-clock/no external entropy)
/// random multi-chunk splits per fixture must also match the whole-body
/// decode -- single split points prove pairwise chunk boundaries don't
/// matter, this proves arbitrarily many simultaneous chunk boundaries don't
/// either.
#[tokio::test]
async fn two_hundred_seeded_random_multi_splits_match_the_whole_body_decode() {
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    for fixture in fixtures() {
        let whole = decode_chunks(split_at(fixture, &[])).await;
        let mut rng = StdRng::seed_from_u64(0xA17_C0DE_u64);
        for trial in 0..200 {
            let num_splits = rng.random_range(0..8usize);
            let points: Vec<usize> = (0..num_splits)
                .map(|_| rng.random_range(0..=fixture.len()))
                .collect();
            let split_result = decode_chunks(split_at(fixture, &points)).await;
            assert_eq!(
                split_result,
                whole,
                "seeded random multi-split trial {trial} (points {points:?}) of a \
                 {}-byte fixture produced a different event sequence than the whole-body decode",
                fixture.len()
            );
        }
    }
}
