use roundhouse_provider::codec::anthropic_messages::{
    decode_anthropic_messages_stream, StreamFailureKind,
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
