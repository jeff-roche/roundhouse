use roundhouse_provider::codec::anthropic_messages::decode_anthropic_messages_stream;
use roundhouse_provider::{
    BlockDelta, BlockKind, CassetteTransport, HttpRequest, HttpTransport, StreamEvent,
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

    let events = decode_anthropic_messages_stream(resp.body).await;

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
