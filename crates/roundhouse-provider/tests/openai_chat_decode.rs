use roundhouse_provider::codec::openai_chat::decode_openai_chat_stream;
use roundhouse_provider::{
    BlockDelta, BlockKind, CassetteTransport, HttpRequest, HttpTransport, StreamEvent,
};

#[tokio::test]
async fn decodes_streaming_tool_call_into_block_events() {
    let sse_bytes = include_bytes!("fixtures/openai_chat_tool_call.sse").to_vec();
    let transport = CassetteTransport {
        status: 200,
        headers: vec![],
        body: sse_bytes,
        chunk_size: 7,
    };

    let resp = transport
        .send(HttpRequest {
            method: "POST".into(),
            url: "https://api.openai.com/v1/chat/completions".into(),
            headers: vec![],
            body: vec![],
        })
        .await
        .unwrap();

    let events = decode_openai_chat_stream(resp.body).await;

    assert!(matches!(
        events[0],
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::ToolUse { .. }
        }
    ));
    let arg_fragments: String = events
        .iter()
        .filter_map(|e| match e {
            StreamEvent::BlockDelta {
                index: 0,
                delta: BlockDelta::ToolArgsFragment(f),
            } => Some(f.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(arg_fragments, r#"{"path":"a.rs"}"#);
    assert!(matches!(events.last(), Some(StreamEvent::MessageStop)));
    assert!(events.iter().any(|e| matches!(
        e,
        StreamEvent::UsageDelta {
            input_tokens: Some(50),
            output_tokens: Some(12),
            ..
        }
    )));

    // Audit finding 4: BlockStop must arrive in the same order BlockStart opened the
    // blocks — index 0 (call_1) started first, index 1 (call_2) started second.
    let start_order: Vec<u32> = events
        .iter()
        .filter_map(|e| match e {
            StreamEvent::BlockStart { index, .. } => Some(*index),
            _ => None,
        })
        .collect();
    let stop_order: Vec<u32> = events
        .iter()
        .filter_map(|e| match e {
            StreamEvent::BlockStop { index } => Some(*index),
            _ => None,
        })
        .collect();
    assert_eq!(start_order, vec![0, 1]);
    assert_eq!(
        stop_order, start_order,
        "BlockStop must preserve BlockStart's first-seen order"
    );
}
