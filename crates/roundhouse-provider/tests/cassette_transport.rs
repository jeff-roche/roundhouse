use futures::StreamExt;
use roundhouse_provider::{CassetteTransport, HttpRequest, HttpTransport};

#[tokio::test]
async fn replays_body_in_fixed_size_chunks() {
    let transport = CassetteTransport {
        status: 200,
        headers: vec![],
        body: b"0123456789".to_vec(),
        chunk_size: 3,
    };

    let resp = transport
        .send(HttpRequest {
            method: "POST".into(),
            url: "https://example.invalid/v1/chat".into(),
            headers: vec![],
            body: vec![],
        })
        .await
        .unwrap();

    assert_eq!(resp.status, 200);

    let chunks: Vec<Vec<u8>> = resp
        .body
        .map(|c| c.unwrap().to_vec())
        .collect()
        .await;

    assert_eq!(
        chunks,
        vec![b"012".to_vec(), b"345".to_vec(), b"678".to_vec(), b"9".to_vec()]
    );
}
