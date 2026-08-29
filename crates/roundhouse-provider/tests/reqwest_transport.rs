//! Proves `ReqwestTransport` performs a real network round-trip — but against
//! a hand-rolled local TCP responder, not the real Anthropic API, so this test
//! stays hermetic: no `ANTHROPIC_API_KEY`, no outbound connection, no money.

use futures::StreamExt;
use roundhouse_provider::{HttpRequest, HttpTransport, ReqwestTransport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn sends_a_real_request_and_returns_the_response_body() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = socket.read(&mut buf).await.unwrap(); // drain the request; not parsed
        let body = b"{\"ok\":true}";
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        socket.write_all(response.as_bytes()).await.unwrap();
        socket.write_all(body).await.unwrap();
        socket.shutdown().await.unwrap();
    });

    let transport = ReqwestTransport::new();
    let response = transport
        .send(HttpRequest {
            method: "POST".into(),
            url: format!("http://{addr}/v1/messages"),
            headers: vec![("content-type".into(), "application/json".into())],
            body: b"{}".to_vec(),
        })
        .await
        .unwrap();

    assert_eq!(response.status, 200);

    let mut collected = Vec::new();
    let mut body_stream = response.body;
    while let Some(chunk) = body_stream.next().await {
        collected.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(collected, b"{\"ok\":true}");

    server.await.unwrap();
}

/// A connection failure must surface as a `TransportError`, never as a panic.
/// This is the first place in the workspace where a *real* socket can refuse,
/// reset, or vanish, so the "no panics at the network boundary" rule gets an
/// explicit test rather than being assumed from the `?`-free implementation.
///
/// Binding and immediately dropping a listener yields a port nothing is
/// listening on, which is far more reliably "connection refused" than picking
/// a hardcoded port and hoping it is free.
#[tokio::test]
async fn a_refused_connection_is_an_error_not_a_panic() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let transport = ReqwestTransport::new();
    let result = transport
        .send(HttpRequest {
            method: "POST".into(),
            url: format!("http://{addr}/v1/messages"),
            headers: vec![],
            body: b"{}".to_vec(),
        })
        .await;

    assert!(result.is_err(), "a refused connection must be a TransportError");
}

/// A method string the HTTP spec rejects must be an error, not a panic.
/// `HttpRequest.method` is a bare `String`, so nothing upstream of this
/// transport constrains it to a valid token.
#[tokio::test]
async fn an_invalid_http_method_is_an_error_not_a_panic() {
    let transport = ReqwestTransport::new();
    let result = transport
        .send(HttpRequest {
            method: "not a valid method".into(),
            url: "http://127.0.0.1:1/v1/messages".into(),
            headers: vec![],
            body: vec![],
        })
        .await;

    assert!(result.is_err(), "an invalid method must be a TransportError");
}
