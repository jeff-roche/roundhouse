//! Proves `ReqwestTransport` performs a real network round-trip — but against
//! a hand-rolled local TCP responder, not the real Anthropic API, so this test
//! stays hermetic: no `ANTHROPIC_API_KEY`, no outbound connection, no money.
//!
//! The round-trip tests use `allowing_plaintext_http()` because a local
//! responder cannot speak TLS without a generated certificate chain;
//! `new()`'s extra restriction (HTTPS only) gets its own test below rather
//! than going unproven.

use futures::StreamExt;
use roundhouse_provider::{
    HttpRequest, HttpResponseStream, HttpTransport, ReqwestTransport, TransportError,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// `Result::expect_err` needs `T: Debug`, and `HttpResponseStream` deliberately
/// isn't (it wraps a boxed stream) — so error-path tests unwrap through this.
fn expect_err(result: Result<HttpResponseStream, TransportError>) -> TransportError {
    match result {
        Ok(_) => panic!("expected a TransportError, got a response"),
        Err(err) => err,
    }
}

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

    let transport = ReqwestTransport::allowing_plaintext_http();
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

    let transport = ReqwestTransport::allowing_plaintext_http();
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

/// The transport must not follow redirects, because `reqwest`'s
/// `remove_sensitive_headers` strips only `Authorization`/`Cookie`/`Cookie2`/
/// `Proxy-Authorization`/`WWW-Authenticate` on a cross-origin hop — `x-api-key`,
/// the header this crate authenticates Anthropic with, is a custom header on
/// none of those lists, so a followed `302` would hand the live credential to
/// whatever origin the redirect names.
///
/// Two things are asserted, because either alone would be weak: the 302 is
/// returned to the caller verbatim (so `AnthropicMessagesProvider` can classify
/// it) *and* the redirect target never receives a connection at all (so the
/// credential provably did not go anywhere).
#[tokio::test]
async fn does_not_follow_redirects_so_the_api_key_cannot_be_forwarded() {
    let attacker = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let attacker_addr = attacker.local_addr().unwrap();

    let redirector = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redirector_addr = redirector.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut socket, _) = redirector.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = socket.read(&mut buf).await.unwrap();
        let response = format!(
            "HTTP/1.1 302 Found\r\nlocation: http://{attacker_addr}/steal\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
        );
        socket.write_all(response.as_bytes()).await.unwrap();
        socket.shutdown().await.unwrap();
    });

    let transport = ReqwestTransport::allowing_plaintext_http();
    let response = transport
        .send(HttpRequest {
            method: "POST".into(),
            url: format!("http://{redirector_addr}/v1/messages"),
            headers: vec![("x-api-key".into(), "sk-ant-secret".into())],
            body: b"{}".to_vec(),
        })
        .await
        .unwrap();

    assert_eq!(
        response.status, 302,
        "the redirect must be handed back to the caller, not followed"
    );

    server.await.unwrap();

    // Nothing ever connected to the redirect target. `accept()` would complete
    // if it had; the timeout is what proves the absence.
    let accepted = tokio::time::timeout(std::time::Duration::from_millis(250), attacker.accept())
        .await;
    assert!(
        accepted.is_err(),
        "the redirect target received a connection — the API key was forwarded"
    );
}

/// `new()` — the constructor production uses — must refuse plaintext outright,
/// so a misconfigured `base_url` (a `pub` field, and where §9.9's future
/// `ROUNDHOUSE_<PROVIDER>_BASE_URL` override will land) cannot put the
/// credential on the wire in the clear. The failure has to happen before any
/// connection is made, so this points at a listener that would otherwise answer.
#[tokio::test]
async fn the_production_constructor_refuses_plaintext_http() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let transport = ReqwestTransport::new();
    let result = transport
        .send(HttpRequest {
            method: "POST".into(),
            url: format!("http://{addr}/v1/messages"),
            headers: vec![("x-api-key".into(), "sk-ant-secret".into())],
            body: b"{}".to_vec(),
        })
        .await;

    assert!(result.is_err(), "http:// must be refused by ReqwestTransport::new()");

    let accepted =
        tokio::time::timeout(std::time::Duration::from_millis(250), listener.accept()).await;
    assert!(
        accepted.is_err(),
        "a connection was opened despite https_only — the refusal happened too late"
    );
}

/// Pins the third-party assumption the adapter's secret handling rests on:
/// `reqwest::Error`'s `Display` reports the URL and a cause, never the request
/// headers — so wrapping it in `TransportError::Io(e.to_string())` cannot leak
/// `x-api-key`. That is a fact about someone else's crate, so it gets a test
/// that will fail if a future `reqwest` upgrade changes it, rather than a
/// comment asserting it.
///
/// Both reachable failure shapes are covered: a connection that fails after the
/// request was built, and a header value so malformed the request never builds
/// at all (`reqwest` defers `InvalidHeaderValue` to `send()`) — the latter being
/// the case where the offending value is most likely to be echoed back.
#[tokio::test]
async fn transport_errors_never_echo_the_request_headers() {
    const KEY: &str = "sk-ant-super-secret-value";

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let transport = ReqwestTransport::allowing_plaintext_http();

    let refused = expect_err(
        transport
            .send(HttpRequest {
                method: "POST".into(),
                url: format!("http://{addr}/v1/messages"),
                headers: vec![("x-api-key".into(), KEY.into())],
                body: b"{}".to_vec(),
            })
            .await,
    );
    let rendered = format!("{refused} / {refused:?}");
    assert!(
        !rendered.contains(KEY),
        "the API key leaked through a connection error: {rendered}"
    );

    // A newline makes this an invalid header value; `reqwest` rejects it at
    // `send()`.
    let malformed = format!("{KEY}\ninjected: header");
    let invalid = expect_err(
        transport
            .send(HttpRequest {
                method: "POST".into(),
                url: format!("http://{addr}/v1/messages"),
                headers: vec![("x-api-key".into(), malformed)],
                body: b"{}".to_vec(),
            })
            .await,
    );
    let rendered = format!("{invalid} / {invalid:?}");
    assert!(
        !rendered.contains(KEY),
        "the API key leaked through an invalid-header error: {rendered}"
    );
}

/// A method string the HTTP spec rejects must be an error, not a panic.
/// `HttpRequest.method` is a bare `String`, so nothing upstream of this
/// transport constrains it to a valid token.
#[tokio::test]
async fn an_invalid_http_method_is_an_error_not_a_panic() {
    let transport = ReqwestTransport::allowing_plaintext_http();
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
