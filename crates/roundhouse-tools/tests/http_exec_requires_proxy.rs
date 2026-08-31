//! `HttpTaskExecutor` can only ever be constructed from a real `ProxyHandle` — this
//! is a live, hermetic assertion on the real request path (Task 23's `LoopbackProxy`,
//! actually serving), not a mock: a non-allowlisted host must fail through the
//! proxy's 403 with a real recorded deny `Note`, never bypass it; an allowlisted
//! host's request must actually reach the tunnel.

use once_cell::sync::Lazy;
use roundhouse_core::{EventPayload, SessionId, TaskRunner};
use roundhouse_net::policy::{EgressPolicy, HostPattern};
use roundhouse_net::proxy::LoopbackProxy;
use roundhouse_tools::http::HttpTaskExecutor;
use std::sync::Arc;

/// `TaskRunner::bootstrap()` panics on a second call in the same process (S-LOG-1) —
/// this test binary's `#[tokio::test]` functions share one process, so they must
/// share one `TaskRunner` instance. Matches the precedent in
/// `crates/roundhouse-net/tests/proxy_hermetic.rs`.
static RUNNER: Lazy<TaskRunner> = Lazy::new(TaskRunner::bootstrap);

async fn fresh_writer() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    roundhouse_store::EventWriter,
) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = roundhouse_store::open(&db_path).await.unwrap();
    let writer = roundhouse_store::spawn_writer(store).await;
    (dir, db_path, writer)
}

#[tokio::test]
async fn http_task_execution_only_ever_reaches_an_allowlisted_host_through_the_proxy() {
    let (_dir, db_path, writer) = fresh_writer().await;

    let proxy = Arc::new(LoopbackProxy::new());
    let policy = EgressPolicy {
        allowed_hosts: vec![HostPattern::exact("example.invalid")],
    };
    let session_id = SessionId::new();
    // register_session (fix-round-2) reads the proxy's own bound address, set by
    // serve() below, rather than trusting a caller-supplied one — so serve() must
    // run first, and register_session can now fail if it hasn't.
    proxy.clone().serve(&RUNNER, writer).await.unwrap();
    let handle = proxy.register_session(session_id, policy).unwrap();

    // Constructing the executor is only possible with a ProxyHandle — there is no
    // other public constructor, so an http task literally cannot bypass the proxy
    // (mirrors ControlLaneToken's type-level guarantee, Task 18).
    let executor = HttpTaskExecutor::via_proxy(&handle);
    let result = executor.execute("https://not-allowlisted.example/x").await;
    // A non-allowlisted host must fail closed through the proxy's 403, not silently
    // route around it — this is a live, hermetic assertion on the real request path.
    // Fix-round-1 strengthening: `result.is_err()` alone can't distinguish "denied by
    // the allowlist" from "never reached any proxy at all" (it would also pass with a
    // dead proxy address or broken auth wiring). Assert on the real recorded deny
    // `Note` event too, mirroring
    // `proxy_hermetic.rs::non_allowlisted_host_gets_403_and_a_recorded_deny`.
    assert!(
        result.is_err(),
        "a request to a non-allowlisted host must fail, never bypass the proxy"
    );

    tokio::time::sleep(std::time::Duration::from_millis(50)).await; // let the append land
    let store2 = roundhouse_store::open(&db_path).await.unwrap();
    let events = roundhouse_store::session_events(&store2, session_id)
        .await
        .unwrap();
    assert!(
        events.iter().any(|e| matches!(
            &e.payload,
            EventPayload::Note { text, .. } if text.contains("not-allowlisted.example")
        )),
        "the denied host must appear in a real recorded event, proving the request \
         actually reached LoopbackProxy's deny path rather than failing for some other \
         reason (dead address, broken auth wiring, etc.)"
    );
}

#[tokio::test]
async fn http_task_execution_actually_tunnels_an_allowlisted_request_through_the_proxy() {
    let (_dir, _db_path, writer) = fresh_writer().await;

    // A hermetic stand-in "upstream": a plain TCP listener on loopback that never
    // speaks TLS. `HttpTaskExecutor` always uses `https://` (the proxy is CONNECT-only,
    // §6.6), so a request to this upstream through a real tunnel fails at the TLS
    // handshake — but that failure has a distinct shape from a proxy-level deny, which
    // is exactly what this test uses to prove the tunnel was actually established
    // rather than the request being rejected before ever reaching the upstream.
    //
    // Fix-round-2 finding (N3): asserting only on the *shape* of the resulting error
    // (e.g. "doesn't mention TunnelUnsuccessful") is too weak — a dead proxy address
    // produces a `ConnectionRefused` error that also doesn't mention that string, so
    // that assertion alone can't tell "reached the upstream through a real tunnel"
    // apart from "never reached any proxy at all". Have the upstream signal on a
    // channel the moment it actually accepts a connection, and assert on that
    // positive signal directly — the real proof the tunnel was established — in
    // addition to the error-shape check.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let _ = accepted_tx.send(());
            use tokio::io::AsyncWriteExt;
            // A real TCP accept happened, but no TLS ServerHello is ever sent —
            // reqwest's TLS handshake fails to parse whatever bytes (if any) show up.
            let _ = sock.write_all(b"not a tls server hello").await;
        }
    });

    let proxy = Arc::new(LoopbackProxy::new());
    let policy = EgressPolicy {
        allowed_hosts: vec![HostPattern::exact("127.0.0.1")],
    };
    proxy.clone().serve(&RUNNER, writer).await.unwrap();
    let handle = proxy.register_session(SessionId::new(), policy).unwrap();

    let executor = HttpTaskExecutor::via_proxy(&handle);
    let url = format!("https://127.0.0.1:{}/", upstream_addr.port());
    let err = executor
        .execute(&url)
        .await
        .expect_err("the hermetic upstream never speaks TLS, so this must fail");

    // The positive signal: the hermetic upstream itself confirms a real TCP
    // connection reached it — this cannot be produced by a denied request (which
    // never leaves the proxy) or a dead/misconfigured proxy address (which never
    // reaches the upstream at all).
    tokio::time::timeout(std::time::Duration::from_secs(2), accepted_rx)
        .await
        .expect("timed out waiting for the hermetic upstream to accept a connection")
        .expect("the accept-signal sender was dropped without sending");

    // A denied request fails with `TunnelUnsuccessful` (the CONNECT itself was
    // rejected by the proxy with a non-200 status) — verified directly against this
    // proxy in the sibling deny-path test above. A failure at the TLS layer, after a
    // real 200 Connection Established tunnel, looks different: reqwest/hyper report it
    // as a connect-phase error whose *source* is a TLS parse failure, not a tunnel
    // rejection. This is a secondary corroborating check now that the positive signal
    // above is the real proof.
    let debug = format!("{err:?}");
    assert!(
        !debug.contains("TunnelUnsuccessful"),
        "an allowlisted host's CONNECT must succeed (a real tunnel), not be rejected \
         by the proxy like a denied one — got: {debug}"
    );
}
