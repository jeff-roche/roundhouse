//! Hermetic end-to-end tests for `LoopbackProxy`: an ALLOW case that never
//! depends on real internet access (a plain TCP echo listener on loopback
//! stands in for the "upstream"), a DENY case that asserts a real recorded
//! `Note` event lands (not just a closed socket), the metadata-IP hard-deny
//! even under an allow-everything policy, and the fail-closed
//! unknown-bearer-token case.

use std::sync::Arc;

use once_cell::sync::Lazy;
use roundhouse_core::{EventPayload, SessionId, TaskRunner};
use roundhouse_net::policy::{EgressPolicy, HostPattern, METADATA_IP};
use roundhouse_net::proxy::LoopbackProxy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// `TaskRunner::bootstrap()` panics on a second call in the same process
/// (S-LOG-1) — this test binary's `#[tokio::test]` functions share one
/// process, so they must share one `TaskRunner` instance. Matches the real
/// precedent in `crates/roundhouse-secrets/tests/keyring_fallback.rs`.
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

/// A hermetic stand-in "upstream" — a plain TCP echo listener on loopback,
/// so the ALLOW case never depends on real internet access. Its bound port
/// is what the test allowlists, not a real hostname.
async fn spawn_echo_upstream() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 5];
            if sock.read_exact(&mut buf).await.is_ok() {
                let _ = sock.write_all(&buf).await;
            }
        }
    });
    addr
}

async fn send_connect(
    proxy_addr: std::net::SocketAddr,
    token: &str,
    target: &str,
) -> (u16, TcpStream) {
    let mut sock = TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Bearer {token}\r\n\r\n"
    );
    sock.write_all(req.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 512];
    let n = sock.read(&mut buf).await.unwrap();
    let status_line = String::from_utf8_lossy(&buf[..n]);
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (status, sock)
}

#[tokio::test]
async fn allowed_host_gets_200_and_a_real_tunnel() {
    let (_dir, _db_path, writer) = fresh_writer().await;
    let upstream_addr = spawn_echo_upstream().await;
    let target = format!("127.0.0.1:{}", upstream_addr.port());

    let proxy = Arc::new(LoopbackProxy::new());
    let policy = EgressPolicy {
        allowed_hosts: vec![HostPattern::exact("127.0.0.1")],
    };
    let token = proxy.register_session(SessionId::new(), policy);
    let proxy_addr = proxy.clone().serve(&RUNNER, writer).await.unwrap();

    let (status, mut sock) = send_connect(proxy_addr, &token, &target).await;
    assert_eq!(
        status, 200,
        "an allowlisted target must get a real 200 Connection Established tunnel"
    );

    sock.write_all(b"hello").await.unwrap();
    let mut echoed = [0u8; 5];
    sock.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"hello", "the tunnel must actually splice bytes through to the upstream, not just approve the handshake");
}

#[tokio::test]
async fn non_allowlisted_host_gets_403_and_a_recorded_deny() {
    let (_dir, db_path, writer) = fresh_writer().await;
    let proxy = Arc::new(LoopbackProxy::new());
    let session_id = SessionId::new();
    let policy = EgressPolicy {
        allowed_hosts: vec![HostPattern::exact("crates.io")],
    };
    let token = proxy.register_session(session_id, policy);
    let proxy_addr = proxy.clone().serve(&RUNNER, writer).await.unwrap();

    let (status, _sock) = send_connect(proxy_addr, &token, "evil.example:443").await;
    assert_eq!(status, 403);

    // §6.6: "A blocked request produces a real Deny task record with the
    // URL, not a network error the model must guess at." (Ruling 4: this
    // proxy has no `TaskId` in scope, so the deny is recorded as a `Note`,
    // not a `TaskFailed` — Task 24 wires task-scoped failure recording in.)
    tokio::time::sleep(std::time::Duration::from_millis(50)).await; // let the append land
    let store2 = roundhouse_store::open(&db_path).await.unwrap();
    let events = roundhouse_store::session_events(&store2, session_id)
        .await
        .unwrap();
    assert!(
        events.iter().any(|e| matches!(
            &e.payload,
            EventPayload::Note { text, .. } if text.contains("evil.example")
        )),
        "the denied host must appear in a real recorded event, not just a closed socket"
    );
}

#[tokio::test]
async fn metadata_ip_is_denied_even_with_an_allow_all_policy() {
    let (_dir, _db_path, writer) = fresh_writer().await;
    let proxy = Arc::new(LoopbackProxy::new());
    // A wildcard allow-everything policy — the metadata IP must still be
    // denied, because it is checked first and unconditionally, matched-first
    // just like the sealed floor.
    let policy = EgressPolicy {
        allowed_hosts: vec![HostPattern::wildcard_suffix("")],
    };
    let token = proxy.register_session(SessionId::new(), policy);
    let proxy_addr = proxy.clone().serve(&RUNNER, writer).await.unwrap();

    let (status, _sock) = send_connect(proxy_addr, &token, &format!("{METADATA_IP}:80")).await;
    assert_eq!(
        status, 403,
        "169.254.169.254 is denied always, regardless of allowlist (§6.6)"
    );
}

#[tokio::test]
async fn unknown_bearer_token_is_rejected_before_any_allowlist_check() {
    let (_dir, _db_path, writer) = fresh_writer().await;
    let proxy = Arc::new(LoopbackProxy::new());
    let proxy_addr = proxy.clone().serve(&RUNNER, writer).await.unwrap();

    let (status, _sock) = send_connect(proxy_addr, "not-a-real-token", "crates.io:443").await;
    assert_eq!(
        status, 407,
        "a request with no matching session token must never reach allowlist evaluation at all"
    );
}

#[tokio::test]
async fn evil_crates_io_is_not_matched_by_exact_crates_io_allowlist_entry() {
    let (_dir, _db_path, writer) = fresh_writer().await;
    let proxy = Arc::new(LoopbackProxy::new());
    let policy = EgressPolicy {
        allowed_hosts: vec![HostPattern::exact("crates.io")],
    };
    let token = proxy.register_session(SessionId::new(), policy);
    let proxy_addr = proxy.clone().serve(&RUNNER, writer).await.unwrap();

    let (status, _sock) = send_connect(proxy_addr, &token, "evil-crates.io:443").await;
    assert_eq!(
        status, 403,
        "an exact allowlist entry for crates.io must never substring-match evil-crates.io"
    );
}

#[tokio::test]
async fn evilexample_com_is_not_matched_by_wildcard_example_com_allowlist_entry() {
    let (_dir, _db_path, writer) = fresh_writer().await;
    let proxy = Arc::new(LoopbackProxy::new());
    let policy = EgressPolicy {
        allowed_hosts: vec![HostPattern::wildcard_suffix("example.com")],
    };
    let token = proxy.register_session(SessionId::new(), policy);
    let proxy_addr = proxy.clone().serve(&RUNNER, writer).await.unwrap();

    let (status, _sock) = send_connect(proxy_addr, &token, "evilexample.com:443").await;
    assert_eq!(
        status, 403,
        "a *.example.com wildcard must require a literal dot boundary, not just a raw suffix match"
    );
}
