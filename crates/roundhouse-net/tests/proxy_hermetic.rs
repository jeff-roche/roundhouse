//! Hermetic end-to-end tests for `LoopbackProxy`: an ALLOW case that never
//! depends on real internet access (a plain TCP echo listener on loopback
//! stands in for the "upstream"), a DENY case that asserts a real recorded
//! `Note` event lands (not just a closed socket), the metadata-IP hard-deny
//! even under an allow-everything policy, and the fail-closed
//! unknown-bearer-token case — plus fix-round-1 regression tests for the
//! security review's two Critical findings (IP-level metadata-IP bypass via
//! alternate encodings; no IP-level enforcement / DNS-rebinding-shaped
//! TOCTOU) and its four Important findings (unbounded CONNECT-preamble
//! read; no handshake/idle timeouts or connection cap; accept-loop death on
//! transient errors; unsanitized attacker-controlled text landing in a
//! durable event).

use std::sync::Arc;
use std::time::Duration;

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

/// A hermetic upstream that accepts and then goes silent — stands in for
/// the "upstream accepted, then never sends anything" idle-tunnel case.
async fn spawn_silent_upstream() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((sock, _)) = listener.accept().await {
            // Hold the connection open, send/receive nothing, until the
            // proxy's idle timeout (or the test) closes it.
            let mut sock = sock;
            let mut buf = [0u8; 1];
            let _ = sock.read(&mut buf).await;
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
    // Explicit exact allowlist entry — deliberate operator intent to reach
    // this specific loopback address, which the private-range check
    // (only applied to wildcard matches) does not second-guess.
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

// ---------------------------------------------------------------------
// Fix-round-1 regression tests (security review, both Criticals + 4
// Importants), all reproduced against pre-fix behavior per the review.
// ---------------------------------------------------------------------

/// Critical 1: the pre-fix code compared the raw CONNECT-target string
/// against the literal string `"169.254.169.254"` — every one of these
/// nine alternate textual encodings resolves (via the real resolver,
/// confirmed empirically: `tokio::net::lookup_host` on this host resolves
/// all nine to `169.254.169.254`/`::ffff:169.254.169.254`) to the exact
/// same address, but compared unequal to the literal string and sailed
/// through unblocked. Under an allow-all wildcard policy (so a failure
/// here cannot be masked by an unrelated allowlist deny), every one of
/// these must now be denied.
#[tokio::test]
async fn nine_alternate_encodings_of_the_metadata_ip_are_all_denied() {
    let (_dir, _db_path, writer) = fresh_writer().await;
    let proxy = Arc::new(LoopbackProxy::new());
    let policy = EgressPolicy {
        allowed_hosts: vec![HostPattern::wildcard_suffix("")],
    };
    let token = proxy.register_session(SessionId::new(), policy);
    let proxy_addr = proxy.clone().serve(&RUNNER, writer).await.unwrap();

    let encodings = [
        "169.254.169.254.:80",         // trailing dot — DNS root-anchored form
        "2852039166:80",               // decimal-dword encoding
        "0251.0376.0251.0376:80",      // octal
        "0xa9.0xfe.0xa9.0xfe:80",      // hex, dotted
        "0xa9fea9fe:80",               // hex, single dword
        "0XA9FEA9FE:80",               // hex, upper case
        "169.254.43518:80",            // truncated 3-part form
        "[::ffff:169.254.169.254]:80", // IPv4-mapped IPv6, dotted-quad form
        "[::ffff:a9fe:a9fe]:80",       // IPv4-mapped IPv6, hex-group form
    ];
    for target in encodings {
        let (status, _sock) = send_connect(proxy_addr, &token, target).await;
        assert_eq!(status, 403, "encoding `{target}` of the metadata IP must be denied, not just its canonical spelling");
    }
}

/// Critical 2: the pre-fix code had no IP-level check at all — the
/// allowlist matched a hostname string and `TcpStream::connect` separately
/// (and independently) resolved that same string, meaning a *wildcard*
/// allowlist entry gave no real guarantee about what address a connection
/// would actually reach. Scope decision for this round (see report):
/// exact allowlist entries (explicit, specific operator intent, exercised
/// by `allowed_host_gets_200_and_a_real_tunnel` above) are trusted as-is;
/// a *wildcard*-matched hostname resolving into a private/loopback/
/// link-local range is now denied, closing exactly the gap the security
/// review's own reproduction demonstrated ("a wildcard-allowlisted
/// subdomain resolving to 169.254.169.254 is allowed with no further
/// check" / "a working tunnel to 127.0.0.1 under the crate's own allow-all
/// test policy").
#[tokio::test]
async fn wildcard_allowlisted_host_resolving_to_a_loopback_address_is_denied() {
    let (_dir, _db_path, writer) = fresh_writer().await;
    let upstream_addr = spawn_echo_upstream().await;
    let target = format!("127.0.0.1:{}", upstream_addr.port());

    let proxy = Arc::new(LoopbackProxy::new());
    // An allow-everything *wildcard* policy — exactly the shape the
    // security review's own reproduction used to demonstrate an
    // unrestricted pivot into the daemon host's internal network.
    let policy = EgressPolicy {
        allowed_hosts: vec![HostPattern::wildcard_suffix("")],
    };
    let token = proxy.register_session(SessionId::new(), policy);
    let proxy_addr = proxy.clone().serve(&RUNNER, writer).await.unwrap();

    let (status, _sock) = send_connect(proxy_addr, &token, &target).await;
    assert_eq!(
        status, 403,
        "a wildcard-matched host resolving to a loopback address must be denied, even under an allow-all policy"
    );
}

/// Important finding 2: `read_connect_request` used to accumulate an
/// unterminated line into an unbounded `String`. Sending well past the
/// preamble budget with no line terminator must now get the connection
/// dropped promptly (not hang, not accept unbounded data) — this doesn't
/// push gigabytes (impractical in a unit test) but does push comfortably
/// past `MAX_PREAMBLE_BYTES` (64 KiB) to prove the cap is real, then
/// confirms the socket is closed rather than still open and readable.
#[tokio::test]
async fn oversized_unterminated_preamble_gets_the_connection_dropped() {
    let (_dir, _db_path, writer) = fresh_writer().await;
    let proxy = Arc::new(LoopbackProxy::new());
    let proxy_addr = proxy.clone().serve(&RUNNER, writer).await.unwrap();

    let mut sock = TcpStream::connect(proxy_addr).await.unwrap();
    // No newline anywhere in this payload — the pre-fix code would have
    // kept appending to its `String` forever. 256 KiB is comfortably past
    // the 64 KiB preamble cap.
    let payload = vec![b'A'; 256 * 1024];
    // A write of this size may not complete in one syscall if the proxy
    // stops reading once its budget is exhausted — that's fine, we only
    // care that the connection ends up closed, not that every byte lands.
    let _ = tokio::time::timeout(Duration::from_secs(5), sock.write_all(&payload)).await;

    let mut buf = [0u8; 16];
    let result = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf)).await;
    match result {
        Ok(Ok(0)) => {} // connection closed — expected
        Ok(Err(_)) => {} // reset — also an acceptable "dropped" outcome
        other => panic!("expected the connection to be closed after an oversized unterminated preamble, got {other:?}"),
    }
}

/// Important finding 3a: a client that opens a connection and never sends
/// a complete CONNECT request ("slowloris") used to park a task in
/// `read_line` forever. With a short handshake timeout, the connection
/// must be closed once that timeout elapses.
#[tokio::test]
async fn slow_client_that_never_completes_the_handshake_is_dropped_after_the_timeout() {
    let (_dir, _db_path, writer) = fresh_writer().await;
    let proxy = Arc::new(LoopbackProxy::with_limits(
        Duration::from_millis(150),
        Duration::from_secs(60),
        256,
    ));
    let proxy_addr = proxy.clone().serve(&RUNNER, writer).await.unwrap();

    let mut sock = TcpStream::connect(proxy_addr).await.unwrap();
    // Send nothing at all — never completes a request line.
    let mut buf = [0u8; 16];
    let result = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf)).await;
    match result {
        Ok(Ok(0)) => {}
        Ok(Err(_)) => {}
        other => panic!("expected the handshake-timed-out connection to be closed, got {other:?}"),
    }
}

/// Important finding 3b: an established tunnel to an upstream that accepts
/// and then goes completely silent used to be held open forever. With a
/// short idle timeout, the tunnel must be torn down once that timeout
/// elapses with no bytes flowing either direction.
#[tokio::test]
async fn idle_tunnel_with_no_bytes_flowing_is_closed_after_the_idle_timeout() {
    let (_dir, _db_path, writer) = fresh_writer().await;
    let upstream_addr = spawn_silent_upstream().await;
    let target = format!("127.0.0.1:{}", upstream_addr.port());

    let proxy = Arc::new(LoopbackProxy::with_limits(
        Duration::from_secs(10),
        Duration::from_millis(150),
        256,
    ));
    let policy = EgressPolicy {
        allowed_hosts: vec![HostPattern::exact("127.0.0.1")],
    };
    let token = proxy.register_session(SessionId::new(), policy);
    let proxy_addr = proxy.clone().serve(&RUNNER, writer).await.unwrap();

    let (status, mut sock) = send_connect(proxy_addr, &token, &target).await;
    assert_eq!(status, 200);

    // Send nothing on either side — the tunnel must be torn down by the
    // idle timeout, not held open forever.
    let mut buf = [0u8; 16];
    let result = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf)).await;
    match result {
        Ok(Ok(0)) => {}
        Ok(Err(_)) => {}
        other => {
            panic!("expected the idle tunnel to be closed after the idle timeout, got {other:?}")
        }
    }
}

/// Important finding 5 (end-to-end): a denied CONNECT target containing
/// ANSI/control characters must land in the recorded `Note` event with
/// those characters stripped — the event log is immutable, append-only,
/// and rendered by the operator's TUI as a trusted audit trail.
#[tokio::test]
async fn control_characters_in_a_denied_target_are_sanitized_in_the_recorded_event() {
    let (_dir, db_path, writer) = fresh_writer().await;
    let proxy = Arc::new(LoopbackProxy::new());
    let session_id = SessionId::new();
    let policy = EgressPolicy {
        allowed_hosts: vec![HostPattern::exact("crates.io")],
    };
    let token = proxy.register_session(session_id, policy);
    let proxy_addr = proxy.clone().serve(&RUNNER, writer).await.unwrap();

    // A CONNECT target embedding an ANSI escape byte and a BEL, with no
    // other visible characters between them and the surrounding text —
    // stripping just those two control bytes should leave
    // "evilhost.example:443" contiguous, which the assertion below checks
    // for. Sent as the raw request-line token, not through the ordinary
    // `send_connect` helper, so it reaches the proxy exactly as an
    // attacker would send it.
    let evil_target = "evil\u{1b}\u{7}host.example:443";
    let mut sock = TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!(
        "CONNECT {evil_target} HTTP/1.1\r\nHost: {evil_target}\r\nProxy-Authorization: Bearer {token}\r\n\r\n"
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
    assert_eq!(status, 403);

    tokio::time::sleep(Duration::from_millis(50)).await;
    let store2 = roundhouse_store::open(&db_path).await.unwrap();
    let events = roundhouse_store::session_events(&store2, session_id)
        .await
        .unwrap();
    let note_text = events
        .iter()
        .find_map(|e| match &e.payload {
            EventPayload::Note { text, .. } if text.contains("evilhost.example") => {
                Some(text.clone())
            }
            _ => None,
        })
        .expect("a Note event for the denied target must be recorded");
    assert!(
        !note_text.chars().any(|c| c.is_control()),
        "the recorded event text must never contain raw control characters, got: {note_text:?}"
    );
}
