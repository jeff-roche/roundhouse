//! Fix round 1, fix 2 (security review Important 1 / Minor 7, ruling
//! W1-R33): a single NDJSON line — either direction — is capped at
//! `MAX_FRAME_BYTES` rather than accumulated without bound. The reviewer
//! measured 512 MiB of no-newline input driving RSS from 3,764 KiB to
//! 529,228 KiB against the pre-fix `BufReader::lines()` read side; these
//! tests use a much smaller (but still definitely-over-the-real-cap)
//! payload, since the point is proving the cap exists and closes only the
//! one offending connection, not re-measuring the amplification factor.

use std::sync::Arc;
use std::time::Duration;

use roundhouse_daemon::session_registry::SessionRegistry;
use roundhouse_proto::{ClientEvent, ClientRequest};
use roundhouse_tui::ConnectIntent;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

/// Comfortably past `socket_server::MAX_FRAME_BYTES` (1 MiB) without being
/// so large the test is slow to write.
const OVERSIZED_LEN: usize = 4 * 1024 * 1024;

/// Mirrors `socket_server::MAX_FRAME_BYTES` / `client::MAX_FRAME_BYTES`
/// (both private to their own crates, hence duplicated here as a plain
/// literal rather than exposed just for this test file to read).
const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Builds a `ClientRequest::CreateSession` whose serialized JSON line is
/// exactly `target_len` bytes (not counting the trailing `\n`), by padding
/// `workspace_name` with filler. Fix round 2, item 5: `frame_size_cap.rs`
/// exercised 4 KiB (comfortably under) and 4 MiB (comfortably over) but
/// never the boundary itself.
fn create_session_line_of_exact_length(target_len: usize) -> (String, String) {
    let base = serde_json::to_string(&ClientRequest::CreateSession {
        workspace_name: String::new(),
    })
    .unwrap();
    let padding = target_len
        .checked_sub(base.len())
        .expect("target_len must be at least the base frame's length");
    let workspace_name = "x".repeat(padding);
    let line = serde_json::to_string(&ClientRequest::CreateSession {
        workspace_name: workspace_name.clone(),
    })
    .unwrap();
    assert_eq!(
        line.len(),
        target_len,
        "sanity: constructed line must be exactly target_len"
    );
    (workspace_name, line)
}

/// Builds a `ClientEvent::TaskEvent`/`Note` whose serialized JSON line is
/// exactly `target_len` bytes (not counting the trailing `\n`), by padding
/// the note's `text`. The client-side mirror of
/// `create_session_line_of_exact_length`.
fn note_event_line_of_exact_length(
    session_id: roundhouse_core::SessionId,
    target_len: usize,
) -> String {
    let build = |text: String| ClientEvent::TaskEvent {
        session_id,
        task_id: None,
        payload: Box::new(roundhouse_core::EventPayload::Note {
            level: roundhouse_core::NoteLevel::Info,
            text,
        }),
    };
    let base = serde_json::to_string(&build(String::new())).unwrap();
    let padding = target_len
        .checked_sub(base.len())
        .expect("target_len must be at least the base frame's length");
    let line = serde_json::to_string(&build("y".repeat(padding))).unwrap();
    assert_eq!(
        line.len(),
        target_len,
        "sanity: constructed line must be exactly target_len"
    );
    line
}

#[tokio::test]
async fn an_overlong_request_line_closes_only_that_connection_not_the_accept_loop() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let registry = Arc::new(SessionRegistry::new());
    let listener = roundhouse_daemon::socket_server::bind_socket(&socket_path).unwrap();
    tokio::spawn(roundhouse_daemon::socket_server::accept_loop(
        listener,
        registry.clone(),
    ));

    // Send `OVERSIZED_LEN` bytes of non-newline filler directly over a raw
    // connection — a legitimate `roundhouse_tui` client can never construct
    // an oversized `ClientRequest`, so exercising the cap means writing raw
    // bytes rather than going through `connect_create`.
    let mut hostile =
        tokio::time::timeout(Duration::from_secs(2), UnixStream::connect(&socket_path))
            .await
            .expect("connect must not hang")
            .unwrap();
    let filler = vec![b'a'; OVERSIZED_LEN];
    // Best-effort: the daemon may close its read side once it detects the
    // overflow, before this write finishes — a write error here is exactly
    // as expected as the write completing, so ignore either outcome.
    let _ = tokio::time::timeout(Duration::from_secs(5), hostile.write_all(&filler)).await;

    // The daemon must close *this* connection (never write anything back,
    // and eventually drop the socket) rather than crash or hang.
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(5), hostile.read(&mut buf)).await;
    assert!(
        matches!(read, Ok(Ok(0)) | Ok(Err(_))),
        "the daemon must close the oversized connection rather than hang, got {read:?}"
    );

    // The accept loop itself must have survived: a brand new, well-behaved
    // client must still be able to connect and complete a handshake.
    let session_id = tokio::time::timeout(
        Duration::from_secs(2),
        roundhouse_tui::connect_create(&socket_path, "still-alive"),
    )
    .await
    .expect("a fresh client must not hang after a hostile peer was dropped")
    .expect("a fresh client must still be able to create a session")
    .session_id();
    // Sanity: it's a real, freshly minted session id, not a leftover.
    assert_ne!(session_id, roundhouse_core::SessionId::new());
}

#[tokio::test]
async fn a_generously_long_but_legitimate_workspace_name_still_round_trips() {
    // `placeholder_session_spec` echoes `workspace_name` straight back in
    // the handshake reply (ruling W1-R6) — the cap must not be so tight it
    // breaks a real, if unusually long, workspace name.
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let registry = Arc::new(SessionRegistry::new());
    let listener = roundhouse_daemon::socket_server::bind_socket(&socket_path).unwrap();
    tokio::spawn(roundhouse_daemon::socket_server::accept_loop(
        listener,
        registry.clone(),
    ));

    let long_name = "w".repeat(4096);
    let client = tokio::time::timeout(
        Duration::from_secs(2),
        roundhouse_tui::connect_create(&socket_path, &long_name),
    )
    .await
    .expect("must not hang")
    .expect("a 4 KiB workspace name must round-trip under the 1 MiB cap");
    let _ = client.session_id();

    // Also exercise the raw wire form directly, matching what
    // `serde_json` would actually put on the socket for `ClientRequest`.
    let line = serde_json::to_string(&ClientRequest::CreateSession {
        workspace_name: long_name,
    })
    .unwrap();
    assert!(
        line.len() < 1024 * 1024,
        "sanity: the test's own long-but-legitimate line must actually be \
         under the cap it's proving survives, got {} bytes",
        line.len()
    );
}

/// The client-side mirror (security review Minor 7): `DaemonClient::recv`
/// had the identical unbounded `read_line` shape. Exercised here, in
/// `roundhouse-daemon`'s own test crate (which already depends on
/// `roundhouse-tui` throughout this file), against a bare `UnixListener`
/// playing a hostile daemon — `roundhouse-daemon`'s own real server can
/// never be coerced into emitting an over-length `ClientEvent` today, since
/// nothing it sends is attacker-influenced past a workspace name already
/// covered by the server-side test above.
#[tokio::test]
async fn an_overlong_reply_line_from_the_daemon_does_not_hang_or_grow_without_bound() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        // Read (and discard) the client's handshake request line so the
        // write below isn't itself blocked on a full socket buffer.
        let mut discard = [0u8; 4096];
        let _ = stream.read(&mut discard).await;
        let filler = vec![b'a'; OVERSIZED_LEN];
        let _ = tokio::time::timeout(Duration::from_secs(5), stream.write_all(&filler)).await;
        // Keep the connection open indefinitely rather than letting `stream`
        // drop here: a real attacker never sends EOF. Dropping it here would
        // let an *unbounded* pre-fix `read_line` still return successfully
        // (it reads until either a newline or EOF, and EOF would arrive the
        // moment this task ends) — which would prove nothing about the
        // unbounded-growth hazard this test exists to catch. The `#[tokio::
        // test]` runtime aborts this task when the test function returns, so
        // nothing leaks past the test itself.
        std::future::pending::<()>().await;
    });

    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        roundhouse_tui::connect(
            &socket_path,
            ConnectIntent::CreateSession {
                workspace_name: "test".into(),
            },
        ),
    )
    .await
    .expect("connect must not hang")
    .unwrap();

    let received = tokio::time::timeout(Duration::from_secs(5), client.recv()).await;
    match received {
        Ok(Ok(_)) => panic!("an over-length line with no newline must not parse as a frame"),
        Ok(Err(_)) => {} // expected: DaemonClient::recv reports the cap violation
        Err(_) => panic!("DaemonClient::recv must not hang on an over-length reply"),
    }

    // `server` never completes on its own (see the comment above); aborting
    // it explicitly makes that deliberate rather than relying on the test
    // runtime tearing it down implicitly.
    server.abort();
}

/// Fix round 2, item 5 (boundary coverage): a request line whose content is
/// exactly `MAX_FRAME_BYTES` bytes (excluding the trailing `\n`) must be
/// accepted — `LinesCodec::new_with_max_length` searches for a newline
/// within the first `max_length + 1` bytes, so a newline landing exactly at
/// that boundary is still found.
#[tokio::test]
async fn a_request_line_exactly_at_the_cap_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let registry = Arc::new(SessionRegistry::new());
    let listener = roundhouse_daemon::socket_server::bind_socket(&socket_path).unwrap();
    tokio::spawn(roundhouse_daemon::socket_server::accept_loop(
        listener,
        registry.clone(),
    ));

    // Deliberately a raw connection, not `connect_create`: the daemon's
    // `SessionCreated` reply echoes `workspace_name` back inside a larger
    // envelope (session_id, task_id, the rest of `SessionSpec`), so a
    // *reply* built from an exactly-at-cap `workspace_name` is itself over
    // `MAX_FRAME_BYTES` — a real, separate constraint on the client's own
    // read side, not a sign the server rejected the *request*. Reading the
    // raw bytes back (rather than through `DaemonClient::recv`, which
    // enforces its own cap) isolates what this test is actually about: did
    // the server's read side accept the line and proceed far enough to
    // attempt a reply at all.
    let (workspace_name, line) = create_session_line_of_exact_length(MAX_FRAME_BYTES);
    let mut client =
        tokio::time::timeout(Duration::from_secs(2), UnixStream::connect(&socket_path))
            .await
            .expect("connect must not hang")
            .unwrap();
    client.write_all(line.as_bytes()).await.unwrap();
    client.write_all(b"\n").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let read = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf)).await;
    assert!(
        matches!(read, Ok(Ok(n)) if n > 0),
        "an exactly-at-cap request line must be accepted and answered \
         (some reply bytes must arrive), got {read:?}"
    );
    let _ = workspace_name;
}

/// The mirror of the test above: one byte past the cap must be rejected —
/// closing that one connection, not the accept loop.
#[tokio::test]
async fn a_request_line_one_byte_over_the_cap_closes_the_connection() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let registry = Arc::new(SessionRegistry::new());
    let listener = roundhouse_daemon::socket_server::bind_socket(&socket_path).unwrap();
    tokio::spawn(roundhouse_daemon::socket_server::accept_loop(
        listener,
        registry.clone(),
    ));

    let (_workspace_name, line) = create_session_line_of_exact_length(MAX_FRAME_BYTES + 1);
    let mut hostile =
        tokio::time::timeout(Duration::from_secs(2), UnixStream::connect(&socket_path))
            .await
            .expect("connect must not hang")
            .unwrap();
    hostile.write_all(line.as_bytes()).await.unwrap();
    hostile.write_all(b"\n").await.unwrap();

    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(5), hostile.read(&mut buf)).await;
    assert!(
        matches!(read, Ok(Ok(0))),
        "a request line one byte over MAX_FRAME_BYTES must close the connection, got {read:?}"
    );

    // The accept loop itself must have survived.
    let fresh = tokio::time::timeout(
        Duration::from_secs(2),
        roundhouse_tui::connect_create(&socket_path, "still-alive"),
    )
    .await;
    assert!(
        matches!(fresh, Ok(Ok(_))),
        "the accept loop must survive a one-byte-over-cap connection"
    );
}

/// The client-side mirror: a reply line whose content is exactly
/// `MAX_FRAME_BYTES` bytes must still parse.
#[tokio::test]
async fn a_reply_line_exactly_at_the_cap_is_accepted_by_the_client() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let session_id = roundhouse_core::SessionId::new();
    let line = note_event_line_of_exact_length(session_id, MAX_FRAME_BYTES);

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut discard = [0u8; 4096];
        let _ = stream.read(&mut discard).await;
        stream.write_all(line.as_bytes()).await.unwrap();
        stream.write_all(b"\n").await.unwrap();
        // Keep the connection open long enough for the client below to
        // finish reading before this task (and its stream) is dropped.
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        roundhouse_tui::connect(
            &socket_path,
            ConnectIntent::CreateSession {
                workspace_name: "t".into(),
            },
        ),
    )
    .await
    .expect("connect must not hang")
    .unwrap();

    let received = tokio::time::timeout(Duration::from_secs(5), client.recv())
        .await
        .expect("must not hang")
        .expect("a reply line exactly at MAX_FRAME_BYTES must parse");
    assert!(received.is_some());

    server.abort();
}

/// The client-side mirror of the one-byte-over test: `DaemonClient::recv`
/// must report an error (not hang, not silently accept) for a reply line
/// one byte past the cap.
#[tokio::test]
async fn a_reply_line_one_byte_over_the_cap_is_rejected_by_the_client() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let session_id = roundhouse_core::SessionId::new();
    let line = note_event_line_of_exact_length(session_id, MAX_FRAME_BYTES + 1);

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut discard = [0u8; 4096];
        let _ = stream.read(&mut discard).await;
        stream.write_all(line.as_bytes()).await.unwrap();
        stream.write_all(b"\n").await.unwrap();
        // Keep the connection open — see the analogous over-length test
        // above for why closing it here would prove nothing.
        std::future::pending::<()>().await;
    });

    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        roundhouse_tui::connect(
            &socket_path,
            ConnectIntent::CreateSession {
                workspace_name: "t".into(),
            },
        ),
    )
    .await
    .expect("connect must not hang")
    .unwrap();

    let received = tokio::time::timeout(Duration::from_secs(5), client.recv()).await;
    match received {
        Ok(Ok(_)) => panic!("a reply line one byte over MAX_FRAME_BYTES must not parse as a frame"),
        Ok(Err(_)) => {} // expected
        Err(_) => panic!("DaemonClient::recv must not hang on a one-byte-over reply"),
    }

    server.abort();
}
