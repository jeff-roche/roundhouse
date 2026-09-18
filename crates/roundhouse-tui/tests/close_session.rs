//! Phase 8, T19a Task 8: `DaemonClient::close_session` — sends
//! `ClientRequest::CloseSession` for this client's own session and waits for
//! the daemon's `Ack`, skipping any other frame that arrives first. Mirrors
//! `attach.rs`'s own "fake server over a real Unix socket" shape rather than
//! standing up a full daemon, since this crate's own unit is `DaemonClient`
//! itself, not `roundhouse-daemon`'s handling of the request (covered by
//! that crate's own `tests/close_session.rs`).

use std::time::Duration;

use roundhouse_core::{Delta, EventPayload, SessionId};
use roundhouse_proto::{ApiVersion, ClientEvent, ClientRequest};
use roundhouse_tui::{connect_create, TuiError};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

/// `close_session` must send the request naming this client's own session,
/// then keep reading until it sees the `Ack` — skipping an unrelated frame
/// the fake server deliberately sends first.
#[tokio::test]
async fn close_session_sends_the_request_and_skips_other_frames_until_the_ack() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let minted_session_id = SessionId::new();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        // Handshake: reply with SessionCreated so connect_create resolves.
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let _: ClientRequest = serde_json::from_str(line.trim_end()).unwrap();
        let created = ClientEvent::TaskEvent {
            session_id: minted_session_id,
            task_id: None,
            payload: Box::new(EventPayload::SessionCreated {
                spec: Box::new(roundhouse_core::SessionSpec::test_requesting(
                    roundhouse_core::Tier::Sandbox,
                    roundhouse_core::OnDegrade::Refuse,
                )),
            }),
        };
        let reply = serde_json::to_string(&created).unwrap();
        write_half.write_all(reply.as_bytes()).await.unwrap();
        write_half.write_all(b"\n").await.unwrap();

        // The CloseSession request, naming the session the handshake minted.
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        let request: ClientRequest = serde_json::from_str(line.trim_end()).unwrap();
        assert!(matches!(
            request,
            ClientRequest::CloseSession { session_id } if session_id == minted_session_id
        ));

        // An unrelated frame first — close_session must not mistake it for
        // its own reply.
        let unrelated = ClientEvent::TaskEvent {
            session_id: minted_session_id,
            task_id: None,
            payload: Box::new(EventPayload::TaskDelta {
                delta: Delta::Text {
                    text: "unrelated".into(),
                },
            }),
        };
        let line = serde_json::to_string(&unrelated).unwrap();
        write_half.write_all(line.as_bytes()).await.unwrap();
        write_half.write_all(b"\n").await.unwrap();

        let ack = ClientEvent::Ack {
            api_version: ApiVersion::CURRENT,
        };
        let line = serde_json::to_string(&ack).unwrap();
        write_half.write_all(line.as_bytes()).await.unwrap();
        write_half.write_all(b"\n").await.unwrap();
    });

    let mut client = connect_create(&socket_path, "test-workspace")
        .await
        .unwrap();
    assert_eq!(client.session_id(), minted_session_id);

    client.close_session().await.unwrap();

    // The fake server sent exactly two lines after the handshake: the
    // unrelated frame, then the `Ack`. If `close_session` returned as soon
    // as it saw the unrelated frame instead of skipping it, the real `Ack`
    // would still be sitting unread on the wire, and this next read would
    // see it rather than the clean EOF the server's `write_half` dropping
    // (its task has already returned by the time `close_session` resolved,
    // per `server.await` below) actually produces.
    server.await.unwrap();
    let leftover = client.recv().await.unwrap();
    assert!(
        leftover.is_none(),
        "close_session must consume every frame through the Ack, not return early and leave \
         the Ack itself unread; got {leftover:?}"
    );
}

/// A daemon-side refusal is silent on the wire by design (see
/// `DaemonClient::close_session`'s own `# No wire NAK exists` doc section):
/// no frame at all, connection kept open. `close_session` must not then hang
/// this caller forever — it must time out and report `ErrorKind::TimedOut`.
///
/// `#[tokio::test(start_paused = true)]` + `tokio::time::advance`: real time
/// never needs to elapse for what is nominally a 40s wait. A `oneshot`
/// signals once the fake server has actually read the `CloseSession`
/// request, so the clock is only advanced once `close_session`'s own
/// internal wait has genuinely started — not a fixed guess about how much
/// virtual scheduling the handshake and request round trip need first.
#[tokio::test(start_paused = true)]
async fn close_session_times_out_if_the_daemon_never_acknowledges_it() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let minted_session_id = SessionId::new();
    let (request_seen_tx, request_seen_rx) = tokio::sync::oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let _: ClientRequest = serde_json::from_str(line.trim_end()).unwrap();
        let created = ClientEvent::TaskEvent {
            session_id: minted_session_id,
            task_id: None,
            payload: Box::new(EventPayload::SessionCreated {
                spec: Box::new(roundhouse_core::SessionSpec::test_requesting(
                    roundhouse_core::Tier::Sandbox,
                    roundhouse_core::OnDegrade::Refuse,
                )),
            }),
        };
        let reply = serde_json::to_string(&created).unwrap();
        write_half.write_all(reply.as_bytes()).await.unwrap();
        write_half.write_all(b"\n").await.unwrap();

        line.clear();
        reader.read_line(&mut line).await.unwrap();
        let request: ClientRequest = serde_json::from_str(line.trim_end()).unwrap();
        assert!(matches!(
            request,
            ClientRequest::CloseSession { session_id } if session_id == minted_session_id
        ));

        // Never replies, and never drops `write_half` either — a real
        // refusal keeps the connection open, it does not close it. Signal
        // that the request was read, then park forever.
        let _ = request_seen_tx.send(());
        std::future::pending::<()>().await;
    });

    let mut client = connect_create(&socket_path, "test-workspace")
        .await
        .unwrap();
    assert_eq!(client.session_id(), minted_session_id);

    let closing = tokio::spawn(async move { client.close_session().await });

    request_seen_rx
        .await
        .expect("the fake server must read the CloseSession request before being dropped");

    // Deterministic: jumps straight past close_session's own Ack-wait
    // timeout without any real time elapsing.
    tokio::time::advance(Duration::from_secs(3600)).await;

    let result = closing
        .await
        .expect("close_session's own task must not panic");
    match result.expect_err("no Ack ever arrives, so close_session must time out") {
        TuiError::Io(io_err) => {
            assert_eq!(
                io_err.kind(),
                std::io::ErrorKind::TimedOut,
                "expected a TimedOut error, got {io_err:?}"
            );
        }
        other => panic!("expected TuiError::Io(TimedOut), got {other:?}"),
    }

    // The fake server is parked forever by design; this test only needs the
    // client's own observable behavior, so it is aborted rather than
    // awaited.
    server.abort();
}
