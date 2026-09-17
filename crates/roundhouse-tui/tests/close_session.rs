//! Phase 8, T19a Task 8: `DaemonClient::close_session` — sends
//! `ClientRequest::CloseSession` for this client's own session and waits for
//! the daemon's `Ack`, skipping any other frame that arrives first. Mirrors
//! `attach.rs`'s own "fake server over a real Unix socket" shape rather than
//! standing up a full daemon, since this crate's own unit is `DaemonClient`
//! itself, not `roundhouse-daemon`'s handling of the request (covered by
//! that crate's own `tests/close_session.rs`).

use roundhouse_core::{Delta, EventPayload, SessionId};
use roundhouse_proto::{ApiVersion, ClientEvent, ClientRequest};
use roundhouse_tui::connect_create;
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
