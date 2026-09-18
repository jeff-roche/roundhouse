//! Phase 7 Task 2: `connect` now performs a real handshake (sends a
//! `ClientRequest` derived from a `ConnectIntent`) and `recv` decodes real
//! `roundhouse-proto` `ClientEvent` frames, instead of the retired
//! `ServerMessage`.

use roundhouse_core::{Delta, EventPayload, SessionId};
use roundhouse_proto::{ApiVersion, ClientEvent, ClientRequest};
use roundhouse_tui::{connect, connect_resume, ConnectIntent, TuiError};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

#[tokio::test]
async fn attaches_sends_a_client_request_and_decodes_one_ndjson_client_event() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        // `connect` must have sent its handshake `ClientRequest` as the
        // connection's first line.
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let request: ClientRequest = serde_json::from_str(line.trim_end()).unwrap();
        assert!(
            matches!(request, ClientRequest::CreateSession { workspace_name } if workspace_name == "test-workspace")
        );

        let event = ClientEvent::Committed {
            session_id: SessionId::new(),
            seq: 3,
            task_id: None,
            payload: Box::new(EventPayload::TaskDelta {
                delta: Delta::Text {
                    text: "Hello".into(),
                },
            }),
        };
        let line = serde_json::to_string(&event).unwrap();
        write_half.write_all(line.as_bytes()).await.unwrap();
        write_half.write_all(b"\n").await.unwrap();
    });

    let mut client = connect(
        &socket_path,
        ConnectIntent::CreateSession {
            workspace_name: "test-workspace".into(),
        },
    )
    .await
    .unwrap();
    let message = client.recv().await.unwrap();

    server.await.unwrap();

    match message {
        Some(ClientEvent::Committed { seq, payload, .. }) => {
            assert_eq!(seq, 3);
            assert!(matches!(
                *payload,
                EventPayload::TaskDelta {
                    delta: Delta::Text { ref text }
                } if text == "Hello"
            ));
        }
        other => panic!("expected a Committed event carrying a raw EventPayload, got {other:?}"),
    }
    assert_eq!(
        client.last_seq(),
        Some(3),
        "recv must track the seq of every Committed frame it returns"
    );
}

/// Phase 8 Task 21: `connect_resume` sends `Resume` with the caller's cursor,
/// waits for the `Ack`, and reports that cursor as `last_seq` until a newer
/// `Committed` frame arrives.
#[tokio::test]
async fn connect_resume_sends_the_cursor_and_tracks_last_seq_from_it() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let session_id = SessionId::new();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let request: ClientRequest = serde_json::from_str(line.trim_end()).unwrap();
        assert!(matches!(
            request,
            ClientRequest::Resume { session_id: named, after_seq: 4 } if named == session_id
        ));
        for event in [
            ClientEvent::Ack {
                api_version: ApiVersion::CURRENT,
            },
            ClientEvent::Committed {
                session_id,
                seq: 5,
                task_id: None,
                payload: Box::new(EventPayload::TaskDelta {
                    delta: Delta::Text {
                        text: "next".into(),
                    },
                }),
            },
        ] {
            let line = serde_json::to_string(&event).unwrap();
            write_half.write_all(line.as_bytes()).await.unwrap();
            write_half.write_all(b"\n").await.unwrap();
        }
    });

    let mut client = connect_resume(&socket_path, session_id, 4).await.unwrap();
    assert_eq!(client.session_id(), session_id);
    assert_eq!(client.last_seq(), Some(4));
    assert!(matches!(
        client.recv().await.unwrap(),
        Some(ClientEvent::Committed { seq: 5, .. })
    ));
    assert_eq!(client.last_seq(), Some(5));
    server.await.unwrap();
}

/// A `ResyncRequired` answer to `Resume` is an error the caller can recognise:
/// its cursor is past the session's head.
#[tokio::test]
async fn connect_resume_reports_resync_required_as_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let session_id = SessionId::new();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let line = serde_json::to_string(&ClientEvent::ResyncRequired {
            session_id,
            head: Some(2),
        })
        .unwrap();
        write_half.write_all(line.as_bytes()).await.unwrap();
        write_half.write_all(b"\n").await.unwrap();
    });

    match connect_resume(&socket_path, session_id, 9).await {
        Err(TuiError::Io(err)) => assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput),
        Err(other) => panic!("expected an InvalidInput io error, got {other:?}"),
        Ok(_) => panic!("a ResyncRequired answer must not yield a client"),
    }
    server.await.unwrap();
}
