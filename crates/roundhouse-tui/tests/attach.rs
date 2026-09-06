//! Phase 7 Task 2: `connect` now performs a real handshake (sends a
//! `ClientRequest` derived from a `ConnectIntent`) and `recv` decodes real
//! `roundhouse-proto` `ClientEvent` frames, instead of the retired
//! `ServerMessage`.

use roundhouse_core::{Delta, EventPayload, SessionId};
use roundhouse_proto::{ClientEvent, ClientRequest};
use roundhouse_tui::{connect, ConnectIntent};
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

        let event = ClientEvent::TaskEvent {
            session_id: SessionId::new(),
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
        Some(ClientEvent::TaskEvent { payload, .. }) => {
            assert!(matches!(
                *payload,
                EventPayload::TaskDelta {
                    delta: Delta::Text { ref text }
                } if text == "Hello"
            ));
        }
        other => panic!("expected a TaskEvent carrying a raw EventPayload, got {other:?}"),
    }
}
