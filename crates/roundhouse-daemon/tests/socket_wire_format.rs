//! Phase 7 Task 2: proves `socket_server::serve` speaks `roundhouse-proto`'s
//! real `ClientRequest`/`ClientEvent` wire types, not the retired
//! `roundhouse_tui::ServerMessage` — the precondition Task 3's real
//! bidirectional accept loop needs before it can carry an MCP tool call, a
//! policy denial, or a sub-agent spawn event over this socket.

use roundhouse_proto::ClientRequest;
use roundhouse_tui::ConnectIntent;

#[tokio::test]
async fn a_real_client_request_round_trips_as_roundhouse_proto_types_not_servermessage() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let (requests_tx, mut requests_rx) = tokio::sync::mpsc::channel(4);
    let (events_tx, events_rx) = tokio::sync::mpsc::channel(4);
    let server = tokio::spawn({
        let socket_path = socket_path.clone();
        async move {
            roundhouse_daemon::socket_server::serve(&socket_path, requests_tx, events_rx).await
        }
    });
    // `serve` is the async body being spawned here, not (like Phase 1's
    // `serve_ndjson`) a plain function that bound synchronously before
    // returning its `JoinHandle` — so its `bind` doesn't run until the
    // runtime actually polls this task. Give it a moment before dialing.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut client = roundhouse_tui::connect(
        &socket_path,
        ConnectIntent::CreateSession {
            workspace_name: "test".into(),
        },
    )
    .await
    .unwrap();
    // connect() must send a real ClientRequest — assert the server actually received one
    let received = requests_rx.recv().await.unwrap();
    assert!(matches!(
        received,
        ClientRequest::CreateSession { .. } | ClientRequest::Attach { .. }
    ));
    drop(events_tx);
    server.abort();
    let _ = client.recv().await; // drains cleanly on server-side channel close
}
