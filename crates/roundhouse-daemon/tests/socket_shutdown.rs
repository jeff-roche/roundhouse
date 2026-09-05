//! Regression tests for a review-round bug: `serve_connection` used to track
//! independent `read_done`/`write_done` flags and loop until *both* were set,
//! which deadlocked on the single most common shutdown order there is — one
//! side finishing while the other has nothing more to say. Both tests here
//! deliberately avoid `server.abort()`, since that call is exactly how the
//! bug hid: it manufactures a socket closure that only exists in tests, never
//! exercising whether `serve` can return on its own.

use roundhouse_tui::ConnectIntent;
use std::time::Duration;

/// Ordering 1: the event stream ends first (the normal shutdown order once a
/// session finishes, e.g. `run_demo_session` returning and dropping its
/// sender) while the client is still connected and has nothing more to send.
/// `serve` must return on its own, and the client must see a clean EOF
/// (`Ok(None)`), not hang forever waiting for a peer that will never write
/// anything else.
#[tokio::test]
async fn dropping_the_events_sender_ends_the_connection_and_the_client_sees_a_clean_eof() {
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
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut client = roundhouse_tui::connect(
        &socket_path,
        ConnectIntent::CreateSession {
            workspace_name: "test".into(),
        },
    )
    .await
    .unwrap();
    // Drain the handshake request so `requests_out`'s buffer isn't sitting
    // full for the rest of the test (it has room regardless, but this keeps
    // the scenario realistic: something is actually consuming requests).
    requests_rx.recv().await.unwrap();

    // The event stream ending — no `server.abort()` anywhere in this test.
    drop(events_tx);

    let outcome = tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("serve must return on its own once events_in closes, not hang forever")
        .expect("serve's task must not panic");
    assert!(
        outcome.is_ok(),
        "serve should return Ok(()) on this shutdown order, got {outcome:?}"
    );

    let received = tokio::time::timeout(Duration::from_secs(2), client.recv())
        .await
        .expect("the client must see the daemon close its side, not hang forever");
    assert!(
        matches!(received, Ok(None)),
        "expected a clean EOF once serve tears the connection down, got {received:?}"
    );
}

/// Ordering 2 (the mirror case): the client disconnects first while the
/// event stream is still alive (standing in for Task 3's registry, which
/// keeps a session's event sender alive independent of any one connection).
/// `serve` must return on its own rather than leak a task parked forever on
/// `events_in.recv()` for a connection nothing will ever read again.
#[tokio::test]
async fn the_client_disconnecting_first_ends_serve_without_leaking_a_blocked_task() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let (requests_tx, mut requests_rx) = tokio::sync::mpsc::channel(4);
    let (_events_tx, events_rx) = tokio::sync::mpsc::channel(4);
    let server = tokio::spawn({
        let socket_path = socket_path.clone();
        async move {
            roundhouse_daemon::socket_server::serve(&socket_path, requests_tx, events_rx).await
        }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let client = roundhouse_tui::connect(
        &socket_path,
        ConnectIntent::CreateSession {
            workspace_name: "test".into(),
        },
    )
    .await
    .unwrap();
    requests_rx.recv().await.unwrap();

    // The client disconnects first. `_events_tx` is deliberately kept alive
    // (unused past this point) for the whole test — a leaking `serve_connection`
    // would sit blocked on `events_in.recv()` forever with this sender still
    // live, exactly the failure mode this test exists to catch.
    drop(client);

    let outcome = tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect(
            "serve must return once its peer disconnects, not leak a task \
             blocked on events_in.recv() forever",
        )
        .expect("serve's task must not panic");
    assert!(
        outcome.is_ok(),
        "serve should return Ok(()) on this shutdown order, got {outcome:?}"
    );
}
