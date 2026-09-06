//! Phase 1's exit criterion, verified end to end: a scripted session opens the
//! real event log, runs one chat turn through `roundhouse-engine`, edits a real
//! file through `roundhouse-tools`, and the resulting updates arrive over the
//! Unix socket as real `roundhouse-proto` `ClientEvent`s (Phase 7 Task 2
//! retired the hand-rolled `ServerMessage` this test used to assert on).

use roundhouse_core::{Delta, EventPayload, SessionState, TaskRunner};
use roundhouse_daemon::demo::{run_demo_session, DemoConfig, FakeEditProvider, NoopTransport};
use roundhouse_daemon::socket_server::serve;
use roundhouse_provider::RequestCtx;
use roundhouse_tui::{connect, ConnectIntent};
use std::sync::Arc;
use tokio::sync::mpsc;

#[tokio::test]
async fn human_runs_round_starts_a_session_watches_an_edit_and_sees_it_over_the_socket() {
    // `TaskRunner::bootstrap()` panics on a second call per process. Each
    // integration-test binary is its own process and this file holds exactly one
    // test, so a plain local binding is safe here — no shared `Lazy` needed.
    let runner = TaskRunner::bootstrap();

    let dir = tempfile::tempdir().unwrap();
    let store_path = dir.path().join("events.db");
    let socket_path = dir.path().join("round.sock");
    let edit_target = dir.path().join("main.rs");
    tokio::fs::write(&edit_target, "fn main() { let x = \"old\"; }\n")
        .await
        .unwrap();

    let (events_tx, events_rx) = mpsc::channel(16);
    let (requests_tx, _requests_rx) = mpsc::channel(16);
    let server = tokio::spawn({
        let socket_path = socket_path.clone();
        async move { serve(&socket_path, requests_tx, events_rx).await }
    });

    // Unlike Phase 1's `serve_ndjson` (a plain function that bound
    // synchronously before returning its `JoinHandle`), `serve` is itself
    // the async body being spawned above — its `bind` doesn't run until the
    // runtime actually polls this task, which isn't guaranteed to happen
    // before `tokio::spawn` returns control here. A short sleep closes that
    // scheduling gap; see `socket_server::serve`'s doc comment.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut client = connect(
        &socket_path,
        ConnectIntent::CreateSession {
            workspace_name: "test".into(),
        },
    )
    .await
    .unwrap();

    let cfg = DemoConfig {
        store_path,
        edit_target: edit_target.clone(),
        find: "old".into(),
        replace: "new".into(),
        provider: Arc::new(FakeEditProvider {
            reply_text: "Edited main.rs".into(),
        }),
        request_ctx: RequestCtx {
            trace_id: None,
            transport: Arc::new(NoopTransport),
            api_key: "test".into(),
            credentials: None,
        },
    };

    let outcome = run_demo_session(cfg, &runner, events_tx).await.unwrap();

    assert!(
        outcome.edited_file.contains("\"new\""),
        "edit_file must have replaced \"old\" with \"new\" on disk"
    );
    assert!(!outcome.edited_file.contains("\"old\""));

    let first = client.recv().await.unwrap();
    match first {
        Some(roundhouse_proto::ClientEvent::TaskEvent {
            session_id,
            payload,
            ..
        }) => {
            assert_eq!(session_id, outcome.session_id);
            assert!(matches!(
                *payload,
                EventPayload::TaskDelta {
                    delta: Delta::Text { ref text }
                } if text == "Edited main.rs"
            ));
        }
        other => panic!("expected a TaskDelta TaskEvent, got {other:?}"),
    }

    let second = client.recv().await.unwrap();
    match second {
        Some(roundhouse_proto::ClientEvent::TaskEvent {
            session_id,
            payload,
            ..
        }) => {
            assert_eq!(session_id, outcome.session_id);
            assert!(matches!(
                *payload,
                EventPayload::SessionStateChanged {
                    state: SessionState::Closed,
                    reason: None
                }
            ));
        }
        other => panic!("expected a SessionStateChanged TaskEvent, got {other:?}"),
    }

    server.abort();
}
