//! Phase 1's exit criterion, verified end to end: a scripted session opens the
//! real event log, runs one chat turn through `roundhouse-engine`, edits a real
//! file through `roundhouse-tools`, and the resulting updates arrive over the
//! Unix socket in `roundhouse-tui`'s NDJSON wire format.

use roundhouse_core::TaskRunner;
use roundhouse_daemon::demo::{run_demo_session, DemoConfig, FakeEditProvider, NoopTransport};
use roundhouse_daemon::socket_server::serve_ndjson;
use roundhouse_provider::RequestCtx;
use roundhouse_tui::{connect, ServerMessage};
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

    let (tx, rx) = mpsc::channel(16);
    let server = serve_ndjson(&socket_path, rx).unwrap();

    // `serve_ndjson` binds synchronously before returning the join handle
    // (see `socket_server.rs`), so the socket already exists — no sleep needed
    // before dialing, same as Task 18's own attach test.
    let mut client = connect(&socket_path).await.unwrap();

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
        },
    };

    let outcome = run_demo_session(cfg, &runner, tx).await.unwrap();

    assert!(
        outcome.edited_file.contains("\"new\""),
        "edit_file must have replaced \"old\" with \"new\" on disk"
    );
    assert!(!outcome.edited_file.contains("\"old\""));

    let first = client.recv().await.unwrap();
    assert_eq!(
        first,
        Some(ServerMessage::TaskDelta {
            task_id: outcome.session_id.to_string(),
            text: "Edited main.rs".into()
        })
    );
    let second = client.recv().await.unwrap();
    assert_eq!(
        second,
        Some(ServerMessage::SessionSummary {
            session_id: outcome.session_id.to_string(),
            running_tasks: 0,
            blocked: false
        })
    );

    server.abort();
}
