//! The daemon binary: wiring, API server, and lifecycle for `round daemon`
//! — the long-running process every `roundhouse-cli` client attaches to or
//! sends requests through. Depends on nearly every other crate in the
//! workspace (it's one of only two crates — the other is
//! `roundhouse-cli` — allowed to; nothing else may depend on either).
//!
//! Phase 1 runs exactly one scripted demo session (the vertical-slice exit
//! criterion) and serves its updates to one attached client; the real
//! supervisor/API-server/lifecycle wiring is Phase 2+ (§13.2). The testable
//! parts live in `roundhouse_daemon`'s lib target, next to this file.
#![forbid(unsafe_code)]

use roundhouse_core::TaskRunner;
use roundhouse_daemon::demo::{run_demo_session, DemoConfig, FakeEditProvider, NoopTransport};
use roundhouse_daemon::socket_server::serve_ndjson;
use roundhouse_provider::RequestCtx;
use std::sync::Arc;

/// The demo file's starting contents, rewritten on every run so repeated
/// `cargo run`s behave identically: `edit_file` fails closed when `find` doesn't
/// occur exactly once (S-TOOL-3), so a file left containing "new" from a
/// previous run would make the second run error instead of demoing anything.
const DEMO_FILE_CONTENTS: &str = "hello old world\n";

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    // Phase 0 proves the dependency graph compiles; this proves the five
    // vertical-slice crates run together. This binary runs exactly one scripted
    // demo session against a fake provider; see `demo::FakeEditProvider`'s doc
    // comment for why a real one doesn't exist yet.
    //
    // `TaskRunner::bootstrap()` is called here, at the daemon's actual startup
    // site, which is exactly the contract its doc comment states ("called
    // exactly once ... at daemon startup, and threaded through from there") —
    // it panics on a second call. `roundhouse_engine::EngineHandles::bootstrap`
    // is the eventual home for this call, but it also demands an
    // `Arc<dyn Bus>`, and no concrete `Bus` implementation exists yet (Phase 0
    // shipped only the trait). Nothing in this demo uses the bus, so this
    // bypasses `EngineHandles` rather than inventing a stub bus for it.
    let runner = TaskRunner::bootstrap();
    let _layers = roundhouse_config::default_layers(None);

    let socket_path = std::env::var_os("ROUND_SOCKET")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("round-demo.sock"));
    // A stale socket file from a previous run would make `bind` fail with
    // `EADDRINUSE`; removing it is the standard Unix-socket startup dance.
    let _ = std::fs::remove_file(&socket_path);
    let store_path = std::env::temp_dir().join("round-demo-events.db");
    let edit_target = std::env::temp_dir().join("round-demo-target.txt");
    tokio::fs::write(&edit_target, DEMO_FILE_CONTENTS).await?;

    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let server = serve_ndjson(&socket_path, rx)?;

    let cfg = DemoConfig {
        store_path,
        edit_target,
        find: "old".into(),
        replace: "new".into(),
        provider: Arc::new(FakeEditProvider {
            reply_text: "Edited the demo file.".into(),
        }),
        request_ctx: RequestCtx {
            trace_id: None,
            transport: Arc::new(NoopTransport),
            api_key: "demo".into(),
        },
    };

    // Runs to completion immediately (the fake provider never touches the
    // network); the two resulting messages sit buffered in the channel
    // until a `round` client connects and drains them below.
    let outcome = run_demo_session(cfg, &runner, tx)
        .await
        .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?;

    // `println!`, not `tracing::info!`: no subscriber is installed (Phase 2's
    // real daemon lifecycle owns that decision), so a `tracing` event here would
    // go nowhere — and this line is the operator's cue to start `round` in a
    // second terminal.
    println!(
        "demo session complete: session_id={} socket={}",
        outcome.session_id,
        socket_path.display()
    );

    // Blocks on `listener.accept()` until a `round` client attaches, then
    // drains the buffered messages and exits once the channel closes.
    server.await.ok();
    Ok(())
}
