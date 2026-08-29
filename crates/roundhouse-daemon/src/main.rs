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
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

/// The demo file's starting contents, rewritten on every run so repeated
/// `cargo run`s behave identically: `edit_file` fails closed when `find` doesn't
/// occur exactly once (S-TOOL-3), so a file left containing "new" from a
/// previous run would make the second run error instead of demoing anything.
const DEMO_FILE_CONTENTS: &str = "hello old world\n";

/// Owner-only. Everything the daemon writes lives under a directory with this
/// mode, so no other unprivileged user on the host can pre-plant a symlink at a
/// path the daemon is about to open with `O_CREAT`.
const RUNTIME_DIR_MODE: u32 = 0o700;

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

    // Every artifact below (socket, event log, scratch file) goes inside one
    // private directory rather than straight into the shared temp dir. Writing
    // predictable names into a world-writable `/tmp` lets any other local user
    // pre-create one as a symlink; both `tokio::fs::write` and SQLite's
    // `O_CREAT` open follow symlinks, so the daemon would truncate a file the
    // attacker chose, as the victim.
    let runtime_dir = roundhouse_tui::default_runtime_dir();
    prepare_runtime_dir(&runtime_dir)?;

    let socket_path = std::env::var_os("ROUND_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(roundhouse_tui::default_socket_path);
    remove_stale_socket(&socket_path)?;

    let store_path = runtime_dir.join("demo-events.db");
    let edit_target = runtime_dir.join("demo-target.txt");
    write_demo_file(&edit_target).await?;

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

    // Unlink on the way out: a bound Unix socket outlives the process that
    // created it, and a leftover one makes the next run's `bind` fail with
    // `EADDRINUSE` (and looks, to a client, like a daemon that never answers).
    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

/// Creates the daemon's runtime directory `0700`, or accepts an existing one
/// only if it is still a real, owner-only directory.
///
/// Uses `symlink_metadata`, which does *not* follow symlinks, so a pre-planted
/// `runtime_dir -> /somewhere/else` is rejected here instead of being silently
/// accepted as "a directory". The mode check rejects a directory some other user
/// left group- or world-writable, which would otherwise still allow the symlink
/// pre-plant this whole function exists to stop.
///
/// Deliberately does not verify the owning uid: reading the current process's
/// uid needs a `getuid()` call, and this crate is `#![forbid(unsafe_code)]` with
/// no `libc`/`rustix` dependency. The gap is small — a `0700` directory owned by
/// *another* user is one this process cannot traverse at all, so every
/// subsequent open fails with `EACCES`. That degrades the attack to denial of
/// service rather than a clobber, which is the property that matters here.
fn prepare_runtime_dir(dir: &Path) -> std::io::Result<()> {
    match std::fs::DirBuilder::new().mode(RUNTIME_DIR_MODE).create(dir) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {
            let meta = std::fs::symlink_metadata(dir)?;
            if !meta.file_type().is_dir() {
                return Err(std::io::Error::new(
                    ErrorKind::AlreadyExists,
                    format!(
                        "{} exists but is not a directory; refusing to use it",
                        dir.display()
                    ),
                ));
            }
            let mode = meta.permissions().mode() & 0o777;
            if mode != RUNTIME_DIR_MODE {
                return Err(std::io::Error::new(
                    ErrorKind::PermissionDenied,
                    format!(
                        "{} has mode {mode:04o}, expected {RUNTIME_DIR_MODE:04o}; \
                         refusing to write runtime state into a directory others can reach",
                        dir.display()
                    ),
                ));
            }
            Ok(())
        }
        Err(err) => Err(err),
    }
}

/// Removes a leftover socket from a previous run, and *only* a socket.
///
/// An unconditional `remove_file` here would delete whatever happened to sit at
/// the path — including a file the operator pointed `$ROUND_SOCKET` at by
/// mistake. `symlink_metadata` does not follow symlinks, so a symlink at this
/// path is reported as a symlink (not a socket) and is refused rather than
/// followed.
fn remove_stale_socket(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path),
        Ok(_) => Err(std::io::Error::new(
            ErrorKind::AlreadyExists,
            format!(
                "{} exists and is not a socket; refusing to remove it",
                path.display()
            ),
        )),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

/// Writes the demo's scratch file, refusing to follow a pre-planted symlink.
///
/// `remove_file` unlinks a symlink itself rather than its target, and
/// `create_new` opens with `O_EXCL`, which refuses to follow one. Together they
/// close the symlink-clobber hole that a plain `fs::write` (`O_CREAT|O_TRUNC`,
/// which does follow) would leave open — belt-and-braces with the `0700`
/// directory, which is the primary defense.
async fn write_demo_file(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .await?;
    file.write_all(DEMO_FILE_CONTENTS.as_bytes()).await?;
    file.flush().await?;
    Ok(())
}
