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
use roundhouse_provider::{AnthropicMessagesProvider, Provider, RequestCtx, ReqwestTransport};
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
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
    // demo session — against `demo::FakeEditProvider` by default, and against
    // the real `AnthropicMessagesProvider` when `ANTHROPIC_API_KEY` is set (see
    // the provider selection below).
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

    // The one switch between the hermetic demo and a real model call.
    //
    // Keyed on the *presence* of `ANTHROPIC_API_KEY` rather than on a flag, so
    // the no-key path is the default: with no key set this binary opens zero
    // outbound connections, matching §12.5's "zero outbound connections before
    // first session creation" budget, and the exit-criterion demo stays runnable
    // offline and in CI. Only an operator who has deliberately exported a key
    // gets a live, billable request.
    //
    // The key is moved straight into `RequestCtx` and never touched again here:
    // it is not logged, not echoed into the "demo session complete" line below,
    // and neither `RequestCtx` nor `HttpRequest` derives `Debug`, so no
    // formatter downstream can print it either (§9.9).
    let (provider, request_ctx): (Arc<dyn Provider>, RequestCtx) =
        match std::env::var("ANTHROPIC_API_KEY") {
            Ok(api_key) => (
                Arc::new(AnthropicMessagesProvider::new()),
                RequestCtx {
                    trace_id: None,
                    transport: Arc::new(ReqwestTransport::new()),
                    api_key,
                },
            ),
            Err(_) => (
                Arc::new(FakeEditProvider {
                    reply_text: "Edited the demo file.".into(),
                }),
                RequestCtx {
                    trace_id: None,
                    transport: Arc::new(NoopTransport),
                    api_key: "demo".into(),
                },
            ),
        };

    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let server = serve_ndjson(&socket_path, rx)?;

    let cfg = DemoConfig {
        store_path,
        edit_target,
        find: "old".into(),
        replace: "new".into(),
        provider,
        request_ctx,
    };

    // With the fake provider this runs to completion immediately (it never
    // touches the network); with the real one it takes as long as one Anthropic
    // turn. Either way the two resulting messages sit buffered in the channel
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
    //
    // Goes through the same guarded helper as startup, so this can never delete
    // something that isn't a socket — the path could have been replaced while
    // the daemon ran. Failure is ignored rather than propagated: the run
    // succeeded, and `remove_stale_socket` at the next startup is self-healing.
    let _ = remove_stale_socket(&socket_path);
    Ok(())
}

/// Creates the daemon's runtime directory `0700`, or accepts an existing one
/// only if it is still a real, owner-only directory belonging to this user.
///
/// All three checks run against the *same* `symlink_metadata` result, so there
/// is no window between them. `symlink_metadata` does not follow symlinks, so a
/// pre-planted `runtime_dir -> /somewhere/else` is rejected here rather than
/// silently accepted as "a directory".
///
/// The three refusals, and why each is load-bearing:
/// 1. **Not a directory** — catches the symlink pre-plant directly.
/// 2. **Mode != 0700** — catches a directory left group- or world-writable, which
///    would let anyone drop a symlink *inside* it for the daemon to open.
/// 3. **Owned by another uid** — catches a `0700` directory the attacker owns.
///    Mode alone is not enough: running as root (or with `CAP_DAC_OVERRIDE`)
///    traverses a foreign `0700` directory freely, and SQLite opens `store_path`
///    with `O_CREAT` *following symlinks*, so an attacker-owned directory is a
///    root-clobber primitive. Even unprivileged, accepting a directory whose
///    entries the attacker controls leaves a TOCTOU window in which they can
///    swap a symlink in between this check and the later open.
fn prepare_runtime_dir(dir: &Path) -> std::io::Result<()> {
    match std::fs::DirBuilder::new().mode(RUNTIME_DIR_MODE).create(dir) {
        // Freshly created by us, so it is by construction a directory, 0700, and
        // ours — none of the checks below can fail.
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
            check_owned_by_current_user(dir, &meta)?;
            Ok(())
        }
        Err(err) => Err(err),
    }
}

/// Rejects a runtime directory owned by anyone but the current user.
///
/// Linux-only, because the uid is read from `/proc/self` — `std::fs::metadata`
/// on it reports the current process's own uid, which is the whole trick that
/// makes this dependency-free (`getuid()` itself would mean taking on `libc` or
/// `rustix`). Failing to read `/proc` is treated as a hard error, not as a pass:
/// an ownership check that silently no-ops when it can't run isn't a check.
///
/// **`metadata`, never `symlink_metadata`, on this one path.** `/proc/self` is a
/// *symlink* to `/proc/<pid>`, and like every `/proc` symlink it is itself owned
/// by `root:root` — so `symlink_metadata` here would report uid 0 for every
/// process and make this check reject every directory (or, worse, pass when
/// running as root). Following it reaches the real `/proc/<pid>` directory,
/// whose owner is this process's uid. This is the one place in this file where
/// following a symlink is the correct behavior; every other call deliberately
/// uses `symlink_metadata` for the opposite reason.
#[cfg(target_os = "linux")]
fn check_owned_by_current_user(dir: &Path, meta: &std::fs::Metadata) -> std::io::Result<()> {
    let current_uid = std::fs::metadata("/proc/self")
        .map_err(|err| {
            std::io::Error::new(
                err.kind(),
                format!("cannot read /proc/self to determine this process's uid: {err}"),
            )
        })?
        .uid();
    let owner_uid = meta.uid();
    if owner_uid != current_uid {
        return Err(std::io::Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "{} is owned by uid {owner_uid}, not this process's uid {current_uid}; \
                 refusing to write runtime state into another user's directory",
                dir.display()
            ),
        ));
    }
    Ok(())
}

/// Non-Linux fallback: no `/proc`, and reading the uid otherwise would mean
/// adding `libc`/`rustix` for one syscall.
///
/// The gap is narrow in practice on the platform that matters here: macOS gives
/// each user a private, per-user `$TMPDIR` (`/var/folders/...`, mode `0700`), so
/// the shared-directory pre-plant this check defends against does not arise on
/// the fallback path there the way it does under a world-writable `/tmp`. Linux —
/// where `temp_dir()` really is the shared `/tmp` — gets the real check above.
#[cfg(not(target_os = "linux"))]
fn check_owned_by_current_user(_dir: &Path, _meta: &std::fs::Metadata) -> std::io::Result<()> {
    Ok(())
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
