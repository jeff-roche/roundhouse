//! The `round` binary: TUI attach, headless/one-shot runs, and `round
//! daemon` (a separate process, spawned by `commands::daemon::run` — not a
//! Cargo dependency edge; see §5.2's dependency table note on why this
//! crate deliberately doesn't depend on `roundhouse-daemon` despite the
//! table listing that edge).
//!
//! Phase 1 implemented the attach path only. Task A8/G6 adds this binary's
//! first argument parsing (`cli::Cli`, ruling P11): `round daemon` and
//! `round service install`/`round service uninstall`. Running `round` with
//! no subcommand keeps the Phase 1 behavior below unchanged. Session
//! selection and other headless runs are later tasks, extending
//! `cli::Command` rather than replacing it.
#![forbid(unsafe_code)]

use clap::Parser;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use roundhouse_cli::cli::{Cli, Command, ServiceAction};
use roundhouse_cli::commands::{daemon, service_install};
use roundhouse_tui::Dashboard;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    match Cli::parse().command {
        Some(Command::Daemon) => run_daemon().await,
        Some(Command::Service { action }) => run_service(action),
        None => attach().await,
    }
}

/// `round daemon`: runs the real daemon binary in the foreground and exits
/// with its exit code, per `commands::daemon`'s module doc.
async fn run_daemon() -> color_eyre::Result<()> {
    let status = daemon::run()
        .await
        .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?;
    std::process::exit(status.code().unwrap_or(1));
}

/// `round service install`/`round service uninstall`, per
/// `commands::service_install`'s module doc.
fn run_service(action: ServiceAction) -> color_eyre::Result<()> {
    let os = current_os_family()?;
    match action {
        ServiceAction::Install { force } => {
            let exec_path = service_install::resolve_exec_path()
                .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?;
            let installed = service_install::install(os, &exec_path, force)
                .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?;
            println!("installed {}", installed.display());
            print_enable_instructions(os);
        }
        ServiceAction::Uninstall => {
            service_install::uninstall(os).map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?;
            println!("removed the roundhouse service for this user");
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn current_os_family() -> color_eyre::Result<service_install::OsFamily> {
    Ok(service_install::OsFamily::Linux)
}

#[cfg(target_os = "macos")]
fn current_os_family() -> color_eyre::Result<service_install::OsFamily> {
    Ok(service_install::OsFamily::MacOs)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn current_os_family() -> color_eyre::Result<service_install::OsFamily> {
    Err(color_eyre::eyre::eyre!(
        "round service is only supported on Linux (systemd) and macOS (launchd)"
    ))
}

/// Enabling/starting the unit is left to the operator (see
/// `service_install::install`'s doc comment for why `install` itself never
/// shells out): print the exact next command instead of running it.
fn print_enable_instructions(os: service_install::OsFamily) {
    match os {
        service_install::OsFamily::Linux => println!(
            "run: systemctl --user daemon-reload && systemctl --user enable --now roundhouse.service"
        ),
        service_install::OsFamily::MacOs => println!(
            "run: launchctl load -w ~/Library/LaunchAgents/com.roundhouse.daemon.plist"
        ),
    }
}

/// Phase 1's attach path, unchanged: connect to the daemon's Unix socket and
/// render every incoming `ServerMessage` through `roundhouse_tui::Dashboard`.
async fn attach() -> color_eyre::Result<()> {
    // Phase 0's placeholder `roundhouse_tui::client_schema()`: not yet consumed
    // for anything beyond proving the wire-schema call site exists.
    let _schema = roundhouse_tui::client_schema();

    // Resolved through `roundhouse-tui` rather than computed here: the daemon
    // resolves the same default from the same function, which is what keeps the
    // two sides from drifting onto different paths. It lives in the shared crate
    // because this crate does not link `roundhouse-daemon` — per the enforced
    // baseline in `xtask/tests/exit_criterion.rs`, not per §5.2, whose table does
    // list that edge (see `roundhouse_tui::default_runtime_dir`).
    let socket_path = std::env::var_os("ROUND_SOCKET")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(roundhouse_tui::default_socket_path);

    let mut client = roundhouse_tui::connect(&socket_path)
        .await
        .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?;

    // Deliberately no `enable_raw_mode()` here, despite that being the usual
    // ratatui preamble. Raw mode clears `ISIG`, so Ctrl+C stops generating
    // SIGINT and instead arrives as an ordinary keystroke — and this loop reads
    // no keystrokes, because `DaemonClient::recv` wraps a `BufReader::read_line`
    // that is *not* cancellation-safe, so racing it against a key-event stream
    // in a `select!` could silently discard a half-buffered NDJSON line. Until
    // there is a real input path (Phase 5's TUI), leaving the terminal cooked
    // means Ctrl+C keeps working and no failure mode can strand the user's
    // terminal in raw mode. The loop also ends on its own when the daemon closes
    // the socket.
    let backend = CrosstermBackend::new(std::io::stdout());
    let mut terminal = Terminal::new(backend)?;
    let mut dashboard = Dashboard::new();

    run_attach_loop(&mut client, &mut terminal, &mut dashboard).await
}

/// The real attach-and-render loop: every message received drives `Dashboard::apply`,
/// then `Dashboard::tick` runs the real `render_tick` path — the exit criterion's "watch
/// it edit a file, see the task log" exercised through Tasks 19-20's actual code, not a
/// parallel scripted one.
///
/// Returns `Ok(())` on a clean EOF (the daemon closed the socket). A malformed
/// NDJSON line is a hard error rather than a skipped line: the daemon is the
/// only writer on this socket, so a line that won't parse means the two sides
/// disagree about the wire format, and continuing would render a silently
/// incomplete session.
///
/// A failed draw is likewise an error, not something to ignore: with stdout
/// closed (`round | head -1`) or the terminal gone, every subsequent frame would
/// fail too, so exiting is the only sensible response.
async fn run_attach_loop<B>(
    client: &mut roundhouse_tui::DaemonClient,
    terminal: &mut Terminal<B>,
    dashboard: &mut Dashboard,
) -> color_eyre::Result<()>
where
    B: ratatui::backend::Backend,
    // `Backend::Error` is only bounded by `core::error::Error` upstream; eyre
    // needs the extra three bounds to absorb it. `CrosstermBackend`'s
    // `io::Error` satisfies them.
    B::Error: std::error::Error + Send + Sync + 'static,
{
    while let Some(message) = client
        .recv()
        .await
        .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?
    {
        dashboard.apply(message);
        dashboard.tick(terminal)?;
    }
    Ok(())
}
