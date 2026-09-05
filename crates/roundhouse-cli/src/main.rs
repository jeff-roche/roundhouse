//! The `round` binary: TUI attach, headless/one-shot runs, and `round
//! daemon` (a separate process, spawned by `commands::daemon::run` — not a
//! Cargo dependency edge; see §5.2's dependency table note on why this
//! crate deliberately doesn't depend on `roundhouse-daemon` despite the
//! table listing that edge).
//!
//! Phase 1 implemented the attach path only. Task A8/G6 added this binary's
//! first argument parsing (`cli::Cli`, ruling P11): `round daemon` and
//! `round service install`/`round service uninstall`. Phase 7, Task 7 adds
//! the session-selection/headless subcommands lane W1's exit criterion
//! names: `round attach --session ID`, `round create [--workspace NAME]`,
//! and `round run [--workspace NAME]` (headless, no TUI). Running `round`
//! with no subcommand keeps the Phase 1 behavior unchanged — equivalent to
//! `round create` with the default workspace name.
#![forbid(unsafe_code)]

use clap::Parser;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use roundhouse_cli::cli::{Cli, Command, ServiceAction, DEFAULT_WORKSPACE_NAME};
use roundhouse_cli::commands::{daemon, service_install};
use roundhouse_tui::{DaemonClient, Dashboard, SessionId};

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    install_tracing_subscriber();

    match Cli::parse().command {
        Some(Command::Daemon) => run_daemon().await,
        Some(Command::Service { action }) => run_service(action),
        Some(Command::Attach { session }) => attach_to_session(session).await,
        Some(Command::Create { workspace }) => create_and_attach(workspace).await,
        Some(Command::Run { workspace }) => run_headless(workspace).await,
        None => create_and_attach(DEFAULT_WORKSPACE_NAME.to_string()).await,
    }
}

/// Ruling W1-R96 (fix round 1): installs a real `tracing` subscriber before
/// anything else runs — see `round-daemon-internal`'s identical function
/// for the full rationale. This crate has no `tracing::*` call site of its
/// own today, but the review named "both `main`s" explicitly: without this,
/// a future one (most plausibly inside `roundhouse-tui`) would be silently
/// dropped the same way the daemon's were before this fix round.
fn install_tracing_subscriber() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .init();
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

/// The socket path every subcommand below connects to: `$ROUND_SOCKET` if
/// set, otherwise the same default the daemon itself binds
/// (`roundhouse_tui::default_socket_path`) — resolved through
/// `roundhouse-tui` rather than computed here so the two sides can't drift
/// onto different paths.
fn socket_path() -> std::path::PathBuf {
    std::env::var_os("ROUND_SOCKET")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(roundhouse_tui::default_socket_path)
}

/// `round create [--workspace NAME]`: mint a new session and attach the TUI
/// to it. Also what running `round` with no subcommand does (with
/// `DEFAULT_WORKSPACE_NAME`), preserving the Phase 1 exit-criterion path
/// unchanged.
async fn create_and_attach(workspace_name: String) -> color_eyre::Result<()> {
    // Phase 0's placeholder `roundhouse_tui::client_schema()`: not yet consumed
    // for anything beyond proving the wire-schema call site exists.
    let _schema = roundhouse_tui::client_schema();

    let client = roundhouse_tui::connect_create(&socket_path(), &workspace_name)
        .await
        .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?;
    run_tui(client).await
}

/// `round attach --session ID`: attach the TUI to an already-running
/// session.
///
/// **Read-only once the creating connection has disconnected** (rulings
/// W1-R37/W1-R52) — see `cli::Command::Attach`'s own doc comment. This
/// function only ever *receives* the session's event stream; it never sends
/// anything past the handshake `Attach` request itself, so that limitation
/// isn't something this function could work around even if it tried to.
async fn attach_to_session(session: SessionId) -> color_eyre::Result<()> {
    let client = roundhouse_tui::connect_attach(&socket_path(), session)
        .await
        .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?;
    run_tui(client).await
}

/// Shared by [`create_and_attach`]/[`attach_to_session`]: build the
/// `ratatui` terminal and dashboard, then run the real attach-and-render
/// loop. See [`run_attach_loop`]'s own doc comment for why raw mode is
/// deliberately never enabled here.
async fn run_tui(mut client: DaemonClient) -> color_eyre::Result<()> {
    let backend = CrosstermBackend::new(std::io::stdout());
    let mut terminal = Terminal::new(backend)?;
    let mut dashboard = Dashboard::new();

    run_attach_loop(&mut client, &mut terminal, &mut dashboard).await
}

/// `round run [--workspace NAME]`: mint a new session and stream its
/// events to stdout, one JSON line per event, with no TUI — for scripting
/// and CI, where there is no terminal to draw a dashboard into.
///
/// Prints the minted session id to stdout FIRST, before any event, so a
/// caller that wants to `round attach --session ID` this same session from
/// another terminal (a viewer, per the read-only limitation above) can
/// capture it. Exits cleanly once the daemon closes the connection — the
/// session's own actor keeps running independently of this connection
/// (ruling W1-R51), so exiting here does not stop whatever the session is
/// doing.
async fn run_headless(workspace_name: String) -> color_eyre::Result<()> {
    let mut client = roundhouse_tui::connect_create(&socket_path(), &workspace_name)
        .await
        .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?;
    println!("session_id={}", client.session_id());

    while let Some(event) = client
        .recv()
        .await
        .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?
    {
        println!(
            "{}",
            serde_json::to_string(&event).map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?
        );
    }
    Ok(())
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
    while let Some(event) = client
        .recv()
        .await
        .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?
    {
        // `ClientEvent` is `#[non_exhaustive]` (Phase 0) and today carries
        // only `TaskEvent`/`Ack`; `Ack` — no protocol-version negotiation UI
        // exists yet (Phase 5) — falls through untouched.
        if let roundhouse_proto::ClientEvent::TaskEvent {
            session_id,
            payload,
            ..
        } = event
        {
            dashboard.apply(session_id, *payload);
            dashboard.tick(terminal)?;
        }
    }
    Ok(())
}
