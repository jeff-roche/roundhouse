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
use roundhouse_proto::{ClientEvent, ClientRequest, TurnOutcome};
use roundhouse_tui::{DaemonClient, Dashboard, SessionId};
use std::process::ExitCode;
use std::time::Duration;

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(report) = color_eyre::install() {
        eprintln!("Error: {report:?}");
        return ExitCode::FAILURE;
    }
    install_tracing_subscriber();

    let result = match Cli::parse().command {
        Some(Command::Daemon { workspaces }) => run_daemon(workspaces).await,
        Some(Command::Service { action }) => run_service(action),
        Some(Command::Attach { session }) => attach_to_session(session).await,
        Some(Command::Create { workspace }) => create_and_attach(workspace).await,
        Some(Command::Run {
            workspace,
            message: Some(text),
        }) => return run_one_turn(workspace, text).await,
        Some(Command::Run {
            workspace,
            message: None,
        }) => run_headless(workspace).await,
        None => create_and_attach(DEFAULT_WORKSPACE_NAME.to_string()).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        // What returning the `Err` from `main` printed before `main` returned
        // an `ExitCode`.
        Err(report) => {
            eprintln!("Error: {report:?}");
            ExitCode::FAILURE
        }
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
async fn run_daemon(workspaces: Vec<String>) -> color_eyre::Result<()> {
    let status = daemon::run(&workspaces)
        .await
        .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?;
    std::process::exit(status.code().unwrap_or(1));
}

/// `round service install`/`round service uninstall`, per
/// `commands::service_install`'s module doc.
fn run_service(action: ServiceAction) -> color_eyre::Result<()> {
    let os = current_os_family()?;
    match action {
        ServiceAction::Install { force, workspaces } => {
            let exec_path = service_install::resolve_exec_path()
                .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?;
            let installed = service_install::install(os, &exec_path, force, &workspaces)
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
/// doing. With `--message`, [`run_one_turn`] runs instead.
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
        print_frame(&event)?;
    }
    Ok(())
}

/// Exit code for a turn that failed, or that the daemon refused.
const EXIT_TURN_FAILED: u8 = 1;
/// Exit code for a turn that was cancelled.
const EXIT_TURN_CANCELLED: u8 = 2;
/// Exit code when no outcome arrived: the daemon could not be reached, or
/// the connection ended (or broke) before this turn's `TurnFinished`.
const EXIT_NO_OUTCOME: u8 = 3;

/// Bounds the wait for `CloseSession`'s `Ack`. The daemon refuses a close
/// silently (no frame; see `DaemonClient::close_session`), so without a
/// bound a refusal would hang this process. Same value, for the same reason,
/// as `roundhouse-tui`'s `CLOSE_SESSION_ACK_TIMEOUT`, which is private.
const CLOSE_ACK_TIMEOUT: Duration = Duration::from_secs(40);

/// `round run [--workspace NAME] --message TEXT`: [`run_headless`]'s output,
/// but finishing on the submitted turn's own outcome (Phase 8 Task 21, #40).
///
/// Prints `session_id=`, then every frame as NDJSON up to and including THIS
/// connection's `TurnFinished`. Then it sends `CloseSession` and keeps
/// printing frames (the close's `SessionClosed`) until the `Ack`. The exit
/// code is the turn's: 0 completed, 1 failed or refused, 2 cancelled, 3 no
/// outcome. A failed close is a stderr warning and does not change it.
async fn run_one_turn(workspace_name: String, text: String) -> ExitCode {
    let (mut client, session_id) = match create_session_printing_frames(&workspace_name).await {
        Ok(created) => created,
        Err(err) => {
            eprintln!("error: could not create a session: {err}");
            return ExitCode::from(EXIT_NO_OUTCOME);
        }
    };

    // Ruling W1-R119: sent on THIS connection, the one that ran
    // `CreateSession`, because `drive_session` honors `SubmitTurn` from the
    // creating connection alone (W1-R37); `round attach` is a viewer and a
    // turn submitted from it would be refused (W1-R52). Sent AFTER
    // `session_id` is printed, so a caller capturing that line has it even
    // if the submission itself fails.
    if let Err(err) = client
        .send(&ClientRequest::SubmitTurn { session_id, text })
        .await
    {
        eprintln!("error: could not submit the turn: {err}");
        return ExitCode::from(EXIT_NO_OUTCOME);
    }

    let outcome = match await_turn_outcome(&mut client, session_id).await {
        Ok(Some(outcome)) => outcome,
        Ok(None) => {
            eprintln!("error: the daemon closed the connection before the turn finished");
            return ExitCode::from(EXIT_NO_OUTCOME);
        }
        Err(err) => {
            eprintln!("error: lost the connection before the turn finished: {err}");
            return ExitCode::from(EXIT_NO_OUTCOME);
        }
    };

    if let Err(err) = close_and_print(&mut client, session_id).await {
        eprintln!("warning: could not close session {session_id}: {err}");
    }
    exit_code_for(&outcome)
}

/// `CreateSession`, printing `session_id=` and then every frame from the
/// first, so stdout carries the session's seq 0 (`SessionCreated`) too.
/// `roundhouse_tui::connect_create` would consume that frame without
/// returning it.
///
/// The daemon commits `SessionCreated` as a new session's seq 0 and streams
/// it to the creator as its first `Committed` frame, so the session id is
/// read off that frame. Frames before it (none today) are held back until
/// `session_id=` is printed, which must be the first line.
async fn create_session_printing_frames(
    workspace_name: &str,
) -> color_eyre::Result<(DaemonClient, SessionId)> {
    let mut client = roundhouse_tui::connect(
        &socket_path(),
        roundhouse_tui::ConnectIntent::CreateSession {
            workspace_name: workspace_name.to_string(),
        },
    )
    .await
    .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?;
    let mut held_back = Vec::new();
    loop {
        let event = client
            .recv()
            .await
            .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?
            .ok_or_else(|| {
                color_eyre::eyre::eyre!("the daemon closed the connection before SessionCreated")
            })?;
        let created = match &event {
            ClientEvent::Committed {
                session_id, seq: 0, ..
            } => Some(*session_id),
            _ => None,
        };
        held_back.push(event);
        if let Some(session_id) = created {
            println!("session_id={session_id}");
            for event in &held_back {
                print_frame(event)?;
            }
            return Ok((client, session_id));
        }
    }
}

/// Prints frames until this connection's `TurnFinished` for `session_id`,
/// and returns its outcome; `None` on EOF first.
async fn await_turn_outcome(
    client: &mut DaemonClient,
    session_id: SessionId,
) -> color_eyre::Result<Option<TurnOutcome>> {
    while let Some(event) = client
        .recv()
        .await
        .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?
    {
        print_frame(&event)?;
        if let ClientEvent::TurnFinished {
            session_id: finished,
            outcome,
            ..
        } = event
        {
            if finished == session_id {
                return Ok(Some(outcome));
            }
        }
    }
    Ok(None)
}

/// Sends `CloseSession` and prints every frame up to and including its
/// `Ack`. Not `DaemonClient::close_session`, which discards the frames that
/// arrive before the `Ack` — among them the close's own `SessionClosed`,
/// which belongs in this command's output.
///
/// Cancelling the `recv` on [`CLOSE_ACK_TIMEOUT`] can desynchronize the
/// client's reader (see `DaemonClient::recv`'s cancel-safety note); that is
/// harmless here because the client is dropped right after.
async fn close_and_print(
    client: &mut DaemonClient,
    session_id: SessionId,
) -> color_eyre::Result<()> {
    client
        .send(&ClientRequest::CloseSession { session_id })
        .await
        .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?;
    let wait = async {
        while let Some(event) = client
            .recv()
            .await
            .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?
        {
            print_frame(&event)?;
            if matches!(event, ClientEvent::Ack { .. }) {
                return Ok(());
            }
        }
        Err(color_eyre::eyre::eyre!(
            "the daemon closed the connection without acknowledging CloseSession"
        ))
    };
    tokio::time::timeout(CLOSE_ACK_TIMEOUT, wait)
        .await
        .map_err(|_| {
            color_eyre::eyre::eyre!("no Ack for CloseSession within {CLOSE_ACK_TIMEOUT:?}")
        })?
}

/// The exit code for `outcome`, as `cli::Command::Run` documents it.
fn exit_code_for(outcome: &TurnOutcome) -> ExitCode {
    match outcome {
        TurnOutcome::Completed => ExitCode::SUCCESS,
        TurnOutcome::Cancelled { .. } => ExitCode::from(EXIT_TURN_CANCELLED),
        TurnOutcome::Failed { .. } | TurnOutcome::Rejected { .. } => {
            ExitCode::from(EXIT_TURN_FAILED)
        }
        // `TurnOutcome` is `#[non_exhaustive]`: an outcome this build does
        // not know is not a success it can vouch for.
        _ => ExitCode::from(EXIT_TURN_FAILED),
    }
}

/// One frame as one NDJSON line on stdout.
fn print_frame(event: &ClientEvent) -> color_eyre::Result<()> {
    println!(
        "{}",
        serde_json::to_string(event).map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?
    );
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
        match event {
            roundhouse_proto::ClientEvent::Committed {
                session_id,
                payload,
                ..
            } => {
                dashboard.apply(session_id, *payload);
                dashboard.tick(terminal)?;
            }
            // The daemon only sends this in answer to a `Resume` whose cursor
            // is past the session's head; this loop never resumes, so it
            // means the two sides disagree about the session's history.
            roundhouse_proto::ClientEvent::ResyncRequired { session_id, head } => {
                return Err(color_eyre::eyre::eyre!(
                    "the daemon requires a resync for session {session_id} (head {head:?})"
                ));
            }
            // `TurnFinished` (this loop submits no turns) and `Ack` (no
            // protocol-version negotiation UI exists yet) carry nothing to
            // render. `ClientEvent` is `#[non_exhaustive]` (Phase 0), so this
            // arm also covers any later variant.
            _ => {}
        }
    }
    Ok(())
}
