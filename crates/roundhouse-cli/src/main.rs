//! The `round` binary: TUI attach, headless/one-shot runs, and `round
//! daemon` (the same binary, invoked as a subprocess — not a Cargo
//! dependency edge; see §5.2's dependency table note on why this crate
//! deliberately doesn't depend on `roundhouse-daemon` despite the table
//! listing that edge).
//!
//! Phase 1 implements the attach path only: connect to the daemon's Unix
//! socket and render every incoming `ServerMessage` through
//! `roundhouse_tui::Dashboard`. Command parsing, headless runs, and session
//! selection are Phase 2+.
#![forbid(unsafe_code)]

use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use roundhouse_tui::Dashboard;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
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
