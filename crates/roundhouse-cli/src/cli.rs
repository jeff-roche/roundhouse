//! The `round` subcommand scaffold (Task A8/G6, ruling P11; extended by
//! Phase 7, Task 7).
//!
//! Before Task A8/G6, `roundhouse-cli/src/main.rs` had no argument parsing at
//! all — running `round` with any arguments did whatever the TUI-attach
//! default did, silently ignoring them. That task built the first
//! `clap`-based surface for the binary: `round daemon` and `round service
//! install`/`round service uninstall`. Phase 7, Task 7 extends this same
//! enum with the session-selection/headless subcommands lane W1's exit
//! criterion names — `round attach`, `round create`, `round run` — rather
//! than building a second parser: **extend the existing `Command` enum; do
//! not create a parser.**
//!
//! Running `round` with no subcommand keeps the Phase 1 behavior (attach the
//! TUI to the daemon's socket, minting a fresh session named `"default"`)
//! unchanged — equivalent to `round create` with no `--workspace` override.
//!
//! Kept as pure data + `clap` derive, with no I/O, so parsing itself is unit
//! testable without touching a filesystem or spawning a process. Session-id
//! parsing (`--session`) is the one exception with real logic worth testing
//! directly — see [`parse_session_id`].

use clap::{Parser, Subcommand};
use roundhouse_tui::SessionId;

/// The workspace name every subcommand that mints a new session defaults to
/// when `--workspace` is omitted — matches the literal Phase 1 used for the
/// no-subcommand default path before this task existed.
pub const DEFAULT_WORKSPACE_NAME: &str = "default";

#[derive(Debug, Parser)]
#[command(name = "round", about = "Roundhouse: a task-oriented agent harness", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the daemon in the foreground.
    ///
    /// Locates and runs the real daemon binary (`round-daemon-internal`) as
    /// a child process rather than linking `roundhouse-daemon` into this
    /// binary — see `commands::daemon` and ruling P10. This is what a
    /// systemd `Type=simple` unit or launchd `LaunchAgent` installed by
    /// `round service install` actually execs.
    Daemon,
    /// Manage the OS-level service that keeps the daemon alive: a systemd
    /// user unit on Linux, a launchd `LaunchAgent` on macOS.
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Attach the TUI to an already-running session.
    ///
    /// **Read-only, by design, once the creating connection has
    /// disconnected (rulings W1-R37/W1-R52):** the daemon honors
    /// post-handshake requests only from the connection that ran
    /// `CreateSession` — an attached connection always *receives* the
    /// session's event stream, but a fresh `round attach` after the
    /// original `round create`/`round run` has exited is a VIEWER, not a
    /// controller. This is deliberate and fail-closed, not a bug: see
    /// `roundhouse-daemon`'s `socket_server::drive_session` for the full
    /// rationale.
    Attach {
        /// The session to attach to, as printed by `round create`/`round run`.
        #[arg(long, value_parser = parse_session_id)]
        session: SessionId,
    },
    /// Create a new session and attach the TUI to it interactively — the
    /// explicit, nameable form of the no-subcommand default path.
    Create {
        /// The workspace the new session belongs to.
        #[arg(long, default_value = DEFAULT_WORKSPACE_NAME)]
        workspace: String,
    },
    /// Create a new session and stream its events to stdout, one JSON line
    /// per event, with no TUI — for scripting and CI, where there is no
    /// terminal to draw a dashboard into. Exits once the daemon closes the
    /// connection (the session itself keeps running independently — ruling
    /// W1-R51: a session's actor lifetime is not tied to any one attached
    /// connection).
    Run {
        /// The workspace the new session belongs to.
        #[arg(long, default_value = DEFAULT_WORKSPACE_NAME)]
        workspace: String,
    },
}

/// `clap` value-parser for `--session`: a `SessionId` is a UUIDv4 on the
/// wire and on the command line — this is the one place that string gets
/// parsed, so a malformed value is rejected by `clap` itself (a clear
/// "invalid value" error naming the bad argument) rather than surfacing
/// later as a confusing daemon-side "unknown session."
fn parse_session_id(raw: &str) -> Result<SessionId, String> {
    uuid::Uuid::parse_str(raw)
        .map(SessionId::from_uuid)
        .map_err(|err| format!("not a valid session id (expected a UUID): {err}"))
}

#[derive(Debug, Subcommand)]
pub enum ServiceAction {
    /// Write the unit/plist for this OS into the per-user service
    /// directory, naming the currently installed `round` binary.
    Install {
        /// Overwrite an existing unit file instead of refusing.
        #[arg(long)]
        force: bool,
    },
    /// Remove the previously installed unit/plist for this OS.
    Uninstall,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_arguments_parses_to_no_subcommand() {
        let cli = Cli::parse_from(["round"]);
        assert!(cli.command.is_none());
    }

    #[test]
    fn daemon_parses() {
        let cli = Cli::parse_from(["round", "daemon"]);
        assert!(matches!(cli.command, Some(Command::Daemon)));
    }

    #[test]
    fn service_install_parses_with_and_without_force() {
        let cli = Cli::parse_from(["round", "service", "install"]);
        match cli.command {
            Some(Command::Service {
                action: ServiceAction::Install { force },
            }) => assert!(!force),
            other => panic!("expected Service{{Install}}, got {other:?}"),
        }

        let cli = Cli::parse_from(["round", "service", "install", "--force"]);
        match cli.command {
            Some(Command::Service {
                action: ServiceAction::Install { force },
            }) => assert!(force),
            other => panic!("expected Service{{Install}}, got {other:?}"),
        }
    }

    #[test]
    fn service_uninstall_parses() {
        let cli = Cli::parse_from(["round", "service", "uninstall"]);
        assert!(matches!(
            cli.command,
            Some(Command::Service {
                action: ServiceAction::Uninstall
            })
        ));
    }

    #[test]
    fn unknown_subcommand_is_rejected() {
        assert!(Cli::try_parse_from(["round", "bogus"]).is_err());
    }

    #[test]
    fn attach_parses_a_valid_session_id() {
        let uuid = uuid::Uuid::new_v4();
        let cli = Cli::parse_from(["round", "attach", "--session", &uuid.to_string()]);
        match cli.command {
            Some(Command::Attach { session }) => assert_eq!(session.as_uuid(), uuid),
            other => panic!("expected Attach, got {other:?}"),
        }
    }

    #[test]
    fn attach_rejects_a_malformed_session_id() {
        assert!(Cli::try_parse_from(["round", "attach", "--session", "not-a-uuid"]).is_err());
    }

    #[test]
    fn attach_requires_session() {
        assert!(Cli::try_parse_from(["round", "attach"]).is_err());
    }

    #[test]
    fn create_defaults_workspace_name() {
        let cli = Cli::parse_from(["round", "create"]);
        match cli.command {
            Some(Command::Create { workspace }) => assert_eq!(workspace, DEFAULT_WORKSPACE_NAME),
            other => panic!("expected Create, got {other:?}"),
        }
    }

    #[test]
    fn create_accepts_an_explicit_workspace_name() {
        let cli = Cli::parse_from(["round", "create", "--workspace", "my-project"]);
        match cli.command {
            Some(Command::Create { workspace }) => assert_eq!(workspace, "my-project"),
            other => panic!("expected Create, got {other:?}"),
        }
    }

    #[test]
    fn run_defaults_workspace_name() {
        let cli = Cli::parse_from(["round", "run"]);
        match cli.command {
            Some(Command::Run { workspace }) => assert_eq!(workspace, DEFAULT_WORKSPACE_NAME),
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn run_accepts_an_explicit_workspace_name() {
        let cli = Cli::parse_from(["round", "run", "--workspace", "ci-job"]);
        match cli.command {
            Some(Command::Run { workspace }) => assert_eq!(workspace, "ci-job"),
            other => panic!("expected Run, got {other:?}"),
        }
    }
}
