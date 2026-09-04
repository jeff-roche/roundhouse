//! The `round` subcommand scaffold (Task A8/G6, ruling P11).
//!
//! Before this task `roundhouse-cli/src/main.rs` had no argument parsing at
//! all — running `round` with any arguments did whatever the TUI-attach
//! default did, silently ignoring them. This module is the first
//! `clap`-based surface for the binary: **at minimum** `round daemon` and
//! `round service install`/`round service uninstall`, per P11. Later tasks
//! (session selection, headless runs, sub-agent commands, ...) add variants
//! to `Command` here; they do not replace this scaffold.
//!
//! Running `round` with no subcommand keeps today's behavior (attach the TUI
//! to the daemon's socket) so this task does not change the existing
//! Phase 1 exit-criterion path.
//!
//! Kept as pure data + `clap` derive, with no I/O, so parsing itself is unit
//! testable without touching a filesystem or spawning a process.

use clap::{Parser, Subcommand};

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
}
