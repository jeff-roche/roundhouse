//! `round daemon`: locates and runs the real daemon binary.
//!
//! Ruling P10: the frozen §5.2 dependency table lists `roundhouse-cli` as
//! depending on only `proto` and `tui` — deliberately **not**
//! `roundhouse-daemon` — because "`round daemon` is spawned as a separate
//! process/binary, not linked in". So this module's whole job is finding the
//! sibling `round-daemon-internal` binary and running it as a child process,
//! not calling into daemon code directly.
//!
//! Found next to the currently running `round` executable (via
//! [`std::env::current_exe`]), the same way `service_install::resolve_exec_path`
//! resolves the path baked into the installed unit/plist — not via `$PATH`,
//! so a `round` invoked from an arbitrary `$PATH` entry launches the daemon
//! that actually shipped alongside it.
//!
//! Spawned as a real child process rather than `exec`'d in place: replacing
//! the current process image needs `execve`, which is `unsafe` and outside
//! `std`, and this crate is `#![forbid(unsafe_code)]`. A spawn-and-wait,
//! forwarding stdio and exit status, is indistinguishable from `exec` to
//! systemd's `Type=simple` supervision (it only cares that *a* process is
//! running and reports the same exit code either way).

use std::io;
use std::path::PathBuf;

/// The real daemon binary's name, matching `[[bin]] name` in
/// `crates/roundhouse-daemon/Cargo.toml`.
pub const DAEMON_BINARY_NAME: &str = "round-daemon-internal";

/// Resolves the daemon binary's path: the directory containing the
/// currently running `round` executable, joined with
/// [`DAEMON_BINARY_NAME`]. Does not check that the file exists — spawning it
/// surfaces a clear "not found" error on its own.
pub fn daemon_binary_path() -> io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or_else(|| {
        io::Error::other(format!(
            "{} has no parent directory; cannot locate {DAEMON_BINARY_NAME}",
            exe.display()
        ))
    })?;
    Ok(dir.join(DAEMON_BINARY_NAME))
}

/// Runs the daemon binary in the foreground, inheriting this process's
/// stdio, and returns once it exits.
pub async fn run() -> io::Result<std::process::ExitStatus> {
    let path = daemon_binary_path()?;
    tokio::process::Command::new(&path).status().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_binary_path_sits_next_to_the_current_executable() {
        let path = daemon_binary_path().unwrap();
        assert_eq!(path.file_name().unwrap(), DAEMON_BINARY_NAME);
        let current_exe_dir = std::env::current_exe().unwrap();
        let current_exe_dir = current_exe_dir.parent().unwrap();
        assert_eq!(path.parent().unwrap(), current_exe_dir);
    }
}
