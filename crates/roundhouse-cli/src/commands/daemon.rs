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
//! [`std::env::current_exe`], canonicalized) — not via `$PATH`, so a `round`
//! invoked from an arbitrary `$PATH` entry launches the daemon that actually
//! shipped alongside it. This canonicalizes the same first step
//! `service_install::resolve_exec_path` does, but — unlike that function —
//! does *not* additionally run `check_exec_path_safe`: that check exists to
//! protect a *boot-persistent installed unit* from being pointed at a path
//! someone else could later replace, which doesn't apply here. This
//! function's result is used immediately, in the same process invocation
//! that computed it, not baked into a long-lived artifact another user gets
//! a window to tamper with.
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
/// currently running `round` executable (canonicalized, to resolve any
/// symlink to the real underlying file), joined with [`DAEMON_BINARY_NAME`].
/// Pure path computation — does not check that the file exists; [`run`]
/// does that separately, before spawning.
pub fn daemon_binary_path() -> io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let exe = std::fs::canonicalize(&exe)?;
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
///
/// Checks the resolved sibling binary exists *before* spawning, so a
/// missing `round-daemon-internal` (an incomplete install, say) produces a
/// clear error naming the exact path that was searched, rather than a bare
/// `ENOENT` with no path in it.
pub async fn run(workspaces: &[String]) -> io::Result<std::process::ExitStatus> {
    let path = daemon_binary_path()?;
    if !path.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "{} not found; expected the real daemon binary next to this executable — \
                 is roundhouse installed correctly?",
                path.display()
            ),
        ));
    }
    let mut command = tokio::process::Command::new(&path);
    for workspace in workspaces {
        command.arg("--workspace").arg(workspace);
    }
    command.status().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_binary_path_sits_next_to_the_current_executable() {
        let path = daemon_binary_path().unwrap();
        assert_eq!(path.file_name().unwrap(), DAEMON_BINARY_NAME);
        let current_exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        assert_eq!(path.parent().unwrap(), current_exe.parent().unwrap());
    }
}
