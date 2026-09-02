//! `round service install`/`round service uninstall`: the OS-liveness half
//! of §8.7's "the daemon owns scheduling; the OS owns liveness" split
//! (Phase 5 audit gap G6). Scheduling Task 6 already built the sleep/wake
//! *detection* half (`PowerEvents`/`run_power_watch`) and the catch-up that
//! makes a restarted daemon self-healing (`compute_catch_up`, wired through
//! `Scheduler::tick`); this module is what actually keeps the daemon
//! restart-on-crash and boot-persistent in the first place, by installing a
//! systemd *user* unit (Linux) or a launchd `LaunchAgent` (macOS).
//!
//! ## Security posture
//!
//! This writes files into the real user's config directories and decides
//! the absolute path an init system execs on every boot/login, so:
//!
//! - **Per-user only, never root.** Targets are `~/.config/systemd/user`
//!   and `~/Library/LaunchAgents` — never `/etc`, never
//!   `/Library/LaunchDaemons` — and nothing here shells out to `sudo`.
//! - **The exec path is derived from the running executable**
//!   ([`resolve_exec_path`]), canonicalized to resolve any symlink, and
//!   rejected by [`check_exec_path_safe`] if it resolves into a
//!   world-writable directory without the sticky bit. Without this, running
//!   `round service install` once from a shared/temporary directory (a
//!   freshly extracted tarball in `/tmp`, say) would wire a boot-persistent
//!   unit to a path any other local user could later replace with their own
//!   binary.
//! - **Never clobbers.** [`install_to`] refuses to overwrite an existing
//!   unit file unless `force` is set, so a hand-customised unit is never
//!   silently destroyed.
//! - **File permissions.** Every file this module writes is opened with an
//!   explicit `0o644` (owner read/write, group/other read-only) regardless
//!   of the process umask, and the directory this module creates is
//!   `0o700`.
//! - **No shell interpolation.** Unit contents come from substituting a
//!   typed `&Path` into a fixed template string via `str::replace` and
//!   writing the result with `std::fs::File` — there is no shell in this
//!   path, so there is nothing for a hostile path or binary name to inject
//!   into.
//!
//! ## Testability
//!
//! Every function that touches the filesystem takes its target directory as
//! an explicit argument ([`install_to`], [`uninstall_from`]) rather than
//! reading `$HOME` itself, so tests point them at a `tempfile::tempdir()`
//! and never touch the real user's home directory. `install`/`uninstall`
//! are the thin `$HOME`-resolving wrappers `round service install` actually
//! calls; [`install_dir`] is exercised only for its shape (ends in the
//! right OS-specific suffix), never by mutating process-wide environment
//! state from a test.

use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsFamily {
    Linux,
    MacOs,
}

/// Files a Linux install writes, relative to [`install_dir`].
const LINUX_UNIT_FILES: &[&str] = &["roundhouse.service", "roundhouse.socket"];
/// Files a macOS install writes, relative to [`install_dir`].
const MACOS_UNIT_FILES: &[&str] = &["com.roundhouse.daemon.plist"];

/// Renders the systemd *user* unit (§8.7: "ship a systemd user service")
/// with the actual installed binary path substituted in. The committed
/// `packaging/systemd/roundhouse.service` uses `%h/.local/bin/round` as the
/// common-case default; this is what `round service install` writes when
/// the binary lives somewhere else.
pub fn render_systemd_unit(exec_path: &Path) -> String {
    let base = include_str!("../../../../packaging/systemd/roundhouse.service");
    base.replace("%h/.local/bin/round", &exec_path.display().to_string())
}

/// Renders the launchd `LaunchAgent` plist with the actual installed binary
/// path substituted in, mirroring [`render_systemd_unit`].
pub fn render_launchd_plist(exec_path: &Path) -> String {
    let base = include_str!("../../../../packaging/launchd/com.roundhouse.daemon.plist");
    base.replace("/usr/local/bin/round", &exec_path.display().to_string())
}

/// §8.7's clean split ("the OS answers is-the-daemon-running") means the
/// install location follows each OS's own user-service convention, not a
/// Roundhouse-invented path. Reads `$HOME`/`$XDG_CONFIG_HOME` directly
/// rather than pulling in a directories crate for two lookups; see the task
/// report's "Deviations from the plan text" for why.
pub fn install_dir(os: OsFamily) -> PathBuf {
    let home = home_dir();
    match os {
        OsFamily::Linux => {
            let config_home = std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| home.join(".config"));
            config_home.join("systemd").join("user")
        }
        OsFamily::MacOs => home.join("Library").join("LaunchAgents"),
    }
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Errors from resolving the exec path or writing/removing service files.
#[derive(Debug, thiserror::Error)]
pub enum ServiceInstallError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error(
        "refusing to use {path} as the daemon's install path: its directory {dir} is \
         world-writable without the sticky bit, so another local user could replace the \
         binary a boot-persistent unit would keep re-launching; reinstall round to a \
         directory only you can write to (e.g. ~/.local/bin) and retry"
    )]
    UnsafeExecPath { path: PathBuf, dir: PathBuf },
    #[error("{path} already exists; rerun with --force to overwrite")]
    AlreadyExists { path: PathBuf },
}

/// Rejects an exec path that resolves into a world-writable directory
/// without the sticky bit (the same shape `/tmp` deliberately avoids via
/// `+t`). A directory that is merely world-writable lets any other local
/// user delete-and-replace the binary a systemd/launchd unit is configured
/// to keep restarting — the sticky bit is exactly what closes that hole for
/// otherwise-shared directories.
pub fn check_exec_path_safe(path: &Path) -> Result<(), ServiceInstallError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = path.parent().unwrap_or(Path::new("/"));
        let meta = std::fs::metadata(dir)?;
        let mode = meta.permissions().mode();
        let world_writable = mode & 0o002 != 0;
        let sticky = mode & 0o1000 != 0;
        if world_writable && !sticky {
            return Err(ServiceInstallError::UnsafeExecPath {
                path: path.to_path_buf(),
                dir: dir.to_path_buf(),
            });
        }
    }
    Ok(())
}

/// Resolves the path to embed in the installed unit/plist: the currently
/// running executable, canonicalized (to resolve any symlink to its real,
/// underlying file) and checked by [`check_exec_path_safe`].
pub fn resolve_exec_path() -> Result<PathBuf, ServiceInstallError> {
    let raw = std::env::current_exe()?;
    let real = std::fs::canonicalize(&raw)?;
    check_exec_path_safe(&real)?;
    Ok(real)
}

/// Opens `path` for writing with `0o644` permissions and no group/world
/// write bit, refusing to overwrite an existing file unless `force` is set.
/// Using `create_new` for the non-`force` case makes the existence check
/// atomic (`O_EXCL`) rather than a separate `exists()` call racing another
/// writer.
fn write_unit_file(path: &Path, contents: &str, force: bool) -> Result<(), ServiceInstallError> {
    use std::io::Write as _;

    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }

    let file = match options.open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            return Err(ServiceInstallError::AlreadyExists {
                path: path.to_path_buf(),
            });
        }
        Err(err) => return Err(err.into()),
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
    }

    (&file).write_all(contents.as_bytes())?;
    Ok(())
}

/// The seam `install` wraps: writes the rendered unit(s) for `os` into
/// `dir`, creating `dir` (mode `0o700`) if needed. Returns the path of the
/// primary unit file (the `.service` on Linux, the `.plist` on macOS).
///
/// Pre-checks that no target file already exists before writing any of them
/// when `force` is `false`, so a Linux install that would clobber the
/// `.socket` but not the `.service` fails cleanly instead of leaving a
/// half-written pair.
pub fn install_to(
    dir: &Path,
    os: OsFamily,
    exec_path: &Path,
    force: bool,
) -> Result<PathBuf, ServiceInstallError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        match std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
        {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(err.into()),
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)?;
    }

    let targets: Vec<(PathBuf, String)> = match os {
        OsFamily::Linux => vec![
            (
                dir.join(LINUX_UNIT_FILES[0]),
                render_systemd_unit(exec_path),
            ),
            (
                dir.join(LINUX_UNIT_FILES[1]),
                include_str!("../../../../packaging/systemd/roundhouse.socket").to_string(),
            ),
        ],
        OsFamily::MacOs => vec![(
            dir.join(MACOS_UNIT_FILES[0]),
            render_launchd_plist(exec_path),
        )],
    };

    if !force {
        for (path, _) in &targets {
            if path.exists() {
                return Err(ServiceInstallError::AlreadyExists { path: path.clone() });
            }
        }
    }

    for (path, contents) in &targets {
        write_unit_file(path, contents, force)?;
    }

    Ok(targets[0].0.clone())
}

/// Removes the unit/plist files for `os` from `dir`, tolerating any that
/// are already absent (uninstalling twice is not an error).
pub fn uninstall_from(dir: &Path, os: OsFamily) -> io::Result<()> {
    let files: &[&str] = match os {
        OsFamily::Linux => LINUX_UNIT_FILES,
        OsFamily::MacOs => MACOS_UNIT_FILES,
    };
    for name in files {
        match std::fs::remove_file(dir.join(name)) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

/// `round service install`: writes the rendered unit/plist for this OS into
/// its real per-user service directory ([`install_dir`]). Enabling/starting
/// the unit (`systemctl --user enable --now` / `launchctl load`) is left to
/// the caller printing instructions rather than done here — see the task
/// report's "Deviations from the plan text" for why: this function must stay
/// callable from an ordinary `cargo test` run with no systemd/launchd
/// present, which shelling out to either would violate.
pub fn install(
    os: OsFamily,
    exec_path: &Path,
    force: bool,
) -> Result<PathBuf, ServiceInstallError> {
    install_to(&install_dir(os), os, exec_path, force)
}

/// `round service uninstall`: removes the unit/plist for this OS from its
/// real per-user service directory.
pub fn uninstall(os: OsFamily) -> io::Result<()> {
    uninstall_from(&install_dir(os), os)
}
