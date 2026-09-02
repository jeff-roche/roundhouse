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
//!   rejected by [`check_exec_path_safe`] if *any ancestor directory* — not
//!   just its immediate parent — is group- or world-writable without the
//!   sticky bit. Without the ancestor walk, `/srv/shared/bin/round` would
//!   pass with `bin/` at a safe `0755` even though `/srv/shared` itself is a
//!   shared, writable-by-everyone directory: any other member could replace
//!   `bin/` wholesale. Without the group-write check, a `0775` directory
//!   owned by a shared group (common on build hosts / NFS trees) would pass
//!   too. Either gap lets a boot-persistent unit end up pointed at a path
//!   another local user can later replace with their own binary.
//! - **The exec path is validated before it is ever embedded in a rendered
//!   unit/plist** ([`resolve_exec_path`] and [`install_to`] both call
//!   [`validate_exec_path_for_render`]): non-UTF-8 paths are rejected
//!   outright (a lossy `.display()`/`.to_string_lossy()` substitution could
//!   silently swap in a *different* path than the one that was
//!   safety-checked), and so is any path containing a raw newline, carriage
//!   return, NUL, or other control character — both the systemd unit format
//!   and plist XML are line/structure-based, and no amount of render-time
//!   escaping can make a literal embedded line break safe inside either.
//! - **Escaped at render.** `render_systemd_unit` doubles every `%`
//!   (systemd's specifier-expansion escape), backslash-escapes `"`/`\`, and
//!   wraps the whole value in double quotes, so systemd's own
//!   whitespace-splitting treats the path as a single `argv[0]` even when it
//!   contains a space — `/tmp/rh build/round` would otherwise parse as
//!   executable `/tmp/rh` with argv `build/round daemon`.
//!   `render_launchd_plist` XML-escapes `&`/`<`/`>`, so a path containing
//!   `</string>` can't close the `ProgramArguments` array and inject
//!   additional plist keys.
//! - **Never clobbers.** [`install_to`] refuses to overwrite an existing
//!   unit file unless `force` is set, so a hand-customised unit is never
//!   silently destroyed.
//! - **File permissions.** Every file this module writes is created with
//!   `0o644` (owner read/write, group/other read-only) passed directly to
//!   the creating `open(2)` call (`OpenOptionsExt::mode`), not applied via a
//!   separate `chmod` afterwards — so there is no window in which the file
//!   briefly exists with a more permissive mode under a permissive umask.
//!   The directory [`install_to`] creates is `0o700`; if the directory
//!   already existed with a group- or world-writable mode, `install_to`
//!   refuses rather than writing into it (a writable *directory* lets
//!   another user replace the unit file wholesale regardless of the file's
//!   own mode).
//! - **`$HOME`/`$XDG_CONFIG_HOME` must be absolute.** [`install`]/
//!   [`uninstall`] hard-error if `$HOME` is unset or relative, rather than
//!   falling back to the process's current directory — matching the
//!   precedent in `roundhouse_tui::paths::default_runtime_dir`, which
//!   rejects a relative `$XDG_RUNTIME_DIR` for the same reason. A relative
//!   `$XDG_CONFIG_HOME` is likewise ignored per the XDG base-directory
//!   spec, falling back to `$HOME/.config`.
//! - **No socket-activation unit is shipped.** See the comment in
//!   `packaging/systemd/roundhouse.service` and this module's `install_to`:
//!   the daemon does not implement `sd_listen_fds`/`LISTEN_FDS`, so a
//!   `.socket` unit here would bind a socket nobody accepts on and hang
//!   whoever connects to it.
//!
//! ## Testability
//!
//! Every function that touches the filesystem takes its target directory as
//! an explicit argument ([`install_to`], [`uninstall_from`]) rather than
//! reading `$HOME` itself, so tests point them at a `tempfile::tempdir()`
//! and never touch the real user's home directory. `install`/`uninstall`
//! are the thin `$HOME`-resolving wrappers `round service install` actually
//! calls. The `$HOME`/`$XDG_CONFIG_HOME` policy itself ([`build_install_dir`],
//! [`require_home`]) is factored out as pure functions taking explicit
//! `Option<PathBuf>` arguments, so it is unit-tested directly rather than by
//! mutating process-wide environment variables (which would race Rust's
//! default parallel test execution). [`install_dir`] is exercised only for
//! its shape (ends in the right OS-specific suffix) against whatever the
//! real environment happens to be.

use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsFamily {
    Linux,
    MacOs,
}

/// Files a Linux install writes, relative to [`install_dir`].
///
/// Just the service unit — no `.socket` unit. See the module doc's "No
/// socket-activation unit is shipped" note: the daemon binds
/// `roundhouse_tui::paths::default_socket_path()`
/// (`$XDG_RUNTIME_DIR/roundhouse-<user>/round.sock`), not the
/// `%t/roundhouse/daemon.sock` a `.socket` unit would listen on, and never
/// reads `LISTEN_FDS`, so a committed `.socket` unit would be a dead
/// artefact that silently does nothing and hangs any real socket-activation
/// client.
const LINUX_UNIT_FILES: &[&str] = &["roundhouse.service"];
/// Files a macOS install writes, relative to [`install_dir`].
const MACOS_UNIT_FILES: &[&str] = &["com.roundhouse.daemon.plist"];

/// Renders the systemd *user* unit (§8.7: "ship a systemd user service")
/// with the actual installed binary path substituted in. The committed
/// `packaging/systemd/roundhouse.service` uses `%h/.local/bin/round` as the
/// common-case default; this is what `round service install` writes when
/// the binary lives somewhere else.
///
/// The substituted value is quoted and escaped by
/// [`quote_systemd_exec_path`] — see the module doc's "Escaped at render"
/// note. This function has no way to *reject* an unsafe `exec_path` (its
/// signature returns a plain `String`), so a non-UTF-8 path falls back to a
/// lossy conversion here; the real install path never reaches this function
/// with such a path because both [`resolve_exec_path`] and [`install_to`]
/// call [`validate_exec_path_for_render`] first and refuse outright.
pub fn render_systemd_unit(exec_path: &Path) -> String {
    let base = include_str!("../../../../packaging/systemd/roundhouse.service");
    base.replace("%h/.local/bin/round", &quote_systemd_exec_path(exec_path))
}

/// Renders the launchd `LaunchAgent` plist with the actual installed binary
/// path substituted in, mirroring [`render_systemd_unit`]. Also substitutes
/// the log paths' `~` with an absolute directory under `$HOME`: launchd does
/// not expand `~` itself, so `StandardOutPath`/`StandardErrorPath` left as
/// `~/Library/Logs/...` would silently never be written to.
pub fn render_launchd_plist(exec_path: &Path) -> String {
    let base = include_str!("../../../../packaging/launchd/com.roundhouse.daemon.plist");
    let escaped_exec_path = escape_xml_text(&exec_path.to_string_lossy());
    let mut rendered = base.replace("/usr/local/bin/round", &escaped_exec_path);

    let log_dir = best_effort_home_dir()
        .join("Library")
        .join("Logs")
        .join("roundhouse");
    rendered = rendered.replace(
        "~/Library/Logs/roundhouse/daemon.log",
        &escape_xml_text(&log_dir.join("daemon.log").display().to_string()),
    );
    rendered = rendered.replace(
        "~/Library/Logs/roundhouse/daemon.err",
        &escape_xml_text(&log_dir.join("daemon.err").display().to_string()),
    );
    rendered
}

/// Doubles every `%` (systemd's specifier-expansion escape character),
/// backslash-escapes `"` and `\`, then wraps the result in double quotes so
/// systemd's own `ExecStart=` word-splitting treats the whole value as one
/// `argv[0]` regardless of embedded spaces.
///
/// Uses a lossy string conversion rather than rejecting non-UTF-8 input —
/// this is a pure rendering helper with no `Result` in its signature; the
/// reject-non-UTF-8 behavior lives in [`validate_exec_path_for_render`],
/// which every real writer of a unit file calls first.
fn quote_systemd_exec_path(path: &Path) -> String {
    let raw = path.to_string_lossy();
    let percent_doubled = raw.replace('%', "%%");
    let mut quoted = String::with_capacity(percent_doubled.len() + 2);
    quoted.push('"');
    for ch in percent_doubled.chars() {
        if ch == '"' || ch == '\\' {
            quoted.push('\\');
        }
        quoted.push(ch);
    }
    quoted.push('"');
    quoted
}

/// Escapes the three characters that are structurally significant in XML
/// text content. `>` does not strictly need escaping outside of a `]]>`
/// sequence, but escaping it unconditionally is harmless and cheaper to
/// reason about than special-casing that sequence.
fn escape_xml_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(ch),
        }
    }
    out
}

/// §8.7's clean split ("the OS answers is-the-daemon-running") means the
/// install location follows each OS's own user-service convention, not a
/// Roundhouse-invented path. Reads `$HOME`/`$XDG_CONFIG_HOME` directly
/// rather than pulling in a directories crate for two lookups; see the task
/// report's "Deviations from the plan text" for why.
///
/// Best-effort: falls back to `.` if `$HOME` is unset, because this
/// function's signature (pinned by this task's brief) returns a plain
/// `PathBuf` with no way to report an error. [`install`]/[`uninstall`] — the
/// functions that actually touch the filesystem — use
/// [`resolved_install_dir`] instead, which hard-errors on an unset or
/// relative `$HOME` rather than silently resolving into the process's
/// current directory.
pub fn install_dir(os: OsFamily) -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| PathBuf::from("."));
    let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    build_install_dir(os, &home, xdg_config_home.as_deref())
}

/// Shared path-assembly logic between the best-effort [`install_dir`] and
/// the hard-erroring [`resolved_install_dir`] — the two differ only in how
/// strictly they resolve `$HOME`/`$XDG_CONFIG_HOME` (see [`require_home`]),
/// not in the resulting directory shape. Pure and unit-tested directly with
/// explicit arguments, rather than through the environment.
fn build_install_dir(os: OsFamily, home: &Path, xdg_config_home: Option<&Path>) -> PathBuf {
    match os {
        OsFamily::Linux => {
            // A relative `$XDG_CONFIG_HOME` is invalid per the XDG base
            // directory spec and must be ignored, not resolved against the
            // process's cwd — same rule (and the same `is_absolute` filter,
            // which subsumes the empty-string case) as
            // `roundhouse_tui::paths::default_runtime_dir` applies to
            // `$XDG_RUNTIME_DIR`.
            let config_home = xdg_config_home
                .filter(|p| p.is_absolute())
                .map(Path::to_path_buf)
                .unwrap_or_else(|| home.join(".config"));
            config_home.join("systemd").join("user")
        }
        OsFamily::MacOs => home.join("Library").join("LaunchAgents"),
    }
}

/// [`install_dir`]'s hard-erroring counterpart, used by [`install`]/
/// [`uninstall`]: refuses to guess a fallback when `$HOME` is unset or
/// relative rather than risk writing a boot-persistent unit under the
/// process's current directory.
fn resolved_install_dir(os: OsFamily) -> Result<PathBuf, ServiceInstallError> {
    let home = require_home(std::env::var_os("HOME").map(PathBuf::from))?;
    let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    Ok(build_install_dir(os, &home, xdg_config_home.as_deref()))
}

/// Accepts `home` only if it is `Some` and absolute; otherwise a hard
/// [`ServiceInstallError::HomeNotSet`]. A pure function of its argument (not
/// of the environment) so it is unit-tested directly.
fn require_home(home: Option<PathBuf>) -> Result<PathBuf, ServiceInstallError> {
    home.filter(|p| p.is_absolute())
        .ok_or(ServiceInstallError::HomeNotSet)
}

/// Best-effort `$HOME`, used only by [`render_launchd_plist`]'s log-path
/// substitution — a rendering nicety, not a decision about where to write a
/// boot-persistent unit, so falling back to `.` here (rather than erroring)
/// is acceptable: by the time a real install reaches this function,
/// [`resolved_install_dir`] has already hard-errored on an unset `$HOME`.
fn best_effort_home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Errors from resolving the exec path or writing/removing service files.
#[derive(Debug, thiserror::Error)]
pub enum ServiceInstallError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error(
        "refusing to use {path} as the daemon's install path: its directory {dir} is \
         group- or world-writable without the sticky bit, so another local user could replace \
         the binary (or the directory entry itself) that a boot-persistent unit would keep \
         re-launching; reinstall round to a directory only you (or a trusted group) can write \
         to and retry"
    )]
    UnsafeExecPath { path: PathBuf, dir: PathBuf },
    #[error("refusing to use {path:?} as the daemon's install path: it {reason}")]
    InvalidExecPath { path: PathBuf, reason: String },
    #[error("{path} already exists; rerun with --force to overwrite")]
    AlreadyExists { path: PathBuf },
    #[error(
        "refusing to write into {dir}: it already exists and is group- or world-writable, \
         which would let another local user replace an installed unit file regardless of the \
         file's own permissions; fix its mode (chmod 700) and retry"
    )]
    UnsafeInstallDir { dir: PathBuf },
    #[error(
        "$HOME is not set (or is not an absolute path); cannot determine the per-user service \
         install directory"
    )]
    HomeNotSet,
}

/// Rejects an exec path unsafe to embed literally in a rendered unit/plist:
/// non-UTF-8 (whose lossy `.display()`/`.to_string_lossy()` substitution in
/// [`render_systemd_unit`]/[`render_launchd_plist`] could silently swap in a
/// *different* path than the one [`check_exec_path_safe`] verified), or
/// containing a raw newline, carriage return, NUL, or other control
/// character. Both the systemd unit format and plist XML are
/// line/structure-based: a literal embedded line break splits a unit file
/// into a second directive (or a plist into invalid/injected XML) no matter
/// how the surrounding value is quoted or escaped, so this has to be an
/// outright rejection rather than something [`quote_systemd_exec_path`]/
/// [`escape_xml_text`] can neutralize at render time.
pub fn validate_exec_path_for_render(path: &Path) -> Result<(), ServiceInstallError> {
    let s = path
        .to_str()
        .ok_or_else(|| ServiceInstallError::InvalidExecPath {
            path: path.to_path_buf(),
            reason: "is not valid UTF-8".to_string(),
        })?;
    if s.chars().any(|c| c.is_control()) {
        return Err(ServiceInstallError::InvalidExecPath {
            path: path.to_path_buf(),
            reason: "contains a control character (e.g. a newline), which cannot be safely \
                     embedded in a unit file or plist regardless of quoting"
                .to_string(),
        });
    }
    Ok(())
}

/// Rejects an exec path that resolves under a group- or world-writable
/// directory without the sticky bit (the same shape `/tmp` deliberately
/// avoids via `+t`), walking *every* ancestor directory up to the
/// filesystem root — not just the immediate parent.
///
/// The ancestor walk matters: `/srv/shared/bin/round` would pass a
/// parent-only check if `bin/` itself is a safe `0755`, even though
/// `/srv/shared` is a shared, writable directory anyone could replace `bin/`
/// wholesale inside. Checking the group-write bit (`0o020`), not just
/// world-write (`0o002`), matters too: a `0775` directory owned by a shared
/// group — common on build hosts and NFS-mounted trees — is exactly as
/// replaceable by any group member as a `0777` one is by any user.
///
/// Deliberately does *not* check ownership (uid): the ancestor walk plus the
/// group/world-write check already closes both concrete exploit shapes
/// without it, and a uid comparison needs either a new capability or
/// `/proc` parsing (`roundhouse-daemon`'s `check_owned_by_current_user`
/// pattern), neither of which this narrower check needs to take on.
pub fn check_exec_path_safe(path: &Path) -> Result<(), ServiceInstallError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut dir = path.parent();
        while let Some(d) = dir {
            let meta = std::fs::metadata(d)?;
            let mode = meta.permissions().mode();
            let group_or_world_writable = mode & 0o022 != 0;
            let sticky = mode & 0o1000 != 0;
            if group_or_world_writable && !sticky {
                return Err(ServiceInstallError::UnsafeExecPath {
                    path: path.to_path_buf(),
                    dir: d.to_path_buf(),
                });
            }
            dir = d.parent();
        }
    }
    Ok(())
}

/// Resolves the path to embed in the installed unit/plist: the currently
/// running executable, canonicalized (to resolve any symlink to its real,
/// underlying file), checked by [`validate_exec_path_for_render`], and
/// checked by [`check_exec_path_safe`].
pub fn resolve_exec_path() -> Result<PathBuf, ServiceInstallError> {
    let raw = std::env::current_exe()?;
    let real = std::fs::canonicalize(&raw)?;
    validate_exec_path_for_render(&real)?;
    check_exec_path_safe(&real)?;
    Ok(real)
}

/// Creates `path` with `0o644` permissions set *at creation* (via
/// `OpenOptionsExt::mode`, not a separate `set_permissions` call
/// afterwards, so there is no window in which the file briefly exists with
/// whatever the process umask would otherwise allow), refusing to overwrite
/// an existing file unless `force` is set. Using `create_new` for the
/// non-`force` case makes the existence check atomic (`O_EXCL`) rather than
/// a separate `exists()` call racing another writer.
fn write_unit_file(path: &Path, contents: &str, force: bool) -> Result<(), ServiceInstallError> {
    use std::io::Write as _;

    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }

    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            return Err(ServiceInstallError::AlreadyExists {
                path: path.to_path_buf(),
            });
        }
        Err(err) => return Err(err.into()),
    };

    file.write_all(contents.as_bytes())?;
    Ok(())
}

/// The seam `install` wraps: writes the rendered unit(s) for `os` into
/// `dir`, creating `dir` (mode `0o700`) if needed. Returns the path of the
/// primary unit file (the `.service` on Linux, the `.plist` on macOS).
///
/// Pre-checks that no target file already exists before writing any of them
/// when `force` is `false`, so an install that would clobber one of several
/// target files but not another fails cleanly instead of leaving a
/// half-written set. Also pre-checks that `dir`, if it already existed
/// before this call, isn't itself group- or world-writable — a writable
/// *directory* lets another user replace an installed unit file wholesale
/// regardless of the file's own `0o644` mode.
pub fn install_to(
    dir: &Path,
    os: OsFamily,
    exec_path: &Path,
    force: bool,
) -> Result<PathBuf, ServiceInstallError> {
    validate_exec_path_for_render(exec_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        // Recursive `create` does not error when `dir` already exists (it
        // only creates what's missing), so the safety of a pre-existing
        // directory has to be checked separately, below — it is not
        // guaranteed to be the `0o700` this creates a fresh directory with.
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        let mode = std::fs::metadata(dir)?.permissions().mode();
        if mode & 0o022 != 0 {
            return Err(ServiceInstallError::UnsafeInstallDir {
                dir: dir.to_path_buf(),
            });
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)?;
    }

    let targets: Vec<(PathBuf, String)> = match os {
        OsFamily::Linux => vec![(
            dir.join(LINUX_UNIT_FILES[0]),
            render_systemd_unit(exec_path),
        )],
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
/// its real per-user service directory ([`resolved_install_dir`], which
/// hard-errors on an unset/relative `$HOME` rather than [`install_dir`]'s
/// best-effort fallback). Enabling/starting the unit (`systemctl --user
/// enable --now` / `launchctl load`) is left to the caller printing
/// instructions rather than done here — see the task report's "Deviations
/// from the plan text" for why: this function must stay callable from an
/// ordinary `cargo test` run with no systemd/launchd present, which
/// shelling out to either would violate.
pub fn install(
    os: OsFamily,
    exec_path: &Path,
    force: bool,
) -> Result<PathBuf, ServiceInstallError> {
    install_to(&resolved_install_dir(os)?, os, exec_path, force)
}

/// `round service uninstall`: removes the unit/plist for this OS from its
/// real per-user service directory.
pub fn uninstall(os: OsFamily) -> Result<(), ServiceInstallError> {
    uninstall_from(&resolved_install_dir(os)?, os)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_install_dir_uses_xdg_config_home_when_absolute() {
        let dir = build_install_dir(
            OsFamily::Linux,
            Path::new("/home/u"),
            Some(Path::new("/custom/config")),
        );
        assert_eq!(dir, Path::new("/custom/config/systemd/user"));
    }

    /// The bug both the code and security reviews caught: a relative
    /// `$XDG_CONFIG_HOME` must be ignored (XDG base-dir spec), not resolved
    /// against the process's current directory.
    #[test]
    fn build_install_dir_ignores_a_relative_xdg_config_home() {
        let dir = build_install_dir(
            OsFamily::Linux,
            Path::new("/home/u"),
            Some(Path::new("relative/config")),
        );
        assert_eq!(dir, Path::new("/home/u/.config/systemd/user"));
    }

    #[test]
    fn build_install_dir_falls_back_to_home_dot_config() {
        let dir = build_install_dir(OsFamily::Linux, Path::new("/home/u"), None);
        assert_eq!(dir, Path::new("/home/u/.config/systemd/user"));
    }

    #[test]
    fn build_install_dir_macos_uses_library_launch_agents() {
        let dir = build_install_dir(OsFamily::MacOs, Path::new("/Users/u"), None);
        assert_eq!(dir, Path::new("/Users/u/Library/LaunchAgents"));
    }

    #[test]
    fn require_home_rejects_unset() {
        assert!(matches!(
            require_home(None),
            Err(ServiceInstallError::HomeNotSet)
        ));
    }

    #[test]
    fn require_home_rejects_relative() {
        assert!(matches!(
            require_home(Some(PathBuf::from("relative"))),
            Err(ServiceInstallError::HomeNotSet)
        ));
    }

    #[test]
    fn require_home_accepts_absolute() {
        assert_eq!(
            require_home(Some(PathBuf::from("/home/u"))).unwrap(),
            PathBuf::from("/home/u")
        );
    }
}
