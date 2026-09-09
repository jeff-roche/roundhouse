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
//!   checked by [`check_exec_path_safe`], which rejects it if: the exec
//!   *file itself* is group- or world-writable (directly overwritable by
//!   any local user regardless of what its ancestor directories look like);
//!   or *any ancestor directory* — not just its immediate parent — is
//!   group- or world-writable without the sticky bit. Without the ancestor
//!   walk, `/srv/shared/bin/round` would pass with `bin/` at a safe `0755`
//!   even though `/srv/shared` itself is a shared, writable-by-everyone
//!   directory: any other member could replace `bin/` wholesale. Without
//!   the group-write check, a `0775` directory owned by a shared group
//!   (common on build hosts / NFS trees) would pass too. Any of these gaps
//!   lets a boot-persistent unit end up pointed at a path another local
//!   user can replace with their own binary. [`install_to`] applies the
//!   same ancestor walk to the *install directory* for the identical
//!   reason: a shared, writable `$XDG_CONFIG_HOME` grandparent is just as
//!   replaceable as a shared exec-path grandparent.
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
//! - **File permissions, on both the create and `--force` paths.** Every
//!   file this module writes is created with `0o644` passed directly to the
//!   creating `open(2)` call (`OpenOptionsExt::mode`), closing the
//!   permissive-umask window a post-hoc `chmod` would otherwise leave open
//!   on first creation — *and* `write_unit_file` additionally calls
//!   `set_permissions(0o644)` after opening, because `open(2)`'s mode
//!   argument is silently ignored whenever `O_CREAT` doesn't actually
//!   create the file (i.e. exactly the `--force` overwrite path). Without
//!   the second call, `round service install --force` over a unit file that
//!   already existed at a permissive mode (hand-copied under a loose umask,
//!   restored from an archive, synced from another host) would leave it
//!   just as permissive — precisely the moment a user expects the file to
//!   be put right. The directory [`install_to`] creates is `0o700`; if the
//!   directory (or any of its ancestors) already existed group- or
//!   world-writable, `install_to` refuses rather than writing into it (a
//!   writable *directory* lets another user replace the unit file wholesale
//!   regardless of the file's own mode).
//! - **`$HOME`/`$XDG_CONFIG_HOME` must be absolute.** [`install`]/
//!   [`uninstall`] hard-error if `$HOME` is unset or relative, rather than
//!   falling back to the process's current directory — matching the
//!   precedent in `roundhouse_tui::paths::default_runtime_dir`, which
//!   rejects a relative `$XDG_RUNTIME_DIR` for the same reason. A relative
//!   `$XDG_CONFIG_HOME` is likewise ignored per the XDG base-directory
//!   spec, falling back to `$HOME/.config`.
//! - **No socket-activation unit is shipped** (new installs), **and a
//!   leftover one from before this decision is cleaned up** (upgrades). See
//!   the comment in `packaging/systemd/roundhouse.service` and this
//!   module's `install_to`: the daemon does not implement
//!   `sd_listen_fds`/`LISTEN_FDS`, so a `.socket` unit here would bind a
//!   socket nobody accepts on and hang whoever connects to it.
//!   [`uninstall_from`] additionally removes [`LINUX_LEGACY_UNIT_FILES`] —
//!   the `.socket` unit an earlier version of this installer wrote — so
//!   upgrading and then uninstalling doesn't orphan an enabled, still-loaded
//!   socket unit that nothing installed by the *current* version would ever
//!   clean up.
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
//! default parallel test execution). [`install_dir_unchecked`] is exercised
//! only for its shape (ends in the right OS-specific suffix) against
//! whatever the real environment happens to be.

use std::collections::HashSet;
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
/// Files an earlier version of this installer wrote for Linux that
/// [`install_to`] no longer writes, but [`uninstall_from`] must still remove
/// — fix round 2 (code review): shrinking [`LINUX_UNIT_FILES`] correctly
/// stopped *writing* `roundhouse.socket`, but it also stopped *removing* it,
/// so anyone who installed the previous version and then upgraded and ran
/// `round service uninstall` would be left with an enabled, still-loaded
/// socket unit nobody accepts on — exactly the client-hang its removal was
/// meant to prevent, now orphaned and unreachable by the tool that created
/// it.
const LINUX_LEGACY_UNIT_FILES: &[&str] = &["roundhouse.socket"];
const PROTECTED_SYSTEM_ROOTS: &[&str] = &[
    "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/run", "/sbin", "/sys", "/tmp",
    "/usr", "/var", "/home",
];

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
/// Renders the systemd unit with the workspace registrations needed to boot a
/// fresh daemon after volatile runtime state has been recreated.
pub fn render_systemd_unit(
    exec_path: &Path,
    workspaces: &[String],
) -> Result<String, ServiceInstallError> {
    validate_exec_path_for_render(exec_path)?;
    validate_workspace_arguments(workspaces)?;
    validate_daemon_protected_workspace_paths(workspaces, exec_path)?;
    let base = include_str!("../../../../packaging/systemd/roundhouse.service");
    let workspace_args = workspaces
        .iter()
        .map(|workspace| {
            format!(
                " --workspace {}",
                quote_systemd_exec_path(Path::new(workspace))
            )
        })
        .collect::<String>();
    Ok(base.replace(
        "%h/.local/bin/round daemon",
        &format!(
            "{} daemon{}",
            quote_systemd_exec_path(exec_path),
            workspace_args
        ),
    ))
}

/// Renders the launchd `LaunchAgent` plist with the actual installed binary
/// path substituted in, mirroring [`render_systemd_unit`]. Also substitutes
/// the log paths' `~` with an absolute directory under `$HOME`: launchd does
/// not expand `~` itself, so `StandardOutPath`/`StandardErrorPath` left as
/// `~/Library/Logs/...` would silently never be written to.
/// Renders the launchd plist with the workspace registrations needed to boot a
/// fresh daemon after volatile runtime state has been recreated.
pub fn render_launchd_plist(
    exec_path: &Path,
    workspaces: &[String],
) -> Result<String, ServiceInstallError> {
    validate_exec_path_for_render(exec_path)?;
    validate_workspace_arguments(workspaces)?;
    validate_daemon_protected_workspace_paths(workspaces, exec_path)?;
    let base = include_str!("../../../../packaging/launchd/com.roundhouse.daemon.plist");
    let escaped_exec_path = escape_xml_text(&exec_path.to_string_lossy());
    let mut rendered = base.replace("/usr/local/bin/round", &escaped_exec_path);
    let workspace_arguments = workspaces
        .iter()
        .map(|workspace| {
            format!(
                "        <string>--workspace</string>\n        <string>{}</string>\n",
                escape_xml_text(workspace)
            )
        })
        .collect::<String>();
    rendered = rendered.replace(
        "        <string>daemon</string>\n",
        &format!("        <string>daemon</string>\n{workspace_arguments}"),
    );

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
    Ok(rendered)
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
    let percent_doubled = raw.replace('%', "%%").replace('$', "$$");
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
/// function's signature (pinned by an earlier task's brief) returns a plain
/// `PathBuf` with no way to report an error.
///
/// **Phase 7, Task 28 — the naming-trap fix.** This function used to be
/// named `install_dir`, and the actually-safe, hard-erroring function below
/// was `resolved_install_dir` — an operator or a future caller reaching for
/// the obviously-named `install_dir` got the LESS safe one, silently. This
/// function is renamed `install_dir_unchecked` (its best-effort behavior is
/// otherwise unchanged) so that the plain, obviously-reached-for name
/// belongs to the safe function instead. **Prefer [`install_dir`] for
/// anything other than shape-checking/testing** — it hard-errors on an
/// unset or relative `$HOME` instead of silently degrading to a path
/// relative to the process's current directory, and is the function
/// [`install`]/[`uninstall`] actually use.
pub fn install_dir_unchecked(os: OsFamily) -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| PathBuf::from("."));
    let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    build_install_dir(os, &home, xdg_config_home.as_deref())
}

/// Shared path-assembly logic between the best-effort [`install_dir_unchecked`]
/// and the hard-erroring [`install_dir`] — the two differ only in how
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

/// [`install_dir_unchecked`]'s hard-erroring counterpart, and — since Phase 7,
/// Task 28's rename — the function the obvious, plain name `install_dir`
/// actually belongs to: refuses to guess a fallback when `$HOME` is unset or
/// relative rather than risk writing a boot-persistent unit under the
/// process's current directory. [`install`]/[`uninstall`] use this, not
/// [`install_dir_unchecked`] — and so should any future caller that needs
/// the *real* install location (a `round service status`, or a "would
/// install to X" dry run, say). This is the safe function to reach for, and
/// the plain name is deliberately no longer a trap for a caller who reaches
/// for the obviously-named one.
pub fn install_dir(os: OsFamily) -> Result<PathBuf, ServiceInstallError> {
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
/// [`install_dir`] has already hard-errored on an unset `$HOME`.
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
    #[error(
        "refusing to use {path} as the daemon's install path: the file itself is group- or \
         world-writable, so another local user could overwrite it directly regardless of its \
         directory's permissions; fix its mode (chmod 755) and retry"
    )]
    UnsafeExecFileMode { path: PathBuf },
    #[error("refusing to use {path:?} as the daemon's install path: it {reason}")]
    InvalidExecPath { path: PathBuf, reason: String },
    #[error("{path} already exists; rerun with --force to overwrite")]
    AlreadyExists { path: PathBuf },
    #[error(
        "refusing to write into {dir}: it (or one of its ancestor directories) is group- or \
         world-writable without the sticky bit, which would let another local user replace an \
         installed unit file wholesale regardless of the file's own permissions; fix its mode \
         (chmod 700) and retry"
    )]
    UnsafeInstallDir { dir: PathBuf },
    #[error(
        "$HOME is not set (or is not an absolute path); cannot determine the per-user service \
         install directory"
    )]
    HomeNotSet,
    #[error("at least one --workspace NAME=PATH is required for a bootable service")]
    MissingWorkspace,
    #[error("workspace registrations cannot contain control characters")]
    InvalidWorkspaceArgument,
}

fn validate_workspace_arguments(workspaces: &[String]) -> Result<(), ServiceInstallError> {
    if workspaces.is_empty() {
        return Err(ServiceInstallError::MissingWorkspace);
    }
    let mut names = HashSet::new();
    let mut roots = HashSet::new();
    for workspace in workspaces {
        if workspace.chars().any(char::is_control) {
            return Err(ServiceInstallError::InvalidWorkspaceArgument);
        }
        let Some((name, root)) = workspace.split_once('=') else {
            return Err(ServiceInstallError::InvalidWorkspaceArgument);
        };
        if name.is_empty() || root.is_empty() || !Path::new(root).is_absolute() {
            return Err(ServiceInstallError::InvalidWorkspaceArgument);
        }
        if name.len() > 4096 {
            return Err(ServiceInstallError::InvalidWorkspaceArgument);
        }
        let canonical = Path::new(root)
            .canonicalize()
            .map_err(|_| ServiceInstallError::InvalidWorkspaceArgument)?;
        if !canonical.is_dir() || canonical == Path::new("/") {
            return Err(ServiceInstallError::InvalidWorkspaceArgument);
        }
        if PROTECTED_SYSTEM_ROOTS.iter().any(|raw_root| {
            let Ok(protected) = Path::new(raw_root).canonicalize() else {
                return false;
            };
            canonical == protected
                || (*raw_root != "/tmp" && *raw_root != "/home" && canonical.starts_with(protected))
        }) {
            return Err(ServiceInstallError::InvalidWorkspaceArgument);
        }
        if let Some(home) = std::env::var_os("HOME") {
            if PathBuf::from(home).canonicalize().ok().as_deref() == Some(canonical.as_path()) {
                return Err(ServiceInstallError::InvalidWorkspaceArgument);
            }
        }
        if !names.insert(name) || !roots.insert(canonical) {
            return Err(ServiceInstallError::InvalidWorkspaceArgument);
        }
    }
    Ok(())
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

/// A directory mode unsafe to leave a unit/binary sitting under: group- or
/// world-writable (`0o022`) without the sticky bit (`0o1000`) — the sticky
/// bit is what makes an otherwise-shared, writable directory safe (only the
/// owner of an entry can rename/delete it out from under another user), the
/// same shape `/tmp` relies on via `+t`.
#[cfg(unix)]
fn dir_mode_is_unsafely_writable(mode: u32) -> bool {
    let group_or_world_writable = mode & 0o022 != 0;
    let sticky = mode & 0o1000 != 0;
    group_or_world_writable && !sticky
}

/// A *file* mode unsafe to execute/write-into: group- or world-writable.
/// Unlike a directory, a regular file's sticky bit carries no
/// restricted-write semantics, so there is no exemption to check for — any
/// group/world write bit means any other local user (or, for world-write,
/// anyone on the host) can overwrite its contents directly, regardless of
/// what its parent directory's permissions look like.
#[cfg(unix)]
fn file_mode_is_unsafely_writable(mode: u32) -> bool {
    mode & 0o022 != 0
}

/// Walks every ancestor directory of `path` (**not** including `path`
/// itself) up to the filesystem root, returning the first one found
/// unsafely writable by [`dir_mode_is_unsafely_writable`], or `None` if
/// every ancestor is safe. Shared by [`check_exec_path_safe`] (walking the
/// exec path's ancestors) and [`install_to`] (walking the install
/// directory's ancestors) — the same "a shared, writable ancestor lets
/// someone replace the whole subtree" attack shape applies to both, so
/// fix round 2 made both use this one implementation rather than leaving
/// the install-directory check one level deep while the exec-path check
/// walked all the way up.
#[cfg(unix)]
fn first_unsafe_ancestor(path: &Path) -> io::Result<Option<PathBuf>> {
    use std::os::unix::fs::PermissionsExt;
    let mut dir = path.parent();
    while let Some(d) = dir {
        let mode = std::fs::metadata(d)?.permissions().mode();
        if dir_mode_is_unsafely_writable(mode) {
            return Ok(Some(d.to_path_buf()));
        }
        dir = d.parent();
    }
    Ok(None)
}

/// Rejects an exec path that is itself group- or world-writable
/// ([`file_mode_is_unsafely_writable`]), or that resolves under a group- or
/// world-writable ancestor directory without the sticky bit
/// ([`first_unsafe_ancestor`]).
///
/// Checking the file's own mode matters on top of the ancestor walk: a
/// `round` binary at `~/.local/bin/round` with mode `0664`/`0666` under
/// perfectly safe `0755` ancestors is still directly overwritable by any
/// local user — exactly the boot-persistent-execution risk the ancestor
/// walk exists to prevent, just reached through the file instead of a
/// directory.
///
/// Deliberately does *not* check ownership (uid) anywhere in this function:
/// the ancestor walk plus the group/world-write checks already close every
/// concrete exploit shape identified in review without it, and a uid
/// comparison needs either a new capability or `/proc` parsing
/// (`roundhouse-daemon`'s `check_owned_by_current_user` pattern), neither of
/// which this narrower check needs to take on.
pub fn check_exec_path_safe(path: &Path) -> Result<(), ServiceInstallError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file_mode = std::fs::metadata(path)?.permissions().mode();
        if file_mode_is_unsafely_writable(file_mode) {
            return Err(ServiceInstallError::UnsafeExecFileMode {
                path: path.to_path_buf(),
            });
        }
        if let Some(dir) = first_unsafe_ancestor(path)? {
            return Err(ServiceInstallError::UnsafeExecPath {
                path: path.to_path_buf(),
                dir,
            });
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

/// Creates (or, with `force`, overwrites) `path` with contents that end up
/// at `0o644` regardless of which branch is taken:
///
/// - On first creation, `OpenOptionsExt::mode(0o644)` is passed directly to
///   the creating `open(2)` call, so there is no window in which the file
///   briefly exists at whatever the process umask would otherwise allow.
/// - On the `--force` overwrite path the file already exists, so `open(2)`
///   silently ignores the `mode` argument (it only applies when `O_CREAT`
///   actually creates the file) — fix round 2 (code review) caught that the
///   first cut of this function dropped the permission repair that used to
///   run here, so an existing file that was already group/world-writable
///   (hand-copied under a loose umask, restored from an archive preserving
///   modes, synced from another host) would survive `--force` unchanged.
///   The explicit `set_permissions` call below is what repairs it; it is a
///   harmless no-op on the fresh-create path.
///
/// Refuses to overwrite an existing file unless `force` is set. Using
/// `create_new` for the non-`force` case makes the existence check atomic
/// (`O_EXCL`) rather than a separate `exists()` call racing another writer.
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
/// when `force` is `false`, so an install that would clobber one of several
/// target files but not another fails cleanly instead of leaving a
/// half-written set. Also pre-checks that `dir` — whether freshly created or
/// pre-existing — and every one of its ancestors is safe
/// ([`dir_mode_is_unsafely_writable`]/[`first_unsafe_ancestor`], the same
/// check [`check_exec_path_safe`] applies to the exec path): a writable
/// *directory* anywhere in the chain lets another user replace an installed
/// unit file wholesale regardless of the file's own `0o644` mode.
/// Writes a service unit that re-registers the supplied workspaces on every
/// boot, including after volatile runtime state has been recreated.
pub fn install_to(
    dir: &Path,
    os: OsFamily,
    exec_path: &Path,
    force: bool,
    workspaces: &[String],
) -> Result<PathBuf, ServiceInstallError> {
    validate_workspace_arguments(workspaces)?;
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
        if dir_mode_is_unsafely_writable(mode) {
            return Err(ServiceInstallError::UnsafeInstallDir {
                dir: dir.to_path_buf(),
            });
        }
        if let Some(bad_ancestor) = first_unsafe_ancestor(dir)? {
            return Err(ServiceInstallError::UnsafeInstallDir { dir: bad_ancestor });
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)?;
    }

    let targets: Vec<(PathBuf, String)> = match os {
        OsFamily::Linux => vec![(
            dir.join(LINUX_UNIT_FILES[0]),
            render_systemd_unit(exec_path, workspaces)?,
        )],
        OsFamily::MacOs => vec![(
            dir.join(MACOS_UNIT_FILES[0]),
            render_launchd_plist(exec_path, workspaces)?,
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

/// Removes a single file, tolerating its absence.
fn remove_if_present(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

/// Removes the unit/plist files for `os` from `dir`, tolerating any that
/// are already absent (uninstalling twice is not an error). On Linux, also
/// removes [`LINUX_LEGACY_UNIT_FILES`] — files an earlier version of this
/// installer wrote that [`install_to`] no longer writes — so upgrading and
/// then uninstalling doesn't leave a dangling unit behind that nothing else
/// would ever clean up.
pub fn uninstall_from(dir: &Path, os: OsFamily) -> io::Result<()> {
    let files: &[&str] = match os {
        OsFamily::Linux => LINUX_UNIT_FILES,
        OsFamily::MacOs => MACOS_UNIT_FILES,
    };
    for name in files {
        remove_if_present(&dir.join(name))?;
    }
    if os == OsFamily::Linux {
        for name in LINUX_LEGACY_UNIT_FILES {
            remove_if_present(&dir.join(name))?;
        }
    }
    Ok(())
}

/// `round service install`: writes the rendered unit/plist for this OS into
/// its real per-user service directory ([`install_dir`], which
/// hard-errors on an unset/relative `$HOME` rather than
/// [`install_dir_unchecked`]'s best-effort fallback). Enabling/starting the
/// unit (`systemctl --user
/// enable --now` / `launchctl load`) is left to the caller printing
/// instructions rather than done here — see the task report's "Deviations
/// from the plan text" for why: this function must stay callable from an
/// ordinary `cargo test` run with no systemd/launchd present, which
/// shelling out to either would violate.
pub fn install(
    os: OsFamily,
    exec_path: &Path,
    force: bool,
    workspaces: &[String],
) -> Result<PathBuf, ServiceInstallError> {
    let dir = install_dir(os)?;
    if os == OsFamily::MacOs {
        ensure_launchd_log_dir(&dir)?;
    }
    install_to(&dir, os, exec_path, force, workspaces)
}

fn validate_daemon_protected_workspace_paths(
    workspaces: &[String],
    exec_path: &Path,
) -> Result<(), ServiceInstallError> {
    let mut protected = vec![roundhouse_tui::default_runtime_dir()];
    if let Some(parent) = exec_path.parent() {
        protected.push(parent.join("round-daemon-internal"));
    }
    let protected = protected
        .into_iter()
        .map(|path| {
            path.canonicalize()
                .unwrap_or_else(|_| normalize_absolute_path(&path))
        })
        .collect::<Vec<_>>();
    for workspace in workspaces {
        let (_, root) = workspace
            .split_once('=')
            .ok_or(ServiceInstallError::InvalidWorkspaceArgument)?;
        let root = Path::new(root)
            .canonicalize()
            .map_err(|_| ServiceInstallError::InvalidWorkspaceArgument)?;
        if protected
            .iter()
            .any(|path| root.starts_with(path) || path.starts_with(&root))
        {
            return Err(ServiceInstallError::InvalidWorkspaceArgument);
        }
    }
    Ok(())
}

fn normalize_absolute_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            component => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

fn ensure_launchd_log_dir(install_dir: &Path) -> io::Result<()> {
    let log_dir = install_dir
        .parent()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "install directory has no parent",
            )
        })?
        .join("Logs/roundhouse");
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        validate_directory_chain(&log_dir)?;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&log_dir)?;
        let metadata = std::fs::symlink_metadata(&log_dir)?;
        if !metadata.file_type().is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "launchd log path exists but is not a directory",
            ));
        }
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o700 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "launchd log directory must be owner-only",
            ));
        }
        validate_directory_chain(&log_dir)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(&log_dir)?;
    }
    Ok(())
}

fn validate_directory_chain(path: &Path) -> io::Result<()> {
    let mut current = Some(path);
    while let Some(directory) = current {
        let metadata = match std::fs::symlink_metadata(directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                current = directory.parent();
                continue;
            }
            Err(error) => return Err(error),
        };
        if metadata.file_type().is_symlink() {
            let kind = if directory == path {
                io::ErrorKind::AlreadyExists
            } else {
                io::ErrorKind::InvalidInput
            };
            return Err(io::Error::new(kind, "directory path contains a symlink"));
        }
        if !metadata.file_type().is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "directory path contains a non-directory or symlink ancestor",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode() & 0o7777;
            if dir_mode_is_unsafely_writable(mode) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "directory path contains an unsafe writable ancestor",
                ));
            }
        }
        current = directory.parent();
    }
    Ok(())
}

/// `round service uninstall`: removes the unit/plist (and any legacy unit —
/// see [`uninstall_from`]) for this OS from its real per-user service
/// directory.
pub fn uninstall(os: OsFamily) -> Result<(), ServiceInstallError> {
    uninstall_from(&install_dir(os)?, os)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Phase 7, Task 28 — the naming-trap fix, proven at the type level: the
    /// obviously-named function is the SAFE (hard-erroring) one, not the
    /// best-effort one. Before this task, `install_dir` was the best-effort
    /// `PathBuf`-returning function and the safe one was named
    /// `resolved_install_dir` — a future caller reaching for the obvious
    /// name got the less-safe function silently.
    #[test]
    fn install_dir_is_the_safe_function_not_the_best_effort_one() {
        let _: fn(OsFamily) -> Result<PathBuf, ServiceInstallError> = install_dir;
        let _: fn(OsFamily) -> PathBuf = install_dir_unchecked;
    }

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

    #[cfg(unix)]
    #[test]
    fn launchd_log_setup_rejects_an_existing_symlink_directory() {
        let root = tempfile::tempdir().unwrap();
        let install_dir = root.path().join("LaunchAgents");
        std::fs::create_dir(&install_dir).unwrap();
        let logs = root.path().join("Logs");
        std::fs::create_dir(&logs).unwrap();
        let target = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(target.path(), logs.join("roundhouse")).unwrap();

        let error = ensure_launchd_log_dir(&install_dir).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    }

    #[cfg(unix)]
    #[test]
    fn launchd_log_setup_rejects_a_symlinked_logs_ancestor() {
        let root = tempfile::tempdir().unwrap();
        let install_dir = root.path().join("LaunchAgents");
        std::fs::create_dir(&install_dir).unwrap();
        let target = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(target.path(), root.path().join("Logs")).unwrap();

        let error = ensure_launchd_log_dir(&install_dir).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
}
