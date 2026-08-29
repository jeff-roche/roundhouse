//! Where `round` and `round daemon` agree the daemon's runtime artifacts live.

use std::path::PathBuf;

/// The per-user directory holding the daemon's runtime artifacts: the Unix
/// socket, the event log, and (in Phase 1) the demo's scratch file.
///
/// Lives in `roundhouse-tui` because it is the only crate *both* binaries
/// depend on. §5.2 forbids `roundhouse-cli` from depending on
/// `roundhouse-daemon`, so the daemon can't own a location the client must also
/// resolve, and duplicating the rule in two binaries would let the two sides
/// drift apart silently — the client would dial a socket the daemon never bound.
///
/// Prefers `$XDG_RUNTIME_DIR`, which the OS already provides as a `0700`
/// directory owned by the invoking user — exactly the private-directory
/// property wanted here, and obtainable without a `getuid()` call, which
/// `#![forbid(unsafe_code)]` rules out. Falls back to a per-user subdirectory of
/// the shared temp dir, whose privacy the daemon establishes and verifies itself
/// (see `roundhouse_daemon`'s `prepare_runtime_dir`).
///
/// This is pure path computation — it creates nothing and touches no
/// filesystem. Creating and mode-checking the directory is the daemon's job,
/// since the daemon is the only process that writes there.
pub fn default_runtime_dir() -> PathBuf {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        // A relative `$XDG_RUNTIME_DIR` would resolve against the process's cwd,
        // which differs between `round` and `round daemon`. Reject it.
        .filter(|p| p.is_absolute())
        .unwrap_or_else(std::env::temp_dir);
    base.join(format!("roundhouse-{}", user_tag()))
}

/// The Unix socket both binaries default to when `$ROUND_SOCKET` is unset.
pub fn default_socket_path() -> PathBuf {
    default_runtime_dir().join("round.sock")
}

/// A filesystem-safe tag identifying the invoking user, used only to keep
/// different users on one host out of each other's directory.
///
/// The tag does **not** need to be unguessable: the security property comes from
/// the directory's `0700` mode, not from a secret name. It *does* need to be
/// safe to interpolate into a path, so everything outside `[A-Za-z0-9._-]` is
/// dropped — otherwise a hostile `$USER` containing `../..` would let the caller
/// steer the runtime directory anywhere it liked.
fn user_tag() -> String {
    let raw = std::env::var_os("USER")
        .or_else(|| std::env::var_os("LOGNAME"))
        .and_then(|v| v.into_string().ok())
        .unwrap_or_default();
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .take(64)
        .collect();
    if cleaned.is_empty() {
        "default".to_string()
    } else {
        cleaned
    }
}
