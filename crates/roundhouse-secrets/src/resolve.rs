//! Keyring-first, 0600-file-fallback secret resolution over the real
//! `roundhouse_config::SecretRef` (the frozen pointer type — this crate
//! only handles what a `SecretRef` points at, never the pointer's own
//! storage/validation). The keyring fallback is recorded as a visible
//! startup `Degradation` event (§6.7) — not just a log line — via the real
//! `TaskRunner`/`EventWriter` pair, the same pattern
//! `roundhouse_policy::approval::suspend_for_approval` uses to mint and
//! persist an event.
//!
//! Only `SecretRef::Keyring` has a keyring-vs-file-fallback story — that's
//! specifically about resolving a value that's *supposed* to live in the
//! OS keyring, falling back to a local file if the keyring is unavailable.
//! `SecretRef::EnvVar` and `SecretRef::File` are direct resolution paths
//! with no fallback semantics of their own; they are not routed through
//! the keyring-fallback machinery.

use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use roundhouse_config::SecretRef;
use roundhouse_core::{NoteLevel, SessionId, TaskRunner, Timestamp};
use roundhouse_store::{EventWriter, StoreError};

use crate::secret::Secret;

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("secret not found: {0}")]
    NotFound(String),
    #[error("environment variable {0} is not set")]
    EnvVarNotSet(String),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Seam over the OS keyring lookup so tests can deterministically force the
/// keyring branch to fail and exercise the file-fallback path.
///
/// This exists because `keyring` 4.x's public `v1` API
/// (`keyring::Entry::new`) installs a real, platform-specific,
/// process-global credential backend the first time it's called (via an
/// internal `LazyLock` in `keyring::v1`), with no parameter or hook to
/// override that for a test. Without this seam, a test could only exercise
/// the fallback path by accident (no real keyring present) or flakily (a
/// real keyring present with unrelated ambient state) — never
/// deterministically.
pub trait KeyringBackend {
    fn get_password(&self, service: &str, account: &str) -> Result<String, String>;
}

/// The real backend: wraps `keyring::Entry::new(service, account)?.get_password()`.
/// Used by production callers of [`resolve_secret`].
pub struct RealKeyring;

impl KeyringBackend for RealKeyring {
    fn get_password(&self, service: &str, account: &str) -> Result<String, String> {
        let entry = keyring::Entry::new(service, account).map_err(|e| e.to_string())?;
        entry.get_password().map_err(|e| e.to_string())
    }
}

/// Resolves `ref_` to its secret material. `SecretRef::Keyring` tries the
/// OS keyring first, falling back to `~/.config/roundhouse/secrets.toml`
/// (mode 0600) if the keyring is unavailable — the fallback is recorded as
/// a startup `Degradation` event visible in the UI (§6.7), not a log line.
/// `SecretRef::EnvVar`/`SecretRef::File` resolve directly, with no
/// fallback of their own.
pub async fn resolve_secret(
    ref_: &SecretRef,
    runner: &TaskRunner,
    writer: &EventWriter,
    session_id: SessionId,
) -> Result<Secret, SecretError> {
    resolve_secret_with_backend(ref_, runner, writer, session_id, &RealKeyring).await
}

/// Same as [`resolve_secret`], but takes an explicit [`KeyringBackend`] —
/// the seam tests use to force the keyring-fallback path deterministically.
pub async fn resolve_secret_with_backend<B: KeyringBackend>(
    ref_: &SecretRef,
    runner: &TaskRunner,
    writer: &EventWriter,
    session_id: SessionId,
    backend: &B,
) -> Result<Secret, SecretError> {
    match ref_ {
        SecretRef::Keyring { service, account } => {
            resolve_keyring(service, account, runner, writer, session_id, backend).await
        }
        SecretRef::EnvVar { name } => resolve_env_var(name),
        SecretRef::File { path } => resolve_file(path),
    }
}

async fn resolve_keyring<B: KeyringBackend>(
    service: &str,
    account: &str,
    runner: &TaskRunner,
    writer: &EventWriter,
    session_id: SessionId,
    backend: &B,
) -> Result<Secret, SecretError> {
    match backend.get_password(service, account) {
        Ok(password) => Ok(Secret::new(password)),
        Err(keyring_err) => {
            let ts = now_ts();
            // NEVER interpolate the resolved secret's value into this (or
            // any) event text — only the backend's error string and the
            // lookup identifier (`account`, not a value derived from
            // material read anywhere below) are safe to include. This
            // event is durably persisted and UI-visible by design (§6.7);
            // a future "make the error message more helpful" edit must
            // not turn it into a secret-exfiltration path.
            let event = runner.record_note(
                session_id,
                0, // placeholder seq — EventWriter::append assigns the real one
                ts,
                None,
                NoteLevel::Degradation,
                format!(
                    "secrets: keyring unavailable for {account} ({keyring_err}), \
                     using 0600 file fallback"
                ),
                1, // schema_v
            );
            writer.append(event).await?;
            try_file_fallback(account)
        }
    }
}

fn resolve_env_var(name: &str) -> Result<Secret, SecretError> {
    std::env::var(name)
        .map(Secret::new)
        .map_err(|_| SecretError::EnvVarNotSet(name.to_string()))
}

fn resolve_file(path: &Path) -> Result<Secret, SecretError> {
    let contents = read_permission_checked_file(path)
        .map_err(|e| SecretError::NotFound(format!("{} ({e})", path.display())))?;
    Ok(Secret::new(
        contents.trim_end_matches(['\n', '\r']).to_string(),
    ))
}

fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

/// `std::env::var_os("HOME")`-based helper, matching this codebase's
/// established convention (`roundhouse_policy::sealed::home_dir`,
/// `roundhouse-config`'s loader) rather than adding a `dirs` dependency.
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

fn secrets_toml_path() -> Option<PathBuf> {
    home_dir().map(|home| home.join(".config/roundhouse/secrets.toml"))
}

fn try_file_fallback(account: &str) -> Result<Secret, SecretError> {
    let path = secrets_toml_path().ok_or_else(|| SecretError::NotFound(account.to_string()))?;
    let contents = read_permission_checked_file(&path)
        .map_err(|e| SecretError::NotFound(format!("{account} ({e})")))?;
    let table: toml::Table =
        toml::from_str(&contents).map_err(|_| SecretError::NotFound(account.to_string()))?;
    table
        .get(account)
        .and_then(|v| v.as_str())
        .map(|s| Secret::new(s.to_string()))
        .ok_or_else(|| SecretError::NotFound(account.to_string()))
}

/// Reads `path`'s contents, refusing to do so unless it is both owned by
/// the current process's user AND has no group/other permission bits set.
///
/// Two things a naive `std::fs::metadata(path)` + `std::fs::read_to_string(path)`
/// pair gets wrong, both fixed here:
///
/// - **TOCTOU**: calling `metadata()` on a *path* and then separately
///   opening that same path for reading is two syscalls against whatever
///   happens to be at that path at each moment — an attacker able to swap
///   the file (or replace it with a symlink to a file they don't control)
///   between the two calls could get a permission check against one file
///   and a read against another. Fixed by opening the file once and
///   `fstat`-ing the *open file descriptor* (`File::metadata`, not
///   `std::fs::metadata`) — the permission check and the read are then
///   guaranteed to be about the exact same inode.
/// - **Owner check**: mode bits alone don't mean what they look like if
///   the file is owned by a different user — a file owned by `attacker`
///   with mode 0600 is unreadable to us regardless (the OS enforces that),
///   but a file owned by `attacker` with mode 0600 *that we somehow can*
///   read (e.g. we're root, or some other privilege escalation) would
///   otherwise pass the permission-bits check even though it was never
///   ours to trust. Fixed by also requiring `metadata.uid() ==
///   rustix::process::getuid()`.
fn read_permission_checked_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let meta = file.metadata()?;

    let current_uid = rustix::process::getuid().as_raw();
    if meta.uid() != current_uid {
        return Err(std::io::Error::other(format!(
            "{} is not owned by the current user, refusing to read",
            path.display()
        )));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(std::io::Error::other(format!(
            "{} permissions too open, refusing to read",
            path.display()
        )));
    }

    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}
