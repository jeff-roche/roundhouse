//! Keyring-first, 0600-file-fallback secret resolution. The fallback is
//! recorded as a visible startup `Degradation` event (§6.7) — not just a
//! log line — via the real `TaskRunner`/`EventWriter` pair, the same
//! pattern `roundhouse_policy::approval::suspend_for_approval` uses to mint
//! and persist an event.

use std::path::PathBuf;

use roundhouse_core::{NoteLevel, SessionId, TaskRunner, Timestamp};
use roundhouse_store::{EventWriter, StoreError};

use crate::secret::Secret;

/// A pointer to secret material — `roundhouse-config`'s type (unchanged).
/// This crate only ever handles what a `SecretRef` points at, never the
/// pointer's own storage/validation.
pub struct SecretRef {
    pub key: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("secret not found: {0}")]
    NotFound(String),
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
    fn get_password(&self, service: &str, key: &str) -> Result<String, String>;
}

/// The real backend: wraps `keyring::Entry::new(service, key)?.get_password()`.
/// Used by production callers of [`resolve_secret`].
pub struct RealKeyring;

impl KeyringBackend for RealKeyring {
    fn get_password(&self, service: &str, key: &str) -> Result<String, String> {
        let entry = keyring::Entry::new(service, key).map_err(|e| e.to_string())?;
        entry.get_password().map_err(|e| e.to_string())
    }
}

/// OS keyring first; `~/.config/roundhouse/secrets.toml` mode 0600 as
/// fallback. The fallback is recorded as a startup `Degradation` event
/// visible in the UI (§6.7), not a log line.
pub async fn resolve_secret(
    ref_: &SecretRef,
    runner: &TaskRunner,
    writer: &EventWriter,
    session_id: SessionId,
) -> Result<Secret, SecretError> {
    resolve_secret_with_backend(ref_, runner, writer, session_id, &RealKeyring).await
}

/// Same as [`resolve_secret`], but takes an explicit [`KeyringBackend`] —
/// the seam tests use to force the fallback path deterministically.
pub async fn resolve_secret_with_backend<B: KeyringBackend>(
    ref_: &SecretRef,
    runner: &TaskRunner,
    writer: &EventWriter,
    session_id: SessionId,
    backend: &B,
) -> Result<Secret, SecretError> {
    match backend.get_password("roundhouse", &ref_.key) {
        Ok(password) => Ok(Secret::new(password)),
        Err(keyring_err) => {
            let ts = now_ts();
            let event = runner.record_note(
                session_id,
                0, // placeholder seq — EventWriter::append assigns the real one
                ts,
                None,
                NoteLevel::Degradation,
                format!("secrets: keyring unavailable ({keyring_err}), using 0600 file fallback"),
                1, // schema_v
            );
            writer.append(event).await?;
            try_file_fallback(&ref_.key)
        }
    }
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

#[cfg(unix)]
fn try_file_fallback(key: &str) -> Result<Secret, SecretError> {
    use std::os::unix::fs::PermissionsExt;

    let path = secrets_toml_path().ok_or_else(|| SecretError::NotFound(key.to_string()))?;
    let meta = std::fs::metadata(&path).map_err(|_| SecretError::NotFound(key.to_string()))?;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(SecretError::NotFound(format!(
            "{key} (secrets.toml permissions too open, refusing to read)"
        )));
    }
    let contents =
        std::fs::read_to_string(&path).map_err(|_| SecretError::NotFound(key.to_string()))?;
    let table: toml::Table =
        toml::from_str(&contents).map_err(|_| SecretError::NotFound(key.to_string()))?;
    table
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| Secret::new(s.to_string()))
        .ok_or_else(|| SecretError::NotFound(key.to_string()))
}

#[cfg(not(unix))]
fn try_file_fallback(key: &str) -> Result<Secret, SecretError> {
    Err(SecretError::NotFound(format!(
        "{key} (0600 file fallback is only supported on unix)"
    )))
}
