//! Exercises `resolve_secret`'s keyring-first, 0600-file-fallback path.
//!
//! Uses the injected `KeyringBackend` seam (Ruling 4) to deterministically
//! force the keyring branch to fail, rather than relying on the real OS
//! keyring's ambient (and platform-dependent) state — `keyring` 4.x's
//! public `v1::Entry` API has no override hook, so this seam is the only
//! way to exercise the fallback path deterministically.

use std::os::unix::fs::PermissionsExt;

use once_cell::sync::Lazy;
use roundhouse_core::{EventPayload, NoteLevel, SessionId, TaskRunner};
use roundhouse_secrets::resolve::{resolve_secret_with_backend, KeyringBackend, SecretRef};

/// `TaskRunner::bootstrap()` panics on a second call in the same process
/// (S-LOG-1) — this test binary's `#[tokio::test]` functions share one
/// process, so they must share one `TaskRunner` instance.
static RUNNER: Lazy<TaskRunner> = Lazy::new(TaskRunner::bootstrap);

/// `HOME` is process-global; every test in this file that mutates it holds
/// this lock for the duration (including across `.await` points, hence a
/// `tokio::sync::Mutex` rather than a `std::sync::Mutex` — clippy's
/// `await_holding_lock` correctly flags holding a std lock across an
/// await).
static HOME_ENV_LOCK: Lazy<tokio::sync::Mutex<()>> = Lazy::new(|| tokio::sync::Mutex::new(()));

/// Always fails, forcing `resolve_secret_with_backend` down the
/// file-fallback path deterministically.
struct AlwaysFailKeyring;

impl KeyringBackend for AlwaysFailKeyring {
    fn get_password(&self, _service: &str, _key: &str) -> Result<String, String> {
        Err("no backend available (test double)".to_string())
    }
}

/// Always succeeds, so the fallback path never runs.
struct AlwaysSucceedKeyring(String);

impl KeyringBackend for AlwaysSucceedKeyring {
    fn get_password(&self, _service: &str, _key: &str) -> Result<String, String> {
        Ok(self.0.clone())
    }
}

/// Writes `~/.config/roundhouse/secrets.toml` containing `key = value` under
/// a fresh temp dir, with the given file mode. Callers must hold
/// `HOME_ENV_LOCK` and point `HOME` at the returned dir before this file is
/// read by `resolve_secret_with_backend`.
fn setup_home_with_secrets_toml(key: &str, value: &str, mode: u32) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let config_dir = dir.path().join(".config/roundhouse");
    std::fs::create_dir_all(&config_dir).unwrap();
    let secrets_path = config_dir.join("secrets.toml");
    std::fs::write(&secrets_path, format!("{key} = \"{value}\"\n")).unwrap();
    let mut perms = std::fs::metadata(&secrets_path).unwrap().permissions();
    perms.set_mode(mode);
    std::fs::set_permissions(&secrets_path, perms).unwrap();
    dir
}

#[tokio::test]
async fn keyring_backend_failure_falls_back_to_file_and_records_degradation() {
    let _guard = HOME_ENV_LOCK.lock().await;
    let home = setup_home_with_secrets_toml("anthropic_api_key", "sk-from-file", 0o600);
    let prev_home = std::env::var_os("HOME");
    std::env::set_var("HOME", home.path());

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = roundhouse_store::open(&db_path).await.unwrap();
    let writer = roundhouse_store::spawn_writer(store).await;
    let session_id = SessionId::new();

    let secret = resolve_secret_with_backend(
        &SecretRef {
            key: "anthropic_api_key".into(),
        },
        &RUNNER,
        &writer,
        session_id,
        &AlwaysFailKeyring,
    )
    .await;

    match prev_home {
        Some(v) => std::env::set_var("HOME", v),
        None => std::env::remove_var("HOME"),
    }

    let secret = secret.unwrap();
    let token = roundhouse_secrets::provider_bridge::issue_for_provider_call();
    assert_eq!(secret.expose_for_request(&token), "sk-from-file");

    let dir2 = dir; // keep temp dir alive through the query below
    let store2 = roundhouse_store::open(&dir2.path().join("events.db"))
        .await
        .unwrap();
    let events = roundhouse_store::session_events(&store2, session_id)
        .await
        .unwrap();
    let degraded = events.iter().any(|e| {
        matches!(
            &e.payload,
            EventPayload::Note { level: NoteLevel::Degradation, text }
                if text.contains("keyring")
        )
    });
    assert!(
        degraded,
        "fallback must be a visible startup Degradation, not a log line (§6.7)"
    );
}

#[tokio::test]
async fn a_token_from_the_provider_bridge_can_expose_a_resolved_secret() {
    let secret = roundhouse_secrets::secret::Secret::new("sk-live-xyz".into());
    let token = roundhouse_secrets::provider_bridge::issue_for_provider_call();
    assert_eq!(secret.expose_for_request(&token), "sk-live-xyz");
}

#[tokio::test]
async fn keyring_backend_success_skips_the_file_fallback_entirely() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = roundhouse_store::open(&db_path).await.unwrap();
    let writer = roundhouse_store::spawn_writer(store).await;
    let session_id = SessionId::new();

    let secret = resolve_secret_with_backend(
        &SecretRef {
            key: "anthropic_api_key".into(),
        },
        &RUNNER,
        &writer,
        session_id,
        &AlwaysSucceedKeyring("sk-from-keyring".to_string()),
    )
    .await
    .unwrap();

    let token = roundhouse_secrets::mcp_bridge::issue_for_mcp_call();
    assert_eq!(secret.expose_for_request(&token), "sk-from-keyring");

    let events = roundhouse_store::session_events(&store_reopen(&db_path).await, session_id)
        .await
        .unwrap();
    let degraded = events.iter().any(|e| {
        matches!(
            &e.payload,
            EventPayload::Note {
                level: NoteLevel::Degradation,
                ..
            }
        )
    });
    assert!(
        !degraded,
        "a successful keyring lookup must not record a Degradation"
    );
}

async fn store_reopen(path: &std::path::Path) -> roundhouse_store::StorePool {
    roundhouse_store::open(path).await.unwrap()
}

/// Fail-closed discipline (§6.7): a `secrets.toml` that's readable by group
/// or other must be refused outright, not read anyway. Proves the
/// `meta.permissions().mode() & 0o077 != 0` check in
/// `resolve::try_file_fallback` genuinely rejects a too-permissive file
/// rather than merely compiling.
#[tokio::test]
async fn a_too_permissive_secrets_toml_is_refused_not_read() {
    let _guard = HOME_ENV_LOCK.lock().await;
    let home = setup_home_with_secrets_toml("anthropic_api_key", "sk-should-never-be-read", 0o644);
    let prev_home = std::env::var_os("HOME");
    std::env::set_var("HOME", home.path());

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = roundhouse_store::open(&db_path).await.unwrap();
    let writer = roundhouse_store::spawn_writer(store).await;
    let session_id = SessionId::new();

    let result = resolve_secret_with_backend(
        &SecretRef {
            key: "anthropic_api_key".into(),
        },
        &RUNNER,
        &writer,
        session_id,
        &AlwaysFailKeyring,
    )
    .await;

    match prev_home {
        Some(v) => std::env::set_var("HOME", v),
        None => std::env::remove_var("HOME"),
    }

    // Not `.expect_err(...)`: that requires `T: Debug`, and `Secret`
    // deliberately has no `Debug` impl (§6.7) — matching this by hand is
    // the correct shape for a `Result<Secret, _>` in this codebase.
    let message = match result {
        Ok(_) => panic!("a 0644 secrets.toml must be refused, not read"),
        Err(err) => err.to_string(),
    };
    assert!(
        message.contains("permissions too open"),
        "expected a permissions-too-open error, got: {message}"
    );
}
