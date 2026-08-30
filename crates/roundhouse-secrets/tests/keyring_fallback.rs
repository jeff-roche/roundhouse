//! Exercises `resolve_secret`'s handling of all three real
//! `roundhouse_config::SecretRef` variants: `Keyring` (OS keyring first,
//! `~/.config/roundhouse/secrets.toml` mode-0600 fallback second — the
//! fallback recorded as a visible `Degradation` event), and the two direct
//! paths, `EnvVar` and `File`, which have no fallback semantics of their
//! own.
//!
//! Uses the injected `KeyringBackend` seam (Ruling 4) to deterministically
//! force the keyring branch to fail, rather than relying on the real OS
//! keyring's ambient (and platform-dependent) state — `keyring` 4.x's
//! public `v1::Entry` API has no override hook, so this seam is the only
//! way to exercise the fallback path deterministically.

use std::os::unix::fs::PermissionsExt;

use once_cell::sync::Lazy;
use roundhouse_config::SecretRef;
use roundhouse_core::{EventPayload, NoteLevel, SessionId, TaskRunner};
use roundhouse_secrets::resolve::{resolve_secret_with_backend, KeyringBackend};
use roundhouse_secrets::secret::Secret;
use roundhouse_secrets::{mcp_bridge, provider_bridge};

/// `TaskRunner::bootstrap()` panics on a second call in the same process
/// (S-LOG-1) — this test binary's `#[tokio::test]` functions share one
/// process, so they must share one `TaskRunner` instance.
static RUNNER: Lazy<TaskRunner> = Lazy::new(TaskRunner::bootstrap);

/// Process environment mutation (`HOME`, or any of this file's
/// `ROUNDHOUSE_SECRETS_TEST_ENV_VAR_*` test variables) is not just a
/// same-key race risk — concurrent `std::env::set_var`/`remove_var` calls
/// from different threads, even touching *different* keys, can race at the
/// C library level on the process's single shared `environ` table. Every
/// test in this file that touches the environment holds this lock for its
/// entire body (including across `.await` points, hence a
/// `tokio::sync::Mutex` rather than a `std::sync::Mutex` — clippy's
/// `await_holding_lock` correctly flags holding a std lock across an
/// await).
static ENV_LOCK: Lazy<tokio::sync::Mutex<()>> = Lazy::new(|| tokio::sync::Mutex::new(()));

/// Always fails, forcing `resolve_secret_with_backend` down the
/// file-fallback path deterministically.
struct AlwaysFailKeyring;

impl KeyringBackend for AlwaysFailKeyring {
    fn get_password(&self, _service: &str, _account: &str) -> Result<String, String> {
        Err("no backend available (test double)".to_string())
    }
}

/// Always succeeds, so the fallback path never runs.
struct AlwaysSucceedKeyring(String);

impl KeyringBackend for AlwaysSucceedKeyring {
    fn get_password(&self, _service: &str, _account: &str) -> Result<String, String> {
        Ok(self.0.clone())
    }
}

/// Writes `~/.config/roundhouse/secrets.toml` containing `key = value` under
/// a fresh temp dir, with the given file mode. Callers must hold
/// `ENV_LOCK` and point `HOME` at the returned dir before this file is
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

async fn fresh_writer() -> (tempfile::TempDir, roundhouse_store::EventWriter) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = roundhouse_store::open(&db_path).await.unwrap();
    let writer = roundhouse_store::spawn_writer(store).await;
    (dir, writer)
}

/// Exposes `secret`'s material via the provider bridge and returns it as an
/// owned `String` — the only way any of these tests can observe the
/// resolved value, since `Secret` has no `Debug`/`Display` and there is no
/// longer any capability object to stash and use later (see `secret.rs`'s
/// module doc comment for why).
fn expose(secret: &Secret) -> String {
    provider_bridge::expose_secret_for_provider_call(secret, |s| s.to_string())
}

#[tokio::test]
async fn keyring_backend_failure_falls_back_to_file_and_records_degradation() {
    let _guard = ENV_LOCK.lock().await;
    let home = setup_home_with_secrets_toml("anthropic_api_key", "sk-from-file", 0o600);
    let prev_home = std::env::var_os("HOME");
    std::env::set_var("HOME", home.path());

    let (dir, writer) = fresh_writer().await;
    let db_path = dir.path().join("events.db");
    let session_id = SessionId::new();

    let secret = resolve_secret_with_backend(
        &SecretRef::Keyring {
            service: "roundhouse".into(),
            account: "anthropic_api_key".into(),
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
    assert_eq!(expose(&secret), "sk-from-file");

    let store2 = roundhouse_store::open(&db_path).await.unwrap();
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
async fn a_provider_bridge_call_can_expose_a_resolved_secret() {
    let secret = Secret::new("sk-live-xyz".into());
    assert_eq!(expose(&secret), "sk-live-xyz");
}

#[tokio::test]
async fn an_mcp_bridge_call_can_also_expose_a_resolved_secret() {
    let secret = Secret::new("sk-live-mcp".into());
    let result = mcp_bridge::expose_secret_for_mcp_call(&secret, |s| s.len());
    assert_eq!(result, "sk-live-mcp".len());
}

#[tokio::test]
async fn keyring_backend_success_skips_the_file_fallback_entirely() {
    let (dir, writer) = fresh_writer().await;
    let db_path = dir.path().join("events.db");
    let session_id = SessionId::new();

    let secret = resolve_secret_with_backend(
        &SecretRef::Keyring {
            service: "roundhouse".into(),
            account: "anthropic_api_key".into(),
        },
        &RUNNER,
        &writer,
        session_id,
        &AlwaysSucceedKeyring("sk-from-keyring".to_string()),
    )
    .await
    .unwrap();

    assert_eq!(expose(&secret), "sk-from-keyring");

    let store2 = roundhouse_store::open(&db_path).await.unwrap();
    let events = roundhouse_store::session_events(&store2, session_id)
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

/// Fail-closed discipline (§6.7): a `secrets.toml` that's readable by group
/// or other must be refused outright, not read anyway. Proves the
/// permission check in `resolve::read_permission_checked_file` genuinely
/// rejects a too-permissive file rather than merely compiling.
#[tokio::test]
async fn a_too_permissive_secrets_toml_is_refused_not_read() {
    let _guard = ENV_LOCK.lock().await;
    let home = setup_home_with_secrets_toml("anthropic_api_key", "sk-should-never-be-read", 0o644);
    let prev_home = std::env::var_os("HOME");
    std::env::set_var("HOME", home.path());

    let (_dir, writer) = fresh_writer().await;
    let session_id = SessionId::new();

    let result = resolve_secret_with_backend(
        &SecretRef::Keyring {
            service: "roundhouse".into(),
            account: "anthropic_api_key".into(),
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

#[tokio::test]
async fn env_var_ref_resolves_directly_from_the_process_environment() {
    let _guard = ENV_LOCK.lock().await;
    let (_dir, writer) = fresh_writer().await;
    let session_id = SessionId::new();

    // Unique var name, and still under ENV_LOCK — see that static's doc
    // comment for why a distinct key alone isn't enough.
    std::env::set_var(
        "ROUNDHOUSE_SECRETS_TEST_ENV_VAR_RESOLVES",
        "sk-from-env-var",
    );

    let secret = resolve_secret_with_backend(
        &SecretRef::EnvVar {
            name: "ROUNDHOUSE_SECRETS_TEST_ENV_VAR_RESOLVES".into(),
        },
        &RUNNER,
        &writer,
        session_id,
        &AlwaysFailKeyring, // unreachable — EnvVar never touches the keyring
    )
    .await
    .unwrap();

    std::env::remove_var("ROUNDHOUSE_SECRETS_TEST_ENV_VAR_RESOLVES");

    assert_eq!(expose(&secret), "sk-from-env-var");
}

#[tokio::test]
async fn env_var_ref_errors_clearly_when_the_variable_is_unset() {
    let _guard = ENV_LOCK.lock().await;
    let (_dir, writer) = fresh_writer().await;
    let session_id = SessionId::new();

    std::env::remove_var("ROUNDHOUSE_SECRETS_TEST_ENV_VAR_MISSING");

    let result = resolve_secret_with_backend(
        &SecretRef::EnvVar {
            name: "ROUNDHOUSE_SECRETS_TEST_ENV_VAR_MISSING".into(),
        },
        &RUNNER,
        &writer,
        session_id,
        &AlwaysFailKeyring,
    )
    .await;

    let message = match result {
        Ok(_) => panic!("an unset env var must be a clear error, not a silent success"),
        Err(err) => err.to_string(),
    };
    assert!(
        message.contains("ROUNDHOUSE_SECRETS_TEST_ENV_VAR_MISSING"),
        "expected the error to name the missing variable, got: {message}"
    );
}

#[tokio::test]
async fn file_ref_resolves_directly_from_a_permission_checked_path() {
    let (_dir, writer) = fresh_writer().await;
    let session_id = SessionId::new();

    let secret_dir = tempfile::tempdir().unwrap();
    let secret_path = secret_dir.path().join("token");
    std::fs::write(&secret_path, "sk-from-file-ref\n").unwrap();
    let mut perms = std::fs::metadata(&secret_path).unwrap().permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(&secret_path, perms).unwrap();

    let secret = resolve_secret_with_backend(
        &SecretRef::File {
            path: secret_path.clone(),
        },
        &RUNNER,
        &writer,
        session_id,
        &AlwaysFailKeyring, // unreachable — File never touches the keyring
    )
    .await
    .unwrap();

    // Trailing newline is trimmed, matching how a human would author a
    // plain token file.
    assert_eq!(expose(&secret), "sk-from-file-ref");
}

#[tokio::test]
async fn file_ref_refuses_a_too_permissive_path_the_same_way_the_keyring_fallback_does() {
    let (_dir, writer) = fresh_writer().await;
    let session_id = SessionId::new();

    let secret_dir = tempfile::tempdir().unwrap();
    let secret_path = secret_dir.path().join("token");
    std::fs::write(&secret_path, "sk-should-never-be-read").unwrap();
    let mut perms = std::fs::metadata(&secret_path).unwrap().permissions();
    perms.set_mode(0o644);
    std::fs::set_permissions(&secret_path, perms).unwrap();

    let result = resolve_secret_with_backend(
        &SecretRef::File { path: secret_path },
        &RUNNER,
        &writer,
        session_id,
        &AlwaysFailKeyring,
    )
    .await;

    let message = match result {
        Ok(_) => panic!("a 0644 File secret must be refused, not read"),
        Err(err) => err.to_string(),
    };
    assert!(
        message.contains("permissions too open"),
        "expected a permissions-too-open error, got: {message}"
    );
}
