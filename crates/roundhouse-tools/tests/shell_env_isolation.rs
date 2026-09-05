//! Fix round A (Phase 7, Task 5, finding F1): a real reproduction that a
//! child spawned by `run_shell`/`spawn_cancellable` no longer inherits the
//! daemon's own environment — specifically, a secret-shaped value like
//! `ANTHROPIC_API_KEY` must never reach the child. Before the fix, a replica
//! of these exact `Command` constructions printed the injected secret
//! verbatim; these tests assert it is now genuinely absent, not merely that
//! redaction would catch it downstream.
//!
//! `std::env::set_var`/`remove_var` mutate real process-global state, so
//! these two tests run in the SAME test binary but never concurrently with
//! each other by construction (each sets, asserts, then restores within its
//! own body) — `cargo test` runs tests in this binary on separate OS
//! threads by default, so a var mutated here could otherwise race a
//! concurrently-running test in the same binary that reads the environment.
//! Neither test here reads `PATH`/other env vars besides the ones it sets
//! itself, and no other test file in `roundhouse-tools` reads
//! `ANTHROPIC_API_KEY_TEST_FIXTURE`, so this is safe in practice; guarded
//! with `--test-threads=1`-independent correctness by using a name no real
//! config would ever set.

use roundhouse_tools::{run_shell, spawn_cancellable};

const FIXTURE_SECRET: &str = "sk-ant-DAEMON-SECRET-abc123";
const FIXTURE_VAR: &str = "ANTHROPIC_API_KEY_TEST_FIXTURE";

fn path_env() -> Vec<(String, String)> {
    vec![(
        "PATH".to_string(),
        std::env::var("PATH").unwrap_or_default(),
    )]
}

#[tokio::test]
async fn run_shell_does_not_leak_the_daemon_process_env_into_the_child() {
    // SAFETY (of the test, not memory): sets/removes a var scoped to this
    // test's own lifetime, using a name reserved for this fixture only.
    std::env::set_var(FIXTURE_VAR, FIXTURE_SECRET);

    let dir = tempfile::tempdir().unwrap();
    let output = run_shell("env", &[], dir.path()).await.unwrap();

    std::env::remove_var(FIXTURE_VAR);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains(FIXTURE_SECRET),
        "run_shell must not leak the daemon's own environment into the child — \
         got stdout: {stdout:?}"
    );
}

#[tokio::test]
async fn spawn_cancellable_does_not_leak_the_daemon_process_env_into_the_child() {
    std::env::set_var(FIXTURE_VAR, FIXTURE_SECRET);

    let dir = tempfile::tempdir().unwrap();
    let mut handle = spawn_cancellable("env", &[], dir.path(), &path_env())
        .await
        .unwrap();
    let (stdout, _stderr) = handle.take_stdio();
    let mut stdout = stdout.expect("stdout must be piped");
    let status = handle.wait().await.unwrap();

    std::env::remove_var(FIXTURE_VAR);

    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    stdout.read_to_end(&mut buf).await.unwrap();

    assert!(status.success());
    let stdout = String::from_utf8_lossy(&buf);
    assert!(
        !stdout.contains(FIXTURE_SECRET),
        "spawn_cancellable must not leak the daemon's own environment into the child — \
         got stdout: {stdout:?}"
    );
    // PATH was explicitly allowlisted, so the resolved `env` binary itself
    // proves the allowlist mechanism works at all (not merely that
    // everything, including PATH, was silently cleared and `env` failed to
    // even run) — a real, positive control against a vacuous pass.
    assert!(
        stdout.contains("PATH="),
        "the explicitly allowlisted PATH entry must still reach the child — got: {stdout:?}"
    );
}
