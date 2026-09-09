//! Phase 7, Task 7's own exit criterion: `round-daemon-internal` boots the
//! REAL accept loop, not the scripted demo — verified two ways, per the
//! lane file's own status-block correction ("the test below only proves
//! this indirectly ... consider asserting directly that
//! `DEMO_FILE_CONTENTS`/`run_demo_session` no longer exist in the binary's
//! boot path").

use std::io::Read;

/// Direct assertion, not just behavioral: `main.rs`'s own source no longer
/// contains `DEMO_FILE_CONTENTS` at all, nor a live *call* to
/// `run_demo_session` (the bare identifier is allowed to appear in prose —
/// `main.rs`'s own module doc comment explains what replaced it — but an
/// actual invocation, `run_demo_session(`, must not).
#[test]
fn main_rs_no_longer_references_the_demo_boot_path() {
    let main_rs_path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs");
    let mut source = String::new();
    std::fs::File::open(main_rs_path)
        .expect("read src/main.rs")
        .read_to_string(&mut source)
        .expect("src/main.rs must be valid UTF-8");

    assert!(
        !source.contains("DEMO_FILE_CONTENTS"),
        "main.rs must no longer reference DEMO_FILE_CONTENTS at all"
    );
    assert!(
        !source.contains("run_demo_session("),
        "main.rs must no longer CALL run_demo_session — the demo is retired \
         as boot behavior (it may still be mentioned in prose explaining \
         what replaced it)"
    );
}

/// The behavioral exit criterion: a real `round-daemon-internal` process,
/// started via its own `--socket` flag (not a `daemon` subcommand — see
/// `commands::daemon::run`, which execs this binary and forwards its daemon
/// options), accepts a real `CreateSession` handshake over the real accept loop
/// — no demo script anywhere on the path.
#[tokio::test]
async fn round_daemon_boots_the_real_accept_loop_not_the_scripted_demo() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let workspace_root = dir.path().join("workspace");
    std::fs::create_dir(&workspace_root).unwrap();
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_round-daemon-internal"))
        .arg("--socket")
        .arg(&socket_path)
        .arg("--workspace")
        .arg(format!("smoke-test={}", workspace_root.display()))
        // Ruling W1-R95 (fix round 1): the default `OnDegrade::Refuse`
        // means a `CreateSession` on a host that cannot achieve
        // `Tier::Sandbox` refuses outright — genuinely true of this test
        // environment (real `bwrap` isn't installed at the hardcoded
        // production path, `/usr/libexec/roundhouse/bwrap`). This is a
        // smoke test proving the accept loop is real, not a test of
        // isolation-tier enforcement, so it opts into the explicit,
        // operator-only degradation escape hatch rather than silently
        // relying on the (now-reverted, and actively wrong) permissive
        // default.
        .arg("--allow-degraded-to")
        .arg("none")
        .env("HOME", dir.path())
        .env("XDG_RUNTIME_DIR", dir.path())
        // Never inherit this test's own stdout/stderr: the daemon runs
        // forever (it's the accept loop), so an inherited pipe stays open —
        // and, more importantly, if this test panics before reaching
        // `child.kill()` below, `kill_on_drop(true)` is what actually
        // reaps the process instead of leaking an orphaned daemon that
        // outlives the test binary.
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    // Poll for the socket to exist rather than a fixed sleep: bind happens
    // synchronously in `main` before the accept loop is ever spawned
    // (ruling W1-R12), but this test still has to wait for the child
    // PROCESS itself to reach that point after `spawn()` returns here.
    let bound = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if socket_path.exists() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(bound.is_ok(), "the daemon must bind its socket promptly");

    // A real client must be able to CreateSession against a live daemon
    // process — this is the exit criterion this whole track has been
    // building toward: no demo script anywhere in this path.
    let client = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        roundhouse_tui::connect_create(&socket_path, "smoke-test"),
    )
    .await
    .expect("connect_create must not hang")
    .expect("a real daemon process must accept a real CreateSession handshake");
    // Sanity: it's a real, freshly minted session id, not a leftover.
    assert_ne!(client.session_id(), roundhouse_core::SessionId::new());

    // A second, independent client must be able to attach to the same
    // session — proving this is Task 3's real multi-connection accept loop,
    // not a single-shot `serve`.
    let attach = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        roundhouse_tui::connect_attach(&socket_path, client.session_id()),
    )
    .await
    .expect("connect_attach must not hang");
    assert!(
        attach.is_ok(),
        "a second client must be able to attach to the session the first created"
    );

    let _ = child.kill().await;
}

#[tokio::test]
async fn round_daemon_refuses_to_boot_without_a_workspace_and_preserves_the_socket_path() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    std::fs::write(&socket_path, "pre-existing marker").unwrap();

    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_round-daemon-internal"))
        .arg("--socket")
        .arg(&socket_path)
        .env("HOME", dir.path())
        .env("XDG_RUNTIME_DIR", dir.path())
        .output()
        .await
        .unwrap();

    assert!(
        !output.status.success(),
        "an empty workspace registry must refuse boot"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no workspaces are registered"),
        "the refusal must explain how to register a workspace, got {stderr:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&socket_path).unwrap(),
        "pre-existing marker",
        "failed workspace validation must not remove an existing socket path"
    );
}
