//! Fix round 3, MUST 3, as amended by fix round 4 (ruling W1-R109):
//! `main`'s previous handling of `mcp_config::load_mcp_servers` propagated
//! any `McpConfigError` straight out via `?`, which `color_eyre` renders to
//! stderr — entirely bypassing the `tracing` subscriber (and therefore
//! `tracing-subscriber` 0.3.23's own ANSI-escape sanitization, which only
//! applies to lines that actually go through `tracing`). `McpConfigError::
//! Parse`'s `Display` (via `toml::de::Error`) embeds a verbatim snippet of
//! the offending source line — for `[[mcp_server]]` config, that line can
//! be one of the OPERATOR'S OWN real secret values (an `env` entry with the
//! wrong shape, say), printed verbatim to stderr and the journal on nothing
//! worse than a config typo.
//!
//! **The boot-behavior half of fix round 3's original fix was reverted in
//! fix round 4.** Round 3 made a malformed `[[mcp_server]]` config
//! non-fatal (falls back to zero configured MCP servers). Round 4's ruling:
//! unlike `[network]` config (whose non-fatal fallback specifically resists
//! a hostile-repo DoS — a cloned repo's `.roundhouse/config.toml` really is
//! read as a layer), `[[mcp_server]]` config structurally drops every
//! non-`UserGlobal` layer before any file is ever opened (see
//! `mcp_config`'s own module doc comment), so the only possible source of a
//! malformed `[[mcp_server]]` config is the OPERATOR'S OWN file — never a
//! hostile repository. For an operator's own config, refusing to boot is
//! the more honest failure (comparable to `sshd`/`nginx` refusing to start
//! on a malformed config file). So this daemon now refuses to boot on a
//! malformed `[[mcp_server]]` config again — the fix that changed is
//! purely the RENDERING: never `err`'s own `Display` (which can embed the
//! config file's own text verbatim), only `err.kind()`, a short, static,
//! never-attacker-influenced string, in both the log line and the
//! `color_eyre` error `main` returns.
//!
//! This test proves the fix end to end against the real binary: a real
//! secret-shaped string, placed in the operator's own user-global MCP
//! config in a way that reliably produces a `toml::de::Error` embedding it,
//! must never appear on either stream, and the daemon must refuse to boot
//! (non-zero exit, socket never bound) rather than silently continuing.
//!
//! **Deliberately does not call `mcp_config::load_mcp_servers_from_layers`
//! directly** (fix round 3 self-review, after an earlier version of this
//! file did exactly that in a "sanity" test): that function is `pub`,
//! kept that way only for `mcp_config.rs`'s OWN tests, and calling it from
//! this external crate would be exactly the same "raw, caller-labeled
//! function reachable from outside the crate" back door fix round 2's
//! MUST 4 closed for `roundhouse-config`'s equivalent function. The
//! equivalent sanity check (proving the hostile config really does make
//! `McpConfigError`'s `Display` embed the secret) lives in
//! `mcp_config.rs`'s own `#[cfg(test)]` module instead.

use std::process::Stdio;
use std::time::Duration;

const SECRET: &str = "sk-ant-should-never-leak-12345";

/// The exact hostile shape (see `mcp_config.rs`'s own in-crate sanity test
/// for the proof) known to produce a `toml::de::Error` whose `Display`
/// embeds `SECRET` verbatim: `env` is a `Vec<(String, String)>` in
/// `McpTransportKind::Stdio`, so giving it a bare string instead of an
/// array is a type mismatch at exactly the line containing the secret.
fn hostile_mcp_config() -> String {
    format!(
        "[[mcp_server]]\nid = \"fake\"\n[mcp_server.transport]\nkind = \"stdio\"\n\
         command = \"/bin/true\"\nargs = []\nenv = \"{SECRET}\"\n"
    )
}

#[tokio::test]
async fn a_malformed_operator_mcp_config_refuses_to_boot_without_leaking_its_own_secret() {
    let dir = tempfile::tempdir().unwrap();
    let config_dir = dir.path().join(".config/roundhouse");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(config_dir.join("config.toml"), hostile_mcp_config()).unwrap();

    let socket_path = dir.path().join("round.sock");
    let workspace_root = dir.path().join("workspace");
    std::fs::create_dir(&workspace_root).unwrap();
    let child = tokio::process::Command::new(env!("CARGO_BIN_EXE_round-daemon-internal"))
        .arg("--socket")
        .arg(&socket_path)
        .arg("--workspace")
        .arg(format!("daemon-a-session={}", workspace_root.display()))
        .arg("--allow-degraded-to")
        .arg("none")
        .env("HOME", dir.path())
        .env("XDG_RUNTIME_DIR", dir.path())
        // Crate-scoped, not a blanket `info` — see
        // `on_degrade_boot_behavior.rs`'s fix round 3 doc comment for why a
        // blanket filter can hide a target-naming regression that a real
        // operator's own filter would not.
        .env("RUST_LOG", "roundhouse_daemon=info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    let output = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .expect("a daemon that refuses to boot must exit promptly, not hang")
        .expect("waiting on the child process must not itself fail");

    assert!(
        !output.status.success(),
        "the daemon must refuse to boot (non-zero exit) on a malformed [[mcp_server]] \
         config, got exit status: {:?}",
        output.status
    );
    assert!(
        !socket_path.exists(),
        "the daemon must never bind its socket when it refuses to boot over a malformed \
         [[mcp_server]] config"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stdout.contains(SECRET),
        "the secret must never reach stdout; captured: {stdout:?}"
    );
    assert!(
        !stderr.contains(SECRET),
        "the secret must never reach stderr; captured: {stderr:?}"
    );
    assert!(
        stderr.contains("mcp_server_section_parse_error"),
        "expected the daemon's stderr to name the error's kind() (both the tracing log \
         line and the color_eyre report main returns); captured: {stderr:?}"
    );
}

/// Fix round 5, W1-R111: a REGRESSION test for the ordering bug the
/// previous round's own test could not have caught — that test asserts
/// `!socket_path.exists()` on a socket path that was never bound in the
/// first place, so it stays green even if `remove_stale_socket` runs
/// before config validation and unlinks nothing (because there was nothing
/// there to unlink). The real defect only shows up against a PRE-EXISTING,
/// LIVE socket: before this round, `main` called `remove_stale_socket`
/// (line ~330-ish, no liveness probe — see that function's own doc
/// comment) BEFORE loading `[[mcp_server]]` config, so re-running
/// `round-daemon-internal` against an already-running daemon's socket path,
/// with a newly-introduced config typo, unlinked the LIVE daemon's socket
/// and only THEN refused to boot — stranding the original, still-running
/// daemon (holding real isolation handles, an egress-proxy registration,
/// any MCP subprocesses) with no control channel, recoverable only by
/// `kill`.
///
/// This test starts a real daemon A (a fresh, valid config), confirms it
/// is genuinely alive (a real `CreateSession` handshake succeeds, not just
/// "the socket file exists"), THEN introduces the hostile config and boots
/// a second daemon B against the SAME socket path. B must refuse to boot;
/// A's socket must survive untouched, and a SECOND `CreateSession` against
/// the ORIGINAL socket path must still succeed — proving A is still alive
/// and still reachable, not merely that its process hasn't been reaped.
#[tokio::test]
async fn a_refused_reboot_never_unlinks_a_live_daemons_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let workspace_root = dir.path().join("workspace");
    let daemon_b_home = dir.path().join("daemon-b-home");
    std::fs::create_dir(&workspace_root).unwrap();
    std::fs::create_dir(&daemon_b_home).unwrap();

    let mut daemon_a = tokio::process::Command::new(env!("CARGO_BIN_EXE_round-daemon-internal"))
        .arg("--socket")
        .arg(&socket_path)
        .arg("--workspace")
        .arg(format!("daemon-a-session={}", workspace_root.display()))
        .arg("--allow-degraded-to")
        .arg("none")
        .env("HOME", dir.path())
        .env("XDG_RUNTIME_DIR", dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    let bound = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if socket_path.exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(bound.is_ok(), "daemon A must bind its socket promptly");

    // Proves daemon A is genuinely alive and serving, not just that a file
    // happens to exist at the path.
    let first_client = tokio::time::timeout(
        Duration::from_secs(10),
        roundhouse_tui::connect_create(&socket_path, "daemon-a-session"),
    )
    .await
    .expect("connect_create against daemon A must not hang")
    .expect("daemon A must accept a real CreateSession handshake");
    drop(first_client);

    // Now introduce the config typo and try to boot a SECOND daemon against
    // the SAME socket path — the exact scenario an operator hits editing
    // their MCP config and re-running `round daemon` without realizing one
    // is already up.
    let config_dir = daemon_b_home.join(".config/roundhouse");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(config_dir.join("config.toml"), hostile_mcp_config()).unwrap();

    let daemon_b = tokio::process::Command::new(env!("CARGO_BIN_EXE_round-daemon-internal"))
        .arg("--socket")
        .arg(&socket_path)
        .arg("--workspace")
        .arg(format!("daemon-a-session={}", workspace_root.display()))
        .arg("--allow-degraded-to")
        .arg("none")
        .env("HOME", daemon_b_home)
        .env("XDG_RUNTIME_DIR", dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    let output = tokio::time::timeout(Duration::from_secs(10), daemon_b.wait_with_output())
        .await
        .expect("daemon B must exit promptly rather than hang")
        .expect("waiting on daemon B must not itself fail");
    assert!(
        !output.status.success(),
        "daemon B must refuse to boot on the malformed [[mcp_server]] config, got: {:?}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    // The load-bearing assertions: daemon A's socket must be untouched, and
    // daemon A must still be genuinely reachable — not merely that the
    // process is still running (which `kill_on_drop` alone can't tell us).
    assert!(
        socket_path.exists(),
        "daemon A's socket must survive daemon B's refused boot attempt"
    );
    let second_client = tokio::time::timeout(
        Duration::from_secs(10),
        roundhouse_tui::connect_create(&socket_path, "daemon-a-session"),
    )
    .await
    .expect("connect_create against daemon A must not hang after daemon B's refused reboot")
    .expect(
        "daemon A must still accept a real CreateSession handshake after daemon B refused \
         to boot against its socket path",
    );
    drop(second_client);

    let _ = daemon_a.kill().await;
}
