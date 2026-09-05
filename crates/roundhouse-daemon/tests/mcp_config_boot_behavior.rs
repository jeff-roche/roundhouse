//! Fix round 3, MUST 3: `main`'s previous handling of `mcp_config::
//! load_mcp_servers` propagated any `McpConfigError` straight out via `?`,
//! which `color_eyre` renders to stderr — entirely bypassing the `tracing`
//! subscriber (and therefore `tracing-subscriber` 0.3.23's own ANSI-escape
//! sanitization, which only applies to lines that actually go through
//! `tracing`). `McpConfigError::Parse`'s `Display` (via `toml::de::Error`)
//! embeds a verbatim snippet of the offending source line — for
//! `[[mcp_server]]` config, that line can be one of the OPERATOR'S OWN real
//! secret values (an `env` entry with the wrong shape, say), printed
//! verbatim to stderr and the journal on nothing worse than a config typo.
//! This is CF-11(c) for the operator's own config, not the hostile-cloned-
//! repo attack (project-scoped `[[mcp_server]]` layers are structurally
//! dropped before any file is ever read).
//!
//! This test proves the fix end to end against the real binary: a real
//! secret-shaped string, placed in the operator's own user-global MCP
//! config in a way that reliably produces a `toml::de::Error` embedding it
//! (verified directly against `mcp_config::load_mcp_servers_from_layers` —
//! see the sanity assertion below), must never appear on either stream,
//! and the daemon must still boot successfully (falling back to zero
//! configured MCP servers) rather than refusing to start over one
//! malformed table.

use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

const SECRET: &str = "sk-ant-should-never-leak-12345";

/// The exact hostile shape verified (see this file's own sanity test) to
/// produce a `toml::de::Error` whose `Display` embeds `SECRET` verbatim:
/// `env` is a `Vec<(String, String)>` in `McpTransportKind::Stdio`, so
/// giving it a bare string instead of an array is a type mismatch at
/// exactly the line containing the secret.
fn hostile_mcp_config() -> String {
    format!(
        "[[mcp_server]]\nid = \"fake\"\n[mcp_server.transport]\nkind = \"stdio\"\n\
         command = \"/bin/true\"\nargs = []\nenv = \"{SECRET}\"\n"
    )
}

/// Sanity check, run against this crate's own library code (no subprocess):
/// proves `hostile_mcp_config` really does make `McpConfigError`'s `Display`
/// embed `SECRET` — so the real-binary test below, which asserts the
/// secret is ABSENT from the daemon's output, is proving the fix actually
/// intercepts a real leak, not asserting something that was never going to
/// leak in the first place.
#[test]
fn sanity_the_hostile_config_really_does_make_the_raw_error_embed_the_secret() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, hostile_mcp_config()).unwrap();
    let err = roundhouse_daemon::mcp_config::load_mcp_servers_from_layers(vec![(
        roundhouse_config::ConfigScope::UserGlobal,
        path,
    )])
    .unwrap_err();
    assert!(
        format!("{err}").contains(SECRET),
        "sanity check failed: the raw McpConfigError's Display should embed the secret"
    );
    assert!(
        !err.kind().contains(SECRET),
        "McpConfigError::kind() must never contain the secret"
    );
}

#[tokio::test]
async fn a_malformed_operator_mcp_config_never_leaks_its_own_secret_and_the_daemon_still_boots() {
    let dir = tempfile::tempdir().unwrap();
    let config_dir = dir.path().join(".config/roundhouse");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(config_dir.join("config.toml"), hostile_mcp_config()).unwrap();

    let socket_path = dir.path().join("round.sock");
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_round-daemon-internal"))
        .arg("--socket")
        .arg(&socket_path)
        .arg("--allow-degraded-to")
        .arg("none")
        .env("HOME", dir.path())
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
    let mut stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");

    // The real proof this didn't just refuse to boot instead of leaking:
    // the socket must still come up, despite the malformed MCP config.
    let bound = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if socket_path.exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        bound.is_ok(),
        "the daemon must still boot (falling back to zero configured MCP servers) despite \
         a malformed [[mcp_server]] config, not refuse to start"
    );

    // Drain both streams for a settle window — long enough for the boot-time
    // log line to have been written, short enough to keep the suite fast.
    let mut stderr_lines = BufReader::new(stderr).lines();
    let mut seen_stderr = Vec::new();
    let _ = tokio::time::timeout(Duration::from_millis(500), async {
        while let Ok(Some(line)) = stderr_lines.next_line().await {
            seen_stderr.push(line);
        }
    })
    .await;
    let mut stdout_buf = String::new();
    let _ = tokio::time::timeout(
        Duration::from_millis(200),
        stdout.read_to_string(&mut stdout_buf),
    )
    .await;

    let all_stderr = seen_stderr.join("\n");
    assert!(
        !all_stderr.contains(SECRET),
        "the secret must never reach stderr; captured: {all_stderr:?}"
    );
    assert!(
        !stdout_buf.contains(SECRET),
        "the secret must never reach stdout; captured: {stdout_buf:?}"
    );
    assert!(
        seen_stderr
            .iter()
            .any(|line| line.contains("mcp_server_section_parse_error")),
        "expected the daemon to log the error's kind() naming the parse failure; saw: \
         {seen_stderr:?}"
    );

    let _ = child.kill().await;
}
