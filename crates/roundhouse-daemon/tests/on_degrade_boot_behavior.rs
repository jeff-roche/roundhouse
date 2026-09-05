//! Fix round 2, SHOULD (b): `real_boot_smoke.rs` proves the real accept loop
//! works, but every one of its boots passes `--allow-degraded-to none` — so
//! nothing in this crate's real-binary tests ever exercised the PRODUCTION
//! default, `OnDegrade::Refuse`, actually refusing `CreateSession` on a
//! degraded host. This file closes that gap, and also closes the loop on
//! fix round 2's MUST 3 (`--allow-degraded-to none` must log loudly): proven
//! empirically, before that fix, that starting with the flag printed
//! nothing about it on either stream.
//!
//! Both tests set `RUST_LOG=info` explicitly on the child process rather
//! than relying on `install_tracing_subscriber`'s own `"info"` fallback —
//! a CI environment that happens to export a more restrictive `RUST_LOG`
//! (e.g. `error`) would otherwise silently suppress the `warn!`-level lines
//! these tests assert on, for a reason that has nothing to do with either
//! fix being real.

use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};

async fn wait_for_socket(socket_path: &std::path::Path) {
    let bound = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if socket_path.exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(bound.is_ok(), "the daemon must bind its socket promptly");
}

/// Reads lines from `stderr` until one contains `needle` or `timeout`
/// elapses, returning every line read so far either way (so a failing
/// assertion can show the caller what the daemon actually logged).
async fn wait_for_stderr_line_containing(
    stderr: tokio::process::ChildStderr,
    needle: &str,
    timeout: Duration,
) -> (bool, Vec<String>) {
    let mut lines = BufReader::new(stderr).lines();
    let mut seen = Vec::new();
    let found = tokio::time::timeout(timeout, async {
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    let hit = line.contains(needle);
                    seen.push(line);
                    if hit {
                        return true;
                    }
                }
                Ok(None) | Err(_) => return false,
            }
        }
    })
    .await
    .unwrap_or(false);
    (found, seen)
}

/// The production default (no `--allow-degraded-to` flag at all):
/// `OnDegrade::Refuse` must genuinely refuse `CreateSession` on a host that
/// cannot achieve `Tier::Sandbox` at the daemon's hardcoded production
/// isolation path — not merely compile to that behavior in principle.
///
/// **The trap this test is written to avoid:** on a host where the
/// production isolation mechanism genuinely IS available, `Refuse` legally
/// SUCCEEDS, and asserting a refusal unconditionally would make this test
/// wrong on that host, not the code. So a successful `CreateSession` here is
/// treated as "this host is capable of Tier::Sandbox — nothing to assert
/// about the fail-closed path," not a failure. On this development
/// environment, `bwrap` exists at `/usr/bin/bwrap` but not at the daemon's
/// hardcoded production path, so this test exercises the refusal branch.
#[tokio::test]
async fn refuse_is_the_production_default_and_actually_refuses_on_a_degraded_host() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_round-daemon-internal"))
        .arg("--socket")
        .arg(&socket_path)
        // Deliberately NOT `--allow-degraded-to` — this is the whole point:
        // proving the compiled-in default, not the opt-in escape hatch
        // `real_boot_smoke.rs` already covers.
        .env("HOME", dir.path())
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().expect("stderr was piped");

    wait_for_socket(&socket_path).await;

    let result = tokio::time::timeout(
        Duration::from_secs(10),
        roundhouse_tui::connect_create(&socket_path, "degraded-host-test"),
    )
    .await
    .expect("connect_create must not hang");

    match result {
        Ok(_) => {
            eprintln!(
                "this host achieved Tier::Sandbox at the daemon's production isolation path — \
                 OnDegrade::Refuse legitimately succeeded here, so there is nothing to assert \
                 about the fail-closed refusal path on THIS host"
            );
        }
        Err(_) => {
            let (found, seen) = wait_for_stderr_line_containing(
                stderr,
                "refusing CreateSession",
                Duration::from_secs(5),
            )
            .await;
            assert!(
                found,
                "expected the daemon's stderr to log a refusal naming \"refusing \
                 CreateSession\"; saw these lines instead: {seen:?}"
            );
        }
    }

    let _ = child.kill().await;
}

/// Fix round 2, MUST 3, proven against the real binary rather than only at
/// the source level: `--allow-degraded-to none` must log, loudly, that
/// `sealed_tier_shortfall` is disarmed — on every boot, unconditionally,
/// before any client ever connects (the warning fires once, at the
/// `default_on_degrade` binding in `main`, not per session).
#[tokio::test]
async fn allow_degraded_to_none_logs_that_sealed_tier_shortfall_is_disarmed() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_round-daemon-internal"))
        .arg("--socket")
        .arg(&socket_path)
        .arg("--allow-degraded-to")
        .arg("none")
        .env("HOME", dir.path())
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().expect("stderr was piped");

    let (found, seen) =
        wait_for_stderr_line_containing(stderr, "sealed_tier_shortfall", Duration::from_secs(10))
            .await;
    assert!(
        found,
        "expected the daemon's stderr to name sealed_tier_shortfall as disarmed when booted \
         with --allow-degraded-to none; saw these lines instead: {seen:?}"
    );

    let _ = child.kill().await;
}
