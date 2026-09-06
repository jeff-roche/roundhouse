//! Phase 7, Task 9's own exit criterion: `round-daemon-internal` binds
//! `roundhouse-web`'s HTTP surface alongside Task 3's Unix-socket accept
//! loop, and a real HTTP `GET /api/runs` against the live process answers
//! `200` with a real, empty JSON array — proving the crate is actually
//! linked into the daemon, not merely compiled against it.
//!
//! Before this task, this test fails for the one reason that matters:
//! nothing in `roundhouse-daemon` ever printed a `web=` address, because
//! nothing bound a listener at all (`roundhouse-web`'s own module doc:
//! "nothing links it yet"). Running this test against that tree does not
//! get a wrong status code — it never gets a status code, because
//! `wait_for_web_addr` times out waiting for a line that is never printed.
//! That is the RED evidence recorded in the task report (reproduced with
//! `git stash`, not merely asserted).

use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::Child;

/// Drains `child`'s stdout in a background task (so the daemon's later
/// `println!`s, if any, never block on a full pipe or fail with `EPIPE`
/// against a dropped read end), and resolves with the first `SocketAddr`
/// found in a `web=http://<addr>` line — `main.rs`'s own status line, whose
/// exact shape this test is entitled to depend on since it lives in the
/// same crate.
async fn wait_for_web_addr(child: &mut Child) -> std::net::SocketAddr {
    let stdout = child.stdout.take().expect("child stdout must be piped");
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        let mut tx = Some(tx);
        while let Ok(Some(line)) = lines.next_line().await {
            if let Some(sender) = tx.take() {
                let parsed = line
                    .split("web=http://")
                    .nth(1)
                    .and_then(|after| after.split_whitespace().next())
                    .and_then(|addr_str| addr_str.parse().ok());
                match parsed {
                    Some(addr) => {
                        let _ = sender.send(addr);
                    }
                    None => tx = Some(sender),
                }
            }
        }
    });

    tokio::time::timeout(Duration::from_secs(10), rx)
        .await
        .expect("the daemon must print its web= listening address promptly")
        .expect("the stdout-draining task ended without ever finding a web= line")
}

/// A hand-rolled HTTP/1.1 `GET`, deliberately not a crate: this daemon
/// already declares no HTTP client dependency, and the point of this test is
/// asserting on the real bytes a real socket produced, not on how a client
/// library parsed them. Returns the numeric status code and the body (the
/// text after the header/body blank-line separator).
async fn http_get(addr: std::net::SocketAddr, path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr)
        .await
        .expect("connect to the daemon's web listener");
    let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write the HTTP request");

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .expect("read the HTTP response");

    let status_line = response
        .split("\r\n")
        .next()
        .expect("a response has at least a status line");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .expect("the status line has a status code")
        .parse()
        .expect("the status code is a decimal number");
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    (status, body)
}

#[tokio::test]
async fn round_daemon_serves_a_real_http_get_api_runs_alongside_the_unix_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_round-daemon-internal"))
        .arg("--socket")
        .arg(&socket_path)
        // Inert for what this test actually exercises: `--allow-degraded-to`
        // only feeds `OnDegrade`, which is consulted at `CreateSession` —
        // this test never sends one, so the flag changes nothing here. Kept
        // only so this test spawns `round-daemon-internal` with the exact
        // same argument list as its sibling, `real_boot_smoke.rs`.
        .arg("--allow-degraded-to")
        .arg("none")
        .env("HOME", dir.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    let web_addr = wait_for_web_addr(&mut child).await;

    let (status, body) = http_get(web_addr, "/api/runs").await;
    assert_eq!(
        status, 200,
        "GET /api/runs against a live round-daemon-internal process must answer 200 once \
         roundhouse-web is actually linked into the daemon (body: {body:?})"
    );
    assert_eq!(
        body.trim(),
        "[]",
        "a fresh, empty store's runs inbox must answer a real empty JSON array, not just any \
         200 — a wrong route or a stub could also answer 200"
    );

    child.kill().await.ok();
}
