use crate::secret::Secret;
use roundhouse_provider::credential::{CredentialCtx, CredentialError, CredentialProvider};
use roundhouse_provider::{BoxFut, HttpRequest};
use std::time::Duration;
use tokio::io::AsyncReadExt;

/// Ceiling on how long a credential helper may run before it's killed. A
/// hung helper must not wedge the request indefinitely — Phase 2 did real
/// process-cancellation work; this does not regress it.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Ceiling on how much stdout a helper's output is trusted to produce. A
/// well-behaved helper prints one short-lived token; anything past this is
/// treated as a malfunction, not truncated-and-used.
const MAX_STDOUT_BYTES: usize = 8 * 1024;

/// Ceiling on how much of a failed helper's stderr is ever surfaced (after
/// redaction — see `apply`'s error path).
const MAX_STDERR_CHARS: usize = 200;

/// Ceiling on how many raw stderr bytes are ever *buffered* while draining
/// the pipe (before the `MAX_STDERR_CHARS` truncation on the redacted,
/// decoded text is applied). Far larger than `MAX_STDERR_CHARS` needs, but
/// the point of this constant is different: the drain loop keeps reading
/// (and discarding) stderr past this point rather than stopping, so a
/// helper that writes a large amount of stderr can never block on a full
/// pipe waiting for a reader that has stopped listening — see the
/// concurrency note on `apply`.
const MAX_STDERR_BYTES_BUFFERED: usize = 4 * 1024;

/// Sends `SIGKILL` to a helper's entire process group (see `process_group(0)`
/// on the spawned `Command` below), not just the immediate child — so a
/// grandchild the helper forked that's still holding the stdout pipe open
/// (the exact case `process_group(0)` alone does not reach) is torn down
/// too, rather than remaining bounded only by the whole-call timeout.
///
/// `rustix::process::kill_process_group` is a **safe fn** (fix round 1,
/// Ruling R34 — an earlier version of this fix wrongly believed group-kill
/// needed `unsafe` or a new dependency; neither is true: `rustix` is already
/// a dependency here, used in `resolve.rs`, and this crate's
/// `#![forbid(unsafe_code)]` binds only this crate's own code, not a
/// dependency's internals). It wraps `kill(-pgid, SIGKILL)`.
///
/// `pgid` must be `child.id()` captured **immediately after `spawn()`**,
/// before any `.wait()`/`.kill()` call — `Child::id()` returns `None` once
/// the child has been reaped, which is exactly when a caller on an error
/// path would otherwise be tempted to fetch it.
fn kill_helper_process_group(pgid: u32) {
    if let Some(pid) = rustix::process::Pid::from_raw(pgid as i32) {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
}

/// Runs a configured external helper command and treats its stdout (trimmed)
/// as a bearer token. Common for credential helpers that print a
/// short-lived token to stdout (e.g. a cloud CLI's `print-access-token`).
///
/// Hardened per security review: `command` must be an absolute path (no
/// `PATH` search, so a compromised `PATH` entry can't be substituted for the
/// configured helper); the child process runs with a cleared environment
/// plus only the caller's explicit allow-list (never the daemon's full
/// environment, which would otherwise hand every secret in the process's env
/// to an arbitrary configured helper); it is killed if it outruns
/// `DEFAULT_TIMEOUT` (or a `with_timeout` override); and its stdout is
/// rejected outright — not silently truncated-and-used — if it exceeds
/// `MAX_STDOUT_BYTES` or is empty.
pub struct ExecCommandCredential {
    command: String,
    args: Vec<String>,
    env: Vec<(String, String)>,
    timeout: Duration,
}

impl ExecCommandCredential {
    /// `env` is an explicit allow-list of environment variables to pass to
    /// the helper — never the calling process's ambient environment. Pass an
    /// empty `Vec` for a helper that needs none.
    pub fn new(
        command: String,
        args: Vec<String>,
        env: Vec<(String, String)>,
    ) -> Result<Self, CredentialError> {
        if !std::path::Path::new(&command).is_absolute() {
            return Err(CredentialError::ExecFailed(
                None,
                format!("credential helper command must be an absolute path, got `{command}`"),
            ));
        }
        Ok(Self {
            command,
            args,
            env,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// Overrides the default 10s helper timeout — primarily for tests that
    /// need a short bound rather than waiting out the real default.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl CredentialProvider for ExecCommandCredential {
    fn apply<'a>(
        &'a self,
        req: &'a mut HttpRequest,
        _ctx: &'a CredentialCtx<'a>,
    ) -> BoxFut<'a, Result<(), CredentialError>> {
        Box::pin(async move {
            let mut command = tokio::process::Command::new(&self.command);
            command
                .args(&self.args)
                .env_clear()
                .envs(self.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                // Phase 7 U4 (Ruling R14): put the helper (and anything it
                // forks) in its own new process group rather than the
                // daemon's, so a terminal signal delivered to the daemon's
                // foreground process group (e.g. Ctrl-C's SIGINT) never also
                // lands directly on a credential helper mid-run. A pgid of 0
                // makes the child the leader of that new group (see
                // `tokio::process::Command::process_group`'s own doc
                // example) — and gives `kill_helper_process_group` below a
                // group it can address deliberately, rather than relying on
                // whatever group the daemon itself happens to be in.
                .process_group(0)
                // If the timeout below fires and this future is dropped
                // before the child exits, tokio kills the direct child on
                // drop — but see `kill_helper_process_group`'s doc comment
                // for why that alone doesn't reach a grandchild.
                .kill_on_drop(true);

            let mut child = command
                .spawn()
                .map_err(|e| CredentialError::ExecFailed(None, e.to_string()))?;
            // Capture NOW, before any `.wait()`/`.kill()` below can reap the
            // child and make `child.id()` start returning `None`.
            let pgid = child.id();

            let run = async {
                let mut stdout = child
                    .stdout
                    .take()
                    .expect("stdout was configured as piped above");
                let mut stderr = child
                    .stderr
                    .take()
                    .expect("stderr was configured as piped above");

                // Stream stdout instead of buffering it to completion and
                // only checking its length afterward (Ruling R14): a helper
                // that emits far more than `MAX_STDOUT_BYTES` before exiting
                // — or one that never exits at all, e.g. because it forked a
                // grandchild that inherited and holds open the stdout pipe —
                // would otherwise be read into memory in full, bounded only
                // by the whole-call timeout below. Reading in bounded chunks
                // and failing the instant the running total crosses the cap
                // means a misbehaving helper is killed and rejected within
                // one chunk's read latency, not the full timeout, and this
                // process never holds more than one chunk past the cap in
                // memory.
                //
                // Stdout and stderr are drained CONCURRENTLY (`tokio::join!`
                // below), not sequentially. A pipe has a finite OS buffer
                // (~64 KiB on Linux); a helper that writes more than that to
                // stderr before it finishes writing stdout blocks on that
                // write until something reads the other end. Draining stdout
                // to EOF first (a naive streaming rewrite's first instinct)
                // would then hang until the whole-call timeout — a helper
                // that would have succeeded gets misreported as "timed out"
                // instead. `.output()`, what this replaced, always drained
                // both concurrently for exactly this reason.
                let mut stdout_buf: Vec<u8> = Vec::new();
                let stdout_fut = async {
                    let mut chunk = [0u8; 4096];
                    loop {
                        let n = stdout
                            .read(&mut chunk)
                            .await
                            .map_err(|e| CredentialError::ExecFailed(None, e.to_string()))?;
                        if n == 0 {
                            break;
                        }
                        stdout_buf.extend_from_slice(&chunk[..n]);
                        if stdout_buf.len() > MAX_STDOUT_BYTES {
                            // Kill immediately rather than draining a
                            // possibly unbounded stream to EOF first.
                            // `kill_on_drop` alone wouldn't fire until this
                            // whole async block is dropped (i.e. not until
                            // the outer timeout elapses), so an explicit
                            // kill here is what makes detection fast rather
                            // than timeout-bounded. Kill the whole process
                            // GROUP, not just the direct child — a
                            // grandchild the helper forked may be the one
                            // actually still holding this pipe open.
                            if let Some(pgid) = pgid {
                                kill_helper_process_group(pgid);
                            }
                            let _ = child.kill().await;
                            return Err(CredentialError::ExecFailed(
                                None,
                                format!(
                                    "credential helper stdout exceeded {MAX_STDOUT_BYTES} bytes"
                                ),
                            ));
                        }
                    }
                    Ok(())
                };

                // Bounded, not `read_to_end`: this drain runs for as long as
                // the pipe stays open, independent of whatever `stdout_fut`
                // decides above, so it must never itself grow unboundedly.
                // It keeps consuming (and discarding) bytes past the cap
                // rather than stopping, since stopping early would recreate
                // the exact full-pipe stall this concurrent drain exists to
                // avoid.
                let stderr_fut = async {
                    let mut buf: Vec<u8> = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        match stderr.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if buf.len() < MAX_STDERR_BYTES_BUFFERED {
                                    let take = (MAX_STDERR_BYTES_BUFFERED - buf.len()).min(n);
                                    buf.extend_from_slice(&chunk[..take]);
                                }
                            }
                        }
                    }
                    buf
                };

                let (stdout_result, stderr_buf) = tokio::join!(stdout_fut, stderr_fut);
                stdout_result?;

                let status = child
                    .wait()
                    .await
                    .map_err(|e| CredentialError::ExecFailed(None, e.to_string()))?;

                if !status.success() {
                    // A helper's stderr is not vetted content: it can carry
                    // diagnostics that echo token material (e.g. under
                    // `set -x`, or a partial-write bug). `redact_error_body`'s
                    // shape-based patterns are the only thing that ever sees
                    // this text, and it is hard-truncated regardless, since a
                    // persisted `CredentialError` derives `Display`/`Debug`.
                    let redacted = roundhouse_provider::audit::redact_error_body(
                        &String::from_utf8_lossy(&stderr_buf),
                    );
                    let truncated: String = redacted.chars().take(MAX_STDERR_CHARS).collect();
                    return Err(CredentialError::ExecFailed(status.code(), truncated));
                }

                let token = String::from_utf8_lossy(&stdout_buf).trim().to_string();
                if token.is_empty() {
                    return Err(CredentialError::ExecFailed(
                        status.code(),
                        "credential helper produced empty stdout".to_string(),
                    ));
                }

                Ok(token)
            };

            let token = match tokio::time::timeout(self.timeout, run).await {
                Ok(result) => result?,
                Err(_) => {
                    // `run` (and its borrow of `child`) was just dropped by
                    // `timeout` elapsing, so `child` is usable again here.
                    // Same reasoning as the cap-exceeded branch above: kill
                    // the whole process group, not just the direct child,
                    // so a hung grandchild doesn't outlive this call.
                    if let Some(pgid) = pgid {
                        kill_helper_process_group(pgid);
                    }
                    let _ = child.kill().await;
                    return Err(CredentialError::ExecFailed(
                        None,
                        format!(
                            "credential helper `{}` timed out after {:?}",
                            self.command, self.timeout
                        ),
                    ));
                }
            };

            // Wrapped in a `Secret` immediately, and read only through the
            // shared `apply_bearer_secret` exposure site — never held as a
            // bare `String` beyond this point, even though it is freshly
            // generated and only ever used within this call.
            let secret = Secret::new(token);
            super::apply_bearer_secret(&secret, req);
            Ok(())
        })
    }
}
