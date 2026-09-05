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
                // example). This is a plain `std`-mirroring API — no
                // `unsafe` needed, unlike a raw `kill(-pgid, ..)` FFI call,
                // which this crate's `#![forbid(unsafe_code)]` would reject.
                .process_group(0)
                // If the timeout below fires and this future is dropped
                // before the child exits, tokio kills the child on drop
                // instead of leaving it running as an orphan.
                .kill_on_drop(true);

            let run = async {
                let mut child = command
                    .spawn()
                    .map_err(|e| CredentialError::ExecFailed(None, e.to_string()))?;
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
                let mut stdout_buf: Vec<u8> = Vec::new();
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
                        // Kill immediately rather than draining a possibly
                        // unbounded stream to EOF first. `kill_on_drop`
                        // alone wouldn't fire until this whole async block
                        // is dropped (i.e. not until the outer timeout
                        // elapses), so an explicit kill here is what makes
                        // detection fast rather than timeout-bounded.
                        let _ = child.kill().await;
                        return Err(CredentialError::ExecFailed(
                            None,
                            format!("credential helper stdout exceeded {MAX_STDOUT_BYTES} bytes"),
                        ));
                    }
                }

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
                    let mut stderr_buf = Vec::new();
                    let _ = stderr.read_to_end(&mut stderr_buf).await;
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
