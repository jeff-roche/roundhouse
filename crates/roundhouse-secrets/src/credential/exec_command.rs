use crate::secret::Secret;
use roundhouse_provider::credential::{CredentialCtx, CredentialError, CredentialProvider};
use roundhouse_provider::{BoxFut, HttpRequest};
use std::time::Duration;

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
                // If the timeout below fires and this future is dropped
                // before the child exits, tokio kills the child on drop
                // instead of leaving it running as an orphan.
                .kill_on_drop(true);

            let output = match tokio::time::timeout(self.timeout, command.output()).await {
                Ok(result) => {
                    result.map_err(|e| CredentialError::ExecFailed(None, e.to_string()))?
                }
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

            if !output.status.success() {
                // A helper's stderr is not vetted content: it can carry
                // diagnostics that echo token material (e.g. under `set -x`,
                // or a partial-write bug). `redact_error_body`'s shape-based
                // patterns are the only thing that ever sees this text, and
                // it is hard-truncated regardless, since a persisted
                // `CredentialError` derives `Display`/`Debug`.
                let redacted = roundhouse_provider::audit::redact_error_body(
                    &String::from_utf8_lossy(&output.stderr),
                );
                let truncated: String = redacted.chars().take(MAX_STDERR_CHARS).collect();
                return Err(CredentialError::ExecFailed(output.status.code(), truncated));
            }

            if output.stdout.len() > MAX_STDOUT_BYTES {
                return Err(CredentialError::ExecFailed(
                    output.status.code(),
                    format!("credential helper stdout exceeded {MAX_STDOUT_BYTES} bytes"),
                ));
            }

            let token = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if token.is_empty() {
                return Err(CredentialError::ExecFailed(
                    output.status.code(),
                    "credential helper produced empty stdout".to_string(),
                ));
            }

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
