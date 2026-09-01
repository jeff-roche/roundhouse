use crate::secret::Secret;
use roundhouse_provider::credential::{CredentialCtx, CredentialError, CredentialProvider};
use roundhouse_provider::{BoxFut, HttpRequest};

/// Runs a configured external helper command and treats its stdout (trimmed)
/// as a bearer token. Common for credential helpers that print a
/// short-lived token to stdout (e.g. a cloud CLI's `print-access-token`).
pub struct ExecCommandCredential {
    command: String,
    args: Vec<String>,
}

impl ExecCommandCredential {
    pub fn new(command: String, args: Vec<String>) -> Self {
        Self { command, args }
    }
}

impl CredentialProvider for ExecCommandCredential {
    fn apply<'a>(
        &'a self,
        req: &'a mut HttpRequest,
        _ctx: &'a CredentialCtx<'a>,
    ) -> BoxFut<'a, Result<(), CredentialError>> {
        Box::pin(async move {
            let output = tokio::process::Command::new(&self.command)
                .args(&self.args)
                .output()
                .await
                .map_err(|e| CredentialError::ExecFailed(None, e.to_string()))?;
            if !output.status.success() {
                return Err(CredentialError::ExecFailed(
                    output.status.code(),
                    String::from_utf8_lossy(&output.stderr).into_owned(),
                ));
            }
            let token = String::from_utf8_lossy(&output.stdout).trim().to_string();
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
