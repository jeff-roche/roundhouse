use crate::secret::Secret;
use roundhouse_provider::credential::{CredentialCtx, CredentialError, CredentialProvider};
use roundhouse_provider::{BoxFut, HttpRequest};

/// A secret value attached under a caller-configured header name (e.g.
/// `x-api-key`), rather than `Authorization: Bearer`.
pub struct HeaderKeyCredential {
    header: String,
    value: Secret,
}

impl HeaderKeyCredential {
    pub fn new(header: String, value: Secret) -> Self {
        Self { header, value }
    }
}

impl CredentialProvider for HeaderKeyCredential {
    fn apply<'a>(
        &'a self,
        req: &'a mut HttpRequest,
        _ctx: &'a CredentialCtx<'a>,
    ) -> BoxFut<'a, Result<(), CredentialError>> {
        Box::pin(async move {
            // Idempotent per `CredentialProvider::apply`'s documented
            // contract: drop any prior value under this same header name
            // before pushing, so a repeat `apply` (e.g. a retry) never
            // accumulates duplicates.
            req.headers
                .retain(|(k, _)| !k.eq_ignore_ascii_case(&self.header));
            // Distinct header name means this can't reuse
            // `apply_bearer_secret` (which always writes `authorization`),
            // so it is its own physical exposure call site.
            crate::provider_bridge::expose_secret_for_provider_call(&self.value, |s| {
                req.headers.push((self.header.clone(), s.to_string()));
            });
            Ok(())
        })
    }
}
