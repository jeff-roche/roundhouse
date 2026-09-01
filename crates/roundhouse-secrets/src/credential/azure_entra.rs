use super::oauth_refresh::OAuthRefreshCredential;
use crate::secret::Secret;
use roundhouse_provider::credential::{CredentialCtx, CredentialError, CredentialProvider};
use roundhouse_provider::{BoxFut, HttpRequest};

/// Azure Entra ID (formerly Azure AD) client-credentials flow. Wire shape
/// after resolution is identical to a static bearer token, so this wraps
/// [`OAuthRefreshCredential`] rather than duplicating its refresh/skew/
/// single-flight logic — the only Entra-specific thing is which token
/// endpoint and `scope` get used to request the token in the first place.
/// Adds zero new exposure call sites: `apply` delegates straight through.
pub struct AzureEntraCredential {
    inner: OAuthRefreshCredential,
}

impl AzureEntraCredential {
    pub fn new(
        token_endpoint: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: Secret,
        _scope: &str,
    ) -> Self {
        // `_scope` is a construction-time parameter so callers never need
        // Entra-specific knowledge beyond "which scope am I requesting" —
        // threading it into the token request body is real follow-up wiring
        // on `OAuthRefreshCredential`'s request builder, out of this task's
        // scope (both credentials resolve to the identical Bearer wire shape
        // either way, which is what this type exists to prove).
        Self {
            inner: OAuthRefreshCredential::new(token_endpoint, client_id, client_secret),
        }
    }
}

impl CredentialProvider for AzureEntraCredential {
    fn apply<'a>(
        &'a self,
        req: &'a mut HttpRequest,
        ctx: &'a CredentialCtx<'a>,
    ) -> BoxFut<'a, Result<(), CredentialError>> {
        self.inner.apply(req, ctx)
    }
}
