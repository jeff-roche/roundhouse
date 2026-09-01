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
    /// `scope` is threaded into the token request body — Entra's v2.0
    /// endpoint makes `scope` **required** for `grant_type=client_credentials`
    /// and returns `AADSTS900144` without it (this was a real, fixed defect
    /// in an earlier draft of this type, not an intentional omission).
    pub fn new(
        token_endpoint: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: Secret,
        scope: &str,
    ) -> Result<Self, CredentialError> {
        Ok(Self {
            inner: OAuthRefreshCredential::with_scope(
                token_endpoint,
                client_id,
                client_secret,
                Some(scope.to_string()),
            )?,
        })
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
