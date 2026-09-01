use crate::secret::Secret;
use roundhouse_provider::credential::{CredentialCtx, CredentialError, CredentialProvider};
use roundhouse_provider::{BoxFut, HttpRequest};

/// A static, pre-issued bearer token — the simplest of the six mechanisms.
pub struct BearerCredential {
    token: Secret,
}

impl BearerCredential {
    pub fn new(token: Secret) -> Self {
        Self { token }
    }
}

impl CredentialProvider for BearerCredential {
    fn apply<'a>(
        &'a self,
        req: &'a mut HttpRequest,
        _ctx: &'a CredentialCtx<'a>,
    ) -> BoxFut<'a, Result<(), CredentialError>> {
        Box::pin(async move {
            super::apply_bearer_secret(&self.token, req);
            Ok(())
        })
    }
}
