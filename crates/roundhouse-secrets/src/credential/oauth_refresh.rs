use crate::secret::Secret;
use futures::StreamExt;
use roundhouse_provider::credential::{CredentialCtx, CredentialError, CredentialProvider};
use roundhouse_provider::{BoxFut, HttpRequest};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

struct CachedToken {
    value: Secret,
    expires_at: Instant,
}

/// OAuth2 client-credentials grant, with a single-flight refresh cache.
///
/// Single-flight is achieved via the cache mutex itself: `apply` holds the
/// lock across the *entire* refresh — including the network await — so a
/// concurrent caller that arrives while a refresh is in flight blocks on the
/// same lock and, once it acquires it, observes the freshly-cached token
/// instead of firing its own request.
pub struct OAuthRefreshCredential {
    refresh_url: String,
    client_id: String,
    client_secret: Secret,
    /// §9.9: "single-flight, 60s skew."
    skew: Duration,
    cached: Mutex<Option<CachedToken>>,
}

#[derive(serde::Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    expires_in: u64,
}

impl OAuthRefreshCredential {
    pub fn new(
        refresh_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: Secret,
    ) -> Self {
        Self {
            refresh_url: refresh_url.into(),
            client_id: client_id.into(),
            client_secret,
            skew: Duration::from_secs(60),
            cached: Mutex::new(None),
        }
    }
}

impl CredentialProvider for OAuthRefreshCredential {
    fn apply<'a>(
        &'a self,
        req: &'a mut HttpRequest,
        ctx: &'a CredentialCtx<'a>,
    ) -> BoxFut<'a, Result<(), CredentialError>> {
        Box::pin(async move {
            let mut guard = self.cached.lock().await;
            if let Some(tok) = guard.as_ref() {
                if tok.expires_at.saturating_duration_since(ctx.now) > self.skew {
                    super::apply_bearer_secret(&tok.value, req);
                    return Ok(());
                }
            }

            // The exposure closure is synchronous, so the request body is
            // built entirely inside it and returned; the async `send` below
            // happens outside the closure, over the already-serialized bytes
            // — never over the exposed `&str` itself. This is the crate's
            // second physical exposure call site: distinct secret
            // (`client_secret`, not a resolved bearer token) and distinct
            // purpose (authenticating to the token endpoint), so it cannot
            // reuse `apply_bearer_secret`.
            let body =
                crate::provider_bridge::expose_secret_for_provider_call(&self.client_secret, |s| {
                    serde_json::to_vec(&serde_json::json!({
                        "grant_type": "client_credentials",
                        "client_id": self.client_id,
                        "client_secret": s,
                    }))
                    .expect("static shape always serializes")
                });

            let resp = ctx
                .transport
                .send(HttpRequest {
                    method: "POST".into(),
                    url: self.refresh_url.clone(),
                    headers: vec![("content-type".to_string(), "application/json".to_string())],
                    body,
                })
                .await
                .map_err(|e| CredentialError::RefreshFailed(e.to_string()))?;

            let mut body_bytes = Vec::new();
            let mut stream = resp.body;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|e| CredentialError::RefreshFailed(e.to_string()))?;
                body_bytes.extend_from_slice(&chunk);
            }
            let parsed: OAuthTokenResponse = serde_json::from_slice(&body_bytes)
                .map_err(|e| CredentialError::RefreshFailed(e.to_string()))?;

            let fresh = CachedToken {
                value: Secret::new(parsed.access_token),
                expires_at: ctx.now + Duration::from_secs(parsed.expires_in),
            };
            super::apply_bearer_secret(&fresh.value, req);
            *guard = Some(fresh);
            Ok(())
        })
    }
}
