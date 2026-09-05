use crate::secret::Secret;
use futures::StreamExt;
use roundhouse_provider::credential::{
    record_base_url_override, CredentialCtx, CredentialError, CredentialProvider,
};
use roundhouse_provider::{BoxFut, HttpRequest};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

struct CachedToken {
    value: Secret,
    expires_at: Instant,
}

/// A tight ceiling on the OAuth token endpoint's response body. Modelled on
/// `transport/eventstream.rs`'s `MAX_BUFFERED_BYTES`, but far smaller: a
/// client-credentials token response is a few hundred bytes of JSON
/// (`access_token`, `token_type`, `expires_in`, optionally `scope`), and
/// even a large opaque or JWT-shaped `access_token` comes nowhere near this.
/// This sits on the credential-resolution path (reached before any codec is
/// involved), so it is not covered by the seven codec `collect_body` copies'
/// recorded residual. Exceeding it is a reject, not a truncate: a truncated
/// token response must not be parsed as if it were complete.
const MAX_TOKEN_RESPONSE_BYTES: usize = 64 * 1024;

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
    /// Entra's v2.0 endpoint (and OAuth2 generally, when the authorization
    /// server requires it) makes `scope` a required field of the
    /// client-credentials grant. `None` for a plain OAuth2 server that
    /// doesn't need one.
    scope: Option<String>,
    /// §9.9: "single-flight, 60s skew."
    skew: Duration,
    cached: Mutex<Option<CachedToken>>,
}

#[derive(serde::Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    expires_in: u64,
}

/// Rejects a `refresh_url` that could route this credential's secret
/// material somewhere unintended: embedded userinfo (`https://user:pass@host/`)
/// would ride along on every token request, and a non-`https` scheme would
/// send the client secret in the clear.
///
/// **Never interpolates `raw` (or anything derived from it besides
/// [`record_base_url_override`]'s host-only form) into an error.** Fix-round-1's
/// A5 closed three leak paths where a `TransportError`'s `Display` could carry
/// embedded userinfo into a persisted error — round 2 found this function had
/// reopened exactly that class here: the rejection message for a URL
/// containing `user:s3cr3t@host` used to echo `raw` verbatim, meaning the
/// password ended up in the very error raised to reject it, and this
/// project persists error text onto physically-immutable `Event` rows.
/// `url::ParseError`'s `Display` (used in the parse-failure arm) is a
/// static, enum-driven description (e.g. "invalid port number") that never
/// echoes the input string, so that one is safe to interpolate as-is.
fn validate_refresh_url(raw: &str) -> Result<(), CredentialError> {
    let parsed = url::Url::parse(raw).map_err(|e| {
        CredentialError::InvalidBaseUrl(format!(
            "refresh_url for host `{}` is not a valid URL: {e}",
            record_base_url_override(raw)
        ))
    })?;
    if parsed.scheme() != "https" {
        return Err(CredentialError::InvalidBaseUrl(format!(
            "refresh_url for host `{}` must use https, got scheme `{}`",
            record_base_url_override(raw),
            parsed.scheme()
        )));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(CredentialError::InvalidBaseUrl(format!(
            "refresh_url for host `{}` must not contain embedded userinfo",
            record_base_url_override(raw)
        )));
    }
    Ok(())
}

impl OAuthRefreshCredential {
    /// Plain OAuth2 client-credentials grant with no `scope`. Use
    /// [`OAuthRefreshCredential::with_scope`] for an authorization server
    /// (e.g. Azure Entra) that requires one.
    pub fn new(
        refresh_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: Secret,
    ) -> Result<Self, CredentialError> {
        Self::with_scope(refresh_url, client_id, client_secret, None)
    }

    pub fn with_scope(
        refresh_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: Secret,
        scope: Option<String>,
    ) -> Result<Self, CredentialError> {
        let refresh_url = refresh_url.into();
        validate_refresh_url(&refresh_url)?;
        Ok(Self {
            refresh_url,
            client_id: client_id.into(),
            client_secret,
            scope,
            skew: Duration::from_secs(60),
            cached: Mutex::new(None),
        })
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
            //
            // RFC 6749 §4.4.2 (and both of Azure Entra's token endpoints)
            // require the client-credentials grant as
            // `application/x-www-form-urlencoded`, not JSON.
            let body =
                crate::provider_bridge::expose_secret_for_provider_call(&self.client_secret, |s| {
                    let mut form = url::form_urlencoded::Serializer::new(String::new());
                    form.append_pair("grant_type", "client_credentials");
                    form.append_pair("client_id", &self.client_id);
                    form.append_pair("client_secret", s);
                    if let Some(scope) = &self.scope {
                        form.append_pair("scope", scope);
                    }
                    form.finish().into_bytes()
                });

            let resp = ctx
                .transport
                .send(HttpRequest {
                    method: "POST".into(),
                    url: self.refresh_url.clone(),
                    headers: vec![(
                        "content-type".to_string(),
                        "application/x-www-form-urlencoded".to_string(),
                    )],
                    body,
                })
                .await
                .map_err(|_e| {
                    // Never interpolate `TransportError`'s `Display` here.
                    // Phase 7 U4 fix round 1 (Ruling R33) corrected this
                    // comment's originally-stated reason, which was wrong:
                    // `reqwest = 0.13.4`'s own error `Display` ends with
                    // `" for url ({url})"`, but `reqwest` itself STRIPS
                    // userinfo from that embedded URL before formatting the
                    // error — executed: a request to
                    // `http://user:pass@host/x` produces an error message
                    // containing `http://host/x`, no credentials. What
                    // `reqwest`'s `Display` does NOT strip is the QUERY
                    // STRING: `http://host/x?api_key=...` survives verbatim.
                    // So the real leak this guards against is a
                    // `refresh_url` carrying a secret in its query (e.g.
                    // `?client_secret=...`), not userinfo — report the host
                    // only regardless.
                    CredentialError::RefreshFailed(format!(
                        "token request to {} failed",
                        record_base_url_override(&self.refresh_url)
                    ))
                })?;

            if !(200..300).contains(&resp.status) {
                return Err(CredentialError::RefreshFailed(format!(
                    "token endpoint {} returned HTTP {}",
                    record_base_url_override(&self.refresh_url),
                    resp.status
                )));
            }

            let mut body_bytes = Vec::new();
            let mut stream = resp.body;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|_e| {
                    CredentialError::RefreshFailed(format!(
                        "reading token response from {} failed",
                        record_base_url_override(&self.refresh_url)
                    ))
                })?;
                if body_bytes.len().saturating_add(chunk.len()) > MAX_TOKEN_RESPONSE_BYTES {
                    return Err(CredentialError::RefreshFailed(format!(
                        "token response from {} exceeded the {MAX_TOKEN_RESPONSE_BYTES}-byte \
                         safety ceiling before completing",
                        record_base_url_override(&self.refresh_url)
                    )));
                }
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
