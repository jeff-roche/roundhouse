use crate::secret::Secret;
use hmac::{Hmac, Mac};
use roundhouse_provider::credential::{CredentialCtx, CredentialError, CredentialProvider};
use roundhouse_provider::{BoxFut, HttpRequest};
use sha2::{Digest, Sha256};

/// AWS SigV4 request signing (§9.9). The AWS access-key ID is a plain
/// `String`, not wrapped in `Secret` — it is an identifier routinely visible
/// in AWS's own request signature and CloudTrail, not signing material.
/// `secret_key` and `session_token` (when present) are the only two pieces
/// of actual signing material, and each is read exactly once, only inside
/// [`sign`].
///
/// The service name (`"bedrock"`, `"execute-api"`, etc.) is a construction
/// parameter, never hardcoded here — a `Provider` adapter reads it from its
/// profile's `AuthKind::SigV4 { service }` (Task 4) and threads it through at
/// construction, so this type has no per-provider knowledge baked in.
pub struct SigV4Credential {
    access_key: String,
    secret_key: Secret,
    session_token: Option<Secret>,
    region: String,
    service: String,
}

impl SigV4Credential {
    pub fn new(
        access_key: impl Into<String>,
        secret_key: Secret,
        session_token: Option<Secret>,
        region: impl Into<String>,
        service: impl Into<String>,
    ) -> Self {
        Self {
            access_key: access_key.into(),
            secret_key,
            session_token,
            region: region.into(),
            service: service.into(),
        }
    }
}

impl CredentialProvider for SigV4Credential {
    fn apply<'a>(
        &'a self,
        req: &'a mut HttpRequest,
        _ctx: &'a CredentialCtx<'a>,
    ) -> BoxFut<'a, Result<(), CredentialError>> {
        Box::pin(async move {
            // For SigV4, "applying" a credential to a request IS signing it
            // — there is no header to attach independently of the
            // canonical-request hash, so `apply` and `sign` are the same
            // operation here (§12e/§12b of Phase 6's REALITY-CORRECTIONS: no
            // `Provider` impl special-cases SigV4; every credential kind goes
            // through this one `apply` call).
            let url = url::Url::parse(&req.url)
                .map_err(|e| CredentialError::SigningFailed(format!("invalid URL: {e}")))?;
            sign(
                &self.access_key,
                &self.secret_key,
                self.session_token.as_ref(),
                &self.region,
                &self.service,
                &req.method,
                &url,
                &mut req.headers,
                &req.body,
                chrono::Utc::now(),
            )
        })
    }
}

type HmacSha256 = Hmac<Sha256>;

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Signs one request in place (SigV4, service-scoped). This and
/// `HeaderKeyCredential::apply` are the module's other two physical
/// exposure call sites: HMAC key derivation from `secret_key`, and (when
/// present) the `x-amz-security-token` header from `session_token`.
#[allow(clippy::too_many_arguments)]
pub fn sign(
    access_key: &str,
    secret_key: &Secret,
    session_token: Option<&Secret>,
    region: &str,
    service: &str,
    method: &str,
    url: &url::Url,
    headers: &mut Vec<(String, String)>,
    body: &[u8],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), CredentialError> {
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();
    let host = url
        .host_str()
        .ok_or_else(|| CredentialError::SigningFailed("SigV4 target has no host".into()))?
        .to_string();

    headers.push(("x-amz-date".to_string(), amz_date.clone()));
    headers.push(("host".to_string(), host));
    if let Some(token) = session_token {
        crate::provider_bridge::expose_secret_for_provider_call(token, |s| {
            headers.push(("x-amz-security-token".to_string(), s.to_string()));
        });
    }

    let mut sorted = headers.clone();
    sorted.sort_by_key(|(k, _)| k.to_lowercase());
    let canonical_headers: String = sorted
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k.to_lowercase(), v.trim()))
        .collect();
    let signed_headers = sorted
        .iter()
        .map(|(k, _)| k.to_lowercase())
        .collect::<Vec<_>>()
        .join(";");

    let canonical_request = format!(
        "{method}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{body_hash}",
        path = url.path(),
        query = url.query().unwrap_or(""),
        body_hash = sha256_hex(body),
    );
    let credential_scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        sha256_hex(canonical_request.as_bytes()),
    );

    let signature = crate::provider_bridge::expose_secret_for_provider_call(secret_key, |s| {
        let k_date = hmac_sha256(format!("AWS4{s}").as_bytes(), date_stamp.as_bytes());
        let k_region = hmac_sha256(&k_date, region.as_bytes());
        let k_service = hmac_sha256(&k_region, service.as_bytes());
        let k_signing = hmac_sha256(&k_service, b"aws4_request");
        hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()))
    });

    headers.push((
        "authorization".to_string(),
        format!(
            "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
        ),
    ));
    Ok(())
}
