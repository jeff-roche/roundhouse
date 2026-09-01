use crate::secret::Secret;
use hmac::{Hmac, Mac};
use roundhouse_provider::credential::{CredentialCtx, CredentialError, CredentialProvider};
use roundhouse_provider::{BoxFut, HttpRequest};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

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

/// RFC 3986 `%XX`-encodes every byte outside the unreserved set
/// (`A-Za-z0-9-_.~`). AWS's canonicalization rules preserve `/` unescaped
/// inside a canonical *path* (it's the segment separator) but require it
/// escaped like any other reserved character inside a canonical *query*
/// key/value — `preserve_slash` selects which.
fn uri_encode(s: &str, preserve_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b'/' if preserve_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// AWS's "CanonicalURI" (SigV4 "Task 1"): the request path, URI-encoded
/// once for every service, and encoded a **second** time for every service
/// except S3, which signs against the once-encoded path (S3 object keys can
/// themselves contain `%`-sequences that must not be re-escaped). `url`'s
/// own path is already RFC 3986-normalized (dot-segments resolved) by the
/// `url` crate at parse time, so only the encode step is this function's
/// job.
fn canonical_uri(path: &str, service: &str) -> String {
    let path = if path.is_empty() { "/" } else { path };
    let once = uri_encode(path, true);
    if service.eq_ignore_ascii_case("s3") {
        once
    } else {
        uri_encode(&once, true)
    }
}

/// AWS's "CanonicalQueryString": every parameter name/value URI-encoded
/// (slashes included — unlike the path, a query value is not segmented),
/// then sorted by encoded name (ties broken by encoded value), joined with
/// `&`. Built from the URL's already-*decoded* query pairs
/// (`Url::query_pairs`), not the raw query string, so a value's own
/// `&`/`=`/`%` bytes are re-encoded correctly rather than assumed
/// already-canonical.
fn canonical_query(url: &url::Url) -> String {
    let mut pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (uri_encode(&k, false), uri_encode(&v, false)))
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// AWS's "CanonicalHeaders" + "SignedHeaders": header names lowercased,
/// same-named headers merged into ONE comma-joined value on ONE line (never
/// repeated as separate canonical-header lines or repeated entries in
/// `SignedHeaders`), sorted by name via `BTreeMap`.
fn canonical_headers_and_signed(headers: &[(String, String)]) -> (String, String) {
    let mut merged: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (k, v) in headers {
        merged
            .entry(k.to_lowercase())
            .or_default()
            .push(v.trim().to_string());
    }
    let canonical_headers: String = merged
        .iter()
        .map(|(k, vs)| format!("{k}:{}\n", vs.join(",")))
        .collect();
    let signed_headers = merged.keys().cloned().collect::<Vec<_>>().join(";");
    (canonical_headers, signed_headers)
}

/// Signs one request in place (SigV4, service-scoped). This and
/// `HeaderKeyCredential::apply` are the module's other two physical
/// exposure call sites: HMAC key derivation from `secret_key`, and (when
/// present) the `x-amz-security-token` header from `session_token`.
///
/// Idempotent per `CredentialProvider::apply`'s documented contract: strips
/// any `x-amz-date`/`host`/`x-amz-security-token`/`authorization` header a
/// previous signing pass on this same request left behind before signing
/// again, so a retried request is re-signed cleanly instead of folding a
/// stale `authorization` value into the next canonical-headers hash.
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
    for name in [
        "x-amz-date",
        "host",
        "x-amz-security-token",
        "authorization",
    ] {
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    }

    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();
    let host = url
        .host_str()
        .ok_or_else(|| CredentialError::SigningFailed("SigV4 target has no host".into()))?;
    // Include the port when it's non-default for the scheme, so the signed
    // `Host` matches what the transport actually sends — `Url::port()`
    // already returns `None` for the scheme's default port.
    let host_header = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };

    headers.push(("x-amz-date".to_string(), amz_date.clone()));
    headers.push(("host".to_string(), host_header));
    if let Some(token) = session_token {
        crate::provider_bridge::expose_secret_for_provider_call(token, |s| {
            headers.push(("x-amz-security-token".to_string(), s.to_string()));
        });
    }

    let (canonical_headers, signed_headers) = canonical_headers_and_signed(headers);

    let canonical_request = format!(
        "{method}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{body_hash}",
        path = canonical_uri(url.path(), service),
        query = canonical_query(url),
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
