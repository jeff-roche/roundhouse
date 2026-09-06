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

/// Strict RFC 3986 percent-decoding — deliberately NOT
/// `application/x-www-form-urlencoded` decoding, which treats a literal `+`
/// as an encoded space. Used only by [`canonical_query`] (see its doc
/// comment) to undo the percent-encoding `url::Url` applies to the raw
/// query string at parse time, so query canonicalization re-encodes the
/// actual literal characters AWS's algorithm expects, not `url`'s
/// already-encoded output a second time.
///
/// **Deliberately NOT used by [`canonical_uri`] any more** (C1, fix-round-3):
/// an earlier version of this fix decoded `url.path()` before
/// re-encoding it, which seemed parallel to the query fix but was wrong for
/// the path — see `canonical_uri`'s doc comment for why decode-then-encode
/// is only correct for the query, not the path.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let Some(hex) = s.get(i + 1..i + 3) {
                // C2 (fix-round-3): `u8::from_str_radix` alone accepts a
                // leading `+` (Rust integer parsing is more permissive than
                // a hex-pair grammar), so `%+f` would decode to `0x0F`
                // identically to `%0f` — a second aliasing, and a real
                // deviation from "strict RFC 3986" above. Require both
                // characters to actually be hex digits first.
                if hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    if let Ok(byte) = u8::from_str_radix(hex, 16) {
                        out.push(byte);
                        i += 3;
                        continue;
                    }
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// AWS's "CanonicalURI" (SigV4 "Task 1"): `url.path()` treated as
/// **already the wire form**, URI-encoded once more for every service
/// except S3 (which signs the path exactly as it appears on the wire, with
/// no further encoding).
///
/// `url::Url` **preserves percent-escapes verbatim** in the path — it does
/// not decode them at parse time, confirmed empirically against `url 2.5`
/// (`https://h/a%2Fb` parses to path `/a%2Fb`, not `/a/b`). So `url.path()`
/// already IS the once-encoded canonical form for a non-S3 service, and the
/// literal string S3 needs.
///
/// **C1 (fix-round-3, Important): do NOT percent-decode `path` here before
/// re-encoding it**, even though [`canonical_query`] correctly does exactly
/// that for the query string. An earlier version of this function did:
/// `percent_decode(path)` then `uri_encode(_, true)` with `preserve_slash:
/// true`. That makes `/` a fixed point of the round-trip, which erases the
/// distinction between a literal wire `/` (a path-segment delimiter) and an
/// *encoded* `%2F` inside a single segment — `/a%2Fb` and `/a/b` are two
/// different resources on the wire, but the decode-then-preserve-slash
/// version canonicalized both to `/a/b` and therefore signed them
/// identically. It also contradicted its own reasoning: this function
/// treats S3 specially because "S3 object keys can contain `%`-sequences
/// that must not be re-escaped" — and then the decode step un-escaped them
/// first, before that special case ever got a chance to matter. Percent-
/// decoding a path before AWS's own encode-once/-twice step is simply not
/// part of SigV4's algorithm; treating `url.path()` as already-encoded and
/// re-encoding *that* string is.
fn canonical_uri(path: &str, service: &str) -> String {
    let path = if path.is_empty() { "/" } else { path };
    if is_s3_family_service(service) {
        path.to_string()
    } else {
        uri_encode(path, true)
    }
}

/// `true` for a SigV4 `service` name in the S3 family — every one of which
/// shares S3's literal-path canonicalization (see [`canonical_uri`]'s doc
/// comment). Widened (Task 31 item 6, Phase 7 U4) from an exact match on
/// `"s3"`, which missed two real, currently-shipped AWS service names:
/// `s3-outposts` (S3 on Outposts) and `s3express` (S3 Express One Zone).
/// Both fell through to the generic double-encoding branch, producing a
/// signature AWS rejects for any request whose path contains a character
/// URI-encoding changes (`%`, a space, or a pre-encoded `%2F` inside one
/// segment).
///
/// **An explicit, case-insensitive ALLOWLIST — not a prefix match** (fix
/// round 1, Ruling R35; the first version of this fix used a prefix match
/// and its justifying comment was WRONG). Checked directly against
/// botocore's own service models, where `metadata.signatureVersion` is
/// exactly this single-vs-double-encode flag: `s3` and `s3control` have
/// signingName `s3` and single-encode (the S3 family), but **`s3tables`**
/// (signatureVersion `v4`, signingName `s3tables`) and **`s3vectors`**
/// (signatureVersion `v4`, signingName `s3vectors`) both need
/// DOUBLE-encoding despite the name. Both are real, currently-shipping AWS
/// services whose signing name happens to start with `s3` but are NOT part
/// of this literal-path family — so `starts_with("s3")` silently
/// misclassified both. An allowlist of the services actually known to need
/// single-encoding is the only shape that can't be fooled by a future
/// `s3`-prefixed, non-S3-family service name; a `contains` match would have
/// the same problem plus a worse false-positive direction (matching a
/// hypothetical unrelated service that merely has `s3` somewhere *inside*
/// its name, e.g. `costs3-reports`).
///
/// `s3-object-lambda` is included: a real S3-family signing name, covered
/// for free by the old (wrong) prefix match, kept here deliberately.
///
/// **`s3-outposts` is a deliberate, documented choice under genuine
/// ambiguity**, not an oversight: the same signing name serves both the S3
/// data-plane path on Outposts (single-encode, like `s3`) and a separate
/// standalone "Outposts" control-plane API (double-encode) — real AWS SDKs
/// disambiguate this by which client/endpoint configuration constructed the
/// request, not by service name alone, information this function does not
/// have. Listing it here is the data-plane reading, matching this crate's
/// actual use (signing requests to an S3-shaped endpoint).
fn is_s3_family_service(service: &str) -> bool {
    matches!(
        service.to_ascii_lowercase().as_str(),
        "s3" | "s3express" | "s3-outposts" | "s3-object-lambda"
    )
}

/// AWS's "CanonicalQueryString": every parameter name/value URI-encoded
/// (slashes included — unlike the path, a query value is not segmented),
/// then sorted by encoded name (ties broken by encoded value), joined with
/// `&`. Built by splitting the URL's RAW query string on `&`/`=` and
/// percent-decoding each piece with [`percent_decode`] — NOT
/// `Url::query_pairs()`, which form-decodes and therefore turns a literal
/// `+` in a query value into a space before this function ever sees it (B3,
/// fix-round-2): `?b=x+y` would have canonicalized as `b=x%20y` (silently
/// changing what's being signed) instead of the correct `b=x%2By`.
fn canonical_query(url: &url::Url) -> String {
    let raw = url.query().unwrap_or("");
    let mut pairs: Vec<(String, String)> = raw
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let k = parts.next().unwrap_or("");
            let v = parts.next().unwrap_or("");
            (percent_decode(k), percent_decode(v))
        })
        .map(|(k, v)| (uri_encode(&k, false), uri_encode(&v, false)))
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// AWS's canonicalization rule for a header value: trim leading/trailing
/// whitespace AND collapse internal runs of whitespace into a single space
/// (B3, fix-round-2 — the previous version only trimmed the ends).
fn canonicalize_header_value(v: &str) -> String {
    v.split_whitespace().collect::<Vec<_>>().join(" ")
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
            .push(canonicalize_header_value(v));
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

#[cfg(test)]
mod tests {
    use super::{canonical_uri, uri_encode};

    /// Task 31 item 6, Phase 7 U4: real S3-family services with a signing
    /// name other than the bare `"s3"` must get S3's literal-path
    /// treatment, not the generic double-encoding path the old exact match
    /// fell back to.
    #[test]
    fn s3_outposts_and_s3express_get_s3s_literal_path_treatment() {
        let path = "/bucket/key%2Fwith-percent and space";
        let s3_treatment = canonical_uri(path, "s3");
        assert_eq!(canonical_uri(path, "s3-outposts"), s3_treatment);
        assert_eq!(canonical_uri(path, "s3express"), s3_treatment);
        assert_eq!(canonical_uri(path, "S3EXPRESS"), s3_treatment);
        // Sanity: the literal-path treatment is actually observably
        // different from the generic branch for this path, so the
        // assertions above are not vacuously true.
        assert_ne!(s3_treatment, uri_encode(path, true));
    }

    /// The widened match must stay a PREFIX match, not a `contains` match:
    /// a service name that merely has `s3` somewhere inside it, but doesn't
    /// start with it, must still get the generic (non-S3) treatment.
    #[test]
    fn a_service_name_merely_containing_s3_is_not_treated_as_s3() {
        let path = "/bucket/key%2Fwith-percent and space";
        let generic = canonical_uri(path, "execute-api");
        assert_eq!(canonical_uri(path, "costs3-reports"), generic);
        assert_ne!(
            canonical_uri(path, "costs3-reports"),
            canonical_uri(path, "s3")
        );
    }

    /// Fix round 1 (Ruling R35): `s3tables` and `s3vectors` are real,
    /// currently-shipping AWS SigV4 service names (botocore's own service
    /// models: `metadata.signatureVersion = "v4"`, i.e. plain double-encode,
    /// for both) that happen to START WITH `s3` but are NOT part of the S3
    /// literal-path family. A plain prefix match misclassifies both into
    /// S3's branch; the allowlist below must not.
    #[test]
    fn s3tables_and_s3vectors_are_not_treated_as_s3_despite_the_s3_prefix() {
        let path = "/bucket/key%2Fwith-percent and space";
        let generic = canonical_uri(path, "execute-api");
        assert_eq!(canonical_uri(path, "s3tables"), generic);
        assert_eq!(canonical_uri(path, "s3vectors"), generic);
        assert_ne!(canonical_uri(path, "s3tables"), canonical_uri(path, "s3"));
        assert_ne!(canonical_uri(path, "s3vectors"), canonical_uri(path, "s3"));
    }

    /// `s3-object-lambda` is a real S3-family signing name (also covered
    /// for free by the old prefix match, but never pinned by a test) --
    /// keep it in the explicit allowlist.
    #[test]
    fn s3_object_lambda_gets_s3s_literal_path_treatment() {
        let path = "/bucket/key%2Fwith-percent and space";
        assert_eq!(
            canonical_uri(path, "s3-object-lambda"),
            canonical_uri(path, "s3")
        );
    }
}
