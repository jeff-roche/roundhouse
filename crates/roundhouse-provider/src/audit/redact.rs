//! §9.9: "a final redaction pass regexes every persisted error body for
//! API-key-shaped strings, bearer tokens, and JWTs, because providers echo
//! request bodies in 400s more often than you'd like."
//!
//! **This is deliberately a second, complementary mechanism, not a
//! duplicate of Phase 2's redactor** (`roundhouse_store::redact::Redactor`).
//! Phase 2's is a known-literal Aho-Corasick matcher: it scrubs secret
//! *values Phase 2 already resolved and holds a reference to* out of
//! arbitrary log lines, at the persistence boundary, before an
//! `EventPayload` is ever serialized. This one has no literal to look for —
//! it runs on provider error-body text specifically, which can echo back a
//! key that was never resolved through Phase 2's path at all (e.g. a stale
//! or mistyped key rejected before credential resolution completes), so it
//! matches by *shape* instead of by known value. `roundhouse-provider`
//! cannot depend on `roundhouse-store` (that dependency runs the other
//! direction), so this genuinely has to be a separate layer, not a shared
//! helper.
//!
//! Coverage is deliberately broad (fail-closed over fail-open): every shape
//! this phase's own six `CredentialProvider` mechanisms actually produce —
//! `sk-`/`pk-`/`rk-`-prefixed opaque keys, bearer tokens, JWTs, AWS access
//! key IDs, Google API keys, and (via a label-anchored fallback, since
//! neither has a fixed shape) Azure `client_secret` values and AWS secret
//! access keys — is covered. `regex`'s engine is linear-time by
//! construction, so broadening this has no backtracking/ReDoS cost.

use regex::{Captures, Regex};
use std::sync::LazyLock;

static API_KEY_SHAPED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(sk|pk|rk)-[A-Za-z0-9_-]{16,}\b").unwrap());
static BEARER_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Bearer\s+[A-Za-z0-9._-]{8,}").unwrap());
/// Only a JWT's *header* segment is guaranteed to start `eyJ` — it's the
/// base64 of a JSON object whose leading `{"` bytes are shared by every JWT
/// header regardless of its fields. The *payload* segment's leading bytes
/// depend on its own first claim's key and are not guaranteed to start
/// `eyJ` too. An earlier version of this pattern required both segments to
/// start `eyJ`, which under-matched real JWTs whose claims happen to encode
/// to a different leading sequence.
static JWT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}").unwrap()
});
/// AWS access-key-ID shapes. An access key ID is an identifier, not signing
/// material (see `sigv4.rs`'s doc comment), but it's still worth redacting
/// alongside the values that are actual secrets — narrows what an attacker
/// would need to guess.
static AWS_ACCESS_KEY_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b").unwrap());
/// Google API keys: fixed `AIza` prefix, fixed total length.
static GOOGLE_API_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bAIza[A-Za-z0-9_-]{35}\b").unwrap());
/// Label-anchored fallback for shapes with no fixed, recognizable prefix of
/// their own: Azure `client_secret` values, AWS secret access keys (a bare
/// 40-character base64-ish string is too weak a signal to match
/// unlabeled — false-positive city over arbitrary text), and any other
/// provider's opaque token. Anchored on a nearby field-name label so it
/// doesn't fire on arbitrary base64-shaped text with no such context.
static LABELED_SECRET_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(client[_-]?secret|secret[_-]?access[_-]?key|api[_-]?key|access[_-]?token)["']?\s*[:=]\s*["']?[A-Za-z0-9/_+.~-]{16,}"#,
    )
    .unwrap()
});

pub fn redact_error_body(body: &str) -> String {
    let redacted = JWT.replace_all(body, "[REDACTED-JWT]");
    let redacted = BEARER_TOKEN.replace_all(&redacted, "Bearer [REDACTED]");
    let redacted = LABELED_SECRET_VALUE.replace_all(&redacted, |caps: &Captures| {
        format!("{}=[REDACTED]", &caps[1])
    });
    let redacted = AWS_ACCESS_KEY_ID.replace_all(&redacted, "[REDACTED-AWS-KEY-ID]");
    let redacted = GOOGLE_API_KEY.replace_all(&redacted, "[REDACTED-GOOGLE-KEY]");
    let redacted = API_KEY_SHAPED.replace_all(&redacted, "[REDACTED-KEY]");
    redacted.into_owned()
}
