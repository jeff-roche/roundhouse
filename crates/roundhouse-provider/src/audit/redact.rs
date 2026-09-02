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
///
/// The trailing `[^\s"',&}]*` (fix-round-3, C3 — replacing fix-round-2 B4's
/// unbounded `\S*`) consumes any remaining characters of the value past the
/// initial 16-character run, up to the value's own delimiter: whitespace,
/// a closing quote, a comma, a `&` (form-encoded field separator), or a
/// closing `}` (JSON object terminator). B4 fixed a real bug — the
/// then-current pattern stopped at the first character outside
/// `[A-Za-z0-9/_+.~-]`, so a value containing punctuation
/// (`"abcdefghijklmnop!QRSTUVWX"`) redacted only its first 16 characters and
/// left the rest sitting in the persisted body untouched — but `\S*` has no
/// terminator except whitespace or end-of-string, so on a compact JSON or
/// form-encoded body (the common case: no whitespace between fields) it ran
/// to the end of the string, destroying every field after the labeled
/// secret. This is bounded to the value's own delimiters instead, so it
/// stops at the actual end of the value the way the surrounding
/// `["']?`/`\s*[:=]\s*` context already implies one exists.
static LABELED_SECRET_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(client[_-]?secret|secret[_-]?access[_-]?key|api[_-]?key|access[_-]?token)["']?\s*[:=]\s*["']?[A-Za-z0-9/_+.~-]{16,}[^\s"',&}]*"#,
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

/// Matches an embedded `http(s)://` URL inside a larger error-message string
/// (fix round 1, L3 -- `cohere_v2`) -- `reqwest::Error`'s `Display` appends
/// `for url (<full url>)` verbatim, query string and userinfo included, to a
/// transport error's text. Stops at the first whitespace, parenthesis, or
/// quote character, which is always where such an embedded URL ends in
/// practice (a bare URL token, not URL-encoded punctuation of that shape).
static EMBEDDED_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"https?://[^\s()'"]+"#).unwrap());

/// Redacts a transport-error message for safe inclusion in a public error
/// field: every embedded `http(s)://` URL is reduced to `host[:port]` via
/// the same host-only helper `resolve_base_url` already uses before a
/// base-URL override is ever persisted (`crate::credential::
/// record_base_url_override`), THEN the result is passed through
/// [`redact_error_body`] to catch anything else (a bearer token, an API key)
/// the error text might otherwise echo.
///
/// Without this, a gateway base URL carrying credentials in its query
/// string would leak them into a persisted error field. [`redact_error_body`]
/// alone does NOT strip a URL's query string or userinfo (it only matches a
/// labeled `api_key`/`access_token`/`client_secret`-shaped field of at least
/// 16 chars), so a gateway base URL's bare `?key=abc123` matches neither.
///
/// Fix round 1, L3 introduced this in `cohere_v2::decode` for its mid-stream
/// `StreamFailure.message`. Fix round 2, N2 promoted it to `cohere_v2::mod`
/// so `cohere_v2::provider`'s three other transport-error sinks (base-URL
/// resolution failure, credential-application failure, HTTP-send failure)
/// could share it. Fix round 4, R4: hoisted here (a pure move -- no logic
/// changes, this crate's `openai_chat::decode` made the identical claim
/// about its own `Transport`-kind message without ever calling this
/// function, which was false) so every codec in this crate shares the one
/// real implementation instead of `cohere_v2` alone having it, or a second,
/// weaker copy growing elsewhere.
///
/// That sharing claim was itself still false for four of six codecs until
/// fix round 5, H1: `openai_chat::provider`, `google_genai::provider`,
/// `openai_responses::provider`, and `bedrock_converse::provider` each had
/// three `ProviderError::Transport` sinks still calling plain
/// [`redact_error_body`] directly (the gap the previous paragraph's "was
/// false" already flagged for `openai_chat::decode`'s doc claim, but the
/// `provider.rs` sinks in all four files had the identical bug, not just the
/// comment). H1 switched all twelve of those sinks to this function.
///
/// Fix round 6, J5 narrows what "every codec in this crate" actually means,
/// rather than repeating a blanket claim of the same shape that let the
/// original gap sit undetected for four rounds. Fix round 7, K4 corrects two
/// enumerations below that were themselves inexact -- an over-broad or
/// merely-mostly-true claim in this doc comment is exactly what let the
/// original gap (and, separately, the K1/K2 defects fix round 7 fixes) sit
/// undetected across several rounds. What is covered, concretely, as of fix
/// round 7:
///
/// - Every `ProviderError::Transport` construction site in this crate that
///   can carry a `TransportError`'s or a credential/base-URL-resolution
///   error's text: all three `provider.rs` sinks in each of `openai_chat`,
///   `cohere_v2`, `google_genai`, `openai_responses`, and `bedrock_converse`,
///   plus `anthropic_provider.rs`'s single such sink (its `send(..)` call,
///   J4) -- `anthropic_provider.rs` has only ONE `ProviderError::Transport`
///   sink carrying error text, not three; its other `Transport` construction
///   site (`anthropic_provider.rs:100`) is a fixed, status-only
///   `format!("...{status}")` string with no error text to redact.
/// - Every mid-stream `StreamFailure.message` (or equivalent) construction
///   site that echoes a transport/framing error's `{e}` text directly:
///   `openai_chat::decode`'s and `cohere_v2::decode`'s one SSE-transport-error
///   site each, and `google_genai::decode`'s and `bedrock_converse::decode`'s
///   two SSE-transport-error sites each (`bedrock_converse::decode`'s second
///   is its eventstream-framing-error site, fix round 6, J3) -- six sites
///   total, all routed through this function.
/// - The `tracing::warn!` log site in `openai_chat::provider`'s and
///   `cohere_v2::provider`'s `stream_failure_to_provider_error` (fix round 7,
///   K2) -- belt-and-braces on top of the construction-site redaction the
///   next paragraph describes, since a `StreamFailure.message` built by
///   `sanitize_untrusted_wire_string`/`sanitize_finish_reason_for_message`
///   only ever runs the *shape*-based [`redact_error_body`], which does not
///   reduce an embedded URL's query string or userinfo.
///
/// Not covered by this function, by design: `redact_error_body` alone (not
/// this function) is what runs *at construction* inside
/// `openai_chat::decode::sanitize_untrusted_wire_string` and
/// `cohere_v2::decode::sanitize_finish_reason_for_message` (fix round 7, K1)
/// for a mid-stream in-band failure frame's *own* diagnostic text (e.g. an
/// in-band `{"error": {...}}` frame's `message` field, or an unrecognized
/// `finish_reason` value) -- that text is not URL-shaped in the general case,
/// so the shape-based redactor is the right tool at that specific
/// construction site. The `tracing::warn!` sink these construction sites feed
/// into, listed above, is what closes the remaining "what if it embeds a URL
/// anyway" gap.
pub(crate) fn redact_transport_error_text(raw: &str) -> String {
    let url_redacted = EMBEDDED_URL.replace_all(raw, |caps: &Captures| {
        crate::credential::record_base_url_override(&caps[0])
    });
    redact_error_body(&url_redacted)
}

#[cfg(test)]
mod redact_transport_error_text_tests {
    //! Fix round 1, L3: `redact_transport_error_text` must strip an embedded
    //! request URL down to host-only, on top of the crate's existing
    //! secret-shape redaction. Moved verbatim from `cohere_v2::mod`'s
    //! `redaction_tests` module (fix round 4, R4) -- unchanged.
    use super::redact_transport_error_text;

    #[test]
    fn strips_query_string_and_userinfo_from_an_embedded_url() {
        let raw = "transport io error: error sending request for url \
                    (https://user:pass@gateway.example.com/proxy?key=abc123): \
                    operation timed out";
        let redacted = redact_transport_error_text(raw);
        assert!(
            !redacted.contains("abc123"),
            "the query string's credential-shaped value must not survive: {redacted}"
        );
        assert!(
            !redacted.contains("user:pass"),
            "userinfo must not survive: {redacted}"
        );
        assert!(
            redacted.contains("gateway.example.com"),
            "the host itself is not secret and should stay, for diagnosability: {redacted}"
        );
        assert!(
            redacted.contains("operation timed out"),
            "the non-URL diagnostic text must survive redaction intact: {redacted}"
        );
    }

    #[test]
    fn a_message_with_no_url_at_all_passes_through_unchanged() {
        let raw = "connection reset by peer";
        assert_eq!(redact_transport_error_text(raw), raw);
    }

    /// The crate's general secret-shape redactor still applies on top of
    /// the URL-stripping pass -- a bearer token appearing outside any URL
    /// must also be caught.
    #[test]
    fn a_bearer_token_outside_any_url_is_still_redacted() {
        let raw = "unauthorized: Authorization: Bearer sk-test-abcdefgh12345678";
        let redacted = redact_transport_error_text(raw);
        assert!(!redacted.contains("sk-test-abcdefgh12345678"));
    }

    /// Fix round 2, N2: the same helper `decode.rs` uses for its mid-stream
    /// `StreamFailure.message` now also covers `provider.rs`'s three other
    /// transport-error sinks -- a gateway base URL's query-string credential
    /// must not survive a connection-failure error either.
    #[test]
    fn strips_a_gateway_query_string_from_a_connection_failure_message() {
        let raw = "error trying to connect: dns error: failed to lookup address \
                    information for url (https://gateway.example.com/proxy?key=abc123)";
        let redacted = redact_transport_error_text(raw);
        assert!(!redacted.contains("abc123"));
        assert!(redacted.contains("gateway.example.com"));
    }
}
