//! Cohere v2 `/v2/chat` wire-format codec. The task brief calls this surface
//! "Not spec-gated... a stable, well-documented shape," so this task doesn't
//! carry the formal fetched-OpenAPI-spec-verification gate/decision-doc the
//! other Phase 6 codec tasks do -- but REALITY-CORRECTIONS §13b names this
//! task explicitly ("binding on every remaining codec task (6, 7, 8, ...)"),
//! so every wire literal `decode.rs` matches on was still checked against the
//! real, fetched Cohere API reference rather than trusted from memory or the
//! task brief's unverified sketch:
//!
//! - `https://docs.cohere.com/reference/chat-stream` (fetched 2026-09-02):
//!   the 11 real SSE event `type` values -- `message-start`, `content-start`,
//!   `content-delta`, `content-end`, `citation-start`, `citation-end`,
//!   `tool-plan-delta`, `tool-call-start`, `tool-call-delta`,
//!   `tool-call-end`, `message-end` -- and verbatim example JSON for each,
//!   e.g. `content-start`: `{"delta":{"message":{"content":{"text":"",
//!   "type":"text"}}},"index":0,"type":"content-start"}`; `tool-call-start`:
//!   `{"delta":{"message":{"tool_calls":{"function":{"arguments":"","name":
//!   "..."},"id":"...","type":"function"}}},"index":0,"type":"tool-call-start"}`.
//!   Citations reuse the SAME `index` as the content block they annotate
//!   (verified from the fetched `citation-start` example), never a fresh one.
//! - `https://docs.cohere.com/reference/chat` (fetched 2026-09-02): the
//!   `finish_reason` enum's 6 real values (`COMPLETE`, `STOP_SEQUENCE`,
//!   `MAX_TOKENS`, `TOOL_CALL`, `ERROR`, `TIMEOUT`); the `messages[]`
//!   role/content shapes for `user`/`assistant`/`system`/`tool`, including
//!   the assistant content array's `"type": "thinking"` block (round-trips a
//!   prior turn's reasoning, unlike this crate's `google_genai`/
//!   `openai_responses` codecs, which fail closed on `Thinking` for their own
//!   documented reasons); the `tool_choice` enum's only two real values
//!   (`REQUIRED`/`NONE` -- there is no per-tool named-forcing mechanism, so
//!   `ToolChoice::Named` fails closed rather than silently widening the
//!   request into `"REQUIRED"`, per fix round 1's L4); and the `thinking`
//!   request field's shape (`{"type": "enabled"|"disabled", "token_budget":
//!   int}`).
//! - `https://docs.cohere.com/reference/errors` (fetched 2026-09-02): real
//!   Cohere error bodies are a plain `{"message": "..."}` string with no
//!   machine-readable code/type field at all -- see `profiles/cohere-v2.toml`'s
//!   own doc comment on what that means for this codec's `[errors]` table
//!   (deliberately empty, per fix round 1's L5).
//!
//! **A note for institutional memory (fix round 1, L12):** a `WebSearch`
//! query made during this task's initial verification pass returned a
//! plausible-looking summary claiming `finish_reason`'s real values are
//! LOWERCASE (`complete`, `max_tokens`, ...), sourced from a stale or
//! different page than the live reference. Re-fetching
//! `docs.cohere.com/reference/chat` directly and reading its own schema
//! section (not a search-engine summary of it) showed the real values are
//! UPPERCASE (`COMPLETE`, `MAX_TOKENS`, ...) -- confirmed independently by
//! two reviewers in fix round 1. The lesson: a search snippet is not the
//! same source as the page it summarizes, and a schema's own authoritative
//! enum beats any prose describing it, search-engine-summarized prose
//! included. The verified values are already committed in this module's
//! vendored `.txt` lists and doc comments; this paragraph exists only so a
//! future reader doesn't have to relearn why the check mattered.
//!
//! See `tests/cohere_v2_wire_literal_tripwire.rs` for the vendored literal
//! lists these values are checked against, and `tests/conformance_cohere_v2.rs`'s
//! module doc for where each cassette's bytes come from.
pub mod decode;
pub mod encode;
mod provider;

pub use provider::CohereV2Provider;

use regex::{Captures, Regex};
use std::sync::LazyLock;

/// Matches an embedded `http(s)://` URL inside a larger error-message string
/// (fix round 1, L3) -- `reqwest::Error`'s `Display` appends `for url
/// (<full url>)` verbatim, query string and userinfo included, to a
/// transport error's text. Stops at the first whitespace, parenthesis, or
/// quote character, which is always where such an embedded URL ends in
/// practice (a bare URL token, not URL-encoded punctuation of that shape).
static EMBEDDED_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"https?://[^\s()'"]+"#).unwrap());

/// Redacts a transport-error message for safe inclusion in a public error
/// field: every embedded `http(s)://` URL is reduced to `host[:port]` via
/// the same host-only helper `resolve_base_url` already uses before a
/// base-URL override is ever persisted (`crate::credential::
/// record_base_url_override`), THEN the result is passed through this
/// crate's general secret-shape redactor (`crate::audit::redact_error_body`)
/// to catch anything else (a bearer token, an API key) the error text might
/// otherwise echo.
///
/// Without this, a gateway base URL carrying credentials in its query
/// string (this codec's own `preserves_a_gateway_query_string` test proves
/// that shape is supported) would leak them into a persisted error field.
///
/// Fix round 1, L3 introduced this for `decode.rs`'s mid-stream
/// `StreamFailure.message`. Fix round 2, N2: promoted from `decode.rs` to
/// here so `provider.rs`'s three OTHER transport-error sinks (the base-URL
/// resolution failure, the credential-application failure, and the
/// HTTP-send failure) share the same redaction instead of each calling
/// `crate::audit::redact_error_body` alone -- which does NOT strip a URL's
/// query string or userinfo (it only matches a labeled `api_key`/
/// `access_token`/`client_secret`-shaped field of at least 16 chars), so a
/// gateway base URL's bare `?key=abc123` matched neither, and the
/// HTTP-send-failure sink in particular is reachable with exactly that
/// shape via this codec's own supported gateway-base-URL override.
fn redact_transport_error_text(raw: &str) -> String {
    let url_redacted = EMBEDDED_URL.replace_all(raw, |caps: &Captures| {
        crate::credential::record_base_url_override(&caps[0])
    });
    crate::audit::redact_error_body(&url_redacted)
}

#[cfg(test)]
mod redaction_tests {
    //! Fix round 1, L3: `redact_transport_error_text` must strip an embedded
    //! request URL down to host-only, on top of the crate's existing
    //! secret-shape redaction.
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
