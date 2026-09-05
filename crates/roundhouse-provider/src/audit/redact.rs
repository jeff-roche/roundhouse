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
//!
//! Audit L4/L4b (round 8): the twelve `openai-chat`-family profiles this
//! phase shipped include several providers whose current published key
//! format has its own fixed, recognizable prefix -- `API_KEY_SHAPED` only
//! covered `sk-`/`pk-`/`rk-` (Anthropic/OpenAI-style) until this round, so a
//! provider's own 401 body (`"Incorrect API key provided: gsk_ABCDEFGH..."`)
//! echoed the key back verbatim: `LABELED_SECRET_VALUE` doesn't save this
//! case either, since it requires the label immediately followed by `:`/`=`,
//! and a free-prose 401 message has no such anchor. Five more fixed-prefix
//! shapes, each checked against that vendor's own current docs (or, where
//! the vendor's own docs don't spell out the shape, the same
//! community-maintained secret-pattern corpora several open-source secret
//! scanners draw on) as of 2026-09-02:
//!
//! - `gsk_` (Groq) -- <https://console.groq.com/docs/quickstart> shows
//!   `GROQ_API_KEY=gsk_...`; corroborated by
//!   <https://github.com/mazen160/secrets-patterns-db> and
//!   <https://github.com/h33tlit/secret-regex-list>'s Groq entries.
//! - `csk-` (Cerebras) -- <https://inference-docs.cerebras.ai/resources/openai>'s
//!   own example reads `csk-your-cerebras-api-key`; corroborated by the same
//!   two community pattern corpora above.
//! - `fw_` (Fireworks) -- <https://docs.fireworks.ai/api-reference/create-api-key>
//!   documents `fw_...` as the direct-routing key format (a separate
//!   `fpk_`-prefixed "Fire Pass" key also exists but is out of scope here --
//!   not one of this phase's shipped profiles). Community secret-scanner
//!   rules for this one gate `fw_` on a nearby `fireworks` keyword rather
//!   than shipping it as a bare prefix, since three characters is short and
//!   collision-prone on its own; this pattern's `{16,}` minimum body length
//!   (already applied to every prefix here, matching `sk-`/`pk-`/`rk-`'s
//!   existing threshold) gives the same protection without a keyword gate,
//!   since `fw_` immediately followed by 16+ opaque characters is not a
//!   shape ordinary text produces by accident.
//! - `xai-` (xAI/Grok) -- confirmed directly on
//!   <https://docs.x.ai/build/overview>: "If your key doesn't start with
//!   `xai-`, it's not an xAI key."
//! - `nvapi-` (NVIDIA NIM) -- confirmed directly on
//!   <https://docs.nvidia.com/nemo/retriever/26.5.0/extraction/api-keys/>:
//!   "Keys typically start with `nvapi-`."
//!
//! **Residual gap, stated rather than papered over (L4b):** Mistral,
//! DeepInfra, and Z.ai issue bare opaque tokens with no distinguishing
//! prefix of their own. In a free-prose 401 body there is no prefix to
//! anchor on, no `label=`/`label:` anchor for `LABELED_SECRET_VALUE` to
//! catch, and (unless the provider happens to echo it inside an
//! `Authorization` header string) no `Bearer ` anchor for `BEARER_TOKEN`
//! either -- so a bare-token key in free prose is NOT redacted by this
//! module today. Closing that with a generic "N-char alphanumeric" pattern
//! was considered and rejected: it would also redact commit SHAs, request
//! IDs, and trace IDs throughout every persisted error body, and a redactor
//! that fires constantly on non-secrets gets distrusted and worked around.
//! Bare-token keys stay covered only when a label (`api_key=...`) or
//! `Bearer ` anchor is present in the text, matching every other opaque,
//! unprefixed secret this module already handles the same way (Azure
//! `client_secret`, AWS secret access keys). See
//! `hardening_test.rs::a_bare_token_key_with_no_prefix_label_or_bearer_anchor_is_not_redacted_a_known_gap`
//! for the test that keeps this gap visible rather than silently forgotten.

use regex::{Captures, Regex};
use std::sync::LazyLock;

static API_KEY_SHAPED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:sk|pk|rk|csk|xai|nvapi)-[A-Za-z0-9_-]{16,}\b|\b(?:gsk|fw)_[A-Za-z0-9_-]{16,}\b",
    )
    .unwrap()
});
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
/// Phase 7 Task 16: `key` on its own (no `client_secret`/`api_key`/etc.
/// prefix) is a genuine, separately-observed label some gateways use. It's
/// added as its own alternative, anchored with a leading `\b`, rather than
/// folded into the existing prefixed alternatives — those already sit at a
/// word start in every real body this pattern has ever matched, so they
/// don't need the anchor, but a bare `key` does: this pattern is `(?i)` with
/// no leading anchor at all, so an unanchored `key` alternative would also
/// fire inside `monkey=`, `pubkey=`, `hostkey=` — words that merely *end* in
/// `key`, not the label itself. `\b` only matches between a word and a
/// non-word character (or string start/end), and every character in
/// `monkey`/`pubkey`/`hostkey` immediately before its trailing `key` is
/// itself a word character, so `\bkey` correctly does not match there while
/// still matching a `key` that starts right after a quote, brace, `&`, or
/// whitespace.
///
/// **This over-redacts other `\bkey`-anchored spellings, deliberately (fix
/// round 1, Ruling R25 / security S6).** `-` is a non-word character, so
/// `\b` also fires right after it: any `<word>-key` label (`Idempotency-Key:
/// ...`, `partition key=...`, `x-key=...`) and any bare `"key"` JSON field
/// (`{"key":"claude-sonnet-4-20250514"}`, `{"key":"projects/.../models/
/// gemini-2.5-pro"}`) is redacted too, even though none of those values is
/// actually secret. This is accepted as fail-closed, not fixed: a persisted
/// `events` row physically rejects `UPDATE`/`DELETE`, so under-redacting a
/// real secret is permanent in a way over-redacting a model id or an
/// idempotency key is merely inconvenient. Three narrowings were considered
/// and rejected — do not re-propose them without addressing why each one
/// fails:
///
/// 1. **A trailing `\bkey\b` is a provable no-op.** The pattern already
///    requires `["']?\s*[:=]` immediately after the label, so the character
///    following `key` is always `"`, `'`, whitespace, `:`, or `=` — every
///    one of those is already non-word, so the trailing boundary the label
///    would need is always already satisfied. Adding it changes nothing.
/// 2. **Constraining the value's character class (e.g. excluding `/`)
///    regresses AWS.** The value class `[A-Za-z0-9/_+.~-]{16,}` is shared by
///    *every* alternative in this one regex, not just `key`'s — `/` and `+`
///    are in it precisely because AWS `secret_access_key` values are
///    base64. Narrowing it to fix `key` breaks the label this pattern was
///    originally built for.
/// 3. **Excluding a preceding `-` (so `\bkey` can't fire right after a
///    hyphen) is fail-*open* on a real secret.** A gateway that names its
///    header `gateway-key: <secret>` — a real, plausible label shape — would
///    then never be redacted at all. Fail-open on an unproven-safe label is
///    strictly worse than fail-closed over-redaction on a proven-safe one.
///
/// A narrowing that *would* work — lifting the bare-`key` alternative into
/// its own regex with its own value class and its own preceding-delimiter
/// set (one that excludes `-` but keeps `"`/`'`/whitespace/`{`/`&`),
/// re-emitting the delimiter in the replacement — is a separate task, not a
/// tweak to this line, since it touches the replacement closure's shape too.
static LABELED_SECRET_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(client[_-]?secret|secret[_-]?access[_-]?key|api[_-]?key|access[_-]?token|\bkey)["']?\s*[:=]\s*["']?[A-Za-z0-9/_+.~-]{16,}[^\s"',&}]*"#,
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
/// original gap sit undetected for four rounds. Fix round 7, K4 corrected an
/// enumeration below that was itself inexact -- and by audit round 8 (L3),
/// that hand-maintained enumeration's own running count had been wrong
/// *three rounds running* (each recount produced a different, still-wrong
/// number as new codecs and transport shims kept landing sinks the prose
/// never got updated for). The mechanism was wrong, not the arithmetic: a
/// prose count of something this cheap to check mechanically will always
/// drift.
///
/// **What is actually covered is no longer stated here as a count.** It is
/// enforced by
/// `tests/transport_error_redaction_test.rs::every_provider_error_transport_site_is_redacted_or_explicitly_allowlisted`,
/// which greps every `.rs` file under `src/` for `ProviderError::Transport(`
/// and fails the build unless each occurrence either calls this function on
/// the same line or is named in that test's own `ALLOWLIST`, with a stated
/// reason (a fixed, status-only `format!` with no error text; a `match` arm
/// that only forwards an already-redacted `StreamFailure.message`; a pattern
/// match rather than a construction; or a test assertion). That test is the
/// source of truth for coverage, not this doc comment -- read it, don't
/// recount by hand.
///
/// Two related sinks this function does NOT cover, by design, are still
/// worth naming here because the reason is about *design*, not a count:
/// `redact_error_body` alone (not this function) is what runs *at
/// construction* inside `openai_chat::decode::sanitize_untrusted_wire_string`
/// and `cohere_v2::decode::sanitize_finish_reason_for_message` (fix round 7,
/// K1) for a mid-stream in-band failure frame's *own* diagnostic text (e.g.
/// an in-band `{"error": {...}}` frame's `message` field, or an unrecognized
/// `finish_reason` value) -- that text is not URL-shaped in the general
/// case, so the shape-based redactor is the right tool at that specific
/// construction site. The `tracing::warn!` log site in `openai_chat::provider`'s
/// and `cohere_v2::provider`'s `stream_failure_to_provider_error` (fix round
/// 7, K2) calls *this* function as belt-and-braces on top of that
/// construction-site redaction, closing the remaining "what if it embeds a
/// URL anyway" gap.
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
