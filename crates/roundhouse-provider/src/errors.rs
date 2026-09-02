//! §9.8 — HTTP-response-to-`ProviderError` classification: a raw HTTP
//! status/body/headers from any LLM provider's API is mapped onto the
//! frozen `ProviderError` (`crate::ir::ProviderError`) via a three-tier
//! priority: provider-specific error code table, then message regex
//! patterns, then HTTP status code defaults.
//!
//! `ProviderError` itself is Phase 0's frozen type (`crate::ir::ProviderError`,
//! extended in place 2026-08-28 with exactly the variant set `classify` below
//! needs) — imported, not redefined, so every `Provider` adapter can actually
//! return what this module classifies.
use crate::ir::ProviderError;
use http::HeaderMap;
use std::collections::HashMap;
use std::time::Duration;

/// Ceiling on a parsed `Retry-After` value. The header is attacker/provider
/// controlled wire input; passing it through uncapped lets a hostile or
/// buggy value (e.g. `u64::MAX` seconds) turn into an effectively-infinite
/// wait, or overflow a later `Instant + retry_after` computation — a
/// self-inflicted availability failure. Five minutes is generous for any
/// legitimate rate-limit backoff while bounding the worst case.
/// `pub(crate)`, not private: `crate::retry`'s `retry_with_policy` sleeps a
/// caller-supplied `RateLimited { retry_after }` duration directly (a future
/// caller could construct `ProviderError::RateLimited` by hand, bypassing
/// `parse_retry_after` below entirely), so the sleep site clamps against this
/// same ceiling belt-and-braces — sharing the constant instead of duplicating
/// the magic number keeps the two caps from drifting apart.
pub(crate) const MAX_RETRY_AFTER: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProviderErrorKind {
    Overloaded,
    RateLimited,
    QuotaExhausted,
    ModelNotFound,
}

pub struct ErrorProfile {
    // §14g / Phase 6 Task 4: relaxed from `HashMap<&'static str, _>` so
    // TOML-loaded, owned error codes (`ProviderProfile::error_profile`) can
    // populate it too; lookups stay `&str` via `HashMap::get`.
    pub code_table: HashMap<String, ProviderErrorKind>,
    pub message_patterns: Vec<(regex::Regex, ProviderErrorKind)>,
}

impl ErrorProfile {
    pub fn empty() -> Self {
        Self {
            code_table: HashMap::new(),
            message_patterns: Vec::new(),
        }
    }

    pub fn anthropic_like() -> Self {
        let mut code_table = HashMap::new();
        code_table.insert(
            "rate_limit_error".to_string(),
            ProviderErrorKind::RateLimited,
        );
        code_table.insert(
            "overloaded_error".to_string(),
            ProviderErrorKind::Overloaded,
        );
        Self {
            code_table,
            // Anthropic's real, verbatim wording is "Your credit balance is
            // too low to access the Anthropic API" — note "is too low", not
            // "too low" alone.
            message_patterns: vec![(
                regex::Regex::new("credit balance is too low").unwrap(),
                ProviderErrorKind::QuotaExhausted,
            )],
        }
    }
}

/// Classification order (§9.8): provider error code -> message regex -> HTTP status
/// default. Never `?` on JSON parsing here — an outage returning HTML must not
/// become a decode panic in the error path.
pub fn classify(
    profile: &ErrorProfile,
    status: u16,
    body: &[u8],
    headers: &HeaderMap,
) -> ProviderError {
    let parsed: Option<serde_json::Value> = serde_json::from_slice(body).ok();

    if let Some(v) = &parsed {
        if let Some(code) = v.pointer("/error/type").and_then(|x| x.as_str()) {
            if let Some(kind) = profile.code_table.get(code) {
                return kind_to_error(*kind, headers);
            }
        }
    }

    // Match message patterns against the structured `/error/message` field
    // when the body parsed as JSON, not the raw body: a provider that echoes
    // request content back in a 400 (§9.9's explicit warning — e.g. a file
    // the agent read, or fetched web content sitting in context) must not be
    // able to steer classification by having a pattern string appear
    // incidentally in that echoed content. Only fall back to the raw,
    // lossy-decoded body when the response didn't parse as JSON at all (the
    // HTML-error-page case), where there is no structured field to prefer.
    let message_haystack: std::borrow::Cow<'_, str> = match &parsed {
        Some(v) => match v.pointer("/error/message").and_then(|x| x.as_str()) {
            Some(msg) => std::borrow::Cow::Borrowed(msg),
            None => std::borrow::Cow::Owned(String::new()),
        },
        None => String::from_utf8_lossy(body),
    };
    for (pattern, kind) in &profile.message_patterns {
        if pattern.is_match(&message_haystack) {
            return kind_to_error(*kind, headers);
        }
    }

    // No profile matched — this is a pure HTTP-status guess, not something
    // the provider told us explicitly. Per this project's invariants, a
    // degrade like this must be observable, not silent: e.g. OpenAI-family
    // providers return HTTP 429 for `insufficient_quota` (a permanent
    // billing failure, not a rate limit), which an empty/incomplete profile
    // would otherwise silently misclassify as retryable.
    tracing::debug!(
        status,
        "provider error classification fell through to HTTP-status default \
         (no code-table or message-pattern match)"
    );

    match status {
        429 => ProviderError::RateLimited {
            retry_after: parse_retry_after(headers),
        },
        400 => ProviderError::BadRequest {
            status,
            // §9.9: no redaction pass exists yet, so the safe amount of
            // unredacted provider body to persist is none — matches
            // `anthropic_provider::classify_status`'s existing precedent.
            body_snippet: String::new(),
        },
        404 => ProviderError::ModelNotFound,
        500..=599 => ProviderError::Server { status },
        _ => ProviderError::BadRequest {
            status,
            body_snippet: String::new(),
        },
    }
}

fn kind_to_error(kind: ProviderErrorKind, headers: &HeaderMap) -> ProviderError {
    match kind {
        ProviderErrorKind::Overloaded => ProviderError::Overloaded,
        ProviderErrorKind::RateLimited => ProviderError::RateLimited {
            retry_after: parse_retry_after(headers),
        },
        ProviderErrorKind::QuotaExhausted => ProviderError::QuotaExhausted,
        ProviderErrorKind::ModelNotFound => ProviderError::ModelNotFound,
    }
}

fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .map(|secs| Duration::from_secs(secs).min(MAX_RETRY_AFTER))
}
