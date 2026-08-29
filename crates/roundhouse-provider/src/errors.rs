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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProviderErrorKind {
    Overloaded,
    RateLimited,
    QuotaExhausted,
    ModelNotFound,
}

pub struct ErrorProfile {
    pub code_table: HashMap<&'static str, ProviderErrorKind>,
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
        code_table.insert("rate_limit_error", ProviderErrorKind::RateLimited);
        code_table.insert("overloaded_error", ProviderErrorKind::Overloaded);
        Self {
            code_table,
            message_patterns: vec![(
                regex::Regex::new("credit balance too low").unwrap(),
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

    let body_str = String::from_utf8_lossy(body);
    for (pattern, kind) in &profile.message_patterns {
        if pattern.is_match(&body_str) {
            return kind_to_error(*kind, headers);
        }
    }

    match status {
        429 => ProviderError::RateLimited {
            retry_after: parse_retry_after(headers),
        },
        400 => ProviderError::BadRequest {
            status,
            body_snippet: body_str.chars().take(200).collect(),
        },
        404 => ProviderError::ModelNotFound,
        500..=599 => ProviderError::Server { status },
        _ => ProviderError::BadRequest {
            status,
            body_snippet: body_str.chars().take(200).collect(),
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
        .map(Duration::from_secs)
}
