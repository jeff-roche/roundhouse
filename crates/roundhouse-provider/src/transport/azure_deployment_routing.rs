//! The `azure-deployment-routing` transport shim (§9.4's second named shim,
//! alongside Task 7's `sigv4-eventstream`). Azure OpenAI does not route by
//! model id in the URL path the way every other `openai-chat` provider
//! does; it routes by **deployment name**, a customer-chosen identifier
//! configured per-model in the Azure resource, and the API version is a
//! **query parameter**, not part of the path or a header. Pure URL
//! construction — no I/O — so it's testable without a transport at all,
//! matching `sigv4::sign`'s shape (§6: a pure function over inputs, called
//! by the `Provider` impl's `stream_chat`).
//!
//! Verified against Microsoft's own current REST API reference (fetched
//! 2026-09-02), <https://learn.microsoft.com/en-us/azure/foundry/openai/reference>,
//! "REST API versioning" section:
//! ```text
//! POST https://YOUR_RESOURCE_NAME.openai.azure.com/openai/deployments/YOUR_DEPLOYMENT_NAME/chat/completions?api-version=2024-06-01
//! ```
//! — the deployment name is a path segment between `deployments/` and
//! `/chat/completions`, and `api-version` is a query parameter, exactly the
//! shape this module builds.
//!
//! ## Deployment name as a URL path segment — the injection surface
//!
//! `deployment_name` is customer/config-sourced (a profile's `[[model]]
//! azure_deployment` field today; a value this crate does not control the
//! provenance of forever), and it becomes a raw path segment sandwiched
//! between two literal path components (`.../deployments/{name}/chat/...`).
//! Unlike `google_genai::provider::build_endpoint_url`'s model id (always
//! glued to a `:streamGenerateContent` suffix, so a standalone `..` can
//! never form), a deployment name stands ALONE between two `/` separators —
//! an all-dots value here really would be a working `..` traversal segment,
//! not merely a defense-in-depth concern. `is_safe_deployment_name` rejects:
//!
//! - empty and all-`.` strings (`""`, `.`, `..`, `...`) — a real traversal
//!   segment, not merely blocked by a suffix that happens to stay attached;
//! - any character outside a positive allowlist (ASCII alphanumerics, `.`,
//!   `-`, `_`) — this is a positive allowlist, not a denylist of `/`, `..`,
//!   `%`: `url::Url::set_path` normalizes AFTER this check runs, and a
//!   denylist of raw substrings has known bypasses in the `url` crate's own
//!   pre-parse normalization (`\` is a path separator for special schemes;
//!   the parser strips tab/LF/CR before parsing, so `.` + TAB + `.`
//!   reassembles into a literal `..` segment that never appeared in the
//!   pre-check string) — both are covered by this module's tests.
//!
//! A rejected deployment name is never interpolated into the returned
//! `ProviderError` raw: it may contain newlines or other control bytes, and
//! `ProviderError`'s `Display` can reach a persisted, physically-immutable
//! `events` row, so it is `{:?}`-escaped, mirroring
//! `google_genai::provider::build_endpoint_url`'s identical guarantee for a
//! rejected model id.
//!
//! `base_url` also fails closed on a "cannot be a base" URL (e.g. a
//! `mailto:`/`data:` scheme) — `Url::set_path` silently no-ops on those per
//! the `url` crate's own documented behavior, which would otherwise send
//! the deployment-routed request to whatever the original opaque path
//! happened to be instead of failing loudly.

use crate::ir::ProviderError;
use crate::profile::{glob_match, ProviderProfile};

fn is_safe_deployment_name(name: &str) -> bool {
    let all_dots = !name.is_empty() && name.chars().all(|c| c == '.');
    !name.is_empty()
        && !all_dots
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// Builds the full Azure OpenAI request URL:
/// `{base_url}/openai/deployments/{deployment_name}/chat/completions?api-version={api_version}`.
/// Preserves `base_url`'s existing path prefix (matching
/// `openai_chat`/`google_genai`/`cohere_v2`'s identical
/// `build_endpoint_url` precedent for a gateway base URL).
///
/// Fails closed (never sends an unrouted or mis-routed request) when:
/// - `base_url` doesn't parse as a URL at all;
/// - `base_url` parses but "cannot be a base" (no path/host to route
///   through — `Url::set_path` would silently no-op);
/// - `deployment_name` fails [`is_safe_deployment_name`]'s allowlist.
pub fn azure_deployment_url(
    base_url: &str,
    deployment_name: &str,
    api_version: &str,
) -> Result<url::Url, ProviderError> {
    let mut url = url::Url::parse(base_url).map_err(|e| {
        ProviderError::Transport(format!("invalid Azure base_url {base_url:?}: {e}"))
    })?;
    if url.cannot_be_a_base() {
        return Err(ProviderError::Transport(format!(
            "Azure base_url {base_url:?} cannot be a base URL (no host/path to route through)"
        )));
    }
    if !is_safe_deployment_name(deployment_name) {
        return Err(ProviderError::Unsupported(format!(
            "Azure deployment name {deployment_name:?} is not a safe URL path segment (only \
             ASCII alphanumerics, '.', '-', '_' are permitted, and it may not be empty or all dots)"
        )));
    }
    let base_path = url.path().strip_suffix('/').unwrap_or(url.path());
    url.set_path(&format!(
        "{base_path}/openai/deployments/{deployment_name}/chat/completions"
    ));
    url.query_pairs_mut()
        .append_pair("api-version", api_version);
    Ok(url)
}

/// Looks up the deployment name for a model id from the profile, via the
/// same `glob_match` every other codec uses (Task 4) — Azure's ONE
/// divergence from the shared `OpenAiChatProvider` path is which URL this
/// resolves to, not how the model id is matched.
pub fn resolve_deployment_name<'a>(
    profile: &'a ProviderProfile,
    model_id: &str,
) -> Result<&'a str, ProviderError> {
    profile
        .model
        .iter()
        .find(|m| m.match_globs.iter().any(|g| glob_match(g, model_id)))
        .and_then(|m| m.azure_deployment.as_deref())
        .ok_or_else(|| {
            ProviderError::Unsupported(format!(
                "no azure_deployment mapping in profile `{}` for model {model_id:?}",
                profile.id
            ))
        })
}
