use super::{host_only::record_base_url_override, CredentialError};

/// §9.9: "Base URL resolves as: explicit override -> `ROUNDHOUSE_<PROVIDER>_BASE_URL`
/// env -> profile default." Handles no secret material — the profile default,
/// override, and env value are all non-secret configuration.
///
/// Returns the resolved `Url` alongside its host-only recording (§9.9's
/// hardening triad, part 1) as one inseparable pair, rather than as two
/// functions a caller could call independently — a caller cannot obtain the
/// full `Url` (which may carry userinfo or a query string, e.g. a gateway
/// that puts an API key in a query param) without also obtaining the
/// host-only string that's safe to persist on a task record. There is no
/// call path in this crate that resolves a base URL without recording it.
pub fn resolve_base_url(
    provider_id: &str,
    profile_default: &str,
    explicit_override: Option<&str>,
) -> Result<(url::Url, String), CredentialError> {
    let raw = if let Some(explicit) = explicit_override {
        explicit.to_string()
    } else {
        let env_key = format!(
            "ROUNDHOUSE_{}_BASE_URL",
            provider_id.to_uppercase().replace('-', "_")
        );
        std::env::var(&env_key).unwrap_or_else(|_| profile_default.to_string())
    };
    let parsed = url::Url::parse(&raw)
        .map_err(|e| CredentialError::InvalidBaseUrl(format!("{raw}: {e}")))?;
    let recorded = record_base_url_override(&raw);
    Ok((parsed, recorded))
}
