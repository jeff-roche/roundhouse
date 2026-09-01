use super::CredentialError;

/// §9.9: "Base URL resolves as: explicit override -> `ROUNDHOUSE_<PROVIDER>_BASE_URL`
/// env -> profile default." Handles no secret material — the profile default,
/// override, and env value are all non-secret configuration.
pub fn resolve_base_url(
    provider_id: &str,
    profile_default: &str,
    explicit_override: Option<&str>,
) -> Result<url::Url, CredentialError> {
    let raw = if let Some(explicit) = explicit_override {
        explicit.to_string()
    } else {
        let env_key = format!(
            "ROUNDHOUSE_{}_BASE_URL",
            provider_id.to_uppercase().replace('-', "_")
        );
        std::env::var(&env_key).unwrap_or_else(|_| profile_default.to_string())
    };
    url::Url::parse(&raw).map_err(|e| CredentialError::InvalidBaseUrl(format!("{raw}: {e}")))
}
