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
///
/// **`allow_insecure` / the HTTPS gate (Phase 7 Task 16, Ruling R9):** a
/// non-loopback, plain-`http://` value only ever rejects here when it came
/// from an *operator-supplied* source — `explicit_override` or the
/// `ROUNDHOUSE_<PROVIDER>_BASE_URL` env var — never from `profile_default`.
/// Five shipped local-runtime profiles (`ollama`, `lm-studio`, `llama-cpp`,
/// `sglang`, `vllm`) declare an `http://localhost` `profile_default`; a
/// blanket scheme check on the resolved URL would break all five. A profile
/// default is reviewed code, not operator input — the threat this gate
/// closes is a typo'd override silently downgrading a credentialed request
/// to cleartext, which a shipped default cannot do. Loopback hosts
/// (`localhost`, `127.0.0.1`, `::1`) are exempt from the gate even when
/// operator-supplied, since redirecting one loopback port to another never
/// leaves the local machine; a non-loopback operator override still needs
/// `https://` or `allow_insecure: true`.
pub fn resolve_base_url(
    provider_id: &str,
    profile_default: &str,
    explicit_override: Option<&str>,
    allow_insecure: bool,
) -> Result<(url::Url, String), CredentialError> {
    let (raw, operator_supplied) = match explicit_override {
        Some(explicit) => (explicit.to_string(), true),
        None => {
            let env_key = format!(
                "ROUNDHOUSE_{}_BASE_URL",
                provider_id.to_uppercase().replace('-', "_")
            );
            match std::env::var(&env_key) {
                Ok(from_env) => (from_env, true),
                Err(_) => (profile_default.to_string(), false),
            }
        }
    };
    // Never interpolate `raw` itself into the error — a malformed override
    // can carry a query string (e.g. a gateway API key) or embedded
    // userinfo, and this project persists error text onto
    // physically-immutable `Event` rows. `record_base_url_override` already
    // degrades gracefully to `<unparseable-host>` when `raw` doesn't parse,
    // so it's safe to call here even on the failure path this feeds.
    let parsed = url::Url::parse(&raw).map_err(|e| {
        CredentialError::InvalidBaseUrl(format!(
            "base URL for host `{}` is not a valid URL: {e}",
            record_base_url_override(&raw)
        ))
    })?;

    if operator_supplied
        && !allow_insecure
        && parsed.scheme() == "http"
        && !is_loopback_host(parsed.host_str())
    {
        return Err(CredentialError::InsecureBaseUrl(format!(
            "operator-supplied base URL for provider `{provider_id}` uses insecure http:// \
             (host `{}`) -- use https://, or opt in with allow_insecure",
            record_base_url_override(&raw)
        )));
    }

    let recorded = record_base_url_override(&raw);
    Ok((parsed, recorded))
}

/// `true` for the loopback hosts an operator-supplied `http://` override is
/// exempted for (see [`resolve_base_url`]'s doc comment). `Url::host_str`
/// returns an IPv6 literal without its `[...]` brackets, so `::1` (not
/// `[::1]`) is the right literal to compare against here.
fn is_loopback_host(host: Option<&str>) -> bool {
    matches!(host, Some("localhost") | Some("127.0.0.1") | Some("::1"))
}
