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
/// `https://` or an opt-in (`allow_insecure: true`, or the sibling env var
/// below).
///
/// **The gate is an allowlist, not a denylist (fix round 1, Ruling R24 /
/// security S5):** the condition below is "reject unless `https`, or `http`
/// on a loopback host" — not "reject only `http`". An earlier version
/// checked `scheme() == "http"` alone, which let every *other* non-TLS
/// scheme (`ws://`, `ftp://`, `gopher://`, `file://`, `data:`) straight
/// through a check whose entire job is "this transport is not TLS"; it was
/// correct only by accident of `reqwest` supporting just `http`/`https` and
/// the daemon's `https_only(true)`. `is_loopback_host` already returns
/// `false` for `Host::None`, so `file:`/`data:` (which have no host at all)
/// are gated by the allowlist for free.
///
/// **`ROUNDHOUSE_<PROVIDER>_ALLOW_INSECURE_BASE_URL` (fix round 1, Ruling
/// R23):** §9.9 documents `ROUNDHOUSE_<PROVIDER>_BASE_URL` as a first-class
/// operator override with no scheme restriction, and the local-runtime
/// profile family's real deployment mode is exactly a non-loopback internal
/// host reached over plain `http://` (e.g. a GPU box on the LAN with no
/// TLS). Before the HTTPS gate existed that worked; after it, nothing in
/// production could ever set `allow_insecure: true`, so that documented
/// mode had no way back in. This env var is the operator-facing opt-in,
/// read per-provider (same name transformation as the base-URL env var
/// itself — see [`provider_env_key`]) right next to it, and is equivalent
/// to passing `allow_insecure: true` for that one provider's resolution
/// only; it never affects any other provider's gate. Parsing is an explicit
/// truthy check: `1` or `true` (case-insensitive) is truthy, anything else
/// — including absent, empty, or any other value — is not. Default stays
/// fail-closed: an absent or unparseable env var never opts in.
///
/// **This opt-in alone does NOT make the GPU-box scenario work end to end
/// today (fix round 3, Ruling R39) — say so precisely, don't imply it
/// does.** Setting the env var clears *this gate*, nothing more. The
/// daemon's actual transport (`ReqwestTransport::new()`,
/// `roundhouse-daemon/src/main.rs`) sets `https_only(true)`
/// (`reqwest_transport.rs`), which rejects a plain `http://` request
/// independently of anything this function decides — so an insecure base
/// URL that passes this gate still fails one layer down, at the transport.
/// `ReqwestTransport::allowing_plaintext_http()` already exists
/// (`reqwest_transport.rs`) with only test callers today; **when plaintext
/// HTTP must actually reach a local-runtime provider, the fix is
/// per-provider transport selection driven by this SAME
/// `ROUNDHOUSE_<PROVIDER>_ALLOW_INSECURE_BASE_URL` signal — NOT wiring the
/// daemon to `allowing_plaintext_http()` globally.** A global switch
/// removes `https_only` for every provider at once, silently widening the
/// exact control this gate exists to tighten, for every provider whether
/// or not its operator ever opted in. Recorded here, not only in a
/// gitignored ledger, because an operator who follows this gate's error
/// message, sets the env var, and still fails will go looking — and
/// `allowing_plaintext_http()` is one grep away and already written.
pub fn resolve_base_url(
    provider_id: &str,
    profile_default: &str,
    explicit_override: Option<&str>,
    allow_insecure: bool,
) -> Result<(url::Url, String), CredentialError> {
    let (raw, operator_supplied) = match explicit_override {
        Some(explicit) => (explicit.to_string(), true),
        None => {
            let env_key = provider_env_key(provider_id, "BASE_URL");
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

    let allow_insecure_env_key = provider_env_key(provider_id, "ALLOW_INSECURE_BASE_URL");
    let opted_in_via_env = std::env::var(&allow_insecure_env_key)
        .is_ok_and(|v| v.eq_ignore_ascii_case("1") || v.eq_ignore_ascii_case("true"));
    let effective_allow_insecure = allow_insecure || opted_in_via_env;

    let scheme_is_allowed = parsed.scheme() == "https"
        || (parsed.scheme() == "http" && is_loopback_host(parsed.host()));

    if operator_supplied && !effective_allow_insecure && !scheme_is_allowed {
        return Err(CredentialError::InsecureBaseUrl(format!(
            "operator-supplied base URL for provider `{provider_id}` uses insecure \
             scheme `{}` (host `{}`) -- use an https base URL, or set \
             {allow_insecure_env_key}=1 to opt in",
            parsed.scheme(),
            record_base_url_override(&raw)
        )));
    }

    let recorded = record_base_url_override(&raw);
    Ok((parsed, recorded))
}

/// The `ROUNDHOUSE_<PROVIDER>_<suffix>` env var name for `provider_id`,
/// using the exact same provider-name-to-env-var transformation the
/// pre-existing `ROUNDHOUSE_<PROVIDER>_BASE_URL` lookup already used
/// (uppercase, `-` -> `_`) — factored out here (fix round 1, F1) so the new
/// `ALLOW_INSECURE_BASE_URL` sibling can't drift from it.
fn provider_env_key(provider_id: &str, suffix: &str) -> String {
    format!(
        "ROUNDHOUSE_{}_{suffix}",
        provider_id.to_uppercase().replace('-', "_")
    )
}

/// `true` for the loopback hosts an operator-supplied `http://` override is
/// exempted for (see [`resolve_base_url`]'s doc comment). Uses the *typed*
/// `Url::host()` rather than `Url::host_str()`'s string form: `host_str`
/// serializes an IPv6 address WITH its `[...]` brackets (`"[::1]"`, not
/// `"::1"`), so a literal string comparison against `"::1"` silently never
/// matches -- this was caught by
/// `credential_test.rs::a_loopback_http_operator_override_is_never_gated`'s
/// `http://[::1]:9001/v1` case failing before this switched to `Ipv6Addr::
/// is_loopback()`. The typed form also correctly covers all of 127.0.0.0/8
/// via `Ipv4Addr::is_loopback()`, not just the single `127.0.0.1` literal.
fn is_loopback_host(host: Option<url::Host<&str>>) -> bool {
    match host {
        Some(url::Host::Domain(d)) => d == "localhost",
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::provider_env_key;

    /// N2 (Phase 7 U3 fix round 1 carry-forward, Ruling R31): `provider_env_key`
    /// uppercases and maps `-` -> `_`, so it is not injective in general --
    /// hypothetical provider ids `foo-bar` and `foo_bar` would both collapse to
    /// `ROUNDHOUSE_FOO_BAR_*`. That was always true for the pre-existing
    /// `BASE_URL` lookup, but harmless there; this same transformation now also
    /// gates `ALLOW_INSECURE_BASE_URL`, a control that disables an HTTPS
    /// downgrade check, so a future colliding id would silently let one
    /// provider's insecure-transport opt-in leak onto its sibling.
    ///
    /// This is a ratchet, not a behavior change: it drives the assertion off
    /// the real shipped profile list (`crate::PROFILE_SOURCES`, populated by
    /// build.rs from `profiles/*.toml`) rather than a hand-maintained copy, so
    /// a newly added id that collides with an existing one fails this test the
    /// moment it ships.
    #[test]
    fn every_shipped_profile_id_yields_a_distinct_env_key() {
        let mut seen: std::collections::HashMap<String, &str> = std::collections::HashMap::new();
        for (id, _src) in crate::PROFILE_SOURCES.iter() {
            let key = provider_env_key(id, "BASE_URL");
            if let Some(prev) = seen.insert(key.clone(), id) {
                panic!(
                    "provider ids `{prev}` and `{id}` both map to env key `{key}` via \
                     provider_env_key -- rename one of the ids so the mapping stays \
                     injective (in particular, avoid introducing `_` into a provider id \
                     that would otherwise be spelled with `-`)"
                );
            }
        }
    }
}
