//! §9.5 — TOML quirk-profile deserializer, `ReasoningControl`, and
//! §9.4's endpoint-preference resolution (audit findings 3, 7, 8).

use roundhouse_provider::profile::{
    DispositionKind, Intent, ParamsMode, ProviderProfile, ReasoningKind,
};

const MOONSHOT_TOML: &str = include_str!("../profiles/moonshot.toml");

#[test]
fn moonshot_profile_deserializes_with_expected_shape() {
    let profile: ProviderProfile =
        toml::from_str(MOONSHOT_TOML).expect("valid profile must deserialize");
    assert_eq!(profile.id, "moonshot");
    assert_eq!(profile.codec, "openai-chat");
    assert!(!profile.defaults.allow_raw_extra);
    assert_eq!(profile.defaults.params.mode, ParamsMode::AllowOnly);
    assert_eq!(
        profile.defaults.params.fields,
        vec!["max_output_tokens", "stop"]
    );
    assert_eq!(profile.defaults.base_url, "https://api.moonshot.ai/v1");
    assert!(matches!(
        profile.defaults.auth,
        roundhouse_provider::profile::AuthKind::Bearer
    ));

    let model = &profile.model[0];
    assert_eq!(model.match_globs, vec!["kimi-k3*"]);
    let reasoning = model
        .reasoning
        .as_ref()
        .expect("kimi-k3* declares a reasoning control");
    assert_eq!(reasoning.kind, ReasoningKind::Effort);
    assert_eq!(reasoning.field, "/reasoning_effort");
    assert_eq!(reasoning.vocabulary, vec!["none", "low", "medium", "high"]);
    assert_eq!(reasoning.resolve(Intent::Max).unwrap(), "high");
    assert_eq!(reasoning.resolve(Intent::Off).unwrap(), "none");

    let overloaded = &profile.errors["engine_overloaded_error"];
    assert_eq!(overloaded.disposition, DispositionKind::RetryBackoff);
    let quota = &profile.errors["exceeded_current_quota_error"];
    assert_eq!(quota.disposition, DispositionKind::Fatal);
    assert_eq!(quota.category.as_deref(), Some("quota"));
}

#[test]
fn unknown_field_in_profile_is_a_deserialize_error_not_a_silent_ignore() {
    // This is what build.rs turning a typo into a build error depends on:
    // #[serde(deny_unknown_fields)] must actually be present on every profile
    // struct, or a typo'd key would silently vanish instead of failing.
    let broken = r#"
        id = "moonshot"
        codec = "openai-chat"

        [defaults]
        allow_raw_extra = false
        base_url = "https://api.moonshot.ai/v1"

        [defaults.params]
        mode = "allow_only"
        fields = ["max_output_tokens"]

        [defaults.auth]
        kind = "bearer"

        [[model]]
        match = ["kimi-k3*"]

        [model.reasoning]
        kind = "effort"
        field = "/reasoning_effort"
        vocabulary = ["none", "high"]
        dispositon = "off"

        [model.reasoning.map]
        off = "none"
    "#; // "dispositon" — deliberate typo of a field name that does not exist at all
        // on `ReasoningControl`. Every field `ReasoningControl` actually
        // requires (kind/field/vocabulary/map) is present and valid here, so
        // this can ONLY fail via `deny_unknown_fields` rejecting `dispositon`
        // — a missing-required-field error would pass this assertion for the
        // wrong reason and not actually pin down the guarantee.
    let result: Result<ProviderProfile, _> = toml::from_str(broken);
    assert!(
        result.is_err(),
        "a typo'd field must fail deserialization, matching build.rs's guarantee"
    );
}

#[test]
fn reasoning_control_rejects_a_map_target_outside_the_declared_vocabulary() {
    let bad = r#"
        kind = "effort"
        field = "/reasoning_effort"
        vocabulary = ["none", "high"]
        map = { max = "extreme" }
    "#; // "extreme" is not in `vocabulary` — a defense-in-depth check, not just trust the TOML author
    let reasoning: roundhouse_provider::profile::ReasoningControl = toml::from_str(bad).unwrap();
    assert!(reasoning.resolve(Intent::Max).is_err());
}

#[test]
fn endpoint_preference_prefers_the_first_non_degraded_available_endpoint() {
    // §9.4: "[responses, chat] with chat marked degraded" — the exact case this
    // mechanism exists for (audit finding 3). Both endpoints are available here,
    // so the non-degraded one wins even though it's listed first anyway.
    use roundhouse_provider::profile::{resolve_endpoint_preference, EndpointKind, EndpointPref};
    let preference = vec![
        EndpointPref {
            endpoint: EndpointKind::Responses,
            degraded: false,
        },
        EndpointPref {
            endpoint: EndpointKind::Chat,
            degraded: true,
        },
    ];
    let resolution =
        resolve_endpoint_preference(&preference, &[EndpointKind::Responses, EndpointKind::Chat])
            .unwrap();
    assert_eq!(resolution.endpoint, EndpointKind::Responses);
    assert!(!resolution.degraded);
}

#[test]
fn endpoint_preference_falls_back_to_degraded_only_when_nothing_else_is_available() {
    use roundhouse_provider::profile::{resolve_endpoint_preference, EndpointKind, EndpointPref};
    let preference = vec![
        EndpointPref {
            endpoint: EndpointKind::Responses,
            degraded: false,
        },
        EndpointPref {
            endpoint: EndpointKind::Chat,
            degraded: true,
        },
    ];
    // Responses is NOT available this time (e.g. not yet promoted past
    // `experimental`, or a transient outage) — must fall back to Chat and
    // report the fallback as degraded so the caller can log a LossEvent.
    let resolution = resolve_endpoint_preference(&preference, &[EndpointKind::Chat]).unwrap();
    assert_eq!(resolution.endpoint, EndpointKind::Chat);
    assert!(
        resolution.degraded,
        "falling back to the only available (degraded) endpoint must be reported as degraded"
    );
}

#[test]
fn endpoint_preference_errors_when_nothing_in_the_list_is_available() {
    use roundhouse_provider::profile::{resolve_endpoint_preference, EndpointKind, EndpointPref};
    let preference = vec![EndpointPref {
        endpoint: EndpointKind::Responses,
        degraded: false,
    }];
    assert!(resolve_endpoint_preference(&preference, &[EndpointKind::Chat]).is_err());
}

#[test]
fn glob_match_shared_helper_matches_prefix_and_exact_patterns() {
    // Audit finding 8: one shared implementation, used identically by every
    // codec's encode.rs instead of a per-task reimplementation.
    use roundhouse_provider::profile::glob_match;
    assert!(glob_match("gpt-5*", "gpt-5.4"));
    assert!(!glob_match("gpt-5*", "gpt-4o"));
    assert!(glob_match("kimi-k3*", "kimi-k3-1226"));
    assert!(glob_match("command-a-03-2026", "command-a-03-2026"));
    assert!(!glob_match("command-a-03-2026", "command-a-04-2026"));
}
