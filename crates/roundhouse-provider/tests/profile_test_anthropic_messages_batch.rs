//! Deserialization shape tests for Task 15's six `anthropic-messages`
//! batch profiles (Vertex, Microsoft Foundry, Qwen/OpenRouter/DeepInfra
//! Anthropic-compat, Bedrock new-Claude) -- REALITY-CORRECTIONS §9.2's
//! audit finding: these six speak the SAME real Anthropic Messages wire
//! format as first-party Anthropic (already covered by Phase 1), so this
//! codec's `encode_anthropic_messages`/`decode_anthropic_messages_stream`
//! are reused unchanged; what differs per profile is base URL, auth, and
//! error classification -- see `src/codec/anthropic_messages/provider.rs`'s
//! module doc for the full design note, including the one deliberate
//! per-profile-identity body/URL branch (Vertex).

use roundhouse_provider::profile::{AuthKind, ProviderProfile};

fn load(name: &str) -> ProviderProfile {
    let path = format!("{}/profiles/{name}.toml", env!("CARGO_MANIFEST_DIR"));
    toml::from_str(&std::fs::read_to_string(path).unwrap()).expect("valid profile must deserialize")
}

#[test]
fn vertex_anthropic_profile_shape() {
    let p = load("vertex-anthropic");
    assert_eq!(p.codec, "anthropic-messages");
    assert!(
        matches!(p.defaults.auth, AuthKind::Bearer),
        "Vertex authenticates with a Google OAuth2 access token, a Bearer-shaped credential \
         from this crate's point of view"
    );
    assert_eq!(
        p.error_pointer, "/error/status",
        "Vertex is a Google Cloud API and uses google.rpc.Status's JSON mapping, which nests \
         the machine-readable code under /error/status, not this codec's default /error/type"
    );
}

#[test]
fn microsoft_foundry_profile_uses_azure_entra() {
    let p = load("microsoft-foundry");
    assert_eq!(p.codec, "anthropic-messages");
    match &p.defaults.auth {
        AuthKind::AzureEntra { scope } => assert_eq!(
            scope, "https://ai.azure.com/.default",
            "verified against Anthropic's own Foundry docs (az account get-access-token \
             --resource https://ai.azure.com / get_bearer_token_provider(..., \
             \"https://ai.azure.com/.default\")), not cognitiveservices.azure.com"
        ),
        other => panic!("expected AzureEntra auth, got {other:?}"),
    }
}

#[test]
fn qwen_anthropic_compat_profile_shape() {
    let p = load("qwen-anthropic");
    assert_eq!(p.codec, "anthropic-messages");
    assert!(matches!(p.defaults.auth, AuthKind::Bearer));
    assert!(
        p.defaults.base_url.contains("/apps/anthropic"),
        "DashScope's real Anthropic-compat base path is /apps/anthropic, not /api/v1/anthropic \
         -- base_url was {:?}",
        p.defaults.base_url
    );
}

#[test]
fn openrouter_anthropic_compat_profile_shape() {
    let p = load("openrouter-anthropic");
    assert_eq!(p.codec, "anthropic-messages");
    assert!(matches!(p.defaults.auth, AuthKind::Bearer));
}

#[test]
fn deepinfra_anthropic_compat_profile_shape() {
    let p = load("deepinfra-anthropic");
    assert_eq!(p.codec, "anthropic-messages");
    assert!(matches!(p.defaults.auth, AuthKind::Bearer));
    assert!(
        !p.defaults.base_url.contains("/v1/anthropic"),
        "DeepInfra's real base is https://api.deepinfra.com/anthropic (with /v1/messages \
         appended by the provider), not .../v1/anthropic -- base_url was {:?}",
        p.defaults.base_url
    );
}

#[test]
fn bedrock_anthropic_messages_profile_uses_sigv4_and_the_real_bedrock_mantle_host() {
    // §9.2, quoted exactly: "new Claude models use
    // bedrock-mantle.{region}.api.aws/anthropic/v1/messages, a real Anthropic
    // Messages endpoint over ordinary SSE, not the binary eventstream
    // Converse API" -- this is what distinguishes this profile from Task 7's
    // bedrock-converse.toml (legacy non-Claude, binary eventstream).
    let p = load("bedrock-anthropic-messages");
    assert_eq!(p.codec, "anthropic-messages");
    assert!(p.defaults.base_url.contains("bedrock-mantle"));
    match &p.defaults.auth {
        AuthKind::SigV4 { service } => assert_eq!(
            service, "bedrock-mantle",
            "verified against Anthropic's own Bedrock Mantle docs curl example \
             (--aws-sigv4 \"aws:amz:us-east-1:bedrock-mantle\"), not \"bedrock\" (that is the \
             legacy Converse/InvokeModel service name, bedrock-converse.toml's own value)"
        ),
        other => panic!("expected SigV4 auth, got {other:?}"),
    }
}
