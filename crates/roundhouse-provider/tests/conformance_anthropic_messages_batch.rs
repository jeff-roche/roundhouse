//! `roundhouse-conformance` wiring for Task 15's six `anthropic-messages`
//! batch profiles (Vertex, Microsoft Foundry, Qwen/OpenRouter/DeepInfra
//! Anthropic-compat, Bedrock new-Claude).
//!
//! Cassette provenance: every `testdata/cassettes/{vertex_anthropic,
//! microsoft_foundry,qwen_anthropic,openrouter_anthropic,deepinfra_anthropic,
//! bedrock_anthropic_messages}/text.cassette` is hand-authored (no live
//! credential to record against any of these six providers), reproducing the
//! EXACT SSE frame shape already verified in Phase 1's own
//! `tests/fixtures/anthropic_thinking.sse` (`event: <type>` / `data: {...}`
//! pairs for `message_start` -> `content_block_start` -> `content_block_delta`
//! -> `content_block_stop` -> `message_delta` -> `message_stop`, each
//! `data:` line's JSON matching the exact field names
//! `decode_anthropic_messages_stream` reads). Per REALITY-CORRECTIONS §13b
//! item 3, this proves the six profiles' decoding agrees with THIS codec's
//! own already-verified wire shape, not independent per-vendor wire capture
//! -- which is the entire premise of the audit finding this task implements
//! (§9.2: these six are "a real Anthropic Messages endpoint", the same one
//! Phase 1 already built and tested). Every cassette ends with a trailing
//! blank line (REALITY-CORRECTIONS §13b item 1), verified for the whole
//! `testdata/cassettes/` tree by `every_sse_cassette_has_a_terminator_test.rs`.

use roundhouse_conformance::{run, ConformanceCase, ConformanceSubject, SerializeOnlyMask};
use roundhouse_provider::codec::anthropic_messages::{
    encode_anthropic_messages, AnthropicMessagesProfileProvider,
};
use roundhouse_provider::credential::{CredentialCtx, CredentialError, CredentialProvider};
use roundhouse_provider::profile::{AuthKind, ProviderProfile};
use roundhouse_provider::{BoxFut, ChatRequest, HttpRequest};
use roundhouse_secrets::credential::SigV4Credential;
use roundhouse_secrets::secret::Secret;
use std::path::PathBuf;
use std::sync::Arc;

/// A minimal fake `CredentialProvider` -- matches `credential_test.rs`'s
/// `FixedHeaderCredential` precedent exactly. `microsoft-foundry` declares
/// `AzureEntra` auth, whose real `roundhouse_secrets` implementation
/// performs a genuine OAuth token-exchange HTTP call before it can apply a
/// header; driving that through this harness's `CassetteTransport` (which
/// always replays the SAME recorded body regardless of which URL is
/// requested) would make the token-exchange call itself receive the SSE
/// cassette body as if it were a token JSON response and fail to parse, not
/// exercise anything real about this profile's own wire shape. This fake
/// proves the same thing `test_sigv4_credentials` proves for Bedrock: that
/// `stream_chat` reaches `HttpTransport::send` at all when a credential IS
/// supplied, without depending on a second, unrelated OAuth mock.
///
/// Fix-round-1 Fix 3: `scope` is read from the profile's own declared
/// `AuthKind::AzureEntra { scope }` (`from_profile`) rather than being a
/// hand-written literal, and is folded into the applied header value below --
/// so the profile's declared `scope` reaches a real `CredentialProvider::apply`
/// call site, not only a test that re-asserts the same TOML field it read.
struct FakeAzureEntraCredential {
    scope: String,
}
impl FakeAzureEntraCredential {
    fn from_profile(profile: &ProviderProfile) -> Self {
        match &profile.defaults.auth {
            AuthKind::AzureEntra { scope } => Self {
                scope: scope.clone(),
            },
            other => panic!(
                "expected AzureEntra auth for {:?}, got {other:?}",
                profile.id
            ),
        }
    }
}
impl CredentialProvider for FakeAzureEntraCredential {
    fn apply<'a>(
        &'a self,
        req: &'a mut HttpRequest,
        _ctx: &'a CredentialCtx<'a>,
    ) -> BoxFut<'a, Result<(), CredentialError>> {
        Box::pin(async move {
            req.headers.push((
                "authorization".to_string(),
                format!("Bearer fake-entra-token (scope={})", self.scope),
            ));
            Ok(())
        })
    }
}

#[path = "support/anthropic_messages_batch_fixtures.rs"]
mod fixtures;

fn load(name: &str) -> ProviderProfile {
    let path = format!("{}/profiles/{name}.toml", env!("CARGO_MANIFEST_DIR"));
    toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn cassette_path(id: &str, name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/cassettes")
        .join(id.replace('-', "_"))
        .join(name)
}

/// A real `SigV4Credential` (fixed, obviously-fake test key material) --
/// `bedrock-anthropic-messages` has no bare `api_key` fallback that can sign
/// an AWS request (REALITY-CORRECTIONS §12b: SigV4 "applying" a credential
/// IS signing it), so the conformance run for that one profile must supply
/// one. Matches `conformance_bedrock_converse.rs`'s identical precedent.
///
/// Fix-round-1 Fix 3: `service` is read from the profile's own declared
/// `AuthKind::SigV4 { service }` rather than a hand-written `"bedrock-mantle"`
/// literal, so the profile's declared value reaches the real `sigv4::sign()`
/// signature path this credential's `apply` calls -- proving the data is
/// load-bearing, not merely re-asserted by a test that reads the same TOML.
fn test_sigv4_credentials(profile: &ProviderProfile) -> Arc<dyn CredentialProvider> {
    let service = match &profile.defaults.auth {
        AuthKind::SigV4 { service } => service.clone(),
        other => panic!("expected SigV4 auth for {:?}, got {other:?}", profile.id),
    };
    Arc::new(SigV4Credential::new(
        "AKIAEXAMPLETESTKEY00000",
        Secret::new("wJalrXUtnFEMIexampleSECRETkey1234567890".to_string()),
        None,
        "us-east-1",
        service,
    ))
}

/// Every field `encode_anthropic_messages` can ever put on the wire that is
/// governed by a profile's `[defaults.params]` policy. Passed to
/// `ParamsPolicy::allowed_fields` (REALITY-CORRECTIONS §12c) so each
/// subject's mask is derived from that profile's OWN declared policy, even
/// though every profile in this batch happens to declare the same
/// `deny_list`-with-nothing-denied policy today -- the derivation is still
/// real and per-profile, not a shared hardcoded constant.
const ALL_KNOWN_PARAM_FIELDS: &[&str] = &["temperature", "top_p", "max_output_tokens", "stop"];

/// Maps a params-policy field identifier onto the actual wire key
/// `encode_anthropic_messages` emits for it. Identity for every field except
/// `max_output_tokens` (wire key `max_tokens`) and `stop` (wire key
/// `stop_sequences`).
fn params_wire_path(field: &str) -> &'static str {
    match field {
        "temperature" => "temperature",
        "top_p" => "top_p",
        "max_output_tokens" => "max_tokens",
        "stop" => "stop_sequences",
        other => panic!(
            "an anthropic-messages batch profile declares params field {other:?}, which this \
             test's wire-path translation table doesn't know about -- add it here"
        ),
    }
}

/// The mask for one profile, derived from that profile's own `ParamsPolicy`
/// (REALITY-CORRECTIONS §12c) plus the structural keys `encode_anthropic_
/// messages` always emits for a plain single-turn-text request (no tools, no
/// reasoning, no cache breakpoints -- this batch's one shared fixture).
fn mask(profile: &ProviderProfile) -> SerializeOnlyMask {
    let mut allowed: Vec<String> = vec![
        "system".into(),
        "messages".into(),
        "messages.role".into(),
        "messages.content".into(),
        "messages.content.type".into(),
        "messages.content.text".into(),
        "stream".into(),
        // Vertex's one documented envelope quirk (see provider.rs's module
        // doc): `anthropic_version` replaces `model` in the body for that
        // profile only. Harmless to permit for every profile's mask (a
        // profile that never emits it is simply never checked against this
        // entry).
        "anthropic_version".into(),
    ];
    for field in profile
        .defaults
        .params
        .allowed_fields(ALL_KNOWN_PARAM_FIELDS)
    {
        allowed.push(params_wire_path(&field).to_string());
    }
    SerializeOnlyMask {
        // `model` is mandatory for every profile except Vertex, whose
        // provider strips it (provider.rs's `adjust_body_for_vertex`) --
        // `mandatory` only asserts these keys are PERMITTED, not that every
        // case's body must contain them, so listing it here is still
        // correct for the five non-Vertex subjects and inert (never
        // present, never flagged) for Vertex's own case.
        mandatory: vec![
            "model".into(),
            "system".into(),
            "messages".into(),
            "max_tokens".into(),
        ],
        allowed,
    }
}

/// One conformance subject per profile, all reusing the same
/// `AnthropicMessagesProfileProvider` -- the "provider is data" thesis made
/// concrete: nothing here differs except which TOML file is loaded, which
/// cassette directory is read from, and (Bedrock only) which credential is
/// supplied.
macro_rules! anthropic_messages_profile_subject {
    ($subject:ident, $id:literal, $model:literal) => {
        struct $subject;
        impl ConformanceSubject for $subject {
            type Provider = AnthropicMessagesProfileProvider;
            fn provider() -> Self::Provider {
                AnthropicMessagesProfileProvider::new(load($id))
            }
            fn cases() -> Vec<ConformanceCase> {
                vec![ConformanceCase {
                    name: "text",
                    request: fixtures::single_turn_text($model),
                    cassette_path: cassette_path($id, "text.cassette"),
                    mask: mask(&load($id)),
                    declared_loss_events: vec![],
                    expected_error: None,
                }]
            }
            fn wire_body(req: &ChatRequest) -> serde_json::Value {
                encode_anthropic_messages(req)
            }
        }
    };
}

anthropic_messages_profile_subject!(
    VertexAnthropicSubject,
    "vertex-anthropic",
    "claude-sonnet-5"
);
anthropic_messages_profile_subject!(QwenAnthropicSubject, "qwen-anthropic", "qwen3.8-max");
anthropic_messages_profile_subject!(
    OpenRouterAnthropicSubject,
    "openrouter-anthropic",
    "anthropic/claude-sonnet-5"
);
anthropic_messages_profile_subject!(
    DeepInfraAnthropicSubject,
    "deepinfra-anthropic",
    "anthropic/claude-sonnet-5"
);

struct MicrosoftFoundrySubject;
impl ConformanceSubject for MicrosoftFoundrySubject {
    type Provider = AnthropicMessagesProfileProvider;
    fn provider() -> Self::Provider {
        AnthropicMessagesProfileProvider::new(load("microsoft-foundry"))
    }
    fn cases() -> Vec<ConformanceCase> {
        vec![ConformanceCase {
            name: "text",
            request: fixtures::single_turn_text("claude-sonnet-5"),
            cassette_path: cassette_path("microsoft-foundry", "text.cassette"),
            mask: mask(&load("microsoft-foundry")),
            declared_loss_events: vec![],
            expected_error: None,
        }]
    }
    fn wire_body(req: &ChatRequest) -> serde_json::Value {
        encode_anthropic_messages(req)
    }
    /// `AzureEntra` auth has no bare-`api_key` fallback either -- see
    /// `FakeAzureEntraCredential`'s own doc comment for why this uses a
    /// fake rather than the real `roundhouse_secrets::AzureEntraCredential`.
    fn credentials() -> Option<Arc<dyn CredentialProvider>> {
        Some(Arc::new(FakeAzureEntraCredential::from_profile(&load(
            "microsoft-foundry",
        ))))
    }
}

struct BedrockAnthropicMessagesSubject;
impl ConformanceSubject for BedrockAnthropicMessagesSubject {
    type Provider = AnthropicMessagesProfileProvider;
    fn provider() -> Self::Provider {
        AnthropicMessagesProfileProvider::new(load("bedrock-anthropic-messages"))
    }
    fn cases() -> Vec<ConformanceCase> {
        vec![ConformanceCase {
            name: "text",
            request: fixtures::single_turn_text("anthropic.claude-sonnet-5"),
            cassette_path: cassette_path("bedrock-anthropic-messages", "text.cassette"),
            mask: mask(&load("bedrock-anthropic-messages")),
            declared_loss_events: vec![],
            expected_error: None,
        }]
    }
    fn wire_body(req: &ChatRequest) -> serde_json::Value {
        encode_anthropic_messages(req)
    }
    /// Fix-round-1 H3 precedent (`conformance_bedrock_converse.rs`): a
    /// SigV4-only profile has no bare-`api_key` fallback, so this subject
    /// overrides the defaulted `credentials()` to supply a real one -- this
    /// is what lets `run::<BedrockAnthropicMessagesSubject>()` reach
    /// `HttpTransport::send` at all instead of failing closed on a missing
    /// credential before ever touching the cassette transport.
    fn credentials() -> Option<Arc<dyn CredentialProvider>> {
        Some(test_sigv4_credentials(&load("bedrock-anthropic-messages")))
    }
}

#[tokio::test]
async fn vertex_anthropic_is_conformant() {
    run::<VertexAnthropicSubject>().await.assert_green();
}
#[tokio::test]
async fn microsoft_foundry_is_conformant() {
    run::<MicrosoftFoundrySubject>().await.assert_green();
}
#[tokio::test]
async fn qwen_anthropic_is_conformant() {
    run::<QwenAnthropicSubject>().await.assert_green();
}
#[tokio::test]
async fn openrouter_anthropic_is_conformant() {
    run::<OpenRouterAnthropicSubject>().await.assert_green();
}
#[tokio::test]
async fn deepinfra_anthropic_is_conformant() {
    run::<DeepInfraAnthropicSubject>().await.assert_green();
}
#[tokio::test]
async fn bedrock_anthropic_messages_is_conformant() {
    run::<BedrockAnthropicMessagesSubject>()
        .await
        .assert_green();
}
