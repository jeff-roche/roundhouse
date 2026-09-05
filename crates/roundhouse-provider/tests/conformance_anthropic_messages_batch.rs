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

use roundhouse_conformance::{checks, run, ConformanceCase, ConformanceSubject, SerializeOnlyMask};
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

/// Task 12 (Cross-Cutting #2, Ruling R16): mandatory truncate-mid-stream
/// check, wired here (rather than a standalone `conformance_anthropic_
/// messages.rs`, which doesn't exist) since this file already IS this
/// codec's `roundhouse-conformance` wiring. `anthropic_messages` is in the
/// "strict" truncation-signaling group (`decode_guard.rs`'s module doc,
/// Ruling R17): it must `Err`, never fabricate a `MessageStop`, when
/// truncated before its real `message_stop` terminal.
#[tokio::test]
async fn vertex_anthropic_text_cassette_is_never_indistinguishable_from_a_clean_completion_when_truncated(
) {
    let failures = checks::check_truncate_mid_stream(
        &VertexAnthropicSubject::provider(),
        &fixtures::single_turn_text("claude-sonnet-5"),
        &cassette_path("vertex-anthropic", "text.cassette"),
        VertexAnthropicSubject::credentials(),
    )
    .await;
    assert!(
        failures.is_empty(),
        "anthropic-messages must never report a clean completion for a stream truncated before \
         its real terminal: {failures:#?}"
    );
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

/// A transport that forwards to a real `CassetteTransport` but first
/// records the exact headers the request carried -- `CassetteTransport::
/// send` itself ignores `_req` entirely and replays the same recorded body
/// regardless, so nothing in the conformance harness above can observe what
/// `SigV4Credential::apply` actually signed. Mirrors `openai_chat_provider_
/// test.rs`'s identical `RecordingTransport` helper.
struct RecordingTransport {
    inner: roundhouse_provider::CassetteTransport,
    captured_headers: std::sync::Mutex<Vec<(String, String)>>,
}

impl roundhouse_provider::HttpTransport for RecordingTransport {
    fn send<'a>(
        &'a self,
        req: HttpRequest,
    ) -> futures::future::BoxFuture<
        'a,
        Result<roundhouse_provider::HttpResponseStream, roundhouse_provider::TransportError>,
    > {
        *self.captured_headers.lock().unwrap() = req.headers.clone();
        self.inner.send(req)
    }
}

/// Fix-round-2 Fix 8: fix-round-1's fix made `test_sigv4_credentials` read
/// `service` from the profile's own `AuthKind::SigV4 { service }` instead of
/// a hand-written literal -- a real change, but not one that would have
/// caught the regression it was written for. `CassetteTransport::send`
/// (`src/cassette.rs`) ignores its request and replays regardless, and
/// nothing in this file ever inspected the produced `authorization` header
/// -- so reverting `bedrock-anthropic-messages.toml`'s `service` back to the
/// historical wrong literal `"bedrock"` (the regression this whole mechanism
/// exists to catch) would leave every test in this file green.
///
/// This test asserts on something derived from the produced `authorization`
/// header instead: it drives `stream_chat` through `RecordingTransport`,
/// then parses the signed SigV4 header's `Credential=<key>/<date>/<region>/
/// <service>/aws4_request` scope and asserts the `<service>` segment equals
/// a HARDCODED expected value -- REALITY-CORRECTIONS §15 rule 3: an earlier
/// draft of this test read the expected value from
/// `profile.defaults.auth`'s own `service` field, which made it a tautology
/// (both "expected" and "actual" trace back to the same, possibly-reverted,
/// TOML field) -- confirmed hollow by reverting the TOML to `"bedrock"` and
/// watching that draft stay green. `"bedrock-mantle"` is hardcoded here
/// instead, matching Task 15's own corrected value (the `bedrock-mantle.
/// {region}.api.aws` host this profile's `base_url` uses, distinct from
/// `bedrock-converse.toml`'s `bedrock-runtime` host), so this test can only
/// pass if the profile's ACTUAL, LIVE declared value still matches what it
/// is supposed to be, not merely whatever it currently says.
///
/// Confirmed by reverting `bedrock-anthropic-messages.toml`'s `service` to
/// `"bedrock"` and re-running: see this task's report for the paired
/// RED/GREEN transcript (the revert is not present in this commit -- it
/// would ship a wrong profile value; only its evidence is).
#[tokio::test]
async fn bedrock_anthropic_messages_sigv4_header_scope_matches_declared_service() {
    use roundhouse_provider::{ChunkStrategy, Provider, RequestCtx};

    const EXPECTED_SERVICE: &str = "bedrock-mantle";

    let profile = load("bedrock-anthropic-messages");
    // Premise check only -- deliberately does NOT assert the service VALUE
    // (that would make this a second copy of the same tautology the final
    // assertion below exists to avoid). It only confirms the profile still
    // declares SigV4 at all, so a `credentials()` call below has something
    // to sign with.
    assert!(
        matches!(&profile.defaults.auth, AuthKind::SigV4 { .. }),
        "test premise: bedrock-anthropic-messages must declare SigV4 auth, got {:?}",
        profile.defaults.auth
    );

    let cassette = roundhouse_provider::CassetteTransport::from_file(
        &cassette_path("bedrock-anthropic-messages", "text.cassette"),
        ChunkStrategy::WholeBody,
    )
    .expect("text.cassette must parse");
    let transport = Arc::new(RecordingTransport {
        inner: cassette,
        captured_headers: std::sync::Mutex::new(Vec::new()),
    });

    let ctx = RequestCtx {
        trace_id: None,
        transport: transport.clone(),
        api_key: String::new(),
        credentials: Some(test_sigv4_credentials(&profile)),
    };
    let provider = AnthropicMessagesProfileProvider::new(profile);
    provider
        .stream_chat(
            &fixtures::single_turn_text("anthropic.claude-sonnet-5"),
            &ctx,
        )
        .await
        .expect("must succeed against the text cassette");

    let headers = transport.captured_headers.lock().unwrap();
    let auth = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.as_str())
        .expect("SigV4 signing must produce an authorization header");

    // "AWS4-HMAC-SHA256 Credential=<key>/<date>/<region>/<service>/aws4_request, ..."
    let scope_segment = auth
        .split("Credential=")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap_or_else(|| panic!("authorization header {auth:?} has no Credential=... segment"));
    let service_in_scope = scope_segment
        .split('/')
        .nth(3)
        .unwrap_or_else(|| panic!("Credential scope {scope_segment:?} has no <service> segment"));
    assert_eq!(
        service_in_scope, EXPECTED_SERVICE,
        "signed Credential scope {scope_segment:?} does not carry the expected service \
         {EXPECTED_SERVICE:?} -- authorization header was {auth:?}"
    );
}

/// A transport that panics if `send` is ever called -- proves a request is
/// rejected before any network I/O is attempted. Mirrors
/// `conformance_openai_responses_batch.rs`'s identical helper.
struct PanicsIfCalledTransport;

impl roundhouse_provider::HttpTransport for PanicsIfCalledTransport {
    fn send<'a>(
        &'a self,
        _req: roundhouse_provider::HttpRequest,
    ) -> futures::future::BoxFuture<
        'a,
        Result<roundhouse_provider::HttpResponseStream, roundhouse_provider::TransportError>,
    > {
        panic!(
            "stream_chat must reject a SigV4/AzureEntra-declared profile's bare api_key \
             fallback before ever calling HttpTransport::send -- no authorization header, \
             Bearer or otherwise, may reach the wire"
        )
    }
}

/// Fix round 4, Fix 2: `anthropic_messages/provider.rs`'s bare-`api_key`
/// fallback's catch-all `other =>` arm (SigV4/AzureEntra) has no regression
/// proof for the two profiles that actually declare those auth kinds on
/// this codec. Mirrors `conformance_openai_responses_batch.rs`'s
/// `aws_open_responses_bare_api_key_fallback_fails_closed_for_sigv4` shape:
/// no `CredentialProvider` supplied, `PanicsIfCalledTransport` so a
/// regression fails by panic (an authorization header reaching `send`)
/// rather than a soft assertion.
#[tokio::test]
async fn bedrock_anthropic_messages_bare_api_key_fallback_fails_closed_for_sigv4() {
    use roundhouse_provider::{Provider, ProviderError, RequestCtx};

    let profile = load("bedrock-anthropic-messages");
    assert!(
        matches!(profile.defaults.auth, AuthKind::SigV4 { .. }),
        "test premise: bedrock-anthropic-messages must declare SigV4 auth, got {:?}",
        profile.defaults.auth
    );

    let ctx = RequestCtx {
        trace_id: None,
        transport: Arc::new(PanicsIfCalledTransport),
        api_key: "sk-ant-test-do-not-use".into(),
        credentials: None,
    };
    let provider = AnthropicMessagesProfileProvider::new(profile);
    match provider
        .stream_chat(
            &fixtures::single_turn_text("anthropic.claude-sonnet-5"),
            &ctx,
        )
        .await
    {
        Err(err) => assert!(
            matches!(err, ProviderError::Unsupported(_)),
            "expected Unsupported, got {err:?}"
        ),
        Ok(_) => panic!("a SigV4-declared profile with no real credentials must fail closed"),
    }
}

/// Same guarantee as above, for `microsoft-foundry` (`AzureEntra` auth).
#[tokio::test]
async fn microsoft_foundry_bare_api_key_fallback_fails_closed_for_azure_entra() {
    use roundhouse_provider::{Provider, ProviderError, RequestCtx};

    let profile = load("microsoft-foundry");
    assert!(
        matches!(profile.defaults.auth, AuthKind::AzureEntra { .. }),
        "test premise: microsoft-foundry must declare AzureEntra auth, got {:?}",
        profile.defaults.auth
    );

    let ctx = RequestCtx {
        trace_id: None,
        transport: Arc::new(PanicsIfCalledTransport),
        api_key: "sk-ant-test-do-not-use".into(),
        credentials: None,
    };
    let provider = AnthropicMessagesProfileProvider::new(profile);
    match provider
        .stream_chat(&fixtures::single_turn_text("claude-sonnet-5"), &ctx)
        .await
    {
        Err(err) => assert!(
            matches!(err, ProviderError::Unsupported(_)),
            "expected Unsupported, got {err:?}"
        ),
        Ok(_) => panic!("an AzureEntra-declared profile with no real credentials must fail closed"),
    }
}
