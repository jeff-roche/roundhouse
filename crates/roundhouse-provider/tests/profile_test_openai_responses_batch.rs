//! Deserialization shape tests for Task 16's six `openai-responses` batch
//! profiles (NVIDIA, Vercel, OpenRouter, HuggingFace, Databricks, AWS) --
//! §9.4's audit finding: `OpenAiResponsesProvider` (Task 5) already takes a
//! `ProviderProfile` in its constructor, so every profile below is pure data
//! reusing that codec's `encode`/`decode` unchanged; what differs per
//! profile is base URL, auth, error classification and (for three of the
//! six) `error_pointer`.
//!
//! Several of the brief's sample values were checked against each vendor's
//! own current documentation (task addendum §3c) and diverge here -- see
//! each profile TOML's header comment for the citation and fetch date:
//!
//! - `vercel.toml`: base_url corrected (`ai-gateway.vercel.sh`, not
//!   `gateway.ai.vercel.app`, which is not a real Vercel AI Gateway host).
//! - `openrouter-responses.toml`: `error_pointer` corrected to the
//!   endpoint's own documented top-level `error_type` field.
//! - `huggingface.toml`: base_url corrected (`router.huggingface.co`, the
//!   real Inference Providers / Responses API host, not
//!   `api-inference.huggingface.co`, the older, endpoint-less legacy host).
//! - `databricks.toml`: base_url is workspace-specific, so this uses the
//!   same RFC 6761 `.invalid` placeholder pattern already established by
//!   `microsoft-foundry.toml`/`azure-openai.toml`/`vertex-anthropic.toml`.
//!   `error_pointer` corrected to Databricks' own top-level `error_code`
//!   field.
//!
//! `nvidia-open-responses.toml` is a separate, larger concern reported in
//! this task's report file: this task's own research could not confirm
//! NVIDIA's hosted `integrate.api.nvidia.com` supports `/v1/responses` at
//! all (only `/v1/chat/completions` is documented, and a live probe against
//! that host is reported to return 404) -- the profile is still built per
//! the brief's explicit requirement (§9.4 lists NVIDIA on this codec's row),
//! but see the report for the full citation trail and an explicit request
//! for orchestrator review.

use roundhouse_provider::profile::ProviderProfile;

fn load(name: &str) -> ProviderProfile {
    let path = format!("{}/profiles/{name}.toml", env!("CARGO_MANIFEST_DIR"));
    toml::from_str(&std::fs::read_to_string(path).unwrap()).expect("valid profile must deserialize")
}

#[test]
fn nvidia_open_responses_profile_shape() {
    let p = load("nvidia-open-responses");
    assert_eq!(p.codec, "openai-responses");
    assert_eq!(p.defaults.base_url, "https://integrate.api.nvidia.com/v1");
}

#[test]
fn vercel_profile_shape() {
    let p = load("vercel");
    assert_eq!(p.codec, "openai-responses");
    assert_eq!(
        p.defaults.base_url, "https://ai-gateway.vercel.sh/v1",
        "verified against Vercel's own current AI Gateway docs (vercel.com/docs/ai-gateway/\
         sdks-and-apis/responses, fetched 2026-09-02) -- gateway.ai.vercel.app is not a real \
         Vercel AI Gateway host"
    );
}

#[test]
fn openrouter_responses_profile_shape() {
    // Distinct from openrouter.toml (Task 10) and openrouter-anthropic.toml
    // (Task 15) -- same vendor, third wire format, per §9.4's table.
    let p = load("openrouter-responses");
    assert_eq!(p.codec, "openai-responses");
    assert_eq!(
        p.error_pointer, "/error_type",
        "verified against OpenRouter's own Responses-API-specific error format doc (openrouter\
         .ai/docs/api_reference/errors-and-debugging, fetched 2026-09-02): 'both the streaming \
         terminal event and the non-streaming JSON body carry the canonical error_type at the \
         top level of the response object' -- NOT this codec's default /error/type, which for \
         this endpoint addresses a different, non-canonical field"
    );
}

#[test]
fn huggingface_profile_shape() {
    let p = load("huggingface");
    assert_eq!(p.codec, "openai-responses");
    assert_eq!(
        p.defaults.base_url, "https://router.huggingface.co/v1",
        "verified against Hugging Face's own current Responses API guide (huggingface.co/docs/\
         inference-providers/en/guides/responses-api, fetched 2026-09-02) -- \
         api-inference.huggingface.co is the older, deprecated-for-this-purpose legacy \
         Inference API host and documents no /v1/responses endpoint at all"
    );
}

#[test]
fn databricks_profile_shape() {
    let p = load("databricks");
    assert_eq!(p.codec, "openai-responses");
    assert_eq!(
        p.error_pointer, "/error_code",
        "verified against Databricks' own REST API error reference (docs.databricks.com/api/\
         workspace/errors, fetched 2026-09-02): the standard error body is a top-level \
         error_code field alongside message, not this codec's default nested /error/type"
    );
}

#[test]
fn aws_open_responses_profile_uses_sigv4() {
    // §9.2: "AWS" appears in the Open Responses backer list distinct from
    // both bedrock-converse (Task 7) and bedrock-anthropic-messages (Task 15).
    let p = load("aws-open-responses");
    assert_eq!(p.codec, "openai-responses");
    assert!(matches!(
        p.defaults.auth,
        roundhouse_provider::profile::AuthKind::SigV4 { .. }
    ));
}
