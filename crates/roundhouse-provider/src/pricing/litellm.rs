//! LiteLLM is used strictly as a **secondary** pricing source — only for its
//! cache-read/cache-write rates. This crate never reads LiteLLM's
//! `input_cost_per_token`/`output_cost_per_token` (models.dev, the primary
//! source, supplies those), so this struct carries only the two fields
//! `pricing::merge_entry` actually consults.
//!
//! **The "better on cache-write/per-image corner cases" rationale (§9.7) is
//! measured, and only true in a narrow long tail — correct this comment if
//! you touch that document without re-measuring.** Fix round 1's O7 measured
//! the actual merge against the live files: of 7,056 priced models.dev
//! models, only 332 (4.7%) exact-match a LiteLLM key at all, and LiteLLM
//! supplies a cache rate models.dev lacks for just 37 (0.5%) of them. Fix
//! round 2 added bare-id normalization for the four frontier providers where
//! the rationale's stated motivation actually applies (anthropic, openai,
//! google, amazon-bedrock — LiteLLM's real key convention for exactly these
//! four is the bare upstream model name, not models.dev's
//! `"<provider>/<model>"`); reconciliation for those four jumped from 0/213
//! to 199/213, but net-new cache coverage rose only 5 models (anthropic +0/14,
//! openai +2/43, google +2/33, bedrock +1/123) — 42/7,056 (0.6%) globally.
//! **models.dev already carries cache rates for the frontier providers on its
//! own**; LiteLLM's actual contribution is long-tail aggregators and
//! resellers, not the frontier-model cache-cost dominance the rationale was
//! originally framed around. The merge is kept anyway — it's real, tested,
//! and hardened (O1 plausibility ceiling, O2 parse validation, O4
//! force-evaluated in CI) — but say why accurately: coverage, not the
//! originally-stated frontier-cache-cost case.
//!
//! **Real file shape, verified live** (fetching
//! `https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json`
//! directly, 2026-09-02): a top-level JSON **object** keyed by model name
//! (3,518 entries, not the models.dev array shape) — including one
//! non-pricing `sample_spec` documentation entry mixed into the same map, and
//! many entries that are image/audio-only and carry neither cache field.
//! Every field here is `Option` with `#[serde(default)]` so none of that
//! aborts the parse.
//!
//! **Cross-dataset id reconciliation beyond the four normalized providers
//! remains a known, documented gap, not solved by this task** (see
//! `testdata/litellm_fixture.json`'s comment and `pricing::mod::lookup_litellm`):
//! for every other provider, LiteLLM's real keys use a different,
//! inconsistent naming convention from models.dev's `"<provider>/<model>"`
//! (e.g. `"bedrock/us-gov-east-1/anthropic.claude-sonnet-4-5-20250929-v1:0"`
//! for a model an *unnormalized* provider would otherwise never match), so an
//! exact-match lookup against a models.dev-style key will miss most real
//! entries there and fall back to models.dev's own cache rates. That
//! fallback is correct, honest behavior, not a bug: it never invents a rate
//! LiteLLM didn't actually publish under the key being looked up.

use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct LiteLlmEntry {
    #[serde(default)]
    pub cache_read_input_token_cost: Option<f64>,
    #[serde(default)]
    pub cache_creation_input_token_cost: Option<f64>,
}
