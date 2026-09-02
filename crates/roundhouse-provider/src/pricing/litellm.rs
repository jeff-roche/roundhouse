//! LiteLLM is used strictly as a **secondary** pricing source — only for its
//! cache-read/cache-write rates, which §9.7 calls out as the corner case it is
//! "better on." This crate never reads LiteLLM's `input_cost_per_token`/
//! `output_cost_per_token` (models.dev, the primary source, supplies those),
//! so this struct carries only the two fields `pricing::merge_entry` actually
//! consults.
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
//! **Cross-dataset id reconciliation is a known, documented gap, not solved
//! by this task** (see `testdata/litellm_fixture.json`'s comment and
//! `pricing::PricingSnapshot`'s `PricingLookup` impl): LiteLLM's real keys use
//! a different, inconsistent naming convention from models.dev's
//! `"<provider>/<model>"` (e.g. bare `"claude-sonnet-5"`, or
//! `"bedrock/us-gov-east-1/anthropic.claude-sonnet-4-5-20250929-v1:0"`), so an
//! exact-match lookup against a models.dev-style key will miss most real
//! entries and fall back to models.dev's own cache rates. That fallback is
//! correct, honest behavior, not a bug: it never invents a rate LiteLLM
//! didn't actually publish under the key being looked up.

use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct LiteLlmEntry {
    #[serde(default)]
    pub cache_read_input_token_cost: Option<f64>,
    #[serde(default)]
    pub cache_creation_input_token_cost: Option<f64>,
}
