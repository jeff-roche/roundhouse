//! §9.7 pricing-dataset ingestion: normalizes model cost data from two
//! vendored third-party JSON snapshots (models.dev, LiteLLM) into
//! `PicoUsdPerToken` rates, and offers `PricingSnapshot`, an implementation
//! of the *already existing* `crate::fallback::PricingLookup` trait over the
//! merged result.
//!
//! **`Cost`/`PricingLookup` are not defined here.** They already exist in
//! `crate::fallback` — this module feeds them, it does not redefine them.
//! Defining a second `Cost` type would repeat a duplicate-type mistake this
//! crate has already had to clean up once (see `errors.rs`'s module doc for
//! that history).
//!
//! **Audit finding 4, "the #1 silent cost bug":** `usage.input_tokens`
//! includes cache reads by the IR's own invariant (§9.3), so charging every
//! input token the base input rate overcharges every cache-heavy task — the
//! dominant real-world pattern (a stable system prompt/tool-definition prefix
//! re-read turn after turn). `price_usage`/`price_usage_with_cache_write`
//! split `input_tokens` into the true base-rate remainder and
//! `cache_read_tokens`, billing each at its own rate, and actually load and
//! merge *both* vendored snapshots (`PricingSnapshot::vendored`), preferring
//! LiteLLM's cache rates when present and falling back to models.dev's own
//! `cache_read`/`cache_write` fields otherwise (`merge_entry`).
//!
//! Cache-*write* tokens have no counterpart field in Phase 0's frozen
//! `roundhouse_core::Usage` (only `cache_read_tokens` exists there), so
//! `price_usage_with_cache_write` accepts that count as an explicit
//! out-of-band parameter for the codec paths that observe it directly from
//! the wire (e.g. Anthropic's `cache_creation_input_tokens`); the default
//! `price_usage` (used by everything else) passes `0`.

mod litellm;
mod models_dev;

pub use litellm::LiteLlmEntry;
pub use models_dev::{ModelsDevCost, ModelsDevEntry, ModelsDevLimit};

use crate::fallback::{Cost, PricingLookup};
use crate::{ModelId, ProviderId};
use roundhouse_core::Usage;
use std::collections::BTreeMap;
use std::sync::LazyLock;
use thiserror::Error;

#[derive(Debug, Error, Clone, Copy, PartialEq)]
pub enum PricingError {
    #[error("rate {0} is not a valid non-negative finite USD rate")]
    InvalidRate(f64),
    #[error("rate {0} overflows PicoUsdPerToken's u64 range")]
    Overflow(f64),
}

/// USD price per token, stored as 10^-12 USD ("pico-dollars") per token, so
/// summing across millions of usage rows never accumulates float drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PicoUsdPerToken(pub u64);

impl PicoUsdPerToken {
    /// models.dev publishes USD per **million** tokens.
    pub fn from_usd_per_million(usd_per_million: f64) -> Result<Self, PricingError> {
        Self::from_rate(usd_per_million, 1_000_000.0)
    }

    /// LiteLLM publishes USD per **single** token.
    pub fn from_usd_per_token(usd_per_token: f64) -> Result<Self, PricingError> {
        Self::from_rate(usd_per_token, 1_000_000_000_000.0)
    }

    fn from_rate(rate: f64, multiplier: f64) -> Result<Self, PricingError> {
        if !rate.is_finite() || rate < 0.0 {
            return Err(PricingError::InvalidRate(rate));
        }
        let pico = (rate * multiplier).round();
        if !pico.is_finite() || pico > u64::MAX as f64 {
            return Err(PricingError::Overflow(rate));
        }
        Ok(PicoUsdPerToken(pico as u64))
    }

    /// Cost, in pico-USD, of billing `tokens` tokens at this rate. Returns
    /// `u128` (rather than a possibly-overflowing `u64`) because this is only
    /// ever one term of a sum `price_usage_with_cache_write` folds down to
    /// `u64` (or `Cost::Unknown` on overflow) at the end.
    pub fn cost_for_tokens(self, tokens: u64) -> u128 {
        self.0 as u128 * tokens as u128
    }
}

/// The per-model rates `price_usage` actually needs, merged from both
/// datasets. `input`/`output` always come from models.dev (the primary
/// source, §9.7); `cache_read_pico`/`cache_write_pico` prefer LiteLLM when it
/// has an entry for this model ("better on cache-write/per-image cost corner
/// cases," §9.7) and fall back to models.dev's own `cache_read`/`cache_write`
/// fields otherwise. `None` means neither source has a cache rate for this
/// model — `price_usage` then falls back to the base input rate for that
/// portion rather than silently charging $0 (audit finding 4: the bug this
/// whole task fixes was silently mispricing cache tokens, so a missing rate
/// must never resolve to "free").
struct MergedPricingEntry {
    input: f64,
    output: f64,
    cache_read_pico: Option<PicoUsdPerToken>,
    cache_write_pico: Option<PicoUsdPerToken>,
}

fn merge_entry(md: &ModelsDevEntry, litellm: Option<&LiteLlmEntry>) -> MergedPricingEntry {
    let cache_read_pico = litellm
        .and_then(|l| l.cache_read_input_token_cost)
        .and_then(|r| PicoUsdPerToken::from_usd_per_token(r).ok())
        .or_else(|| {
            md.cost
                .cache_read
                .and_then(|r| PicoUsdPerToken::from_usd_per_million(r).ok())
        });
    let cache_write_pico = litellm
        .and_then(|l| l.cache_creation_input_token_cost)
        .and_then(|r| PicoUsdPerToken::from_usd_per_token(r).ok())
        .or_else(|| {
            md.cost
                .cache_write
                .and_then(|w| PicoUsdPerToken::from_usd_per_million(w).ok())
        });
    MergedPricingEntry {
        input: md.cost.input,
        output: md.cost.output,
        cache_read_pico,
        cache_write_pico,
    }
}

/// A merged models.dev + LiteLLM pricing table, keyed by models.dev's own
/// fully-qualified `"<provider>/<model>"` id. Implements the *existing*
/// `PricingLookup` trait (`crate::fallback`) rather than redefining pricing
/// types.
pub struct PricingSnapshot {
    by_model_id: BTreeMap<String, MergedPricingEntry>,
}

impl PricingSnapshot {
    /// Test-only: builds a snapshot from a hand-written models.dev-shaped
    /// fixture (a flat JSON array — see `testdata/models_dev_fixture.json`),
    /// with no LiteLLM data merged in.
    pub fn from_fixture_for_test(models_dev_json: &str) -> Self {
        Self::from_fixture_pair_for_test(models_dev_json, "{}")
    }

    /// Test-only: same as `from_fixture_for_test`, but also merges a
    /// hand-written LiteLLM-shaped fixture (a JSON *object* keyed by model
    /// name — see `testdata/litellm_fixture.json`), so tests can exercise the
    /// merge-precedence rule (audit finding 4) directly instead of only ever
    /// hitting the models.dev-only fallback.
    pub fn from_fixture_pair_for_test(models_dev_json: &str, litellm_json: &str) -> Self {
        let md_entries: Vec<ModelsDevEntry> = serde_json::from_str(models_dev_json)
            .expect("test fixture must be valid ModelsDevEntry JSON");
        let litellm_by_id: BTreeMap<String, LiteLlmEntry> = serde_json::from_str(litellm_json)
            .expect(
                "test fixture must be valid LiteLLM-shaped JSON (an object keyed by model name)",
            );
        Self::from_entries(md_entries, litellm_by_id)
    }

    fn from_entries(
        md_entries: Vec<ModelsDevEntry>,
        litellm_by_id: BTreeMap<String, LiteLlmEntry>,
    ) -> Self {
        Self {
            by_model_id: md_entries
                .into_iter()
                .map(|md| {
                    let merged = merge_entry(&md, litellm_by_id.get(&md.id));
                    (md.id, merged)
                })
                .collect(),
        }
    }

    /// The real, live-fetched-and-vendored snapshot: both
    /// `vendor/models_dev_snapshot.json` (the real nested
    /// `provider -> models -> model` shape, flattened by
    /// `models_dev::flatten_root`) and `vendor/litellm_pricing_snapshot.json`
    /// (a flat object keyed by model name) are parsed and merged — audit
    /// finding 4's fix: an earlier draft parsed only the first file and never
    /// read the second.
    pub fn vendored() -> &'static Self {
        static SNAPSHOT: LazyLock<PricingSnapshot> = LazyLock::new(|| {
            let root: BTreeMap<String, models_dev::ModelsDevProvider> =
                serde_json::from_slice(include_bytes!("../../vendor/models_dev_snapshot.json"))
                    .expect(
                        "vendored models.dev snapshot must parse — the weekly refresh PR's CI \
                 run validates this before merge (§9.7)",
                    );
            let md_entries = models_dev::flatten_root(root);

            let litellm_by_id: BTreeMap<String, LiteLlmEntry> = serde_json::from_slice(
                include_bytes!("../../vendor/litellm_pricing_snapshot.json"),
            )
            .expect("vendored LiteLLM snapshot must parse (§9.7)");

            PricingSnapshot::from_entries(md_entries, litellm_by_id)
        });
        &SNAPSHOT
    }
}

impl PricingLookup for PricingSnapshot {
    /// models.dev's own id convention is `"<provider>/<model>"` (verified
    /// live, 2026-09-02) — reconciling that against every real provider's own
    /// `ProviderId`/`ModelId` naming is a known, documented gap (see
    /// `litellm.rs`'s module doc): this builds that same key and does an
    /// exact-match lookup, nothing more.
    fn cost_for(&self, usage: &Usage, provider: &ProviderId, model: &ModelId) -> Cost {
        let key = ModelId(format!("{}/{}", provider.0, model.0));
        price_usage_with_cache_write(usage, 0, &key, self)
    }
}

/// §9.7: "cost is a derived view over (usage, pricing_snapshot_id), never a
/// stored column." Charges the base input rate only to the non-cache-read
/// remainder of `input_tokens` (fixing audit finding 4's "#1 silent cost
/// bug" — see this module's doc comment). No cache-write tokens: Phase 0's
/// frozen `Usage` carries none, so this is
/// `price_usage_with_cache_write(.., 0, ..)`.
pub fn price_usage(usage: &Usage, model: &ModelId, snapshot: &PricingSnapshot) -> Cost {
    price_usage_with_cache_write(usage, 0, model, snapshot)
}

/// Same as `price_usage`, plus an explicit cache-write token count for the
/// codec paths that observe one directly from the wire (e.g. Anthropic's
/// `cache_creation_input_tokens`) — see this module's doc comment on why this
/// isn't just a field on `Usage` itself.
pub fn price_usage_with_cache_write(
    usage: &Usage,
    cache_write_tokens: u64,
    model: &ModelId,
    snapshot: &PricingSnapshot,
) -> Cost {
    let Some(entry) = snapshot.by_model_id.get(&model.0) else {
        return Cost::Unknown;
    };
    let Ok(input_rate) = PicoUsdPerToken::from_usd_per_million(entry.input) else {
        return Cost::Unknown;
    };
    let Ok(output_rate) = PicoUsdPerToken::from_usd_per_million(entry.output) else {
        return Cost::Unknown;
    };

    // §9.3 invariant: input_tokens is the TOTAL already including cache reads
    // — never charge the (typically much higher) base input rate to them.
    let cache_read_tokens = usage.cache_read_tokens.min(usage.input_tokens);
    let base_input_tokens = usage.input_tokens - cache_read_tokens;
    let cache_read_rate = entry.cache_read_pico.unwrap_or(input_rate);
    let cache_write_rate = entry.cache_write_pico.unwrap_or(input_rate);

    let total_pico_usd: u128 = input_rate.cost_for_tokens(base_input_tokens)
        + cache_read_rate.cost_for_tokens(cache_read_tokens)
        + cache_write_rate.cost_for_tokens(cache_write_tokens)
        + output_rate.cost_for_tokens(usage.output_tokens);

    match u64::try_from(total_pico_usd) {
        Ok(pico_usd) => Cost::Known(pico_usd),
        Err(_) => Cost::Unknown,
    }
}
