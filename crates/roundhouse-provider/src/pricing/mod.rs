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
//!
//! **Fail-safe direction, throughout:** every fallback in this module errs
//! toward *not pricing* (`Cost::Unknown`) or toward the more expensive rate,
//! never toward a confident low number. A refusal to price is recoverable
//! (a caller can retry once pricing data improves); a silently wrong price
//! is not.

mod litellm;
mod models_dev;

pub use litellm::LiteLlmEntry;
pub use models_dev::{ModelsDevCost, ModelsDevEntry};

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
    #[error(
        "rate {0} (${1:.2}/1M tokens) exceeds the ${MAX_USD_PER_MILLION:.0}/1M plausibility ceiling"
    )]
    AboveCeiling(f64, f64),
}

/// Anything priced above this many USD per million tokens is treated as
/// implausible rather than billed. The highest real input rate anywhere in
/// the live-vendored dataset (checked 2026-09-02) is $150/1M
/// (`openai/o1-pro`); $10,000/1M is ~65x that, leaving headroom for a
/// genuinely expensive future frontier model while still catching a
/// corrupted or maliciously altered upstream entry: `PicoUsdPerToken`'s
/// other checks (non-negative, finite, fits in `u64`) all pass for a
/// mis-scaled or tampered rate like $15,000/1M just as readily as for a real
/// one, since it's still finite, non-negative, and well inside `u64`'s pico
/// range — only an explicit plausibility ceiling catches that (O1).
/// LiteLLM in particular is fetched from `main` on `raw.githubusercontent.com`
/// with no pinned commit, so a single merged upstream PR is the entire attack
/// surface for this class of bug.
const MAX_USD_PER_MILLION: f64 = 10_000.0;

/// USD price per token, stored as 10^-12 USD ("pico-dollars") per token, so
/// summing across millions of usage rows never accumulates float drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PicoUsdPerToken(pub u64);

impl PicoUsdPerToken {
    /// models.dev publishes USD per **million** tokens.
    pub fn from_usd_per_million(usd_per_million: f64) -> Result<Self, PricingError> {
        Self::from_rate(usd_per_million, 1_000_000.0, usd_per_million)
    }

    /// LiteLLM publishes USD per **single** token.
    pub fn from_usd_per_token(usd_per_token: f64) -> Result<Self, PricingError> {
        Self::from_rate(
            usd_per_token,
            1_000_000_000_000.0,
            usd_per_token * 1_000_000.0,
        )
    }

    /// `rate` is the raw value as published by the source (already in its
    /// own unit); `multiplier` converts it to pico-USD-per-token;
    /// `usd_per_million_equivalent` is `rate` re-expressed in USD-per-million
    /// terms purely so the plausibility ceiling (O1) can be stated and
    /// checked in one unit regardless of which of the two source units
    /// called in.
    fn from_rate(
        rate: f64,
        multiplier: f64,
        usd_per_million_equivalent: f64,
    ) -> Result<Self, PricingError> {
        if !rate.is_finite() || rate < 0.0 {
            return Err(PricingError::InvalidRate(rate));
        }
        if usd_per_million_equivalent > MAX_USD_PER_MILLION {
            return Err(PricingError::AboveCeiling(rate, usd_per_million_equivalent));
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
/// source, §9.7) — `Option` because `ModelsDevCost.input`/`.output` are now
/// `Option<f64>` too (fix round 2 close-out item 2), and a `None` here means
/// `price_usage` fails closed to `Cost::Unknown` rather than pricing with a
/// fabricated rate; `flatten_root` already skips a live-dataset model
/// missing either field, so this is defense-in-depth for that plus the
/// hand-written test fixture path, which bypasses `flatten_root` entirely.
/// `cache_read_pico`/`cache_write_pico` prefer LiteLLM when it has an entry
/// for this model ("better on cache-write/per-image cost corner cases,"
/// §9.7 — though fix round 1's O7 measurement found this contributes only
/// 5 net-new models of 7,056 even after id-normalization; models.dev's own
/// cache coverage already dominates, see `litellm.rs`'s module doc) and fall
/// back to models.dev's own `cache_read`/`cache_write` fields otherwise.
/// `None` means neither source has a cache rate for this model —
/// `price_usage` then falls back to the base input rate for that portion
/// rather than silently charging $0 (audit finding 4: the bug this whole
/// task fixes was silently mispricing cache tokens, so a missing rate must
/// never resolve to "free").
struct MergedPricingEntry {
    input: Option<f64>,
    output: Option<f64>,
    cache_read_pico: Option<PicoUsdPerToken>,
    cache_write_pico: Option<PicoUsdPerToken>,
}

/// Parses one cache rate, logging (not silently swallowing, O9) and folding
/// to `None` if the source published something `PicoUsdPerToken` rejects
/// (negative, non-finite, or above the plausibility ceiling) — the caller
/// then falls through to the next-preferred source rather than treating a
/// malformed rate as "no rate," which would be observationally identical to
/// a genuinely absent field.
fn parse_cache_rate(
    model_id: &str,
    source: &str,
    field: &str,
    rate: f64,
    parse: impl FnOnce(f64) -> Result<PicoUsdPerToken, PricingError>,
) -> Option<PicoUsdPerToken> {
    match parse(rate) {
        Ok(p) => Some(p),
        Err(e) => {
            tracing::warn!(
                model_id,
                source,
                field,
                rate,
                error = %e,
                "malformed pricing rate ignored, falling back to the next source"
            );
            None
        }
    }
}

fn merge_entry(md: &ModelsDevEntry, litellm: Option<&LiteLlmEntry>) -> MergedPricingEntry {
    let cache_read_pico = litellm
        .and_then(|l| l.cache_read_input_token_cost)
        .and_then(|r| {
            parse_cache_rate(
                &md.id,
                "litellm",
                "cache_read_input_token_cost",
                r,
                PicoUsdPerToken::from_usd_per_token,
            )
        })
        .or_else(|| {
            md.cost.cache_read.and_then(|r| {
                parse_cache_rate(
                    &md.id,
                    "models.dev",
                    "cache_read",
                    r,
                    PicoUsdPerToken::from_usd_per_million,
                )
            })
        });
    let cache_write_pico = litellm
        .and_then(|l| l.cache_creation_input_token_cost)
        .and_then(|r| {
            parse_cache_rate(
                &md.id,
                "litellm",
                "cache_creation_input_token_cost",
                r,
                PicoUsdPerToken::from_usd_per_token,
            )
        })
        .or_else(|| {
            md.cost.cache_write.and_then(|w| {
                parse_cache_rate(
                    &md.id,
                    "models.dev",
                    "cache_write",
                    w,
                    PicoUsdPerToken::from_usd_per_million,
                )
            })
        });
    MergedPricingEntry {
        input: md.cost.input,
        output: md.cost.output,
        cache_read_pico,
        cache_write_pico,
    }
}

/// Provider ids (models.dev's own, i.e. the segment before the `/` in a
/// fully-qualified `"<provider>/<model>"` id) for which `lookup_litellm`
/// below also tries a normalized, provider-prefix-stripped key against
/// LiteLLM's map (O7). Scoped narrowly to the four frontier providers where
/// prompt caching is the dominant real-world cost pattern — the entire
/// stated motivation for merging LiteLLM in at all — rather than applied
/// blanket to every provider, since the measured effect for the other ~200
/// models.dev providers is unmeasured and out of scope for this fix.
const ID_NORMALIZED_PROVIDERS: &[&str] = &["anthropic", "openai", "google", "amazon-bedrock"];

/// Looks up `fully_qualified_id` (models.dev's own `"<provider>/<model>"`
/// key) in LiteLLM's map, trying an exact match first and then — only for
/// `ID_NORMALIZED_PROVIDERS` — the bare model id with the provider prefix
/// stripped, since LiteLLM's real key convention for exactly these four
/// providers is the bare upstream model name (verified live, 2026-09-02:
/// e.g. models.dev's `"anthropic/claude-sonnet-5"` vs LiteLLM's bare
/// `"claude-sonnet-5"`). Google's LiteLLM entries additionally often carry a
/// `"gemini/"` prefix instead of no prefix at all, so that variant is tried
/// too.
///
/// This is a **known-narrow, measured** normalization, not general
/// cross-dataset id reconciliation (see `litellm.rs`'s module doc for why
/// that remains an explicit, out-of-scope gap for every other provider).
fn lookup_litellm<'a>(
    litellm_by_id: &'a BTreeMap<String, LiteLlmEntry>,
    fully_qualified_id: &str,
) -> Option<&'a LiteLlmEntry> {
    if let Some(entry) = litellm_by_id.get(fully_qualified_id) {
        return Some(entry);
    }
    for provider in ID_NORMALIZED_PROVIDERS {
        let Some(bare) = fully_qualified_id
            .strip_prefix(provider)
            .and_then(|s| s.strip_prefix('/'))
        else {
            continue;
        };
        if let Some(entry) = litellm_by_id.get(bare) {
            return Some(entry);
        }
        if *provider == "google" {
            if let Some(entry) = litellm_by_id.get(&format!("gemini/{bare}")) {
                return Some(entry);
            }
        }
    }
    None
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
                    let litellm_entry = lookup_litellm(&litellm_by_id, &md.id);
                    let merged = merge_entry(&md, litellm_entry);
                    (md.id, merged)
                })
                .collect(),
        }
    }

    /// Parses `bytes` as models.dev's real, live-verified nested JSON shape
    /// (`provider -> models -> model`, not a flat array) and flattens it to
    /// the id-qualified shape `PricingSnapshot` uses internally. Exposed
    /// (not just used by `vendored()` below) so `refresh_pricing.rs` can run
    /// the same real typed parse against a freshly-fetched body *before*
    /// overwriting the committed vendor file (O2) — a body that is valid
    /// JSON but the wrong shape (e.g. `{}`, or an upstream API error
    /// payload) must fail this parse rather than silently becoming an
    /// all-`Cost::Unknown` snapshot.
    pub fn parse_models_dev_snapshot(
        bytes: &[u8],
    ) -> Result<Vec<ModelsDevEntry>, serde_json::Error> {
        let root: BTreeMap<String, models_dev::ModelsDevProvider> = serde_json::from_slice(bytes)?;
        Ok(models_dev::flatten_root(root))
    }

    /// Parses `bytes` as LiteLLM's real shape (a flat JSON object keyed by
    /// model name). Exposed for the same reason as
    /// `parse_models_dev_snapshot` above (O2).
    pub fn parse_litellm_snapshot(
        bytes: &[u8],
    ) -> Result<BTreeMap<String, LiteLlmEntry>, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// The real, live-fetched-and-vendored snapshot: both
    /// `vendor/models_dev_snapshot.json` (the real nested
    /// `provider -> models -> model` shape, flattened by
    /// `models_dev::flatten_root`) and `vendor/litellm_pricing_snapshot.json`
    /// (a flat object keyed by model name) are parsed and merged — audit
    /// finding 4's fix: an earlier draft parsed only the first file and never
    /// read the second.
    ///
    /// The `.expect()`s below are **not** a build-time guarantee — `LazyLock`
    /// defers them to first use, so a malformed vendored file would
    /// otherwise compile fine and panic the daemon on the first real pricing
    /// lookup (O4). `refresh_pricing.rs`'s own use of
    /// `parse_models_dev_snapshot`/`parse_litellm_snapshot` before writing
    /// (O2) is the primary defense; this crate's own
    /// `vendored_snapshot_parses_and_prices_a_known_model` test
    /// (`tests/pricing_test.rs`) is the second, forcing this `LazyLock` to
    /// evaluate under `cargo test --workspace` so a committed-but-broken
    /// snapshot fails CI instead of reaching production.
    pub fn vendored() -> &'static Self {
        static SNAPSHOT: LazyLock<PricingSnapshot> = LazyLock::new(|| {
            let md_entries = PricingSnapshot::parse_models_dev_snapshot(include_bytes!(
                "../../vendor/models_dev_snapshot.json"
            ))
            .expect(
                "vendored models.dev snapshot must parse — the weekly refresh PR's CI \
                 run validates this before merge (§9.7)",
            );
            let litellm_by_id = PricingSnapshot::parse_litellm_snapshot(include_bytes!(
                "../../vendor/litellm_pricing_snapshot.json"
            ))
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

/// Sums the (up to four) individually-computed pico-USD terms billed for one
/// usage, folding to `None` (→ `Cost::Unknown`) rather than silently
/// wrapping if the total overflows `u128` (O5). Each individual
/// `cost_for_tokens` term is already bounded well under `u128::MAX` for any
/// rate that went through `PicoUsdPerToken::from_usd_per_million`/
/// `from_usd_per_token` (both now capped by `MAX_USD_PER_MILLION`, O1) — but
/// `PicoUsdPerToken`'s inner `u64` is a public field, constructible directly
/// without going through either parser, so this guard is independent
/// defense-in-depth, not redundant with the ceiling.
fn checked_sum_pico_usd(terms: [u128; 4]) -> Option<u128> {
    terms
        .into_iter()
        .try_fold(0u128, |acc, term| acc.checked_add(term))
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
    // A `None` here means models.dev published this model's `cost` object
    // without `input`/`output` -- fails closed rather than fabricating a
    // rate. `flatten_root` already skips this case for the live dataset;
    // this covers the hand-written test-fixture path too (fix round 2
    // close-out item 2).
    let Some(input) = entry.input else {
        return Cost::Unknown;
    };
    let Some(output) = entry.output else {
        return Cost::Unknown;
    };
    let Ok(input_rate) = PicoUsdPerToken::from_usd_per_million(input) else {
        return Cost::Unknown;
    };
    let Ok(output_rate) = PicoUsdPerToken::from_usd_per_million(output) else {
        return Cost::Unknown;
    };

    // §9.3 invariant: input_tokens is the TOTAL already including cache
    // reads, so cache_read_tokens must never exceed it. If it does, usage
    // itself is inconsistent with the IR's own contract — billing anyway
    // (the old behavior clamped via `.min()`) would silently under-bill the
    // excess, which is the wrong failure direction for a billing path (O8).
    if usage.cache_read_tokens > usage.input_tokens {
        return Cost::Unknown;
    }
    let cache_read_tokens = usage.cache_read_tokens;
    let base_input_tokens = usage.input_tokens - cache_read_tokens;
    let cache_read_rate = entry.cache_read_pico.unwrap_or(input_rate);
    let cache_write_rate = entry.cache_write_pico.unwrap_or(input_rate);

    let terms = [
        input_rate.cost_for_tokens(base_input_tokens),
        cache_read_rate.cost_for_tokens(cache_read_tokens),
        cache_write_rate.cost_for_tokens(cache_write_tokens),
        output_rate.cost_for_tokens(usage.output_tokens),
    ];
    let Some(total_pico_usd) = checked_sum_pico_usd(terms) else {
        return Cost::Unknown;
    };

    match u64::try_from(total_pico_usd) {
        Ok(pico_usd) => Cost::Known(pico_usd),
        Err(_) => Cost::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// O5: two terms that individually sit near `u128::MAX` must fold the
    /// total to `Cost::Unknown` (via `None` here) rather than wrapping to an
    /// arbitrary small, confidently-wrong value. Exercised at this internal
    /// level (rather than only through the public `price_usage` API) because
    /// every rate reachable through the public parsing path is now bounded
    /// by `MAX_USD_PER_MILLION` (O1), so this specific overflow can only be
    /// driven through `PicoUsdPerToken`'s public tuple field directly.
    #[test]
    fn checked_sum_pico_usd_folds_to_none_on_overflow_rather_than_wrapping() {
        let near_max = PicoUsdPerToken(u64::MAX).cost_for_tokens(u64::MAX);
        assert!(checked_sum_pico_usd([near_max, near_max, 0, 0]).is_none());
        assert_eq!(checked_sum_pico_usd([1, 2, 3, 4]), Some(10));
    }

    /// O1: a rate above the plausibility ceiling is rejected even though it
    /// is finite, non-negative, and well inside `u64`'s pico range — the
    /// exact shape a compromised upstream entry would take.
    #[test]
    fn from_usd_per_million_rejects_a_rate_above_the_plausibility_ceiling() {
        assert!(PicoUsdPerToken::from_usd_per_million(150.0).is_ok());
        assert!(PicoUsdPerToken::from_usd_per_million(15_000.0).is_err());
    }

    #[test]
    fn from_usd_per_token_rejects_a_rate_above_the_plausibility_ceiling() {
        // $150/1M == $0.00015/token; $15,000/1M == $0.015/token.
        assert!(PicoUsdPerToken::from_usd_per_token(0.00015).is_ok());
        assert!(PicoUsdPerToken::from_usd_per_token(0.015).is_err());
    }

    /// O7: bare-id normalization for the four frontier providers actually
    /// finds a LiteLLM entry that an exact-match lookup would miss.
    #[test]
    fn lookup_litellm_normalizes_bare_ids_for_the_four_frontier_providers() {
        let mut litellm_by_id = BTreeMap::new();
        litellm_by_id.insert(
            "claude-sonnet-5".to_string(),
            LiteLlmEntry {
                cache_read_input_token_cost: Some(0.0000002),
                cache_creation_input_token_cost: None,
            },
        );
        litellm_by_id.insert(
            "gemini/gemini-2.5-pro".to_string(),
            LiteLlmEntry {
                cache_read_input_token_cost: Some(0.000000125),
                cache_creation_input_token_cost: None,
            },
        );

        assert!(lookup_litellm(&litellm_by_id, "anthropic/claude-sonnet-5").is_some());
        assert!(lookup_litellm(&litellm_by_id, "google/gemini-2.5-pro").is_some());
        // Not in the normalized list: no bare-id fallback for an arbitrary provider.
        assert!(lookup_litellm(&litellm_by_id, "some-other-provider/claude-sonnet-5").is_none());
    }
}
