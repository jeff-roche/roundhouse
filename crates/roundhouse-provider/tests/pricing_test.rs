//! §9.7 / audit finding 4: models.dev + LiteLLM pricing-dataset ingestion.
//!
//! Uses the *existing* `roundhouse_provider::fallback::Cost` (a `Known(u64)`/
//! `Unknown` enum in pico-USD) rather than a second, task-specific `Cost` type
//! — see `src/pricing/mod.rs`'s module doc and this phase's
//! REALITY-CORRECTIONS §14d. `Usage` is `roundhouse_core::Usage`, not a
//! provider type (§14b); `ModelId` comes from the crate root, not
//! `roundhouse_provider::ir` (§14a, `ir` is a private module).

use roundhouse_core::Usage;
use roundhouse_provider::fallback::Cost;
use roundhouse_provider::pricing::{price_usage, PicoUsdPerToken, PricingSnapshot};
use roundhouse_provider::ModelId;

#[test]
fn models_dev_and_litellm_rates_normalize_identically() {
    // §9.7: "per-token not per-million — unit mismatch is a real bug source."
    // models.dev quotes $3.00 / 1M tokens; LiteLLM quotes $0.000003 / token for
    // the same real-world price. Both must normalize to the same PicoUsdPerToken.
    let from_models_dev = PicoUsdPerToken::from_usd_per_million(3.0).unwrap();
    let from_litellm = PicoUsdPerToken::from_usd_per_token(0.000003).unwrap();
    assert_eq!(from_models_dev, from_litellm);
    assert_eq!(from_models_dev.0, 3_000_000);
}

#[test]
fn negative_and_non_finite_rates_are_rejected() {
    assert!(PicoUsdPerToken::from_usd_per_million(-1.0).is_err());
    assert!(PicoUsdPerToken::from_usd_per_million(f64::NAN).is_err());
    assert!(PicoUsdPerToken::from_usd_per_token(f64::INFINITY).is_err());
}

#[test]
fn cost_for_tokens_scales_linearly_in_pico_usd() {
    let rate = PicoUsdPerToken::from_usd_per_million(3.0).unwrap();
    assert_eq!(rate.cost_for_tokens(1_000_000), 3_000_000_000_000); // $3.00 in pico-USD
    assert_eq!(rate.cost_for_tokens(0), 0);
}

#[test]
fn known_model_prices_from_fixture_snapshot() {
    let snapshot =
        PricingSnapshot::from_fixture_for_test(include_str!("../testdata/models_dev_fixture.json"));
    let usage = Usage {
        input_tokens: 1_000_000,
        output_tokens: 500_000,
        cache_read_tokens: 0,
    };
    let cost = price_usage(
        &usage,
        &ModelId("anthropic/claude-fixture-test".into()),
        &snapshot,
    );
    // Pinned by hand against the fixture's rates: 1,000,000 input tokens @
    // $3.00/M ($3,000,000,000,000 pico-USD) + 500,000 output tokens @
    // $15.00/M ($7,500,000,000,000 pico-USD) = $10,500,000,000,000 pico-USD.
    assert_eq!(cost, Cost::Known(10_500_000_000_000));
}

#[test]
fn unknown_model_yields_cost_unknown_not_a_guess() {
    // §9.7: "unknown pricing yields Cost::Unknown with tokens still recorded"
    let snapshot =
        PricingSnapshot::from_fixture_for_test(include_str!("../testdata/models_dev_fixture.json"));
    let usage = Usage {
        input_tokens: 100,
        output_tokens: 50,
        cache_read_tokens: 0,
    };
    let cost = price_usage(
        &usage,
        &ModelId("totally/unknown-model-xyz".into()),
        &snapshot,
    );
    assert!(matches!(cost, Cost::Unknown));
}

#[test]
fn cache_reads_are_billed_at_the_cache_read_rate_not_the_full_input_rate() {
    // Audit finding 4, the "#1 silent cost bug": input_tokens INCLUDES cache
    // reads (§9.3 invariant). claude-fixture-test's cache_read rate ($0.30/M)
    // is 10x cheaper than its base input rate ($3.00/M) — a task that is 90%
    // cache reads must cost far less than naively billing every input token
    // at the base rate would.
    let snapshot =
        PricingSnapshot::from_fixture_for_test(include_str!("../testdata/models_dev_fixture.json"));
    let model = ModelId("anthropic/claude-fixture-test".into());
    let usage = Usage {
        input_tokens: 1_000_000,
        output_tokens: 0,
        cache_read_tokens: 900_000,
    };
    let cost = price_usage(&usage, &model, &snapshot);

    // Pinned by hand: 100,000 base-rate tokens @ $3.00/M
    // ($300,000,000,000 pico-USD) + 900,000 cache-read tokens @ $0.30/M
    // ($270,000,000,000 pico-USD) = $570,000,000,000 pico-USD. A version that
    // silently charged the full input rate to every token (the bug this
    // fixes) would instead compute $3,000,000,000,000 (over 5x more, and the
    // 900,000-token cache-read portion alone would be overcharged 10x) — so
    // this pinned value fails loudly if the cache-read split silently stops
    // happening.
    assert_eq!(cost, Cost::Known(570_000_000_000));

    let naive_overcharge = PicoUsdPerToken::from_usd_per_million(3.0)
        .unwrap()
        .cost_for_tokens(1_000_000) as u64;
    let Cost::Known(pico_usd) = cost else {
        panic!("fixture model should be found")
    };
    assert!(
        pico_usd < naive_overcharge,
        "cache-aware pricing must charge less than the naive full-input-rate calculation"
    );
}

#[test]
fn cache_write_tokens_are_billed_at_the_cache_write_rate_when_supplied_out_of_band() {
    // Phase 0's frozen `roundhouse_core::Usage` has no `cache_write_tokens`
    // field (only `cache_read_tokens`) — see this task's design note. Codecs
    // that observe a distinct cache-write count directly (e.g. Anthropic's
    // `cache_creation_input_tokens`) pass it explicitly here instead.
    use roundhouse_provider::pricing::price_usage_with_cache_write;
    let snapshot =
        PricingSnapshot::from_fixture_for_test(include_str!("../testdata/models_dev_fixture.json"));
    let model = ModelId("anthropic/claude-fixture-test".into());
    let usage = Usage {
        input_tokens: 100_000,
        output_tokens: 0,
        cache_read_tokens: 0,
    };
    let cost = price_usage_with_cache_write(&usage, 50_000, &model, &snapshot);

    // Pinned by hand: 100,000 input tokens @ $3.00/M ($300,000,000,000
    // pico-USD) + 50,000 cache-write tokens @ $3.75/M ($187,500,000,000
    // pico-USD) = $487,500,000,000 pico-USD.
    assert_eq!(cost, Cost::Known(487_500_000_000));
}

#[test]
fn litellm_cache_rates_take_precedence_over_models_dev_when_both_are_present() {
    // §9.7: LiteLLM is "a pricing-only secondary (better on cache-write/
    // per-image cost corner cases)" — the merge must actually prefer it for
    // those fields, not just parse it and never read it (audit finding 4).
    let snapshot = PricingSnapshot::from_fixture_pair_for_test(
        include_str!("../testdata/models_dev_fixture.json"),
        include_str!("../testdata/litellm_fixture.json"),
    );
    let model = ModelId("anthropic/claude-fixture-test".into());
    let usage = Usage {
        input_tokens: 100_000,
        output_tokens: 0,
        cache_read_tokens: 100_000,
    };
    let cost = price_usage(&usage, &model, &snapshot);

    // litellm_fixture.json's cache_read_input_token_cost for this model is
    // $0.0000005/token ($0.50/M) — deliberately DIFFERENT from models.dev's
    // fixture value ($0.30/M) so the test can tell which source won. All
    // 100,000 input tokens are cache reads, so the base-rate portion is 0:
    // 100,000 cache-read tokens @ $0.50/M = $50,000,000,000 pico-USD. Had the
    // merge silently kept models.dev's $0.30/M instead, this would be
    // $30,000,000,000 — a different, wrong, pinned number.
    assert_eq!(
        cost,
        Cost::Known(50_000_000_000),
        "cache-read rate must come from LiteLLM when it has an entry, not silently fall back to models.dev"
    );
}

#[test]
fn litellm_object_with_no_matching_entry_still_yields_models_dev_pricing() {
    // Regression guard for the "[]" default the brief's own draft used for
    // `from_fixture_for_test`'s implicit LiteLLM fixture — LiteLLM's real
    // shape is a JSON OBJECT keyed by model name, not an array, so an empty
    // default must be "{}", not "[]", or this would fail to deserialize.
    let snapshot = PricingSnapshot::from_fixture_pair_for_test(
        include_str!("../testdata/models_dev_fixture.json"),
        "{}",
    );
    let usage = Usage {
        input_tokens: 1_000,
        output_tokens: 0,
        cache_read_tokens: 0,
    };
    let cost = price_usage(
        &usage,
        &ModelId("openai/gpt-fixture-test".into()),
        &snapshot,
    );
    // Pinned by hand: 1,000 input tokens @ $2.50/M = $2,500,000,000 pico-USD.
    // If "{}" failed to deserialize as an empty LiteLLM map (e.g. someone
    // "fixed" it back to the brief's original "[]"), this test would panic on
    // the `serde_json::from_str` inside `from_fixture_pair_for_test`, not
    // silently pass.
    assert_eq!(cost, Cost::Known(2_500_000_000));
}
