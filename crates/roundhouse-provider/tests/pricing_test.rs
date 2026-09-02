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

/// Fix round 1, O1: same shape as `testdata/models_dev_fixture.json`'s
/// `anthropic/claude-fixture-test` entry, except the input rate is
/// implausibly high ($15,000/1M — the exact shape a compromised upstream
/// entry would take: finite, non-negative, well inside `u64`'s pico range).
const ABOVE_CEILING_MODELS_DEV_JSON: &str = r#"[
  {
    "id": "anthropic/claude-too-expensive",
    "cost": { "input": 15000.0, "output": 15.0, "cache_read": 0.3, "cache_write": 3.75 }
  }
]"#;

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

#[test]
fn a_model_with_a_rate_above_the_plausibility_ceiling_prices_as_unknown() {
    // Fix round 1, O1: `PicoUsdPerToken::from_usd_per_million` now rejects
    // implausible rates (see `pricing/mod.rs`'s internal unit tests for the
    // constructor-level check); this is the black-box consequence —
    // `price_usage` must fail closed to `Cost::Unknown` for such a model
    // rather than propagating a confident, wrong `Cost::Known`.
    let snapshot = PricingSnapshot::from_fixture_for_test(ABOVE_CEILING_MODELS_DEV_JSON);
    let usage = Usage {
        input_tokens: 1_000,
        output_tokens: 0,
        cache_read_tokens: 0,
    };
    let cost = price_usage(
        &usage,
        &ModelId("anthropic/claude-too-expensive".into()),
        &snapshot,
    );
    assert!(
        matches!(cost, Cost::Unknown),
        "a rate above the plausibility ceiling must yield Cost::Unknown, not a wrong Cost::Known"
    );
}

#[test]
fn cache_read_tokens_exceeding_input_tokens_prices_as_unknown_not_a_silent_underbill() {
    // Fix round 1, O8: §9.3's invariant is that input_tokens INCLUDES cache
    // reads, so cache_read_tokens must never exceed input_tokens. Usage that
    // violates this is internally inconsistent; the old behavior silently
    // clamped via `.min()`, which under-bills the excess. Failing to
    // Cost::Unknown is the correct direction for a billing path.
    let snapshot =
        PricingSnapshot::from_fixture_for_test(include_str!("../testdata/models_dev_fixture.json"));
    let usage = Usage {
        input_tokens: 100,
        output_tokens: 0,
        cache_read_tokens: 900, // invariant violation: more cache reads than input tokens
    };
    let cost = price_usage(
        &usage,
        &ModelId("anthropic/claude-fixture-test".into()),
        &snapshot,
    );
    assert!(
        matches!(cost, Cost::Unknown),
        "cache_read_tokens > input_tokens is an invariant violation and must not be silently priced"
    );
}

#[test]
fn id_normalization_reconciles_a_bare_litellm_key_for_a_frontier_provider() {
    // Fix round 1, O7: LiteLLM's real key convention for anthropic/openai/
    // google/amazon-bedrock is the bare upstream model name, not
    // models.dev's fully-qualified "<provider>/<model>" id (verified live,
    // 2026-09-02). Without normalization this LiteLLM entry would never be
    // found for an "anthropic/..." models.dev id.
    let models_dev_json = r#"[
      {
        "id": "anthropic/claude-bare-key-test",
        "cost": { "input": 3.0, "output": 15.0, "cache_read": 0.3, "cache_write": 3.75 }
      }
    ]"#;
    // Bare key -- no "anthropic/" prefix -- matching LiteLLM's real convention.
    let litellm_json = r#"{
      "claude-bare-key-test": {
        "cache_read_input_token_cost": 0.0000005,
        "cache_creation_input_token_cost": null
      }
    }"#;
    let snapshot = PricingSnapshot::from_fixture_pair_for_test(models_dev_json, litellm_json);
    let usage = Usage {
        input_tokens: 100_000,
        output_tokens: 0,
        cache_read_tokens: 100_000,
    };
    let cost = price_usage(
        &usage,
        &ModelId("anthropic/claude-bare-key-test".into()),
        &snapshot,
    );
    // If normalization didn't fire, this would fall back to models.dev's
    // $0.30/M cache_read ($30,000,000,000 pico-USD) instead of LiteLLM's
    // $0.50/M ($50,000,000,000 pico-USD).
    assert_eq!(
        cost,
        Cost::Known(50_000_000_000),
        "bare-id normalization must reconcile the LiteLLM entry for a frontier provider"
    );
}

#[test]
fn id_normalization_does_not_apply_to_an_unlisted_provider() {
    // Fix round 1, O7: the normalization is deliberately scoped to the four
    // measured frontier providers, not a blanket bare-id fallback for every
    // provider -- an unlisted provider's bare-key collision with LiteLLM
    // must NOT be picked up.
    let models_dev_json = r#"[
      {
        "id": "some-other-provider/claude-bare-key-test",
        "cost": { "input": 3.0, "output": 15.0, "cache_read": 0.3, "cache_write": 3.75 }
      }
    ]"#;
    let litellm_json = r#"{
      "claude-bare-key-test": {
        "cache_read_input_token_cost": 0.0000005,
        "cache_creation_input_token_cost": null
      }
    }"#;
    let snapshot = PricingSnapshot::from_fixture_pair_for_test(models_dev_json, litellm_json);
    let usage = Usage {
        input_tokens: 100_000,
        output_tokens: 0,
        cache_read_tokens: 100_000,
    };
    let cost = price_usage(
        &usage,
        &ModelId("some-other-provider/claude-bare-key-test".into()),
        &snapshot,
    );
    // Must fall back to models.dev's $0.30/M cache_read
    // ($30,000,000,000 pico-USD), NOT LiteLLM's $0.50/M.
    assert_eq!(cost, Cost::Known(30_000_000_000));
}

#[test]
fn vendored_snapshot_parses_and_prices_a_known_model() {
    // Fix round 1, O4: `PricingSnapshot::vendored()`'s `.expect()`s are only
    // checked when the `LazyLock` is first forced -- NOT at build time. This
    // test forces that evaluation under `cargo test --workspace`, so a
    // committed-but-unparseable (or drastically restructured) vendor file
    // fails CI instead of panicking the daemon on the first real pricing
    // lookup in production.
    let snapshot = PricingSnapshot::vendored();
    let usage = Usage {
        input_tokens: 1_000,
        output_tokens: 100,
        cache_read_tokens: 0,
    };
    // anthropic/claude-sonnet-5 is present in the live-fetched vendor file as
    // of this commit; if a future refresh renames/removes it, swap this for
    // another currently-vendored model rather than deleting the test -- the
    // point is forcing real evaluation of the LazyLock, not this specific id.
    let cost = price_usage(
        &usage,
        &ModelId("anthropic/claude-sonnet-5".into()),
        snapshot,
    );
    assert!(
        matches!(cost, Cost::Known(_)),
        "expected a known vendored model to price successfully, got {cost:?}"
    );
}

#[test]
fn an_empty_models_dev_body_parses_but_yields_zero_priced_models() {
    // Fix round 1, O2: `{}` is valid JSON and a valid (if trivial) instance
    // of the real provider->models->model shape, so it parses successfully
    // -- to zero entries. This is exactly the gap `refresh_pricing.rs`'s
    // minimum-entry-count check exists to catch before such a body silently
    // replaces the vendored snapshot with one that prices nothing.
    let entries = PricingSnapshot::parse_models_dev_snapshot(b"{}").unwrap();
    assert_eq!(entries.len(), 0);
}

#[test]
fn a_wrong_shaped_models_dev_body_is_rejected_outright() {
    // Fix round 1, O2: a body that is valid JSON but not even the right
    // shape (e.g. an upstream API error payload) fails the typed parse
    // itself, distinct from (and a stronger guard than) the empty-body case
    // above.
    let result = PricingSnapshot::parse_models_dev_snapshot(br#"{"error":"rate limited"}"#);
    assert!(result.is_err());
}

#[test]
fn a_real_shaped_models_dev_body_parses_to_a_nonzero_entry_count() {
    // Sanity complement to the two tests above: confirms the zero/error
    // cases are actually distinguishing "empty/malformed" from "real,"
    // rather than this parse path always returning zero or always erroring.
    let body = br#"{
        "anthropic": {
            "models": {
                "claude-test": { "id": "claude-test", "cost": { "input": 3.0, "output": 15.0 } }
            }
        }
    }"#;
    let entries = PricingSnapshot::parse_models_dev_snapshot(body).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].id, "anthropic/claude-test");
}

#[test]
fn a_malformed_litellm_cache_rate_falls_back_to_models_dev_rather_than_going_free() {
    // Fix round 1, O9: an invalid (negative) LiteLLM cache rate must not be
    // silently treated as "no rate" and priced at zero -- it falls back to
    // models.dev's own cache_read rate (fail-safe direction: never free).
    // This crate additionally logs the rejection via `tracing::warn!` (see
    // `pricing/mod.rs`'s `parse_cache_rate`) so it's observable in practice,
    // not just correct in outcome.
    let models_dev_json = r#"[
      {
        "id": "anthropic/claude-fixture-test",
        "cost": { "input": 3.0, "output": 15.0, "cache_read": 0.3, "cache_write": 3.75 }
      }
    ]"#;
    let litellm_json = r#"{
      "anthropic/claude-fixture-test": {
        "cache_read_input_token_cost": -1.0,
        "cache_creation_input_token_cost": null
      }
    }"#;
    let snapshot = PricingSnapshot::from_fixture_pair_for_test(models_dev_json, litellm_json);
    let usage = Usage {
        input_tokens: 100_000,
        output_tokens: 0,
        cache_read_tokens: 100_000,
    };
    let cost = price_usage(
        &usage,
        &ModelId("anthropic/claude-fixture-test".into()),
        &snapshot,
    );
    // Falls back to models.dev's $0.30/M cache_read rate: 100,000 tokens @
    // $0.30/M = $30,000,000,000 pico-USD.
    assert_eq!(cost, Cost::Known(30_000_000_000));
}
