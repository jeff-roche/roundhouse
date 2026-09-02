//! Types for models.dev's pricing dataset — both the small, hand-written test
//! fixtures (a flat JSON array) and the real vendored dataset
//! (`vendor/models_dev_snapshot.json`, a deeply nested object), flattened to
//! the same shape.
//!
//! **The real dataset's shape was verified live** (fetching
//! `https://models.dev/api.json` directly, 2026-09-02) and is *not* the flat
//! array this task's brief assumed: it is a top-level JSON **object** keyed by
//! provider id (212 providers), each holding a `models` object keyed by that
//! provider's own model id (7,492 models total). `cost` is absent for ~6% of
//! models (free/local backends, image-only endpoints); when present,
//! `cache_read`/`cache_write` are each independently sometimes absent too.
//! `flatten_root` below normalizes that real shape into the same
//! `Vec<ModelsDevEntry>` the fixture-array path produces, fully-qualifying
//! each id as `"<provider>/<model>"` — the same convention
//! `testdata/models_dev_fixture.json` uses for its hand-written `id` field —
//! so `pricing::merge_entry` and `PricingSnapshot` never need to know which
//! path an entry came from.

use serde::Deserialize;
use std::collections::BTreeMap;

/// One flattened models.dev pricing entry, keyed by a fully-qualified
/// `"<provider>/<model>"` id. `limit` (context/output token caps) is
/// deliberately not modeled here: nothing in this crate reads it, and
/// requiring it as a mandatory field would mean one upstream model omitting
/// `limit` aborts the parse of the entire ~7,500-entry live dataset (O10).
/// Unknown JSON fields (including `limit`) are ignored by default, both for
/// the hand-written test fixtures and the real vendored file.
#[derive(Debug, Clone, Deserialize)]
pub struct ModelsDevEntry {
    pub id: String,
    pub cost: ModelsDevCost,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModelsDevCost {
    pub input: f64,
    pub output: f64,
    /// Absent for a real, verified fraction of models.dev's live dataset —
    /// not every model publishes a cache-read discount.
    #[serde(default)]
    pub cache_read: Option<f64>,
    #[serde(default)]
    pub cache_write: Option<f64>,
}

/// One provider entry in the real, live `models.dev/api.json` shape: a
/// `models` object keyed by that provider's own model id. Other fields on the
/// real provider object (name, env, api base url, ...) are irrelevant to
/// pricing and deliberately not modeled here.
#[derive(Debug, Deserialize)]
pub struct ModelsDevProvider {
    #[serde(default)]
    pub models: BTreeMap<String, ModelsDevRawModel>,
}

/// One model entry as it actually appears nested under a provider in the live
/// dataset. `cost` is `Option`: verified live, ~6% of the 7,492 real models
/// carry no `cost` object at all (free/local backends, image-generation-only
/// endpoints, etc.).
#[derive(Debug, Deserialize)]
pub struct ModelsDevRawModel {
    #[serde(default)]
    pub cost: Option<ModelsDevCost>,
}

/// Flattens the real, live nested dataset (`provider -> models -> model`) into
/// the same flat `ModelsDevEntry` shape the hand-written test fixtures use,
/// id-qualified as `"<provider>/<model>"`. Models with no `cost` object are
/// skipped: no price data means `PricingSnapshot` correctly has no entry for
/// them, which `price_usage` already turns into `Cost::Unknown` rather than a
/// guess — silently defaulting an unpriced model to `$0` would be exactly the
/// kind of silent mispricing this task exists to prevent.
pub fn flatten_root(root: BTreeMap<String, ModelsDevProvider>) -> Vec<ModelsDevEntry> {
    root.into_iter()
        .flat_map(|(provider_id, provider)| {
            provider
                .models
                .into_iter()
                .filter_map(move |(model_id, m)| {
                    let cost = m.cost?;
                    Some(ModelsDevEntry {
                        id: format!("{provider_id}/{model_id}"),
                        cost,
                    })
                })
        })
        .collect()
}
