//! §9.5's `ReasoningControl` — "a closed enum keyed by (provider, model),
//! not two Options" — and §9.4's endpoint-preference resolution (audit
//! finding 3).
use std::collections::BTreeMap;
use thiserror::Error;

/// Audit finding 7: NOT a new type. Phase 1 already delivers this exact enum
/// (`Off | Low | Medium | High | Max`) as `roundhouse_provider::ir::ReasoningIntent`
/// for `ChatRequest.reasoning.intent` (a bare, non-`Option` value once a
/// caller has defaulted a missing `Option<ReasoningIntent>` to `Off` — see
/// REALITY-CORRECTIONS §7). Re-exporting it under the name §9.5 uses
/// (`Intent`) keeps this module's vocabulary matching the architecture doc
/// while staying the SAME type `ChatRequest` actually carries, so there is
/// no conversion needed anywhere a `ChatRequest` and a profile meet.
/// `impl Intent` below is a legal inherent impl because `ReasoningIntent` is
/// defined in this same crate (`roundhouse-provider`), just in a different
/// module (`ir`). Note `ReasoningIntent` has no `Default` derive (see
/// REALITY-CORRECTIONS §7) — callers map a missing intent to `Intent::Off`
/// themselves.
pub use crate::ir::ReasoningIntent as Intent;
impl Intent {
    fn key(self) -> &'static str {
        match self {
            Intent::Off => "off",
            Intent::Low => "low",
            Intent::Medium => "medium",
            Intent::High => "high",
            Intent::Max => "max",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningKind {
    Effort,
    Budget,
}

#[derive(Debug, Error)]
pub enum ProfileReasoningError {
    #[error("intent `{0:?}` (wire key `{1}`) has no entry in this model's reasoning map")]
    UnmappedIntent(Intent, String),
    #[error(
        "profile maps intent to wire value `{0}` which is not in the declared vocabulary {1:?}"
    )]
    WireValueNotInVocabulary(String, Vec<String>),
}

/// §9.5: "ReasoningControl is a closed enum keyed by (provider, model), not two
/// Options" — the (provider, model) keying happens one level up, via
/// `ModelEntry::match_globs`; this struct is the per-model control itself.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReasoningControl {
    pub kind: ReasoningKind,
    pub field: String,
    pub vocabulary: Vec<String>,
    pub map: BTreeMap<String, String>,
}
impl ReasoningControl {
    pub fn resolve(&self, intent: Intent) -> Result<&str, ProfileReasoningError> {
        let wire = self.map.get(intent.key()).ok_or_else(|| {
            ProfileReasoningError::UnmappedIntent(intent, intent.key().to_string())
        })?;
        if !self.vocabulary.iter().any(|v| v == wire) {
            return Err(ProfileReasoningError::WireValueNotInVocabulary(
                wire.clone(),
                self.vocabulary.clone(),
            ));
        }
        Ok(wire.as_str())
    }
}

/// §9.4's endpoint-preference mechanism (audit finding 3): which wire endpoint
/// a model should actually be sent over, as data. `openai-chat`/`openai-responses`
/// are both wire formats OpenAI first-party can speak for the same model; other
/// (provider, codec) pairs are the other variants a profile might list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointKind {
    Responses,
    Chat,
    AnthropicMessages,
    GoogleGenai,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointPref {
    pub endpoint: EndpointKind,
    #[serde(default)]
    pub degraded: bool,
}

/// The resolved outcome of `resolve_endpoint_preference`. `degraded: true`
/// means the caller fell back to a degraded endpoint because nothing
/// non-degraded was available — §9.1's "loss is a first-class, logged event"
/// says this must become a `LossEvent` on the `infer` task, not a silent
/// downgrade; this type is what a caller checks to decide whether to emit one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointResolution {
    pub endpoint: EndpointKind,
    pub degraded: bool,
}

#[derive(Debug, Error)]
#[error("no endpoint in this model's endpoint_preference list is in the available set: {0:?}")]
pub struct NoEndpointAvailable(pub Vec<EndpointKind>);

/// Picks the first entry that is both available and not `degraded`. Only if
/// NO non-degraded entry is available does it fall back to the first
/// available entry regardless of its `degraded` flag, reporting that fact so
/// the caller can log it — never silently prefer a degraded entry over an
/// available non-degraded one, and never silently swallow a fallback.
pub fn resolve_endpoint_preference(
    preference: &[EndpointPref],
    available: &[EndpointKind],
) -> Result<EndpointResolution, NoEndpointAvailable> {
    if let Some(pref) = preference
        .iter()
        .find(|p| !p.degraded && available.contains(&p.endpoint))
    {
        return Ok(EndpointResolution {
            endpoint: pref.endpoint,
            degraded: false,
        });
    }
    if let Some(pref) = preference.iter().find(|p| available.contains(&p.endpoint)) {
        return Ok(EndpointResolution {
            endpoint: pref.endpoint,
            degraded: true,
        });
    }
    Err(NoEndpointAvailable(
        preference.iter().map(|p| p.endpoint).collect(),
    ))
}
