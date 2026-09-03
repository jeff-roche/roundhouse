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

/// Fix round 7, K6: the JSON *type* a resolved reasoning wire value must be
/// emitted as. `/reasoning_effort`-style controls (OpenAI documents
/// `"low"`/`"medium"`/`"high"` as strings) are `String`, the default so
/// every profile shipped before this field existed keeps deserializing and
/// emitting exactly as before. Qwen's `/enable_thinking` is vendor-documented
/// as a JSON boolean -- encoding it as the *string* `"true"` is a silent
/// protocol violation a gateway may accept-but-ignore rather than reject,
/// which is the fail-open shape §13b item 5 exists to prevent. `Number`
/// covers a future profile needing e.g. a numeric budget through this same
/// `kind = "effort"` vocabulary/map mechanism (distinct from `ReasoningKind::
/// Budget`'s own `google_genai`-specific `i64`-parsing path, which does not
/// go through this type at all).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningValueType {
    #[default]
    String,
    Bool,
    Number,
}

impl ReasoningValueType {
    /// Parses `wire` (a `map`/`vocabulary` entry, always stored as a TOML
    /// string regardless of the wire type it represents) into the
    /// [`WireValue`] this type declares. `ReasoningControl::validate_value_type`
    /// calls this over every vocabulary/map entry at BUILD time (§9.5: "a
    /// typo in a quirk profile is a BUILD error, not a production 400") so
    /// `resolve_wire_value` calling it again at request-encode time can only
    /// ever fail if that build-time validation was skipped.
    fn parse(self, wire: &str) -> Result<WireValue, ProfileReasoningError> {
        match self {
            ReasoningValueType::String => Ok(WireValue::String(wire.to_string())),
            ReasoningValueType::Bool => wire
                .parse::<bool>()
                .map(WireValue::Bool)
                .map_err(|_| ProfileReasoningError::WireValueWrongType(self, wire.to_string())),
            ReasoningValueType::Number => wire
                .parse::<f64>()
                .ok()
                // Round-8 review, M4: `"1e400".parse::<f64>()` is `Ok(f64::
                // INFINITY)`, not an `Err` -- an out-of-range literal must
                // not fail open. `f64::is_finite()` rejects both infinities
                // and NaN, so this build-time check (`validate_value_type`
                // calls `parse` over every vocabulary/map entry) catches a
                // non-finite literal the same way it already catches a
                // non-numeric one, instead of `json!(f64::INFINITY)` later
                // silently serializing to `null` and dropping the field —
                // the same fail-open shape as `google_genai/encode.rs:366`'s
                // `.unwrap_or(0)`.
                .filter(|parsed| parsed.is_finite())
                .map(WireValue::Number)
                .ok_or_else(|| ProfileReasoningError::WireValueWrongType(self, wire.to_string())),
        }
    }
}

/// A resolved reasoning wire value, typed per [`ReasoningValueType`]. Kept
/// free of any JSON library type (`reasoning.rs` is mirrored dependency-free
/// into `build.rs`'s own compilation unit -- see this module's callers'
/// comments) -- each codec's own `encode.rs` (currently only `openai_chat`'s)
/// converts this into its wire representation (`serde_json::Value` for
/// `openai_chat`).
#[derive(Debug, Clone, PartialEq)]
pub enum WireValue {
    String(String),
    Bool(bool),
    Number(f64),
}

#[derive(Debug, Error)]
pub enum ProfileReasoningError {
    #[error("intent `{0:?}` (wire key `{1}`) has no entry in this model's reasoning map")]
    UnmappedIntent(Intent, String),
    #[error(
        "profile maps intent to wire value `{0}` which is not in the declared vocabulary {1:?}"
    )]
    WireValueNotInVocabulary(String, Vec<String>),
    /// Fix round 7, K6: a vocabulary/map entry that does not parse under its
    /// control's declared `value_type` -- `ReasoningControl::validate_value_type`
    /// raises this as a BUILD error (§9.5); `resolve_wire_value` returning it
    /// at runtime would mean that build-time check was skipped.
    #[error("value_type {0:?} declared for this reasoning control, but wire value `{1}` does not parse as that type")]
    WireValueWrongType(ReasoningValueType, String),
}

/// §9.5: "ReasoningControl is a closed enum keyed by (provider, model), not two
/// Options" — the (provider, model) keying happens one level up, via
/// `ModelEntry::match_globs`; this struct is the per-model control itself.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReasoningControl {
    pub kind: ReasoningKind,
    pub field: String,
    /// Fix round 7, K6: the JSON type `resolve_wire_value` emits a resolved
    /// value as. `#[serde(default)]` so every profile shipped before this
    /// field existed keeps deserializing unchanged, defaulting to `String`
    /// (`ReasoningValueType`'s own `#[default]`) -- the exact behavior every
    /// profile before Qwen already relied on.
    #[serde(default)]
    pub value_type: ReasoningValueType,
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

    /// Fix round 7, K6: `resolve`, then converts the wire string into the
    /// [`WireValue`] this control's `value_type` declares. Used by
    /// `openai_chat::encode` (the shared codec whose profiles' reasoning
    /// wire shapes genuinely diverge -- see that module's `encode_openai_chat`
    /// doc comment) and, as of Task 17 (Ruling P108), by
    /// `google_genai::encode_generate_content` for its Budget-kind control
    /// (`thinkingBudget` is a genuine JSON *number* on the wire, not a
    /// vendor-documented string -- hand-parsing it via bare `resolve()` and
    /// defaulting an unparseable value to `0` silently disabled reasoning;
    /// see that module's own doc comment on the fix). `cohere_v2` and
    /// `openai_responses` still call bare `resolve()` directly -- no profile
    /// gives either of them a non-string wire value today, so wiring them
    /// through `resolve_wire_value` would be unevidenced churn (a recorded
    /// Task 17 scoping decision, not an oversight). `google_genai`'s OTHER
    /// reasoning path (`EndpointMode::Interactions`'s `thinking_level`) does
    /// not go through `ReasoningControl`/this method at all -- it is a small,
    /// hardcoded, spec-mandated enum, per that module's own documentation.
    pub fn resolve_wire_value(&self, intent: Intent) -> Result<WireValue, ProfileReasoningError> {
        let wire = self.resolve(intent)?;
        self.value_type.parse(wire)
    }

    /// §9.5's "a wrong type must be a BUILD error, not a runtime surprise":
    /// verifies every `vocabulary`/`map` entry actually parses under this
    /// control's declared `value_type`. Called from `build.rs` for every
    /// profile's `[[model]].reasoning` table (regardless of codec, since
    /// `value_type` is part of this schema's own contract, not an
    /// `openai-chat`-specific concept) so a profile declaring `value_type =
    /// "bool"` against a non-boolean vocabulary/map entry fails the build,
    /// never a live inference call.
    pub fn validate_value_type(&self) -> Result<(), ProfileReasoningError> {
        for wire in self.vocabulary.iter().chain(self.map.values()) {
            self.value_type.parse(wire)?;
        }
        Ok(())
    }

    /// Fix round 3, Fix 2: `google_genai::encode::encode_generate_content`
    /// calls `resolve_wire_value` for whichever `ReasoningControl` matches a
    /// model, regardless of `kind` -- so that codec, unlike `cohere-v2`/
    /// `openai-responses`, can legitimately declare any `value_type`. But a
    /// Budget-kind control's wire field (`thinkingBudget`) is documented by
    /// the vendor schema as a JSON *number*, not a string -- that is a fact
    /// about THIS field, not about what the encoder generically consumes.
    /// `build.rs` calls this for every `google-genai` profile's
    /// `[[model]].reasoning` table: `true` means the control declares (or,
    /// via `#[serde(default)]`, silently defaults to) `value_type =
    /// "string"` for a Budget-kind control, which would build clean today
    /// and then `resolve_wire_value` would emit a quoted string
    /// (`"8192"`) where the API expects an integer.
    pub fn google_genai_budget_kind_has_an_invalid_string_value_type(&self) -> bool {
        self.kind == ReasoningKind::Budget && self.value_type == ReasoningValueType::String
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

#[cfg(test)]
mod reasoning_value_type_tests {
    //! Fix round 7, K6: unit coverage for `ReasoningValueType`/`WireValue`/
    //! `ReasoningControl::{resolve_wire_value, validate_value_type}` in
    //! isolation from any codec's `encode.rs` -- the end-to-end proof that
    //! `openai_chat::encode_openai_chat` actually emits a typed JSON value
    //! lives in `tests/openai_chat_encode.rs` and
    //! `tests/profile_test_openai_chat_batch_c.rs` (against the real,
    //! shipped `qwen.toml`).
    use super::{Intent, ReasoningControl, ReasoningKind, ReasoningValueType, WireValue};
    use std::collections::BTreeMap;

    fn control(value_type: ReasoningValueType, vocabulary: &[&str]) -> ReasoningControl {
        ReasoningControl {
            kind: ReasoningKind::Effort,
            field: "/enable_thinking".into(),
            value_type,
            vocabulary: vocabulary.iter().map(|s| s.to_string()).collect(),
            map: BTreeMap::from([
                ("off".to_string(), "false".to_string()),
                ("high".to_string(), "true".to_string()),
            ]),
        }
    }

    #[test]
    fn a_string_value_type_resolves_to_a_wire_value_string() {
        let c = control(ReasoningValueType::String, &["false", "true"]);
        assert_eq!(
            c.resolve_wire_value(Intent::High).unwrap(),
            WireValue::String("true".into())
        );
    }

    #[test]
    fn a_bool_value_type_resolves_to_a_wire_value_bool_not_a_string() {
        let c = control(ReasoningValueType::Bool, &["false", "true"]);
        assert_eq!(
            c.resolve_wire_value(Intent::High).unwrap(),
            WireValue::Bool(true)
        );
        assert_eq!(
            c.resolve_wire_value(Intent::Off).unwrap(),
            WireValue::Bool(false)
        );
    }

    #[test]
    fn value_type_defaults_to_string_when_absent_from_a_profile() {
        // Mirrors what `#[serde(default)]` gives every profile shipped
        // before this field existed: deserializing a TOML fragment with no
        // `value_type` key must still produce `ReasoningValueType::String`.
        let toml_src = r#"
            kind = "effort"
            field = "/reasoning_effort"
            vocabulary = ["low", "high"]
            [map]
            off = "low"
            high = "high"
        "#;
        let c: ReasoningControl = toml::from_str(toml_src).unwrap();
        assert_eq!(c.value_type, ReasoningValueType::String);
    }

    #[test]
    fn validate_value_type_accepts_a_bool_vocabulary_for_a_bool_control() {
        let c = control(ReasoningValueType::Bool, &["false", "true"]);
        assert!(c.validate_value_type().is_ok());
    }

    /// §9.5's "a wrong type must be a BUILD error, not a runtime surprise" --
    /// `build.rs` calls exactly this method over every profile's reasoning
    /// control.
    #[test]
    fn validate_value_type_rejects_a_non_boolean_vocabulary_entry_for_a_bool_control() {
        let c = control(ReasoningValueType::Bool, &["nope", "true"]);
        let err = c.validate_value_type().unwrap_err();
        assert!(matches!(
            err,
            super::ProfileReasoningError::WireValueWrongType(..)
        ));
    }

    /// Round-8 review, M4: `"1e400"` parses as `Ok(f64::INFINITY)`, not an
    /// `Err` -- without the `is_finite()` guard this would build clean and
    /// then `json!(f64::INFINITY)` would silently serialize to `null` at
    /// request-encode time, dropping the field with no error. This must be
    /// a BUILD error instead (`validate_value_type` calls `parse` over
    /// every vocabulary/map entry).
    #[test]
    fn validate_value_type_rejects_a_non_finite_number_literal() {
        let mut c = control(ReasoningValueType::Number, &["0", "1e400"]);
        c.map = BTreeMap::from([
            ("off".to_string(), "0".to_string()),
            ("high".to_string(), "1e400".to_string()),
        ]);
        let err = c.validate_value_type().unwrap_err();
        assert!(matches!(
            err,
            super::ProfileReasoningError::WireValueWrongType(..)
        ));
    }

    #[test]
    fn resolve_wire_value_rejects_nan() {
        let mut c = control(ReasoningValueType::Number, &["0", "nan"]);
        c.map = BTreeMap::from([
            ("off".to_string(), "0".to_string()),
            ("high".to_string(), "nan".to_string()),
        ]);
        assert!(c.resolve_wire_value(Intent::High).is_err());
    }

    #[test]
    fn a_number_value_type_resolves_to_a_wire_value_number() {
        let mut c = control(ReasoningValueType::Number, &["0", "100"]);
        c.map = BTreeMap::from([
            ("off".to_string(), "0".to_string()),
            ("high".to_string(), "100".to_string()),
        ]);
        assert_eq!(
            c.resolve_wire_value(Intent::High).unwrap(),
            WireValue::Number(100.0)
        );
        assert!(c.validate_value_type().is_ok());
    }

    /// Fix round 3, Fix 2 (§15 evidence for `build.rs`'s inverted
    /// `google-genai` codec guard): the exact reachable shape the fix
    /// brief names -- a Budget-kind control that omits `value_type`
    /// (`#[serde(default)]` gives it `String`) -- must be flagged.
    #[test]
    fn budget_kind_with_the_default_string_value_type_is_flagged() {
        let mut c = control(ReasoningValueType::String, &["0", "8192"]);
        c.kind = ReasoningKind::Budget;
        assert!(c.google_genai_budget_kind_has_an_invalid_string_value_type());
    }

    /// A Budget-kind control that correctly declares `value_type = "number"`
    /// (what every shipped `google-genai` profile actually declares) must
    /// NOT be flagged.
    #[test]
    fn budget_kind_with_a_number_value_type_is_not_flagged() {
        let mut c = control(ReasoningValueType::Number, &["0", "8192"]);
        c.kind = ReasoningKind::Budget;
        assert!(!c.google_genai_budget_kind_has_an_invalid_string_value_type());
    }

    /// An Effort-kind control is never flagged by this check regardless of
    /// `value_type` -- the vendor-schema fact this check encodes
    /// ("thinkingBudget is a JSON number") is specific to Budget-kind
    /// controls, not a blanket claim about every google-genai reasoning
    /// control.
    #[test]
    fn effort_kind_is_never_flagged_regardless_of_value_type() {
        let effort_string = control(ReasoningValueType::String, &["false", "true"]);
        assert!(!effort_string.google_genai_budget_kind_has_an_invalid_string_value_type());
        let effort_number = control(ReasoningValueType::Number, &["0", "1"]);
        assert!(!effort_number.google_genai_budget_kind_has_an_invalid_string_value_type());
    }
}
