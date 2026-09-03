//! §9.5 — the TOML quirk-profile schema. Every struct here derives
//! `#[serde(deny_unknown_fields)]` so a typo'd key in a profile TOML fails
//! deserialization instead of silently vanishing — that guarantee is what
//! lets `build.rs` turn a typo into a build error rather than a production
//! 400. `unknown_field_in_profile_is_a_deserialize_error_not_a_silent_ignore`
//! (`tests/profile_test.rs`) exists specifically to pin this down for every
//! nested struct, not just the top-level one.
use std::collections::BTreeMap;
use std::collections::HashMap;

// `#[allow(unused_imports)]`: when `build.rs` mounts this file as a bare
// binary-crate module (it needs only `ProviderProfile` to deserialize), a
// `pub use` re-export doesn't count as "used" the way it does in the real
// lib (nothing can consume a binary's public surface), so this would
// otherwise trip `unused_imports` there even though the real lib's
// `profile::mod` genuinely re-exports these names.
#[allow(unused_imports)]
pub use super::reasoning::{
    resolve_endpoint_preference, EndpointKind, EndpointPref, EndpointResolution, Intent,
    NoEndpointAvailable, ReasoningControl, ReasoningKind,
};

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderProfile {
    pub id: String,
    pub codec: String,
    pub defaults: Defaults,
    #[serde(rename = "model", default)]
    pub model: Vec<ModelEntry>,
    #[serde(default)]
    pub errors: BTreeMap<String, ErrorEntry>,
    /// M2 (round-8 review, M1/M2): the RFC 6901 JSON pointer into a
    /// vendor's error body where this profile's `[errors]` table keys are
    /// found. `classify()` used to hardcode `/error/type` — an
    /// OpenAI-shape assumption that silently never matched for every
    /// vendor whose real error body doesn't nest a `type` string at that
    /// exact location (Mistral nests `type` at the top level; Z.ai/Qwen/
    /// DeepInfra key their machine-readable code under `/error/code`, not
    /// `/error/type`; vLLM/SGLang key `type` at different nesting depths).
    /// Defaults to `/error/type` so every profile shipped before this field
    /// existed (moonshot, azure-openai, and the rest whose real shape
    /// genuinely nests `type` there) keeps resolving exactly as before.
    /// `build.rs` validates this is a well-formed pointer — see
    /// `error_pointer_validation::validate_error_pointer` — the same
    /// "typo is a BUILD error" guarantee `value_type` (`c058dbe`) already
    /// gives `[[model]].reasoning`.
    #[serde(default = "default_error_pointer")]
    pub error_pointer: String,
}

fn default_error_pointer() -> String {
    "/error/type".to_string()
}

impl ProviderProfile {
    /// REALITY-CORRECTIONS §14g: wires this profile's `[errors]` table into
    /// the real §9.8 classification path (`crate::errors::classify`), which
    /// otherwise never reads it. Each `ErrorEntry`'s disposition/category is
    /// mapped onto the closest-fitting `ProviderErrorKind` — see the mapping
    /// notes on `ErrorEntry::error_kind` for the cases that cannot be mapped
    /// exactly. An entry that `error_kind()` can't map faithfully (fix round
    /// 1, E1) is simply omitted from `code_table`: `classify()` then falls
    /// through to its existing, already-tested HTTP-status tier for that
    /// code, rather than this wiring asserting a specific, wrong
    /// `ProviderErrorKind`.
    pub fn error_profile(&self) -> crate::errors::ErrorProfile {
        let mut code_table = HashMap::new();
        for (code, entry) in &self.errors {
            if let Some(kind) = entry.error_kind() {
                code_table.insert(code.clone(), kind);
            }
        }
        crate::errors::ErrorProfile {
            code_table,
            message_patterns: Vec::new(),
            error_pointer: self.error_pointer.clone(),
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    #[serde(default)]
    pub allow_raw_extra: bool,
    pub params: ParamsPolicy,
    /// §9.9: "Base URL resolves as: explicit override -> env -> profile
    /// default" — this IS the profile default. A real per-provider value
    /// (never a placeholder) is required on every profile.
    pub base_url: String,
    pub auth: AuthKind,
}

/// Which of Task 2's `CredentialProvider` wire shapes this provider expects.
/// Data, not a per-provider `if` — the whole point of §9.5's quirk profile.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthKind {
    Bearer,
    HeaderKey {
        header: String,
    },
    // `rename_all = "snake_case"` would turn `SigV4` into `sig_v4` (it treats
    // the capital V as a new word boundary) — every profile in this plan
    // writes `kind = "sigv4"` (matching the `sigv4-eventstream`/`sigv4::sign`
    // naming used everywhere else), so this variant needs an explicit rename.
    #[serde(rename = "sigv4")]
    SigV4 {
        service: String,
    },
    AzureEntra {
        scope: String,
    },
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParamsPolicy {
    pub mode: ParamsMode,
    #[serde(default)]
    pub fields: Vec<String>,
}
impl ParamsPolicy {
    /// Bridges into `roundhouse_conformance::SerializeOnlyMask` — deliberately
    /// NOT a `From` impl in this crate (that would make roundhouse-provider
    /// depend on roundhouse-conformance in [dependencies], creating a cycle
    /// with Task 3's [dev-dependencies] direction). Each codec's *test* file
    /// calls this and wraps the result itself.
    pub fn allowed_fields(&self, all_known_param_fields: &[&str]) -> Vec<String> {
        match self.mode {
            ParamsMode::AllowOnly => self.fields.clone(),
            ParamsMode::DenyList => all_known_param_fields
                .iter()
                .filter(|f| !self.fields.iter().any(|d| d == *f))
                .map(|f| f.to_string())
                .collect(),
            ParamsMode::AllowAll => all_known_param_fields
                .iter()
                .map(|f| f.to_string())
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamsMode {
    AllowOnly,
    DenyList,
    AllowAll,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelEntry {
    #[serde(rename = "match")]
    pub match_globs: Vec<String>,
    pub reasoning: Option<ReasoningControl>,
    /// §9.4's endpoint-preference mechanism (audit finding 3). Empty for
    /// profiles with only one wire endpoint (every profile before Task 13) —
    /// `#[serde(default)]` keeps `moonshot.toml` and friends parsing unchanged.
    #[serde(default)]
    pub endpoint_preference: Vec<EndpointPref>,
    /// Azure OpenAI only (Task 14, audit finding 2): the deployment name
    /// this model id maps to in the customer's Azure resource. `None` for
    /// every non-Azure profile — `#[serde(default)]` keeps every existing
    /// profile parsing unchanged.
    #[serde(default)]
    pub azure_deployment: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorEntry {
    pub disposition: DispositionKind,
    pub category: Option<String>,
}

impl ErrorEntry {
    /// REALITY-CORRECTIONS §14g's mapping from a profile's (disposition,
    /// category) pair onto the closed `ProviderErrorKind` enum. Only four
    /// variants exist (`Overloaded`, `RateLimited`, `QuotaExhausted`,
    /// `ModelNotFound`), so this is deliberately a many-to-one mapping rather
    /// than a fifth invented variant:
    ///
    /// - `RetryBackoff` is a transient, retry-with-backoff condition — the
    ///   same semantics `ProviderErrorKind::Overloaded` already carries.
    /// - `ShedConcurrency` means "reduce concurrent load," which is the same
    ///   caller-facing behaviour as `ProviderErrorKind::RateLimited` (back
    ///   off and reduce request rate/concurrency).
    /// - `Fatal` is not retryable, but *why* it's fatal varies. `category =
    ///   "quota"` maps to `QuotaExhausted` and `category = "model_not_found"`
    ///   maps to `ModelNotFound` — both are exact fits.
    /// - Fix round 1, E1: a `Fatal` entry with any OTHER category, or no
    ///   category at all, returns `None` rather than guessing. The earlier
    ///   draft defaulted an unrecognized `Fatal` to `QuotaExhausted`, which
    ///   is not imprecise, it's a *wrong specific*: `QuotaExhausted` is an
    ///   actionable claim about billing state, and a permanent auth failure
    ///   or a content-policy rejection would then be reported to the caller
    ///   as "you are out of quota." `error_profile()` skips a `None` entry
    ///   entirely, so `classify()` falls through to its existing
    ///   HTTP-status tier for that code instead — honest about not
    ///   knowing, rather than confidently wrong.
    pub fn error_kind(&self) -> Option<crate::errors::ProviderErrorKind> {
        use crate::errors::ProviderErrorKind;
        match (self.disposition, self.category.as_deref()) {
            (DispositionKind::RetryBackoff, _) => Some(ProviderErrorKind::Overloaded),
            (DispositionKind::ShedConcurrency, _) => Some(ProviderErrorKind::RateLimited),
            (DispositionKind::Fatal, Some("model_not_found")) => {
                Some(ProviderErrorKind::ModelNotFound)
            }
            (DispositionKind::Fatal, Some("quota")) => Some(ProviderErrorKind::QuotaExhausted),
            (DispositionKind::Fatal, _) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispositionKind {
    RetryBackoff,
    ShedConcurrency,
    Fatal,
}
