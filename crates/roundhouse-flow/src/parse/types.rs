//! Typed shape of a workflow definition's top-level YAML structure (§8.9).
//! Step bodies (individual `steps`/`catch`/`finally` entries) are
//! intentionally left as raw [`serde_yaml::Value`] here — Task 3 of this
//! subsystem defines `StepDef` and parses them; this module only owns what
//! surrounds the step list.
//!
//! # Fail-closed by construction
//!
//! Workflow YAML is untrusted input whose parsed result decides what an
//! agent is allowed to do. Every struct in this module is
//! `#[serde(deny_unknown_fields)]` (except [`PermissionRuleDef`] — see its
//! doc comment for why flatten makes that attribute unnecessary there
//! rather than merely absent), and every field whose value space is a known
//! finite set (`type`, `isolation`, `effect`, `escalate`, `on_timeout`,
//! `permissions.default`) is a Rust enum, not a raw `String` — an unknown
//! variant or a misspelled value is a deserialize error, never a silently
//! ignored field.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// JSON Schema's primitive type names, as used by
/// `inputs: { <name>: { type: ... } }`. §8.9: "the `inputs:` schema ...
/// becomes the JSON tool schema when the workflow is exposed as a
/// sub-agent tool," so this deliberately matches JSON Schema's own
/// `type` vocabulary rather than inventing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputType {
    String,
    Integer,
    Number,
    Boolean,
    Array,
    Object,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputDef {
    #[serde(rename = "type")]
    pub ty: InputType,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub default: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RetryDef {
    #[serde(default)]
    pub attempts: u32,
    /// Free-form today: only exponential backoff is implemented
    /// (`crate::retry`), which never branches on this value, so validating
    /// it as an enum here would assert a contract nothing downstream
    /// checks. See the Task 2 report's fixture-coverage table.
    #[serde(default)]
    pub backoff: Option<String>,
    #[serde(default)]
    pub base: Option<String>,
    #[serde(default)]
    pub max: Option<String>,
    /// Failure-class names this retry rule applies to (e.g. `retryable`).
    /// Also free-form today for the same reason as `backoff`.
    #[serde(default)]
    pub on: Vec<String>,
}

/// Mirrors `roundhouse_core::Tier`'s variants exactly, but with its own
/// lowercase wire representation (`worktree`, not `Worktree`) matching the
/// workflow YAML convention (§8.9's fixture: `isolation: worktree`).
/// Deliberately NOT a `#[serde(with = ...)]` shim bolted onto `Tier`
/// itself: `Tier`'s serde shape is a frozen, already-persisted contract
/// (it round-trips through `IsolationAttestation`/`EventPayload` in the
/// store today), so this crate owns its own convert-at-the-boundary type
/// rather than touching a shared contract for this one caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationDef {
    None,
    Worktree,
    Sandbox,
    Container,
    Remote,
}

impl IsolationDef {
    /// Converts to the canonical core type, for callers (the executor,
    /// scheduling) that need `roundhouse_core::Tier` rather than this
    /// crate's wire-format mirror of it.
    pub fn to_core_tier(self) -> roundhouse_core::Tier {
        match self {
            IsolationDef::None => roundhouse_core::Tier::None,
            IsolationDef::Worktree => roundhouse_core::Tier::Worktree,
            IsolationDef::Sandbox => roundhouse_core::Tier::Sandbox,
            IsolationDef::Container => roundhouse_core::Tier::Container,
            IsolationDef::Remote => roundhouse_core::Tier::Remote,
        }
    }
}

/// §8.5 point 4: "Unattended jobs default to worktree or higher" — omitting
/// `defaults.isolation` must never silently fall back to `None`
/// (unsandboxed execution). This is the explicit, named, tested safe
/// floor the dispatch's risk callout asked for, not `IsolationDef`
/// implementing `Default` by accident.
fn default_isolation() -> IsolationDef {
    IsolationDef::Worktree
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    #[serde(default = "default_isolation")]
    pub isolation: IsolationDef,
    #[serde(default)]
    pub retry: RetryDef,
}

impl Default for Defaults {
    fn default() -> Self {
        Defaults {
            isolation: default_isolation(),
            retry: RetryDef::default(),
        }
    }
}

/// A permission rule's effect: `allow` runs it, `deny` blocks it,
/// `escalate` asks a human. §8.5 point 3's structured-denial behavior
/// lives in the executor (a later task), not here; this type only makes a
/// typo in the value (`alow`, `dney`) impossible to parse successfully.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Deny,
    Escalate,
}

/// Risk callout: "If `permissions.default` is absent, the safe default is
/// deny, never allow." Named function, not `Effect::default()` — `Effect`
/// deliberately does not implement `Default` at all, so nothing can ever
/// reach a permissive fallback by accident through a generic `T::default()`
/// call elsewhere. See `parses_when_permissions_default_is_omitted_it_is_deny`.
fn default_permission_effect() -> Effect {
    Effect::Deny
}

/// One matcher kind a [`PermissionRuleDef`] can key on. Closed on purpose:
/// only the two kinds §8.9's format actually specifies (`http`, `shell`)
/// are accepted today. A workflow author who reaches for a matcher kind
/// this doesn't recognise gets a parse error naming the bad key, not a
/// rule that silently matches nothing (or, worse, is misinterpreted).
/// `roundhouse-flow` has no `roundhouse-policy` dependency (ruling P7), so
/// this is a parse-time shape check only — actual matching against a live
/// request happens in `roundhouse-policy` at bind/admission time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PermissionMatcher {
    #[serde(rename = "http")]
    Http {
        #[serde(default)]
        methods: Vec<String>,
        #[serde(default)]
        hosts: Vec<String>,
    },
    #[serde(rename = "shell")]
    Shell {
        program: String,
        #[serde(default)]
        args: Vec<String>,
    },
}

/// One `permissions.rules[]` entry: `{ <matcher-kind>: {...}, effect: ... }`.
///
/// `matcher` is `#[serde(flatten)]`ed so `http`/`shell` sit as sibling keys
/// of `effect` in the YAML mapping, matching §8.9's literal shape. This
/// struct deliberately does NOT also carry `#[serde(deny_unknown_fields)]`
/// — serde does not support combining that attribute with a flattened
/// field (the flattened field always absorbs "the rest" of the mapping, so
/// there is never anything left for `deny_unknown_fields` to reject).
/// Fail-closed is preserved anyway: [`PermissionMatcher`] is an
/// externally-tagged enum with a closed, fixed set of variants, so any key
/// besides `http`/`shell` — or a rule carrying more than one matcher key —
/// fails to deserialize as a `PermissionMatcher` regardless; the flattened
/// "rest" of the mapping has to match exactly one known variant shape or
/// the whole rule fails to parse.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PermissionRuleDef {
    #[serde(flatten)]
    pub matcher: PermissionMatcher,
    pub effect: Effect,
}

/// §8.5 point 2: "`Escalate` is configurable per job: `Park{deadline,
/// on_timeout}`, `DenyAndContinue`, or `Fail`." Named `UnattendedEscalate`
/// rather than bare `Escalate`: ruling P7 reserves the name `Escalate` for
/// a distinct, richer type a later task builds on top of
/// `roundhouse_core::PolicyDecision`. This is only the wire-format value of
/// `unattended.escalate`, not that type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnattendedEscalate {
    Park,
    DenyAndContinue,
    Fail,
}

/// §8.4 (by way of the gate/unattended grammar): `on_timeout: deny | fail |
/// default(value) | approve`. `Default`'s argument is carried verbatim as
/// text — interpreting it is the `${{ }}` expression language's job (Task 4
/// of this subsystem), not this parser's. This type only validates the
/// *shape* of the value, so a typo (`aproove`, `defualt(...)`) is a parse
/// error rather than an unrecognised string nothing downstream understands.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum OnTimeout {
    Deny,
    Fail,
    Approve,
    Default(String),
}

impl TryFrom<String> for OnTimeout {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let trimmed = value.trim();
        match trimmed {
            "deny" => Ok(OnTimeout::Deny),
            "fail" => Ok(OnTimeout::Fail),
            "approve" => Ok(OnTimeout::Approve),
            _ => trimmed
                .strip_prefix("default(")
                .and_then(|rest| rest.strip_suffix(')'))
                .map(|inner| OnTimeout::Default(inner.to_string()))
                .ok_or_else(|| {
                    format!(
                        "invalid on_timeout value {value:?} — expected one of: deny, fail, approve, default(<value>)"
                    )
                }),
        }
    }
}

impl From<OnTimeout> for String {
    fn from(value: OnTimeout) -> Self {
        match value {
            OnTimeout::Deny => "deny".to_string(),
            OnTimeout::Fail => "fail".to_string(),
            OnTimeout::Approve => "approve".to_string(),
            OnTimeout::Default(inner) => format!("default({inner})"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnattendedDef {
    pub escalate: UnattendedEscalate,
    #[serde(default)]
    pub deadline: Option<String>,
    #[serde(default)]
    pub on_timeout: Option<OnTimeout>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionsDef {
    #[serde(default = "default_permission_effect")]
    pub default: Effect,
    #[serde(default)]
    pub rules: Vec<PermissionRuleDef>,
    pub unattended: UnattendedDef,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowDef {
    pub name: String,
    pub version: u32,
    #[serde(default)]
    pub inputs: HashMap<String, InputDef>,
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub secrets: Vec<String>,
    pub permissions: PermissionsDef,
    /// Raw step bodies — Task 3 defines `StepDef` and parses these.
    pub steps: Vec<serde_yaml::Value>,
    #[serde(default)]
    pub catch: Vec<serde_yaml::Value>,
    #[serde(default)]
    pub finally: Vec<serde_yaml::Value>,
}
