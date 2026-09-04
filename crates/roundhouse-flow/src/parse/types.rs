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
//! `#[serde(deny_unknown_fields)]` except [`PermissionRuleDef`], whose
//! validation instead comes from a `#[serde(try_from = ...)]` conversion —
//! see its doc comment for why. (Fix round 1 on Task 10, finding H1,
//! replaced an earlier `#[serde(flatten)]`ed-closed-enum design whose own
//! claim to already be fail-closed was measured false; this summary
//! sentence originally still described that retracted design and was
//! corrected in fix round 2 after review caught the inconsistency.) Every
//! field whose value space is a known finite set (`type`, `isolation`,
//! `effect`, `escalate`, `on_timeout`, `permissions.default`) is a Rust
//! enum, not a raw `String` — an unknown variant or a misspelled value is
//! a deserialize error, never a silently ignored field.

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

/// §8.9's `http:` matcher shape. `#[serde(deny_unknown_fields)]` here is
/// what actually catches a typo like `hostz` instead of `hosts` — fix
/// round 1 on Task 10 (finding H1) found that the previous design (a
/// `#[serde(flatten)]`ed externally-tagged enum) did NOT reject that typo:
/// flatten only guarantees *at least one* recognised matcher key is
/// present among the leftover fields, not that every field inside that
/// matcher's own mapping is recognised, and not that no second matcher key
/// is also present. See [`PermissionRuleDef`]'s doc comment for the fixed
/// mechanism and `unknown_field_within_a_permission_matcher_is_rejected` /
/// `two_matcher_kinds_on_one_rule_is_rejected` in
/// `tests/parse_top_level.rs` for what is now actually caught.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpMatcher {
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
}

/// §8.9's `shell:` matcher shape. See [`HttpMatcher`]'s doc comment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellMatcher {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
}

/// One matcher kind a [`PermissionRuleDef`] can key on. Closed on purpose:
/// only the two kinds §8.9's format actually specifies (`http`, `shell`)
/// are accepted today. A workflow author who reaches for a matcher kind
/// this doesn't recognise gets a parse error naming the bad key, not a
/// rule that silently matches nothing (or, worse, is misinterpreted).
/// `roundhouse-flow` has no `roundhouse-policy` dependency (ruling P7), so
/// this is a parse-time shape check only — actual matching against a live
/// request happens in `roundhouse-policy` at bind/admission time.
///
/// Does not derive `Deserialize`: [`PermissionRuleDef`]'s custom
/// `TryFrom`-based deserialization (see its doc comment) builds this
/// directly from validated `HttpMatcher`/`ShellMatcher` values rather than
/// deserializing a tagged enum itself.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum PermissionMatcher {
    #[serde(rename = "http")]
    Http(HttpMatcher),
    #[serde(rename = "shell")]
    Shell(ShellMatcher),
}

/// The as-written-in-YAML shape of a `permissions.rules[]` entry: deserialize
/// into a validated [`PermissionRuleDef`] (see its doc comment), and
/// serialize a [`PermissionRuleDef`] back into this same wire shape (fix
/// round 2 on Task 10, minor: an earlier version only derived `Deserialize`
/// here, so `PermissionRuleDef`'s derived `Serialize` emitted its own
/// struct layout — `{"matcher": {"http": {...}}, "effect": "allow"}` —
/// instead of the wire shape, which `Deserialize` then rejected on
/// re-parsing). Never constructed or read directly otherwise.
#[derive(Debug, Serialize, Deserialize)]
struct PermissionRuleDefWire {
    effect: Effect,
    #[serde(flatten)]
    matcher_fields: std::collections::BTreeMap<String, serde_yaml::Value>,
}

/// One `permissions.rules[]` entry: `{ <matcher-kind>: {...}, effect: ... }`.
///
/// # Fix round 1 on Task 10 (finding H1): flatten alone does not fail closed
///
/// An earlier version of this type deserialized `matcher` as a
/// `#[serde(flatten)]`ed, externally-tagged `PermissionMatcher` enum
/// directly, with a doc comment (and this task's own report) claiming that
/// was sufficient to reject any unrecognised or extra matcher key. Measured
/// false: flatten's contract is "find *a* recognised key among the
/// leftover fields and deserialize its value," not "every leftover field
/// must belong to exactly one recognised matcher." Concretely, that
/// version accepted `{ http: { methods: [GET], hostz: [...] }, effect:
/// allow }` — silently dropping the whole `hosts` constraint into a typo'd
/// `hostz` field the enum's `Http` variant doesn't have, producing an
/// *unrestricted* allow rule that still reads as host-restricted in the
/// source — and `{ http: {...}, shell: {...}, effect: allow }`, silently
/// keeping whichever matcher happened to deserialize first and dropping
/// the other one entirely.
///
/// This version instead deserializes into [`PermissionRuleDefWire`] (whose
/// own `#[serde(flatten)]` field is an ordinary `BTreeMap`, not a fixed
/// enum) via `#[serde(try_from = "PermissionRuleDefWire")]`, then validates
/// explicitly in [`PermissionRuleDef`]'s `TryFrom` impl below: exactly one
/// matcher key must be present (catching both "no matcher" and "more than
/// one matcher"), it must be `http` or `shell`, and its value is
/// deserialized into the corresponding `#[serde(deny_unknown_fields)]`
/// [`HttpMatcher`]/[`ShellMatcher`] (catching a typo'd field *within* a
/// recognised matcher). All three failure modes above are now rejected —
/// see `tests/parse_top_level.rs`'s
/// `unknown_permission_matcher_kind_is_rejected`,
/// `unknown_field_within_a_permission_matcher_is_rejected`,
/// `two_matcher_kinds_on_one_rule_is_rejected`, and
/// `zero_matchers_on_one_rule_is_rejected`.
///
/// `#[serde(into = "PermissionRuleDefWire")]` (fix round 2 on Task 10,
/// minor) makes `Serialize` go back through the same wire shape
/// `Deserialize` expects, via [`From<PermissionRuleDef> for
/// PermissionRuleDefWire`] below — see `serializing_and_reparsing_a_
/// permission_rule_round_trips` in `tests/parse_top_level.rs`. No
/// exploitable path reaches this today (nothing in this crate
/// re-serializes a parsed `WorkflowDef`), but a security-relevant type
/// whose own output its own parser rejects is exactly the kind of trap a
/// future normalize-persist-reparse path would fall into silently.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "PermissionRuleDefWire", into = "PermissionRuleDefWire")]
pub struct PermissionRuleDef {
    pub matcher: PermissionMatcher,
    pub effect: Effect,
}

impl From<PermissionRuleDef> for PermissionRuleDefWire {
    fn from(def: PermissionRuleDef) -> Self {
        let (kind, matcher_value) = match def.matcher {
            PermissionMatcher::Http(http) => (
                "http",
                serde_yaml::to_value(http).expect("HttpMatcher always serializes"),
            ),
            PermissionMatcher::Shell(shell) => (
                "shell",
                serde_yaml::to_value(shell).expect("ShellMatcher always serializes"),
            ),
        };
        let mut matcher_fields = std::collections::BTreeMap::new();
        matcher_fields.insert(kind.to_string(), matcher_value);
        PermissionRuleDefWire {
            effect: def.effect,
            matcher_fields,
        }
    }
}

impl TryFrom<PermissionRuleDefWire> for PermissionRuleDef {
    type Error = String;

    fn try_from(wire: PermissionRuleDefWire) -> Result<Self, Self::Error> {
        if wire.matcher_fields.len() != 1 {
            return Err(format!(
                "a permission rule must have exactly one matcher (http or shell), found {}: {:?}",
                wire.matcher_fields.len(),
                wire.matcher_fields.keys().collect::<Vec<_>>()
            ));
        }
        // `.len() == 1` was just checked, so this always succeeds.
        let (kind, value) = wire
            .matcher_fields
            .into_iter()
            .next()
            .expect("checked above: matcher_fields has exactly one entry");
        let matcher = match kind.as_str() {
            "http" => PermissionMatcher::Http(
                serde_yaml::from_value(value)
                    .map_err(|err| format!("invalid `http` permission matcher: {err}"))?,
            ),
            "shell" => PermissionMatcher::Shell(
                serde_yaml::from_value(value)
                    .map_err(|err| format!("invalid `shell` permission matcher: {err}"))?,
            ),
            other => {
                return Err(format!(
                    "unrecognised permission rule matcher kind {other:?} — expected one of: http, shell"
                ));
            }
        };
        Ok(PermissionRuleDef {
            matcher,
            effect: wire.effect,
        })
    }
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
