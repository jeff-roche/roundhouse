//! Typed shape of a single step body (§8.9: `tool`/`agent`/`map`/`gate`/
//! `call`/`emit`/`report`), and `needs:`-respecting run ordering over a
//! parsed list of steps.
//!
//! `WorkflowDef.steps`/`.catch`/`.finally` (Task 2, [`super::WorkflowDef`])
//! stay raw `serde_yaml::Value` — this module is what a caller hands each
//! entry to individually via [`parse_step`], and what it hands the parsed
//! result to via [`topological_order`] to get a run order.
//!
//! # Fail-closed by construction — scoped honestly
//!
//! Every step-body-shape key (`tool`, `agent`, `map`, `gate`, `call`,
//! `emit`, `report`, plus the `with`/`steps` keys some of them take a
//! sibling from) is a named field on [`StepDefWire`], one single
//! `#[serde(deny_unknown_fields)]` struct with no `#[serde(flatten)]`
//! anywhere in it — a typo (`toolz:`, `agemt:`) is a parse error, not a
//! silently-ignored field. Every field whose value space is a closed set
//! (`on_item_error`, `gate.on_timeout`, `map.isolation`'s tier name,
//! `caps.max_cost_usd`'s finiteness) is validated, not accepted as
//! arbitrary text or an arbitrary JSON value.
//!
//! **This heading is scoped deliberately, not blanket, per fix round 1's
//! review** (which found the un-scoped version of this heading was already
//! the fourth retracted "fail-closed"/"safe by construction" claim in this
//! crate's `parse` module — see `parse/mod.rs`'s own history). Five fields
//! remain intentionally untyped `serde_json::Value`, because they are
//! generic payloads a tool/agent/notification/report consumes, not values
//! that gate an isolation, permission, or budget decision: `tool`'s/`call`'s
//! `with:` argument bag, `agent.output_schema`, `gate.form`, `emit`, and
//! `report`. Leaving these as `Value` is a scope choice, not an oversight.
//!
//! **Fix round 2, finding Minor 3: a specific field count ("sixteen") was
//! asserted here and could not be reconstructed under any reading** — this
//! is the fourth "fail-closed" claim in this module's own history, and the
//! third to be falsified by execution rather than merely reworded, so the
//! fix is to stop quantifying and name the fields instead. "Fail-closed by
//! construction" is true of: `id` (charset/length), `needs` (length
//! bound), `env`'s key names and value contents (charset), `map.as`
//! (charset, plus a reserved-root check), `map.on_item_error` (closed
//! enum), `map.isolation` and its `worktree.base_ref` parameter (closed
//! tier set, plus a git-ref-shaped charset check — see
//! [`validate_git_ref`]'s own doc comment for the narrow, four-character
//! exemption that check makes for expression syntax; fix round 3 found
//! and closed a version of that exemption that was a complete bypass, not
//! a narrowing, so this summary line says "check" rather than implying
//! zero exceptions), `caps.max_cost_usd` (finiteness/sign), and
//! `gate.on_timeout` (closed enum).
//!
//! **Fix round 3: the not-validated list below was incomplete, found by
//! the same review that caught the `base_ref` bypass.** It is deliberately
//! **not** true of `gate.timeout` (stays free-form text — bounded
//! elsewhere, by §8.11's own 7-day reaper cap, same reasoning as the
//! nested-`map`-depth bound `parse_step`'s doc comment names as the
//! executor's responsibility rather than this parser's), nor of `tool`,
//! `call`, `map.over`, `when`, `agent.prompt`, `agent.model`, `gate.title`
//! (expression strings, tool/workflow names, a prompt, a model name, and a
//! human-facing title are not closed value spaces to begin with — `when`
//! in particular is structurally identical to `map.over`, which the
//! original version of this list already named, so omitting `when` read
//! as a deliberate exclusion rather than the oversight it was), nor of
//! `agent.tools` (a list of tool names, each unvalidated), nor of
//! `map.max_parallel` (an unbounded `u32` — `0` and `u32::MAX` both parse,
//! named in `parse_step`'s own doc comment as an executor-owned gap, not
//! repeated here as if unstated), nor of a `map`'s nested `steps:
//! Vec<serde_yaml::Value>` (each entry is itself unparsed until a caller
//! invokes [`parse_step`] on it individually). This module was never
//! going to make any of the above a closed value space, and this list
//! exists so that isn't left to be inferred.
//!
//! **This deliberately does *not* use `#[serde(flatten)]` the way an
//! earlier version of this module did, and the reason is a measured, not
//! assumed, serde limitation.** An earlier version put `id`/`when`/`needs`/
//! etc. directly on `StepDef` and reached the body-shape keys through
//! `#[serde(flatten)] body: StepBody`, with `StepBody` itself resolved from
//! a *second*, `deny_unknown_fields` wire struct via
//! `#[serde(try_from = ...)]` — i.e. two flatten-adjacent layers stacked.
//! That compiled, and `serde_yaml::from_str::<StepBody>("tool: shell\ntoolz: 1")`
//! called directly correctly rejected `toolz`. But
//! `serde_yaml::from_str::<StepDef>("id: a\ntool: shell\ntoolz: 1")` through
//! the flatten field **silently dropped `toolz` and parsed successfully** —
//! confirmed by executing exactly that case, not inferred from serde's
//! docs. `#[serde(flatten)]`'s content-buffering does not enforce the
//! flattened target's own `deny_unknown_fields` the same way a direct,
//! non-flattened deserialize does; a key the *outer* struct doesn't
//! recognise is simply not guaranteed to reach the inner type's own unknown-
//! field check. [`super::types::PermissionRuleDef`]'s own doc comment
//! already records the sibling limitation (can't put `deny_unknown_fields`
//! on the struct *that itself has* a flatten field) — this is a second,
//! independent way the same feature fails closed-by-construction
//! expectations, one level further in.
//!
//! The fix mirrors `PermissionRuleDef`'s pattern applied at the level where
//! it actually holds: **one single wire struct with every recognised key as
//! a named field**, no flatten involved at all, `#[serde(try_from =
//! "StepDefWire", into = "StepDefWire")]` on the real [`StepDef`]. See
//! `unknown_step_level_key_is_rejected` in `tests/parse_steps.rs`, which
//! pins this exact case.
//!
//! # Fix round 1: validation moved from `parse_step` into `TryFrom`
//!
//! The first version of this module ran `validate_step_id` and the
//! `MAX_NEEDS_PER_STEP` check inside [`parse_step`], *after*
//! `serde_yaml::from_value::<StepDef>(v)` had already produced a `StepDef`.
//! Security review measured the consequence directly:
//! `serde_yaml::from_str::<StepDef>("id: \"../../../etc/passwd\"\ntool: shell\n...")`
//! and `serde_json::from_str::<StepDef>(r#"{"id":"z","tool":"shell","needs":[...5000 entries...]}"#)`
//! both returned `Ok` — any caller reaching `StepDef`'s own `Deserialize`
//! impl directly (which is the more idiomatic-looking way to consume a
//! `#[serde(try_from = ...)]` type, and exactly what a future caller
//! re-parsing a `map`'s nested `steps: Vec<serde_yaml::Value>` would reach
//! for) got an unvalidated `StepDef`, silently skipping every check
//! `parse_step` only ran on its own direct callers.
//!
//! **Fix:** `id`/`needs`/`env`-name validation now lives inside
//! `TryFrom<StepDefWire> for StepDef` itself — the same conversion
//! `StepDef`'s derived `Deserialize` impl calls internally, so it fires
//! for *any* deserialize entry point, not just [`parse_step`]. To keep
//! [`parse_step`]'s own errors fully typed (rather than flattened through
//! serde's `Error::custom(Display)` bridge, which would lose the specific
//! `ParseError` variant), `TryFrom<StepDefWire> for StepDef` now has
//! `type Error = ParseError` directly, and `parse_step` calls
//! `StepDef::try_from` itself instead of going through
//! `serde_yaml::from_value::<StepDef>`. A caller who *does* go through
//! `StepDef`'s derived `Deserialize` (bypassing `parse_step`) still runs
//! every check — the input is still rejected — but sees it as a generic
//! `serde_yaml`/`serde_json` error message rather than a matchable
//! `ParseError` variant, since that erasure happens inside `serde`'s own
//! generated bridging code, not this module's. (`map.as`, `map.isolation`,
//! and `caps.max_cost_usd` are validated the same unbypassable way, but one
//! level deeper than this paragraph originally claimed — see "Fix round 2"
//! below for exactly where, and what that costs [`parse_step`]'s own error
//! typing for those three specifically.)
//!
//! **What this does not claim:** every `StepDef`/`StepBody` field is `pub`,
//! in a `pub mod`, on `pub` types — so any downstream crate (not just code
//! within this one) can still construct an invalid `StepDef` via a struct
//! literal, entirely outside any `Deserialize` call. That is a different
//! concern (library-internal/downstream misuse, not untrusted-input
//! handling) and this fix does not close it — nothing today is harmed by
//! it (there are no consumers yet, and serializing such a value would
//! produce output this same type's own `Deserialize` rejects on the way
//! back in, so it fails closed on re-entry even if not on construction).
//! "Validated for every deserialization path" is the claim; "impossible to
//! construct" is not.
//!
//! # Fix round 2: nested-type checks stay unbypassable, but surface as `ParseError::Yaml`
//!
//! Fix round 1's own text above overstated its scope in two ways security
//! review measured directly rather than accepting on inspection:
//!
//! 1. **`map.as` validation does not live in `TryFrom<StepDefWire>`.** It
//!    lives in `TryFrom<MapBodyDefWire> for MapBodyDef` — one level
//!    deeper, since `map.as` is a field of the nested `map:` value, not of
//!    the step itself. The unbypassable-validation *property* still holds
//!    (it fires whenever a `MapBodyDef` is deserialized, which happens
//!    during `StepDefWire`'s own deserialize call, before
//!    `StepDef::try_from` ever runs) — only the *location* claim above was
//!    wrong, and is corrected here rather than left standing.
//! 2. **Because of that nesting, [`parse_step`] does *not* surface
//!    `caps`/`map.as`/`map.isolation` violations as a typed `ParseError`
//!    variant** — they surface as `ParseError::Yaml(...)`, the same
//!    generic erasure the text above describes only for *other* callers
//!    that bypass `parse_step`. `type Error = ParseError` on
//!    `TryFrom<StepDefWire> for StepDef` only preserves typed errors for
//!    checks that run *inside that specific `TryFrom` impl* (`id`,
//!    `needs`, `env` names, and the step-body-shape checks). A nested
//!    type's own `TryFrom` (`CapsDef`, `MapBodyDef`, `MapIsolationDef`)
//!    still goes through serde's ordinary `Error::custom(Display)` bridge
//!    during `StepDefWire`'s deserialization — *before* the outer
//!    `TryFrom<StepDefWire>` body even runs — so there is no path for that
//!    error to arrive as anything other than a `serde_yaml::Error` already
//!    wrapped by the `?` in [`parse_step`]. `tests/parse_steps.rs`'s own
//!    pre-existing assertions already confirmed this without anyone
//!    noticing the doc text disagreed: `h2_nan_max_cost_usd_is_rejected`,
//!    `m3_an_empty_map_as_is_rejected`,
//!    `h1_a_misspelled_isolation_tier_is_rejected`, and several others all
//!    assert `matches!(err, ParseError::Yaml(_))`, never a specific
//!    variant.
//!
//! **Stated plainly, so it doesn't need reconstructing from the above a
//! third time:** the step-level checks in `TryFrom<StepDefWire> for
//! StepDef` (`id`, `needs`, `env` names, and the body-shape checks)
//! surface as typed `ParseError` variants for [`parse_step`]'s own
//! callers; nested-type checks (`caps`, `map.as`, `map.isolation`)
//! surface as `ParseError::Yaml` regardless of entry point.
//!
//! # Duplicate keys inside a step body: already handled below `serde`
//!
//! This task's brief characterized a step body's duplicate-key handling as
//! "silently last-wins today" (true of `serde_yaml::Value` built
//! programmatically, e.g. via `Mapping::insert`) and framed typing the step
//! body as the fix. **Measured against the pinned `serde_yaml` 0.9.34
//! before writing anything that depended on it being true: it is not true
//! for this library version.** `serde_yaml::Mapping`'s own `Deserialize`
//! impl (`serde_yaml-0.9.34+deprecated/src/mapping.rs`, `Visitor::visit_map`)
//! already checks `mapping.entry(key)` and returns a
//! `"duplicate entry with key ..."` error the second time any key repeats —
//! this fires deserializing *raw YAML text* into a plain untyped
//! `serde_yaml::Value`, before this module's types are involved at all.
//! `duplicate_step_body_key_is_rejected_at_the_raw_value_stage` in
//! `tests/parse_steps.rs` proves this directly: parsing
//! `"tool: shell\ntool: http"` into a bare `serde_yaml::Value` already
//! errors, before ever calling [`parse_step`]. This module's own typed
//! structs (ordinary `#[derive(Deserialize)]` structs, whose generated
//! field visitor independently rejects a duplicate *named* field the same
//! way) add a second, redundant layer of the same protection for the
//! fields they define directly — genuinely redundant here, not
//! load-bearing, but still covered by a regression test
//! (`duplicate_nested_agent_field_is_rejected_at_the_raw_value_stage`) in
//! case a future change ever bypasses the `Value` stage. Security review
//! independently reproduced both this and the flatten finding above and
//! confirmed both hold.

use super::ParseError;
use crate::parse::types::{IsolationDef, OnTimeout};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Sanity bound on an identifier's length — used for both a step's `id:`
/// and a `map`'s `as:` loop-item binding name ([`validate_map_as`]). Step
/// ids flow into provenance, logs, and later task records; a loop-item
/// binding name flows into the expression-language scope Task 4 builds.
/// Neither use is a security boundary on its own — this is a refusal to
/// accept an unreasonably long identifier for something meant to be a
/// short, stable name.
pub const MAX_STEP_ID_LEN: usize = 128;

/// Sanity bound on how many `needs:` entries one step may declare. Bounds
/// [`topological_order`]'s own work (`O(steps + total needs entries)`) to a
/// predictable multiple of the step count; not tied to, and making no claim
/// about, the open YAML-parse-cost finding recorded in the parent module's
/// doc comment — that finding is about `serde_yaml` parsing raw text, this
/// is about graph size after parsing has already succeeded.
pub const MAX_NEEDS_PER_STEP: usize = 64;

/// Reserved expression-language context roots (§8.9's own vocabulary:
/// `secrets.*`, `steps.*`, `inputs.*`, `run.*`, `vars.*`, `env.*`) that a
/// `map`'s `as:` loop-item binding must not shadow — see
/// [`validate_map_as`]'s doc comment (fix round 1, finding M3).
const RESERVED_EXPRESSION_ROOTS: &[&str] = &["secrets", "steps", "inputs", "run", "vars", "env"];

fn default_max_parallel() -> u32 {
    1
}

fn default_form() -> serde_json::Value {
    serde_json::json!({})
}

/// Shared charset/length/non-empty rule for both a step `id` and a `map`'s
/// `as:` binding — ASCII alnum/`_`/`-`, non-empty, at most
/// [`MAX_STEP_ID_LEN`]. Returns the failure reason as plain text so each
/// caller can wrap it in whatever error shape fits its own context
/// ([`validate_step_id`] wraps it in [`ParseError::InvalidStepId`];
/// [`validate_map_as`] wraps it in a `String` for its own `TryFrom`).
fn validate_identifier_charset(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("must not be empty".to_string());
    }
    if value.len() > MAX_STEP_ID_LEN {
        return Err(format!("exceeds the {MAX_STEP_ID_LEN}-character limit"));
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err("must contain only ASCII letters, digits, `_`, or `-`".to_string());
    }
    Ok(())
}

/// Step ids are untyped human-chosen text in the YAML, but flow into
/// provenance, logs, and (this crate's downstream tasks) task records — so,
/// unlike a free-form prompt string, this parser gives them a closed
/// charset and a length ceiling rather than accepting arbitrary text. Not a
/// claim that this prevents every possible downstream misuse of an id,
/// only that a step id can't itself smuggle control characters, path
/// separators, or unbounded length into whatever later reads it as a plain
/// identifier.
fn validate_step_id(id: &str) -> Result<(), ParseError> {
    validate_identifier_charset(id).map_err(|reason| ParseError::InvalidStepId {
        id: id.to_string(),
        reason,
    })
}

/// A `map` step's `as:` loop-item binding name becomes a root in Task 4's
/// expression-language scope for every nested step (§8.9: `as: pr` makes
/// `${{ pr.number }}` resolve). Fix round 1, finding M3: an unconstrained
/// string here accepts `""`, `"a b"`, `"${{ x }}"`, or — the sharper
/// problem — one of the language's own other context roots (`steps`,
/// `secrets`, `inputs`, `run`, `vars`, `env`). If a future evaluator merges
/// the loop binding into one flat scope, `as: steps` would make an inner
/// `when: "${{ steps.gate.output.approve }}"` silently resolve against the
/// loop item instead of the real step-output map — and `over:` is
/// frequently external, attacker-influenced data. Reuses
/// [`validate_identifier_charset`] (the same rule [`validate_step_id`]
/// applies) and additionally rejects [`RESERVED_EXPRESSION_ROOTS`].
fn validate_map_as(value: &str) -> Result<(), String> {
    validate_identifier_charset(value).map_err(|reason| format!("map.as {value:?}: {reason}"))?;
    if RESERVED_EXPRESSION_ROOTS.contains(&value) {
        return Err(format!(
            "map.as {value:?} shadows the reserved expression-language root `{value}` (one of {RESERVED_EXPRESSION_ROOTS:?}) — choose a different loop-item binding name"
        ));
    }
    Ok(())
}

/// POSIX-style environment variable name: `[A-Za-z_][A-Za-z0-9_]*`. Fix
/// round 1, finding L2: an untyped `env:` value previously accepted a key
/// containing `=` or a newline (`{"A=B\nLD_PRELOAD": "/tmp/x.so"}` parsed
/// successfully) — harmless through `execve`'s argv array, but a real
/// injection risk once a future executor lowers this into `docker run
/// --env`, a systemd unit, or a `.env` file, all live options given the
/// container/remote isolation tiers this crate's types already name.
fn is_valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Fix round 2, finding Minor 1: [`is_valid_env_name`]'s own doc comment
/// named `docker run --env`, a systemd unit, and a `.env` file as the
/// sinks a bad *name* could reach — the same reasoning applies identically
/// to the *value* half, which fix round 1 left unchecked. Measured:
/// `env: { A: "safe\nLD_PRELOAD=/tmp/evil.so" }` parsed successfully and
/// would render to a `.env` file as two lines; a NUL byte in a value
/// parsed too, which `std::process::Command` rejects at spawn time — a
/// runtime error surfacing far from the YAML that caused it. Rejects any
/// Unicode control character (fix round 3 widened this from the original
/// `\n`/`\r`/`\0`-only check to match [`validate_git_ref`]'s use of
/// `is_control()` — nothing was reachable through the gap between the two
/// definitions, since dotenv/systemd/`execve` all split only on `\n`, but
/// leaving two different definitions of "control character" a few lines
/// apart in the same module was worth closing for free) rather than
/// restricting to a name-style charset, since a value legitimately holds
/// e.g. `${{ secrets.GH_TOKEN }}` or arbitrary URLs/paths.
fn is_valid_env_value(value: &str) -> bool {
    !value.chars().any(|c| c.is_control())
}

/// A step's resource caps (§8.9: `caps: { max_cost_usd, max_tool_calls }`).
/// A transfer out of the run's remaining budget (§8.9's `map`-item caps
/// note) — enforcing that transfer is the executor's job (Task 5), not
/// this parser's; this type only gives it a typed, fail-closed shape.
///
/// # Fix round 1, finding H2: `max_cost_usd` is validated, not raw `f64`
///
/// `f64` accepts `NaN`, `±Infinity`, and negative values with no complaint
/// from `serde` on its own. Security review measured two independent ways
/// that matters here, not just in the abstract: against this workspace's
/// own budget-transfer logic
/// (`roundhouse-engine/src/agent_spawn.rs:168`, `if requested > remaining
/// { refuse }; remaining -= requested`), `max_cost_usd: .nan` passes the
/// refusal check *and* poisons `remaining` to `NaN` (every later `>`
/// comparison is then `false`, permanently disabling the run-level ceiling,
/// not just this step's), and `max_cost_usd: -1.0` *increases* the run's
/// remaining budget. Separately, `roundhouse-store/src/writer.rs`'s
/// `serialize_payload` documents that `serde_json` silently writes a
/// non-finite float as JSON `null`, reasoning that this is benign because
/// `Progress.fraction` was the only float field in the workspace — this
/// type is now a second one, and it's a budget cap, not a progress
/// fraction; a non-finite `max_cost_usd` that reached that path would
/// survive a crash-resume as *no cap at all*. `TryFrom<CapsDefWire>` below
/// rejects a non-finite or negative `max_cost_usd` outright, so no such
/// value can ever exist inside a `CapsDef` in the first place.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "CapsDefWire", into = "CapsDefWire")]
pub struct CapsDef {
    pub max_cost_usd: Option<f64>,
    pub max_tool_calls: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CapsDefWire {
    #[serde(default)]
    max_cost_usd: Option<f64>,
    #[serde(default)]
    max_tool_calls: Option<u32>,
}

impl TryFrom<CapsDefWire> for CapsDef {
    type Error = String;

    fn try_from(w: CapsDefWire) -> Result<Self, String> {
        if let Some(cost) = w.max_cost_usd {
            if !(cost.is_finite() && cost >= 0.0) {
                return Err(format!(
                    "caps.max_cost_usd must be a finite, non-negative number, got {cost}"
                ));
            }
        }
        Ok(CapsDef {
            max_cost_usd: w.max_cost_usd,
            max_tool_calls: w.max_tool_calls,
        })
    }
}

impl From<CapsDef> for CapsDefWire {
    fn from(def: CapsDef) -> Self {
        CapsDefWire {
            max_cost_usd: def.max_cost_usd,
            max_tool_calls: def.max_tool_calls,
        }
    }
}

/// §8.9: "`on_item_error: continue | fail_fast | collect`" (a `map` step's
/// per-item error policy). A closed enum, not a raw `String`, for the same
/// reason [`super::types::Effect`] and friends are: a misspelled value
/// (`continu`, `failfast`) is a parse error, not a silently-ignored typo
/// that falls back to whatever the executor happens to do with an
/// unrecognised string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnItemError {
    Continue,
    FailFast,
    Collect,
}

/// §8.9 names no explicit default for `on_item_error`; `FailFast` is chosen
/// as the safe floor — an item error not explicitly opted into `continue`
/// or `collect` stops the map rather than silently pressing on.
impl Default for OnItemError {
    fn default() -> Self {
        OnItemError::FailFast
    }
}

/// §8.9's `agent: { model, tools, prompt, output_schema }` shape. Private:
/// exists only as [`StepDefWire`]'s deserialization target for the
/// `agent:` key; its fields are copied into [`StepBody::Agent`] by
/// [`StepDef`]'s `TryFrom` impl below, and nothing outside this module ever
/// sees this type directly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentBodyDef {
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    tools: Vec<String>,
    prompt: String,
    #[serde(default)]
    output_schema: Option<serde_json::Value>,
}

/// Parameters for the `worktree` isolation tier under `map.isolation:`
/// (§8.9's fixture: `{worktree: {base_ref: ...}}`) — the only tier with a
/// documented parameter today. `deny_unknown_fields` so a typo'd parameter
/// name is a parse error, not a silently-ignored one.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorktreeIsolationParams {
    #[serde(default)]
    base_ref: Option<String>,
}

/// `base_ref` reaches a git ref-name position (the value is handed to git
/// as the ref to base a new worktree on). Fix round 2, finding Minor 2:
/// this field was free-form — `"--upload-pack=/tmp/x"`, `"$(id)"`, and
/// `"; rm -rf /"` all parsed. A leading `-` is the standard git argument-
/// injection vector (a value starting with `-` is read as a flag, not a
/// ref, by any git plumbing that doesn't defensively insert a `--`
/// separator), and the tier name itself already declares the sink — this
/// isn't a generic "sanitize everything" pass, it's specific to what this
/// one field is used for.
///
/// This is a reasonable approximation of `git check-ref-format`'s own
/// rules plus defense-in-depth against a shell-string invocation, not a
/// byte-for-byte reimplementation of either: rejects empty, a leading `-`
/// (the injection vector above), a leading/trailing `/`, any `..` run, a
/// trailing `.lock`, control characters/whitespace, and
/// [`FORBIDDEN_GIT_REF_CHARS`] (see its own doc comment for the two
/// different reasons its two halves exist). It does not implement every
/// `check-ref-format` rule (e.g. `@{` sequences, a lone `@`) — those are
/// additional git-specific edge cases this function doesn't claim to
/// catch, left for git itself to reject at worktree-creation time if they
/// slip through.
///
/// # Fix round 3: the `${{`-exemption was a complete bypass, not a narrowing
///
/// An earlier version of this function returned `Ok(())` outright whenever
/// `value` contained `${{`, reasoning that a templated `base_ref` (the
/// frozen fixture's own `"refs/pull/${{ pr.number }}/head"`) can't be
/// validated against a literal-ref charset. Security review measured the
/// actual consequence: **every payload this function was written to
/// reject passed again once `${{` was appended** — `"--upload-pack=/tmp/x${{"`,
/// `"$(id)${{"`, `"; rm -rf / #${{"`, and refs with an embedded `\n`/`\0`
/// followed by `${{` all parsed successfully, because the check for
/// *every* rule bailed out before looking at the rest of the string. Worse,
/// the check was unanchored (`contains`, no required matching `}}`), so a
/// string like `"; rm -rf / #${{"` — not a valid expression by any
/// plausible evaluator, which leaves an unterminated `${{` as literal text
/// or errors — passed this check *as if* it were an expression, while
/// reaching git *as* the literal string un-evaluated. The two ends of the
/// exemption disagreed by construction: nothing downstream was ever going
/// to treat that string as anything other than exactly what it says.
///
/// **Fix: narrow the exemption to the four characters expression syntax
/// actually needs — a plain space, `$`, `{`, `}` — and apply every other
/// rule unconditionally**, expression or not. This is deliberately not
/// the span-parsing alternative (find `${{`, require a matching `}}`,
/// validate only the literal parts around it): that would still be
/// reasoning about where a second grammar's tokens start and end, the
/// same shape of heuristic this crate's DoS-scan history
/// (`parse/mod.rs`'s module doc, three bypassed designs) warns against.
/// The four-character exemption needs no such reasoning — it just widens
/// what counts as an acceptable character, uniformly, everywhere in the
/// string — and every one of the payloads above is rejected under it
/// regardless of what's appended: a leading `-` is checked before any
/// character-class scan even runs; `(`, `)`, `;` are still forbidden
/// characters (not part of the four-character exemption); control
/// characters (including `\n`, `\r`, `\0`) are rejected unconditionally,
/// never exempted. The frozen fixture's own `base_ref` still parses: its
/// only exempt-class characters are the two spaces and the `${`/`}`
/// pairs, and its `.` (in `pr.number`) never repeats into a `..` run.
fn validate_git_ref(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("must not be empty".to_string());
    }
    if value.len() > MAX_STEP_ID_LEN {
        return Err(format!("exceeds the {MAX_STEP_ID_LEN}-character limit"));
    }
    if value.starts_with('-') {
        return Err(
            "must not start with `-` (would be read as a command-line flag by git, not a ref name)"
                .to_string(),
        );
    }
    if value.starts_with('/') || value.ends_with('/') {
        return Err("must not start or end with `/`".to_string());
    }
    if value.contains("..") {
        return Err("must not contain `..`".to_string());
    }
    if value.ends_with(".lock") {
        return Err("must not end with `.lock`".to_string());
    }
    let is_expression_syntax_char = |c: char| matches!(c, ' ' | '$' | '{' | '}');
    if value.chars().any(|c| {
        !is_expression_syntax_char(c)
            && (c.is_control() || c.is_whitespace() || FORBIDDEN_GIT_REF_CHARS.contains(c))
    }) {
        return Err(format!(
            "must not contain control characters, whitespace, or any of `{FORBIDDEN_GIT_REF_CHARS}` — a plain space, `$`, `{{`, and `}}` are allowed, needed for `${{{{ }}}}` expression syntax"
        ));
    }
    Ok(())
}

/// `~^:?*[\` is `git check-ref-format`'s own disallowed set for a ref
/// component. `$`() ;|&<>'"` is *not* — check-ref-format doesn't forbid
/// shell metacharacters, because they're not a git concern, they're a
/// concern only if something later builds a shell command string out of
/// this value instead of passing it as a discrete argv element. Measured
/// directly: without this second half, `validate_git_ref` let
/// `"$(id)"` through (fix round 2's own review caught this — the first
/// version of this constant was git's charset alone, and a test written
/// against the reviewer's exact example failed). Added as defense in
/// depth: this parser doesn't know whether the executor (Task 5) invokes
/// git via argv (safe regardless of these characters) or via a shell
/// string (unsafe if it does), and none of these characters ever
/// legitimately appears in a real git ref name, so rejecting them costs
/// nothing either way.
const FORBIDDEN_GIT_REF_CHARS: &str = "~^:?*[\\$`();|&<>'\"";

/// The other four isolation tiers take no documented parameters today;
/// deserializing into this zero-field, `deny_unknown_fields` struct is how
/// `{sandbox: {some_param: 1}}` is rejected rather than silently accepted
/// as if `some_param` were meaningful.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NoParams {}

/// `map.isolation:`'s wire shape — either a bare tier name (reusing
/// [`IsolationDef`]'s own closed set and wire spelling) or a single-key
/// mapping naming the tier with tier-specific parameters. `#[serde(untagged)]`
/// is format-agnostic (works the same deserializing from YAML or JSON) and,
/// unlike the flatten-based approach this module's own history warns
/// against, doesn't buffer content through a *second* type's
/// `deny_unknown_fields` check — it just picks whichever of these two
/// concretely-different shapes (a scalar string vs. a mapping) the input
/// actually is.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
enum MapIsolationWire {
    Bare(IsolationDef),
    Keyed(BTreeMap<String, serde_json::Value>),
}

/// §8.9's `map.isolation:` override — either a bare tier name (matching
/// `defaults.isolation`'s wire values via [`IsolationDef`]) or a
/// single-key mapping naming the tier with tier-specific parameters
/// (`{worktree: {base_ref}}`, the shape the frozen fixture uses).
///
/// # Fix round 1, finding H1: this was an untyped `serde_json::Value`
///
/// Task 2's own `hostz` finding (an untyped permission matcher silently
/// accepting a typo'd field while still *reading* as restrictive) recurs
/// here one level up: an untyped `isolation:` accepted
/// `{worktreee: {base_ref: r}}` (typo'd tier, still reads as a worktree
/// constraint), `none`, `nonesuch`, `42`, and arbitrary nesting, all
/// without complaint. Worse, `isolation: none` under a job whose
/// `defaults.isolation` is `worktree` or higher *widens* the step's
/// isolation, which the phase Global Constraint and §8.5 both forbid ("a
/// step may only narrow the job's policy, never widen it") — and nothing
/// caught or flagged that. This type closes the typo/shape half of that:
/// a misspelled or unrecognised tier name, more than one tier key, or an
/// unrecognised parameter within a tier's own value is now a parse error.
///
/// # What this does not close: narrowing vs. the job default
///
/// [`parse_step`] parses one step in isolation, with no visibility into
/// the enclosing `WorkflowDef.defaults.isolation` — the narrowing-vs-
/// widening comparison can only happen where both values are in scope at
/// once, which today is nowhere in this crate. This is an explicit,
/// named deferral to the executor (Task 5), which resolves a run's actual
/// effective isolation for a step with both values available, not an
/// oversight: see
/// `map_isolation_none_parses_without_checking_narrowing_against_defaults`
/// in `tests/parse_steps.rs`, which pins today's behavior and names the
/// owner of the real check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "MapIsolationWire", into = "MapIsolationWire")]
pub enum MapIsolationDef {
    None,
    Worktree { base_ref: Option<String> },
    Sandbox,
    Container,
    Remote,
}

impl MapIsolationDef {
    fn from_tier_with_no_params(tier: IsolationDef) -> Self {
        match tier {
            IsolationDef::None => MapIsolationDef::None,
            IsolationDef::Worktree => MapIsolationDef::Worktree { base_ref: None },
            IsolationDef::Sandbox => MapIsolationDef::Sandbox,
            IsolationDef::Container => MapIsolationDef::Container,
            IsolationDef::Remote => MapIsolationDef::Remote,
        }
    }
}

impl TryFrom<MapIsolationWire> for MapIsolationDef {
    type Error = String;

    fn try_from(w: MapIsolationWire) -> Result<Self, String> {
        match w {
            MapIsolationWire::Bare(tier) => Ok(MapIsolationDef::from_tier_with_no_params(tier)),
            MapIsolationWire::Keyed(map) => {
                if map.len() != 1 {
                    return Err(format!(
                        "map.isolation must name exactly one tier (none, worktree, sandbox, container, remote), found {}: {:?}",
                        map.len(),
                        map.keys().collect::<Vec<_>>()
                    ));
                }
                let (tier_name, value) = map
                    .into_iter()
                    .next()
                    .expect("checked above: exactly one entry");
                let tier: IsolationDef =
                    serde_json::from_value(serde_json::Value::String(tier_name.clone()))
                        .map_err(|_| {
                            format!(
                                "unrecognised map.isolation tier {tier_name:?} — expected one of: none, worktree, sandbox, container, remote"
                            )
                        })?;
                match tier {
                    IsolationDef::Worktree => {
                        let params: WorktreeIsolationParams = serde_json::from_value(value)
                            .map_err(|e| format!("invalid `worktree` isolation params: {e}"))?;
                        if let Some(base_ref) = &params.base_ref {
                            validate_git_ref(base_ref).map_err(|reason| {
                                format!("worktree.base_ref {base_ref:?}: {reason}")
                            })?;
                        }
                        Ok(MapIsolationDef::Worktree {
                            base_ref: params.base_ref,
                        })
                    }
                    other => {
                        let _: NoParams = serde_json::from_value(value).map_err(|e| {
                            format!("`{tier_name}` isolation takes no parameters: {e}")
                        })?;
                        Ok(MapIsolationDef::from_tier_with_no_params(other))
                    }
                }
            }
        }
    }
}

impl From<MapIsolationDef> for MapIsolationWire {
    fn from(def: MapIsolationDef) -> Self {
        let mut map = BTreeMap::new();
        match def {
            MapIsolationDef::None => {
                map.insert("none".to_string(), serde_json::json!({}));
            }
            MapIsolationDef::Worktree { base_ref } => {
                map.insert(
                    "worktree".to_string(),
                    serde_json::to_value(WorktreeIsolationParams { base_ref })
                        .expect("WorktreeIsolationParams always serializes"),
                );
            }
            MapIsolationDef::Sandbox => {
                map.insert("sandbox".to_string(), serde_json::json!({}));
            }
            MapIsolationDef::Container => {
                map.insert("container".to_string(), serde_json::json!({}));
            }
            MapIsolationDef::Remote => {
                map.insert("remote".to_string(), serde_json::json!({}));
            }
        }
        MapIsolationWire::Keyed(map)
    }
}

/// §8.9's `map: { over, as, max_parallel, on_item_error, isolation }` shape
/// (the sibling `steps:` list is a separate key on the step, not nested
/// under `map:` — see the fixture and [`StepDefWire`]). Private, same
/// visibility reasoning as [`AgentBodyDef`]; unlike it, this one carries
/// its own `TryFrom` (see below) because `as:` needs validation beyond
/// what a derive can express.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "MapBodyDefWire", into = "MapBodyDefWire")]
struct MapBodyDef {
    over: String,
    r#as: String,
    max_parallel: u32,
    on_item_error: OnItemError,
    isolation: Option<MapIsolationDef>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MapBodyDefWire {
    over: String,
    #[serde(rename = "as")]
    r#as: String,
    #[serde(default = "default_max_parallel")]
    max_parallel: u32,
    #[serde(default)]
    on_item_error: OnItemError,
    #[serde(default)]
    isolation: Option<MapIsolationDef>,
}

impl TryFrom<MapBodyDefWire> for MapBodyDef {
    type Error = String;

    fn try_from(w: MapBodyDefWire) -> Result<Self, String> {
        validate_map_as(&w.r#as)?;
        Ok(MapBodyDef {
            over: w.over,
            r#as: w.r#as,
            max_parallel: w.max_parallel,
            on_item_error: w.on_item_error,
            isolation: w.isolation,
        })
    }
}

impl From<MapBodyDef> for MapBodyDefWire {
    fn from(def: MapBodyDef) -> Self {
        MapBodyDefWire {
            over: def.over,
            r#as: def.r#as,
            max_parallel: def.max_parallel,
            on_item_error: def.on_item_error,
            isolation: def.isolation,
        }
    }
}

/// §8.9's `gate: { title, form, timeout, on_timeout }` shape. `on_timeout`
/// reuses [`OnTimeout`] from [`super::types`] rather than inventing a
/// second copy of the same `deny | fail | default(value) | approve`
/// grammar — Task 2's own report flagged this exact reuse as the intended
/// hook for this task. Private, same reasoning as [`AgentBodyDef`].
///
/// # `on_timeout: approve`'s precondition: deferred, not checked here
///
/// §8.11: "`approve` is permitted only when the run's policy is narrower
/// than the job default." Fix round 1, finding M2: this parser accepts
/// `approve` (and `default(...)`, `deny`, `fail`) unconditionally — there
/// is no check anywhere that the enclosing run's policy is actually
/// narrower before admitting `approve`. This is a *different* situation
/// from `permissions.unattended.escalate: park`'s own cross-field check
/// (`ParseError::ParkEscalationRequiresDeadlineAndOnTimeout`, enforced by
/// Task 2's `parse_workflow`): that precondition is fully expressible from
/// sibling fields already present in the same parsed document
/// (`deadline`/`on_timeout` next to `escalate` in the same
/// `permissions.unattended` block). §8.11's precondition is not: "the
/// run's policy is narrower than the job default" is a fact about the
/// *bound, running* policy — resolved from the job's default plus
/// whatever trigger/session-level restrictions apply at run start — which
/// this parser never has enough context to evaluate for one step in
/// isolation. Checking it here would require either inventing a fake
/// approximation from static YAML alone (unsound) or threading run-time
/// policy state through a pure YAML parser (a scope change well beyond
/// this task). Deferred to the executor, which resolves and holds the
/// run's actual effective policy — see
/// `gate_on_timeout_approve_parses_without_checking_its_run_time_precondition`
/// in `tests/parse_steps.rs`, which pins this and names the owner.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GateBodyDef {
    title: String,
    #[serde(default = "default_form")]
    form: serde_json::Value,
    timeout: String,
    on_timeout: OnTimeout,
}

/// The as-written-in-YAML shape of an entire step: every field `StepDef`
/// carries, plus every recognised body-shape key, as one flat
/// `#[serde(deny_unknown_fields)]` struct with **no `#[serde(flatten)]`
/// anywhere** — see this module's doc comment for the measured reason a
/// flatten-based design silently let an unrecognised key through. Never
/// constructed or read directly outside [`StepDef`]'s `TryFrom`/`From`
/// impls below.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StepDefWire {
    id: String,
    #[serde(default)]
    when: Option<String>,
    #[serde(default)]
    needs: Vec<String>,
    #[serde(default)]
    continue_on_error: bool,
    #[serde(default)]
    idempotency_key: Option<String>,
    #[serde(default)]
    caps: Option<CapsDef>,
    /// Fix round 1, finding L2: was `Option<serde_json::Value>` (accepted
    /// scalars, arrays, arbitrary nesting, and a key containing `=` or a
    /// newline). Now a flat string-to-string map with each key checked by
    /// [`is_valid_env_name`] — see [`TryFrom<StepDefWire> for StepDef`].
    #[serde(default)]
    env: Option<BTreeMap<String, String>>,
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    with: Option<serde_json::Value>,
    #[serde(default)]
    agent: Option<AgentBodyDef>,
    #[serde(default)]
    map: Option<MapBodyDef>,
    #[serde(default)]
    steps: Option<Vec<serde_yaml::Value>>,
    #[serde(default)]
    gate: Option<GateBodyDef>,
    #[serde(default)]
    call: Option<String>,
    #[serde(default)]
    emit: Option<serde_json::Value>,
    #[serde(default)]
    report: Option<serde_json::Value>,
}

/// One step's body — exactly one of `tool`/`agent`/`map`/`gate`/`call`/
/// `emit`/`report`. Never derives `Deserialize`/`Serialize` on its own:
/// [`StepDef`]'s `TryFrom`/`From` impls (below) are the only code that
/// builds or takes apart a value of this type, exactly like
/// [`super::types::PermissionMatcher`].
#[derive(Debug, Clone, PartialEq)]
pub enum StepBody {
    Tool {
        tool: String,
        with: serde_json::Value,
    },
    Agent {
        model: Option<String>,
        tools: Vec<String>,
        prompt: String,
        output_schema: Option<serde_json::Value>,
    },
    Map {
        over: String,
        r#as: String,
        max_parallel: u32,
        on_item_error: OnItemError,
        isolation: Option<MapIsolationDef>,
        steps: Vec<serde_yaml::Value>,
    },
    Gate {
        title: String,
        form: serde_json::Value,
        timeout: String,
        on_timeout: OnTimeout,
    },
    Call {
        workflow: String,
        with: serde_json::Value,
    },
    Emit {
        emit: serde_json::Value,
    },
    Report {
        report: serde_json::Value,
    },
}

/// The real, public per-step shape everything downstream of parsing matches
/// on.
///
/// # Why this uses the `PermissionRuleDef` + `TryFrom` pattern, not a
/// `#[serde(flatten)]`ed tagged enum
///
/// [`super::types::PermissionRuleDef`]'s doc comment records that an
/// externally-tagged enum behind `#[serde(flatten)]` only guarantees *at
/// least one* recognised key is present among the leftover fields — it does
/// not reject a second recognised key also being present, and does not
/// reject an unrecognised field *inside* the chosen variant's own value,
/// because flatten just picks whichever recognised key it finds first and
/// deserializes that. A step body has exactly the same "closed set of
/// mutually exclusive keys" shape `permissions.rules[]`'s matcher does, so
/// it uses the same fix, applied at the level this module's doc comment
/// explains it actually has to be applied at (this whole struct, not a
/// nested field reached through a second flatten): deserialize into
/// [`StepDefWire`] (one flat struct, `deny_unknown_fields`, no flatten) via
/// `#[serde(try_from = "StepDefWire")]`, then validate explicitly in the
/// `TryFrom` impl below — exactly one of the seven body-kind keys must be
/// present (zero and more-than-one each get their own actionable message,
/// per this task's brief), and a sibling key that only makes sense with one
/// kind (`with` needs `tool` or `call`; `steps` needs `map`) is rejected
/// when the kind it depends on isn't the one present, rather than being
/// silently ignored.
///
/// `#[serde(into = "StepDefWire")]` (via the `From` impl below) makes this
/// type's own `Serialize` go back through the same wire shape `Deserialize`
/// expects — `PermissionRuleDef`'s fix-round-2 finding was exactly a type
/// whose own `Serialize` output its own `Deserialize` then rejected, closed
/// here from the start rather than as a later fix.
///
/// See this module's "Fix round 1" doc section for why `TryFrom`'s
/// associated `Error` type is [`ParseError`] rather than `String` — it's
/// what lets [`parse_step`] surface fully typed errors (`InvalidStepId`,
/// `TooManyNeeds`, ...) while every other deserialize entry point still
/// gets the same validation, just erased to a formatted message by serde's
/// own bridging.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "StepDefWire", into = "StepDefWire")]
pub struct StepDef {
    pub id: String,
    pub when: Option<String>,
    pub needs: Vec<String>,
    pub continue_on_error: bool,
    pub idempotency_key: Option<String>,
    pub caps: Option<CapsDef>,
    pub env: Option<BTreeMap<String, String>>,
    pub body: StepBody,
}

impl TryFrom<StepDefWire> for StepDef {
    type Error = ParseError;

    fn try_from(w: StepDefWire) -> Result<Self, Self::Error> {
        const KNOWN_KINDS: &str = "tool, agent, map, gate, call, emit, report";

        validate_step_id(&w.id)?;
        if w.needs.len() > MAX_NEEDS_PER_STEP {
            return Err(ParseError::TooManyNeeds {
                step: w.id.clone(),
                actual: w.needs.len(),
                max: MAX_NEEDS_PER_STEP,
            });
        }
        if let Some(env) = &w.env {
            for (name, value) in env {
                if !is_valid_env_name(name) {
                    return Err(ParseError::InvalidStepBody {
                        step: w.id.clone(),
                        reason: format!(
                            "env variable name {name:?} is invalid — must match POSIX-style [A-Za-z_][A-Za-z0-9_]*"
                        ),
                    });
                }
                if !is_valid_env_value(value) {
                    return Err(ParseError::InvalidStepBody {
                        step: w.id.clone(),
                        reason: format!(
                            "env variable {name:?}'s value must not contain a newline, carriage return, or NUL byte"
                        ),
                    });
                }
            }
        }

        let mut kinds: Vec<&'static str> = Vec::with_capacity(1);
        if w.tool.is_some() {
            kinds.push("tool");
        }
        if w.agent.is_some() {
            kinds.push("agent");
        }
        if w.map.is_some() {
            kinds.push("map");
        }
        if w.gate.is_some() {
            kinds.push("gate");
        }
        if w.call.is_some() {
            kinds.push("call");
        }
        if w.emit.is_some() {
            kinds.push("emit");
        }
        if w.report.is_some() {
            kinds.push("report");
        }

        let kind = match kinds.len() {
            0 => {
                return Err(ParseError::InvalidStepBody {
                    step: w.id.clone(),
                    reason: format!(
                        "a step body must have exactly one of: {KNOWN_KINDS} — found none"
                    ),
                });
            }
            1 => kinds[0],
            _ => {
                return Err(ParseError::InvalidStepBody {
                    step: w.id.clone(),
                    reason: format!(
                        "a step body must have exactly one of: {KNOWN_KINDS} — found {}: {:?}",
                        kinds.len(),
                        kinds
                    ),
                });
            }
        };

        if w.with.is_some() && kind != "tool" && kind != "call" {
            return Err(ParseError::InvalidStepBody {
                step: w.id.clone(),
                reason: format!(
                    "`with` is only valid alongside `tool` or `call`, not alongside `{kind}` — found `with` with no `tool`/`call` on the same step"
                ),
            });
        }
        if w.steps.is_some() && kind != "map" {
            return Err(ParseError::InvalidStepBody {
                step: w.id.clone(),
                reason: format!(
                    "`steps` is only valid alongside `map`, not alongside `{kind}` — found a sibling `steps:` list with no `map` on the same step"
                ),
            });
        }

        let body = match kind {
            "tool" => StepBody::Tool {
                tool: w.tool.expect("checked above: kind is tool"),
                with: w.with.unwrap_or_else(|| serde_json::json!({})),
            },
            "agent" => {
                let a = w.agent.expect("checked above: kind is agent");
                StepBody::Agent {
                    model: a.model,
                    tools: a.tools,
                    prompt: a.prompt,
                    output_schema: a.output_schema,
                }
            }
            "map" => {
                let m = w.map.expect("checked above: kind is map");
                let steps = w.steps.ok_or_else(|| ParseError::InvalidStepBody {
                    step: w.id.clone(),
                    reason: "a `map` step requires a sibling `steps:` list".to_string(),
                })?;
                StepBody::Map {
                    over: m.over,
                    r#as: m.r#as,
                    max_parallel: m.max_parallel,
                    on_item_error: m.on_item_error,
                    isolation: m.isolation,
                    steps,
                }
            }
            "gate" => {
                let g = w.gate.expect("checked above: kind is gate");
                StepBody::Gate {
                    title: g.title,
                    form: g.form,
                    timeout: g.timeout,
                    on_timeout: g.on_timeout,
                }
            }
            "call" => StepBody::Call {
                workflow: w.call.expect("checked above: kind is call"),
                with: w.with.unwrap_or_else(|| serde_json::json!({})),
            },
            "emit" => StepBody::Emit {
                emit: w.emit.expect("checked above: kind is emit"),
            },
            "report" => StepBody::Report {
                report: w.report.expect("checked above: kind is report"),
            },
            other => unreachable!("kinds.push only ever pushes a recognised kind, got {other:?}"),
        };

        Ok(StepDef {
            id: w.id,
            when: w.when,
            needs: w.needs,
            continue_on_error: w.continue_on_error,
            idempotency_key: w.idempotency_key,
            caps: w.caps,
            env: w.env,
            body,
        })
    }
}

impl From<StepDef> for StepDefWire {
    fn from(def: StepDef) -> Self {
        let mut wire = StepDefWire {
            id: def.id,
            when: def.when,
            needs: def.needs,
            continue_on_error: def.continue_on_error,
            idempotency_key: def.idempotency_key,
            caps: def.caps,
            env: def.env,
            tool: None,
            with: None,
            agent: None,
            map: None,
            steps: None,
            gate: None,
            call: None,
            emit: None,
            report: None,
        };
        match def.body {
            StepBody::Tool { tool, with } => {
                wire.tool = Some(tool);
                wire.with = Some(with);
            }
            StepBody::Agent {
                model,
                tools,
                prompt,
                output_schema,
            } => {
                wire.agent = Some(AgentBodyDef {
                    model,
                    tools,
                    prompt,
                    output_schema,
                });
            }
            StepBody::Map {
                over,
                r#as,
                max_parallel,
                on_item_error,
                isolation,
                steps,
            } => {
                wire.map = Some(MapBodyDef {
                    over,
                    r#as,
                    max_parallel,
                    on_item_error,
                    isolation,
                });
                wire.steps = Some(steps);
            }
            StepBody::Gate {
                title,
                form,
                timeout,
                on_timeout,
            } => {
                wire.gate = Some(GateBodyDef {
                    title,
                    form,
                    timeout,
                    on_timeout,
                });
            }
            StepBody::Call { workflow, with } => {
                wire.call = Some(workflow);
                wire.with = Some(with);
            }
            StepBody::Emit { emit } => {
                wire.emit = Some(emit);
            }
            StepBody::Report { report } => {
                wire.report = Some(report);
            }
        }
        wire
    }
}

/// Parses one step body (§8.9: `tool`/`agent`/`map`/`gate`/`call`/`emit`/
/// `report`) from a raw `serde_yaml::Value` — one entry of
/// `WorkflowDef.steps`/`.catch`/`.finally` (Task 2), or one entry of a
/// `map` step's own nested `steps:` list (the caller re-invokes this on
/// each nested entry itself; this function does not recurse into a `map`
/// step's `steps:` list on its own).
///
/// **What isn't bounded here, and who owns it (fix round 1, finding L1):**
/// this function doesn't bound a nested `map` step's `steps:` list length
/// (Task 2's `MAX_TOP_LEVEL_STEPS` only applies to the top-level list —
/// roughly 8,700 nested steps fit under the 256 KiB byte cap alone), and
/// [`MapBodyDef`]'s `max_parallel` accepts `0` or `u32::MAX` unchecked.
/// Nesting depth of `map`-inside-`map` is bounded only by `serde_yaml`'s
/// own 128-deep recursion guard (`parse/mod.rs`'s doc comment), not by
/// anything in this crate. All three are the executor's (Task 5) or a
/// future recursive-validation pass's responsibility, not this function's
/// — named here rather than left implicit.
///
/// Calls `StepDef::try_from` directly rather than
/// `serde_yaml::from_value::<StepDef>(v)` so its errors stay a fully typed
/// [`ParseError`] (see this module's "Fix round 1" doc section for why
/// that distinction exists and what it costs other callers).
pub fn parse_step(v: &serde_yaml::Value) -> Result<StepDef, ParseError> {
    let wire: StepDefWire = serde_yaml::from_value(v.clone())?;
    StepDef::try_from(wire)
}

/// Returns step indices in an order that respects `needs:`, falling back to
/// file order when `needs:` doesn't constrain the choice (§8.9: "Steps run
/// in file order unless `needs:` declares an explicit DAG") — a stable
/// Kahn's-algorithm topological sort, always picking the lowest original
/// index among the currently-ready steps, so ties resolve to file order
/// exactly.
///
/// Operates purely on the graph already implied by `steps` — it does not
/// itself bound `steps.len()` (the caller's responsibility; `parse_workflow`
/// bounds the top-level list via `MAX_TOP_LEVEL_STEPS`) beyond bounding the
/// number of `needs:` edges per step ([`MAX_NEEDS_PER_STEP`], now enforced
/// inside `TryFrom<StepDefWire> for StepDef` — see this module's "Fix round
/// 1" doc section — so every `StepDef` this function could ever receive
/// already satisfies it, regardless of how that `StepDef` was built).
/// Security review's own measurements: an iterative (non-recursive) Kahn's
/// algorithm resolves a 100,000-node chain in 19.1 ms and 5,000 steps ×
/// [`MAX_NEEDS_PER_STEP`] each in 8.2 ms, and the duplicate-id pass below
/// makes every later in-degree decrement provably underflow-free (an edge
/// is only ever recorded between two distinct, already-validated indices).
/// Every failure mode below is a typed [`ParseError`], never a panic or a
/// hang:
///
/// - **Duplicate step id** ([`ParseError::DuplicateStepId`]): checked before
///   any graph work, so a duplicate never silently shadows an earlier
///   step's dependents.
/// - **`needs:` naming a step id that isn't in this same list**
///   ([`ParseError::UnknownStepDependency`]).
/// - **A step listing itself in its own `needs:`** falls out of the same
///   cycle detection below as an ordinary length-one cycle — Kahn's
///   algorithm can never make such a step "ready," since the only edge that
///   could decrement its in-degree to zero is an edge from itself, which
///   only fires once the step itself has already been placed in the order.
/// - **A cycle of any length** ([`ParseError::StepGraphCycle`]): if any
///   step's in-degree never reaches zero, the loop below terminates with
///   `order.len() < steps.len()` rather than looping forever — Kahn's
///   algorithm is why a cycle here is termination, not a hang.
pub fn topological_order(steps: &[StepDef]) -> Result<Vec<usize>, ParseError> {
    let n = steps.len();

    let mut id_to_idx: HashMap<&str, usize> = HashMap::with_capacity(n);
    for (i, s) in steps.iter().enumerate() {
        if id_to_idx.contains_key(s.id.as_str()) {
            return Err(ParseError::DuplicateStepId { id: s.id.clone() });
        }
        id_to_idx.insert(s.id.as_str(), i);
    }

    let mut in_degree = vec![0usize; n];
    let mut edges: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, s) in steps.iter().enumerate() {
        for dep in &s.needs {
            let &dep_idx =
                id_to_idx
                    .get(dep.as_str())
                    .ok_or_else(|| ParseError::UnknownStepDependency {
                        step: s.id.clone(),
                        needs: dep.clone(),
                    })?;
            edges[dep_idx].push(i);
            in_degree[i] += 1;
        }
    }

    // Stable Kahn's algorithm: always pick the lowest-index ready node next,
    // so ties resolve to file order exactly as §8.9 specifies.
    let mut ready: BTreeSet<usize> = (0..n).filter(|&i| in_degree[i] == 0).collect();
    let mut order = Vec::with_capacity(n);
    while let Some(&next) = ready.iter().next() {
        ready.remove(&next);
        order.push(next);
        for &dependent in &edges[next] {
            in_degree[dependent] -= 1;
            if in_degree[dependent] == 0 {
                ready.insert(dependent);
            }
        }
    }

    if order.len() != n {
        let stuck: Vec<String> = (0..n)
            .filter(|&i| in_degree[i] > 0)
            .map(|i| steps[i].id.clone())
            .collect();
        return Err(ParseError::StepGraphCycle { steps: stuck });
    }

    Ok(order)
}
