//! The mandatory structured `report` task: §8.6's core+extension schema, its
//! fingerprint diff, and `carry_over: { last_report: true }` seeding.
//!
//! §8.6 of `docs/architecture/05-scheduling-and-workflows.md` calls the
//! report *"the single highest-leverage decision for triage"*: every run ends
//! in one, it is persisted as a real `TaskKind::Report` task rather than
//! assembled in memory, and the Runs inbox's whole generic sort-and-diff
//! reads nothing but its core fields.
//!
//! Everything here is **pure**. Loading the previous run's persisted report —
//! `run.session_id` -> `tasks`/`events` -> filter `kind = 'Report'` ->
//! `TaskCompleted.output` — is a `roundhouse-store` query that does not exist
//! yet and is not this module's to write; [`diff_findings`] and
//! [`build_carry_over_seed`] operate on values a caller has already loaded.
//!
//! # What this module does *not* decide
//!
//! Whether a run is *required* to produce a report, and which terminal states
//! (`Cancelled`? `Failed`? a timed-out `AwaitingHuman`?) must carry one, is
//! the run loop's question, not the schema's. §4.2 of `01-data-model.md` says
//! the report is the mandatory terminal task of every run and that its input
//! is *"none (assembled from the run's tasks)"*, while the landed executor
//! takes it from the author's `report:` block and nothing enforces
//! mandatoriness anywhere. That gap is recorded against Task 20 (B12).

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::job::canonicalize_json;

/// What the run **found** — result triage.
///
/// # This is not [`crate::durability::RunState`], and must never be derived from it
///
/// The two look like one concept arriving twice ([`Outcome::Failed`] against
/// `RunState::Failed`; [`Report::needs_human`] against
/// `RunState::AwaitingHuman`). They are orthogonal axes:
///
/// - **`RunState` is where the run *is*** — its execution position.
/// - **`Outcome`/[`Report::needs_human`] is what the run *found*** — its
///   result.
///
/// A `RunState::Completed` run can carry `Outcome::Findings` with
/// `needs_human: true`: it finished executing cleanly and still wants a human
/// to read what it found. Conversely a run in `RunState::AwaitingHuman` is
/// blocked *right now* and has **no report at all**, because the report is
/// terminal — there is nothing to derive an `Outcome` from yet.
///
/// The Runs inbox shows both because they are two different columns. Deriving
/// either from the other collapses them, and the first run that is
/// `Completed` with findings — the common nightly-lint case — is where that
/// collapse produces a wrong answer.
///
/// The five variants are frozen by §8.6's `// nothing | changed | findings |
/// failed | needs_human` comment; the wire spellings are those words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Nothing,
    Changed,
    Findings,
    Failed,
    NeedsHuman,
}

/// §8.6's three-level severity, on both the report and each finding.
///
/// The derived `Ord` follows declaration order — `Low < Med < High` — which
/// is the direction the inbox's `(needs_human, severity, outcome != nothing)`
/// sort needs; reordering these variants silently reorders the inbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Med,
    High,
}

/// §8.6's `"cost": { "usd": 0.42, "tokens": 118204 }`.
///
/// # `usd` is an `f64` because the wire shape is frozen, and it is not the authority
///
/// The tree's internal money type is an **integer** —
/// `roundhouse_store`'s `RollupCost::known_pico_usd: u64` — precisely because
/// binary floating point cannot represent decimal currency exactly. That
/// integer is the authoritative accounting value. This `f64` is the *report's
/// display rendering* of a cost, fixed by §8.6's example, and the JSON
/// boundary is a legitimate place for the two to differ.
///
/// The consequence, stated rather than left implicit: **never put
/// [`Cost::usd`] into a hash, a fingerprint, or an equality used for
/// deduplication.** `0.1 + 0.2` and `0.3` are different `f64`s and would make
/// two otherwise-identical reports compare unequal. The derived `PartialEq`
/// here exists for tests in `tests/report.rs`; it is deliberately not
/// `Eq`/`Hash`, so the type system refuses to let this value key a map or
/// enter a `HashSet`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Cost {
    pub usd: f64,
    pub tokens: u64,
}

/// One finding, with §8.6's four core fields plus whatever else the job
/// author put on it.
///
/// `id` is the **stable fingerprint**. §8.6: *"who computes the fingerprint
/// `id` is job-specific (a lint job hashes `(file_path, rule_id)`, a
/// PR-review job hashes `(pr_number, comment_category)`) — but that a stable
/// fingerprint exists is core and mandatory."* This crate never computes one;
/// it only ever compares the ids it is handed ([`diff_findings`]).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub location: String,
    /// Everything the finding object carries beyond the four core fields —
    /// rendered generically in a human's detail view, invisible to the
    /// inbox's cross-job sort (§8.6: core is *"precisely the fields the
    /// generic inbox touches, nothing more"*). `#[serde(flatten)]`, so on the
    /// wire these keys sit directly on the finding object (matching §8.6's
    /// `"pr_number": 4471` example) rather than nested under an `extra` key.
    /// Always canonically sorted when produced by [`validate_report`]. No
    /// `Deserialize` on the containing [`Finding`] means flatten affects only
    /// this output direction — see [`Report`]'s doc for why.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// A validated report.
///
/// # Why the fields are `pub`, unlike [`crate::durability::StepOutput`]
///
/// `StepOutput` sits one module over with **private** fields and a
/// `value_for_display()` that withholds secret-derived material. The
/// divergence is deliberate, not an oversight: those two types hold values
/// with different provenance.
///
/// `StepOutput` wraps a step's **unredacted** output — it exists precisely
/// because that value can be secret-derived at rest, so the taint check has
/// to live inside the accessor where a caller cannot skip it. A `Report`, by
/// contrast, is only ever built from material that is **already redacted**:
/// the executor's `report:` arm validates and persists
/// `redact_with_needles(resolved.redacted_for_logging(), …)`, so a
/// `${{ secrets.* }}` reference has become `REDACTION_PLACEHOLDER` before any
/// `Report` exists. There is no unredacted rendering here to guard, and
/// private fields plus an accessor would imply a check that has nothing left
/// to check.
///
/// This holds because of *where the one call site is*, not because anything
/// here enforces it: `exec/mod.rs`'s `Report` step arm is the only place in
/// the crate that calls [`validate_report`], and it always passes the
/// already-redacted `logged` value. A caller that instead validated
/// unredacted material would build a `Report` this guarantee does not
/// actually hold for — there is nothing in this module that would notice.
///
/// The visible consequence, which surprises people: a `headline` or a
/// `finding.id` interpolated from a secret validates and persists as the
/// redaction placeholder, not as the secret. That is correct — the log is
/// append-only and a leak into it is unrecoverable — but it means a job that
/// fingerprints findings from secret-derived material gets one fingerprint
/// for all of them.
///
/// # Why `Serialize` only, and no `Deserialize`
///
/// Nothing in this crate — or downstream — ever deserializes a `Report`: the
/// executor persists the raw redacted `serde_json::Value` as
/// `TaskCompleted.output`, not a serialized `Report`, and reads it back the
/// same way. `Serialize` exists so a validated report can be rendered in
/// §8.6's flat wire shape (via `extra`'s `#[serde(flatten)]` below, on both
/// this type and [`Finding`]); [`validate_report`] is the only way to obtain
/// a `Report` at all.
///
/// `Deserialize` is deliberately absent, not merely unused. Adding it back
/// (even with `#[serde(flatten)]` + `#[serde(default)]` on `extra`, to make
/// §8.6's own example round-trip) would open a second ingress —
/// `serde_json::from_value::<Report>(v)` — that constructs a `Report`
/// straight from `v` without ever calling [`validate_report`], silently
/// skipping every one of its checks. If a future caller needs to read a
/// persisted report back as a typed `Report`, the answer is to call
/// [`validate_report`] on the persisted `Value` a second time, not to
/// deserialize it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Report {
    pub outcome: Outcome,
    pub severity: Severity,
    pub headline: String,
    pub needs_human: bool,
    pub cost: Cost,
    pub findings: Vec<Finding>,
    pub artifacts: Vec<serde_json::Value>,
    pub next_actions: Vec<String>,
    /// Job-defined top-level fields. `#[serde(flatten)]`, so on the wire
    /// these sit at the top level of the report document (matching §8.6's
    /// literal example) rather than nested under an `extra` key. Always
    /// canonically sorted when produced by [`validate_report`].
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Why a candidate report is not one.
///
/// Every variant renders the offending value through [`brief`], so a
/// rejection message can be pasted into a step-failure record without
/// dragging an arbitrarily large payload along with it.
#[derive(Debug, Error)]
pub enum ReportError {
    #[error("report must be a JSON object, got {0}")]
    NotAnObject(String),
    #[error("missing required core field: `{0}`")]
    MissingField(&'static str),
    #[error("invalid value for field `{field}`: {value}")]
    InvalidValue { field: &'static str, value: String },
    #[error("findings[{index}] must be a JSON object, got {value}")]
    FindingNotAnObject { index: usize, value: String },
    #[error("findings[{index}]: missing required core field: `{field}`")]
    MissingFindingField { index: usize, field: &'static str },
    #[error("findings[{index}]: invalid value for field `{field}`: {value}")]
    InvalidFindingValue {
        index: usize,
        field: &'static str,
        value: String,
    },
    #[error("next_actions[{index}]: invalid value: {value}")]
    InvalidNextAction { index: usize, value: String },
}

/// §8.6: *"Core, required, fixed-shape: `outcome`, `severity`, `needs_human`,
/// `headline`, `cost` at the top level."*
const CORE_TOP_LEVEL: &[&str] = &["outcome", "severity", "headline", "needs_human", "cost"];

/// §8.6: *"…`id`, `title`, `severity`, `location` per finding."*
const CORE_FINDING: &[&str] = &["id", "title", "severity", "location"];

/// The three top-level collections that are neither core scalars nor
/// extension fields: they have a known shape, so they are parsed rather than
/// swept into [`Report::extra`].
const KNOWN_COLLECTIONS: &[&str] = &["findings", "artifacts", "next_actions"];

/// Longest value excerpt a [`ReportError`] will quote, in `char`s.
///
/// A rejection message ends up in a persisted step-failure string, so it must
/// not be able to carry a caller-controlled payload of unbounded size. The
/// cap is enforced by [`brief`] and exercised by
/// `a_rejection_message_never_dumps_an_unbounded_payload`, which feeds a
/// 10,000-character `severity` and measures the rendered message.
const MAX_ERROR_VALUE_CHARS: usize = 64;

/// Render `value` as JSON, truncated to [`MAX_ERROR_VALUE_CHARS`] `char`s
/// with a trailing `…` when it was cut.
///
/// Truncation is by `char`, not by byte, so a multi-byte code point is never
/// split.
fn brief(value: &serde_json::Value) -> String {
    let rendered = value.to_string();
    let mut out = String::new();
    for (taken, ch) in rendered.chars().enumerate() {
        if taken == MAX_ERROR_VALUE_CHARS {
            out.push('…');
            return out;
        }
        out.push(ch);
    }
    out
}

/// Parse and validate a candidate report against §8.6's core schema.
///
/// Core fields are required and fixed-shape; everything else is open and
/// job-defined, landing in [`Report::extra`] or [`Finding::extra`] rather
/// than being an error. A collection that is *present with the wrong type*
/// **is** an error: silently reading `"findings": "three of them"` as "no
/// findings" would report a run as clean because its report was malformed,
/// which is the exact failure this validation exists to prevent.
///
/// Every `serde_json::Value` the returned [`Report`] holds is canonicalized
/// (see [`canonicalize_json`]), so a validated report's JSON encoding depends
/// on its structure and not on the key insertion order it arrived in. With
/// `serde_json`'s `preserve_order` live workspace-wide those are different
/// things, and anything downstream that hashes, ETags, or byte-compares a
/// report would otherwise be non-deterministic.
///
/// **This canonicalization does not currently reach the persisted
/// artifact.** It lives in the `Report` this function returns; the
/// executor's `report:` arm calls this function only to decide pass/fail and
/// persists the pre-validation `logged` `Value` — with the author's original
/// key order — as `TaskCompleted.output`. A future inbox that ETags or
/// byte-compares persisted report bytes must canonicalize *on read*; it
/// cannot rely on this function having already done so for what is on disk.
pub fn validate_report(v: &serde_json::Value) -> Result<Report, ReportError> {
    let obj = v
        .as_object()
        .ok_or_else(|| ReportError::NotAnObject(brief(v)))?;
    for field in CORE_TOP_LEVEL {
        if !obj.contains_key(*field) {
            return Err(ReportError::MissingField(field));
        }
    }

    let outcome: Outcome = typed(&obj["outcome"], "outcome")?;
    let severity: Severity = typed(&obj["severity"], "severity")?;
    let headline = obj["headline"]
        .as_str()
        .ok_or_else(|| ReportError::InvalidValue {
            field: "headline",
            value: brief(&obj["headline"]),
        })?
        .to_string();
    let needs_human = obj["needs_human"]
        .as_bool()
        .ok_or_else(|| ReportError::InvalidValue {
            field: "needs_human",
            value: brief(&obj["needs_human"]),
        })?;
    let cost = parse_cost(&obj["cost"])?;

    let mut findings = Vec::new();
    for (index, raw) in array_field(obj, "findings")?.iter().enumerate() {
        findings.push(parse_finding(raw, index)?);
    }

    let artifacts: Vec<serde_json::Value> = array_field(obj, "artifacts")?
        .iter()
        .map(canonicalize_json)
        .collect();

    let mut next_actions = Vec::new();
    for (index, raw) in array_field(obj, "next_actions")?.iter().enumerate() {
        next_actions.push(
            raw.as_str()
                .ok_or_else(|| ReportError::InvalidNextAction {
                    index,
                    value: brief(raw),
                })?
                .to_string(),
        );
    }

    let extra = extension_fields(obj, CORE_TOP_LEVEL, KNOWN_COLLECTIONS);

    Ok(Report {
        outcome,
        severity,
        headline,
        needs_human,
        cost,
        findings,
        artifacts,
        next_actions,
        extra,
    })
}

/// Deserialize one core field into its typed form, reporting the field name
/// and a bounded excerpt of the offending value on failure.
fn typed<T: serde::de::DeserializeOwned>(
    value: &serde_json::Value,
    field: &'static str,
) -> Result<T, ReportError> {
    serde_json::from_value(value.clone()).map_err(|_| ReportError::InvalidValue {
        field,
        value: brief(value),
    })
}

/// §8.6's `"cost": { "usd": 0.42, "tokens": 118204 }`, parsed subfield by
/// subfield rather than through [`typed`] so a missing or mistyped subfield
/// names *that subfield* (`cost.tokens`) instead of quoting the whole `cost`
/// object back at the caller and leaving them to guess which key is wrong.
fn parse_cost(value: &serde_json::Value) -> Result<Cost, ReportError> {
    let obj = value.as_object().ok_or_else(|| ReportError::InvalidValue {
        field: "cost",
        value: brief(value),
    })?;
    let usd = match obj.get("usd") {
        None => return Err(ReportError::MissingField("cost.usd")),
        Some(raw) => raw.as_f64().ok_or_else(|| ReportError::InvalidValue {
            field: "cost.usd",
            value: brief(raw),
        })?,
    };
    let tokens = match obj.get("tokens") {
        None => return Err(ReportError::MissingField("cost.tokens")),
        Some(raw) => raw.as_u64().ok_or_else(|| ReportError::InvalidValue {
            field: "cost.tokens",
            value: brief(raw),
        })?,
    };
    Ok(Cost { usd, tokens })
}

/// An optional array-valued field: absent — or explicitly `null`, which is
/// what ordinary hand-written YAML produces for a key with nothing after
/// it (`findings:` alone) — yields an empty slice; present with any other
/// non-array type is a rejection.
fn array_field<'a>(
    obj: &'a serde_json::Map<String, serde_json::Value>,
    field: &'static str,
) -> Result<&'a [serde_json::Value], ReportError> {
    match obj.get(field) {
        None | Some(serde_json::Value::Null) => Ok(&[]),
        Some(value) => {
            value
                .as_array()
                .map(Vec::as_slice)
                .ok_or_else(|| ReportError::InvalidValue {
                    field,
                    value: brief(value),
                })
        }
    }
}

fn parse_finding(raw: &serde_json::Value, index: usize) -> Result<Finding, ReportError> {
    let obj = raw
        .as_object()
        .ok_or_else(|| ReportError::FindingNotAnObject {
            index,
            value: brief(raw),
        })?;
    for field in CORE_FINDING {
        if !obj.contains_key(*field) {
            return Err(ReportError::MissingFindingField { index, field });
        }
    }
    let string_field = |field: &'static str| -> Result<String, ReportError> {
        obj[field]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| ReportError::InvalidFindingValue {
                index,
                field,
                value: brief(&obj[field]),
            })
    };
    let severity: Severity = serde_json::from_value(obj["severity"].clone()).map_err(|_| {
        ReportError::InvalidFindingValue {
            index,
            field: "severity",
            value: brief(&obj["severity"]),
        }
    })?;
    Ok(Finding {
        id: string_field("id")?,
        title: string_field("title")?,
        severity,
        location: string_field("location")?,
        extra: extension_fields(obj, CORE_FINDING, &[]),
    })
}

/// Everything in `obj` that is neither a core field nor a separately-parsed
/// collection, as a canonically-keyed map — ready to sit behind
/// [`Report::extra`] or [`Finding::extra`]'s `#[serde(flatten)]`.
fn extension_fields(
    obj: &serde_json::Map<String, serde_json::Value>,
    core: &[&str],
    collections: &[&str],
) -> serde_json::Map<String, serde_json::Value> {
    let mut extra = serde_json::Map::new();
    for (key, value) in obj {
        if !core.contains(&key.as_str()) && !collections.contains(&key.as_str()) {
            extra.insert(key.clone(), value.clone());
        }
    }
    match canonicalize_json(&serde_json::Value::Object(extra)) {
        serde_json::Value::Object(map) => map,
        _ => unreachable!("canonicalize_json preserves the Object variant"),
    }
}

/// A finding's standing relative to the previous run of the same binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    New,
    Persisting,
    Resolved,
}

/// §8.6's fingerprint diff: *"findings carry stable fingerprint ids, so the
/// inbox diffs against the previous run of the same binding and labels each
/// finding new / persisting / resolved — you read the twelve nightly lint
/// complaints once, not thirty times."*
///
/// A `current` finding whose `id` appears in `previous` is `Persisting`, one
/// that does not is `New`; a `previous` finding whose `id` is absent from
/// `current` is `Resolved`. Comparison is by `id` alone, because the
/// fingerprint is job-defined and this function is deliberately ignorant of
/// how it was computed.
///
/// A `Persisting` entry carries the **current** run's copy of the finding,
/// not the previous one's: the same issue seen again may have a new title,
/// location detail or count, and the detail view must show what this run
/// found.
///
/// Callers should not depend on the returned order beyond "current findings
/// first, then resolved ones"; the inbox sorts by
/// `(needs_human, severity, …)` anyway.
pub fn diff_findings(previous: &[Finding], current: &[Finding]) -> Vec<(Finding, FindingStatus)> {
    use std::collections::HashSet;
    let previous_ids: HashSet<&str> = previous.iter().map(|f| f.id.as_str()).collect();
    let current_ids: HashSet<&str> = current.iter().map(|f| f.id.as_str()).collect();

    let mut out: Vec<(Finding, FindingStatus)> = current
        .iter()
        .map(|f| {
            let status = if previous_ids.contains(f.id.as_str()) {
                FindingStatus::Persisting
            } else {
                FindingStatus::New
            };
            (f.clone(), status)
        })
        .collect();
    for f in previous {
        if !current_ids.contains(f.id.as_str()) {
            out.push((f.clone(), FindingStatus::Resolved));
        }
    }
    out
}

/// §8.6's `carry_over: { last_report: true }` on a job's `defaults:`.
///
/// This is the whole shape — there is no `memory_scope` field and no fourth
/// `MemoryScope`. §8.6 is explicit that job continuity *"does not need a
/// dedicated memory scope"* and that §15.1's three scopes stay exactly three:
/// *"continuity is data, not scrollback."*
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CarryOver {
    #[serde(default)]
    pub last_report: bool,
}

/// Build the seed a new run is given when `carry_over.last_report` is set and
/// the previous run of the same binding produced a report.
///
/// Returns `None` when carry-over is off, and `None` — never an error — when
/// there is no prior report, because a binding's first-ever run has no
/// history and that is the normal state, not a failure.
///
/// The seed deliberately carries only the previous report's headline,
/// outcome, and each finding's `(id, title)`: enough for the run to recognise
/// an issue it has seen before, without replaying a whole prior transcript.
/// The full prior report remains queryable as a persisted task if a job wants
/// more.
///
/// The result is canonicalized so the same prior report always seeds the same
/// bytes, regardless of the key order in the `Report` it was built from —
/// this function accepts hand-constructed `Report`s, not only ones
/// [`validate_report`] already canonicalized.
pub fn build_carry_over_seed(
    carry_over: &CarryOver,
    previous_report: Option<&Report>,
) -> Option<serde_json::Value> {
    if !carry_over.last_report {
        return None;
    }
    let previous = previous_report?;
    let findings: Vec<serde_json::Value> = previous
        .findings
        .iter()
        .map(|f| serde_json::json!({ "id": f.id, "title": f.title }))
        .collect();
    Some(canonicalize_json(&serde_json::json!({
        "kind": "carry_over_seed",
        "previous_report": {
            "outcome": previous.outcome,
            "headline": previous.headline,
            "findings": findings,
        }
    })))
}

/// §8.6's report schema as a JSON Schema object — what a workflow **returns**
/// when it is exposed as a tool (§8.12: *"`inputs` is the tool schema,
/// `outputs` is the result"*).
///
/// # This is the answer to the `outputs:` gap, and it is "not a declared block"
///
/// [`crate::compose`]'s module doc records `outputs:` as a frozen-contract gap
/// owned by B12c on the grounds that *"the first task with a run loop … is
/// therefore the first that can observe what a workflow's result actually is
/// and therefore judge whether `outputs:` should be a declared block in
/// `parse/types.rs` or derived from the run's `report`/`finally` shape."* With
/// the run loop built, the observation is available and it settles it:
///
/// - **Exactly one thing is produced by every run, in every terminal state.**
///   Ruling P112 makes the `TaskKind::Report` task mandatory —
///   [`crate::run_loop`] synthesises one when the author declares no `report:`
///   step — so the report is the only value a caller of `workflow:<name>` can
///   be promised.
/// - **A declared `outputs:` block would be a promise with no mechanism
///   behind it.** Nothing in the run loop assembles a *second*, author-shaped
///   result value; a `call:` returns the child run, whose durable product is
///   its report. An `outputs:` block would let an author declare a schema the
///   crate has no way to populate or check — worse than the absent schema
///   [`WorkflowToolRegistration::output_schema`](crate::compose::WorkflowToolRegistration::output_schema)
///   refused to fabricate, because it would look authoritative.
/// - **The extension half stays open**, exactly as §8.6 intends: this schema
///   pins the core (*"precisely the fields the generic inbox touches"*) and
///   leaves `additionalProperties` true, which is where a job's own result
///   fields live. That is the author-declared part, and it needs no new
///   keyword.
///
/// So the wire shape does **not** change for `outputs:`, and
/// `register_as_tool` returns this instead of `None`. Recorded as a
/// correction rather than as compliance: B12c's brief lists `outputs:` with
/// `on_crash:` as *"one wire-shape slice"*, and only one of the two turns out
/// to be one.
///
/// # Every constraint here mirrors [`validate_report`], and only those
///
/// The two must agree, so this enumerates §8.6's core and nothing else:
/// `required` is [`CORE_TOP_LEVEL`], per-finding `required` is
/// [`CORE_FINDING`], the two enum domains are [`Outcome`]'s and
/// [`Severity`]'s wire spellings, and the three known collections are typed as
/// arrays because `validate_report` rejects them present-with-the-wrong-type.
/// It does **not** claim anything `validate_report` does not check — there is
/// no `minLength` on `headline`, no bound on `findings`, and no pattern on
/// `id`, because a schema that promised those would be describing a validator
/// that does not exist.
pub fn core_json_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "required": CORE_TOP_LEVEL,
        "properties": {
            "outcome": { "enum": ["nothing", "changed", "findings", "failed", "needs_human"] },
            "severity": { "enum": ["low", "med", "high"] },
            "headline": { "type": "string" },
            "needs_human": { "type": "boolean" },
            "cost": {
                "type": "object",
                "required": ["usd", "tokens"],
                "properties": {
                    "usd": { "type": "number" },
                    "tokens": { "type": "integer", "minimum": 0 },
                },
            },
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": CORE_FINDING,
                    "properties": {
                        "id": { "type": "string" },
                        "title": { "type": "string" },
                        "severity": { "enum": ["low", "med", "high"] },
                        "location": { "type": "string" },
                    },
                    "additionalProperties": true,
                },
            },
            "artifacts": { "type": "array" },
            "next_actions": { "type": "array", "items": { "type": "string" } },
        },
        // §8.6's extension half: "core+extension, with the core defined as
        // precisely the fields the generic inbox touches". Closing this would
        // reject every job-defined field the schema exists to permit.
        "additionalProperties": true,
    })
}
