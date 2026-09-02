//! Typed shape of a single step body (§8.9: `tool`/`agent`/`map`/`gate`/
//! `call`/`emit`/`report`), and `needs:`-respecting run ordering over a
//! parsed list of steps.
//!
//! `WorkflowDef.steps`/`.catch`/`.finally` (Task 2, [`super::WorkflowDef`])
//! stay raw `serde_yaml::Value` — this module is what a caller hands each
//! entry to individually via [`parse_step`], and what it hands the parsed
//! result to via [`topological_order`] to get a run order.
//!
//! # Fail-closed by construction
//!
//! Every step-body-shape key (`tool`, `agent`, `map`, `gate`, `call`,
//! `emit`, `report`, plus the `with`/`steps` keys some of them take a
//! sibling from) is a named field on [`StepDefWire`], one single
//! `#[serde(deny_unknown_fields)]` struct with no `#[serde(flatten)]`
//! anywhere in it — a typo (`toolz:`, `agemt:`) is a parse error, not a
//! silently-ignored field.
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
//! `duplicate_step_body_key_is_rejected` in `tests/parse_steps.rs` proves
//! this directly: parsing `"tool: shell\ntool: http"` into a bare
//! `serde_yaml::Value` already errors, which the test asserts before ever
//! calling [`parse_step`]. This module's own typed structs (ordinary
//! `#[derive(Deserialize)]` structs, whose generated field visitor
//! independently rejects a duplicate *named* field the same way) add a
//! second, redundant layer of the same protection for the fields they
//! define directly — genuinely redundant here, not load-bearing, but still
//! covered by a regression test (`duplicate_nested_agent_field_is_rejected`)
//! in case a future change ever bypasses the `Value` stage.

use super::ParseError;
use crate::parse::types::OnTimeout;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};

/// Sanity bound on a step id's length. Step ids flow into provenance, logs,
/// and later task records — this is not a security boundary, just a
/// refusal to accept an unreasonably long identifier for something meant
/// to be a short, stable name.
pub const MAX_STEP_ID_LEN: usize = 128;

/// Sanity bound on how many `needs:` entries one step may declare. Bounds
/// [`topological_order`]'s own work (`O(steps + total needs entries)`) to a
/// predictable multiple of the step count; not tied to, and making no claim
/// about, the open YAML-parse-cost finding recorded in the parent module's
/// doc comment — that finding is about `serde_yaml` parsing raw text, this
/// is about graph size after parsing has already succeeded.
pub const MAX_NEEDS_PER_STEP: usize = 64;

/// A step's resource caps (§8.9: `caps: { max_cost_usd, max_tool_calls }`).
/// A transfer out of the run's remaining budget (§8.9's `map`-item caps
/// note) — enforcing that transfer is the executor's job (Task 5), not
/// this parser's; this type only gives it a typed, fail-closed shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapsDef {
    #[serde(default)]
    pub max_cost_usd: Option<f64>,
    #[serde(default)]
    pub max_tool_calls: Option<u32>,
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

fn default_max_parallel() -> u32 {
    1
}

fn default_form() -> serde_json::Value {
    serde_json::json!({})
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

/// §8.9's `map: { over, as, max_parallel, on_item_error, isolation }` shape
/// (the sibling `steps:` list is a separate key on the step, not nested
/// under `map:` — see the fixture and [`StepDefWire`]). Private, same
/// reasoning as [`AgentBodyDef`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MapBodyDef {
    over: String,
    #[serde(rename = "as")]
    r#as: String,
    #[serde(default = "default_max_parallel")]
    max_parallel: u32,
    #[serde(default)]
    on_item_error: OnItemError,
    #[serde(default)]
    isolation: Option<serde_json::Value>,
}

/// §8.9's `gate: { title, form, timeout, on_timeout }` shape. `on_timeout`
/// reuses [`OnTimeout`] from [`super::types`] rather than inventing a
/// second copy of the same `deny | fail | default(value) | approve`
/// grammar — Task 2's own report flagged this exact reuse as the intended
/// hook for this task. Private, same reasoning as [`AgentBodyDef`].
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
    #[serde(default)]
    env: Option<serde_json::Value>,
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
        isolation: Option<serde_json::Value>,
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "StepDefWire", into = "StepDefWire")]
pub struct StepDef {
    pub id: String,
    pub when: Option<String>,
    pub needs: Vec<String>,
    pub continue_on_error: bool,
    pub idempotency_key: Option<String>,
    pub caps: Option<CapsDef>,
    pub env: Option<serde_json::Value>,
    pub body: StepBody,
}

impl TryFrom<StepDefWire> for StepDef {
    type Error = String;

    fn try_from(w: StepDefWire) -> Result<Self, Self::Error> {
        const KNOWN_KINDS: &str = "tool, agent, map, gate, call, emit, report";

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
                return Err(format!(
                    "a step body must have exactly one of: {KNOWN_KINDS} — found none"
                ));
            }
            1 => kinds[0],
            _ => {
                return Err(format!(
                    "a step body must have exactly one of: {KNOWN_KINDS} — found {}: {:?}",
                    kinds.len(),
                    kinds
                ));
            }
        };

        if w.with.is_some() && kind != "tool" && kind != "call" {
            return Err(format!(
                "`with` is only valid alongside `tool` or `call`, not alongside `{kind}` — found `with` with no `tool`/`call` on the same step"
            ));
        }
        if w.steps.is_some() && kind != "map" {
            return Err(format!(
                "`steps` is only valid alongside `map`, not alongside `{kind}` — found a sibling `steps:` list with no `map` on the same step"
            ));
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
                let steps = w
                    .steps
                    .ok_or_else(|| "a `map` step requires a sibling `steps:` list".to_string())?;
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

/// Step ids are untyped human-chosen text in the YAML, but flow into
/// provenance, logs, and (this crate's downstream tasks) task records — so,
/// unlike a free-form prompt string, this parser gives them a closed
/// charset and a length ceiling rather than accepting arbitrary text. Not a
/// claim that this prevents every possible downstream misuse of an id,
/// only that a step id can't itself smuggle control characters, path
/// separators, or unbounded length into whatever later reads it as a plain
/// identifier.
fn validate_step_id(id: &str) -> Result<(), ParseError> {
    if id.is_empty() {
        return Err(ParseError::InvalidStepId {
            id: id.to_string(),
            reason: "must not be empty".to_string(),
        });
    }
    if id.len() > MAX_STEP_ID_LEN {
        return Err(ParseError::InvalidStepId {
            id: id.to_string(),
            reason: format!("exceeds the {MAX_STEP_ID_LEN}-character limit"),
        });
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(ParseError::InvalidStepId {
            id: id.to_string(),
            reason: "must contain only ASCII letters, digits, `_`, or `-`".to_string(),
        });
    }
    Ok(())
}

/// Parses one step body (§8.9: `tool`/`agent`/`map`/`gate`/`call`/`emit`/
/// `report`) from a raw `serde_yaml::Value` — one entry of
/// `WorkflowDef.steps`/`.catch`/`.finally` (Task 2), or one entry of a
/// `map` step's own nested `steps:` list (the caller re-invokes this on
/// each nested entry itself; this function does not recurse into a `map`
/// step's `steps:` list on its own, and does not bound that nested list's
/// length — that is either the executor's concern (Task 5) or a future
/// recursive validation pass, not this function's).
pub fn parse_step(v: &serde_yaml::Value) -> Result<StepDef, ParseError> {
    let step: StepDef = serde_yaml::from_value(v.clone())?;
    validate_step_id(&step.id)?;
    if step.needs.len() > MAX_NEEDS_PER_STEP {
        return Err(ParseError::TooManyNeeds {
            step: step.id.clone(),
            actual: step.needs.len(),
            max: MAX_NEEDS_PER_STEP,
        });
    }
    Ok(step)
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
/// number of `needs:` edges per step ([`MAX_NEEDS_PER_STEP`], enforced by
/// [`parse_step`] before a `StepDef` ever reaches this function). Every
/// failure mode below is a typed [`ParseError`], never a panic or a hang:
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
