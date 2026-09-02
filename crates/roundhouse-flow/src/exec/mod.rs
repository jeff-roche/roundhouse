//! Step-graph executor core (Subsystem B, Task 13; §8.8): deterministic
//! sequencing over a parsed [`WorkflowDef`]'s `needs:` DAG, task-subtree
//! provenance for each step ([`provenance`]), and a real `${{ }}` expression
//! context bound from a run's `inputs`/`vars`/`secrets`/`run` (finding 8's
//! fix — an earlier version of this executor evaluated every expression
//! against an empty [`ExprContext`], so `${{ inputs.* }}` etc. silently
//! resolved to `Null` rather than erroring).
//!
//! Only `tool`/`agent`/`emit`/`report` step bodies are dispatched here.
//! `map`/`gate`/`call` are specialized handlers Tasks 6/7/11 build on top of
//! [`Executor::dispatch_step`], not duplicated sequencing logic.
//!
//! # Ruling P23 — establishing trust at the parse boundary: **rejected for this task**
//!
//! This module is the first code in the workspace to hold both a parsed
//! [`WorkflowDef`] and the `${{ }}` evaluator, so ruling P23 asks it to
//! decide, against real usage, whether [`crate::expr::TemplateSource`] /
//! [`crate::expr::ExpressionSource`] / [`crate::expr::JsonTemplateSource`]
//! should flow out of `parse::parse_workflow`'s own output types (so the
//! trust assertion happens once at the YAML boundary) rather than being
//! constructed inline at every `eval`/`interpolate`/`interpolate_json` call
//! site, as this module does below.
//!
//! **Decision: reject, for this task.** Full reasoning is in this task's
//! report (required deliverable per the brief); the short version: doing it
//! for real requires (a) making the three newtypes storable — owned,
//! `Clone`, with their own hand-written `Serialize`/`Deserialize` — which
//! trades away the "nothing can hold one" property that is exactly what
//! makes today's design meet P20's bar with *no more* than that bar, and
//! (b) changing `StepDef`/`StepBody`'s public field types in
//! `crate::parse::steps`, which are outside this task's stated file scope
//! and already carry two rounds of security fix history plus their own wire
//! (de)serialization round-trip guarantees (`StepDefWire`,
//! `PermissionRuleDefWire`) that a wrapped, non-`Deserialize`-derivable type
//! would have to be threaded through by hand. That is a cross-cutting
//! change to already-landed, multiply-reviewed parsing code, not a natural
//! extension of "step-graph executor core." Every call site below instead
//! constructs the newtype inline, directly from a [`StepDef`]/[`StepBody`]
//! field — i.e. from the workflow file's own parsed YAML — and never from
//! `RunContext`, `ExprContext`, a `steps.*` fold result, or any other
//! runtime-derived value. That preserves the exact trust boundary P20/P22
//! require; it just doesn't make the boundary unbypassable by construction
//! the way a typed `parse` output would.

pub mod provenance;
pub use provenance::{Provenance, RunId};

use crate::expr::{
    eval_delimited_expression, interpolate, interpolate_json, ExprContext, JsonTemplateSource,
    TemplateSource,
};
use crate::parse::steps::{parse_step, topological_order, StepBody, StepDef};
use crate::parse::{ParseError, WorkflowDef};
use roundhouse_core::{EventPayload, Origin, TaskId, TaskInput, TaskKind, TaskOutput, Usage};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;

/// Stands in for `roundhouse-engine`'s real task admission so this crate
/// stays testable without linking the full engine (this task's Interfaces).
pub trait TaskSink {
    fn emit(
        &mut self,
        task_id: TaskId,
        parent: Option<TaskId>,
        kind: TaskKind,
        payload: EventPayload,
    );
}

/// Finding 8's fix: everything the `${{ }}` context needs beyond `steps`
/// (which the executor threads through as it runs), gathered at run start.
/// `inputs` comes from the triggering payload/manual-trigger form, already
/// validated against the workflow's `inputs:` schema by the caller (Task
/// 2's `WorkflowDef.inputs`); `vars` is the workflow's own `vars:` block
/// (§8.9); `secrets` is resolved via `roundhouse-secrets`/
/// `roundhouse-config`'s `SecretRef` by the caller and handed here
/// already-resolved, since this crate has no secret store of its own — this
/// crate's obligation is solely to never let a resolved value reach the
/// persisted log unredacted ([`redact_known_secrets`], below). This is also
/// the one and only channel through which values that are not the workflow
/// file's own source text (webhook fields, `map.over` items, prior step
/// results, resolved secrets) are allowed to reach the evaluator — see
/// rulings P20/P22 and this module's own P23 note above.
#[derive(Clone)]
pub struct RunContext {
    pub inputs: Value,
    pub vars: Value,
    pub secrets: HashMap<String, String>,
    pub run_id: RunId,
}

impl fmt::Debug for RunContext {
    /// Hand-written (fix round 1, item 5) rather than derived — mirrors
    /// `crate::expr::ExprContext`'s own `Debug` impl, which exists for the
    /// identical reason: a derived `Debug` would print `secrets`' raw
    /// values (`{"GH_TOKEN": "sk-super-secret"}`), and `RunContext` is
    /// `pub`, `Clone`, and reachable from any caller's `tracing::debug!`,
    /// `dbg!`, or an `expect` on a `Result` that happens to embed one.
    /// Prints only the sorted list of secret *names* — never their values —
    /// alongside `inputs`/`vars` in full, since those are not secret-shaped
    /// by this crate's own contract (a caller handing a resolved secret in
    /// as `inputs`/`vars` rather than through `secrets` is a caller-side
    /// misuse this type cannot detect, the same limitation `ExprContext`'s
    /// own doc comment states for its "cannot tell a secret apart from any
    /// other value" caveat).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut secret_names: Vec<&str> = self.secrets.keys().map(String::as_str).collect();
        secret_names.sort_unstable();
        f.debug_struct("RunContext")
            .field("inputs", &self.inputs)
            .field("vars", &self.vars)
            .field("secrets", &secret_names)
            .field("run_id", &self.run_id)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum StepStatus {
    Completed,
    /// Carries a message (the plan's own illustrative code uses this shape
    /// in its `map`/`gate`/`call` catch-all arm even though the brief's
    /// terser Interfaces gloss lists a payload-free `Failed` — see this
    /// task's report, "Deviations from the plan text": a failure with no
    /// reason attached is not useful to anyone debugging a run).
    Failed {
        message: String,
    },
    Skipped {
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub struct StepOutcome {
    pub step_id: String,
    pub output: Value,
    pub status: StepStatus,
}

pub struct Executor<'a> {
    def: &'a WorkflowDef,
    run_id: RunId,
    sink: &'a mut dyn TaskSink,
    ctx: ExprContext,
    secrets: HashMap<String, String>,
}

impl<'a> Executor<'a> {
    pub fn new(def: &'a WorkflowDef, sink: &'a mut dyn TaskSink, run_ctx: RunContext) -> Self {
        // Fix round 1, item 9: `run_id` used to be a separate constructor
        // parameter, distinct from `run_ctx.run_id`, and nothing checked
        // the two agreed — `run_ctx.run_id` was silently ignored, so a
        // caller (every test included) could mint one `RunId` for the
        // context and pass a different one here, and whichever was passed
        // here is the one that ends up bound into `${{ run.id }}` and
        // reachable from `Provenance`. There is exactly one run identity;
        // take it from `run_ctx`, the value that already carries it.
        let run_id = run_ctx.run_id;
        let mut ctx = ExprContext::new();
        // Finding 8: bind everything the expression language needs besides
        // `steps` (set fresh on every iteration inside `run_to_completion`).
        ctx.set("inputs", run_ctx.inputs);
        ctx.set("vars", run_ctx.vars);
        ctx.set(
            "secrets",
            Value::Object(
                run_ctx
                    .secrets
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                    .collect(),
            ),
        );
        ctx.set("run", serde_json::json!({ "id": run_id.to_string() }));
        Executor {
            def,
            run_id,
            sink,
            ctx,
            secrets: run_ctx.secrets,
        }
    }

    /// Runs every top-level step to completion in dependency order (§8.8's
    /// "the graph is the deterministic skeleton"). `map`/`gate`/`call` steps
    /// are handled by Tasks 6/7/11 respectively via [`Self::dispatch_step`];
    /// this task implements sequencing plus the `tool`/`agent`/`emit`/
    /// `report` leaf dispatch.
    ///
    /// Stopping-on-failure, `catch:`/`finally:`, and retry are later tasks'
    /// concerns (`continue_on_error` is parsed onto every [`StepDef`]
    /// already, but nothing reads it here) — every step in topological
    /// order is attempted regardless of an earlier step's outcome.
    ///
    /// # Residual: dependents cannot reliably detect an upstream failure at all
    ///
    /// Fix round 1, item 11 (correcting the original report's Concerns
    /// section, which understated this): because every step runs regardless
    /// of an earlier step's outcome, and because a missing field resolves
    /// to `Null` rather than erroring (see `crate::expr::index_field`), a
    /// dependent reading `${{ steps.<failed>.output.sha }}` after an
    /// upstream failure gets the literal string `"null"` substituted in,
    /// not an error — e.g. `{"cmd":["git","checkout","null"]}`. This is
    /// **not attacker-controlled** (no path lets an attacker choose the
    /// substituted value), but it is a real correctness gap: today, nothing
    /// in this crate stops a dependent from acting on a degenerate `null`
    /// argument, and `steps.<id>.status` (fixed in this same round, item 3,
    /// to a stable `"completed"`/`"failed"`/`"skipped"` string) is the
    /// *only* signal a workflow author has to guard against it — there is
    /// no `catch:`/stop-on-failure mechanism yet. **Owner: Task 8**
    /// (durability layer), which is where stop-on-failure and `catch:`
    /// handling land.
    pub fn run_to_completion(&mut self) -> Result<Vec<StepOutcome>, ParseError> {
        // Fix round 1, item 2: this used to be
        // `.expect("workflow YAML validated at parse time")`, twice — a
        // false premise. `parse_workflow` validates size/nesting/counts and
        // `validate_unattended` only; it never builds or checks the step
        // graph (`WorkflowDef.steps` stays `Vec<serde_yaml::Value>`), so a
        // cycle, an unknown `needs:` dependency, a duplicate step id, or a
        // step with zero or multiple body kinds all parsed successfully and
        // then panicked here, with the panic message echoing step ids into
        // the abort output. Workflow YAML is untrusted input
        // (`parse/mod.rs`'s own module doc), so this is now a run-level
        // `Err`, not a panic.
        let step_defs: Vec<StepDef> = self
            .def
            .steps
            .iter()
            .map(parse_step)
            .collect::<Result<_, _>>()?;
        let order = topological_order(&step_defs)?;
        let mut outcomes = Vec::with_capacity(step_defs.len());
        let mut steps_context = serde_json::Map::new();

        for idx in order {
            let step = &step_defs[idx];
            self.ctx.set("steps", Value::Object(steps_context.clone()));

            if let Some(when) = &step.when {
                // Fail-closed deviation from the plan's illustrative
                // `unwrap_or(true)` — see this task's report, "Deviations
                // from the plan text": a `when:` that fails to *evaluate*
                // (bad syntax, unknown function) is not the same thing as a
                // `when:` that evaluates to `false`, and running the step
                // anyway on evaluation failure is the wrong default for a
                // codebase whose stated posture elsewhere is "fail closed."
                //
                // Fix round 1, item 4: `when:` is documented (§8.9) as
                // always being a single `${{ ... }}`-delimited block — both
                // reference examples use that form, neither uses a bare
                // one — so this now goes through
                // `eval_delimited_expression`, not the bare `eval`. The
                // earlier version passed `when`'s still-delimited text
                // straight to `eval`, which takes an undelimited
                // `ExpressionSource`, so every documented-form `when:` died
                // at position 0 on the leading `$` and only an undocumented
                // bare form worked.
                match eval_delimited_expression(TemplateSource::from_workflow_file(when), &self.ctx)
                {
                    Ok(cond) => {
                        if !matches!(cond, Value::Bool(true)) {
                            let outcome = StepOutcome {
                                step_id: step.id.clone(),
                                output: Value::Null,
                                status: StepStatus::Skipped {
                                    reason: "when: evaluated false".into(),
                                },
                            };
                            steps_context.insert(step.id.clone(), steps_context_entry(&outcome));
                            outcomes.push(outcome);
                            continue;
                        }
                    }
                    Err(e) => {
                        let outcome = StepOutcome {
                            step_id: step.id.clone(),
                            output: Value::Null,
                            status: StepStatus::Failed {
                                message: format!("evaluating `when:`: {e}"),
                            },
                        };
                        steps_context.insert(step.id.clone(), steps_context_entry(&outcome));
                        outcomes.push(outcome);
                        continue;
                    }
                }
            }

            let outcome = self.dispatch_step(step);
            steps_context.insert(step.id.clone(), steps_context_entry(&outcome));
            outcomes.push(outcome);
        }
        Ok(outcomes)
    }

    fn dispatch_step(&mut self, step: &StepDef) -> StepOutcome {
        // Computed for every dispatch (matching this task's Interfaces
        // list) but not yet attached to anything persisted — see
        // `provenance::Provenance`'s own doc comment for why.
        let provenance = Provenance {
            run_id: self.run_id,
            step_id: step.id.clone(),
            attempt: 1,
            item_index: None,
        };
        let _ = &provenance;

        let task_id = TaskId::new();
        match &step.body {
            StepBody::Tool { tool, with } => {
                // Finding 8: interpolate the whole `with:` block for real —
                // an earlier version passed the raw, uninterpolated YAML
                // value straight through, so `${{ inputs.* }}` never
                // resolved. `with` is a `&serde_json::Value` sourced
                // directly from this step's own parsed YAML body (never
                // from `RunContext`/`ExprContext`/a prior step's output),
                // so constructing `JsonTemplateSource` from it here is
                // exactly the P20/P22-sanctioned use.
                let resolved_with =
                    match interpolate_json(JsonTemplateSource::from_workflow_file(with), &self.ctx)
                    {
                        Ok(v) => v,
                        Err(e) => {
                            return StepOutcome {
                                step_id: step.id.clone(),
                                output: Value::Null,
                                status: StepStatus::Failed {
                                    message: format!("interpolating `with:`: {e}"),
                                },
                            };
                        }
                    };
                let logged_with = redact_known_secrets(&resolved_with, &self.secrets);
                let kind = task_kind_for_tool(tool);
                self.sink.emit(
                    task_id,
                    None,
                    kind.clone(),
                    EventPayload::TaskCreated {
                        kind,
                        parent: None,
                        origin: Origin::System,
                        input: TaskInput::Json(logged_with),
                    },
                );
                // Real dispatch delegates the (unredacted) `resolved_with`
                // to `roundhouse-tools` via `roundhouse-engine`; this
                // executor's job ends at emitting the task and folding its
                // eventual `TaskCompleted` back into `steps.<id>.output` —
                // wired in Task 8's durability layer, which owns the actual
                // run loop.
                StepOutcome {
                    step_id: step.id.clone(),
                    output: serde_json::json!({}),
                    status: StepStatus::Completed,
                }
            }
            StepBody::Agent { prompt, .. } => {
                let resolved_prompt =
                    match interpolate(TemplateSource::from_workflow_file(prompt), &self.ctx) {
                        Ok(s) => s,
                        Err(e) => {
                            return StepOutcome {
                                step_id: step.id.clone(),
                                output: Value::Null,
                                status: StepStatus::Failed {
                                    message: format!("interpolating `agent.prompt`: {e}"),
                                },
                            };
                        }
                    };
                let logged_prompt = redact_known_secrets(
                    &serde_json::json!({"prompt": resolved_prompt}),
                    &self.secrets,
                );
                self.sink.emit(
                    task_id,
                    None,
                    TaskKind::Agent,
                    EventPayload::TaskCreated {
                        kind: TaskKind::Agent,
                        parent: None,
                        origin: Origin::System,
                        input: TaskInput::Json(logged_prompt),
                    },
                );
                StepOutcome {
                    step_id: step.id.clone(),
                    output: serde_json::json!({}),
                    status: StepStatus::Completed,
                }
            }
            StepBody::Emit { emit } => {
                // Finding 2 fix: previously this arm only built an
                // in-memory `StepOutcome` and returned, so `emit:` never
                // left any trace in the task log. An `emit:` step has no
                // dedicated `TaskKind` (§4.2's frozen table has no
                // "notify"/"emit" kind), so it is persisted as a
                // `TaskKind::Flow` task — this crate's general
                // workflow-bookkeeping kind, alongside `checkpoint`/
                // `compact`.
                let resolved =
                    match interpolate_json(JsonTemplateSource::from_workflow_file(emit), &self.ctx)
                    {
                        Ok(v) => v,
                        Err(e) => {
                            return StepOutcome {
                                step_id: step.id.clone(),
                                output: Value::Null,
                                status: StepStatus::Failed {
                                    message: format!("interpolating `emit:`: {e}"),
                                },
                            };
                        }
                    };
                // Fix round 1, item 1 (CRITICAL): this arm used to pass
                // `resolved` straight into both `TaskInput::Json` and
                // `TaskOutput::Json` — unlike the `Tool`/`Agent` arms above,
                // which already split `resolved_with`/`logged_with` and
                // `resolved_prompt`/`logged_prompt`. A `${{ secrets.* }}`
                // reference in `emit:` reached the append-only log in
                // cleartext, and because the `events` table physically
                // rejects UPDATE/DELETE, that is unrecoverable — remediation
                // is credential rotation, not deletion. `logged` is what
                // reaches the sink; the unredacted `resolved` is kept only
                // for `StepOutcome.output`, mirroring the Tool/Agent split.
                let logged = redact_known_secrets(&resolved, &self.secrets);
                self.sink.emit(
                    task_id,
                    None,
                    TaskKind::Flow,
                    EventPayload::TaskCreated {
                        kind: TaskKind::Flow,
                        parent: None,
                        origin: Origin::System,
                        input: TaskInput::Json(logged.clone()),
                    },
                );
                self.sink.emit(
                    task_id,
                    None,
                    TaskKind::Flow,
                    EventPayload::TaskCompleted {
                        output: TaskOutput::Json(logged),
                        usage: Usage::default(),
                    },
                );
                StepOutcome {
                    step_id: step.id.clone(),
                    output: resolved,
                    status: StepStatus::Completed,
                }
            }
            StepBody::Report { report } => {
                // Finding 2 fix (the audit's headline example): the
                // mandatory report is now actually persisted through the
                // sink as a real `TaskKind::Report` task, carrying the
                // report JSON as its completed output — this is what makes
                // the Runs inbox/fingerprint diffing (Task 10) have
                // something to load back. Task 10 additionally wraps this
                // exact call site with a report validator so a malformed
                // report step fails loudly at run time rather than
                // persisting garbage; that validator does not exist yet in
                // this crate, so it is not called here.
                let resolved = match interpolate_json(
                    JsonTemplateSource::from_workflow_file(report),
                    &self.ctx,
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return StepOutcome {
                            step_id: step.id.clone(),
                            output: Value::Null,
                            status: StepStatus::Failed {
                                message: format!("interpolating `report:`: {e}"),
                            },
                        };
                    }
                };
                // Fix round 1, item 1 (CRITICAL): same defect as `Emit`
                // above, and worse in blast radius — `report:` is §8.8's
                // *mandatory* per-run block, so an unredacted
                // `${{ secrets.* }}` reference here was on every run's
                // path, not just an author's optional notification block.
                let logged = redact_known_secrets(&resolved, &self.secrets);
                self.sink.emit(
                    task_id,
                    None,
                    TaskKind::Report,
                    EventPayload::TaskCreated {
                        kind: TaskKind::Report,
                        parent: None,
                        origin: Origin::System,
                        input: TaskInput::Json(logged.clone()),
                    },
                );
                self.sink.emit(
                    task_id,
                    None,
                    TaskKind::Report,
                    EventPayload::TaskCompleted {
                        output: TaskOutput::Json(logged),
                        usage: Usage::default(),
                    },
                );
                StepOutcome {
                    step_id: step.id.clone(),
                    output: resolved,
                    status: StepStatus::Completed,
                }
            }
            // Map/Gate/Call are dispatched by the specialized handlers added
            // in Tasks 6/7/11, which wrap this same `dispatch_step` for
            // their inner/leaf steps rather than duplicating sequencing
            // logic.
            other => StepOutcome {
                step_id: step.id.clone(),
                output: Value::Null,
                status: StepStatus::Failed {
                    // Fix round 1, item 8: this used to be
                    // `format!("step kind {other:?} handled by a later
                    // task")` — a full `{:?}` dump of the step body,
                    // flowing through `steps_context_entry` into the
                    // immutable log. The text is uninterpolated workflow
                    // source, so no *resolved* secret escapes, but a
                    // literal credential typed directly into a
                    // `map`/`gate`/`call` body (e.g. `gate.form`,
                    // `call.with`) would reach the log verbatim. Name only
                    // the variant, never its contents.
                    message: format!(
                        "step kind `{}` handled by a later task",
                        step_body_kind_name(other)
                    ),
                },
            },
        }
    }
}

fn task_kind_for_tool(tool: &str) -> TaskKind {
    match tool {
        "shell" => TaskKind::Shell,
        "http" => TaskKind::Http,
        "read" => TaskKind::Read,
        "write" => TaskKind::Write,
        "edit" => TaskKind::Edit,
        "find" => TaskKind::Find,
        "git" => TaskKind::Git,
        _ => TaskKind::Shell,
    }
}

/// Names a [`StepBody`] variant without dumping its contents — see the
/// catch-all arm of [`Executor::dispatch_step`] for why (fix round 1, item
/// 8). `Tool`/`Agent`/`Emit`/`Report` are dispatched above and never reach
/// this function; it exists for the `Map`/`Gate`/`Call` catch-all.
fn step_body_kind_name(body: &StepBody) -> &'static str {
    match body {
        StepBody::Tool { .. } => "tool",
        StepBody::Agent { .. } => "agent",
        StepBody::Map { .. } => "map",
        StepBody::Gate { .. } => "gate",
        StepBody::Call { .. } => "call",
        StepBody::Emit { .. } => "emit",
        StepBody::Report { .. } => "report",
    }
}

/// Builds the `steps.<id>` entry folded into [`ExprContext`]'s `steps` root
/// on every iteration of [`Executor::run_to_completion`]'s loop.
///
/// Fix round 1, item 3: this used to be built ad hoc at three separate call
/// sites, and each wrote a different, incompatible shape for `status`: the
/// `when:`-false path wrote the lowercase string `"skipped"`; the
/// `when:`-evaluation-error path hard-coded the lowercase string `"failed"`
/// with no message attached; the general dispatch-failure path wrote
/// `format!("{:?}", outcome.status)`, i.e. the Rust-`Debug` string
/// `Failed { message: "..." }`. A dependent's own `when: "${{
/// steps.a.status != 'failed' }}"` — the one gating mechanism this crate
/// implements, and the only failure-signal a workflow author has today (no
/// `catch:`/stop-on-failure exists yet) — matches the second shape and
/// silently fails to match the third, so a dependent could run *after* an
/// upstream dispatch failure while a workflow author's own
/// correctly-written guard says it shouldn't. This function is the fix: a
/// single call site, used by all three paths, writing a stable lowercase
/// discriminant (`"completed"`/`"failed"`/`"skipped"`) with any message or
/// reason carried in a sibling `error` field, never folded into `status`
/// itself.
fn steps_context_entry(outcome: &StepOutcome) -> Value {
    let (status, error) = match &outcome.status {
        StepStatus::Completed => ("completed", None),
        StepStatus::Failed { message } => ("failed", Some(message.as_str())),
        StepStatus::Skipped { reason } => ("skipped", Some(reason.as_str())),
    };
    serde_json::json!({
        "output": outcome.output,
        "status": status,
        "error": error,
    })
}

/// §6.7's redaction obligation, applied at the one seam this crate owns: a
/// step's resolved `with:`/`prompt` is what gets logged via [`TaskSink`],
/// and a resolved secret value must never appear in it verbatim. Walks the
/// whole JSON value (not just top-level strings) replacing any occurrence
/// of a known secret's literal value with `"***"`. This does not replace
/// Phase 2's general secret-scanning/redaction (which catches values this
/// crate never knew were secrets); it specifically guarantees that a value
/// this crate itself resolved via `${{ secrets.* }}` cannot leak through
/// this crate's own emit call site.
///
/// **This is not complete redaction, and must not be read as such.**
/// `${{ env(...) }}` (§8.9's own required function) reads the real process
/// environment via [`std::env::var`], entirely unscoped from any workflow
/// `secrets:` declaration and unscoped from this run's own
/// [`RunContext::secrets`] map — see `crate::expr`'s module doc comment,
/// "`env()` is a second, independent secret-exposure surface." A value
/// obtained through `env()` (for example `${{ env('ANTHROPIC_API_KEY') }}`)
/// is not a key of `secrets`, so this function has no way to recognise it
/// and will not redact it. This gap is escalated, not closed, by `crate::expr`;
/// this function closes exactly the narrower gap it documents (a
/// `secrets.*`-sourced value leaking through this crate's own log call
/// site) and no more.
///
/// # What this function does and does not catch — self-contained (fix round 1, item 7)
///
/// This list is stated here, not left to a caller who happens to route
/// through [`interpolate_json`] first, per fix round 1's own instruction
/// that this function's contract must be self-contained:
///
/// - **A secret used as an object key is never redacted.** This function
///   walks object *values* recursively; keys are copied verbatim
///   (`k.clone()` below). Unreachable through this crate's own pipeline
///   today — [`interpolate_json_inner`] only interpolates values, never
///   keys, so a secret cannot become a key via the one path that reaches
///   this function — but that is a property of today's *callers*, not of
///   this function itself, and becomes live the moment a later task merges
///   a step output (which could carry attacker- or author-chosen keys)
///   into an emitted payload.
/// - **A secret is only ever matched inside a `Value::String` leaf.** A
///   secret whose value happens to look numeric, and which ends up
///   embedded in a `Value::Number` leaf elsewhere in the payload (not
///   reachable via this crate's own string-interpolation pipeline today,
///   but not prevented by this function either), is never scanned.
/// - **Very short secret values over-redact.** A 1-2 character "secret"
///   matches arbitrary, unrelated substrings of ordinary text — measured
///   directly: a secret of `"a"` turns `/path/to/data` into
///   `/p***th/to/d***t***`, corrupting the payload rather than protecting
///   anything. [`MIN_REDACTABLE_SECRET_LEN`] guards against this: a secret
///   value (or a JSON-leaf value extracted from one, see below) shorter
///   than that bound is never used as a redaction needle. This is a
///   heuristic that trades away redacting implausibly short "secrets" (no
///   realistic credential is one or two characters) to avoid corrupting
///   payloads with unrelated text; it is not a security bound and must not
///   be read as one.
///
/// # A JSON-valued secret is redacted leaf-by-leaf, not only whole-value (fix round 1, item 6, ruling P27)
///
/// Filed Minor by the reviewer; the orchestrator's ruling P27 upgraded it to
/// Important and required either a fix or a named, costed limitation. **This
/// is the fix**, not a named limitation: a JSON-shaped secret (a GCP
/// service-account key, an AWS credential blob, a kubeconfig — ordinary
/// shapes, not exotic ones) used to be redacted only when the *whole*
/// secret string appeared verbatim in a resolved value. `${{
/// json(secrets.GCP_KEY).private_key }}` extracts one field, which is not
/// equal to the whole secret string, so it slipped past the scan entirely —
/// measured directly: `{"cmd":["auth","-----BEGIN PRIVATE
/// KEY-----AAAABBBB-----END PRIVATE KEY-----"]}` reached the log in
/// cleartext through the `Tool` arm, the one arm that *is* redacted. The fix
/// expands the set of strings this function scans for: for every secret
/// value that itself parses as JSON, every string leaf of that parsed value
/// (recursively, subject to the same [`MIN_REDACTABLE_SECRET_LEN`] guard
/// above) is added alongside the secret's own whole-string value. This still
/// does not catch a non-string JSON leaf of a JSON-valued secret (a numeric
/// or boolean field), for the same reason a numeric top-level secret isn't
/// caught — that is the second bullet above, extended to apply within a
/// JSON-valued secret's own structure as well as to `secrets` itself.
///
/// The cost of this fix: one `serde_json::from_str` attempt per secret per
/// call (cheap — most secrets are not JSON and fail parsing immediately),
/// plus a recursive walk of the parsed structure for the ones that are.
/// Bounded by the size of the secret values themselves, which this crate
/// does not control the size of but which are not attacker-influenced
/// (`RunContext.secrets` is resolved by the caller before this crate ever
/// sees it) — not measured, since nothing in this diff constructs a secret
/// large enough for the cost to be observable, and no claim beyond "cheap in
/// the common case" is made.
pub fn redact_known_secrets(value: &Value, secrets: &HashMap<String, String>) -> Value {
    let needles = redaction_needles(secrets);
    redact_with_needles(value, &needles)
}

/// A secret value (or a JSON-leaf extracted from one) shorter than this is
/// never used as a redaction needle — see [`redact_known_secrets`]'s "What
/// this function does and does not catch" section for why. Chosen as a
/// round number comfortably below any realistic credential length and
/// comfortably above the lengths (1-2 characters) measured to cause
/// over-redaction; not derived from any formal analysis.
const MIN_REDACTABLE_SECRET_LEN: usize = 8;

/// Builds the flat list of strings [`redact_with_needles`] scans for: each
/// secret's own whole-string value, plus — fix round 1, item 6 — every
/// string leaf of that value when it happens to parse as JSON. Both are
/// filtered through [`MIN_REDACTABLE_SECRET_LEN`].
fn redaction_needles(secrets: &HashMap<String, String>) -> Vec<String> {
    let mut needles = Vec::new();
    for raw in secrets.values() {
        if raw.len() >= MIN_REDACTABLE_SECRET_LEN {
            needles.push(raw.clone());
        }
        if let Ok(parsed) = serde_json::from_str::<Value>(raw) {
            collect_string_leaves(&parsed, &mut needles);
        }
    }
    needles
}

/// Recursively collects every `Value::String` leaf of `value` (that meets
/// [`MIN_REDACTABLE_SECRET_LEN`]) into `out`. Used only to expand a
/// JSON-valued secret into its component strings — see
/// [`redaction_needles`].
fn collect_string_leaves(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) if s.len() >= MIN_REDACTABLE_SECRET_LEN => out.push(s.clone()),
        Value::Array(items) => {
            for item in items {
                collect_string_leaves(item, out);
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                collect_string_leaves(v, out);
            }
        }
        _ => {}
    }
}

/// The actual recursive redaction walk, over a pre-built flat `needles`
/// list rather than the raw `secrets` map — see [`redact_known_secrets`]
/// and [`redaction_needles`]. Object keys are never redacted (see
/// [`redact_known_secrets`]'s doc comment); only `Value::String` leaves are
/// scanned.
fn redact_with_needles(value: &Value, needles: &[String]) -> Value {
    match value {
        Value::String(s) => {
            let mut redacted = s.clone();
            for needle in needles {
                redacted = redacted.replace(needle.as_str(), "***");
            }
            Value::String(redacted)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|v| redact_with_needles(v, needles))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), redact_with_needles(v, needles)))
                .collect(),
        ),
        other => other.clone(),
    }
}
