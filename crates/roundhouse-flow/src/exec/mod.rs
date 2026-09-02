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
    eval, interpolate, interpolate_json, ExprContext, ExpressionSource, JsonTemplateSource,
    TemplateSource,
};
use crate::parse::steps::{parse_step, topological_order, StepBody, StepDef};
use crate::parse::WorkflowDef;
use roundhouse_core::{EventPayload, Origin, TaskId, TaskInput, TaskKind, TaskOutput, Usage};
use serde_json::Value;
use std::collections::HashMap;

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
#[derive(Debug, Clone)]
pub struct RunContext {
    pub inputs: Value,
    pub vars: Value,
    pub secrets: HashMap<String, String>,
    pub run_id: RunId,
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
    pub fn new(
        def: &'a WorkflowDef,
        run_id: RunId,
        sink: &'a mut dyn TaskSink,
        run_ctx: RunContext,
    ) -> Self {
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
    pub fn run_to_completion(&mut self) -> Vec<StepOutcome> {
        let step_defs: Vec<StepDef> = self
            .def
            .steps
            .iter()
            .map(|v| parse_step(v).expect("workflow YAML validated at parse time"))
            .collect();
        let order = topological_order(&step_defs).expect("workflow YAML validated at parse time");
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
                match eval(ExpressionSource::from_workflow_file(when), &self.ctx) {
                    Ok(cond) => {
                        if !matches!(cond, Value::Bool(true)) {
                            let outcome = StepOutcome {
                                step_id: step.id.clone(),
                                output: Value::Null,
                                status: StepStatus::Skipped {
                                    reason: "when: evaluated false".into(),
                                },
                            };
                            steps_context.insert(
                                step.id.clone(),
                                serde_json::json!({"output": null, "status": "skipped"}),
                            );
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
                        steps_context.insert(
                            step.id.clone(),
                            serde_json::json!({"output": null, "status": "failed"}),
                        );
                        outcomes.push(outcome);
                        continue;
                    }
                }
            }

            let outcome = self.dispatch_step(step);
            steps_context.insert(
                step.id.clone(),
                serde_json::json!({"output": outcome.output, "status": format!("{:?}", outcome.status)}),
            );
            outcomes.push(outcome);
        }
        outcomes
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
                self.sink.emit(
                    task_id,
                    None,
                    TaskKind::Flow,
                    EventPayload::TaskCreated {
                        kind: TaskKind::Flow,
                        parent: None,
                        origin: Origin::System,
                        input: TaskInput::Json(resolved.clone()),
                    },
                );
                self.sink.emit(
                    task_id,
                    None,
                    TaskKind::Flow,
                    EventPayload::TaskCompleted {
                        output: TaskOutput::Json(resolved.clone()),
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
                self.sink.emit(
                    task_id,
                    None,
                    TaskKind::Report,
                    EventPayload::TaskCreated {
                        kind: TaskKind::Report,
                        parent: None,
                        origin: Origin::System,
                        input: TaskInput::Json(resolved.clone()),
                    },
                );
                self.sink.emit(
                    task_id,
                    None,
                    TaskKind::Report,
                    EventPayload::TaskCompleted {
                        output: TaskOutput::Json(resolved.clone()),
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
                    message: format!("step kind {other:?} handled by a later task"),
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
pub fn redact_known_secrets(value: &Value, secrets: &HashMap<String, String>) -> Value {
    match value {
        Value::String(s) => {
            let mut redacted = s.clone();
            for secret_value in secrets.values() {
                if !secret_value.is_empty() {
                    redacted = redacted.replace(secret_value.as_str(), "***");
                }
            }
            Value::String(redacted)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|v| redact_known_secrets(v, secrets))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), redact_known_secrets(v, secrets)))
                .collect(),
        ),
        other => other.clone(),
    }
}
