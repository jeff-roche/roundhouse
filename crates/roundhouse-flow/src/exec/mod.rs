//! Step-graph executor core (Subsystem B, Task 13; §8.8): deterministic
//! sequencing over a parsed [`WorkflowDef`]'s `needs:` DAG, task-subtree
//! provenance for each step ([`provenance`]), and a real `${{ }}` expression
//! context bound from a run's `inputs`/`vars`/`secrets`/`run` (finding 8's
//! fix — an earlier version of this executor evaluated every expression
//! against an empty [`ExprContext`], so `${{ inputs.* }}` etc. silently
//! resolved to `Null` rather than erroring).
//!
//! `tool`/`agent`/`emit`/`report`/`map` step bodies are dispatched here (`map`
//! via [`Executor::dispatch_map_step`], defined in [`map_step`], Task
//! 14/B6). **`gate`/`call` are not**: they belong to [`run_loop`] (B12c),
//! which intercepts both before reaching [`Executor::dispatch_step`], because
//! a park is a durable transition plus a checkpoint and a `call:` creates a
//! child run — and this type deliberately holds no
//! [`rusqlite::Connection`](https://docs.rs/rusqlite). `dispatch_step`'s arm
//! for the two is a refusal naming that, and it is reachable only from a
//! caller with no run behind it: the in-memory
//! [`Executor::run_to_completion`], or a `gate:`/`call:` nested inside a
//! `map`.
//!
//! The attribution here used to read "Tasks 7/11", was corrected by Task 19
//! (B11) under ruling P75 §A to "Task 20 (B12)", and is now the module that
//! actually does it. Tasks 7 and 11 landed the *primitives* —
//! [`crate::parking`] (Task 17/B9) for the `gate` park, and
//! [`crate::compose`] (Task 19/B11) for the `call:` budget transfer,
//! recursion bound and workflow-as-tool shape — and deliberately left both
//! arms stubbed, because a run loop is what actually dispatches them.
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

pub mod map_step;
pub mod provenance;
pub mod run_loop;
pub use provenance::{Provenance, RunId};

/// The result of evaluating one step's `when:` gate (Task 14 fix round 2,
/// item 1) — either the caller is cleared to dispatch the step for real (with
/// whether the *condition itself* read secret material, to fold into the
/// step's eventual [`StepOutcome`]), or the gate has already fully decided
/// the step's outcome (`Skipped` when the condition evaluated to anything
/// other than `Bool(true)`, `Failed` when it failed to evaluate at all) and
/// the step must **not** be dispatched.
pub(crate) enum GateDecision {
    Proceed {
        gate_condition_was_secret_derived: bool,
    },
    Decided(StepOutcome),
}

/// Evaluates `step.when` (if present) against `ctx`, with the identical
/// `Ok(non-true) -> Skipped` / `Err -> Failed (fail-closed)` split for every
/// caller — see [`GateDecision`]. A step with no `when:` at all always
/// [`GateDecision::Proceed`]s, with the flag `false` (no condition was
/// evaluated).
///
/// # Why this is a shared helper, not inlined at each dispatch site (fix round 2, item 1)
///
/// Before this existed, `when:` handling lived only in
/// [`Executor::run_to_completion`]'s own loop — the **only** site in the
/// crate that read `step.when` at all. [`Executor::dispatch_step`] never
/// consulted it, and neither did [`map_step::Executor::dispatch_map_step`],
/// which calls `dispatch_step` directly for each inner step. The
/// consequence, measured end to end with `inputs.approved = false`: a
/// `tool: shell` step with `cmd: ["rm","-rf","/"]` guarded by
/// `when: "${{ inputs.approved }}"` is correctly `Skipped` at top level and
/// **dispatched** when the identical step is nested one level under a `map`
/// — the guard evaporates, once per item. Worse: the same nesting also loses
/// this crate's fail-closed posture for a gate that *fails to evaluate* (an
/// unknown-function reference, say) — at top level that is `Failed` and the
/// step never runs; nested under a `map`, it dispatched too, because nothing
/// there evaluated `when:` at all to produce either outcome.
///
/// A **second**, independently written copy of the `Ok`/`Err` split inside
/// `dispatch_map_step` would have "fixed" the measured case while leaving
/// the crate with two implementations of the same decision that can drift
/// again the next time either one changes — which is exactly how this defect
/// was created in the first place (`dispatch_map_step` was written without
/// ever duplicating — or therefore ever including — `run_to_completion`'s
/// gate logic). One function, called from both
/// [`Executor::run_to_completion`] and
/// [`map_step::Executor::dispatch_map_step`], is what makes that class of
/// divergence structurally impossible rather than merely fixed today.
pub(crate) fn evaluate_when_gate(step: &StepDef, ctx: &ExprContext) -> GateDecision {
    let Some(when) = &step.when else {
        return GateDecision::Proceed {
            gate_condition_was_secret_derived: false,
        };
    };
    // Fail-closed deviation from the plan's illustrative `unwrap_or(true)` —
    // see Task 13's report, "Deviations from the plan text": a `when:` that
    // fails to *evaluate* (bad syntax, unknown function) is not the same
    // thing as a `when:` that evaluates to `false`, and running the step
    // anyway on evaluation failure is the wrong default for a codebase whose
    // stated posture elsewhere is "fail closed."
    //
    // Fix round 1, item 4: `when:` is documented (§8.9) as always being a
    // single `${{ ... }}`-delimited block — both reference examples use that
    // form, neither uses a bare one — so this goes through
    // `eval_delimited_expression`, not the bare `eval`. An earlier version
    // passed `when`'s still-delimited text straight to `eval`, which takes an
    // undelimited `ExpressionSource`, so every documented-form `when:` died
    // at position 0 on the leading `$` and only an undocumented bare form
    // worked.
    match eval_delimited_expression(TemplateSource::from_workflow_file(when), ctx) {
        Ok(cond) => {
            // The condition's own *value* cannot reach the log through this
            // branch: all a `Decided(Skipped)` outcome writes into
            // `steps.<id>` is a fixed `"skipped"`/`"completed"` discriminant
            // and a fixed reason string.
            //
            // **That premise is true and the conclusion drawn from it used to
            // be false (fix round 4, item C).** An earlier version of this
            // comment concluded "so no secret material can reach the log" —
            // but *which* of the two fixed strings gets written is a one-bit
            // function of the condition, and the condition may be
            // `${{ secrets.T == 'a' }}`.
            //
            // Executed, and asserted by
            // `the_when_gates_branch_taken_is_a_one_bit_function_of_the_secret_and_is_observable`:
            // two runs of one gated step, against secrets differing only in
            // their first byte, produce (`completed`, 2 events) and
            // (`skipped`, 0 events) — so the bit is readable from the event
            // count alone, with no reader step at all. The fix-round-3
            // security lens measured the multi-bit extension of the same
            // shape (eight gate steps against `T = "abXdeXghXXXXXXXX"`
            // recording that secret's exact character-presence pattern); that
            // figure is theirs, reproduced here only at one bit.
            //
            // The per-run ceiling is arithmetic, not a measurement:
            // `crate::parse::MAX_TOP_LEVEL_STEPS` is 500, so a run admits at
            // most 500 such *top-level* steps and therefore at most ~500 bits
            // (~62 bytes) through this route alone, into a table that
            // physically rejects `UPDATE`/`DELETE`. **Reachability of this
            // function is now shared with `map`** (fix round 2): a `map`
            // inner step's own `when:` gate is evaluated through this exact
            // function too, at up to `MAX_MAP_ITEMS` (2,000) inner-step
            // evaluations per `map` step *call* — a larger per-call ceiling
            // than the top-level one, and per ruling P47 not bounded at all
            // across nesting levels — so the arithmetic bound stated above
            // does not hold for `map`-reached call sites.
            //
            // **What the two call sites do with the result differs, though
            // (fix round 3, item 1/2 — corrected from an earlier, broader
            // claim this comment made).** `Executor::run_to_completion` keeps
            // this function's per-step `gate_condition_was_secret_derived` as
            // a per-step record (see its own use of the flag below).
            // `map_step::Executor::dispatch_map_step` does not: it folds
            // *every* inner step's flag, across *every* item, into ONE
            // aggregate boolean on the map's own `output_is_secret_derived`
            // — see that function's own doc comment, "An inner step's own
            // `gate_condition_was_secret_derived` was discarded", for why. So
            // the one-bit-per-gate accounting this comment describes is not
            // extended to `map`'s inner steps as individually observable
            // bits by this round's fix — only collapsed to one bit for the
            // whole `map` step, which is a *smaller*, not larger, channel per
            // step than the arithmetic bound above assumes. Nothing was
            // measured at either size for this specific one-bit channel.
            //
            // **Accepted, not closed.** The only actor who can build this
            // channel is the workflow author, who already has a designed
            // full-bandwidth one: the unredacted half of every interpolation
            // is handed to real dispatch, so `tool: shell` with
            // `${{ secrets.T }}` delivers the plaintext by design. A covert
            // side channel, even a larger one under `map`, is not worth
            // paying for against an actor holding an overt unlimited one.
            //
            // **The condition that upgrades this.** If §8.5's per-step
            // `permissions:` narrowing is ever meant to make an author *less*
            // privileged than the secrets they may reference, this becomes
            // the surviving channel and stops being Minor. This module
            // consults `permissions:` nowhere today, so that does not hold
            // yet; whoever wires it must revisit this branch.
            //
            // What is recorded instead of acted on: the flag, so the next
            // task decides with a read rather than a re-derivation.
            let gate_condition_was_secret_derived = cond.secret_derived();
            if matches!(cond.value(), Value::Bool(true)) {
                GateDecision::Proceed {
                    gate_condition_was_secret_derived,
                }
            } else {
                GateDecision::Decided(StepOutcome {
                    step_id: step.id.clone(),
                    output: Value::Null,
                    status: StepStatus::Skipped {
                        reason: "when: evaluated false".into(),
                    },
                    output_is_secret_derived: false,
                    gate_condition_was_secret_derived,
                })
            }
        }
        Err(e) => {
            // **Records `true`, and that is the whole point (fix round 5,
            // item 1).** `ExprError` carries no taint flag, so this arm does
            // not *know* whether the condition read secret material — and
            // ruling P35's rule for exactly that situation is: if you do not
            // know a value's provenance, treat it as secret-derived. An
            // earlier version of this arm went through `StepOutcome::failed`,
            // which records `false`, and so reported the gate as **clean for
            // precisely the runs where the secret's content caused the
            // failure.**
            //
            // Executed, one workflow, two runs differing only in the secret's
            // content, asserted by
            // `a_when_that_fails_to_evaluate_because_of_the_secrets_content_records_the_gate_as_secret_derived`:
            // `when: "${{ inputs.arr[json(secrets.K).idx] }}"` with
            // `K = {"idx":0}` completes, and with `K = {"idx":"not-a-number"}`
            // fails — the subscript is a non-number only because of what the
            // secret said. Fix round 4's item F *widened* this class: a
            // secret-derived subscript that used to evaluate silently to
            // `Null` is now an error, so more evaluation failures than before
            // are a function of a secret.
            //
            // This matters because the flag exists to be *read* rather than
            // re-derived (item D): a consumer seeing `false` concludes "no
            // redaction needed" for a gate that did read `secrets.*`.
            // `Option<bool>` was considered and rejected — it makes "unknown"
            // representable but invites `unwrap_or(false)` at the consumer,
            // which is the same fail-open one layer up. `true` is fail-safe
            // by construction and asks no discipline of a future caller; its
            // cost is over-redacting the log line of a gate that failed for a
            // reason having nothing to do with a secret.
            //
            // The failure path itself still writes only a bounded,
            // source-text-only diagnostic (see `StepStatus`'s `Debug` impl),
            // so no secret *value* rides along here.
            //
            // Fix round 2, item 1: before this function existed, this
            // fail-closed arm ran only at the top level — `dispatch_map_step`
            // never evaluated `when:` at all, so an inner step's un-evaluable
            // gate *dispatched* rather than failing closed. Measured:
            // `when: "${{ no_such_fn(1) }}"` on a `map` inner step ran the
            // guarded step.
            let mut outcome = StepOutcome::failed(&step.id, format!("evaluating `when:`: {e}"));
            outcome.gate_condition_was_secret_derived = true;
            GateDecision::Decided(outcome)
        }
    }
}

use crate::expr::{
    eval_delimited_expression, interpolate, interpolate_json, ExprContext, JsonTemplateSource,
    TemplateSource,
};
use crate::parse::steps::{parse_step, topological_order, StepBody, StepDef};
use crate::parse::{ParseError, WorkflowDef};
use crate::report::Report;
use roundhouse_core::{EventPayload, Origin, TaskId, TaskInput, TaskKind, TaskOutput, Usage};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;

/// Stands in for `roundhouse-engine`'s real task admission so this crate
/// stays testable without linking the full engine (this task's Interfaces).
///
/// # The missing `SessionId` is what stops this crate driving a child run
///
/// Named here, at the trait a future implementer would have to change, rather
/// than only in [`run_loop`]'s module doc (B12c fix round): [`Self::emit`]
/// carries no `SessionId`, so every task it writes lands in **the sink's own
/// session**. §8.6 gives a `call:` child run its own Session, so
/// `run_loop::Loop::dispatch_call` can create the child `workflow_run` row and
/// draw its grant — both of which are `workflow_run` writes, not log writes —
/// but it cannot execute the child's steps, because their tasks would be filed
/// under the parent.
///
/// That is a real crate boundary, not a shortcut: a sink that took a
/// `SessionId` would let any caller write into any session's append-only log.
/// The daemon drives a child by calling [`run_loop::run_workflow`] on it with
/// **that** session's sink, exactly as it drives the parent. §8.12's refund
/// needs no driver and is already wired — a child refunds itself at its own
/// terminal transition.
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
    /// Task 19a (§8.6's `carry_over: { last_report: true }`): the report of
    /// "the previous run of this binding", already loaded by the caller —
    /// [`crate::durability::previous_run_for_binding`] finds *which* run
    /// that is, but loading *its report* is a `roundhouse-store`
    /// `tasks`/`events` query this crate does not have (see
    /// [`crate::report`]'s module doc), so it cannot be resolved from
    /// inside `roundhouse-flow`. `None` for a binding's first-ever run, a
    /// manually-invoked run with no binding at all, or simply because the
    /// caller did not look it up (e.g. `defaults.carry_over.last_report` is
    /// `false` and there was nothing worth fetching). See
    /// [`run_loop::run_workflow`]'s use of this field for where the seed it
    /// produces is actually bound.
    pub previous_report: Option<Report>,
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
            // Same caution as `secrets`, and for the same reason `carry_over`
            // is bound through `set_secret` rather than `set_public` in
            // `run_loop::run_workflow`: a prior run's report can contain
            // model-authored text derived from that run's own secrets, and
            // this type's whole `Debug` impl exists to keep a stray
            // `dbg!`/`tracing::debug!` from printing such material — see the
            // doc comment above.
            .field("previous_report_present", &self.previous_report.is_some())
            .finish()
    }
}

#[derive(Clone, PartialEq)]
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

impl fmt::Debug for StepStatus {
    /// Hand-written (fix round 3) rather than derived, so that the
    /// `message`/`reason` text is bounded by
    /// [`MAX_STEPS_CONTEXT_ERROR_LEN`] wherever a `StepStatus` is printed —
    /// not only where [`steps_context_entry`] builds the persisted
    /// `steps.<id>.error`, which was the only place the bound applied before.
    ///
    /// Two things measured against the derived impl it replaces: a ~700-byte
    /// `UnexpectedToken` payload reached a caller's `{:?}` untruncated, and a
    /// credential typed literally into a workflow field (which
    /// [`redact_with_needles`] cannot see, because it was never a
    /// `secrets.*` value) reached it verbatim. Truncation does not make the
    /// second case safe — it bounds it. **What a `StepStatus` message
    /// carries** is this crate's own diagnostic text plus, for an evaluation
    /// failure, a bounded prefix of the offending *workflow-source* field
    /// (see [`crate::expr::ExprError`], every variant of which carries only
    /// source-expression text). It never carries a resolved
    /// `${{ secrets.* }}` value: no failure path in
    /// [`Executor::dispatch_step`] formats an interpolation *result* into a
    /// message.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StepStatus::Completed => f.write_str("Completed"),
            StepStatus::Failed { message } => f
                .debug_struct("Failed")
                .field("message", &truncate_steps_context_error(message))
                .finish(),
            StepStatus::Skipped { reason } => f
                .debug_struct("Skipped")
                .field("reason", &truncate_steps_context_error(reason))
                .finish(),
        }
    }
}

#[derive(Clone)]
pub struct StepOutcome {
    pub step_id: String,
    pub output: Value,
    pub status: StepStatus,
    /// Whether [`Self::output`] was computed by reading secret-marked material
    /// — i.e. whether persisting or logging it requires a redacted stand-in.
    ///
    /// **Carried here rather than discarded (fix round 4, item D).**
    /// [`Executor::dispatch_step`] used to return this alongside the outcome
    /// as a bare `bool` that [`Executor::run_to_completion`] consumed
    /// internally, handing its caller a `Vec<StepOutcome>` with no taint
    /// information at all. Task 8's durability layer has to persist step
    /// outputs to make runs resumable, so it would have had to **re-derive a
    /// fact this executor already computed and threw away** — and a
    /// re-derivation that disagrees with this one is a leak. The justification
    /// for dropping it ("no caller outside this module needs it today") is the
    /// same reasoning that lost taint at the step boundary in fix round 3.
    ///
    /// Note this is a property of `output`, not of the step: a `tool:`/`agent:`
    /// step's `output` is a fixed empty object today, so it is `false` even
    /// when the step's `with:`/`prompt` resolved a secret. The redaction of
    /// *that* value already happened before it reached the sink.
    pub output_is_secret_derived: bool,
    /// Whether this step's `when:` condition was computed by reading
    /// secret-marked material (fix round 4, item C).
    ///
    /// `false` **only** for a step with no `when:` at all, or for one whose
    /// `when:` evaluated successfully without reading a secret-marked root. A
    /// `when:` that *failed to evaluate* records `true` (fix round 5, item 1),
    /// because its taint is unknown and ruling P35's rule for an unknown
    /// provenance is to treat it as secret-derived — recording `false` there
    /// reported the gate as clean for exactly the runs where the secret's
    /// content caused the failure. See [`Executor::run_to_completion`]'s gate
    /// arms for the executed payload and for the channel this exists to make
    /// legible.
    ///
    /// Read this rather than re-deriving it: a re-derivation that disagrees
    /// with this one is a leak.
    pub gate_condition_was_secret_derived: bool,
}

impl StepOutcome {
    /// A step that did not run to completion: no output, so nothing derived
    /// from a secret can be in it. `gate_condition_was_secret_derived` is
    /// filled in by whichever caller evaluated the gate —
    /// [`Executor::run_to_completion`] or
    /// [`map_step::Executor::dispatch_map_step`]'s inner loop — including the
    /// `Err` arm, which deliberately overrides the `false` set here with
    /// `true` (fix round 5, item 1). Do not read the `false` below as a
    /// statement about the gate; it is only the placeholder for a caller
    /// that has not evaluated one.
    fn failed(step_id: &str, message: String) -> Self {
        StepOutcome {
            step_id: step_id.to_string(),
            output: Value::Null,
            status: StepStatus::Failed { message },
            output_is_secret_derived: false,
            gate_condition_was_secret_derived: false,
        }
    }
}

impl fmt::Debug for StepOutcome {
    /// Hand-written (fix round 2, item 1) rather than derived — mirrors
    /// `RunContext`'s own `Debug` impl (fix round 1, item 5) for the
    /// identical reason. This round's own item 1 split deliberately kept
    /// `output` **unredacted** for the `Emit`/`Report` arms (`dispatch_step`,
    /// below): a dependent step reading `${{ steps.<id>.output }}` must see
    /// the step's real value, not a redacted stand-in, so redaction cannot
    /// happen before `output` is stored here. `StepOutcome` is `pub`, and
    /// `run_to_completion` hands a `Vec<StepOutcome>` straight to its
    /// caller — the reviewer measured that Task 8's obvious
    /// `tracing::debug!(?outcomes)` would leak every `emit:`/`report:`
    /// secret through a derived `Debug`, and had previously (wrongly)
    /// cleared this type as carrying no secret material.
    ///
    /// Prints `output`'s *shape* only — a sorted key list for an object, a
    /// length for an array, or just the JSON type name for a scalar — never
    /// a scalar's own value. A key list, not the redacted value itself,
    /// because this type has no `secrets` map to redact against (unlike
    /// [`redact_known_secrets`], which needs the run's secrets to build its
    /// needles); shape-only avoids that dependency entirely, the same way
    /// `RunContext::fmt` avoids it by printing secret *names* rather than
    /// calling into redaction. A bare `emit: "${{ secrets.X }}"` resolves to
    /// a `Value::String` leaf with no key to list, which is exactly why
    /// scalars print only their type, never their content.
    ///
    /// **`status` is bounded too (fix round 3).** An earlier version of this
    /// impl printed `status` through its derived `Debug`, unbounded — the
    /// doc comment above justified shape-only printing of `output` and said
    /// nothing about `status`, which reads as a clearance for Task 8's
    /// `tracing::debug!(?outcomes)`. It is not shape-only: it carries this
    /// crate's diagnostic text and, for an evaluation failure, a bounded
    /// prefix of the offending workflow-source field. What it does **not**
    /// carry is a resolved `${{ secrets.* }}` value — no failure path formats
    /// an interpolation result into a message. See [`StepStatus`]'s own
    /// hand-written `Debug` impl, which is where the length bound now lives.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StepOutcome")
            .field("step_id", &self.step_id)
            .field("output", &ValueShape(&self.output))
            .field("status", &self.status)
            // Booleans, so they carry no content of their own beyond the one
            // bit each already documented on the fields themselves.
            .field("output_is_secret_derived", &self.output_is_secret_derived)
            .field(
                "gate_condition_was_secret_derived",
                &self.gate_condition_was_secret_derived,
            )
            .finish()
    }
}

/// Debug-only helper: renders a [`Value`]'s shape without ever printing a
/// leaf's content — see [`StepOutcome`]'s hand-written `Debug` impl for why.
struct ValueShape<'a>(&'a Value);

impl fmt::Debug for ValueShape<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Value::Object(map) => {
                let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
                keys.sort_unstable();
                write!(f, "Object {{ keys: {keys:?} }}")
            }
            Value::Array(items) => write!(f, "Array {{ len: {} }}", items.len()),
            Value::Null => write!(f, "Null"),
            Value::Bool(_) => write!(f, "Bool(..)"),
            Value::Number(_) => write!(f, "Number(..)"),
            Value::String(_) => write!(f, "String(..)"),
        }
    }
}

/// Why [`Executor::new`] refused to build a run. Currently one variant;
/// [`ExprError`](crate::expr::ExprError) already had to add
/// `#[non_exhaustive]` once this same round for an identical reason, so this
/// gets it from the start.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    /// Fix round 2, item 3 (ruling: reject at construction rather than
    /// redact silently). A secret shorter than [`MIN_REDACTABLE_SECRET_LEN`]
    /// cannot be told apart from an unrelated substring of ordinary text —
    /// [`redact_known_secrets`]'s own doc comment measures a 1-character
    /// "secret" turning `/path/to/data` into `/p***th/to/d***t***`, which is
    /// why this crate refuses to use anything that short as a redaction
    /// needle. Pre-fix, that refusal was silent: a secret 1-7 bytes long
    /// was simply never redacted, reaching the append-only log in
    /// cleartext with no signal to the operator at all — measured directly,
    /// secrets of length 1/4/7 all logged unredacted while length 8
    /// redacted. Refusing to build the run at all, naming the offending
    /// secret's *name* (never its value) and its length, gives the operator
    /// that signal before any step dispatches, rather than after a
    /// credential is already in an unrecoverable log.
    ///
    /// Fix round 3: the secret's actual byte length is **not** reported, in
    /// the message or as a field. It was, and that is a length oracle on a
    /// credential — the same channel this crate already removed once when it
    /// stopped rendering `serde_json`'s column number for a failed
    /// `json(secrets.X)` (see [`crate::expr::JsonErrorCategory`]). Naming the
    /// secret and the fixed minimum tells the operator everything they need;
    /// they can measure their own secret. This error's eventual sink is
    /// untraced — `Executor::new` has no caller outside this crate's tests
    /// yet — so keeping the length costs an unbounded-audience disclosure for
    /// no operator benefit.
    #[error(
        "secret {name:?} is shorter than the \
         {MIN_REDACTABLE_SECRET_LEN}-byte minimum this crate can safely use as a redaction \
         needle (see `redact_known_secrets`) — lengthen it, or accept that it will not be \
         scrubbed from persisted logs and remove it from this run's secrets"
    )]
    SecretTooShortToRedact { name: String },
}

pub struct Executor<'a> {
    def: &'a WorkflowDef,
    run_id: RunId,
    sink: &'a mut dyn TaskSink,
    ctx: ExprContext,
    // Fix round 2, item 5 (M-2): built once here, not on every dispatched
    // step — see `redaction_needles`'s own doc comment for what this
    // replaces and the measured cost of not doing so.
    redaction_needles: Vec<String>,
    /// The run's remaining ceiling as of the step about to be dispatched, set
    /// by [`run_loop::run_workflow`] from
    /// [`map_step::MapBudget::from_run_ledger`] before each dispatch (ruling
    /// P108 §C's obligation).
    ///
    /// **A value, not a `Connection`** — see
    /// [`map_step::MapBudget::unenforced_placeholder`]'s doc for why the
    /// obligation is discharged this way: a run loop holding
    /// `&mut Connection` and an executor holding `&Connection` cannot coexist,
    /// and §8.9 asks for the split to be taken *"at the moment the map
    /// starts"*, which is what a per-dispatch value is and what a stored
    /// handle would only approximate.
    ///
    /// `None` for an [`Executor::new`] with no `workflow_run` row behind it:
    /// there is no ledger to read, and `dispatch_map_step` falls back to the
    /// placeholder that says so.
    map_budget: Option<map_step::MapBudget>,
    /// Where an authored `report:` step's redacted, validated document goes
    /// — see [`ReportEmission`].
    report_emission: ReportEmission,
}

/// Whether an authored `report:` step emits its `TaskKind::Report` task at
/// dispatch, or hands the document back for its caller to emit later.
///
/// **Ruling P117 §C is why this is a choice at all.** §8.6's report is a
/// document *about the run*, and the one fact a reader most needs from it —
/// how the run ended — is not known while the step that writes it is running.
/// A `report:` step that completes and is then followed by a failing step
/// leaves the inbox a document reading `outcome: changed, needs_human: false`
/// for a `Failed` run, which §8.6's `(needs_human, severity, outcome !=
/// nothing)` sort then buries: the same failure ruling P112 exists to prevent,
/// arriving through the authored path rather than the missing one.
///
/// So under a real run the emit is **deferred** to
/// [`run_loop::run_workflow`]'s terminal step, which annotates the run's
/// actual terminal state onto the extension half before emitting. There is
/// still exactly one report task; it is written later and says more.
enum ReportEmission {
    /// [`Executor::run_to_completion`]: emit at dispatch. The in-memory
    /// sequencer has no `workflow_run` row, so there is no terminal state to
    /// annotate and nothing downstream that would ever emit the document.
    Immediate,
    /// [`run_loop::run_workflow`]: hold the validated, redacted document for
    /// the loop to annotate and emit at `finish_run` time. `None` until a
    /// `report:` step actually completes.
    Deferred(Option<Value>),
}

impl<'a> Executor<'a> {
    pub fn new(
        def: &'a WorkflowDef,
        sink: &'a mut dyn TaskSink,
        run_ctx: RunContext,
    ) -> Result<Self, ExecutorError> {
        // Fix round 2, item 3: refuse to build a run carrying a secret this
        // crate cannot safely redact, rather than silently letting it
        // through unprotected — see `ExecutorError::SecretTooShortToRedact`.
        for (name, value) in &run_ctx.secrets {
            if value.len() < MIN_REDACTABLE_SECRET_LEN {
                return Err(ExecutorError::SecretTooShortToRedact { name: name.clone() });
            }
        }
        // Fix round 1, item 9: `run_id` used to be a separate constructor
        // parameter, distinct from `run_ctx.run_id`, and nothing checked
        // the two agreed — `run_ctx.run_id` was silently ignored, so a
        // caller (every test included) could mint one `RunId` for the
        // context and pass a different one here, and whichever was passed
        // here is the one that ends up bound into `${{ run.id }}` and
        // reachable from `Provenance`. There is exactly one run identity;
        // take it from `run_ctx`, the value that already carries it.
        let run_id = run_ctx.run_id;
        // Fix round 2, item 5: build the needle list once per run, before
        // any step dispatches, rather than inside the per-step redaction
        // call. Every secret already passed the length check above.
        let redaction_needles = redaction_needles(&run_ctx.secrets);
        let mut ctx = ExprContext::new();
        // Finding 8: bind everything the expression language needs besides
        // `steps` (set fresh on every iteration inside `run_to_completion`).
        ctx.set_public("inputs", run_ctx.inputs);
        ctx.set_public("vars", run_ctx.vars);
        // Fix round 3 (ruling P33): bound through `set_secret`, not the
        // non-secret `set_public` the three roots above use. That one call is
        // what makes every value any expression computes by reading through
        // `secrets` — a whole value, a field of a parsed JSON secret, its
        // length, a comparison against it — log as `***` while still reaching
        // the dispatched task for real.
        //
        // The three `set_public` calls above are the assertions ruling P35
        // makes load-bearing: `inputs`/`vars`/`run` are declared non-secret
        // here, and a caller who routes a credential through `inputs` rather
        // than `secrets` gets no taint on it. That boundary is pinned by
        // `tests/exec_sequencing.rs`'s
        // `a_credential_handed_in_as_inputs_or_vars_instead_of_secrets_is_not_tainted_and_logs_in_cleartext`
        // so it is a red test, not a stale comment, if it ever changes.
        ctx.set_secret(
            "secrets",
            Value::Object(
                run_ctx
                    .secrets
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                    .collect(),
            ),
        );
        ctx.set_public("run", serde_json::json!({ "id": run_id.to_string() }));
        Ok(Executor {
            def,
            run_id,
            sink,
            ctx,
            redaction_needles,
            map_budget: None,
            report_emission: ReportEmission::Immediate,
        })
    }

    /// Runs every top-level step to completion in dependency order (§8.8's
    /// "the graph is the deterministic skeleton"), **in memory**: no
    /// `workflow_run` row, no checkpoints, no admission, no terminal state.
    ///
    /// # This is not the run loop — [`run_loop::run_workflow`] is
    ///
    /// Stopping-on-failure, `catch:`/`finally:` and the durable half all live
    /// there (B12c). Here, `continue_on_error` is still not read and **every
    /// step in topological order is attempted regardless of an earlier step's
    /// outcome** — which is correct for what this function is (a pure
    /// sequencer for this crate's own tests and
    /// `examples/measure_dual_render.rs`) and wrong for a real run. A caller
    /// that wants §8.9's semantics wants the other function.
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
    /// *only* signal a workflow author has to guard against it.
    ///
    /// **Closed for a real run, and deliberately still open here** (B12c):
    /// [`run_loop::run_workflow`] stops the phase on a failure unless the step
    /// declared `continue_on_error`, so a dependent never runs after an
    /// upstream failure at all. This function keeps the old behaviour because
    /// it has no run to fail — it is the pure sequencer, and a caller that
    /// wants stop-on-failure is asking for the other function.
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
        // Fix round 3 (ruling P33): taint has to survive a step boundary, not
        // just an expression. The `Emit`/`Report` arms deliberately store
        // their *unredacted* resolved value in `StepOutcome.output`, which
        // `steps_context_entry` folds into `steps.<id>.output` — so a
        // dependent's `${{ steps.a.output.body }}` reads secret material that
        // was never itself a `secrets.*` lookup. Recording which step ids
        // produced secret-derived output, and binding `steps` through
        // `set_with_secret_paths`, is what carries the taint across that
        // boundary; without it, provenance would stop at the first step and a
        // *derived* leaf (one the whole-secret backstop cannot match) would
        // reach the append-only log in cleartext from the second step on.
        let mut secret_derived_steps: Vec<String> = Vec::new();

        for idx in order {
            let step = &step_defs[idx];
            self.ctx.set_with_secret_paths(
                "steps",
                Value::Object(steps_context.clone()),
                secret_derived_steps
                    .iter()
                    .map(|id| vec![id.clone(), "output".to_string()]),
            );

            // `when:` handling is a shared helper (fix round 2, item 1) —
            // see `evaluate_when_gate`'s own doc comment for why sharing it
            // with `map_step::Executor::dispatch_map_step` is the fix, not
            // an implementation detail, and for the full history of this
            // exact decision (fail-closed on evaluation error, the delimited
            // form, the one-bit covert-channel accounting).
            let gate_condition_was_secret_derived = match evaluate_when_gate(step, &self.ctx) {
                GateDecision::Decided(outcome) => {
                    steps_context.insert(step.id.clone(), steps_context_entry(&outcome));
                    outcomes.push(outcome);
                    continue;
                }
                GateDecision::Proceed {
                    gate_condition_was_secret_derived,
                } => gate_condition_was_secret_derived,
            };

            let mut outcome = self.dispatch_step(step);
            outcome.gate_condition_was_secret_derived = gate_condition_was_secret_derived;
            if outcome.output_is_secret_derived {
                secret_derived_steps.push(step.id.clone());
            }
            steps_context.insert(step.id.clone(), steps_context_entry(&outcome));
            outcomes.push(outcome);
        }
        Ok(outcomes)
    }

    /// Dispatches one step. The returned [`StepOutcome`] carries
    /// [`StepOutcome::output_is_secret_derived`], which
    /// [`Self::run_to_completion`] folds into `secret_derived_steps` to carry
    /// taint across the step boundary — and which, since fix round 4 (item D),
    /// also survives out of this crate rather than being consumed here, so
    /// Task 8's durability layer reads the fact instead of re-deriving it.
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
                            return StepOutcome::failed(
                                &step.id,
                                format!("interpolating `with:`: {e}"),
                            );
                        }
                    };
                // Ruling P33's dual rendering: `redacted_for_logging()` is the
                // only half that may reach the sink; the backstop needles are
                // applied on top of it for a credential the author pasted
                // literally into the YAML, which no provenance can see.
                let logged_with = redact_with_needles(
                    resolved_with.redacted_for_logging(),
                    &self.redaction_needles,
                );
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
                // Real dispatch delegates
                // `resolved_with.into_unredacted_for_dispatch()` — the real
                // value, `${{ secrets.* }}` included — to `roundhouse-tools`
                // via `roundhouse-engine`; this executor's job ends at
                // emitting the task and folding its eventual `TaskCompleted`
                // back into `steps.<id>.output` — wired in Task 8's
                // durability layer, which owns the actual run loop. Until
                // then the unredacted half is simply dropped here.
                //
                // `output` is a fixed empty object, so it is never
                // secret-derived regardless of what `with:` contained.
                StepOutcome {
                    step_id: step.id.clone(),
                    output: serde_json::json!({}),
                    status: StepStatus::Completed,
                    output_is_secret_derived: false,
                    gate_condition_was_secret_derived: false,
                }
            }
            StepBody::Agent { prompt, .. } => {
                let resolved_prompt =
                    match interpolate(TemplateSource::from_workflow_file(prompt), &self.ctx) {
                        Ok(s) => s,
                        Err(e) => {
                            return StepOutcome::failed(
                                &step.id,
                                format!("interpolating `agent.prompt`: {e}"),
                            );
                        }
                    };
                // A prompt is prose, so the redacted rendering here keeps the
                // surrounding literal template text and replaces only the
                // spliced-in text of each secret-derived `${{ }}` block.
                let logged_prompt = redact_with_needles(
                    &serde_json::json!({"prompt": resolved_prompt.redacted_for_logging()}),
                    &self.redaction_needles,
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
                // As in the `Tool` arm: real dispatch (Task 8) gets
                // `resolved_prompt.into_unredacted_for_dispatch()`; `output`
                // is a fixed empty object and never secret-derived.
                StepOutcome {
                    step_id: step.id.clone(),
                    output: serde_json::json!({}),
                    status: StepStatus::Completed,
                    output_is_secret_derived: false,
                    gate_condition_was_secret_derived: false,
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
                            return StepOutcome::failed(
                                &step.id,
                                format!("interpolating `emit:`: {e}"),
                            );
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
                let logged =
                    redact_with_needles(resolved.redacted_for_logging(), &self.redaction_needles);
                let output_is_secret_derived = resolved.is_secret_derived();
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
                    output: resolved.into_unredacted_for_dispatch(),
                    status: StepStatus::Completed,
                    output_is_secret_derived,
                    gate_condition_was_secret_derived: false,
                }
            }
            StepBody::Report { report } => {
                // Finding 2 fix (the audit's headline example): the
                // mandatory report is now actually persisted through the
                // sink as a real `TaskKind::Report` task, carrying the
                // report JSON as its completed output — this is what makes
                // the Runs inbox/fingerprint diffing (Task 10) have
                // something to load back. Task 18 (B10) supplies the report
                // validator this comment used to say did not exist yet, and
                // gates the emit on it below.
                let resolved = match interpolate_json(
                    JsonTemplateSource::from_workflow_file(report),
                    &self.ctx,
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return StepOutcome::failed(
                            &step.id,
                            format!("interpolating `report:`: {e}"),
                        );
                    }
                };
                // Fix round 1, item 1 (CRITICAL): same defect as `Emit`
                // above, and worse in blast radius — `report:` is §8.8's
                // *mandatory* per-run block, so an unredacted
                // `${{ secrets.* }}` reference here was on every run's
                // path, not just an author's optional notification block.
                let logged =
                    redact_with_needles(resolved.redacted_for_logging(), &self.redaction_needles);
                // Task 18 (B10): validate before emitting, and emit nothing
                // at all when validation fails. The `events` table
                // physically rejects UPDATE/DELETE, so a malformed report
                // that reaches the sink is there permanently — failing the
                // step is the only correction available.
                //
                // Validation runs on `logged`, not on `resolved`. `logged`
                // is byte-for-byte what is persisted and what the inbox
                // loads back, so validating anything else would bless a
                // payload nobody will ever read; and `ReportError` quotes
                // the offending value, so validating the redacted rendering
                // keeps secret material out of the failure message too.
                //
                // Validating the redacted rendering is also provably sound,
                // not merely prudent — a structural argument, not just a
                // practical one (fix round 1, ruling P74): redaction
                // substitutes `***` into **string leaves only**;
                // `needs_human` is a bool and `cost`'s figures are numbers,
                // neither of which redaction ever touches; and no member of
                // `{nothing, changed, findings, failed, needs_human}` or
                // `{low, med, high}` contains `***`. So a `logged` that
                // validates *implies* the typed core (`outcome`, `severity`,
                // `needs_human`, `cost`) of `logged` is byte-identical to
                // `resolved`'s — redaction can only ever steer
                // valid -> invalid, never invalid -> valid.
                //
                // **"Only ever valid -> invalid" is the safe direction for a
                // step, and not for a synthesised report** (ruling P117 §D).
                // Here, an invalid `logged` fails *this step*, which is
                // ordinary control flow: the run goes on to fail with a
                // synthesised report explaining why. On
                // `run_loop::Loop::synthesise_report`'s path there is no step
                // to fail — a `secrets` value that redaction steers into an
                // invalid document there is a run that can reach **no**
                // terminal state at all, on this drive or any later one,
                // because the report is what `finish_run` requires. Same
                // direction, unrecoverable rather than recoverable; see that
                // function's own note.
                //
                // The divergence
                // between `logged` and `resolved` is confined to free-text
                // fields validation does not constrain beyond "is a string"
                // (`headline`, finding `id`/`title`/`location`, and anything
                // under `extra`), which is exactly why those fields can
                // arrive as the redaction placeholder — see `Report`'s doc
                // comment on the visible consequence of that.
                if let Err(e) = crate::report::validate_report(&logged) {
                    return StepOutcome::failed(&step.id, format!("invalid `report:`: {e}"));
                }
                let output_is_secret_derived = resolved.is_secret_derived();
                match &mut self.report_emission {
                    // Ruling P117 §C: hand the document to the run loop
                    // rather than emitting it now, so the one report task
                    // this run leaves behind can carry the run's real
                    // terminal state. See `ReportEmission`.
                    ReportEmission::Deferred(slot) => *slot = Some(logged),
                    ReportEmission::Immediate => {
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
                    }
                }
                StepOutcome {
                    step_id: step.id.clone(),
                    output: resolved.into_unredacted_for_dispatch(),
                    status: StepStatus::Completed,
                    output_is_secret_derived,
                    gate_condition_was_secret_derived: false,
                }
            }
            // Task 14/B6: real `map` dispatch — evaluates `over:`, binds the
            // `as:` item variable per item, and recursively runs the inner
            // steps via this same `dispatch_step`. See
            // `map_step::Executor::dispatch_map_step`'s own doc comment for
            // the full provenance/budget reasoning.
            //
            // (`dispatch_step` matches on `&step.body`, so match ergonomics
            // already bind `over`/`r#as`/`max_parallel`/`on_item_error`/
            // `steps` as references here — `&String`/`u32`/`OnItemError`/
            // `&Vec<serde_yaml::Value>` — which coerce to `&str`/
            // `&[serde_yaml::Value]` at the call site below with no further
            // `&` needed; `max_parallel`/`on_item_error` are `Copy`.)
            StepBody::Map {
                over,
                r#as,
                max_parallel,
                on_item_error,
                steps,
                ..
            } => self.dispatch_map_step(&step.id, over, r#as, *max_parallel, *on_item_error, steps),
            // **`gate:` and `call:` are handled by [`run_loop`], not here**
            // (B12c). Both need a `workflow_run` row and a `&mut Connection`
            // — a park is a durable state transition plus a checkpoint, and a
            // `call:` creates a child run, draws its budget and refunds it —
            // and `Executor` deliberately holds neither (see `map_budget`'s
            // doc). The run loop therefore intercepts these two bodies before
            // it reaches this function, rather than this function acquiring a
            // database handle it would hold for the whole run.
            //
            // Reaching this arm means a `gate:` or `call:` was dispatched with
            // **no run behind it**, and there are exactly two such callers:
            //
            // 1. `Executor::run_to_completion`, the in-memory sequencer, which
            //    has no run row at all.
            // 2. `map_step::dispatch_map_step`'s inner-step loop, for a
            //    `gate:` or `call:` nested inside a `map`. §8.9's own reference
            //    workflow nests a `gate:` that way, so this is a real shape
            //    that is refused rather than an impossible one — and it is
            //    refused for a structural reason, not an omission: a park is a
            //    transition of *the run*, and one run cannot be parked
            //    per-item; a nested `call:` needs the per-item budget pool
            //    whose ceilings ruling P77 §C defers along with `map`'s
            //    worktree fan-out. Both belong with whoever gives `map` real
            //    fan-out.
            //
            // Fix round 1, item 8: the message used to be
            // `format!("step kind {other:?} handled by a later task")` — a
            // full `{:?}` dump of the step body, flowing through
            // `steps_context_entry` into the immutable log. The text is
            // uninterpolated workflow source, so no *resolved* secret escapes,
            // but a literal credential typed directly into a `gate`/`call`
            // body (e.g. `gate.form`, `call.with`) would reach the log
            // verbatim. Name only the variant, never its contents.
            other @ (StepBody::Gate { .. } | StepBody::Call { .. }) => StepOutcome::failed(
                &step.id,
                format!(
                    "step kind `{}` needs a run loop: it is dispatched by \
                     `run_loop::run_workflow`, never by a bare executor or from inside a `map`",
                    step_body_kind_name(other)
                ),
            ),
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
///
/// # `error` is bounded independently of any message-producing call site (fix round 2, item 2)
///
/// Pre-fix, `error` echoed whatever `String` a `StepStatus::Failed`/
/// `Skipped` carried, unbounded — and `crate::expr::ExprError::NotADelimitedExpression`
/// (the `when:`-evaluation-failure path) used to echo the *whole* offending
/// field, so a large `when:` field produced a proportionally large
/// `steps.<id>.error`, readable and re-emittable by any dependent step, into
/// a table that physically rejects `UPDATE`/`DELETE`. Security measured
/// this pre-fix: a 184,334-byte workflow produced a 200,202-byte
/// `steps.a.error`, and 60 dependents each reading and re-emitting it put
/// 21,636,840 bytes through the sink (117.4x amplification, 410ms).
/// `crate::expr`'s own fix (`truncate_echoed_field`) closes that one source,
/// but this function is the single call site every `Failed`/`Skipped`
/// message funnels through regardless of source, so it bounds `error`
/// again, independently — the same defense-in-depth shape as
/// `redact_known_secrets` closing its own narrower gap without depending on
/// every future message-producing call site to remember to truncate on its
/// own.
fn steps_context_entry(outcome: &StepOutcome) -> Value {
    let (status, error) = match &outcome.status {
        StepStatus::Completed => ("completed", None),
        StepStatus::Failed { message } => ("failed", Some(truncate_steps_context_error(message))),
        StepStatus::Skipped { reason } => ("skipped", Some(truncate_steps_context_error(reason))),
    };
    serde_json::json!({
        "output": outcome.output,
        "status": status,
        "error": error,
    })
}

/// Independent bound on the `error` field [`steps_context_entry`] writes
/// into `steps.<id>.error` (fix round 2, item 2) — a round number
/// comfortably larger than any realistic diagnostic message this crate
/// itself produces (the longest today is `NotADelimitedExpression`'s, now
/// itself bounded to roughly 100 bytes by `crate::expr::MAX_ECHOED_FIELD_LEN`)
/// and comfortably smaller than the multi-hundred-thousand-byte amplification
/// this bound exists to rule out regardless of which future call site
/// produces an oversized message. Not derived from any formal analysis, the
/// same status `MIN_REDACTABLE_SECRET_LEN` (below) documents for its own
/// bound.
const MAX_STEPS_CONTEXT_ERROR_LEN: usize = 512;

/// Truncates `text` to at most [`MAX_STEPS_CONTEXT_ERROR_LEN`] bytes (at a
/// valid UTF-8 boundary), appending the original byte length when
/// truncation actually happens.
fn truncate_steps_context_error(text: &str) -> Cow<'_, str> {
    truncate_diagnostic(text, MAX_STEPS_CONTEXT_ERROR_LEN)
}

/// The truncation both bounded diagnostic sinks in this crate share.
///
/// Split out by B12c's fix round for the third one:
/// [`run_loop::MAX_FINDING_TITLE_LEN`] bounds a step's failure message on its
/// way into a synthesised report's finding `title`, and it was the only one of
/// the three arriving unbounded. One implementation rather than a third copy,
/// so "truncate at a char boundary and say how much was dropped" cannot drift
/// between them.
fn truncate_diagnostic(text: &str, limit: usize) -> Cow<'_, str> {
    if text.len() <= limit {
        return Cow::Borrowed(text);
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    Cow::Owned(format!("{}... ({} bytes total)", &text[..end], text.len()))
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
/// - **Very short secret values could over-redact — now refused outright
///   (fix round 2, item 3).** A 1-2 character "secret" matches arbitrary,
///   unrelated substrings of ordinary text — measured directly: a secret of
///   `"a"` turns `/path/to/data` into `/p***th/to/d***t***`, corrupting the
///   payload rather than protecting anything. [`MIN_REDACTABLE_SECRET_LEN`]
///   still names that bound, but it is no longer a silent per-secret filter
///   applied here: pre-fix, a secret shorter than the bound was simply
///   never redacted, with no signal to the operator — measured directly,
///   secrets of length 1/4/7 all reached the log unredacted while length 8
///   redacted. `Executor::new` now refuses to build a run carrying such a
///   secret at all ([`ExecutorError::SecretTooShortToRedact`]), so by the
///   time this function runs, every whole-secret value it is handed is
///   already known to be at least [`MIN_REDACTABLE_SECRET_LEN`] bytes long.
///   The constant is retained because [`redact_known_secrets`] is `pub` and
///   any external caller can still hand it a short secret directly, without
///   going through [`Executor::new`]'s rejection. It no longer gates
///   anything derived: there is nothing derived left to gate (fix round 3).
///
/// # This is a BACKSTOP, not the primary mechanism (ruling P33, fix round 3)
///
/// Redaction is now **provenance-based**, and it happens in
/// `crate::expr`, not here: a value is replaced by `***` in the logged
/// rendering because the expression that produced it read a root bound
/// through [`crate::expr::ExprContext::set_secret`] — see that module's
/// "Provenance-based redaction" section for the full propagation table.
/// [`Executor::dispatch_step`] logs
/// [`crate::expr::Interpolated::redacted_for_logging`] and this function only
/// runs on top of that already-redacted rendering.
///
/// **What is left for this function to catch, and why it stays:** taint
/// cannot see a credential the workflow author **pasted literally into the
/// YAML** — that text was never derived from a `secrets.*` lookup, so no
/// provenance attaches to it. Exact-match needles for the whole declared
/// secret values close exactly that case, and that needle set is *bounded and
/// exact*: it is precisely what the operator declared, one string per secret.
///
/// **What was deleted, and why.** Two earlier rounds expanded this needle set
/// by parsing each JSON-valued secret and adding its string *leaves* as
/// needles. Round 1 added every leaf, which turned a real GCP service-account
/// key's public constants into global find-and-replace needles and corrupted
/// 4 of 4 ordinary strings measured (`"deploying my-project-1234 to staging"`
/// -> `"deploying *** to staging"`, and three more). Round 2 narrowed that to
/// leaves under a list of credential-sounding key names, which then
/// **under**-redacted 29 real credential field names measured end to end —
/// including all three fields of the JSON `aws sts assume-role` returns.
/// Both failures are the same failure: the set of credential field names in
/// the world is unbounded, so any list of them is wrong in one direction or
/// the other. The derived-leaf expansion is therefore deleted outright rather
/// than tuned a third time; provenance covers every derived value the earlier
/// lists were reaching for, without needing to name any of them. Keep
/// bounded, delete unbounded.
///
/// **Consequence for [`MIN_REDACTABLE_SECRET_LEN`]:** it now gates only whole
/// declared secrets, which [`Executor::new`] already rejects below the floor.
/// The sub-floor *derived* leaf that used to slip through silently (a
/// `{"password":"9182"}` field inside an accepted 44-byte secret) is covered
/// by provenance instead, where no length floor applies at all — because a
/// whole substitution is replaced, not a substring searched for.
pub fn redact_known_secrets(value: &Value, secrets: &HashMap<String, String>) -> Value {
    let needles = redaction_needles(secrets);
    redact_with_needles(value, &needles)
}

/// A declared secret value shorter than this is never used as a redaction
/// needle (fix round 3: it is the *only* thing that can be a needle at all,
/// the derived-leaf expansion having been deleted) — see
/// [`redact_known_secrets`]'s "What
/// this function does and does not catch" section for why, and
/// [`ExecutorError::SecretTooShortToRedact`] for how a whole secret this
/// short is now refused before a run ever starts (fix round 2, item 3).
/// Chosen as a round number comfortably below any realistic credential
/// length and comfortably above the lengths (1-2 characters) measured to
/// cause over-redaction; not derived from any formal analysis.
const MIN_REDACTABLE_SECRET_LEN: usize = 8;

/// Builds the flat list of strings [`redact_with_needles`] scans for: each
/// secret's own whole-string value, and **nothing else** (ruling P33, fix
/// round 3). The derived-leaf expansion this function used to perform — parse
/// each JSON-valued secret, add some or all of its string leaves as needles —
/// is deleted; see [`redact_known_secrets`]'s "This is a BACKSTOP" section
/// for why both the broad and the narrow version of it were wrong, and where
/// derived values are covered instead. The remaining set is one string per
/// declared secret, filtered through [`MIN_REDACTABLE_SECRET_LEN`].
///
/// **Fix round 2, item 5 (M-2): called once per run from [`Executor::new`],
/// not once per dispatched step.** That hoist is kept. Its measured payoff,
/// however, was almost entirely about the JSON re-parse and leaf walk this
/// round deleted: the pre-hoist figures recorded here (security, debug
/// build — a 2,000-leaf, 97,781-byte secret costing 24.4ms per call versus
/// 13.7us pre-built, 1,780x; and 70.0ms versus 3.9ms end to end over 100
/// steps, 18x) are figures for code that no longer exists, and are retained
/// only as the history of why the hoist happened. **What this function costs
/// now is unmeasured** and is one `String` clone per declared secret; the
/// hoist stays because it is still exact (the needle list is invariant for
/// the life of a run) and costs nothing to keep, not because a current
/// measurement justifies it.
fn redaction_needles(secrets: &HashMap<String, String>) -> Vec<String> {
    secrets
        .values()
        .filter(|raw| raw.len() >= MIN_REDACTABLE_SECRET_LEN)
        .cloned()
        .collect()
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
