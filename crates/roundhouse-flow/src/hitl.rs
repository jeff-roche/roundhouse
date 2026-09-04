//! §8.11's human-in-the-loop unification: "Three sources of human waits —
//! an explicit `gate` step, an unattended permission `Escalate`, and
//! mid-step elicitation — resolve to **one mechanism**: an `AwaitingHuman`
//! task with a JSON-Schema form that TUI and web render from the same
//! schema. Unifying permission escalation with approval gates is what makes
//! unattended mode tractable rather than a second policy engine."
//!
//! This module is that one mechanism: [`AwaitingHuman`], the constructors
//! that funnel each source into it, and [`Escalate`] — the evaluated form of
//! §8.5 point 2's per-job `Park{deadline, on_timeout}` / `DenyAndContinue` /
//! `Fail` configuration, which is what turns a permission `Ask` into one of
//! these waits.
//!
//! # What this module deliberately does *not* do
//!
//! - **No clock.** [`AwaitingHuman::deadline`] is a *relative*
//!   [`Duration`], never an absolute instant (ruling P65 #4). Reading a
//!   clock is exactly the ambient I/O this crate's position in the graph
//!   exists to avoid, and §8.11 puts the deadline on "the same timer heap
//!   as triggers", which lives in `roundhouse-sched`. The relative ->
//!   absolute conversion belongs to the parking task (Task 17), where "now"
//!   is genuinely known.
//! - **No `on_timeout: approve` precondition check.** §8.11 permits
//!   `approve` "only when the run's policy is narrower than the job
//!   default" — a fact about the *bound, running* policy, not about the
//!   document. `parse/steps.rs` defers it for exactly that reason (see
//!   `GateBodyDef`'s doc comment and
//!   `gate_on_timeout_approve_parses_without_checking_its_run_time_precondition`
//!   in `tests/parse_steps.rs`), and this module preserves the deferral
//!   rather than inventing a static approximation of a run-time fact. The
//!   executor, which resolves and holds the run's effective policy, owns
//!   the check.
//! - **No `SuspendReason` variant.** `roundhouse_core::SuspendReason`
//!   already carries `AwaitingApproval`, `AwaitingElicitation` and
//!   `WorkflowGate { step_ref }` — exactly §8.11's three sources — so
//!   [`HumanWaitSource`] maps 1:1 onto types that already exist rather than
//!   adding a parallel taxonomy. The persistence side is already there.
//! - **No parking.** Releasing the worker slot, the implicit `checkpoint`
//!   task, `hold_workspace`'s TTL and the 7-day reaper are Task 17's, and
//!   `exec::Executor`'s `StepBody::Gate` arm is still the
//!   "handled by a later task" stub.
//! - **No dependency on `roundhouse-policy`.** Ruling P7: [`Escalate`] is a
//!   type this crate owns, built over `roundhouse_core::PolicyDecision`.
//!   §5.2's row for `roundhouse-flow` is `core, engine, store` and stays
//!   that way.

use crate::parse::types::{OnTimeout, UnattendedDef, UnattendedEscalate};
use crate::retry::{parse_duration_str, DurationParseError};
use roundhouse_core::{PolicyDecision, TaskId};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

/// Which of §8.11's three sources produced this human wait.
///
/// These line up 1:1 with `roundhouse_core::SuspendReason`'s already-frozen
/// variants — [`Gate`](Self::Gate) with `WorkflowGate { step_ref }`,
/// [`PermissionEscalate`](Self::PermissionEscalate) with
/// `AwaitingApproval { rule, params_digest }`, and
/// [`Elicitation`](Self::Elicitation) with `AwaitingElicitation { schema }`
/// — so recording one of these waits needs no new suspend reason. Those
/// core variants carry payloads (the matched rule, the params digest, the
/// step ref) that only the recording site holds, which is why this enum is
/// the *source label* and not a conversion.
///
/// Keeping the source as a field is not a hedge against §8.11's "one
/// mechanism": the mechanism is [`AwaitingHuman`] and its form schema, both
/// identical across sources. The label only says where the wait came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanWaitSource {
    /// An explicit `gate:` step written by the workflow author (§8.9).
    Gate,
    /// An unattended permission decision that came back `Ask` and whose job
    /// configured `escalate: park` (§8.5 point 2).
    PermissionEscalate,
    /// A mid-step elicitation: a tool or MCP server asking the human for
    /// structured input while the step is running.
    ///
    /// No constructor here builds one yet — the elicitation call site lives
    /// outside this crate (the MCP host, Phase 3) and this variant exists so
    /// that site has the same mechanism to resolve into rather than a
    /// fourth shape of its own.
    Elicitation,
}

/// §8.11's one mechanism: a task waiting on a human, carrying the
/// JSON-Schema form "TUI and web render from the same schema".
///
/// Every field except [`source`](Self::source) is source-independent by
/// construction — that equality is the property `tests/hitl.rs`'s
/// `an_explicit_gate_step_and_a_permission_escalation_produce_the_same_task_shape`
/// pins.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AwaitingHuman {
    pub task_id: TaskId,
    pub source: HumanWaitSource,
    /// A JSON Schema object: `{"type": "object", "title": ..., "properties":
    /// {...}}`. See [`form_schema`].
    pub form_schema: serde_json::Value,
    /// **Relative**, not absolute — see this module's doc comment. `None`
    /// means "no deadline": nothing times this wait out, so
    /// [`on_timeout`](Self::on_timeout) never fires. A `gate:` step always
    /// has one (`timeout:` is mandatory in the wire shape) and so does
    /// `Escalate::Park`; the `None` case is for an elicitation with no
    /// declared window.
    pub deadline: Option<Duration>,
    /// §8.11's `deny | fail | default(value) | approve`. Reuses
    /// [`crate::parse::types::OnTimeout`] rather than restating the grammar,
    /// so a gate's `on_timeout` and an escalation's are the same type;
    /// `Default`'s argument stays verbatim source text, since evaluating
    /// `${{ }}` is the expression language's job at timeout time.
    pub on_timeout: OnTimeout,
}

/// The form a permission escalation asks: one boolean.
///
/// A `gate:` step's fields are author-written (§8.9's
/// `form: { approve: {...}, note: {...} }`); a permission escalation has no
/// author to write them, so it asks the single question a permission wait
/// actually has. Deliberately the same *shape* a gate declaring
/// `form: { approve: { type: boolean } }` produces, which is what lets the
/// two sources compare equal.
fn permission_approval_fields() -> serde_json::Map<String, serde_json::Value> {
    let mut fields = serde_json::Map::new();
    fields.insert(
        "approve".to_string(),
        serde_json::json!({ "type": "boolean" }),
    );
    fields
}

/// Wraps a map of field-name -> JSON-Schema property in the object schema
/// §8.11 says both renderers consume.
///
/// `fields` is what §8.9's `form:` key holds — the *properties* of the
/// form, not a whole schema — so this is the single place that decides how
/// those properties become one. Both constructors below go through it,
/// which is why a gate and an escalation with equivalent configuration
/// produce identical schemas.
///
/// Takes a [`serde_json::Map`] rather than a [`serde_json::Value`] so this
/// is total: rejecting a non-object `form:` is
/// [`AwaitingHuman::from_gate`]'s job, on the one path where the value came
/// from a workflow author.
fn form_schema(
    title: &str,
    fields: &serde_json::Map<String, serde_json::Value>,
) -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "title": title,
        "properties": fields,
    })
}

fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

impl AwaitingHuman {
    /// Turns a parsed `StepBody::Gate { title, form, timeout, on_timeout }`
    /// into the one mechanism.
    ///
    /// Takes the four fields rather than the `StepBody` so the caller can
    /// destructure once and so this never has to reject a non-`Gate` body it
    /// was handed by mistake.
    ///
    /// `timeout` goes through the crate's single duration parser
    /// ([`parse_duration_str`]), so a gate's `timeout: "10 s"` is rejected
    /// exactly as a retry's `base: "10 s"` is.
    pub fn from_gate(
        task_id: TaskId,
        title: &str,
        form: &serde_json::Value,
        timeout: &str,
        on_timeout: &OnTimeout,
    ) -> Result<Self, HitlError> {
        let deadline =
            parse_duration_str(timeout).map_err(|source| HitlError::InvalidGateTimeout {
                value: timeout.to_string(),
                source,
            })?;
        // `GateBodyDef::form` is an unconstrained `serde_json::Value`, so
        // `form: [1, 2]` parses. Dropping that under `properties` would hand
        // both renderers a JSON Schema neither can render — reject it here
        // instead, at the one point where the value is author-supplied.
        let fields = form.as_object().ok_or(HitlError::FormIsNotAnObject {
            actual: json_type_name(form),
        })?;
        Ok(AwaitingHuman {
            task_id,
            source: HumanWaitSource::Gate,
            form_schema: form_schema(title, fields),
            deadline: Some(deadline),
            on_timeout: on_timeout.clone(),
        })
    }

    /// Turns an [`Escalate::Park`]'s already-evaluated fields into the same
    /// mechanism.
    ///
    /// `title` is the human-readable description of what is being asked —
    /// the caller (the executor, which holds the matched rule and the tool
    /// call) is the only place that knows it, so it is passed in rather than
    /// synthesised here from information this module does not have.
    ///
    /// Infallible, unlike [`from_gate`](Self::from_gate): the deadline is
    /// already a [`Duration`] and the form is this module's own, so there is
    /// nothing left to reject.
    pub fn from_escalate(
        task_id: TaskId,
        title: &str,
        deadline: Duration,
        on_timeout: &OnTimeout,
    ) -> Self {
        AwaitingHuman {
            task_id,
            source: HumanWaitSource::PermissionEscalate,
            form_schema: form_schema(title, &permission_approval_fields()),
            deadline: Some(deadline),
            on_timeout: on_timeout.clone(),
        }
    }
}

/// §8.5 point 2, evaluated: "`Escalate` is configurable per job:
/// `Park{deadline, on_timeout}`, `DenyAndContinue`, or `Fail`."
///
/// The wire shape of the same configuration is
/// [`UnattendedDef`]/[`UnattendedEscalate`] in [`crate::parse::types`];
/// this is what it becomes once its `deadline: Option<String>` has been
/// parsed and its cross-field requirement checked, so `TryFrom<&UnattendedDef>`
/// is the only way to build one from a document. Ruling P7: this type is
/// owned here, not imported from `roundhouse-policy`, and it is built over
/// `roundhouse_core::PolicyDecision` rather than over a second decision enum.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Escalate {
    Park {
        deadline: Duration,
        on_timeout: OnTimeout,
    },
    DenyAndContinue,
    Fail,
}

/// What a [`PolicyDecision`] becomes once the job's [`Escalate`]
/// configuration has been applied to it.
///
/// Total over [`PolicyDecision`]: `Allow` and `Deny` are already settled and
/// pass through untouched, so only `Ask` — the decision unattended mode has
/// no interactive fallback for (§8.5 point 1) — is ever routed by the
/// escalate configuration.
#[derive(Debug, Clone, PartialEq)]
pub enum Escalation {
    /// Settled without a human. An `Ask` reaches this only via
    /// [`Escalate::DenyAndContinue`], as `Deny`; §8.5 point 3's structured
    /// `{error: "permission_denied", rule, hint}` tool error is how the
    /// executor renders that denial back into the model's context, and is
    /// the executor's surface, not this module's.
    Decided(PolicyDecision),
    /// §8.11: park on the one `AwaitingHuman` mechanism.
    Park(AwaitingHuman),
    /// §8.5 point 2's `Fail`: the run fails rather than parking or denying.
    Fail,
}

impl Escalate {
    /// Applies this job-level configuration to one policy decision.
    ///
    /// `title` describes the permission being asked for and is used only on
    /// the `Ask` + [`Park`](Self::Park) path; see
    /// [`AwaitingHuman::from_escalate`] for why the caller supplies it.
    pub fn apply(&self, decision: PolicyDecision, task_id: TaskId, title: &str) -> Escalation {
        match decision {
            // §8.5 point 1: `decide()` is pure and total. An already-settled
            // decision is not the escalate configuration's business.
            PolicyDecision::Allow | PolicyDecision::Deny => Escalation::Decided(decision),
            PolicyDecision::Ask => match self {
                Escalate::Park {
                    deadline,
                    on_timeout,
                } => Escalation::Park(AwaitingHuman::from_escalate(
                    task_id, title, *deadline, on_timeout,
                )),
                Escalate::DenyAndContinue => Escalation::Decided(PolicyDecision::Deny),
                Escalate::Fail => Escalation::Fail,
            },
        }
    }
}

impl TryFrom<&UnattendedDef> for Escalate {
    type Error = HitlError;

    /// `parse_workflow` already rejects `escalate: park` without both
    /// `deadline` and `on_timeout`
    /// (`ParseError::ParkEscalationRequiresDeadlineAndOnTimeout`), but
    /// [`UnattendedDef`] is a plain public struct anyone can build directly,
    /// so this re-checks rather than assuming the value came through the
    /// document parser.
    fn try_from(def: &UnattendedDef) -> Result<Self, Self::Error> {
        match def.escalate {
            UnattendedEscalate::Park => {
                let (Some(deadline), Some(on_timeout)) = (&def.deadline, &def.on_timeout) else {
                    return Err(HitlError::ParkRequiresDeadlineAndOnTimeout);
                };
                Ok(Escalate::Park {
                    deadline: parse_duration_str(deadline).map_err(|source| {
                        HitlError::InvalidEscalateDeadline {
                            value: deadline.clone(),
                            source,
                        }
                    })?,
                    on_timeout: on_timeout.clone(),
                })
            }
            UnattendedEscalate::DenyAndContinue => Ok(Escalate::DenyAndContinue),
            UnattendedEscalate::Fail => Ok(Escalate::Fail),
        }
    }
}

/// Why a human wait could not be built from its source configuration.
///
/// Every variant is a rejection of untrusted workflow YAML — a gate's
/// `timeout:`, its `form:`, or `permissions.unattended` — rather than an
/// internal error, which is why each carries the offending value back to
/// the author.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HitlError {
    #[error("gate `timeout` {value:?} is invalid: {source}")]
    InvalidGateTimeout {
        value: String,
        source: DurationParseError,
    },
    #[error("permissions.unattended.deadline {value:?} is invalid: {source}")]
    InvalidEscalateDeadline {
        value: String,
        source: DurationParseError,
    },
    #[error(
        "permissions.unattended.escalate is `park`, which requires both `deadline` and `on_timeout` (§8.5: \"Escalate is configurable per job: Park{{deadline, on_timeout}}\")"
    )]
    ParkRequiresDeadlineAndOnTimeout,
    #[error(
        "gate `form` must be a JSON object mapping each field name to its JSON-Schema property, got a {actual}"
    )]
    FormIsNotAnObject { actual: &'static str },
}
