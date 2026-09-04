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
//! - **No clock.** [`AwaitingHuman::timeout_after`] is a *relative*
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
//!
//!   The deferral is carried by a *type*, not by this paragraph:
//!   [`AwaitingHuman::on_timeout`] is an [`UncheckedOnTimeout`], so the
//!   only way to turn it into a decision is
//!   [`UncheckedOnTimeout::resolve`], which takes the run-time fact as its
//!   argument. A consumer that writes the obvious
//!   `match awaiting.on_timeout { Approve => grant(), .. }` does not
//!   compile, which is the point: that code reads correctly and is a
//!   privilege escalation.
//! - **No `SuspendReason` variant.** `roundhouse_core::SuspendReason` has
//!   five variants, three of which are human waits — `AwaitingApproval`,
//!   `AwaitingElicitation` and `WorkflowGate { step_ref }` — and those
//!   three are exactly §8.11's three sources, so [`HumanWaitSource`] maps
//!   1:1 onto types that already exist rather than adding a parallel
//!   taxonomy. (`AwaitingReply` and `AwaitingPeer` are the messaging waits
//!   and have no human-wait source; `tests/hitl.rs` pins the whole mapping
//!   with an exhaustive `match`, so a sixth core variant is a build break
//!   rather than a stale comment.) The persistence side is already there.
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

/// `on_timeout` exactly as the document wrote it, with §8.11's `approve`
/// precondition **not** checked.
///
/// §8.11 permits `on_timeout: approve` "only when the run's policy is
/// narrower than the job default". That is a fact about the bound, running
/// policy; no document carries it and this crate never holds it (see the
/// module doc). So the value cannot be read as a decision here — and the
/// danger is that reading it as one is the *obvious* thing to write:
///
/// ```ignore
/// match awaiting.on_timeout { OnTimeout::Approve => grant(), .. } // wrong
/// ```
///
/// That code compiles against a bare [`OnTimeout`], reads correctly, and
/// grants the job default's permissions for an action the bound policy
/// answered `Ask` for, with no human present — §8.5 point 5's "capabilities
/// narrow downward only", violated. Wrapping the field makes supplying the
/// missing fact the only route to a decision: [`resolve`](Self::resolve)
/// takes it as an argument, and [`as_written`](Self::as_written) is named so
/// that using it to decide reads wrong at the call site.
///
/// This adds no check to this crate. It relocates *who must have the fact*
/// from a comment to the type system, which matters because every field of
/// [`AwaitingHuman`] is `pub` and [`HumanWaitSource::Elicitation`] has no
/// constructor here at all — the Phase 3 MCP call site is expected to build
/// one by hand, so anything enforced only inside a constructor is
/// bypassable.
///
/// **The Rust-side obligation does not survive serialization on its own.**
/// A `#[serde(transparent)]` (or any newtype-transparent) wire form is
/// byte-identical to a bare [`OnTimeout`] — `"approve"`, not
/// `{"approve": ...}` — so a hand-rolled consumer that deserializes into a
/// bare `OnTimeout` field (the web UI, an ACP bridge, a park/event record:
/// none of them carry this Rust type) reads it back and grants exactly what
/// [`resolve`](Self::resolve) exists to gate, with no compile-time barrier
/// at all. Dropping `Deserialize` only closed the read-back path *inside
/// this crate*; it closed nothing for a consumer with its own type.
///
/// So the wire form names its own caveat instead of matching `OnTimeout`'s:
/// `{"unchecked": <value>}`. That shape is *useless* to a consumer that
/// naively deserializes into a bare `OnTimeout` — it is an object where
/// `OnTimeout`'s wire form is a string, so the naive read fails loudly
/// instead of succeeding silently — and it puts a name at the call site
/// (`unchecked`) for a renderer author to go find this type's doc comment.
#[derive(Debug, Clone, PartialEq)]
pub struct UncheckedOnTimeout(OnTimeout);

impl Serialize for UncheckedOnTimeout {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("unchecked", &self.0)?;
        map.end()
    }
}

impl UncheckedOnTimeout {
    /// Wraps a document's `on_timeout` without checking anything. Public
    /// because hand-built call sites (elicitation, Phase 3) need it; it
    /// promises nothing beyond "this is what was written".
    pub fn new(on_timeout: OnTimeout) -> Self {
        UncheckedOnTimeout(on_timeout)
    }

    /// Turns the written value into the decision to actually apply, given
    /// §8.11's precondition as resolved by the caller — the executor, which
    /// holds the run's effective policy and the job default.
    ///
    /// [`RunPolicyNarrowing::NotNarrower`] downgrades `Approve` to `Deny`
    /// (fail closed, §8.5 point 5); `Deny`, `Fail` and `Default` carry no
    /// precondition and pass through unchanged regardless of which variant
    /// is supplied.
    pub fn resolve(&self, run_policy: RunPolicyNarrowing) -> OnTimeout {
        match (&self.0, run_policy) {
            (OnTimeout::Approve, RunPolicyNarrowing::NotNarrower) => OnTimeout::Deny,
            (written, _) => written.clone(),
        }
    }

    /// The value as the author wrote it, for **rendering** the wait to a
    /// human ("approves on timeout") — never for deciding it. Deciding is
    /// [`resolve`](Self::resolve).
    pub fn as_written(&self) -> &OnTimeout {
        &self.0
    }
}

/// §8.11's `on_timeout: approve` precondition, stated as a fact
/// [`resolve`](UncheckedOnTimeout::resolve)'s caller must assert in words.
///
/// Not a `bool`: a `bool` parameter is a literal any caller can supply
/// without having computed anything, and the fail-*open* literal (`true`)
/// is exactly as easy to write as the fail-closed one — a future caller
/// (Task 17's executor) that has not yet built the narrowing comparison
/// still compiles with `resolve(true)`, and gets the same escalation this
/// module exists to gate, now wearing the appearance of a discharged
/// obligation. Naming the two states means writing either one requires
/// typing the fact, and `grep -rn NarrowerThanJobDefault` finds every site
/// that asserts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunPolicyNarrowing {
    /// The run's bound policy is narrower than the job's configured
    /// default — §8.11's stated precondition for honoring `approve`.
    NarrowerThanJobDefault,
    /// The precondition does not hold (including "not yet computed"):
    /// `approve` is downgraded to `deny`.
    NotNarrower,
}

/// §8.11's one mechanism: a task waiting on a human, carrying the
/// JSON-Schema form "TUI and web render from the same schema".
///
/// Every field except [`source`](Self::source) is source-independent by
/// construction — that equality is the property `tests/hitl.rs`'s
/// `an_explicit_gate_step_and_a_permission_escalation_produce_the_same_task_shape`
/// pins.
///
/// `Serialize` but deliberately **not** `Deserialize`: a deserialisable
/// `AwaitingHuman` over a *relative* [`timeout_after`](Self::timeout_after)
/// invites a park record to be stored as this struct and re-derived on every
/// resume, which would hand a re-driven park a fresh full window each time —
/// `deny`/`fail` would never fire and the 7-day reaper would become the only
/// bound. A persisted park record must carry the absolute instant Task 17
/// computes, so there is nothing here to read back.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AwaitingHuman {
    pub task_id: TaskId,
    pub source: HumanWaitSource,
    /// A JSON Schema object: `{"type": "object", "title": ..., "properties":
    /// {...}}`. See [`form_schema`].
    pub form_schema: serde_json::Value,
    /// How long the wait lasts from the moment it is parked — **relative**,
    /// not an absolute instant (see this module's doc comment). Named
    /// `timeout_after` rather than `deadline` because "deadline" is the word
    /// an absolute instant would use, and mistaking this for one is what
    /// produces a park that never expires.
    ///
    /// `None` means "no deadline": nothing times this wait out, so
    /// [`on_timeout`](Self::on_timeout) never fires. A `gate:` step always
    /// has one (`timeout:` is mandatory in the wire shape) and so does
    /// `Escalate::Park`; the `None` case is for an elicitation with no
    /// declared window.
    ///
    /// Never [`Duration::ZERO`] when the value came from a document:
    /// [`from_gate`](Self::from_gate) rejects zero, and
    /// `TryFrom<&UnattendedDef>` rejects it before it can reach
    /// [`from_escalate`](Self::from_escalate) — see
    /// [`HitlError::ZeroDeadline`]. `from_escalate` itself takes an
    /// already-parsed [`Duration`] and does not re-check, so a caller that
    /// hands it one, or that builds this struct field by field, can still
    /// produce a zero window.
    pub timeout_after: Option<Duration>,
    /// §8.11's `deny | fail | default(value) | approve`, as written and not
    /// yet checked — see [`UncheckedOnTimeout`] for why that is a type
    /// rather than a caveat. Wraps [`crate::parse::types::OnTimeout`] rather
    /// than restating the grammar, so a gate's `on_timeout` and an
    /// escalation's are the same type; `Default`'s argument stays verbatim
    /// source text, since evaluating `${{ }}` is the expression language's
    /// job at timeout time.
    pub on_timeout: UncheckedOnTimeout,
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
///
/// **Inherited obligation for the web UI task, not handled here.** A gate's
/// field *names* are author-controlled and are carried verbatim into
/// `properties`, so a workflow can declare a field called `__proto__` or
/// `constructor` and that key survives into a JSON object a JavaScript
/// form-builder will iterate. Nesting is structurally sound and outer keys
/// are not shadowed — the schema is a plain `serde_json::Map`, with no
/// prototype semantics on this side — so this is a consumer-side hazard: the
/// renderer must not assign author keys onto a JS object it later reads
/// properties from. Recorded here so the web UI brief inherits it.
///
/// **Two more inherited obligations, same reason.**
/// - A consumer must NOT resolve approval from the mere presence of an
///   `approve` key in a submitted form. `form_schema`'s `properties` names
///   are author-controlled (a `gate:` step can call a field anything,
///   including `approve`, without it meaning what the permission-escalation
///   path's synthesized `approve` boolean means) and presence says nothing
///   about the schema's declared `type`; keying off the field name alone
///   fabricates a decision the author's schema never made.
/// - An author-declared `approve` field of a non-boolean JSON-Schema `type`
///   (e.g. `{"type": "string"}`) is renderer chrome the author chose to
///   label `approve` — it is not the boolean [`UncheckedOnTimeout`] gates,
///   and reading it as a yes/no answer is the same category of mistake as
///   trusting the wire form of `on_timeout` without going through
///   [`UncheckedOnTimeout::resolve`].
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
    /// ([`parse_duration_str`]), so a gate's malformed `timeout: "10 s"` is
    /// rejected exactly as a retry's malformed `base: "10 s"` is. The parser
    /// stops there, though: it accepts `"0s"` as a valid *parse*, and the
    /// policy that zero is an unacceptable configured value lives at each use
    /// site — `resolve_duration` for retry, this function for a gate. Hence
    /// [`HitlError::ZeroDeadline`], which is this path's counterpart to
    /// `RetryPolicyError::ZeroDuration`.
    pub fn from_gate(
        task_id: TaskId,
        title: &str,
        form: &serde_json::Value,
        timeout: &str,
        on_timeout: &OnTimeout,
    ) -> Result<Self, HitlError> {
        // `GateBodyDef::title` is an unconstrained `String`, and an empty one
        // reaches both renderers as an approval prompt with nothing on it
        // saying what is being approved. Rejected rather than debug-asserted:
        // this value comes from untrusted workflow YAML, so a panic — even a
        // debug-only one — would be a worse outcome than the unlabelled
        // prompt it guards against.
        if title.trim().is_empty() {
            return Err(HitlError::EmptyGateTitle);
        }
        let timeout_after =
            parse_duration_str(timeout).map_err(|source| HitlError::InvalidGateTimeout {
                value: timeout.to_string(),
                source,
            })?;
        if timeout_after.is_zero() {
            return Err(HitlError::ZeroDeadline {
                field: "gate.timeout",
                value: timeout.to_string(),
            });
        }
        // `GateBodyDef::form` is an unconstrained `serde_json::Value`, so
        // `form: [1, 2]` parses. Dropping that under `properties` would hand
        // both renderers a JSON Schema neither can render — reject it here
        // instead, at the one point where the value is author-supplied.
        let fields = form.as_object().ok_or(HitlError::FormIsNotAnObject {
            actual: json_type_name(form),
        })?;
        // `form:` is optional (`GateBodyDef` defaults it to `{}`), and an
        // empty properties map is a form with no field expressing the
        // decision — the one shape where §8.11's "TUI and web render from the
        // same schema" would hand the two renderers materially different
        // instructions for the same question, since every escalation gets
        // `{"approve": {"type": "boolean"}}`. A gate that declares nothing
        // therefore asks what an escalation asks. A gate that *does* declare
        // fields has stated the form in full, approve field included if it
        // wants one (§8.9's example writes `form: { approve: {...}, note:
        // {...} }`), and is left exactly as written.
        let fields = if fields.is_empty() {
            permission_approval_fields()
        } else {
            fields.clone()
        };
        Ok(AwaitingHuman {
            task_id,
            source: HumanWaitSource::Gate,
            form_schema: form_schema(title, &fields),
            timeout_after: Some(timeout_after),
            on_timeout: UncheckedOnTimeout::new(on_timeout.clone()),
        })
    }

    /// Turns an [`Escalate::Park`]'s already-evaluated fields into the same
    /// mechanism.
    ///
    /// `title` is the human-readable description of what is being asked —
    /// the caller (the executor, which holds the matched rule and the tool
    /// call) is the only place that knows it, so it is passed in rather than
    /// synthesised here from information this module does not have.
    /// **Caller contract:** it must be non-empty and must name the permission
    /// being asked for; unlike [`from_gate`](Self::from_gate)'s, this title
    /// is built in-process rather than read from untrusted YAML, so it is a
    /// contract rather than a check.
    ///
    /// Infallible, unlike [`from_gate`](Self::from_gate): the timeout is
    /// already a [`Duration`] and the form is this module's own, so there is
    /// nothing left to reject. `Duration::ZERO` is screened out one level up,
    /// where the value is still text
    /// ([`HitlError::ZeroDeadline`] in `TryFrom<&UnattendedDef>`), so that
    /// the rejection can quote what the author wrote.
    pub fn from_escalate(
        task_id: TaskId,
        title: &str,
        timeout_after: Duration,
        on_timeout: &OnTimeout,
    ) -> Self {
        AwaitingHuman {
            task_id,
            source: HumanWaitSource::PermissionEscalate,
            form_schema: form_schema(title, &permission_approval_fields()),
            timeout_after: Some(timeout_after),
            on_timeout: UncheckedOnTimeout::new(on_timeout.clone()),
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
///
/// `Serialize` but deliberately **not** `Deserialize`: deriving it would
/// open a second document path around the `TryFrom` above, and one that
/// cannot even accept the wire syntax — `Duration`'s serde form is
/// `{"secs": N, "nanos": N}`, whereas the shape an author writes is
/// `deadline: "24h"`. Anything that could be deserialised into this type is
/// by construction not the thing a workflow file contains.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Escalate {
    Park {
        /// Keeps §8.5's own field name, but is a *relative* window like
        /// [`AwaitingHuman::timeout_after`] — the value the wait lasts for,
        /// never an absolute instant. It reaches
        /// [`AwaitingHuman::from_escalate`] unchanged. Non-zero on every path
        /// that builds it from a document — `TryFrom<&UnattendedDef>` rejects
        /// zero with [`HitlError::ZeroDeadline`] — though this variant is
        /// `pub`, so a hand-built one can still carry
        /// [`Duration::ZERO`], exactly as a hand-built [`AwaitingHuman`] can.
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
                let parsed = parse_duration_str(deadline).map_err(|source| {
                    HitlError::InvalidEscalateDeadline {
                        value: deadline.clone(),
                        source,
                    }
                })?;
                if parsed.is_zero() {
                    return Err(HitlError::ZeroDeadline {
                        field: "permissions.unattended.deadline",
                        value: deadline.clone(),
                    });
                }
                Ok(Escalate::Park {
                    deadline: parsed,
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
    /// A duration that parses but is degenerate. [`parse_duration_str`]
    /// returns `Ok(Duration::ZERO)` for `"0s"` and always has — zero
    /// rejection was never in the parser, because `"0s"` is a legitimate
    /// *parse* and `resolve_duration` needs `Invalid`/`Overflow`/zero kept
    /// distinct. The policy that zero is an unacceptable *configured value*
    /// belongs at each use site: `RetryPolicyError::ZeroDuration` for retry,
    /// this variant for the two human-wait paths.
    ///
    /// It matters more here than there. A zero window produces a human wait
    /// that is born already expired: it resolves per `on_timeout` with no
    /// human able to see it, while still appearing in the run record as a
    /// configured approval gate — and at the escalate site it does that for
    /// every `PolicyDecision::Ask` in an unattended run. Nothing upstream can
    /// catch it (a gate's `timeout:` is free-form text and
    /// `validate_unattended` checks presence, not content) and nothing
    /// downstream can either, since the parking task receives a `Duration`
    /// and cannot tell an authored `0s` from a legitimately elapsed one.
    /// Rejected rather than clamped to a floor: silently overriding a validly
    /// parsed author statement is the normalisation `resolve_duration`'s doc
    /// comment records this crate as having stopped doing.
    #[error("{field} {value:?} parses to zero, which would park a human wait that is already expired; use a non-zero duration, or drop the approval entirely if no human is meant to see it")]
    ZeroDeadline { field: &'static str, value: String },
    #[error(
        "gate `title` must not be empty — it is the only text the TUI and the web UI have to say what is being approved"
    )]
    EmptyGateTitle,
}
