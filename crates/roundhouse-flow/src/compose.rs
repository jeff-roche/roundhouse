//! §8.12's composition primitives (Task 19, B11): the `call:` budget
//! transfer, the recursion-depth bound, and workflow-as-tool registration.
//!
//! # What this module is, and what it is not
//!
//! Three pure, testable, callable primitives — [`draw_child_budget`] /
//! [`refund_child_budget`], [`child_call_depth`], and [`register_as_tool`].
//! **Nothing calls them yet.** Composition's *run loop* — creating the child
//! `workflow_run`, writing
//! [`WorkflowRun::parent_run_id`](crate::durability::WorkflowRun::parent_run_id),
//! creating the child Session, emitting §8.12's `agent`-kind task standing
//! for the call, and calling all three of these — is **Task 20 (B12)**'s,
//! and [`crate::exec::Executor::dispatch_step`]'s `StepBody::Call` arm stays
//! a stub until then.
//!
//! This is the same primitive/run-loop split the three preceding tasks used:
//! Task 16 (B8) landed the durable state machine with no run loop, Task 17
//! (B9) landed the parking primitives and deliberately left the `Gate` arm a
//! stub, and Task 18 (B10) landed the report schema with no caller. Ruling
//! P75 §A settles it for this task specifically, and this diff corrects
//! `exec/mod.rs`'s stale "Tasks 7/11" attribution in the same commit rather
//! than leaving a second comment naming the wrong owner.
//!
//! # Named gap: `outputs:` is not authorable in the workflow format
//!
//! §8.12 writes *"registered as `workflow:<name>`; `inputs` **is** the tool
//! schema, `outputs` **is** the result."* The first half is implementable
//! today — [`crate::parse::types::WorkflowDef::inputs`] exists, and §8.9 says
//! that schema *"becomes the JSON tool schema when the workflow is exposed as
//! a sub-agent tool."* **The second half is not**: `WorkflowDef` has no
//! `outputs` field and is `#[serde(deny_unknown_fields)]`, so a workflow that
//! writes `outputs:` gets a hard parse error rather than an ignored key —
//! pinned as an observed fact by
//! `outputs_is_not_authorable_in_the_workflow_format_so_no_output_schema_is_registered`
//! in `tests/compose.rs`, which asserts the `parse_workflow` failure directly.
//!
//! [`WorkflowToolRegistration::output_schema`] is therefore `Option` and is
//! **always `None`** today. It is not filled with a fabricated
//! `{"type": "object"}`: a schema that claims to describe a workflow's result
//! while describing nothing is worse than an absent one, because a caller
//! cannot tell the difference. Recorded as a **frozen-contract gap owned by
//! Task 20 (B12)** — the first task with a run loop, hence the first that can
//! observe what a workflow's result actually *is* and therefore judge whether
//! `outputs:` should be a declared block in `parse/types.rs` or derived from
//! the run's `report`/`finally` shape. Adding the field means touching
//! `parse/types.rs`'s wire shape, which this task deliberately does not do.
//! This is the same shape as `durability.rs`'s `on_crash:` gap (ruling P68 §D).
//!
//! # Named deferral: [`WorkflowToolRegistration`] plugs into nothing today
//!
//! §8.12's "registered as" implies registration *somewhere*. That somewhere
//! is the `tools: Vec<ToolDef>` an `infer` task carries, and
//! `roundhouse_provider::ToolDef` is **structurally unreachable from this
//! crate**: it has private fields, its only wire-sourced constructor is
//! `ToolDef::from_wire_parts`, and §5.2's dependency row for `roundhouse-flow`
//! is `core, engine, store` — `roundhouse-engine` depends on
//! `roundhouse-provider` but does not re-export `ToolDef`, so this crate
//! cannot name the type at all.
//!
//! So [`WorkflowToolRegistration`] is a **parallel shape, not a registration**.
//! It is constructed by no caller, handed to no registry, and reaches no
//! model. This is the same structural deferral
//! [`crate::exec::map_step`] records for `map.isolation`/worktree fan-out —
//! the capability is absent from the crate's dependency row, not omitted by
//! choice — but stating it is the point: the plan presented this type as the
//! deliverable without saying it connects to nothing.
//!
//! **Owner of the bridge:** whichever crate can name both types. That is
//! `roundhouse-engine` (which depends on `roundhouse-provider`) or
//! `roundhouse-daemon` (which may depend on everything); it is *not*
//! `roundhouse-flow`, and closing it here would require either a §5.2
//! dependency-row change or a `ToolDef` re-export — both frozen-contract
//! edits, hence escalations rather than task-local decisions.
//!
//! ## Open question the bridge must answer: does `workflow:<name>` share a
//! namespace with MCP's `{server}__{tool}`?
//!
//! `roundhouse_mcp::McpHost::tool_defs()` is described in its own doc comment
//! as *"the single source an `infer` task's `tools: Vec<ToolDef>` draws
//! from."* If a workflow tool joins that same vector, three properties of
//! `roundhouse-mcp/src/namespace.rs` become this module's problem and none of
//! them is decided:
//!
//! 1. MCP names are **sanitized** (`namespace.rs:27-37`: every character
//!    outside `[a-z0-9_-]` becomes `_`), so an MCP name can never contain
//!    `:`. `workflow:<name>` as emitted here is therefore collision-free
//!    against MCP **as long as the colon survives**. Nothing here sanitizes
//!    or length-checks the workflow name.
//! 2. If some later layer sanitizes the colon the way MCP does, the collision
//!    reappears: a workflow named `_pr-review` becomes `workflow__pr-review`,
//!    which is exactly what MCP server `workflow` with tool `pr-review`
//!    produces.
//! 3. MCP truncates at 64 characters with a blake3 suffix
//!    (`namespace.rs:39-54`) because *"most model-facing tool-name fields cap
//!    out around 64 chars across providers"* — that is `roundhouse-mcp`'s
//!    recorded reasoning, not a provider limit this task verified. A
//!    `workflow:<name>` is subject to no such bound here.
//!
//! Whether a workflow may shadow an MCP tool is a policy question for the
//! bridge's owner, not something this module should answer unilaterally by
//! picking a mangling.

use crate::caps::ResourceCaps;
use crate::job::JobVersion;
use crate::parse::types::{InputDef, InputType};
use crate::parse::{parse_workflow, ParseError};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;

// ---------------------------------------------------------------------------
// The recursion bound
// ---------------------------------------------------------------------------

/// Hard, closed-fail cap on how deep a chain of `call:` sub-workflows may
/// nest. The root run is depth 0; each `call:` produces a child one deeper,
/// so this permits at most four nested child runs beneath a root.
///
/// # Why this exists at all
///
/// **Before this constant, nothing in the workspace bounded workflow
/// recursion.** `call:` targets are resolved neither at parse time nor at run
/// time, so `call: self` parses without complaint.
/// [`crate::parse::MAX_FLOW_NESTING_DEPTH`] is unrelated (it bounds YAML
/// flow-collection nesting in raw text and its own doc says it is not a bound
/// on parse cost), and [`crate::exec::map_step::MAX_MAP_ITEMS`] bounds
/// **one** `map` call and says so explicitly — the product across nested
/// `map`s is not bounded by it. §8.12 mandates the fix in one clause,
/// *"Recursion depth and fan-out budget enforced at admission"*, and this is
/// the recursion-depth half of it.
///
/// # Why 4, specifically — and which part of that is inference
///
/// **§8.12 names no number for `call:` depth.** The number comes from §7.7
/// (`docs/architecture/04-messaging-and-teams.md`), which does: *"**Depth
/// limit** 4 (inherited +1 per spawn)"*, for sub-agent spawning.
///
/// The step from there to here is an **inference, not a quotation**. §8.12
/// invokes §7.7 by name for the *budget* model only (*"following §7.7's
/// sub-agent budget model exactly"*). What licenses reusing its depth number
/// is a different sentence: §8.12 says a `call:` *"creates a child
/// `workflow_run` **and a child Session**"* and that the parent's log gets
/// *"one `agent`-kind task standing for the call — identical to sub-agent
/// spawning, which is the point."* A `call:` chain and a sub-agent chain are
/// therefore the same chain of nested Sessions, and two different ceilings
/// over one chain would mean the effective limit depends on which noun the
/// author reached for. One ceiling, 4, is the choice; the frozen doc did not
/// make it for this case.
///
/// # What this bounds, and what it does not — arithmetic, not measurement
///
/// This bounds **depth**. It does **not** bound total work, and the numbers
/// say so plainly: with this constant at 4 and
/// [`MAX_MAP_ITEMS`](crate::exec::map_step::MAX_MAP_ITEMS) at 2,000, a
/// workflow that maps over 2,000 items and calls a workflow that maps over
/// 2,000 items, four deep, is `2000^4` = 1.6x10^13 leaf runs. That is
/// arithmetic over two constants, not a measurement.
///
/// The half that bounds total work is [`draw_child_budget`]: every `call:`
/// withdraws from the parent's remaining pool, so a subtree's total spend is
/// capped by the root's grant no matter how wide it fans. **That half is not
/// enforced yet** — the ledger it would draw against is
/// [`crate::exec::map_step::MapBudget::unenforced_placeholder`], and the
/// admission chokepoint is Task 20's (see [`ResourceCaps`]'s own doc
/// comment). So today: depth is bounded by a real predicate as soon as
/// anyone threads a depth counter through it; fan-out is bounded by
/// arithmetic that no ledger yet feeds.
///
/// **Not measured:** no `call:` chain of any depth has been executed, because
/// [`crate::exec::Executor::dispatch_step`]'s `StepBody::Call` arm is a stub.
/// Nothing here is a claim about runtime cost. [`child_call_depth`] itself is
/// one saturating add and one comparison, with no allocation and no I/O; that
/// is a description of the code, not a benchmark.
///
/// # What Task 20 must supply
///
/// A parent's depth. `workflow_run` has no depth column, but it does have
/// `parent_run_id` (store migration 0006), so depth is derivable by walking
/// that chain — at a cost of one row read per level, which is why a stored
/// column may still be the better answer. Either way the decision is Task
/// 20's; this predicate takes the number rather than sourcing it.
pub const MAX_CALL_DEPTH: u32 = 4;

/// Why a `call:` was refused before it created anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CallDepthError {
    #[error(
        "`call:` refused: a child of a run at depth {parent_depth} would be at depth {attempted}, \
         exceeding the maximum call depth of {max} (the root run is depth 0)"
    )]
    TooDeep {
        parent_depth: u32,
        attempted: u32,
        max: u32,
    },
}

/// The depth a `call:`'s child run would have, or [`CallDepthError::TooDeep`]
/// if that exceeds [`MAX_CALL_DEPTH`]. The root run is depth 0.
///
/// Fail-closed in both directions: a parent depth already at or past the
/// limit is refused, and the increment **saturates** rather than wrapping, so
/// a corrupt or hostile `u32::MAX` depth cannot roll over to 0 and hand back a
/// fresh depth budget. (`u32::MAX` saturates to `u32::MAX`, which is greater
/// than [`MAX_CALL_DEPTH`], so it is refused — pinned by
/// `a_parent_depth_at_the_integer_ceiling_is_refused_rather_than_wrapping_to_zero`.)
pub fn child_call_depth(parent_depth: u32) -> Result<u32, CallDepthError> {
    let attempted = parent_depth.saturating_add(1);
    if attempted > MAX_CALL_DEPTH {
        return Err(CallDepthError::TooDeep {
            parent_depth,
            attempted,
            max: MAX_CALL_DEPTH,
        });
    }
    Ok(attempted)
}

// ---------------------------------------------------------------------------
// The budget transfer
// ---------------------------------------------------------------------------

/// What [`draw_child_budget`] withdrew from a parent's pool: the child's caps,
/// and — because a draw is a transfer — the record of exactly what left the
/// parent, which is the only thing [`refund_child_budget`] will put back.
///
/// # Why this is a token and not a bare `ResourceCaps`
///
/// The plan's `refund_child_budget(parent, unspent: &ResourceCaps)` lets any
/// caller add arbitrary budget to a parent's pool. That directly contradicts
/// §8.12's invariant — *"A workflow subtree can never spend more than its
/// root was given"* — because a refund larger than the draw mints budget that
/// the root never granted. Passing the grant back in means the unspent amount
/// is **computed** (`grant - spent`, floored at zero) rather than trusted.
///
/// Three properties follow from the type, not from caller discipline:
///
/// - **Not `Clone`, and consumed by value.** A grant can be refunded exactly
///   once. Double-refunding a retried `call:` is a compile error, not a
///   runtime budget leak upward.
/// - **Constructible only by [`draw_child_budget`]** (private field), so a
///   refund token always corresponds to a real withdrawal.
/// - **Neither `Serialize` nor `Deserialize`.** Same reasoning as
///   [`crate::hitl::AwaitingHuman`]'s deliberately-absent `Deserialize`: a
///   value that can be persisted and re-loaded can be re-minted, and the
///   whole point of this type is that it cannot be. See "residual" below for
///   what that costs.
///
/// # `#[must_use]`, and what dropping one means
///
/// Dropping a `ChildBudget` without refunding forfeits the drawn budget: it
/// stays withdrawn from the parent forever. That is the **safe** direction of
/// the invariant (the subtree under-spends its root's grant, never over), so
/// it is a warning rather than an error — but it is silent, hence
/// `#[must_use]`.
///
/// # Residual: a child that parks and never completes is never refunded
///
/// §8.12 says the draw is *"refunded on completion"*, which presumes
/// completion. A child that parks on a `gate:` and is never answered has no
/// defined refund behaviour, and this module cannot give it one: accounting
/// for it needs the durable park-interval record that
/// [`ResourceCaps`]'s own doc comment says **does not exist** and assigns to
/// Task 20 (B12) — an in-process tracker would lose exactly the multi-day
/// park it exists to measure across a daemon restart. Compounding it, this
/// token is deliberately non-`Deserialize`, so a daemon restart loses the
/// in-process grant record too and Task 20 must re-derive the refund from
/// durable rows rather than from a rehydrated token. **Named, not closed;
/// owner Task 20.**
#[derive(Debug, PartialEq)]
#[must_use = "a drawn budget must be refunded to the parent, or it is forfeited"]
pub struct ChildBudget {
    caps: ResourceCaps,
}

impl ChildBudget {
    /// The caps granted to the child run.
    pub fn caps(&self) -> &ResourceCaps {
        &self.caps
    }
}

/// §8.12: *"Cost rollup is a real transfer, not just a display rollup … the
/// child's `max_cost_usd`/`max_tokens` are drawn from the parent's remaining
/// budget, refunded on completion, enforced. A workflow subtree can never
/// spend more than its root was given."*
///
/// Every field of `parent_remaining` is read as *what is left*, and every
/// countable one is decremented by what the child got. `requested` is a
/// ceiling the child asks for, never a floor it is owed: the grant is
/// `min(requested, remaining)` in every field.
///
/// # Which fields the doc names, and which follow from the invariant
///
/// **Named explicitly by §8.12:** `max_cost_usd` and `max_tokens`. Those two,
/// and no others.
///
/// **Drawn anyway, by inference from the invariant** — *"a workflow subtree
/// can never spend more than its root was given"* is a statement about the
/// subtree's consumption, and every one of these is a thing a subtree
/// consumes: `max_tool_calls`, `max_tasks`, `max_subagents`,
/// `max_escalations`, `max_bytes_written`. Drawing only the two named fields
/// would leave a child free to request the *full* default of the other five
/// from a parent with none left, which asserts the invariant over two tenths
/// of the ceiling it is supposed to cover. This is an inference from §8.12's
/// invariant, stated as one; it is not a quotation.
///
/// # The three `Duration`s are clamped, not withdrawn
///
/// `run_wall_timeout`, `run_active_timeout` and `step_timeout` are set to
/// `min(requested, parent's remaining)` and the parent's are left untouched.
/// Wall-clock time is not a pool that divides: a parent's clock keeps running
/// while its child runs inside it, so subtracting the child's window from the
/// parent's would charge the same seconds twice. Clamping is what enforces
/// the property that matters — a child can never outlive the parent's
/// window, so a five-minutes-remaining parent cannot spawn a 24-hour child.
/// This mirrors [`crate::exec::map_step::split_budget`], which divides the
/// countables across items and explicitly does not divide the timeouts
/// (*"the run-level timeouts are wall-clock, not a resource that divides
/// sensibly"*). Two functions, same fact about time, opposite operations:
/// `split_budget` passes timeouts through unchanged because every item runs
/// inside one run's window; this clamps them because a child run has a window
/// of its own that must nest inside the parent's.
///
/// **Keeping the `Duration` fields meaning "remaining" is the caller's job.**
/// This crate reads no clock at all (same rule as [`crate::parking`], whose
/// `now` is a parameter everywhere), so it cannot decrement a window by
/// elapsed time. Task 20 owns the run loop and therefore owns keeping
/// `parent_remaining`'s timeouts honest between calls.
///
/// # Hostile `f64` input
///
/// `max_cost_usd` is `f64` (see [`ResourceCaps`]'s recorded deviation from
/// §8.4's `Decimal`) and reaches this function from workflow YAML's `caps:`
/// block, where `.nan`, `-1e18` and `.inf` are all authorable scalars.
/// Unguarded, `parent -= requested.min(parent)` with a *negative* request
/// raises the parent's remaining budget — minting money by writing a minus
/// sign. Non-finite or negative requests therefore draw exactly `0.0`; see
/// `draw_f64` below. Pinned by
/// `a_nan_or_negative_requested_cost_draws_nothing_rather_than_minting_budget`.
pub fn draw_child_budget(
    parent_remaining: &mut ResourceCaps,
    requested: &ResourceCaps,
) -> ChildBudget {
    let max_cost_usd = draw_f64(requested.max_cost_usd, parent_remaining.max_cost_usd);
    let max_tokens = requested.max_tokens.min(parent_remaining.max_tokens);
    let max_tasks = requested.max_tasks.min(parent_remaining.max_tasks);
    let max_tool_calls = requested
        .max_tool_calls
        .min(parent_remaining.max_tool_calls);
    let max_subagents = requested.max_subagents.min(parent_remaining.max_subagents);
    let max_bytes_written = requested
        .max_bytes_written
        .min(parent_remaining.max_bytes_written);
    let max_escalations = requested
        .max_escalations
        .min(parent_remaining.max_escalations);

    // Computed before the mutations below, so this function does not depend on
    // the order its own writes happen in. (The mutations touch no `Duration`
    // field, so the values would be identical either way — but that is a fact
    // a reader would have to check, and this way there is nothing to check.)
    let run_wall_timeout = clamp_duration(
        requested.run_wall_timeout,
        parent_remaining.run_wall_timeout,
    );
    let run_active_timeout = clamp_duration(
        requested.run_active_timeout,
        parent_remaining.run_active_timeout,
    );
    let step_timeout = clamp_duration(requested.step_timeout, parent_remaining.step_timeout);

    // `min` above makes each of these `drawn <= remaining`, so none of these
    // subtractions can underflow; `saturating_sub` costs nothing and means a
    // future edit that breaks that property clamps instead of wrapping.
    //
    // The `.max(0.0)` on the dollar line does double duty: `f64::max` returns
    // the non-`NaN` operand, so a `parent_remaining.max_cost_usd` that arrives
    // as `NaN` (from which `draw_f64` already drew nothing) is normalised
    // *down* to an empty pool rather than staying `NaN` and poisoning every
    // later comparison.
    parent_remaining.max_cost_usd = (parent_remaining.max_cost_usd - max_cost_usd).max(0.0);
    parent_remaining.max_tokens = parent_remaining.max_tokens.saturating_sub(max_tokens);
    parent_remaining.max_tasks = parent_remaining.max_tasks.saturating_sub(max_tasks);
    parent_remaining.max_tool_calls = parent_remaining
        .max_tool_calls
        .saturating_sub(max_tool_calls);
    parent_remaining.max_subagents = parent_remaining.max_subagents.saturating_sub(max_subagents);
    parent_remaining.max_bytes_written = parent_remaining
        .max_bytes_written
        .saturating_sub(max_bytes_written);
    parent_remaining.max_escalations = parent_remaining
        .max_escalations
        .saturating_sub(max_escalations);

    ChildBudget {
        caps: ResourceCaps {
            run_wall_timeout,
            run_active_timeout,
            step_timeout,
            max_tokens,
            max_cost_usd,
            max_tasks,
            max_tool_calls,
            max_subagents,
            max_bytes_written,
            max_escalations,
        },
    }
}

/// The *"refunded on completion"* half of §8.12's transfer model: whatever
/// the child did not spend of its grant flows back into the parent's pool.
///
/// `spent` is the child's measured consumption. The refund is
/// `grant - spent`, floored at zero per field — never `spent` itself and
/// never a caller-supplied "unspent" figure, so no call site can return more
/// than [`draw_child_budget`] took out. A child reporting a spend larger than
/// its grant, or an unusable one (`NaN`, negative, infinite), refunds
/// **nothing**: the safe direction.
///
/// The three `Duration`s are absent from the refund because they were never
/// withdrawn — see [`draw_child_budget`].
pub fn refund_child_budget(
    parent_remaining: &mut ResourceCaps,
    drawn: ChildBudget,
    spent: &ResourceCaps,
) {
    let grant = drawn.caps;

    parent_remaining.max_cost_usd += refund_f64(grant.max_cost_usd, spent.max_cost_usd);
    parent_remaining.max_tokens = parent_remaining
        .max_tokens
        .saturating_add(grant.max_tokens.saturating_sub(spent.max_tokens));
    parent_remaining.max_tasks = parent_remaining
        .max_tasks
        .saturating_add(grant.max_tasks.saturating_sub(spent.max_tasks));
    parent_remaining.max_tool_calls = parent_remaining
        .max_tool_calls
        .saturating_add(grant.max_tool_calls.saturating_sub(spent.max_tool_calls));
    parent_remaining.max_subagents = parent_remaining
        .max_subagents
        .saturating_add(grant.max_subagents.saturating_sub(spent.max_subagents));
    parent_remaining.max_bytes_written = parent_remaining.max_bytes_written.saturating_add(
        grant
            .max_bytes_written
            .saturating_sub(spent.max_bytes_written),
    );
    parent_remaining.max_escalations = parent_remaining
        .max_escalations
        .saturating_add(grant.max_escalations.saturating_sub(spent.max_escalations));
}

/// `min(requested, remaining)` for a dollar budget, fail-closed on every `f64`
/// value that is not a usable non-negative amount. `NaN` requests draw `0.0`
/// rather than propagating (`f64::min` would silently return the *other*
/// operand for a `NaN`, i.e. hand the child the parent's whole pool), and a
/// `NaN` or negative `remaining` is treated as an empty pool.
fn draw_f64(requested: f64, remaining: f64) -> f64 {
    if !requested.is_finite() || requested <= 0.0 {
        return 0.0;
    }
    if !remaining.is_finite() || remaining <= 0.0 {
        return 0.0;
    }
    requested.min(remaining)
}

/// The unspent part of a dollar grant. An unusable reported spend refunds
/// nothing — the direction that cannot inflate the parent's pool.
fn refund_f64(grant: f64, spent: f64) -> f64 {
    if !spent.is_finite() || spent < 0.0 {
        return 0.0;
    }
    (grant - spent).max(0.0)
}

/// A child's window nests inside its parent's; it never widens it.
fn clamp_duration(requested: Duration, remaining: Duration) -> Duration {
    requested.min(remaining)
}

// ---------------------------------------------------------------------------
// Workflow-as-tool
// ---------------------------------------------------------------------------

/// §8.12's *"registered as `workflow:<name>`"*, as far as this crate can
/// express it. **This is a shape, not a registration** — see the module doc
/// comment's "Named deferral" section for why `roundhouse_provider::ToolDef`
/// is unreachable from here, who owns the bridge, and the undecided
/// namespace question with MCP's `{server}__{tool}`.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkflowToolRegistration {
    /// `workflow:<the parsed workflow's own `name:`>`. Not sanitized and not
    /// length-bounded — see the module doc's namespace question.
    pub name: String,
    /// The workflow's `inputs:` block as a JSON Schema object, per §8.9's
    /// *"the `inputs:` schema does triple duty … becomes the JSON tool schema
    /// when the workflow is exposed as a sub-agent tool."*
    pub input_schema: Value,
    /// **Always `None`.** §8.12 says `outputs` is the result, but the
    /// workflow format has no `outputs:` block — see the module doc's "Named
    /// gap" section. Not a fabricated `{"type": "object"}`.
    pub output_schema: Option<Value>,
}

/// Builds a [`WorkflowToolRegistration`] from a job version.
///
/// `job_name` is used **only** to lower a [`crate::job::Body::Prompt`] body,
/// which synthesizes its YAML and has no `name:` of its own (§8.3: a prompt
/// job is sugar for a single-step workflow). For a
/// [`crate::job::Body::Workflow`] body the YAML's own `name:` is
/// authoritative and `job_name` is ignored —
/// [`crate::job::Body::to_workflow_yaml`] returns that body's text verbatim.
/// One rule either way: the tool name is always
/// `workflow:<parsed WorkflowDef.name>`.
///
/// # Returns the parse error rather than swallowing it
///
/// The plan's `parse_workflow(..).map(|d| d.name).unwrap_or_else(|_| "unknown")`
/// turned an unparsable body into a cheerfully-registered
/// `workflow:unknown` — a tool exposed to a model under a name that says
/// nothing, for a workflow that cannot run. A job whose body does not parse
/// is not a tool; this returns the [`ParseError`] (ruling P75 §D.3).
///
/// # `inputs:` here means `WorkflowDef.inputs`, not `JobVersion::input_schema`
///
/// Two different objects with two different shapes.
/// [`crate::job::InputSchema`] is *"a job's declared input JSON Schema,
/// validated against the run inputs supplied at trigger time"* — a raw
/// `serde_json::Value` the job carries. §8.9's sentence is about the
/// workflow's `inputs:` YAML block, which is what this reads.
pub fn register_as_tool(
    job: &JobVersion,
    job_name: &str,
) -> Result<WorkflowToolRegistration, ParseError> {
    let yaml = job.body().to_workflow_yaml(job_name, job.version());
    let def = parse_workflow(&yaml)?;
    Ok(WorkflowToolRegistration {
        name: format!("workflow:{}", def.name),
        input_schema: inputs_to_json_schema(&def.inputs),
        output_schema: None,
    })
}

/// Renders `inputs:` as a JSON Schema object.
///
/// Keys are emitted in **sorted** order and `required` is a sorted array.
/// `WorkflowDef.inputs` is a `HashMap`, whose iteration order is randomised
/// per process, so an unsorted rendering would produce a schema that differs
/// shape-to-shape between daemon restarts once `serde_json`'s
/// `preserve_order` is on (ruling P29) — and a tool schema that is not
/// stable is not cacheable or hashable. Pinned by
/// `required_input_names_are_emitted_in_a_deterministic_sorted_order`.
///
/// `required` is omitted entirely when no input is required, rather than
/// emitted as an empty array.
fn inputs_to_json_schema(inputs: &HashMap<String, InputDef>) -> Value {
    let mut names: Vec<&String> = inputs.keys().collect();
    names.sort();

    let mut properties = Map::new();
    let mut required = Vec::new();
    for name in names {
        let def = &inputs[name];
        let mut prop = Map::new();
        prop.insert("type".to_string(), json!(json_schema_type(def.ty)));
        if let Some(default) = &def.default {
            prop.insert("default".to_string(), default.clone());
        }
        properties.insert(name.clone(), Value::Object(prop));
        if def.required {
            required.push(Value::String(name.clone()));
        }
    }

    let mut schema = Map::new();
    schema.insert("type".to_string(), json!("object"));
    schema.insert("properties".to_string(), Value::Object(properties));
    if !required.is_empty() {
        schema.insert("required".to_string(), Value::Array(required));
    }
    Value::Object(schema)
}

/// [`InputType`]'s JSON Schema `type` keyword. Written out rather than routed
/// through `InputType`'s `Serialize` impl so that adding a variant is a
/// compile error here (this match has no wildcard) instead of silently
/// inheriting whatever serde renames it to.
fn json_schema_type(ty: InputType) -> &'static str {
    match ty {
        InputType::String => "string",
        InputType::Integer => "integer",
        InputType::Number => "number",
        InputType::Boolean => "boolean",
        InputType::Array => "array",
        InputType::Object => "object",
    }
}
