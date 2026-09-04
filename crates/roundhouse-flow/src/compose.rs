//! §8.12's composition primitives (Task 19, B11): the `call:` budget
//! transfer, the recursion-depth and fan-out bounds, and workflow-as-tool
//! registration.
//!
//! # What this module is, and what it is not
//!
//! Four pure, testable, callable primitives — [`draw_child_budget`] /
//! [`refund_child_budget`], [`child_call_depth`], [`admit_child_call`], and
//! [`register_as_tool`].
//! Composition's *run loop* — creating the child `workflow_run`, writing
//! [`WorkflowRun::parent_run_id`](crate::durability::WorkflowRun::parent_run_id),
//! creating the child Session, and emitting §8.12's `agent`-kind task
//! standing for the call — is **B12c**'s, and
//! [`crate::exec::Executor::dispatch_step`]'s `StepBody::Call` arm stays a
//! stub until then.
//!
//! **B12b closed the sourcing half.** [`crate::ledger::admit_call_from_run`]
//! reads the parent run's `session_depth` (migration 0008) and calls both
//! bounds, and [`crate::ledger::refund_child_run`] is the durable twin of the
//! draw/refund pair — see [`MAX_CALL_DEPTH`]'s "What Task 20 must supply",
//! which is about the **session** chain and not the `parent_run_id` chain,
//! and [`ChildBudget`]'s two residuals, one of which that function closes.
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
//! 4. **Workflow-vs-workflow collides before MCP ever enters it.** The tool
//!    name is `workflow:<WorkflowDef.name>`, and nothing makes that name
//!    unique: two different jobs whose bodies both declare `name: pr-review`
//!    both register as `workflow:pr-review`. The job's own identity
//!    ([`crate::job::JobVersion`]'s `JobId`/version) does not appear in the
//!    name at all. Which one a model reaches, and whether the second
//!    registration should be refused or should disambiguate, is the same
//!    bridge owner's decision.
//! 5. **`WorkflowDef.name` is unbounded and unfiltered, and flows into a
//!    model-facing field.** [`crate::parse::parse_workflow`] applies no length
//!    limit and no character filter to `name:`, so whatever a workflow author
//!    writes there — including newlines, or a megabyte of text — reaches
//!    [`WorkflowToolRegistration::name`] verbatim. This module deliberately
//!    does not sanitize it (picking a mangling is the decision above), but it
//!    is recorded here rather than left for the bridge to discover.
//!
//! Whether a workflow may shadow an MCP tool, or another workflow, is a policy
//! question for the bridge's owner, not something this module should answer
//! unilaterally by picking a mangling.

use crate::caps::ResourceCaps;
use crate::job::JobVersion;
use crate::parse::types::{InputDef, InputType};
use crate::parse::{parse_workflow, ParseError};
use roundhouse_engine::limits;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;

// ---------------------------------------------------------------------------
// The recursion bound
// ---------------------------------------------------------------------------

/// Hard, closed-fail cap on how deep a chain of `call:` sub-workflows may
/// nest. The root run is depth 0; each `call:` produces a child one deeper,
/// so this permits at most `MAX_CALL_DEPTH` nested child runs beneath a root
/// — four, at §7.7's current number.
///
/// # This is §7.7's existing constant, not a second ceiling
///
/// It is [`roundhouse_engine::limits::MAX_DEPTH`] widened from `u8` to `u32` —
/// **one definition, aliased, not a copy** — so §7.7's number cannot drift
/// between this predicate and `roundhouse_engine::agent_spawn`'s
/// `check_depth`, which has enforced it on every sub-agent spawn since Phase
/// 4. `roundhouse-flow` cannot depend on `roundhouse-bus` (§5.2's row for this
/// crate is `core, engine, store`), so the constant is reached over the
/// `flow -> engine` edge §5.2 does grant, via a `pub use
/// roundhouse_bus::limits;` in `roundhouse-engine`'s `lib.rs`.
///
/// An earlier version of this constant was a local literal `4` justified as
/// *"nothing in the workspace bounded workflow recursion"*. That was false as
/// stated (ruling P76): `roundhouse-bus/src/limits.rs` already carried this
/// exact number under the identical §7.7 citation, so what landed was the
/// second of the two ceilings the next section explicitly rejects. What was
/// true, and is what this predicate adds, is that nothing bounded the `call:`
/// chain specifically — because [`crate::exec::Executor::dispatch_step`]'s
/// `StepBody::Call` arm never resolved a target at all, so `call: self` parses
/// and would recurse without complaint.
///
/// The two neighbouring bounds remain unrelated:
/// [`crate::parse::MAX_FLOW_NESTING_DEPTH`] bounds YAML flow-collection
/// nesting in raw text and its own doc says it is not a bound on parse cost,
/// and [`crate::exec::map_step::MAX_MAP_ITEMS`] bounds **one** `map` call and
/// says so explicitly.
///
/// # Why the sub-agent limit is the right one — and which part is inference
///
/// **§8.12 names no number for `call:` depth.** The number comes from §7.7
/// (`docs/architecture/04-messaging-and-teams.md`), which does: *"**Depth
/// limit** 4 (inherited +1 per spawn). **Fan-out** ≤8 direct children per
/// session, ≤32 live sessions per team."*
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
/// author reached for. One ceiling is the choice; the frozen doc did not make
/// it for this case.
///
/// # What this bounds, and what it does not — arithmetic, not measurement
///
/// This bounds **depth**: the exponent, not the base. §8.12's clause is
/// *"Recursion depth and fan-out budget enforced at admission"*, and §7.7
/// gives fan-out in two forms, only one of which is a count:
///
/// - **Fan-out as a count** — §7.7's *"≤8 direct children per session"*. That
///   is [`admit_child_call`] / [`MAX_DIRECT_CHILD_CALLS`], landed alongside
///   this and bounding the base. Without it, a `map` over
///   [`MAX_MAP_ITEMS`](crate::exec::map_step::MAX_MAP_ITEMS) = 2,000 items
///   each issuing one `call:` is 2,000 direct children at depth 1 for which
///   `child_call_depth(0)` returns `Ok(1)` every time, and the widest tree
///   four deep is `2000^4` = 1.6x10^13 leaf runs. With both bounds it is
///   `8^4` = 4,096. Arithmetic over the constants, not a measurement.
/// - **Fan-out as a budget pool** — §7.7's transfer model, which is
///   [`draw_child_budget`]: every `call:` withdraws from the parent's
///   remaining pool, so a subtree's total *spend* is capped by the root's
///   grant. **The ledger that half draws against exists as of B12b** —
///   [`crate::ledger::remaining_caps`] and [`crate::ledger::admit_spend`],
///   over migration 0008's columns — but the thing that calls the chokepoint
///   once per task is the run loop's, and that is B12c.
///
/// **Not measured:** no `call:` chain of any depth or width has been executed,
/// because the `StepBody::Call` arm is a stub, and neither predicate has a
/// caller. Nothing here is a claim about runtime cost. Each of
/// [`child_call_depth`] and [`admit_child_call`] is one saturating add and one
/// comparison, with no allocation and no I/O; that is a description of the
/// code, not a benchmark.
///
/// # What Task 20 must supply: the SESSION depth, not a `parent_run_id` walk
///
/// The number handed to [`child_call_depth`] must be the **same number**
/// `roundhouse_engine::agent_spawn` takes as its `parent_depth`: how deep the
/// parent's *Session* sits in the session tree. It must **not** be a
/// workflow-run depth derived by walking
/// [`WorkflowRun::parent_run_id`](crate::durability::WorkflowRun::parent_run_id),
/// which an earlier version of this comment told Task 20 to do.
///
/// Why (ruling P76 §1): those are two independent counters over one session
/// tree. §8.12's `call:` creates a child Session, so a sub-agent already at
/// session depth 3 that starts a workflow run would begin its `call:` chain at
/// run-depth 0 and be granted four more — **session depth 7 against §7.7's
/// limit of 4, with `check_depth` and `child_call_depth` both returning `Ok`
/// at every step.** Counting the session chain in both predicates closes that;
/// counting two chains cannot, however carefully each is implemented.
///
/// **`workflow_run.session_depth` is that number, as of migration 0008**, and
/// [`crate::ledger::admit_call_from_run`] is the chokepoint that reads it and
/// calls both this predicate and [`admit_child_call`]. A run whose column is
/// `NULL` — written before 0008, or by a caller that could not determine the
/// depth — is **refused** rather than read as depth 0, which would be the
/// same escape reached through the schema instead of through the wrong
/// counter. This predicate itself still takes the number rather than sourcing
/// it, so it stays pure and table-testable; `u8` widens into `u32`
/// losslessly, so a caller holding `agent_spawn`'s depth passes it through
/// unchanged.
pub const MAX_CALL_DEPTH: u32 = limits::MAX_DEPTH as u32;

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
// The fan-out bound
// ---------------------------------------------------------------------------

/// Hard, closed-fail cap on how many direct `call:` children one run may have.
///
/// [`roundhouse_engine::limits::MAX_FAN_OUT`] — the *same* constant aliased,
/// for the same reason [`MAX_CALL_DEPTH`] is: §7.7 gives depth and fan-out in
/// **one sentence** (*"**Depth limit** 4 (inherited +1 per spawn). **Fan-out**
/// ≤8 direct children per session, ≤32 live sessions per team."*), §8.12's
/// `call:` creates a child Session exactly as a sub-agent spawn does, and
/// `roundhouse_engine::agent_spawn` already enforces this number on the other
/// half of the same session tree. Quoting the first clause and leaving the
/// second is how the larger of the two factors stayed open (ruling P76 §3).
///
/// # Why this bound is the load-bearing one
///
/// [`MAX_CALL_DEPTH`] bounds the exponent; this bounds the base. See
/// [`MAX_CALL_DEPTH`]'s "What this bounds, and what it does not" for the
/// `2000^4` vs `8^4` arithmetic, which is arithmetic over constants rather
/// than a measurement of anything.
///
/// # §7.7's third clause is not bounded here
///
/// *"≤32 live sessions per team"* is [`roundhouse_engine::limits::MAX_TEAM_SIZE`]
/// and this crate cannot enforce it: team membership lives in
/// `roundhouse-bus`'s roster, which `roundhouse-flow` cannot read (§5.2).
/// `agent_spawn` checks it via `check_team_size` on every spawn, so whichever
/// caller actually creates a `call:`'s child Session inherits that check with
/// it — this is a note about where the clause is enforced, not a claim that
/// this module enforces it.
pub const MAX_DIRECT_CHILD_CALLS: u32 = limits::MAX_FAN_OUT;

/// Why a `call:` was refused before it created anything — the width half,
/// [`CallDepthError`] being the depth half.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CallFanOutError {
    #[error(
        "`call:` refused: a run with {existing_direct_children} direct `call:` children would \
         have {attempted}, exceeding the maximum of {max} direct children per run"
    )]
    TooWide {
        existing_direct_children: u32,
        attempted: u32,
        max: u32,
    },
}

/// The direct-child count a `call:` would bring its parent run to, or
/// [`CallFanOutError::TooWide`] if that exceeds [`MAX_DIRECT_CHILD_CALLS`].
///
/// Mirrors `roundhouse_engine::agent_spawn`'s `check_fan_out` call exactly:
/// the number checked is the count **after** this `call:` would succeed, so a
/// run with 7 existing direct children admits an 8th and a run with 8 does not
/// admit a 9th.
///
/// Fail-closed in both directions, the same shape as [`child_call_depth`]: a
/// count already at or past the ceiling is refused, and the increment
/// **saturates** rather than wrapping, so a corrupt or hostile `u32::MAX`
/// count cannot roll over to 0 and hand back a fresh fan-out budget.
/// (`u32::MAX` saturates to `u32::MAX`, which exceeds
/// [`MAX_DIRECT_CHILD_CALLS`], so it is refused — pinned by
/// `a_direct_child_count_at_the_integer_ceiling_is_refused_rather_than_wrapping_to_zero`.)
///
/// **What the caller must supply, and why B12b did not make it a column:**
/// how many direct children the parent's *Session* already has, counted over
/// the same session tree [`child_call_depth`]'s depth is counted over —
/// `agent_spawn`'s `parent_direct_children`, not a per-`map`-item tally that
/// resets, and **not** a `SELECT COUNT(*) FROM workflow_run WHERE
/// parent_run_id = ?`. That count is the depth mistake one noun over: §7.7
/// says *"≤8 direct children per session"*, and a Session's direct children
/// include its sub-agent spawns, which have no `workflow_run` row at all — so
/// a parent with 8 sub-agents and no child runs would count 0 and admit 8
/// more. The correct number lives in `roundhouse-bus`'s roster, which §5.2
/// does not let this crate read, so [`crate::ledger::admit_call_from_run`]
/// takes it as a parameter rather than inventing a countable it can see.
pub fn admit_child_call(existing_direct_children: u32) -> Result<u32, CallFanOutError> {
    let attempted = existing_direct_children.saturating_add(1);
    if attempted > MAX_DIRECT_CHILD_CALLS {
        return Err(CallFanOutError::TooWide {
            existing_direct_children,
            attempted,
            max: MAX_DIRECT_CHILD_CALLS,
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
/// Three properties follow from the type rather than from caller discipline —
/// all three **per token**, none of them per subtree (see the parent-identity
/// residual below for exactly what that excludes):
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
/// # Residual: the token names an amount, not a parent — closed durably by B12b
///
/// [`refund_child_budget`] takes any `&mut ResourceCaps`, so
/// `draw_child_budget(&mut a, ..)` followed by
/// `refund_child_budget(&mut b, token, ..)` inflates `b`'s pool with budget
/// that left `a`'s. The three properties above hold for each token
/// individually and say nothing about *which* subtree a token returns to; the
/// §8.12 invariant they support is per-subtree, and that half is still caller
/// discipline **for this in-memory pair**.
///
/// Closing it at the type level needs an identity [`ResourceCaps`] does not
/// carry, and one that survives a daemon restart — which this deliberately
/// non-`Deserialize` token cannot. B12b closed it by moving the transfer onto
/// rows instead of onto a token: [`crate::ledger::refund_child_run`] reads the
/// parent from the **child's own `parent_run_id`** rather than taking one as a
/// parameter, so there is no wrong parent to pass, and stamps
/// `workflow_run.refunded_at` so a second refund is a refusal rather than a
/// second credit. That is the durable equivalent of this token's
/// consumed-by-value property, and it is the pair a run loop should use;
/// these two functions remain the in-process arithmetic they are built on.
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
/// defined refund behaviour, and this module cannot give it one.
///
/// **Half of this is now closed and half is not**, and the two halves are
/// worth keeping apart. The *durable record* the accounting needs exists:
/// migration 0008's `parked_at`/`parked_nanos` are the park intervals
/// [`ResourceCaps`]'s doc comment said did not exist, and
/// [`crate::ledger::refund_child_run`] re-derives the refund from rows rather
/// than from this deliberately non-`Deserialize` token. What is **still
/// open** is the policy: `refund_child_run` refuses a child that has not
/// reached a terminal state ([`crate::ledger::LedgerError::ChildNotFinished`]),
/// because returning a live child's grant would let it spend budget its
/// parent had reclaimed — so a child parked forever still holds its grant
/// forever. Deciding that an unanswered park eventually *fails* the child run
/// (which would make it terminal, and refundable through the existing path)
/// is the reaper's call, and the reaper's periodic runner is unowned
/// daemon-side work per ruling P77 §C. **Named, half-closed; the remaining
/// half is a decision, not a mechanism.**
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
/// `now` is a parameter everywhere), so *this function* cannot decrement a
/// window by elapsed time. Since B12b the caller has somewhere to get an
/// honest one: [`crate::ledger::remaining_caps`] takes a `now` and returns a
/// `ResourceCaps` whose `run_wall_timeout` and `run_active_timeout` are the
/// grant minus what the run has actually burned — the latter excluding parked
/// time, per §8.4. Handing *that* value in as `parent_remaining` is what makes
/// the clamp below mean "the child cannot outlive what is left of the
/// parent's window" rather than "cannot outlive the parent's original
/// window".
///
/// # Residual: the pool a `call:` inside a `map` draws against replicates
/// three run-level ceilings
///
/// [`split_budget`](crate::exec::map_step::split_budget) divides
/// `max_cost_usd`, `max_tokens`, `max_tool_calls` and `max_bytes_written`
/// across a `map`'s items, but passes `max_tasks`, `max_subagents` and
/// `max_escalations` through unchanged via `..total.clone()` — deliberately,
/// on the reasoning in its own comment that a nested spawn or escalation is
/// rare enough that the run-level cap is the meaningful per-item ceiling.
/// Once a `call:` draws against one of those per-item pools, those three
/// fields are a **replicated run-level ceiling rather than a share of the
/// run's**: 2,000 map items each carrying the whole run's `max_subagents`.
/// `split_budget`'s own doc already anticipates the collision (*"would be a
/// transfer out of this same pool, not an independent allocation"*).
/// Reconciling the two is **Task 20 (B12)**'s, as the first task with a run
/// loop that can drive a `call:` from inside a `map`; nothing here can, since
/// the `StepBody::Call` arm is a stub. Named, not closed.
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
/// The refund is `grant - spent`, floored at zero per field — never `spent`
/// itself and never a caller-supplied "unspent" figure, so no call site can
/// return more than [`draw_child_budget`] took out. A child reporting a spend
/// larger than its grant, or an unusable one (`NaN`, negative, infinite),
/// refunds **nothing**: the safe direction.
///
/// # Who measures `spent`
///
/// **The parent side, from outside the child run** — Phase 2's cost
/// accounting, which observes the child's actual consumption. Never a figure
/// originating *in* the child run, and never one derived from a model's
/// output. **Within one draw/refund pair**, §8.12's invariant (*"a workflow
/// subtree can never spend more than its root was given"*) reduces entirely to
/// `spent` being truthful: every fail-closed guard in this module is about the
/// *shape* of the number, and none of them can tell an honest small spend from
/// a self-reported one. A child that reports `0` is refunded its entire grant,
/// correctly, by this function.
///
/// # The one exception, which is not about `spent` at all
///
/// The invariant does **not** hold across a **fork**.
/// [`crate::control::retry_from_step`] copies the original run's `caps` and
/// starts the fork's accumulators at zero, and no draw is recorded against the
/// parent, so a retried subtree spends against a grant nobody was charged for
/// — by `n` grants over `n` retries. That is a policy question §8.13 does not
/// answer (see that function's own comment); it is named here because this
/// paragraph is where a reader looks for the invariant's scope.
///
/// What *is* closed is the far worse half: a fork used to be **refundable**,
/// crediting the parent for a draw that never happened and erasing real spend.
/// [`crate::durability::fork_run`] now stamps a fork settled at creation, and
/// [`crate::ledger::refund_child_run`] refuses any child with no recorded
/// draw (rulings P109 §A, P110).
///
/// # `spent` is a measurement typed as a ceiling
///
/// `&ResourceCaps` is a ceilings type, and this parameter is a measurement.
/// It is reused rather than given a type of its own because the seven
/// countables line up field for field and this is the only call site — but the
/// mismatch has two visible consequences worth stating:
///
/// - **Only the seven countables are read.** `spent`'s three `Duration`s are
///   accepted and ignored, because the timeouts were clamped rather than
///   withdrawn — see [`draw_child_budget`].
/// - A caller that passes the *grant* itself as `spent` refunds exactly
///   nothing, silently. That is the safe direction of the invariant, but it is
///   indistinguishable here from a child that really did spend everything.
pub fn refund_child_budget(
    parent_remaining: &mut ResourceCaps,
    drawn: ChildBudget,
    spent: &ResourceCaps,
) {
    let grant = drawn.caps;

    // The `.max(0.0)` is the same normalisation the draw applies, on the same
    // field, for the same reason: `f64::max` returns the non-`NaN` operand, so
    // a `parent_remaining.max_cost_usd` that arrives `NaN` or negative is
    // normalised *down* to an empty pool instead of surviving the refund.
    // Without it a `NaN` parent stays `NaN` — the fail-open the rest of this
    // module exists to avoid — since `NaN + anything` is `NaN`. The draw
    // normalises the pool it is handed, so a poisoned value can only reach
    // here by arriving between the two calls, which is exactly what Task 20's
    // run loop makes possible: it threads one `parent_remaining` across a
    // child run's whole lifetime.
    parent_remaining.max_cost_usd = (parent_remaining.max_cost_usd
        + refund_f64(grant.max_cost_usd, spent.max_cost_usd))
    .max(0.0);
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
/// shape-to-shape between daemon restarts. `serde_json`'s `preserve_order`
/// **is on today** — `agent-client-protocol` 2.0.0 enables it and Cargo's
/// feature unification applies it workspace-wide, which ruling P29 accepted —
/// so `Map`'s iteration order is insertion order, not sorted order, and this
/// function's insertion order is the schema's key order. A tool schema that is
/// not stable is not cacheable or hashable. Pinned by
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
