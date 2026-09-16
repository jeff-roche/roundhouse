//! `map` step fan-out (§8.9, Task 14/B6): per-item budget splitting
//! ([`split_budget`]/[`MapBudget`]/[`run_map`]) and the in-memory
//! `StepBody::Map` dispatch arm ([`Executor::dispatch_map_step`]) that binds
//! the item variable (`as:`) into the expression context for each item —
//! closing finding 8's remaining gap (the `map` item variable was never bound
//! anywhere) — and distinguishes `on_item_error: collect` from `continue`
//! (finding 9/10).
//!
//! # There are two `map` fan-out loops, and this file is one of them (Phase 8 Task 25.7 Task 2)
//!
//! [`Executor::dispatch_map_step`] is the loop the **in-memory** sequencer
//! ([`Executor::run_to_completion`]) drives: no `workflow_run` row, no
//! `Connection`, so a `tool:`/`agent:` inner step takes
//! [`Executor::dispatch_step_or_stub`]'s fixed stub and an item always runs
//! to completion inside one call. `crate::exec::run_loop::Loop::dispatch_map`
//! is the loop a **real run** drives: it holds the `Connection`, dispatches
//! each item's inner steps for real, and suspends the run per item in waves
//! bounded by `map.max_parallel`.
//!
//! The two differ only in control flow. Everything below it — `over:`
//! evaluation and the item cap ([`resolve_map_items`]), inner-step parsing
//! ([`parse_map_inner_steps`]), the `as:`/`worktree` snapshot span
//! ([`snapshot_map_roots`]/[`restore_map_roots`]), per-item isolation
//! ([`Executor::prepare_item_isolation`]/[`Executor::release_item_isolation`]),
//! the nested-`report:` refusal ([`nested_report_refusal`]), the inner-outcome
//! fold ([`fold_inner_step_outcome`]), `on_item_error` bookkeeping
//! ([`ItemErrorPolicy`]) and the map's own aggregate output
//! ([`map_step_outcome`]) — lives here once, and both loops call it. That is
//! deliberate and is the same argument [`evaluate_when_gate`]'s own doc
//! comment makes: two independently written copies of one decision drift, and
//! this file has already paid for that once.
//!
//! One decision here is deliberately *not* shared, and it is the exception
//! that proves the rule: [`per_item_dispatch_refusal`] (Task 4) lives beside
//! [`split_budget`], the division it enforces, but only the run-loop fan-out
//! calls it. See the closure at [`run_map`]'s call site for why — in short,
//! every `tool:`/`agent:` inner step *this* loop reaches is
//! [`Executor::dispatch_step_or_stub`]'s stub, so there is no per-item spend
//! here for a ceiling to bound.
//!
//! # Deviations from the plan text (ruling P1)
//!
//! - **`on_item_error` is [`OnItemError`], not `&str`.** The plan's
//!   illustrative code predates `crate::parse::steps::OnItemError` (a closed,
//!   `#[serde(rename_all = "snake_case")]` enum Task 3 already landed for
//!   exactly this field) and would have reintroduced an unvalidated string
//!   for a value that is validated at parse time everywhere else in this
//!   crate.
//! - **`map.over` goes through [`eval_delimited_expression`]/[`TemplateSource`],
//!   not the plan's `eval`/`ExpressionSource`.** ROUND 2 carry-forward item 2
//!   settles this against the frozen doc — every `over:` example in §8.9 uses
//!   the delimited `${{ }}` form, none uses a bare one, and
//!   `Executor::run_to_completion`'s own `when:` handling already made this
//!   call for the identical field shape (fix round 1, item 4).
//! - **Per-item binding uses [`Evaluated::derive`], not the plan's
//!   `ExprContext::get`/`set`-based restore.** See [`Executor::dispatch_map_step`]'s
//!   own doc comment for the full reasoning (ruling P40/R-1, R-2). This
//!   crate therefore does not add the `ExprContext::get` accessor the plan's
//!   Step 3 lists — it uses
//!   [`crate::expr::ExprContext::snapshot_root`]/[`crate::expr::ExprContext::restore_root`]
//!   instead, a `pub(crate)` pair that snapshots and restores one root's
//!   value *and* provenance atomically. **This mechanism changed twice**
//!   (fresh clone per item → one clone per `map` step → snapshot/restore one
//!   root) — see `dispatch_map_step`'s own doc comment, "History of this
//!   mechanism", for why each prior design was replaced, not merely
//!   restyled.
//! - **`map.isolation`/`base_ref` — landed by Task 34 (lane W5, rulings
//!   W5-8/W5-22), closing Phase 5 ruling P42 for an explicitly declared
//!   tier — not for a `map` step that leaves `isolation:` unset (fix round
//!   2, item 3, ruling W5-33; see [`Executor::dispatch_map_step`]'s own doc
//!   comment, "Task 34", for the qualification in full).** Earlier revisions of this
//!   file left `StepBody::Map`'s `isolation` field completely unread and
//!   created no worktree, reasoning that `roundhouse-flow` had "no
//!   process-spawning or git dependency at all." That premise no longer
//!   holds: Task 14 (this same lane) added the one new `flow -> sandbox`
//!   Cargo edge this crate is permitted (§5.2's `roundhouse-flow` row), and
//!   Task 34 is what actually spends it on `map.isolation`. See
//!   [`Executor::dispatch_map_step`]'s own doc comment, "Task 34:
//!   `isolation: worktree` materialization", for the real mechanism —
//!   `crate::worktree::WorktreeProvider` (defined in `crate::worktree`) and
//!   its `SandboxWorktreeProvider` adapter over
//!   `roundhouse_sandbox::worktree`.

use crate::caps::ResourceCaps;
use crate::exec::{
    evaluate_when_gate, redact_with_needles, Executor, GateDecision, StepOutcome, StepStatus,
};
use crate::expr::{eval_delimited_expression, interpolate, TemplateSource};
use crate::parse::steps::{parse_step, MapIsolationDef, OnItemError, StepBody, StepDef};
use crate::worktree::{WorktreeProvider, WorktreeProviderError};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;

/// The `${{ }}` root name a materialized worktree's path is bound under,
/// alongside `as_name` — never merged into it. See
/// [`Executor::dispatch_map_step`]'s own doc comment, "Task 34: `isolation:
/// worktree` materialization", for the binding/snapshot mechanism and why
/// it deliberately does not reshape `as_name`'s own binding.
const WORKTREE_ROOT_NAME: &str = "worktree";

/// The default `base_ref` text used when `map.isolation` is bare `worktree`
/// (no `base_ref:` key at all — `MapIsolationDef::Worktree { base_ref: None }`).
/// `HEAD` matches the intuitive "isolate me a copy of whatever is checked
/// out right now" reading of asking for worktree isolation without naming a
/// starting point.
const DEFAULT_WORKTREE_BASE_REF: &str = "HEAD";

/// RAII guard around one materialized worktree (Task 34): guarantees
/// [`WorktreeProvider::release`] runs even if the item's inner steps panic
/// or return early, because [`Drop::drop`] runs during unwinding as well as
/// on an ordinary scope exit — see
/// [`Executor::dispatch_map_step`]'s own doc comment, "Cleanup on both
/// paths, panic included", for the full reasoning and why the *explicit*
/// [`Self::release`] call (not `Drop` alone) is what lets a release failure
/// actually reach the item's own [`ItemOutcome`] on the ordinary path.
pub(crate) struct WorktreeGuard {
    provider: Arc<dyn WorktreeProvider>,
    /// `None` once released — by [`Self::release`], or by [`Drop::drop`] on
    /// an unwind/early-return path. `Option` (rather than a plain
    /// `PathBuf`) is what makes both of those paths safe to call
    /// unconditionally without a double-release: whichever runs first takes
    /// the path, and the other sees `None` and does nothing.
    path: Option<PathBuf>,
}

impl WorktreeGuard {
    fn new(provider: Arc<dyn WorktreeProvider>, path: PathBuf) -> Self {
        Self {
            provider,
            path: Some(path),
        }
    }

    /// Explicit release, run on the ordinary (non-panicking) path so a
    /// failure can be folded into the item's own outcome. Consumes `self`
    /// by value: once this returns, the guard's own `Drop` still runs (it
    /// is a local going out of scope), but sees `path: None` and is a
    /// no-op, so this is never a double release.
    fn release(mut self) -> Result<(), WorktreeProviderError> {
        let path = self
            .path
            .take()
            .expect("release() is the only consumer of `self` and runs at most once");
        self.provider.release(&path)
    }
}

impl Drop for WorktreeGuard {
    /// The panic/early-return safety net — see [`Self::release`]'s own doc
    /// comment for why the *ordinary* path goes through that method
    /// instead. Best-effort: a release failure reached only through
    /// unwinding has no [`ItemOutcome`] left to attach itself to (the
    /// closure that would have returned one is itself unwinding), so it is
    /// swallowed here rather than panicking-while-panicking.
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = self.provider.release(&path);
        }
    }
}

/// Hard, closed-fail cap on a single `map` step's item count (fix round 1,
/// item 3). See [`Executor::dispatch_map_step`]'s own doc comment,
/// "`MAX_MAP_ITEMS`", for what this bounds and — importantly — what it does
/// not (the product across nested `map`s). 2,000 is chosen to sit
/// comfortably above any realistic single-level fan-out this crate's own
/// examples reach for (mapping over PRs, files, webhook line items) while
/// keeping this crate's own measured cost — after fix round 1's clone hoist
/// (see `dispatch_map_step`'s own doc comment for the full table) — at
/// **3.15 ms for exactly 2,000 items**, release build, one trivial `emit`
/// inner step, versus the 620 ms a mere 2,500 items cost *before* that fix.
/// Not derived from a formal analysis; a round number in the same order of
/// magnitude as `ResourceCaps::default().max_tool_calls` (2,000), the
/// closest existing precedent for "how many discrete units of work is a
/// lot, for this crate."
///
/// # A parse-time ceiling interacts with this, and it is not in this file
///
/// An `over:` list written **inline in the workflow YAML** is also subject to
/// [`crate::parse::MAX_INTEGER_SCALAR_VISITS`] (65,536) and
/// [`crate::parse::MAX_FLOAT_SCALAR_VISITS`] (5,041), which cap how many
/// numbers one document may make the parser decode. This cap and those are
/// independent: 2,000 items here is a *runtime* fan-out bound, and those are
/// *parse-time* bounds on the whole file.
///
/// What that means in practice, measured (fix round 5):
///
/// - **Integer ids: not a constraint you can reach.** The largest
///   map-over-ids workflow [`crate::parse::MAX_YAML_BYTES`] admits at all is
///   18 steps x 2,000 six-digit ids = 36,001 integers in 253,952 bytes, and
///   65,536 is 1.82x that. The byte cap binds first.
/// - **Float items: reachable.** More than 5,041 float items across a file's
///   inline `over:` lists is refused at parse time — roughly two and a half
///   full 2,000-item lists. A third list of floats will not parse, and the
///   error is `TooManyNumericScalars`.
///
/// This note exists because fix round 4 shipped a single numeric ceiling of
/// 5,041 that refused a 42 KB alias-free workflow of three map steps over
/// 2,000 numeric ids — a shape this constant blesses — and the author would
/// have had no reason to look in `parse` for why.
pub const MAX_MAP_ITEMS: usize = 2_000;

/// A run's remaining resource budget as `map` sees it. This crate's job is to
/// divide whatever `total_remaining` it is handed; the run-level ledger that
/// produces a real one is [`crate::ledger`] (B12b), and the caller that reads
/// it is [`crate::exec::run_loop`] (B12c).
#[derive(Debug, Clone, PartialEq)]
pub struct MapBudget {
    pub total_remaining: ResourceCaps,
}

impl MapBudget {
    /// The run's **real** remaining budget, as of `now`:
    /// [`crate::ledger::remaining_caps`] — its grant minus what it has
    /// already spent, with the two elapsed-time windows decremented by the
    /// time the run has burned.
    ///
    /// This is the constructor [`Self::unenforced_placeholder`]'s doc has
    /// been pointing at since Task 14, and with it [`split_budget`]'s output
    /// is a share of a real ceiling rather than of a default one. It refuses
    /// rather than substituting a default for a run with no recorded grant —
    /// see [`crate::ledger::LedgerError::CapsNotRecorded`].
    pub fn from_run_ledger(
        conn: &rusqlite::Connection,
        run_id: crate::exec::RunId,
        now: roundhouse_core::Timestamp,
    ) -> Result<MapBudget, crate::ledger::LedgerError> {
        Ok(MapBudget {
            total_remaining: crate::ledger::remaining_caps(conn, run_id, now)?,
        })
    }

    /// A [`MapBudget`] that enforces **nothing** — `total_remaining` is
    /// [`ResourceCaps::default`], not sourced from any real run-level
    /// ledger. Fix round 1, item 3: `Executor::dispatch_map_step` used to
    /// construct `MapBudget { total_remaining: ResourceCaps::default() }`
    /// inline, which reads exactly like a real, intentional budget — a
    /// placeholder that looks like an allowance is worse than one that
    /// admits it isn't one. This constructor exists so that call site says
    /// so explicitly and is greppable.
    ///
    /// # What still reaches this constructor, now that B12c has wired the real one
    ///
    /// [`Executor::dispatch_map_step`] uses whatever
    /// [`crate::exec::run_loop`] set on the executor before dispatching the
    /// step — a [`Self::from_run_ledger`] value, read at the moment the `map`
    /// starts, which is §8.9's own words for when the split is taken. This
    /// constructor is the fallback for an [`Executor`] that has **no run
    /// behind it at all**: `Executor::new` builds one from a `WorkflowDef`, a
    /// `TaskSink` and a `RunContext` with no `workflow_run` row anywhere, and
    /// there is no ledger to source from because there is no run to source it
    /// from. That path is this crate's own tests and
    /// `examples/measure_dual_render.rs`; a real run goes through
    /// [`crate::exec::run_loop::run_workflow`].
    ///
    /// The reason the swap could not happen in B12b stands recorded, because
    /// it explains the shape: [`Executor`] held no [`rusqlite::Connection`],
    /// and it still does not. B12c did not give it one — a run loop that holds
    /// `&mut Connection` and an executor that holds `&Connection` cannot
    /// coexist — it hands the executor the **value** the connection would have
    /// produced, which is also what makes "at the moment the map starts"
    /// literal rather than approximate.
    pub fn unenforced_placeholder() -> MapBudget {
        MapBudget {
            total_remaining: ResourceCaps::default(),
        }
    }
}

/// One item's result once its inner steps have run.
#[derive(Debug, Clone, PartialEq)]
pub enum ItemOutcome {
    Completed(Value),
    Failed(String),
    Skipped { reason: String },
}

/// §8.9: "Unset defaults to an even split of the run's remaining budget
/// across the item count at the moment the map starts." An item's own
/// `caps:` block (when present in YAML — a later task's concern; nothing in
/// this crate parses per-item `map` caps yet) would be a transfer out of
/// this same pool, not an independent allocation, so this function is
/// intended only for items that do not set their own caps.
///
/// What holds an item to the share this computes is
/// [`per_item_dispatch_refusal`], which also records which of these fields is
/// enforceable at all and why the rest are not.
pub fn split_budget(total: &ResourceCaps, item_count: u32) -> ResourceCaps {
    let n = item_count.max(1) as f64;
    ResourceCaps {
        max_cost_usd: total.max_cost_usd / n,
        max_tokens: (total.max_tokens as f64 / n) as u64,
        max_tool_calls: (total.max_tool_calls as f64 / n).ceil() as u32,
        max_bytes_written: (total.max_bytes_written as f64 / n) as u64,
        // Not divided — a nested agent spawn or an escalation is rare enough
        // that the run-level cap is the meaningful ceiling per item, not a
        // 1/n share of it; and the run-level timeouts are wall-clock, not a
        // resource that divides sensibly across concurrent items at all.
        ..total.clone()
    }
}

/// **[`split_budget`]'s enforcement half: one item's next real dispatch,
/// refused once the item has spent its own share** (Phase 8 Task 25.7, #64,
/// Task 4). `None` when the dispatch still fits.
///
/// # What this is, and what it deliberately is not
///
/// §8.9 makes an item's budget *"a transfer out of the run's remaining
/// budget, not an independent pool"*, so this adds **no** durable accounting:
/// [`crate::ledger::admit_spend`] stays the one place a run's ledger moves,
/// and a `map` is still charged there exactly once, when it starts. What this
/// adds on top is an in-memory ceiling, derived fresh on every segment from
/// the item's own durable rows, that stops one item consuming the whole run's
/// allowance while its siblings starve — a live risk only since Task 2 of the
/// same task made a `map` item's inner steps dispatch for real.
///
/// **It bounds an item against its siblings, not the map's total.**
/// [`split_budget`] rounds an item's share of `max_tool_calls` *up*, so every
/// item keeps at least one call for as long as the run has any allowance left
/// at all: an n-item `map` still issues n real dispatches whatever this
/// returns. What it prevents is one item running away with the whole share,
/// which is a fairness property rather than an exhaustion one. Bounding the
/// aggregate — including recording the items a spent *run* never reached — is
/// §8.9's cooperative run-budget exhaustion, which is
/// [`run_budget_is_exhausted`] (Task 5).
///
/// # Why `max_tool_calls`, and why that field alone
///
/// Of the four countables [`split_budget`] divides, `max_tool_calls` is the
/// only one whose unit a `map` can observe at all. `max_cost_usd`,
/// `max_tokens` and `max_bytes_written` are measured *outside* the run (see
/// [`crate::ledger::Spend`]'s own doc on why this crate invents none of them),
/// and nothing carries them back: `crate::exec::run_loop::WorkDone` — the only
/// thing a finished dispatch hands this crate — has no field for any of the
/// three. A ceiling on a figure that is always zero would be enforcement
/// theatre; a ceiling on calls is the one §8.9 shares with
/// `crate::exec::run_loop::Loop::admit`, which charges a top-level `tool:`
/// step exactly one.
///
/// **Every real dispatch counts as one call, an `agent:` step included.**
/// `Loop::admit` bills a top-level `agent:` step against `max_subagents`
/// instead, but [`split_budget`] deliberately does not divide that field, so
/// counting an item's agent dispatches there would bound them by the run's
/// *whole* allowance — which is not a per-item bound at all. The question this
/// ceiling answers is "how much real work may one item set going", and both
/// bodies are that.
///
/// # Why the item `Failed` rather than `Skipped`
///
/// A `Skipped` item is one the fan-out never started — `fail_fast`'s fill, or
/// (Task 5) an item the *run* ran out of budget before reaching. This item did
/// run; it ran too much. So it takes the ordinary path any other inner-step
/// failure takes, and `on_item_error` governs what that does to the rest of
/// the fan-out, with the reason in the message rather than in a comment.
pub(crate) fn per_item_dispatch_refusal(
    map_step_id: &str,
    inner_step_id: &str,
    item_index: u32,
    dispatches_so_far: u32,
    item_caps: &ResourceCaps,
) -> Option<ItemOutcome> {
    let allowed = item_caps.max_tool_calls;
    (dispatches_so_far >= allowed).then(|| {
        ItemOutcome::Failed(format!(
            "map step `{map_step_id}`, item {item_index}: inner step `{inner_step_id}` needs a \
             real dispatch, and this item has already made {dispatches_so_far} of the {allowed} \
             it is allowed — its even share of the run's remaining `max_tool_calls` at the \
             moment this `map` started. §8.9 makes an item's budget a transfer out of the run's \
             remaining budget rather than an independent pool, so the dispatch is refused here \
             rather than letting one item spend the whole run's allowance while its siblings \
             starve"
        ))
    })
}

/// **§8.9's cooperative run-budget exhaustion, as the one question a `map` can
/// ask before it starts another item** (Phase 8 Task 25.7, #64, Task 5).
/// `true` once the fan-out's own real dispatches have used up what the *run*
/// had left, which is where §8.9 stops new items starting.
///
/// # A different bound from [`per_item_dispatch_refusal`], not a second copy of it
///
/// That one is a **fairness** bound: one item's tally against
/// [`split_budget`]'s even share, so no item spends the whole allowance while
/// its siblings starve. Because the share is rounded *up*, every item keeps at
/// least one call while the run has any allowance at all — so an n-item `map`
/// over a run with two calls left still issues n real dispatches, and no
/// per-item ceiling can stop it. This is the **aggregate** bound that one's
/// doc comment defers to: the whole fan-out against the run's remainder.
///
/// # Why `max_tool_calls`, and why that field alone
///
/// The same reason [`per_item_dispatch_refusal`] records, unchanged:
/// `max_cost_usd`, `max_tokens` and `max_bytes_written` are measured outside
/// the run and nothing carries them back — `crate::exec::run_loop::WorkDone`,
/// the only thing a finished dispatch hands this crate, has no field for any
/// of the three — so a ceiling on them would bound a figure that is always
/// zero.
///
/// The two elapsed-time windows are left out for a different and sharper
/// reason: [`crate::ledger::admit_spend`] checks both on **every** call
/// regardless of what is being spent, and the `map` step passes through that
/// chokepoint on every segment of its fan-out (a real charge on the first,
/// `Spend::ZERO` on each resumed wave — see
/// `crate::exec::run_loop::Loop::observe_admission`). A `map` whose wall or
/// active window has run out is therefore already refused in
/// `Loop::run_phase`, before this loop is reached at all. `max_tasks` and
/// `max_subagents` are likewise the run-level admission's to enforce, and it
/// charges neither for a `map` item's inner step.
///
/// # What `>=` means here, given nothing spends the field mid-fan-out
///
/// `run_remaining` is re-read from the ledger before every segment, but no
/// part of a `map`'s fan-out charges `max_tool_calls` against it — only
/// `Loop::admit` does, and only for a *top-level* `tool:` step — so the figure
/// is constant for the life of one fan-out. What moves is the left-hand side,
/// the fan-out's own dispatch count, which is why this becomes true part-way
/// through a `map` rather than only ever at its start.
///
/// # What it bounds, and the one thing it does not
///
/// Its caller asks it at the seam an item is **started**, never at the seam an
/// inner step dispatches, because §8.9's rule is *"no new round-trips or new
/// items start"* while an in-flight item *"finishes its current round-trip"* —
/// and an item cut off half-way through its inner steps has no honest outcome
/// to record (it is not `Skipped`, having run, and `Failed` is the
/// conflation §8.9 forbids).
///
/// **The exemption that buys is permanent, not one round-trip long**, and the
/// overshoot it leaves is correspondingly larger.
/// `crate::exec::run_loop::Loop::map_item_is_in_flight` is true for an item
/// from the moment any of its inner steps holds a durable row, and stays true —
/// so an item already started when this first returns `true` goes on
/// dispatching its remaining inner steps on every later segment. Nothing in
/// *this* bound stops it: what does is [`per_item_dispatch_refusal`]'s share,
/// the item's inner-step list running out, or whatever else ends the item
/// first (an inner-step failure, a refusal).
///
/// The bound is therefore the **item count**, not `map.max_parallel` and not
/// one dispatch per item in flight. Every item is held to [`split_budget`]'s
/// share of `ceil(R / N)` — `R` the run's remainder, `N` the item count — so
/// the fan-out's nominal total is `N * ceil(R / N)`, which exceeds `R` by
/// `N - (R mod N)` when `N` does not divide `R` and by nothing when it does:
/// at most `N - 1`, with `N` itself at most [`MAX_MAP_ITEMS`]. (Task 4's own
/// re-decide overshoot, which
/// `crate::exec::run_loop::Loop::map_item_dispatches_so_far` documents, sits on
/// top of that nominal total rather than inside it.)
///
/// Measured, not reasoned, in `tests/run_loop.rs`:
/// `an_already_started_item_keeps_dispatching_past_the_runs_remainder_unflagged`
/// drives three items of three `tool:` steps with seven calls left and
/// `max_parallel: 1`, and gets **nine** dispatches — item 2 starts at a tally
/// of six, which is not yet seven, and then spends its whole share of three.
///
/// **And a run that overshoots this way is not flagged.** Every item completes,
/// so nothing is `Skipped` and [`output_records_a_run_budget_skip`] finds
/// nothing: §8.9's `needs_human` reports *"at least one item was withheld"*,
/// never *"this run stayed inside its remainder"*. An operator reading it as an
/// overspend alarm would miss exactly this case.
///
/// Closing either half would need a cut-off outcome §8.9 does not define.
pub(crate) fn run_budget_is_exhausted(
    map_dispatches_so_far: u32,
    run_remaining: &ResourceCaps,
) -> bool {
    map_dispatches_so_far >= run_remaining.max_tool_calls
}

/// The result of a `map` step's fan-out: the per-item outcomes (never
/// truncated — every item gets an entry, per §8.9), plus, when
/// `on_item_error: collect`, the gathered error messages for the map step's
/// *own* output (finding 10's fix — see [`run_map`] for the distinction from
/// `continue`).
#[derive(Debug, Clone, PartialEq)]
pub struct MapRunResult {
    pub outcomes: Vec<ItemOutcome>,
    pub collected_errors: Vec<String>,
}

/// Runs `items` through `run_item`, respecting `on_item_error`.
///
/// **`max_parallel` is unread *here*, and that is now a statement about this
/// function rather than about `map`.** This is the in-memory fan-out, reached
/// only from [`Executor::run_to_completion`] — a sequencer with no
/// `workflow_run` row, no `Connection`, and therefore nothing to dispatch
/// against: every `tool:`/`agent:` inner step it reaches becomes
/// [`Executor::dispatch_step_or_stub`]'s fixed stub, so "how many at once" is
/// not a question it can answer differently. Running items sequentially is
/// the honest behaviour for it, not a deferral.
///
/// The loop that *does* read `max_parallel` is
/// `crate::exec::run_loop::Loop::dispatch_map` (Phase 8 Task 25.7 Task 2),
/// which drives a `map` inside a real run in waves bounded by it. See that
/// function's own doc comment for why it is a second loop rather than a
/// widening of this one's `run_item` signature — in short, [`ItemOutcome`]
/// has no way to say "this item is half-way through and must suspend", and
/// this function's only caller never needs one.
///
/// **Never drops an item.** Every element of `items` produces exactly one
/// [`ItemOutcome`] in [`MapRunResult::outcomes`], in order — §8.9's explicit
/// requirement (pinned by
/// `run_budget_exhaustion_is_cooperative_and_skips_are_recorded_not_dropped`
/// in `tests/map_step.rs`). This function has no live budget signal of its
/// own (see [`MapBudget`]'s doc comment): whether an item should be skipped
/// for lack of remaining run budget is a decision `run_item` itself makes,
/// using whatever ledger its caller threads in — "cooperative" names exactly
/// this, the caller checking and reporting `Skipped` rather than this
/// function silently withholding a call. `run_item` is still handed
/// [`split_budget`]'s even-split allowance for the item, and the closure at
/// this function's one call site still leaves it unread — see that closure's
/// own comment for why binding it *here* would bound nothing but stub work.
/// The loop that enforces the same share for real is
/// `crate::exec::run_loop::Loop::dispatch_map`, through
/// [`per_item_dispatch_refusal`] — and it is also where the cooperative
/// decision described above is actually made, through
/// [`run_budget_is_exhausted`] and [`skipped_by_run_budget_exhausted`].
///
/// `on_item_error` (finding 10's fix — previously `collect` and `continue`
/// were indistinguishable):
/// - [`OnItemError::FailFast`]: stop dispatching further items after the
///   first failure; every item not yet dispatched is recorded `Skipped`.
/// - [`OnItemError::Continue`]: keep dispatching every item; a failed item's
///   error is visible only on that item's own [`ItemOutcome::Failed`], never
///   aggregated anywhere else.
/// - [`OnItemError::Collect`]: identical control flow to `Continue` (every
///   item still runs), but every failure's message is *additionally*
///   gathered into [`MapRunResult::collected_errors`], which the caller
///   ([`Executor::dispatch_map_step`], below) surfaces on the `map` step's
///   own output — this is the actual behavioural difference `collect` is
///   supposed to have.
pub fn run_map(
    items: Vec<Value>,
    _max_parallel: u32,
    on_item_error: OnItemError,
    budget: &mut MapBudget,
    mut run_item: impl FnMut(&Value, ResourceCaps) -> ItemOutcome,
) -> MapRunResult {
    let per_item_caps = split_budget(&budget.total_remaining, items.len() as u32);
    let mut outcomes = Vec::with_capacity(items.len());
    let mut policy = ItemErrorPolicy::new(on_item_error);
    for item in &items {
        let outcome = run_item(item, per_item_caps.clone());
        let should_stop = policy.observe(&outcome);
        outcomes.push(outcome);
        if should_stop {
            break;
        }
    }
    // Any items not yet visited because of an early `fail_fast` break are
    // recorded as `Skipped` rather than silently absent from the result.
    while outcomes.len() < items.len() {
        outcomes.push(ItemErrorPolicy::skipped_by_fail_fast());
    }
    MapRunResult {
        outcomes,
        collected_errors: policy.into_collected_errors(),
    }
}

/// The reason an item the fan-out never started carries, so a reader can tell
/// it from an item its own `when:` skipped.
pub(crate) const FAIL_FAST_SKIP_REASON: &str = "fail_fast: prior item failed";

/// §8.9's `on_item_error` bookkeeping over a stream of finished per-item
/// outcomes — what `collect` collects, and when `fail_fast` stops.
///
/// **One implementation, two fan-out loops.** [`run_map`]'s sequential loop
/// and [`crate::exec::run_loop`]'s wave-driven one are genuinely different
/// control flows (one runs an item to completion in a closure, the other
/// advances every item one inner step per segment), but the *policy* applied
/// to a finished item's outcome must be identical in both or a workflow's
/// declared `on_item_error` would mean two different things depending on
/// whether its inner steps happened to suspend. That is the same reasoning
/// [`evaluate_when_gate`]'s own doc comment records for sharing the `when:`
/// split rather than writing it twice — and the same defect class it names,
/// reached from the other direction.
pub(crate) struct ItemErrorPolicy {
    on_item_error: OnItemError,
    collected_errors: Vec<String>,
}

impl ItemErrorPolicy {
    pub(crate) fn new(on_item_error: OnItemError) -> Self {
        ItemErrorPolicy {
            on_item_error,
            collected_errors: Vec::new(),
        }
    }

    /// Records one item's finished outcome, returning whether the fan-out
    /// must stop starting further items.
    pub(crate) fn observe(&mut self, outcome: &ItemOutcome) -> bool {
        let ItemOutcome::Failed(message) = outcome else {
            return false;
        };
        match self.on_item_error {
            OnItemError::Collect => {
                self.collected_errors.push(message.clone());
                false
            }
            OnItemError::Continue => false,
            OnItemError::FailFast => true,
        }
    }

    /// The outcome an item the fan-out never started is recorded with —
    /// §8.9's "never drop an item", as a value rather than a string literal
    /// written at each of the two fan-out loops.
    pub(crate) fn skipped_by_fail_fast() -> ItemOutcome {
        ItemOutcome::Skipped {
            reason: FAIL_FAST_SKIP_REASON.to_string(),
        }
    }

    pub(crate) fn into_collected_errors(self) -> Vec<String> {
        self.collected_errors
    }
}

/// The reason §8.9 gives an item the *run* ran out of budget before reaching,
/// so a reader can tell it from an item `fail_fast` withheld
/// ([`FAIL_FAST_SKIP_REASON`]) and from one its own `when:` skipped. The
/// literal §8.9 itself writes.
pub(crate) const RUN_BUDGET_EXHAUSTED_SKIP_REASON: &str = "run_budget_exhausted";

/// [`ItemErrorPolicy::skipped_by_fail_fast`]'s counterpart for §8.9's
/// cooperative run-budget exhaustion — the same "never drop an item" record,
/// for the other of the two reasons a fan-out stops starting items.
///
/// **Deliberately a free function rather than a second method on
/// [`ItemErrorPolicy`], and deliberately not that constructor reused.**
/// `fail_fast` is an `on_item_error` policy, driven by
/// [`ItemErrorPolicy::observe`], which fires only on a real item *failure*;
/// running out of run budget is environmental and no item failed. Sharing the
/// constructor — or the reason string — would make the two indistinguishable
/// in a `map`'s own output, which is what §8.9's "never conflated with a real
/// failure" forbids, and would also make
/// [`output_records_a_run_budget_skip`] fire on a `fail_fast` cutoff.
pub(crate) fn skipped_by_run_budget_exhausted() -> ItemOutcome {
    ItemOutcome::Skipped {
        reason: RUN_BUDGET_EXHAUSTED_SKIP_REASON.to_string(),
    }
}

/// Whether a `map` step's own aggregate output records at least one item
/// [`skipped_by_run_budget_exhausted`] withheld — the signal
/// `crate::exec::run_loop::Loop::synthesise_report` turns into §8.9's
/// `needs_human: true`.
///
/// It reads the shape [`map_step_outcome`] writes, through the same
/// [`item_outcome_to_json`] mapping that wrote it, so the two cannot drift.
///
/// **Structural, so it is stated as what it matches rather than as what it
/// means.** Any output at all can be handed to it, and `false` is simply
/// "nothing of this shape is in there" — but it does not verify that the
/// output came from a `map` step, because its callers hold a
/// [`StepOutcome`]/`workflow_step_run` row rather than the `StepDef` that
/// would say so. The one way to reach a false positive is a non-`map` step
/// whose own output contains an `items` array carrying this crate's private
/// reason constant, and its only effect is to flag a run for an operator that
/// did not need flagging — the safe direction for a field whose purpose is to
/// stop an incomplete run being silently buried.
pub(crate) fn output_records_a_run_budget_skip(output: &Value) -> bool {
    output["items"].as_array().is_some_and(|items| {
        items.iter().any(|item| {
            item["status"] == "skipped" && item["reason"] == RUN_BUDGET_EXHAUSTED_SKIP_REASON
        })
    })
}

fn item_outcome_to_json(o: &ItemOutcome) -> Value {
    match o {
        ItemOutcome::Completed(v) => serde_json::json!({"status": "completed", "output": v}),
        ItemOutcome::Failed(msg) => serde_json::json!({"status": "failed", "error": msg}),
        ItemOutcome::Skipped { reason } => {
            serde_json::json!({"status": "skipped", "reason": reason})
        }
    }
}

/// Names a resolved `map.over` value's JSON type without echoing its
/// content — mirrors `crate::exec`'s own `ValueShape` (see
/// `StepOutcome`'s hand-written `Debug` impl for why: a resolved value can
/// be secret-derived, so an error path must never format the value itself
/// into a message).
/// Scrubs every **declared** secret's raw value out of `message` — the same
/// [`redact_with_needles`] needle scan every other dispatch arm's *logged*
/// copy already goes through (`exec/mod.rs:958`/`:1007`/`:1065`/`:1122`),
/// applied here to an `ItemOutcome::Failed` message instead of a sink-bound
/// event.
///
/// # Why this is needed on top of the withhold (final round, item A1)
///
/// It exists because provenance and the needle list see different things.
/// [`crate::expr::Interpolated`]'s provenance catches a `base_ref` that was
/// *computed from* `${{ secrets.* }}`; a declared secret's raw value can
/// reach `base_ref` through a channel provenance treats as clean, and then
/// the withhold branch would not fire on provenance alone. Without this
/// scrub the raw value lands in the append-only `events` table via the
/// echoed `base_ref`, which is the value itself in that case.
///
/// # What this scrub does and does not catch (final round part 3, ruling W5-48)
///
/// An earlier version of this comment said the needle list catches a
/// declared secret's raw value **"however it arrived"**. That was a false
/// coverage claim, and false in the dangerous direction. A needle is an
/// exact substring match, so it catches every *verbatim* copy of the value
/// — the echoed `base_ref` this function's caller scrubs before formatting,
/// and a subprocess's stderr that quotes the value back unchanged — and it
/// catches **no lossy transform of one**:
///
/// - `@{upstream}`-style syntax makes `git` die mid-interpretation and
///   report only the prefix before the mark. Measured: 27 bytes of a
///   38-byte declared secret, cleartext, past a whole-value needle.
/// - A value longer than `git`'s own `vreportf` stderr buffer (~4KB —
///   **`git`'s buffer, not this workspace's `OUTPUT_CAP`**; a 3024-byte
///   value scrubs fully, a 5029-byte one does not) comes back as a shorter,
///   still-sensitive prefix.
///
/// Those are the same two transforms ruling W5-36 answered for the
/// secret-*derived* branch with withhold-don't-scrub. So the caller no
/// longer relies on this scrub to cover them: a declared secret's
/// **presence** in `base_ref` now routes the provider's own text through
/// `safe_summary()` exactly as provenance does — a property of the input,
/// which nothing `git` does to the value afterwards can defeat. This
/// function's remaining job is the verbatim layer: the echoed value itself,
/// and any declared secret appearing in text that reaches a message through
/// some other route (a downstream provider's release error, say).
///
/// **The two channels that actually reach here** (final round part 2, item
/// 2 — an earlier version of this comment named `env('NAME')` as one of
/// them, which is wrong: `'`, `(` and `)` are all in
/// `parse/steps.rs`'s `FORBIDDEN_GIT_REF_CHARS`, so
/// `"${{ env('NAME') }}"` as a `base_ref` is rejected at parse time and
/// never reaches this function):
///
/// 1. **A literal paste** — the author writing the credential straight into
///    `base_ref:`. `validate_git_ref` bounds *which* literals get here: its
///    forbidden set includes `"`, `\`, quotes and shell metacharacters, so
///    a value carrying any of those is rejected at parse time and a plain
///    one passes.
/// 2. **A placeholder over public data** — `base_ref: "${{ item }}"` (or
///    any other public root) whose *resolved* value happens to equal a
///    declared secret. The template text is what parse-time validation
///    sees; the resolved value is never re-validated, so this channel can
///    carry the characters channel 1 cannot — which is exactly what made
///    the `Debug`-escaping hole at the call site reachable.
///
/// This function was deleted in Task 34's fix round 3, which replaced
/// *scrubbing* with *withholding* on the secret-derived branch (ruling
/// W5-36) and took the backstop off the non-secret-derived branch with it.
/// The withhold is the right fix for its own branch and is unchanged; this
/// restores the independent backstop the other branch always had.
fn redact_message(message: String, needles: &[String]) -> String {
    match redact_with_needles(&Value::String(message), needles) {
        Value::String(s) => s,
        other => unreachable!(
            "redact_with_needles(Value::String(_), _) always returns Value::String, got {other:?}"
        ),
    }
}

fn value_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Object(_) => "an object",
        Value::Array(_) => "an array",
    }
}

/// Names a `MapIsolationDef` tier for an error message — never its
/// contents (this enum's own variants carry no attacker/secret-influenced
/// data besides `Worktree`'s `base_ref`, which this function never touches).
fn map_isolation_tier_name(def: &MapIsolationDef) -> &'static str {
    match def {
        MapIsolationDef::None => "none",
        MapIsolationDef::Worktree { .. } => "worktree",
        MapIsolationDef::Sandbox => "sandbox",
        MapIsolationDef::Container => "container",
        MapIsolationDef::Remote => "remote",
    }
}

// ---------------------------------------------------------------------------
// The per-item evaluation this file owns, factored out of
// `Executor::dispatch_map_step`'s own closure so the **other** fan-out loop —
// `crate::exec::run_loop::Loop::dispatch_map`, the wave-driven one that alone
// can suspend a run — calls the same code rather than a second copy of it
// (Phase 8 Task 25.7 Task 2).
//
// Which loop runs a `map` is decided by who dispatched the step: a caller
// with a `workflow_run` row behind it (`run_loop::run_workflow`) drives the
// wave loop, and the in-memory sequencer (`Executor::run_to_completion`)
// drives this file's synchronous one. Everything *below* that split —
// evaluating `over:`, the item-count cap, binding `as:`, materializing and
// releasing an item's worktree, refusing a nested `report:`, folding an inner
// step's outcome into the item's, and assembling the map's own aggregate
// output — is the same decision either way, so it lives here, once.
// ---------------------------------------------------------------------------

/// `map.over`'s evaluation, [`MAX_MAP_ITEMS`] check and array type check —
/// every refusal being a `StepOutcome` the caller returns for the whole `map`
/// step, exactly as `dispatch_map_step` always did.
///
/// Returns the collection's own [`Evaluated`] alongside the items, because
/// binding one item goes through [`Evaluated::derive`] off it rather than
/// re-asserting a per-item taint — see [`Executor::dispatch_map_step`]'s own
/// doc comment for the ruling P37/P45 argument that makes that the only
/// sanctioned binding route.
///
/// The refusal is boxed because [`StepOutcome`] is the larger of the two
/// variants by an order of magnitude and every call here succeeds in the
/// ordinary case (`clippy::result_large_err`).
pub(crate) fn resolve_map_items(
    ctx: &crate::expr::ExprContext,
    step_id: &str,
    over: &str,
) -> Result<(crate::expr::Evaluated, Vec<Value>), Box<StepOutcome>> {
    let over_evaluated =
        match eval_delimited_expression(TemplateSource::from_workflow_file(over), ctx) {
            Ok(v) => v,
            Err(e) => {
                return Err(Box::new(StepOutcome::failed(
                    step_id,
                    format!("evaluating `map.over`: {e}"),
                )));
            }
        };
    let items: Vec<Value> = match over_evaluated.value() {
        Value::Array(items) => {
            // Fix round 2, item 4: the cap check runs on the *borrowed*
            // array, before it is cloned into `items: Vec<Value>`, so a
            // rejected call never even pays for that clone — see
            // `Executor::dispatch_map_step`'s own doc comment,
            // "`MAX_MAP_ITEMS`", for what this bounds and does not.
            if items.len() > MAX_MAP_ITEMS {
                return Err(Box::new(StepOutcome::failed(
                    step_id,
                    format!(
                        "`map.over` yielded {} items, exceeding the {MAX_MAP_ITEMS}-item \
                         limit for a single `map` step",
                        items.len()
                    ),
                )));
            }
            items.clone()
        }
        other => {
            return Err(Box::new(StepOutcome::failed(
                step_id,
                format!(
                    "`map.over` must evaluate to an array, got {}",
                    value_type_name(other)
                ),
            )));
        }
    };
    Ok((over_evaluated, items))
}

/// The `map`'s own `steps:` list, parsed once per dispatch. A parse failure
/// fails the whole `map` step — workflow YAML is untrusted input, so it is a
/// step outcome rather than a panic. Boxed for the reason
/// [`resolve_map_items`] records.
pub(crate) fn parse_map_inner_steps(
    step_id: &str,
    inner_step_yaml: &[serde_yaml::Value],
) -> Result<Vec<StepDef>, Box<StepOutcome>> {
    inner_step_yaml
        .iter()
        .map(parse_step)
        .collect::<Result<Vec<StepDef>, _>>()
        .map_err(|e| {
            Box::new(StepOutcome::failed(
                step_id,
                format!("parsing `map` inner steps: {e}"),
            ))
        })
}

/// **A `report:` is a property of the run, not of a map item** — the same
/// argument already written for the nested `call:` refusal in
/// [`crate::exec::Executor::dispatch_step`]'s catch-all arm, applied to
/// another step kind with run-wide meaning (B12c fix round, ruling P116 §B).
///
/// **And it is the one of the three that stays refused.** A nested `gate:`
/// carried the same "this is run-wide" objection until Phase 8 Task 25.7
/// Task 6, which resolved it rather than accepting it: a park *is* run-wide,
/// so one item's gate now parks the whole run and the durable record says
/// which item. `report:` has no such resolution, and not for want of
/// plumbing — a run has exactly one report (ruling P112), so an item cannot
/// be given one without taking it from the run.
///
/// Refused where the nesting *is* visible rather than in that arm, because
/// `dispatch_step` is also how a *top-level* `report:` step is run, by both
/// `run_to_completion` and `run_loop::run_workflow`, and the arm cannot tell
/// the two callers apart.
///
/// What it costs to leave open: `run_workflow`'s §8.6 "exactly one report"
/// pre-check flattens only the three phase step lists, so it structurally
/// cannot see a `report:` under a `map` — and a nested one emits one
/// `TaskKind::Report` task **per item**, into a log that physically rejects
/// `UPDATE`/`DELETE`. Ruling P112's invariant would then be violated by a
/// workflow the pre-check accepted.
pub(crate) fn nested_report_refusal(inner: &StepDef) -> Option<ItemOutcome> {
    matches!(inner.body, StepBody::Report { .. }).then(|| {
        ItemOutcome::Failed(format!(
            "step `{}`: a `report:` step cannot run inside a `map`: §8.6's report is a \
             property of the run, and one per item would leave the Runs inbox choosing \
             between them",
            inner.id
        ))
    })
}

/// Folds one inner step's [`StepOutcome`] into the item's running result and
/// the `map`'s aggregate taint, returning whether the item's inner loop must
/// stop.
///
/// **Fix round 1, item 4: an item fails as soon as ANY inner step fails.**
/// The first landed version tracked only the most recently dispatched inner
/// step's outcome, unconditionally overwritten by every subsequent one — so a
/// *non-final* inner step's failure was silently replaced by whatever the
/// following step returned, and both `fail_fast` and `collect` reported full
/// success. Stopping here, on the first `Failed`, is what keeps the failure.
///
/// **Fix round 3, item 1: both taint bits are folded, not just the output
/// one.** [`ItemOutcome`] has no field for an inner step's
/// `gate_condition_was_secret_derived`, so without this the flag
/// [`evaluate_when_gate`] computed — including the `Err` arm's deliberate,
/// fail-safe `true` — was dropped at every item boundary. Both mean the same
/// thing to a caller deciding whether `${{ steps.<map_id>.output }}` needs
/// redaction downstream, so one aggregate carries both.
pub(crate) fn fold_inner_step_outcome(
    last: &mut ItemOutcome,
    outcome: StepOutcome,
    any_item_secret_derived: &mut bool,
) -> bool {
    *any_item_secret_derived |= outcome.output_is_secret_derived;
    *any_item_secret_derived |= outcome.gate_condition_was_secret_derived;
    match outcome.status {
        StepStatus::Failed { message } => {
            *last = ItemOutcome::Failed(message);
            true
        }
        StepStatus::Skipped { reason } => {
            *last = ItemOutcome::Skipped { reason };
            false
        }
        StepStatus::Completed => {
            *last = ItemOutcome::Completed(outcome.output);
            false
        }
    }
}

/// The `${{ }}` roots one `map` step's item loop rebinds, captured before the
/// first item and reverted after the last.
pub(crate) struct MapRootSnapshots {
    as_name: crate::expr::RootSnapshot,
    /// `None` unless this `map` step *explicitly* declared `isolation:
    /// worktree` — the common case (the field absent, inheriting
    /// `Defaults.isolation`) must leave any outer binding of
    /// [`WORKTREE_ROOT_NAME`] completely undisturbed.
    worktree: Option<crate::expr::RootSnapshot>,
}

/// Opens the one snapshot/restore span a `map` step's item loop runs inside —
/// see [`Executor::dispatch_map_step`]'s own doc comment, "Why binding onto
/// the shared context and reverting by name is correct against
/// cross-step/cross-level poisoning", for the atomicity argument both fan-out
/// loops depend on. Shared rather than written twice precisely because that
/// argument is what makes a nested `map` reusing the same `as:` name safe.
pub(crate) fn snapshot_map_roots(
    ctx: &crate::expr::ExprContext,
    as_name: &str,
    isolation: Option<&MapIsolationDef>,
) -> MapRootSnapshots {
    MapRootSnapshots {
        as_name: ctx.snapshot_root(as_name),
        worktree: matches!(isolation, Some(MapIsolationDef::Worktree { .. }))
            .then(|| ctx.snapshot_root(WORKTREE_ROOT_NAME)),
    }
}

/// Closes the span [`snapshot_map_roots`] opened.
pub(crate) fn restore_map_roots(
    ctx: &mut crate::expr::ExprContext,
    as_name: &str,
    snapshots: MapRootSnapshots,
) {
    ctx.restore_root(as_name, snapshots.as_name);
    if let Some(snapshot) = snapshots.worktree {
        ctx.restore_root(WORKTREE_ROOT_NAME, snapshot);
    }
}

/// The `map` step's own [`StepOutcome`], assembled from every item's result.
///
/// **Fix round 2, item 5 (recorded, not fixed here — Task 8's job):** the
/// status is unconditionally `Completed`, even when every item failed. See
/// [`Executor::dispatch_map_step`]'s own doc comment, "The map's own
/// aggregate status is unconditionally `Completed`", for the measured
/// payload and why deciding what it *should* be is a policy question that
/// belongs with a stop-on-failure mechanism rather than a one-line change
/// made here.
pub(crate) fn map_step_outcome(
    step_id: &str,
    result: &MapRunResult,
    any_item_secret_derived: bool,
) -> StepOutcome {
    StepOutcome {
        step_id: step_id.to_string(),
        output: serde_json::json!({
            "items": result.outcomes.iter().map(item_outcome_to_json).collect::<Vec<_>>(),
            "collected_errors": result.collected_errors,
        }),
        status: StepStatus::Completed,
        output_is_secret_derived: any_item_secret_derived,
        // This is the map STEP'S OWN gate — whether *this* `map` step's own
        // `when:` (if it has one) read secret material — not a record of its
        // inner items' gates; those are folded into
        // `output_is_secret_derived` above (fix round 3, item 1), the only
        // field this outcome has that can carry an aggregate. `false` here is
        // a placeholder identical in kind to `StepOutcome::failed`'s own
        // (`crate::exec::mod`): every caller overwrites this field
        // immediately after, from *their* `evaluate_when_gate` call on *this*
        // step. Do not read the `false` below as a statement about this map's
        // own gate.
        gate_condition_was_secret_derived: false,
    }
}

/// One item's isolation, for as long as that item's inner steps are running.
///
/// Carries the guard **and** the withhold decision its `base_ref` produced,
/// because the release path at the end of the item has to apply the same
/// withhold rule the materialize path did (final round part 2, M1) — two
/// paths out of one worktree's lifecycle that must not diverge.
pub(crate) struct ItemWorktree {
    guard: Option<WorktreeGuard>,
    /// Whether this item's `base_ref` carried secret *material*, either
    /// because provenance marked the value or because a declared secret's raw
    /// value is inside it. See [`Executor::prepare_item_isolation`] for why
    /// the second disjunct exists.
    base_ref_carried_secret_material: bool,
}

impl ItemWorktree {
    /// Whether a real worktree was materialized for this item — `false` for
    /// every `map` step that did not explicitly declare `isolation:
    /// worktree`, which is the common case.
    pub(crate) fn holds_worktree(&self) -> bool {
        self.guard.is_some()
    }
}

/// `Err(ItemOutcome::Failed(..))`, as one name, so
/// [`Executor::prepare_item_isolation`]'s refusals read as the item failures
/// they are rather than as `Result` plumbing.
fn item_isolation_failed(message: String) -> Result<ItemWorktree, ItemOutcome> {
    Err(ItemOutcome::Failed(message))
}

impl<'a> Executor<'a> {
    /// Task 34, and Phase 8 Task 25.7 Task 2's extraction of it: materialize
    /// one item's worktree when this `map` step explicitly demanded one.
    ///
    /// The whole reasoning lives on [`Self::dispatch_map_step`]'s own doc
    /// comment — "Task 34: `isolation: worktree` materialization" (fail-closed
    /// on a missing provider, per-item `base_ref` interpolation, the binding
    /// mechanism) and "Fix round 1, item 1" (the taint-leak fix). What is new
    /// here is only *where it lives*: both fan-out loops call this one
    /// function, so the withhold rules a `base_ref` carrying secret material
    /// triggers cannot be got right in one loop and wrong in the other.
    ///
    /// `any_item_secret_derived` is taken by `&mut` rather than returned,
    /// because the `base_ref` taint must be folded in **before** `materialize`
    /// is attempted — so it is set on the failure path too, not only when a
    /// worktree comes back.
    pub(crate) fn prepare_item_isolation(
        &mut self,
        step_id: &str,
        isolation: Option<&MapIsolationDef>,
        item_evaluated: &crate::expr::Evaluated,
        any_item_secret_derived: &mut bool,
    ) -> Result<ItemWorktree, ItemOutcome> {
        let mut worktree_guard: Option<WorktreeGuard> = None;
        // Carried out of the match below and returned on
        // `ItemWorktree`, so that `Self::release_item_isolation` can apply
        // the same withhold rule the materialize arm does (final round part
        // 2, M1). A release error from *this* crate's adapter never sees
        // `base_ref` — `remove_worktree` is handed a generated uuid path and
        // `--force` — but `WorktreeProvider` is a `pub` trait whose doc tells
        // an implementor its release errors are persisted under the same
        // rule, and a caller that ignored that on one of the two paths would
        // make the promise a half-truth.
        //
        // Named for what it actually holds (part 3, W5-48): secret
        // *material*, either because provenance marked the value or because a
        // declared secret's raw value is inside it. See the assignment below
        // for why the second disjunct exists.
        let mut base_ref_carried_secret_material = false;
        match isolation {
            // Fix round 1, item 6 / fix round 2, item 3 (ruling W5-33):
            // `None` (the field absent) and an explicit `isolation: none`
            // take the same no-op arm, but they are not the same claim — see
            // `Executor::dispatch_map_step`'s own doc comment, "Task 34", for
            // why `None` here is a known, tolerated gap (P42's shape for the
            // *inherited* default) and not "genuinely deliverable" the way
            // explicit `none` is. See the match arm below for the other three
            // tiers, which this crate cannot deliver and does not tolerate
            // silently.
            None | Some(MapIsolationDef::None) => {}
            Some(MapIsolationDef::Worktree { base_ref }) => {
                let provider = match &self.worktree_provider {
                    Some(provider) => Arc::clone(provider),
                    None => {
                        return item_isolation_failed(format!(
                            "map step `{step_id}` declares `isolation: worktree`, but no \
                             WorktreeProvider is configured for this run \
                             (RunContext::worktree_provider is None) — refusing to run \
                             this item without the isolation it explicitly asked for, \
                             rather than silently running it unisolated"
                        ));
                    }
                };
                // Fix round 1, item 1 (CRITICAL): `base_ref` may
                // contain `${{ secrets.* }}`, and `interpolate`
                // computes both renderings from one evaluation
                // (ruling P33) precisely so a caller never has to
                // evaluate twice to get a safe-to-log copy. The
                // *redacted* rendering is what goes into every
                // message this arm can return; the *unredacted*
                // one is used strictly for the
                // `provider.materialize` call itself — mirroring
                // `Executor::dispatch_step`'s own `Agent`/`Tool`
                // arms (`resolved_prompt`/`resolved_with` vs.
                // `logged_prompt`/`logged_with`), which this arm
                // did not follow the first time it was written.
                let (unredacted_base_ref, redacted_base_ref, base_ref_is_secret_derived) =
                    match base_ref {
                        Some(text) => {
                            match interpolate(TemplateSource::from_workflow_file(text), &self.ctx) {
                                Ok(interpolated) => {
                                    // The part that actually repairs the
                                    // persisted taint flag — see
                                    // `Executor::dispatch_map_step`'s own
                                    // doc comment, "Fix round 1, item 1".
                                    // Folded in unconditionally, before
                                    // `materialize` is even attempted, so it
                                    // is set on both the success and the
                                    // failure path below — which is why this
                                    // function takes the flag by `&mut`
                                    // rather than returning it.
                                    let is_secret_derived = interpolated.is_secret_derived();
                                    *any_item_secret_derived |= is_secret_derived;
                                    let redacted = interpolated.redacted_for_logging().clone();
                                    (
                                        interpolated.into_unredacted_for_dispatch(),
                                        redacted,
                                        is_secret_derived,
                                    )
                                }
                                Err(e) => {
                                    // No needle scrub here, unlike
                                    // the two arms below (final
                                    // round part 2, recorded rather
                                    // than changed). Clean by
                                    // construction, not by
                                    // oversight: every `ExprError`
                                    // payload is *source text*
                                    // captured before evaluation
                                    // (never a value), and a pasted
                                    // credential cannot be inside
                                    // that source text — `"`, `'`
                                    // and `\` are all in
                                    // `parse/steps.rs`'s
                                    // `FORBIDDEN_GIT_REF_CHARS`, so
                                    // a `base_ref` carrying an
                                    // expression cannot also carry a
                                    // quoted literal. If that
                                    // charset is ever relaxed, this
                                    // arm needs the same backstop
                                    // the failure arms below have.
                                    return item_isolation_failed(format!(
                                        "map step `{step_id}`: resolving \
                                         `isolation.worktree.base_ref`: {e}"
                                    ));
                                }
                            }
                        }
                        None => (
                            DEFAULT_WORKTREE_BASE_REF.to_string(),
                            DEFAULT_WORKTREE_BASE_REF.to_string(),
                            false,
                        ),
                    };
                // **Provenance is not the only reason to withhold
                // (final round part 3, ruling W5-48).** A declared
                // secret's raw value can reach `base_ref` through a
                // channel provenance treats as clean, and the needle
                // scrub alone cannot cover that case: `git` does not
                // always echo a *copy* of what it was given.
                // `@{upstream}`-style syntax makes it die
                // mid-interpretation and report only the prefix
                // before the mark (measured: 27 of a 38-byte secret,
                // cleartext), and a value past `git`'s own `vreportf`
                // stderr buffer — **`git`'s buffer, ~4KB, not this
                // workspace's `OUTPUT_CAP`**; a 3024-byte value
                // scrubs fully and a 5029-byte one does not — comes
                // back as a shorter, still-sensitive prefix. A
                // whole-value needle matches neither.
                //
                // These are the exact two lossy transforms ruling
                // W5-36 already answered with withhold-don't-scrub
                // for the secret-*derived* branch; the scrub-only
                // branch silently inherited the limitation. So a
                // declared secret's *presence* in the value is
                // treated the same as provenance: it is a property
                // of the input, so nothing `git` does to the value
                // afterwards can defeat it.
                //
                // **What this costs, and why it is not a bug to fix
                // (ruling W5-49).** This withholds strictly more
                // often than provenance alone would: a declared
                // secret appearing anywhere inside `base_ref` — as a
                // substring, not only as the whole value —
                // suppresses the provider's own diagnostic text for
                // that item, so an operator debugging a genuine
                // `git` failure gets `safe_summary()`'s rendering —
                // the variant, the program name, the repository
                // root, the generated worktree path and the exit
                // status, all crate-generated — instead of `git`'s
                // own message and argv. That is accepted, for
                // three reasons a future reader should weigh before
                // narrowing it:
                //
                // 1. The failure direction is **diagnostics, not
                //    secrecy** — the correct way to fail at this
                //    boundary, and the same trade ruling W5-36 made
                //    when it chose withholding over scrubbing.
                // 2. It cannot fire on an ordinary short string.
                //    `Executor::new` **refuses to build a run at
                //    all** if any declared secret is shorter than
                //    `MIN_REDACTABLE_SECRET_LEN` (8 bytes) — see
                //    `ExecutorError::SecretTooShortToRedact` — so
                //    nothing like `main` or `HEAD` can ever be a
                //    needle here.
                // 3. Narrowing it means **not** withholding when a
                //    declared secret is demonstrably present in the
                //    value, i.e. trading secrecy back for
                //    diagnostics. That is the wrong direction, and
                //    it reintroduces exactly the gap the two
                //    transforms above make reachable.
                let base_ref_carries_secret_material = base_ref_is_secret_derived
                    || self
                        .redaction_needles
                        .iter()
                        .any(|needle| unredacted_base_ref.contains(needle.as_str()));
                base_ref_carried_secret_material = base_ref_carries_secret_material;
                match provider.materialize(&unredacted_base_ref) {
                    Ok(path) => {
                        // Derived from `item_evaluated`, not asserted fresh
                        // via `set_public`/`set_secret` — see
                        // `Executor::dispatch_map_step`'s own doc comment,
                        // "Task 34", for why, even though the path's own
                        // content is never secret material.
                        let workspace_evaluated = item_evaluated
                            .derive(serde_json::json!({ "path": path.display().to_string() }));
                        self.ctx.set_from(WORKTREE_ROOT_NAME, &workspace_evaluated);
                        worktree_guard = Some(WorktreeGuard::new(provider, path));
                    }
                    Err(e) => {
                        // Fix round 1, item 1 found a secret-derived
                        // `base_ref` reaching `{e}`'s free text
                        // (git's stderr, the echoed argv) verbatim.
                        // Fix round 2 tried closing it by adding
                        // `unredacted_base_ref` as an extra
                        // needle-based scrub. Fix round 3, item 1
                        // (ruling W5-36) retracts that shape:
                        // `git`'s stderr is not always a **copy** of
                        // what it was given — `@{upstream}`-style
                        // syntax makes `git` die mid-interpretation
                        // and echo only a prefix, and `git`'s own
                        // stderr buffer silently truncates values
                        // past ~4KB — so an exact-match needle keyed
                        // on the whole original value can miss a
                        // still-sensitive transformed or truncated
                        // echo entirely, no matter how the needle is
                        // chosen. No scrub of a *lossy* transform
                        // can be made reliable.
                        //
                        // **Fix: withhold, don't scrub.** When
                        // `base_ref` is secret-derived, this message
                        // uses [`WorktreeProviderError::safe_summary`]
                        // instead of `e`'s own `Display` — it keeps
                        // this crate's own vocabulary (which
                        // variant, the exit status) and drops every
                        // piece of free text from outside this
                        // crate's control (argv, stderr, OS error
                        // text) entirely, rather than trying to
                        // predict what a lossy external transform
                        // might do to a scrub. See that method's own
                        // doc comment for the full reasoning. A
                        // `base_ref` that is *not* secret-derived
                        // still gets the full, unwithheld message —
                        // scrubbed through the declared-secrets
                        // needle backstop below, which is a
                        // different guard closing a different hole
                        // (see [`redact_message`]'s own doc comment,
                        // "Why this is needed on top of the
                        // withhold"). Fix round 3 deleted that
                        // backstop along with the scrub it was
                        // replacing; the final round restored it.
                        let detail = if base_ref_carries_secret_material {
                            e.safe_summary().to_string()
                        } else {
                            e.to_string()
                        };
                        // **Scrubbed here, as a plain string, before
                        // the `format!` below embeds it (final round
                        // part 2, item 1).** The first version of
                        // this fix assembled the message first and
                        // scrubbed the whole thing afterwards, which
                        // the security lens defeated: `Debug for str`
                        // escapes `"`, `\` and control characters, so
                        // a declared secret containing any of them no
                        // longer matches the plain-substring needle
                        // *in the `{:?}` copy* while the raw copies
                        // (the argv echo, `git`'s stderr) scrub fine.
                        // Reproduced end to end — two of three
                        // occurrences became `***` and the escaped
                        // one reached the append-only log in
                        // trivially reversible form. Scrubbing first
                        // means `{:?}` has only `***` to escape.
                        let echoed_base_ref =
                            redact_message(redacted_base_ref, &self.redaction_needles);
                        let message = format!(
                            "map step `{step_id}`: materializing a worktree for \
                             base_ref {echoed_base_ref:?}: {detail}"
                        );
                        return item_isolation_failed(if base_ref_is_secret_derived {
                            // Nothing here for a needle to find:
                            // `safe_summary()` carries no text from
                            // outside this crate at all, and
                            // `redacted_base_ref` was already `***`
                            // because provenance caught it.
                            message
                        } else {
                            // Still the whole message, for the
                            // `{detail}` half: that is raw `Display`
                            // text (`git`'s stderr and the echoed
                            // argv), so it scrubs correctly after
                            // assembly. Only the `{:?}` half had to
                            // move ahead of the `format!`.
                            redact_message(message, &self.redaction_needles)
                        });
                    }
                }
            }
            // Fix round 1, item 6: `sandbox`/`container`/`remote`
            // parse successfully (`parse/steps.rs` accepts all five
            // tiers) but this crate can only ever materialize
            // `worktree` — falling through silently here would be
            // exactly Phase 5 ruling P42's shape for three of the
            // four non-`none` tiers, in a diff whose own docs now
            // claim P42 is closed. Fails the item closed, the same
            // way a missing `WorktreeProvider` does, rather than
            // running it with no isolation and no warning.
            Some(
                other @ (MapIsolationDef::Sandbox
                | MapIsolationDef::Container
                | MapIsolationDef::Remote),
            ) => {
                return item_isolation_failed(format!(
                    "map step `{step_id}` declares `isolation: {}`, but this crate can \
                     only materialize `worktree` isolation today — refusing to run this \
                     item with no isolation at all rather than silently ignoring the \
                     tier it explicitly asked for",
                    map_isolation_tier_name(other)
                ));
            }
        }

        Ok(ItemWorktree {
            guard: worktree_guard,
            base_ref_carried_secret_material,
        })
    }

    /// The other half of one item's worktree lifecycle, extracted for the
    /// same reason [`Self::prepare_item_isolation`] is: two fan-out loops,
    /// one release rule.
    pub(crate) fn release_item_isolation(
        &self,
        step_id: &str,
        item_worktree: ItemWorktree,
        last: ItemOutcome,
    ) -> ItemOutcome {
        let ItemWorktree {
            guard: worktree_guard,
            base_ref_carried_secret_material,
        } = item_worktree;
        let mut worktree_guard = worktree_guard;
        let mut last = last;
        // Task 34: called on **every** path out of an item — the caller's
        // inner-step loop may have broken on a failure, fallen through after
        // every inner step ran, or (via `nested_report_refusal`) never
        // entered its body at all; all three reach here. A release failure
        // only overwrites `last` when the item would otherwise have reported
        // success/skip — an item that already failed for its own reason keeps
        // that reason, which is more actionable than a release failure
        // piggy-backing on it. See `WorktreeGuard::release`'s own doc comment
        // for why this explicit call, not `Drop` alone, is what lets a
        // release failure reach `last` at all on this (the non-panicking)
        // path.
        if let Some(guard) = worktree_guard.take() {
            if let Err(e) = guard.release() {
                if !matches!(last, ItemOutcome::Failed(_)) {
                    // Both guards the materialize arm applies, for
                    // the same reasons, so the two paths out of one
                    // item's worktree lifecycle cannot diverge:
                    // withhold when this item's `base_ref` was
                    // secret-derived (final round part 2, M1 —
                    // `safe_summary()` is what the trait promises an
                    // implementor is used), and the declared-secrets
                    // needle backstop on top either way (item A1 —
                    // `{e}` embeds free text this crate does not
                    // control). See [`redact_message`]'s own doc
                    // comment for why the two are independent.
                    let detail = if base_ref_carried_secret_material {
                        e.safe_summary().to_string()
                    } else {
                        e.to_string()
                    };
                    last = ItemOutcome::Failed(redact_message(
                        format!(
                            "map step `{step_id}`: releasing the item's worktree: \
                             {detail}"
                        ),
                        &self.redaction_needles,
                    ));
                }
            }
        }

        last
    }
    /// Dispatches a `StepBody::Map` for the **in-memory** sequencer —
    /// evaluates `over:` for real against the current expression context,
    /// then for each item binds it under the step's `as:` name (so
    /// `${{ pr.number }}` inside the map's inner steps resolves to that item,
    /// not `Null`) before dispatching the inner steps via
    /// [`Executor::dispatch_step_or_stub`].
    ///
    /// **A `map` inside a real run does not come here** (Phase 8 Task 25.7
    /// Task 2): `run_loop::Loop::run_phase` intercepts `StepBody::Map` the
    /// same way it already intercepts `gate:`/`call:`, and
    /// `run_loop::Loop::dispatch_map` drives the fan-out in suspendable
    /// waves. See this module's own doc comment, "There are two `map` fan-out
    /// loops", for the split and for the list of per-item decisions both
    /// loops share rather than duplicate. Everything below describes the
    /// per-item evaluation, which is common to both; only the dispatch of an
    /// inner step differs.
    ///
    /// # Per-item binding: `Evaluated::derive` plus a per-root snapshot/restore, not a context clone (ruling P40/P44/P45/P46, R-1/R-2)
    ///
    /// `over:` is evaluated **once**, via [`eval_delimited_expression`],
    /// producing one [`crate::expr::Evaluated`] over the whole collection —
    /// this crate has no operation that evaluates one collection element
    /// independently, so every item necessarily inherits the same
    /// `secret_derived` flag the *collection* carries (ruling P45: this is
    /// accepted, not a defect — see [`crate::expr::ExprContext::set_public`]'s
    /// own doc comment for the accepted 500-item figure). Binding one item
    /// therefore cannot go through `ExprContext::set_secret`/`set_public`
    /// (both require the caller to *assert* a taint it does not actually
    /// know per element) or through a hand-built `Evaluated` (exactly the
    /// re-assertion-by-the-back-door ruling P37 exists to remove). Instead:
    /// [`crate::expr::Evaluated::derive`] produces a per-item `Evaluated`
    /// whose `secret_derived` is read off the collection's own evaluation,
    /// and it is bound with `ExprContext::set_from` **directly onto
    /// `self.ctx`** — the run's own, shared context, not a clone of it —
    /// which propagates rather than re-asserts (ruling P37).
    ///
    /// # History of this mechanism — two prior designs, both replaced for measured reasons
    ///
    /// (Recorded so a future reader who finds an old fix-round report
    /// describing either prior design does not mistake it for what the code
    /// currently does — ruling P46: a mechanism change is accepted only once
    /// every prose description of the *old* mechanism, crate-wide, has been
    /// reconciled, not just the sites a report named.)
    ///
    /// 1. **Landed with this task: a fresh `ExprContext` clone per item**,
    ///    forked from the pre-map context, discarded after each item. Closed
    ///    the cross-step poisoning hazard (see "Why this is still correct"
    ///    below) but, because `ExprContext::clone` deep-clones every bound
    ///    root including `inputs`/`vars`/`secrets`/`steps`, cost
    ///    **O(items × context size)** — 20,000 items measured at 148.7 s.
    /// 2. **Fix round 1: one `ExprContext` clone per `map` STEP, not per
    ///    item** — `self.ctx` cloned once before the item loop, mutated in
    ///    place per item, restored once after. Fixed the flat (non-nested)
    ///    case (2,000 items: 3.15 ms) but a nested `map` is dispatched once
    ///    per enclosing item, so the **clone count is the product of
    ///    enclosing item counts** — `map(2000) -> map(1) -> emit`, identical
    ///    4,000 events as a flat 2,000-item map, a 32 MB unreferenced
    ///    `inputs.pad`: flat **4.83 ms**, nested **5.366 s** — 1,111× for the
    ///    same event count (fix round 3 correction: measured for
    ///    `task-14-fix-2.md`'s own brief, not fix round 2's own reproduction
    ///    of this now-replaced design, which independently got 3.625 s at
    ///    32 MB on different hardware — same order of magnitude, same
    ///    conclusion; the security lens's own independent reproduction this
    ///    round got 5.49 s, corroborating the brief's figure over round 2's
    ///    own run). A fix-round-1 doc section stated the flat measurement's
    ///    "no longer multiplied by item count" conclusion unconditionally,
    ///    which was false the moment nesting was tried.
    /// 3. **Fix round 2 (current): snapshot and restore the *one root*
    ///    `as_name`, not the whole context.** [`crate::expr::ExprContext::snapshot_root`]/
    ///    [`crate::expr::ExprContext::restore_root`] capture and revert one
    ///    name's value *and* provenance, atomically, in O(1) — see the next
    ///    section for why this is still correct, and "Re-measured" below for
    ///    what it costs under nesting now.
    ///
    /// # Why binding onto the shared context and reverting by name is correct against cross-step/cross-level poisoning
    ///
    /// `ExprContext` provenance is monotone per root **name** and
    /// irreversible **for the life of one `ExprContext` instance** — see
    /// [`crate::expr::ExprContext::set_public`]'s own doc comment. What makes
    /// binding directly onto the long-lived, shared `self.ctx` safe is not
    /// (only) that every item in one `map` step shares one taint bit — it is
    /// that **[`crate::expr::ExprContext::restore_root`] reverts a root's
    /// value and provenance together, atomically**, so `self.ctx` can never
    /// be observed holding a stale value under a provenance that does not
    /// match it. Monotonicity is therefore an invariant of the *span between
    /// a snapshot and its restore*, not of the executor as a whole — and
    /// `dispatch_map_step` deliberately opens and closes exactly one such
    /// span per call, once around the whole item loop:
    ///
    /// 1. Before the first item: `outer_snapshot = self.ctx.snapshot_root(as_name)`.
    /// 2. Per item: `self.ctx.set_from(as_name, &item_evaluated)` — an O(1)-ish
    ///    `HashMap` insert, never a clone of anything but the one bound value.
    /// 3. After the *whole* `run_map` call (every item processed):
    ///    `self.ctx.restore_root(as_name, outer_snapshot)`.
    ///
    /// This is what makes the earlier, weaker justification ("one taint bit
    /// per map step, so repeated `set_from` at a constant level cannot
    /// mis-escalate") not the load-bearing reason, and not sufficient on its
    /// own: it says nothing about **nested** maps sharing a name, where the
    /// inner map's own taint bit can genuinely differ from the outer's.
    /// Measured, the case the atomicity argument has to survive: outer
    /// `as: item` clean, inner (nested) `map` also `as: item`, secret. Inside
    /// the nested `map`, `${{ item }}` correctly logs `***`
    /// (`tests/map_step.rs`'s
    /// `a_nested_maps_secret_derived_as_name_does_not_poison_the_outer_maps_use_of_the_same_as_name`);
    /// once the nested `map` restores its own snapshot and returns, the
    /// *outer* item's remaining inner steps read `${{ item }}` again and get
    /// the outer's real, clean value in cleartext — the nested secret never
    /// survives past its own restore. The reverse direction (outer secret,
    /// inner clean, same name) is deliberately conservative rather than
    /// incorrect: the nested map's own clean items are over-redacted for the
    /// duration of the nested call (they share the outer's still-`Whole`
    /// provenance entry, since a clean [`crate::expr::ExprContext::set_public`]
    /// call cannot lower it) — the same accepted, safe-direction cost this
    /// crate already documents for same-name rebinding generally, never
    /// under-redaction.
    ///
    /// Also confirmed, the sibling-step case fix round 1 originally proved:
    /// `tests/map_step.rs`'s
    /// `a_secret_derived_maps_as_name_does_not_poison_a_later_clean_maps_use_of_the_same_as_name`
    /// — two **sibling** `map` steps, both `as: item`, the first over a
    /// secret-derived collection, the second over a genuinely clean one —
    /// the second map's items still log in cleartext, not `***`.
    ///
    /// # Re-measured after fix round 2, attribution corrected and the missing number filled in by fix round 3 (ruling P18/P46)
    ///
    /// Release build, through [`Executor::run_to_completion`], one trivial
    /// `emit` inner step. Flat case, same shape as fix round 1's own table
    /// (unaffected by this round's change, restated for comparison):
    ///
    /// | items | events | elapsed |
    /// |---|---|---|
    /// | 500 | 1,000 | ~0.9 ms |
    /// | 2,000 | 4,000 | ~3 ms |
    ///
    /// **The case that actually needed re-measuring — nesting** (`map(2000)
    /// items) -> map(1) item -> emit`, identical 4,000 events, `inputs.pad`
    /// varied, referenced by nothing):
    ///
    /// | pad | 0 B | 1 MB | 8 MB | 32 MB |
    /// |---|---|---|---|---|
    /// | nested, fix round 1 (whole-context clone per call)¹ | 23.9 ms | 50.8 ms | 353.8 ms | **5.366 s** |
    /// | nested, fix round 2 (snapshot/restore one root)² | 7.1 ms | 7.5 ms | 8.5 ms | **7.3 ms** |
    ///
    /// ¹ **Fix round 3 correction (ruling P18/P46):** these four numbers are
    /// `task-14-fix-2.md`'s own brief measurement of the *replaced*, fix
    /// round-1 design — not fix round 2's own reproduction of it, which
    /// independently measured 3.625 s at 32 MB on different hardware (same
    /// order of magnitude, same conclusion; the security lens's own
    /// independent reproduction in round 2's review got 5.49 s, corroborating
    /// the brief's figure over round 2's). Kept because it is still the right
    /// order of magnitude for the design it describes, now correctly
    /// attributed rather than left to read as this section's own claim.
    ///
    /// ² **Fix round 3's own measurement, filling in what this row
    /// previously left as prose only** ("flat regardless of `pad` — no
    /// clone of `inputs` occurs at any nesting level," true but with no
    /// number attached, which is exactly the gap ruling P18 exists to close)
    /// — release build, min of 3 runs each after a warm-up run, through
    /// [`Executor::run_to_completion`], identical 4,000 events at every pad
    /// size. Confirms the row's own prose: flat within measurement noise
    /// across the whole 0-32 MB range, not merely "much smaller than the
    /// fix round 1 numbers." Independently corroborated by the security
    /// lens's own reproduction in round 2's review: 6.7-9.0 ms at this same
    /// depth (two levels of nesting), 16-19 ms at three levels, also flat
    /// across 0-32 MB — this function does not measure the three-level case.
    ///
    /// Nesting cost is now **O(1) per level** (one `HashMap` get plus one
    /// insert/remove pair, per level, independent of context size) instead of
    /// O(context size) per level, which was itself multiplied across
    /// enclosing item counts. The residual cost of a nested `map` is now
    /// dominated by dispatch work ([`Executor::dispatch_step`]/
    /// [`evaluate_when_gate`] per inner step), not by anything this function
    /// clones.
    ///
    /// # `MAX_MAP_ITEMS`: an explicit, closed-fail item-count cap — bounds one call, NOT nesting (ruling P47)
    ///
    /// Fix round 1's clone-hoist (and fix round 2's further one) remove the
    /// *quadratic*/*multiplicative* cost terms but not the *unbounded* one:
    /// nothing stops `over:` from yielding an arbitrarily large array
    /// (data-driven — a webhook payload, a `map.over` expression reading
    /// `inputs`/`steps`). `MAX_TOP_LEVEL_STEPS` (500, `crate::parse::mod`)
    /// bounds a *workflow-authored* quantity; a `map` item count is
    /// *data-driven* and needs its own bound for the same reason.
    /// [`MAX_MAP_ITEMS`] fails the step **closed** (not silently truncated)
    /// before any item is dispatched — fix round 2, item 4: the check now
    /// runs on the **borrowed** `over_evaluated.value()` array, before it is
    /// cloned into `items: Vec<Value>`, so the one clone this function still
    /// does for `items` itself never happens for a rejected call either.
    ///
    /// **This bounds one `dispatch_map_step` call. It does NOT bound the
    /// product across nested `map`s** — the cap is *per call*, and a nested
    /// `map` is one call per enclosing item, so each nesting level gets its
    /// own full 2,000. Ruling P47, measured worst case **with the cap
    /// enforced**: a **511-byte**, three-level nested workflow (each level
    /// `map.over` a 2,000-element array) yields
    /// **2 × 2000³ = 1.6 × 10¹⁰ events, ≈ 7.7 hours** at the crate's own
    /// measured 577,000 events/s. Depth 4 is 3.2 × 10¹³. Neither
    /// `MAX_FLOW_NESTING_DEPTH` (256) nor `MAX_YAML_BYTES` (256 KB) is a
    /// binding constraint on this product. Closing it needs a *run-level*
    /// dispatched-task counter this crate does not have — Task 8's admission
    /// ledger (`ResourceCaps::max_tasks`) is the eventual owner, per
    /// [`MapBudget::unenforced_placeholder`]'s own doc comment. This number
    /// is recorded here, with its measurement, rather than left for a later
    /// reader to rediscover — a cap that reads as a bound while the real
    /// product is unbounded is the "placeholder that fails open" shape this
    /// phase has now hit twice.
    ///
    /// **The safe half of the same interaction (ruling P47):** `MAX_MAP_ITEMS`
    /// *does* bound the blast radius of ruling P45's accepted
    /// collection-granularity over-redaction — at most 2,000 blackened log
    /// lines per tainted collection, per `map` step. The cap and P45 interact
    /// in the safe direction even though the cap and the nested-fan-out
    /// hazard above interact in the unsafe one.
    ///
    /// Not a hazard, confirmed by fix round 1's security lens rather than
    /// assumed: recursion depth. `serde_yaml` rejects ≥64 nested `map`
    /// levels at parse time; depth ≤48 executes cleanly with no stack
    /// overflow. No additional guard added for that here.
    ///
    /// # `map.over`'s own residual (ROUND 2 carry-forward item 3, measured, not assumed)
    ///
    /// `expr.rs`'s quote-scanning residual (documented on
    /// `find_closing_delimiter`) can make an unterminated string literal
    /// inside one `${{ }}` block silently absorb what looks like a second,
    /// well-formed block, producing a `Value::String` — the swallowed text,
    /// literally, never evaluated — with **no error at all**. Unlike a
    /// `when:` gate (which only ever accepts `Value::Bool(true)`, so a merge
    /// can only turn it into a skip), `map.over` consumes the *value*
    /// directly, so nothing about the grammar itself protects it. What
    /// protects it here is this function's own explicit type check below: a
    /// resolved `over:` that is not a `Value::Array` fails the step closed,
    /// whatever produced it. Measured directly against this function (see
    /// `tests/map_step.rs`'s
    /// `an_unterminated_quote_can_merge_map_over_into_a_string_but_the_array_type_check_fails_it_closed`):
    /// `over: "${{ 'oops }} filler ${{ inputs.prs }} trailing' }}"` merges
    /// exactly as `expr.rs` predicts — `over_evaluated.value()` is
    /// `&Value::String("oops }} filler ${{ inputs.prs }} trailing")`, and
    /// `inputs.prs` is never evaluated — and the step below fails with
    /// `` `map.over` must evaluate to an array, got a string `` rather than
    /// iterating zero times, one time over the string, or any other silent
    /// substitute. This closes the "wrong type" half of the risk the
    /// carry-forward named. It does **not** close the other half named
    /// there — a merge that still produces a *type-correct* array, drawing
    /// data the author did not intend, from a different but equally
    /// workflow-file-controlled span of the same field's text — which
    /// `expr.rs`'s own doc comment already states is open by design (the
    /// grammar has no escape mechanism) and which no type check downstream
    /// can distinguish from an intentional array.
    ///
    /// # An item's own inner-step failure could be erased by a later inner step (fix round 1, item 4 — CLOSED)
    ///
    /// The first landed version tracked only `last`, the most recently
    /// dispatched inner step's outcome, unconditionally overwritten by every
    /// subsequent inner step regardless of status. So a **non-final** inner
    /// step's failure was silently replaced by whatever the *following*
    /// inner step returned — measured: 3 items, 2 inner steps each, the
    /// *first* inner step failing, both `on_item_error: collect` and
    /// `fail_fast` reported `map status=Completed`, every item
    /// `status=completed`, zero collected errors. `fail_fast` never stopped
    /// dispatching further items; `collect` gathered nothing; the map
    /// reported full success — exactly the distinction this task exists to
    /// establish, defeated.
    ///
    /// **Why the three `on_item_error` tests that shipped with this function
    /// did not catch it, which matters more than the bug itself:** all three
    /// drove [`run_map`] directly with a synthetic `run_item` closure — none
    /// went through this function at all. They validated the *loop*
    /// (`run_map`'s own `should_stop`/`collected_errors` logic, which was and
    /// is correct) in isolation from the thing that actually *populates* an
    /// `ItemOutcome` from a real item's inner steps. A test exercising only
    /// the helper cannot see a defect that lives in the caller.
    ///
    /// **The fix:** an item fails as soon as **any** inner step fails — the
    /// inner loop below breaks immediately on the first `StepStatus::Failed`,
    /// keeping that failure as the item's `ItemOutcome`, rather than
    /// continuing to the next inner step and letting it overwrite `last`.
    /// Non-failing inner steps (`Completed`/`Skipped`) still update `last` in
    /// sequence as before — only a `Failed` status stops the inner loop.
    /// Pinned by two integration tests **through this function**, not
    /// `run_map` directly, per the lesson above: `tests/map_step.rs`'s
    /// `on_item_error_collect_through_dispatch_map_step_gathers_a_non_final_inner_step_failure`
    /// and
    /// `on_item_error_fail_fast_through_dispatch_map_step_stops_at_a_non_final_inner_step_failure`,
    /// both with the failure in the **first** of two inner steps.
    ///
    /// # An inner step's own `when:` gate was silently ignored — fail-OPEN (fix round 2, item 1 — CLOSED, the reason this round exists)
    ///
    /// The first two landed versions of this function called
    /// [`Executor::dispatch_step`] directly for every inner step, and
    /// `dispatch_step` never read `step.when` — only
    /// [`Executor::run_to_completion`]'s own loop did, making it the crate's
    /// **only** site that evaluated a `when:` gate at all. So a `map` inner
    /// step's `when:` was never evaluated, at any nesting level, ever.
    ///
    /// Measured, `inputs.approved = false`: a top-level `tool: shell` step
    /// with `cmd: ["rm","-rf","/"]` guarded by
    /// `when: "${{ inputs.approved }}"` correctly `Skipped`; the *identical*
    /// step nested one level under a `map` **dispatched**, once per item.
    /// Worse: a gate that **fails to evaluate**
    /// (`when: "${{ no_such_fn(1) }}"`) is fail-*closed* (`Failed`, never
    /// dispatched) at top level — this crate's stated posture, re-ruled on
    /// repeatedly — but also **dispatched** when nested, because nothing in
    /// the `map` path evaluated `when:` to produce either the `Skipped` or
    /// the `Failed` outcome. A workflow author who moves a guarded
    /// destructive step inside a `map` for legitimate reasons (fan-out over
    /// a list of candidates, say) has the guard evaporate silently, once per
    /// item, with no error and no warning.
    ///
    /// **The fix:** [`evaluate_when_gate`] (`crate::exec`) — the exact
    /// `Ok(non-`Bool(true)`) -> Skipped` / `Err -> Failed` split
    /// `run_to_completion` already used, extracted into one function **both**
    /// dispatch paths call. See that function's own doc comment for why a
    /// shared helper, not a second hand-written copy of the split, is the
    /// actual fix — the two paths already had one implementation each, once,
    /// and they had already diverged; writing the split a second time here
    /// reproduces the exact defect class this closes rather than closing it.
    /// The inner loop below now calls it before dispatching each inner step,
    /// exactly mirroring `run_to_completion`'s own `Decided`/`Proceed`
    /// handling.
    ///
    /// **A consequence worth stating explicitly:** the `StepStatus::Skipped`
    /// arm in the inner loop below was, until this fix, **unreachable**
    /// through this function — the only thing that ever produces `Skipped`
    /// is a `when:` gate, and nothing reached one. It is reachable now, and
    /// is covered by a dedicated test proving a `Skipped` inner step does
    /// **not** abort the rest of that item's inner steps (unlike `Failed`,
    /// which does): `tests/map_step.rs`'s
    /// `a_skipped_inner_step_does_not_abort_the_item_and_later_inner_steps_still_run`.
    ///
    /// Pinned by two adversarial tests, **through this function**, asserting
    /// **zero sink events, counted** (not merely "the map didn't run the
    /// guarded step" — round 1's own shipped `fail_fast` test could not
    /// distinguish "fan-out stopped" from "the failing step happens to emit
    /// nothing", because its failing step emitted nothing either way; a
    /// destructive `shell`/`tool` step that *dispatches* is exactly what a
    /// sink-event count catches and a status-field check alone would not):
    /// `tests/map_step.rs`'s
    /// `a_when_false_inner_step_gate_is_evaluated_and_skips_the_dispatch`
    /// and
    /// `a_when_that_fails_to_evaluate_on_an_inner_step_fails_closed_and_never_dispatches`.
    ///
    /// # An inner step's own `gate_condition_was_secret_derived` was discarded — CLOSED (fix round 3, item 1)
    ///
    /// Fix round 2 above made every inner step's `when:` gate get
    /// *evaluated* through [`evaluate_when_gate`], closing the fail-open
    /// dispatch bug. It did not make the resulting
    /// [`StepOutcome::gate_condition_was_secret_derived`] flag go anywhere:
    /// on the `Decided` arm the flag *was* set on that inner step's own
    /// `StepOutcome`, but [`ItemOutcome`] — what the closure below actually
    /// returns per item — has no field for it, so it was dropped at every
    /// item boundary; on the `Proceed` arm the flag from `evaluate_when_gate`
    /// was never even read (`GateDecision::Proceed { .. }`). This function's
    /// own returned `StepOutcome` then hard-coded
    /// `gate_condition_was_secret_derived: false` unconditionally (see below)
    /// — a `false` that meant nothing was ever measured, not that nothing
    /// was secret-derived. That is the same `unwrap_or(false)` shape
    /// [`evaluate_when_gate`]'s own `Err` arm (`crate::exec::mod`) was
    /// written specifically to keep a future consumer from reaching — this
    /// function was that consumer, shipped.
    ///
    /// Measured, `${{ secrets.K == 'yesyesyesyes' }}` guarding a step whose
    /// own output is not secret-derived, `K = "yesyesyesyes"` (gate true, so
    /// the inner step actually dispatches): the identical step at the top
    /// level records `gate_condition_was_secret_derived: true` on its own
    /// outcome; through a `map`, before this fix, nothing on the map path
    /// recorded it at all — the map's own `output_is_secret_derived` stayed
    /// `false` too, since it only ever folded in *output* taint. Second
    /// payload, the fail-closed arm this crate's posture depends on:
    /// `when: "${{ inputs.arr[json(secrets.K).idx] }}"` with
    /// `K = {"idx":"not-a-number"}` — the subscript fails to evaluate only
    /// because of what the secret said, `evaluate_when_gate`'s `Err` arm
    /// deliberately forces `true` (fix round 5, item 1), and before this fix
    /// that forced `true` was thrown away identically.
    ///
    /// **The fix:** fold the flag into the same aggregate
    /// `any_item_secret_derived` already accumulates
    /// [`StepOutcome::output_is_secret_derived`] into, per item, on both
    /// `GateDecision` arms — not a new field on [`ItemOutcome`] (which has no
    /// way to distinguish "this item's gate was secret-derived" from "this
    /// item's output was", and does not need to: both mean the same thing to
    /// a caller deciding whether `${{ steps.<map_id>.output }}` needs
    /// redaction downstream). `any_item_secret_derived` already feeds
    /// [`Self`]'s own `output_is_secret_derived` below, so folding the gate
    /// flag in there is what makes it a real record rather than a discarded
    /// one. It deliberately does **not** touch this function's own
    /// `gate_condition_was_secret_derived: false` — see the doc comment on
    /// that field, below, for why that hard-coded value is a distinct,
    /// correct placeholder rather than the same bug.
    ///
    /// Pinned by `tests/map_step.rs`'s
    /// `an_inner_steps_secret_derived_gate_taints_the_maps_own_output_even_when_the_items_output_does_not`
    /// and
    /// `an_inner_gate_that_fails_to_evaluate_because_of_a_secret_taints_the_maps_own_output`.
    ///
    /// # The map's own aggregate status is unconditionally `Completed` — recorded, not fixed here (fix round 2, item 5)
    ///
    /// The `StepOutcome` this function returns always carries
    /// `status: StepStatus::Completed`, regardless of whether every item
    /// failed. Measured: `on_item_error: fail_fast` with item 0 failed and
    /// items 1-4 recorded `Skipped` still reports the map step itself
    /// `Completed`; `on_item_error: collect` with **all five** items failed
    /// and five `collected_errors` also reports `Completed`. So
    /// `${{ steps.<map_id>.status }}` reads `"completed"` for a total
    /// fan-out failure, and [`crate::expr`]'s own module doc comment
    /// documents `status` as exactly the clean, stable discriminant a
    /// downstream step is meant to guard on
    /// (`when: "${{ steps.a.status != 'failed' }}"`).
    ///
    /// **This compounds with the `when:` fix above, not just with itself:** a
    /// downstream step gated on `${{ steps.<map_id>.status != 'failed' }}`
    /// to avoid running after a total `map` failure will run anyway, because
    /// that status never becomes `"failed"` no matter how the fan-out went.
    ///
    /// **Not fixed here — Task 8's job.** No stop-on-failure/`catch:`
    /// mechanism exists anywhere in this crate yet (see
    /// [`Executor::run_to_completion`]'s own "Residual: dependents cannot
    /// reliably detect an upstream failure at all" section, which names the
    /// identical gap at the top level and the same owner). Deciding what
    /// `map`'s own aggregate status *should* be — `Failed` if any item
    /// failed? Only if `on_item_error` was not `continue`/`collect`? — is a
    /// policy question that belongs with that mechanism, not a one-line
    /// change made unilaterally here. Recorded loudly, at the construction
    /// site below and here, so it is not silently rediscovered once
    /// something finally reads `steps.<map_id>.status` for real.
    ///
    /// # Task 34: `isolation: worktree` materialization (Phase 5 ruling P42, lane W5 rulings W5-8/W5-22)
    ///
    /// `isolation` is `StepBody::Map`'s own field
    /// ([`crate::parse::steps::MapIsolationDef`]), `Option<MapIsolationDef>`
    /// — **optionality here is meaningful and is not the same thing as
    /// `Defaults.isolation`'s default value.** `Defaults.isolation` defaults
    /// to `IsolationDef::Worktree` (`crate::parse::types::Defaults`) so that
    /// *some* isolation tier is always declared for a run, but that default
    /// must never be read as an implicit demand to materialize anything —
    /// every existing fixture and test in this crate leaves the map-level
    /// field unset and would gain an unwanted, and likely failing, git
    /// dependency if it did. Only `isolation: Some(MapIsolationDef::Worktree { .. })`
    /// — an author writing `map.isolation: worktree` (or the `{ worktree:
    /// { base_ref } }` form) on *this specific* `map` step — is treated as
    /// an explicit demand.
    ///
    /// **The field being absent and an explicit `isolation: none` are not
    /// the same claim, even though both take the match arm below that does
    /// nothing (fix round 2, item 3 — ruling W5-33, correcting an earlier
    /// version of this paragraph that called both "genuinely
    /// deliverable").** Explicit `none` is a real, deliverable choice: the
    /// author asked for nothing, and nothing is exactly what this crate can
    /// always produce. The field being **absent** inherits
    /// `Defaults.isolation`, which defaults to `Worktree` — a documented
    /// safe floor (`crate::parse::types::Defaults`) — and this arm then
    /// silently does not honour it: no provider lookup, no worktree, no
    /// binding, no error, no warning. That is the P42 shape, for the
    /// *default* configuration, wider than the three tiers the arm below
    /// fails closed. **This is not fixed here.** Ruling W5-33: making the
    /// absent case materialize would require a wired `WorktreeProvider` for
    /// every existing workflow before any of them could run at all — the
    /// daemon does not construct one yet (lane W1's residual, per
    /// [`crate::exec::RunContext::worktree_provider`]'s own doc comment) —
    /// so every fixture and every test in this crate would fail closed
    /// overnight. Ruling W5-8 chose today's behaviour deliberately for
    /// exactly that reason, and that reasoning still holds; what changed
    /// this round is only the claim made about it. **Read every "P42 is
    /// closed" statement in this crate (and in `roundhouse-sandbox`) with
    /// this qualification attached: P42's silence is closed for an
    /// explicitly declared `worktree` tier, and for the three
    /// undeliverable tiers below — it is not closed for a `map` step that
    /// leaves `isolation:` unset and inherits the default.**
    ///
    /// **Fail-closed on a missing provider.** When the map-level field
    /// explicitly asks for `worktree` isolation and this `Executor`'s own
    /// `worktree_provider` field (threaded from
    /// [`crate::exec::RunContext::worktree_provider`]) is `None`, the
    /// *item* fails with a message naming the missing provider — never a
    /// silent no-op. This is exactly the defect Phase 5 ruling P42 raised:
    /// a workflow author who writes `isolation: worktree` and gets no
    /// isolation and no warning. Per-item, not per-`map`-step: `on_item_error`
    /// governs whether that failure stops the whole fan-out
    /// (`fail_fast`) or is recorded per-item (`continue`/`collect`), exactly
    /// like any other item failure.
    ///
    /// **`base_ref` is a workflow-file *template*, resolved per item.**
    /// `parse/steps.rs`'s own doc comment on `validate_git_ref` already
    /// documents §8.9's fixture using `${{ pr.number }}` inside `base_ref`
    /// — so the stored string is not necessarily the literal ref text, and
    /// resolving it happens here, per item, **after** `as_name` is bound
    /// for that item (below), via [`interpolate`] — the same
    /// `TemplateSource`/mixed-literal-and-`${{ }}` mechanism
    /// `StepBody::Agent`'s `prompt` field uses
    /// (`crate::exec::Executor::dispatch_step`), not
    /// [`eval_delimited_expression`] (`over`'s mechanism), because
    /// `base_ref` is ordinary literal text with an *optional* embedded
    /// expression, not a field required to be wholly one `${{ … }}` block.
    /// The **unredacted** rendering crosses to
    /// [`crate::worktree::WorktreeProvider::materialize`] (and from there,
    /// to `git`, as one discrete argv element after `--` — see that
    /// method's own doc comment); nothing here ever builds a shell string
    /// from it. A `base_ref` of `None` (bare `worktree`, no `base_ref:` key)
    /// resolves to the literal text `"HEAD"` rather than invoking
    /// `interpolate` at all.
    ///
    /// **The materialized path is bound into the expression context,
    /// alongside `as_name`, not folded into it.** A downstream step inside
    /// the map body reads it as `${{ worktree.path }}` — a second root,
    /// [`WORKTREE_ROOT_NAME`], bound and reverted with exactly the same
    /// [`crate::expr::ExprContext::snapshot_root`]/
    /// [`crate::expr::ExprContext::restore_root`]/
    /// [`crate::expr::ExprContext::set_from`] mechanism `as_name` itself
    /// uses above, for the identical reason (nested-`map` reuse of the same
    /// root name must revert cleanly — see this function's own "Why binding
    /// onto the shared context and reverting by name is correct" section).
    /// Bound via [`crate::expr::Evaluated::derive`] off `item_evaluated` —
    /// **not** [`crate::expr::ExprContext::set_public`]/`set_secret` called
    /// directly — for the same reason `as_name`'s own binding is: this
    /// function's own doc comment above names hand-building an `Evaluated`
    /// or asserting per-item taint directly as "the re-assertion-by-the-
    /// back-door defect ruling P37 exists to remove," and that reasoning
    /// applies here verbatim even though the worktree path's own content
    /// never contains secret material — deriving from `item_evaluated`
    /// costs nothing and keeps this call site free of a second taint
    /// judgment call to get wrong.
    ///
    /// **Cleanup on both paths, panic included.** [`WorktreeGuard`] is an
    /// RAII guard: it is constructed immediately after a successful
    /// `materialize`, and its `Drop` impl calls
    /// [`crate::worktree::WorktreeProvider::release`] on exactly the path
    /// `materialize` returned. Because it is a local inside the per-item
    /// closure below, Rust drops it at the end of that closure's scope —
    /// on the item's ordinary `Completed`/`Failed`/`Skipped` return *and*
    /// during unwinding if anything in the item's inner-step dispatch
    /// panics — with no explicit cleanup call needed on any of those paths.
    /// **On the ordinary, non-panicking path**, a release failure is folded
    /// into that item's `Failed` outcome rather than silently swallowed —
    /// see the explicit [`WorktreeGuard::release`] call below, run after the
    /// inner-step loop, whose own doc comment covers this. **Fix round 1,
    /// item 7, scoping a claim that used to say this unconditionally:** on
    /// the *panicking* path the guard's `Drop` impl is the only thing that
    /// ever runs, and it deliberately swallows a release failure there (`let
    /// _ = self.provider.release(&path);` — see [`WorktreeGuard::drop`]'s
    /// own doc comment) rather than panicking during an unwind already in
    /// progress. Never a double-drop hazard either way:
    /// [`WorktreeGuard::drop`] extracts the path with [`Option::take`], so a
    /// second drop — there isn't one here, but the guard is written to be
    /// safe if a future refactor introduced one — is a no-op rather than a
    /// double release.
    ///
    /// **The path materialized and the path released are always the same
    /// value** — [`WorktreeGuard`] stores exactly what
    /// [`crate::worktree::WorktreeProvider::materialize`] returned and
    /// never accepts one from anywhere else; nothing derived from
    /// `over`/the item's own value/the workflow document can steer which
    /// path is released, which is the same guarantee
    /// `roundhouse_sandbox::worktree`'s own module doc comment states as an
    /// obligation of its callers.
    pub(crate) fn dispatch_map_step(
        &mut self,
        step_id: &str,
        over: &str,
        as_name: &str,
        max_parallel: u32,
        on_item_error: OnItemError,
        isolation: Option<&MapIsolationDef>,
        inner_step_yaml: &[serde_yaml::Value],
    ) -> StepOutcome {
        let (over_evaluated, items) = match resolve_map_items(&self.ctx, step_id, over) {
            Ok(resolved) => resolved,
            Err(outcome) => return *outcome,
        };

        let inner_steps: Vec<StepDef> = match parse_map_inner_steps(step_id, inner_step_yaml) {
            Ok(v) => v,
            Err(outcome) => return *outcome,
        };

        // B12c (ruling P108 §C): the run loop sets this from
        // `MapBudget::from_run_ledger` before every step it dispatches, so a
        // `map` inside a real run divides the run's **actual** remaining
        // ceiling. An `Executor` with no run behind it has no ledger to read
        // and falls back to the honest placeholder — see its doc.
        let mut budget = self
            .map_budget
            .clone()
            .unwrap_or_else(MapBudget::unenforced_placeholder);

        // Fix round 2, item 2/3: snapshot ONE root's binding, not the whole
        // context — see this function's own doc comment, "Why binding onto
        // the shared context and reverting by name is correct", for the
        // atomicity argument this depends on and the measured cost this
        // replaces under nesting. Shared with the wave loop through
        // `snapshot_map_roots`/`restore_map_roots`, which also decide (Task
        // 34) whether `WORKTREE_ROOT_NAME` is in the span at all.
        let snapshots = snapshot_map_roots(&self.ctx, as_name, isolation);
        // Fix-round-3-style step-boundary taint: if any item's own inner
        // steps produced secret-derived output, or the collection itself was
        // secret-derived, the map step's *own* aggregate output
        // (`items[].output`) can carry that material, so a dependent step
        // reading `${{ steps.<map_id>.output }}` must be tainted too — the
        // same reasoning `Executor::run_to_completion` already applies at
        // the top-level step boundary (see its own `secret_derived_steps`
        // comment). Fix round 3, item 1: this variable also folds in every
        // inner step's own `gate_condition_was_secret_derived`, on both
        // `GateDecision` arms — see the loop below and this function's own
        // doc comment, "An inner step's own `gate_condition_was_secret_derived`
        // was discarded".
        let mut any_item_secret_derived = over_evaluated.secret_derived();

        let result = run_map(
            items,
            max_parallel,
            on_item_error,
            &mut budget,
            // **`_item_caps` stays unread *here*, and that is now a statement
            // about this loop rather than about `map`** (Phase 8 Task 25.7
            // Task 4). Ruling P108 §C's enforcement half landed at the other
            // fan-out loop, `run_loop::Loop::dispatch_map`, which refuses an
            // item's next dispatch once its running tally would exceed this
            // same `split_budget` share — see `per_item_dispatch_refusal`.
            //
            // It is not mirrored here because there is nothing here to
            // refuse: every `tool:`/`agent:` inner step this loop reaches
            // becomes `Executor::dispatch_step_or_stub`'s fabricated `{}`, so
            // an item of *this* fan-out cannot spend a call in the first
            // place. A ceiling on stub work would be enforcement theatre.
            //
            // **That holds whether or not the budget behind it is real, and
            // the distinction is worth stating because both cases occur.**
            // `Executor::run_to_completion`'s in-memory sequencer has no run
            // behind it and falls back to `MapBudget::unenforced_placeholder`
            // — but a `map:` nested *inside* another `map`'s inner steps
            // reaches this same function from a **real** run
            // (`run_loop::Loop::advance_map_item` →
            // `Executor::dispatch_step`'s `StepBody::Map` arm, which is not
            // intercepted the way a top-level `map:` is), and there the
            // divided ceiling is real and ledger-sourced, exactly as the
            // `budget` binding above says. What makes the conclusion the same
            // either way is the stub, not the budget.
            //
            // So this is the line to revisit if a future task ever makes a
            // nested `map`'s own inner steps dispatch for real: at that point
            // this loop acquires a per-item spend, and the argument above
            // stops holding.
            //
            // B12c's mutation sweep left two survivors (`M1`/`M2`), both
            // mutations of the split arithmetic, both `EQUIVALENT` because of
            // this underscore. The arithmetic is observable now — at the loop
            // that dispatches for real. `tests/run_loop.rs`'s per-item
            // admission section asserts on *which dispatches happen* rather
            // than on the number, so a changed divisor and a changed rounding
            // both move the wave sequence and fail:
            // `a_per_item_cap_refuses_an_items_second_dispatch_instead_of_running_it`
            // pins the divisor, and
            // `an_inner_step_that_never_dispatched_does_not_spend_an_items_share`
            // is written over an odd grant so that it pins the `ceil`.
            |item, _item_caps| {
                let item_evaluated = over_evaluated.derive(item.clone());
                self.ctx.set_from(as_name, &item_evaluated);

                // Task 34, per item, through the helper both fan-out loops
                // share (Phase 8 Task 25.7 Task 2) — see
                // `Executor::prepare_item_isolation`.
                let item_worktree = match self.prepare_item_isolation(
                    step_id,
                    isolation,
                    &item_evaluated,
                    &mut any_item_secret_derived,
                ) {
                    Ok(worktree) => worktree,
                    Err(outcome) => return outcome,
                };

                let mut last = ItemOutcome::Completed(Value::Null);
                for inner in &inner_steps {
                    // Ruling P116 §B, through the helper both fan-out loops
                    // share — see `nested_report_refusal`.
                    if let Some(refusal) = nested_report_refusal(inner) {
                        last = refusal;
                        break;
                    }
                    // Fix round 2, item 1: evaluate the inner step's own
                    // `when:` gate before dispatching it — the fail-open
                    // defect this closes, and why a shared helper rather
                    // than a second hand-written copy, are this function's
                    // own doc comment, "An inner step's own `when:` gate was
                    // silently ignored".
                    let outcome = match evaluate_when_gate(inner, &self.ctx) {
                        GateDecision::Decided(outcome) => outcome,
                        GateDecision::Proceed {
                            gate_condition_was_secret_derived,
                        } => {
                            // Fix round 3, item 1: mirror
                            // `Executor::run_to_completion`'s own
                            // `outcome.gate_condition_was_secret_derived = ...`
                            // assignment (`crate::exec::mod`) — the flag
                            // `evaluate_when_gate` computed for *this* inner
                            // step's own gate belongs on *this* step's
                            // outcome, not whatever `dispatch_step` fills the
                            // field with when `inner` is itself a nested
                            // `map` (which is the unconditional `false`
                            // placeholder `map_step_outcome` writes — a
                            // nested map's own inner taint travels on
                            // `output_is_secret_derived`, folded by
                            // `fold_inner_step_outcome` below, not on this
                            // field).
                            //
                            // **`dispatch_step_or_stub`, not
                            // `dispatch_step`, and that is what makes this
                            // the in-memory loop.** This function's caller
                            // (`Executor::run_to_completion`) has no
                            // `workflow_run` row, so an item here has
                            // nothing to suspend *into*; a `tool:`/`agent:`
                            // inner step therefore takes the same stub every
                            // other run-less dispatch takes. The loop that
                            // suspends for real is
                            // `run_loop::Loop::dispatch_map` (Phase 8 Task
                            // 25.7 Task 2), which holds the `Connection`
                            // this one deliberately does not.
                            let mut outcome = self.dispatch_step_or_stub(inner);
                            outcome.gate_condition_was_secret_derived =
                                gate_condition_was_secret_derived;
                            outcome
                        }
                    };
                    // Both taint bits and the "an item fails as soon as any
                    // inner step fails" rule, through the helper both
                    // fan-out loops share — see `fold_inner_step_outcome`.
                    if fold_inner_step_outcome(&mut last, outcome, &mut any_item_secret_derived) {
                        break;
                    }
                }

                // Task 34: release on **every** path out of this item, through
                // the same shared helper — see
                // `Executor::release_item_isolation`.
                self.release_item_isolation(step_id, item_worktree, last)
            },
        );

        restore_map_roots(&mut self.ctx, as_name, snapshots);
        map_step_outcome(step_id, &result, any_item_secret_derived)
    }
}
