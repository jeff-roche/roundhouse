//! `map` step fan-out (§8.9, Task 14/B6): per-item budget splitting
//! ([`split_budget`]/[`MapBudget`]/[`run_map`]) and the real `StepBody::Map`
//! dispatch arm ([`Executor::dispatch_map_step`]) that binds the item
//! variable (`as:`) into the expression context for each item — closing
//! finding 8's remaining gap (the `map` item variable was never bound
//! anywhere) — and distinguishes `on_item_error: collect` from `continue`
//! (finding 9/10).
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
//! - **Per-item binding uses [`Evaluated::derive`] plus a fresh, per-item
//!   `ExprContext`, not `ExprContext::get`/`set`-based restore.** See
//!   [`Executor::dispatch_map_step`]'s own doc comment for the full
//!   reasoning (ruling P40/R-1, R-2, R-2b). This crate therefore does not
//!   add the `ExprContext::get` accessor the plan's Step 3 lists — nothing
//!   in this diff needs to read a binding back, since the outer context is
//!   never mutated in place. Left out per YAGNI, not by oversight.
//! - **`map.isolation`/`base_ref` (the "worktree fan-out" the plan's own
//!   title names) is out of scope for this diff, structurally, not by
//!   omission.** `dispatch_map_step` below never reads `StepBody::Map`'s
//!   `isolation` field and creates no worktree — `roundhouse-flow` has no
//!   process-spawning or git dependency at all (see its `Cargo.toml`: core,
//!   engine, store, serde, serde_json, thiserror, sha2, serde_yaml, uuid),
//!   so it cannot invoke `git worktree add` regardless of what this task
//!   does. Every other "real dispatch" arm in `crate::exec` (`Tool`/`Agent`/
//!   `Emit`/`Report`, see their own doc comments) already defers the actual
//!   process spawn to Task 8's durability layer for the identical reason;
//!   worktree creation is the same deferral, one layer further out. What
//!   this diff *does* keep intact is the guarantee `parse/steps.rs:690-694`
//!   already names this task as the owner of — `base_ref` must reach `git`
//!   as one discrete argv element after `--`, never interpolated into a
//!   shell string — by not touching `base_ref` at all: nothing here builds a
//!   shell string from it, so the guarantee is neither implemented nor
//!   broken by this diff. See this task's report for the full reasoning.

use crate::caps::ResourceCaps;
use crate::exec::{Executor, StepOutcome, StepStatus};
use crate::expr::{eval_delimited_expression, TemplateSource};
use crate::parse::steps::{parse_step, OnItemError, StepDef};
use serde_json::Value;

/// A run's remaining resource budget as `map` sees it. Real, live tracking
/// against actual task consumption is Task 8's durability layer's job (it
/// owns the run-level ledger); this crate's job is to divide whatever
/// `total_remaining` it is handed.
pub struct MapBudget {
    pub total_remaining: ResourceCaps,
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
/// `max_parallel` is accepted (matching this task's Interfaces) but unused —
/// sequential here, matching every other "real dispatch is Task 8's job"
/// deferral in this crate: the real executor swaps this loop body for a
/// bounded concurrent dispatcher once Task 8's durability layer owns actual
/// task admission; nothing today gives a caller a live signal to parallelise
/// against.
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
/// [`split_budget`]'s even-split allowance for the item, which is real and
/// meaningful regardless (Task 8's admission ledger is what enforces it).
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
    let mut collected_errors = Vec::new();
    for item in &items {
        let outcome = run_item(item, per_item_caps.clone());
        if let ItemOutcome::Failed(message) = &outcome {
            if on_item_error == OnItemError::Collect {
                collected_errors.push(message.clone());
            }
        }
        let should_stop =
            matches!(outcome, ItemOutcome::Failed(_)) && on_item_error == OnItemError::FailFast;
        outcomes.push(outcome);
        if should_stop {
            break;
        }
    }
    // Any items not yet visited because of an early `fail_fast` break are
    // recorded as `Skipped` rather than silently absent from the result.
    while outcomes.len() < items.len() {
        outcomes.push(ItemOutcome::Skipped {
            reason: "fail_fast: prior item failed".to_string(),
        });
    }
    MapRunResult {
        outcomes,
        collected_errors,
    }
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

impl<'a> Executor<'a> {
    /// Dispatches a `StepBody::Map` — evaluates `over:` for real against the
    /// current expression context, then for each item binds it under the
    /// step's `as:` name (so `${{ pr.number }}` inside the map's inner steps
    /// resolves to that item, not `Null`) before recursively dispatching the
    /// inner steps via the same [`Executor::dispatch_step`] sequencing every
    /// other step kind uses.
    ///
    /// # Per-item binding: `Evaluated::derive` into a fresh `ExprContext` (ruling P40, R-1/R-2/R-2b)
    ///
    /// `over:` is evaluated **once**, via [`eval_delimited_expression`],
    /// producing one [`crate::expr::Evaluated`] over the whole collection —
    /// this crate has no operation that evaluates one collection element
    /// independently, so every item necessarily inherits the same
    /// `secret_derived` flag the *collection* carries. Binding one item
    /// therefore cannot go through `ExprContext::set_secret`/`set_public`
    /// (both require the caller to *assert* a taint it does not actually
    /// know per element) or through a hand-built `Evaluated` (exactly the
    /// re-assertion-by-the-back-door ruling P37 exists to remove, and the
    /// hazard R-1/ruling P40 named as this task's blocking pre-work). Instead:
    ///
    /// 1. [`crate::expr::Evaluated::derive`] (this task's R-1 pre-work, on
    ///    `Evaluated` itself) produces a per-item `Evaluated` whose
    ///    `secret_derived` is read off the collection's own evaluation —
    ///    there is no parameter through which a caller could lower it.
    /// 2. That per-item `Evaluated` is bound with `ExprContext::set_from`,
    ///    which propagates rather than re-asserts (ruling P37).
    /// 3. The binding happens on a **fresh clone** of the context as it
    ///    stood before this map step started — not on `self.ctx` in place —
    ///    and inner steps run against that clone; `self.ctx` is restored
    ///    (unchanged) after every item.
    ///
    /// Step 3 is R-2b's requirement, taken deliberately: `ExprContext`
    /// provenance is monotone per root **name** and irreversible for the
    /// life of the context (see `ExprContext::set_public`'s own doc comment).
    /// A single, shared context rebinding `as_name` in place would let one
    /// secret-derived item (or, since every item in *this* map shares one
    /// taint flag, one secret-derived `map` step) permanently poison every
    /// later use of that same name — including a *different* `map` step
    /// later in the same workflow that happens to reuse the same `as:`. A
    /// fresh clone per item, forked from the pre-map context rather than
    /// chained from the previous item, makes that impossible by
    /// construction: nothing survives from one item's context to the next,
    /// or from this `map` step to whatever runs after it. This also means
    /// this task does not need `ExprContext::get`/a save-and-restore-by-name
    /// dance (the plan's Step 3) — cloning the whole context and swapping it
    /// back after each item is both simpler and the actually-required fix.
    ///
    /// Measured: `tests/map_step.rs`'s
    /// `a_secret_derived_maps_as_name_does_not_poison_a_later_clean_maps_use_of_the_same_as_name`
    /// runs two `map` steps in one workflow, both `as: item`, the first over
    /// a secret-derived collection and the second over a genuinely clean
    /// one — the second map's items log in cleartext, confirming the fresh-
    /// context design actually closes the poisoning path rather than merely
    /// arguing it does.
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
    /// exactly as `expr.rs` predicts — `over_evaluated.value` is
    /// `Value::String("oops }} filler ${{ inputs.prs }} trailing")`, and
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
    pub(crate) fn dispatch_map_step(
        &mut self,
        step_id: &str,
        over: &str,
        as_name: &str,
        max_parallel: u32,
        on_item_error: OnItemError,
        inner_step_yaml: &[serde_yaml::Value],
    ) -> StepOutcome {
        let over_evaluated =
            match eval_delimited_expression(TemplateSource::from_workflow_file(over), &self.ctx) {
                Ok(v) => v,
                Err(e) => {
                    return StepOutcome::failed(step_id, format!("evaluating `map.over`: {e}"));
                }
            };
        let items: Vec<Value> = match &over_evaluated.value {
            Value::Array(items) => items.clone(),
            other => {
                return StepOutcome::failed(
                    step_id,
                    format!(
                        "`map.over` must evaluate to an array, got {}",
                        value_type_name(other)
                    ),
                );
            }
        };

        let inner_steps: Vec<StepDef> = match inner_step_yaml.iter().map(parse_step).collect() {
            Ok(v) => v,
            Err(e) => {
                return StepOutcome::failed(step_id, format!("parsing `map` inner steps: {e}"));
            }
        };

        let mut budget = MapBudget {
            // The real remaining run-level budget is threaded in by Task 8's
            // durability layer, which owns the run-level ledger — see this
            // module's own doc comment. A fresh default at least gives
            // `split_budget` a real, non-degenerate value to divide today.
            total_remaining: ResourceCaps::default(),
        };

        let base_ctx = self.ctx.clone();
        // Fix-round-3-style step-boundary taint: if any item's own inner
        // steps produced secret-derived output, or the collection itself was
        // secret-derived, the map step's *own* aggregate output
        // (`items[].output`) can carry that material, so a dependent step
        // reading `${{ steps.<map_id>.output }}` must be tainted too — the
        // same reasoning `Executor::run_to_completion` already applies at
        // the top-level step boundary (see its own `secret_derived_steps`
        // comment).
        let mut any_item_secret_derived = over_evaluated.secret_derived;

        let result = run_map(
            items,
            max_parallel,
            on_item_error,
            &mut budget,
            |item, _item_caps| {
                let item_evaluated = over_evaluated.derive(item.clone());
                let mut item_ctx = base_ctx.clone();
                item_ctx.set_from(as_name, &item_evaluated);

                let saved = std::mem::replace(&mut self.ctx, item_ctx);
                let mut last = ItemOutcome::Completed(Value::Null);
                for inner in &inner_steps {
                    let outcome = self.dispatch_step(inner);
                    any_item_secret_derived |= outcome.output_is_secret_derived;
                    last = match outcome.status {
                        StepStatus::Failed { message } => ItemOutcome::Failed(message),
                        StepStatus::Skipped { reason } => ItemOutcome::Skipped { reason },
                        StepStatus::Completed => ItemOutcome::Completed(outcome.output),
                    };
                }
                self.ctx = saved;
                last
            },
        );

        StepOutcome {
            step_id: step_id.to_string(),
            output: serde_json::json!({
                "items": result.outcomes.iter().map(item_outcome_to_json).collect::<Vec<_>>(),
                "collected_errors": result.collected_errors,
            }),
            status: StepStatus::Completed,
            output_is_secret_derived: any_item_secret_derived,
            gate_condition_was_secret_derived: false,
        }
    }
}
