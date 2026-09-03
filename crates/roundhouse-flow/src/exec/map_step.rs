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
//! - **Per-item binding uses [`Evaluated::derive`], not the plan's
//!   `ExprContext::get`/`set`-based restore.** See [`Executor::dispatch_map_step`]'s
//!   own doc comment for the full reasoning (ruling P40/R-1, R-2). This
//!   crate therefore does not add the `ExprContext::get` accessor the plan's
//!   Step 3 lists. **Fix round 1 changed *how* the per-item context is
//!   managed** (originally a fresh clone per item; now one clone per `map`
//!   step, mutated in place per item and restored once at the end) — see
//!   `dispatch_map_step`'s own doc comment, "Fix round 1" section, for why
//!   the original per-item-clone design was itself a defect, not just a
//!   style choice.
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
pub const MAX_MAP_ITEMS: usize = 2_000;

/// A run's remaining resource budget as `map` sees it. Real, live tracking
/// against actual task consumption is Task 8's durability layer's job (it
/// owns the run-level ledger); this crate's job is to divide whatever
/// `total_remaining` it is handed.
pub struct MapBudget {
    pub total_remaining: ResourceCaps,
}

impl MapBudget {
    /// A [`MapBudget`] that enforces **nothing** — `total_remaining` is
    /// [`ResourceCaps::default`], not sourced from any real run-level
    /// ledger. Fix round 1, item 3: `Executor::dispatch_map_step` used to
    /// construct `MapBudget { total_remaining: ResourceCaps::default() }`
    /// inline, which reads exactly like a real, intentional budget — a
    /// placeholder that looks like an allowance is worse than one that
    /// admits it isn't one. This constructor exists so that call site says
    /// so explicitly and is greppable.
    ///
    /// **Task 8 must replace this call site with a `MapBudget` built from
    /// the run's actual remaining budget** once real admission-time
    /// enforcement exists. Until then, [`split_budget`]'s output
    /// (`per_item_caps`, handed to `run_item`) is real and meaningful as an
    /// *allocation* — it is only the *ceiling it is allocated from* that is
    /// fake.
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
/// **`max_parallel` bounds nothing today (fix round 1, "also record").** A
/// workflow declaring `map.max_parallel: 20` runs its items fully
/// sequentially, not "at most 20 concurrently" — the field is accepted and
/// threaded through unread. This is a residual, documented here precisely so
/// a future reader does not mistake `max_parallel` for a working concurrency
/// *ceiling*: today it is neither a floor nor a ceiling, because nothing
/// reads it at all.
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
    /// # Per-item binding: `Evaluated::derive`, one clone per MAP STEP not per item (ruling P40/P44/P45, R-1/R-2)
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
    /// and it is bound with `ExprContext::set_from`, which propagates rather
    /// than re-asserts (ruling P37).
    ///
    /// # Fix round 1: the original per-item `ExprContext` clone was itself the defect (item 3)
    ///
    /// The first landed version cloned a **fresh** `ExprContext` for every
    /// item, forked from the pre-map context. That closed the *cross-step*
    /// poisoning hazard (see below) but, because `ExprContext::clone` deep-
    /// clones every bound root including `inputs`/`vars`/`secrets`/`steps`,
    /// made this function's cost **O(items × context size)** — measured,
    /// release build, one trivial `emit` inner step: 2,500 items → 620 ms;
    /// 10,000 → 15.6 s; 20,000 → **148.7 s**. Attributed by a controlled
    /// experiment (items fixed at 2,000, varying only an `inputs.pad` string
    /// no expression references): 0 KB → 22.5 ms; 8 MB → 396.2 ms — the
    /// per-item clone re-copies context data no expression in the map even
    /// reads. Nested `map`s multiply this: three nested `map` steps over one
    /// input array, k=100 items each level, produced **2,000,000 events**
    /// from a 580-byte workflow in 4.4 s.
    ///
    /// **The fix: one `ExprContext` clone per `map` STEP, not per item.**
    /// `self.ctx` is cloned exactly once, into `saved_outer_ctx`, before the
    /// item loop begins. For every item, `self.ctx` itself (not a fresh
    /// clone) is mutated in place via `set_from(as_name, &item_evaluated)` —
    /// an O(1)-ish `HashMap` insert, not a deep clone — then the item's inner
    /// steps dispatch against `self.ctx` directly. After the *whole* `run_map`
    /// call finishes (every item processed), `self.ctx` is restored to
    /// `saved_outer_ctx` in a single move.
    ///
    /// **Why this is still correct against R-2b's cross-step poisoning
    /// hazard**, even though `self.ctx` is now mutated directly rather than
    /// swapped for a fresh clone per item: `ExprContext` provenance is
    /// monotone per root **name** and irreversible for the life of the
    /// context, but *within one `map` step* every item shares the exact same
    /// `secret_derived` bit (the paragraph above) — so repeatedly calling
    /// `set_from(as_name, ..)` with a *constant* taint level across all
    /// items of this map cannot mis-escalate or mis-lower anything; the
    /// first call sets `as_name`'s provenance to the collection's own level,
    /// every later call in the same map step is a no-op on provenance and
    /// only updates the *value*. What still must not leak is this map
    /// step's taint surviving into a **different** step (a later `map` reusing
    /// the same `as:` name, or any other step) — that is exactly what
    /// restoring `self.ctx = saved_outer_ctx` once, after the whole map
    /// finishes, prevents: nothing this map step did to `as_name`'s
    /// provenance is visible on `self.ctx` once `dispatch_map_step` returns.
    ///
    /// Measured, same payload as before the fix, confirming the property
    /// still holds under the new design: `tests/map_step.rs`'s
    /// `a_secret_derived_maps_as_name_does_not_poison_a_later_clean_maps_use_of_the_same_as_name`
    /// — two `map` steps, both `as: item`, the first over a secret-derived
    /// collection, the second over a genuinely clean one — the second map's
    /// items still log in cleartext, not `***`.
    ///
    /// **Re-measured after the fix (ruling P18 — a cost claim needs a
    /// measurement in the diff), release build, through
    /// [`Executor::run_to_completion`], one trivial `emit` inner step, same
    /// shape as the pre-fix table above but at and below [`MAX_MAP_ITEMS`]
    /// (added by this same fix round — see below):**
    ///
    /// | items | events | elapsed |
    /// |---|---|---|
    /// | 500 | 1,000 | 876 µs |
    /// | 1,000 | 2,000 | 1.53 ms |
    /// | 2,000 | 4,000 | 3.15 ms |
    ///
    /// Roughly linear (each doubling of items costs ~2x, not ~4x+), and 2,000
    /// items now completes in low-single-digit milliseconds versus the
    /// pre-fix 2,500-item figure of 620 ms — a large constant-factor
    /// improvement at comparable scale, consistent with removing the
    /// per-item deep clone rather than merely trimming it.
    ///
    /// The `inputs.pad` attribution, repeated at a fixed 2,000 items: 0 B →
    /// 2.63 ms; 1 MB → 2.57 ms; 8 MB → 4.13 ms — **flat**, not the pre-fix
    /// 0 KB → 22.5 ms / 8 MB → 396.2 ms scaling. The residual ~1.5 ms growth
    /// at 8 MB is exactly the *one* remaining clone (`saved_outer_ctx`,
    /// taken once per map step) doing its one, now-unavoidable, O(context
    /// size) unit of work — no longer multiplied by item count.
    ///
    /// Also confirmed: dispatching above [`MAX_MAP_ITEMS`] fails closed
    /// *before* doing the expensive work, not after — 2,001 items: 209 µs;
    /// 20,000 items: 6.8 ms (dominated by the harness building the input
    /// array itself, not by this function, which never iterates it).
    ///
    /// # `MAX_MAP_ITEMS`: an explicit, closed-fail item-count cap (fix round 1, item 3)
    ///
    /// The clone fix above removes the *quadratic* term but not the
    /// *unbounded* one: nothing before fix round 1 stopped `over:` from
    /// yielding an arbitrarily large array (data-driven — a webhook payload,
    /// a `map.over` expression reading `inputs`/`steps`), and nested `map`s
    /// still multiply item counts across levels. `MAX_TOP_LEVEL_STEPS` (500,
    /// `crate::parse::mod`) bounds a *workflow-authored* quantity; a `map`
    /// item count is *data-driven* and needs its own bound for the same
    /// reason. [`MAX_MAP_ITEMS`] fails the step **closed** (not silently
    /// truncated) before any item is dispatched. This bounds one
    /// `dispatch_map_step` call; it does **not** bound the *product* across
    /// nested `map`s (a 3-level nest at the cap could still multiply to the
    /// cap cubed) — that requires a *run-level* dispatched-task counter this
    /// crate does not have and Task 8's admission ledger
    /// (`ResourceCaps::max_tasks`) is the eventual owner of, per
    /// [`MapBudget::unenforced_placeholder`]'s own doc comment.
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
        let items: Vec<Value> = match over_evaluated.value() {
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

        // Fix round 1, item 3: an explicit, closed-fail bound on a
        // data-driven quantity — see this function's own doc comment,
        // "`MAX_MAP_ITEMS`", for what this does and does not bound.
        if items.len() > MAX_MAP_ITEMS {
            return StepOutcome::failed(
                step_id,
                format!(
                    "`map.over` yielded {} items, exceeding the {MAX_MAP_ITEMS}-item limit for a \
                     single `map` step",
                    items.len()
                ),
            );
        }

        let inner_steps: Vec<StepDef> = match inner_step_yaml.iter().map(parse_step).collect() {
            Ok(v) => v,
            Err(e) => {
                return StepOutcome::failed(step_id, format!("parsing `map` inner steps: {e}"));
            }
        };

        let mut budget = MapBudget::unenforced_placeholder();

        // Fix round 1, item 3: exactly one clone of the whole context for
        // this entire map step, not one per item — see this function's own
        // doc comment, "Fix round 1: the original per-item `ExprContext`
        // clone was itself the defect", for the measured cost this replaces
        // and why mutating `self.ctx` in place per item (rather than
        // swapping in a fresh clone) is still correct against R-2b's
        // cross-step poisoning hazard.
        let saved_outer_ctx = self.ctx.clone();
        // Fix-round-3-style step-boundary taint: if any item's own inner
        // steps produced secret-derived output, or the collection itself was
        // secret-derived, the map step's *own* aggregate output
        // (`items[].output`) can carry that material, so a dependent step
        // reading `${{ steps.<map_id>.output }}` must be tainted too — the
        // same reasoning `Executor::run_to_completion` already applies at
        // the top-level step boundary (see its own `secret_derived_steps`
        // comment).
        let mut any_item_secret_derived = over_evaluated.secret_derived();

        let result = run_map(
            items,
            max_parallel,
            on_item_error,
            &mut budget,
            |item, _item_caps| {
                let item_evaluated = over_evaluated.derive(item.clone());
                self.ctx.set_from(as_name, &item_evaluated);

                let mut last = ItemOutcome::Completed(Value::Null);
                for inner in &inner_steps {
                    let outcome = self.dispatch_step(inner);
                    any_item_secret_derived |= outcome.output_is_secret_derived;
                    match outcome.status {
                        // Fix round 1, item 4: an item fails as soon as ANY
                        // inner step fails — stop dispatching this item's
                        // remaining inner steps and keep the failure, rather
                        // than letting a later inner step's success
                        // overwrite it. See this function's own doc comment
                        // for the measured fail-open payload this replaces.
                        StepStatus::Failed { message } => {
                            last = ItemOutcome::Failed(message);
                            break;
                        }
                        StepStatus::Skipped { reason } => {
                            last = ItemOutcome::Skipped { reason };
                        }
                        StepStatus::Completed => {
                            last = ItemOutcome::Completed(outcome.output);
                        }
                    }
                }
                last
            },
        );

        self.ctx = saved_outer_ctx;

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
