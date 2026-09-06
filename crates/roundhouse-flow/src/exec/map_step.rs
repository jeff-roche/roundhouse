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
struct WorktreeGuard {
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

impl<'a> Executor<'a> {
    /// Dispatches a `StepBody::Map` — evaluates `over:` for real against the
    /// current expression context, then for each item binds it under the
    /// step's `as:` name (so `${{ pr.number }}` inside the map's inner steps
    /// resolves to that item, not `Null`) before recursively dispatching the
    /// inner steps via the same [`Executor::dispatch_step`] sequencing every
    /// other step kind uses.
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
        let over_evaluated =
            match eval_delimited_expression(TemplateSource::from_workflow_file(over), &self.ctx) {
                Ok(v) => v,
                Err(e) => {
                    return StepOutcome::failed(step_id, format!("evaluating `map.over`: {e}"));
                }
            };
        let items: Vec<Value> = match over_evaluated.value() {
            Value::Array(items) => {
                // Fix round 2, item 4: the cap check moved here, onto the
                // *borrowed* array, so a rejected call never even pays for
                // cloning `items` — see this function's own doc comment,
                // "`MAX_MAP_ITEMS`", for what this bounds and does not.
                if items.len() > MAX_MAP_ITEMS {
                    return StepOutcome::failed(
                        step_id,
                        format!(
                            "`map.over` yielded {} items, exceeding the {MAX_MAP_ITEMS}-item \
                             limit for a single `map` step",
                            items.len()
                        ),
                    );
                }
                items.clone()
            }
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
        // replaces under nesting.
        let outer_snapshot = self.ctx.snapshot_root(as_name);
        // Task 34: only an *explicit* `isolation: worktree` on this map
        // step snapshots `WORKTREE_ROOT_NAME` at all — see
        // `Executor::dispatch_map_step`'s own doc comment, "Task 34:
        // `isolation: worktree` materialization", for why `None` here (the
        // common case — the field absent, inheriting `Defaults.isolation`)
        // must leave any outer binding of this name completely undisturbed.
        let materializes_worktree = matches!(isolation, Some(MapIsolationDef::Worktree { .. }));
        let outer_worktree_snapshot =
            materializes_worktree.then(|| self.ctx.snapshot_root(WORKTREE_ROOT_NAME));
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
            // **`_item_caps` is where ruling P108 §C stops being discharged,
            // and this binding is the reason** (named here, at the site a
            // future implementer works, not only where the value is sourced).
            // `run_loop::run_workflow` computes a real, live
            // `split_budget(&budget.total_remaining, n)` from the run's
            // ledger and `run_map` hands it to this closure — and nothing
            // reads it, so per-item *enforcement* does not exist. B12c's
            // mutation sweep measured exactly that: the two survivors it
            // could not kill (`M1`/`M2`) both mutate the split arithmetic,
            // and both are `EQUIVALENT` **because of this underscore**.
            //
            // Whoever gives `map` real fan-out owns closing it: bind the
            // parameter, and admit each item's spend against it through
            // `ledger::admit_spend` the way `run_loop::Loop::admit` does for
            // a top-level step. Until then the sourcing is correct and the
            // ceiling is the run-level one.
            |item, _item_caps| {
                let item_evaluated = over_evaluated.derive(item.clone());
                self.ctx.set_from(as_name, &item_evaluated);

                // Task 34: materialize this item's worktree, if this map
                // step explicitly demanded one — see
                // `Executor::dispatch_map_step`'s own doc comment, "Task
                // 34: `isolation: worktree` materialization", for the full
                // reasoning (fail-closed on a missing provider, per-item
                // `base_ref` interpolation, the binding mechanism, and the
                // cleanup guarantee `worktree_guard` below provides), and
                // "Fix round 1, item 1" for the taint-leak fix below.
                let mut worktree_guard: Option<WorktreeGuard> = None;
                // Carried out of the match below so the release arm at the
                // end of this closure can apply the same withhold rule the
                // materialize arm does (final round part 2, M1). A release
                // error from *this* crate's adapter never sees `base_ref`
                // — `remove_worktree` is handed a generated uuid path and
                // `--force` — but `WorktreeProvider` is a `pub` trait whose
                // doc now tells an implementor its release errors are
                // persisted under the same rule, and a caller that ignored
                // that on one of the two paths would make the promise a
                // half-truth.
                //
                // Named for what it actually holds (part 3, W5-48): secret
                // *material*, either because provenance marked the value or
                // because a declared secret's raw value is inside it. See
                // the assignment below for why the second disjunct exists.
                let mut base_ref_carried_secret_material = false;
                match isolation {
                    // Fix round 1, item 6 / fix round 2, item 3 (ruling
                    // W5-33): `None` (the field absent) and an explicit
                    // `isolation: none` take the same no-op arm, but they
                    // are not the same claim — see this function's own doc
                    // comment, "Task 34", for why `None` here is a known,
                    // tolerated gap (P42's shape for the *inherited*
                    // default) and not "genuinely deliverable" the way
                    // explicit `none` is. See the match arm below for the
                    // other three tiers, which this crate cannot deliver
                    // and does not tolerate silently.
                    None | Some(MapIsolationDef::None) => {}
                    Some(MapIsolationDef::Worktree { base_ref }) => {
                        let provider = match &self.worktree_provider {
                            Some(provider) => Arc::clone(provider),
                            None => {
                                return ItemOutcome::Failed(format!(
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
                                    match interpolate(
                                        TemplateSource::from_workflow_file(text),
                                        &self.ctx,
                                    ) {
                                        Ok(interpolated) => {
                                            // The part that actually
                                            // repairs the persisted taint
                                            // flag — see this function's
                                            // own doc comment. Folded in
                                            // unconditionally, before
                                            // `materialize` is even
                                            // attempted, so it is set on
                                            // both the success and the
                                            // failure path below.
                                            let is_secret_derived =
                                                interpolated.is_secret_derived();
                                            any_item_secret_derived |= is_secret_derived;
                                            let redacted =
                                                interpolated.redacted_for_logging().clone();
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
                                            return ItemOutcome::Failed(format!(
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
                        let base_ref_carries_secret_material = base_ref_is_secret_derived
                            || self
                                .redaction_needles
                                .iter()
                                .any(|needle| unredacted_base_ref.contains(needle.as_str()));
                        base_ref_carried_secret_material = base_ref_carries_secret_material;
                        match provider.materialize(&unredacted_base_ref) {
                            Ok(path) => {
                                // Derived from `item_evaluated`, not
                                // asserted fresh via
                                // `set_public`/`set_secret` — see this
                                // function's own doc comment for why, even
                                // though the path's own content is never
                                // secret material.
                                let workspace_evaluated = item_evaluated.derive(
                                    serde_json::json!({ "path": path.display().to_string() }),
                                );
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
                                return ItemOutcome::Failed(if base_ref_is_secret_derived {
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
                        return ItemOutcome::Failed(format!(
                            "map step `{step_id}` declares `isolation: {}`, but this crate can \
                             only materialize `worktree` isolation today — refusing to run this \
                             item with no isolation at all rather than silently ignoring the \
                             tier it explicitly asked for",
                            map_isolation_tier_name(other)
                        ));
                    }
                }

                let mut last = ItemOutcome::Completed(Value::Null);
                for inner in &inner_steps {
                    // **A `report:` is a property of the run, not of a map
                    // item** — the same argument already written for the
                    // nested `gate:` and `call:` refusals in
                    // `Executor::dispatch_step`'s catch-all arm, applied to
                    // the third step kind that has run-wide meaning (B12c fix
                    // round, ruling P116 §B).
                    //
                    // Refused **here** rather than in that arm because
                    // `dispatch_step` is also how a *top-level* `report:` step
                    // is run, by both `run_to_completion` and
                    // `run_loop::run_workflow`; the arm cannot tell the two
                    // callers apart, and this loop is the one that knows the
                    // step is nested.
                    //
                    // What it costs to leave open: `run_workflow`'s §8.6
                    // "exactly one report" pre-check flattens only the three
                    // phase step lists, so it structurally cannot see a
                    // `report:` under a `map` — and a nested one emits one
                    // `TaskKind::Report` task **per item**, into a log that
                    // physically rejects `UPDATE`/`DELETE`. Ruling P112's
                    // invariant would then be violated by a workflow the
                    // pre-check accepted.
                    if matches!(inner.body, StepBody::Report { .. }) {
                        last = ItemOutcome::Failed(format!(
                            "step `{}`: a `report:` step cannot run inside a `map`: \
                             §8.6's report is a property of the run, and one per item \
                             would leave the Runs inbox choosing between them",
                            inner.id
                        ));
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
                            // placeholder at the bottom of this function — a
                            // nested map's own inner taint travels on
                            // `output_is_secret_derived`, folded on the next
                            // line, not on this field).
                            let mut outcome = self.dispatch_step(inner);
                            outcome.gate_condition_was_secret_derived =
                                gate_condition_was_secret_derived;
                            outcome
                        }
                    };
                    any_item_secret_derived |= outcome.output_is_secret_derived;
                    // Fix round 3, item 1: fold this inner step's own
                    // `when:` gate taint into the map's aggregate too, not
                    // just its output taint — see this function's own doc
                    // comment, "An inner step's own
                    // `gate_condition_was_secret_derived` was discarded",
                    // for why this is fail-safe rather than cosmetic.
                    any_item_secret_derived |= outcome.gate_condition_was_secret_derived;
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

                // Task 34: release on **every** path out of this item —
                // the inner loop above may have `break`d on a failure,
                // fallen through after every inner step ran, or (via
                // `report:`'s refusal above) never entered the loop body at
                // all; all three reach here. A release failure only
                // overwrites `last` when the item would otherwise have
                // reported success/skip — an item that already failed for
                // its own reason keeps that reason, which is more
                // actionable than a release failure piggy-backing on it.
                // See `WorktreeGuard::release`'s own doc comment for why
                // this explicit call, not `Drop` alone, is what lets a
                // release failure reach `last` at all on this (the
                // non-panicking) path.
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
            },
        );

        self.ctx.restore_root(as_name, outer_snapshot);
        if let Some(snapshot) = outer_worktree_snapshot {
            self.ctx.restore_root(WORKTREE_ROOT_NAME, snapshot);
        }

        StepOutcome {
            step_id: step_id.to_string(),
            output: serde_json::json!({
                "items": result.outcomes.iter().map(item_outcome_to_json).collect::<Vec<_>>(),
                "collected_errors": result.collected_errors,
            }),
            // Fix round 2, item 5 (recorded, not fixed here — Task 8's job):
            // unconditionally `Completed`, even when every item failed. See
            // this function's own doc comment, "The map's own aggregate
            // status is unconditionally `Completed`".
            status: StepStatus::Completed,
            output_is_secret_derived: any_item_secret_derived,
            // This is the map STEP'S OWN gate — whether *this* `map` step's
            // own `when:` (if it has one) read secret material — not a
            // record of its inner items' gates; those are folded into
            // `output_is_secret_derived` above (fix round 3, item 1), the
            // only field this function has that can carry an aggregate.
            // `false` here is a placeholder identical in kind to
            // `StepOutcome::failed`'s own (`crate::exec::mod`): the only
            // callers of this function — `Executor::run_to_completion` and,
            // when this `map` is itself nested inside an enclosing one,
            // `dispatch_map_step`'s own inner loop above — always overwrite
            // this field immediately after calling `dispatch_step`, from
            // *their* `evaluate_when_gate` call on *this* step. Do not read
            // the `false` below as a statement about this map's own gate.
            gate_condition_was_secret_derived: false,
        }
    }
}
