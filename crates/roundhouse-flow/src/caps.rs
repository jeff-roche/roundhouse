//! §8.4's `ResourceCaps` — the run-level resource ceiling
//! (`docs/architecture/05-scheduling-and-workflows.md` §8.4), first needed
//! by this crate for `map`'s per-item budget split (§8.9, Task 14).
//!
//! The "caps enforced at task admission" chokepoint §8.4 describes is
//! [`crate::ledger::admit_spend`] (B12b), which checks a request against this
//! type's fields and records it in one transaction over migration 0008's
//! columns. What is still missing is its *caller*: the run loop that invokes
//! it once per task is **B12c**. See [`ResourceCaps`]'s own doc comment for
//! why this owner moved twice — off Task 8, then across ruling P77's split.
//!
//! # Deviation from §8.4's illustrative code block: `max_cost_usd` is `f64`, not `Decimal`
//!
//! §8.4's own pseudocode types this field `Decimal`. Neither this crate nor
//! any other in the workspace depends on `rust_decimal` or any other
//! decimal-arithmetic crate (checked: no hits in any `Cargo.toml` or
//! `Cargo.lock`). Introducing that dependency here, for one field of a
//! struct this task is the first to actually define, would be exactly the
//! kind of net-new pinned dependency `STANDING.md` requires be introduced
//! deliberately and justified (the precedent is `roundhouse-web`'s `axum`
//! pin) — and it would immediately disagree with
//! [`crate::parse::steps::CapsDef`], the step-level `caps:` override Task 3
//! already landed, which types the identical "dollar-cost budget" concept
//! `Option<f64>`. `f64` is used here instead, matching that landed
//! precedent; recorded here per ruling P1 ("fix the code block and say so in
//! your report") rather than silently diverging from the frozen doc.
//! Whoever wires real admission-time enforcement (Task 8) is the owner who
//! would introduce exact decimal arithmetic workspace-wide if it becomes
//! load-bearing; nothing here forecloses that.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Mirrors §8.4's `ResourceCaps` (see the module doc comment for the one
/// field-type deviation). Enforced at task admission — the one chokepoint
/// every task already passes through, per the everything-is-a-task
/// invariant — by [`crate::ledger::admit_spend`]. What remains unbuilt is the
/// **caller**: the run loop that calls it once per task is **B12c**.
///
/// It used to say "Task 8's durability layer", then "Task 20". Both went
/// stale as the ledger moved: Task 16 (B8) landed `durability` with the
/// `workflow_run` / `workflow_step_run` state machine and deliberately no
/// run-level ledger, and ruling P77 then split Task 20 in three, putting the
/// ledger and its migration in B12b and the loop in B12c.
///
/// [`run_active_timeout`](Self::run_active_timeout) is the field that made
/// the owner matter rather than being a formality. Enforcing it as its own
/// knob needs wall time *minus* the time a run spent `AwaitingHuman`, and
/// tracking that requires a durable place to record park intervals — a
/// column, not an in-process tracker, which a daemon restart would lose
/// precisely across the multi-day park it exists to measure. Task 17 (B9)
/// writes the park (`crate::parking`) but added no such column; **migration
/// 0008's `parked_at`/`parked_nanos` are that column**, and
/// [`crate::ledger::active_elapsed`] is the arithmetic over them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceCaps {
    /// Includes parked time (e.g. time spent `AwaitingHuman` on an approval
    /// gate).
    pub run_wall_timeout: Duration,
    /// Excludes parked time — the one an operator actually tunes.
    pub run_active_timeout: Duration,
    pub step_timeout: Duration,
    pub max_tokens: u64,
    pub max_cost_usd: f64,
    pub max_tasks: u32,
    pub max_tool_calls: u32,
    pub max_subagents: u32,
    pub max_bytes_written: u64,
    pub max_escalations: u32,
}

impl Default for ResourceCaps {
    fn default() -> Self {
        ResourceCaps {
            run_wall_timeout: Duration::from_secs(24 * 3600),
            run_active_timeout: Duration::from_secs(4 * 3600),
            step_timeout: Duration::from_secs(1800),
            max_tokens: 2_000_000,
            max_cost_usd: 10.0,
            max_tasks: 5_000,
            max_tool_calls: 2_000,
            max_subagents: 20,
            max_bytes_written: 100_000_000,
            max_escalations: 50,
        }
    }
}

/// Whether an `f64` is usable as a dollar figure: **finite and non-negative**.
///
/// One definition for the whole crate, because there are now three enforcement
/// points for the same rule and they must not drift:
/// [`crate::parse::steps::CapsDef`]'s `TryFrom` (a `caps:` block authored in
/// YAML, where `.nan`, `.inf` and `-1e18` are all valid scalars),
/// [`crate::durability`]'s `insert_run_row` (before a `ResourceCaps` is
/// serialised into `workflow_run.caps_json`) and [`crate::ledger::admit_spend`]
/// (both operands of the cost comparison **and its ceiling**).
///
/// The ceiling is the one that was missed, and it is the only direction in the
/// ledger where a bad `f64` would mean *yes* rather than *no*: against a `NaN`
/// `max_cost_usd`, `cost_total > caps.max_cost_usd` is `false`, so every spend
/// would be admitted (ruling P109 §D). Nothing in the schema catches a bad
/// dollar figure either — measured in `roundhouse-store`'s `migration_0008`
/// tests, `+inf` satisfies `CHECK (spent_cost_usd >= 0)` and is stored (ruling
/// P108 §B).
///
/// # Which of those inputs can actually arrive, measured
///
/// - **`parse::steps`: all of them.** It reads YAML, where `.nan`, `.inf` and
///   `-1e18` are ordinary scalars.
/// - **`admit_spend`: the negative ones.** `-1.0` is finite, valid JSON and
///   round-trips through `caps_json` cleanly. A **non-finite** ceiling cannot
///   arrive that way, because `serde_json` refuses an out-of-range float in
///   *both* directions — `1e999` is a parse error, not `+inf`, which corrects
///   P109 §D's premise. So the fail-open scenario above is what this guard
///   prevents rather than what it currently catches; what it catches today is
///   a negative ceiling that would otherwise report every spend as over
///   budget. Pinned by
///   `tests/ledger.rs::serde_json_refuses_a_non_finite_dollar_figure_in_both_directions`,
///   so the scoping is a measurement rather than a claim.
/// - **`insert_run_row`: the diagnosis leg.** It names the writer, instead of
///   leaving a `null` in the column for some later, unrelated read to trip
///   over.
pub fn is_usable_cost_usd(amount: f64) -> bool {
    amount.is_finite() && amount >= 0.0
}
