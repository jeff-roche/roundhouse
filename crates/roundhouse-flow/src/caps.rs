//! §8.4's `ResourceCaps` — the run-level resource ceiling
//! (`docs/architecture/05-scheduling-and-workflows.md` §8.4), first needed
//! by this crate for `map`'s per-item budget split (§8.9, Task 14). Real
//! enforcement — the "caps enforced at task admission" chokepoint §8.4
//! describes — is Task 8's durability layer's job (it owns the run-level
//! ledger and the one place every task passes through); this crate's job
//! today is only to give the split a real, typed shape to divide.
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
/// invariant — but the enforcement call site itself lives in Task 8's
/// durability layer, where task admission is wired to the store.
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
