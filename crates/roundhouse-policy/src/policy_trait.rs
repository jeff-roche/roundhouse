use crate::task_params::PolicyInput;
use roundhouse_core::PolicyDecision;

/// §6.2 — "every task passes `Policy::decide` before execution — including
/// tasks originating from an external ACP agent we are driving." Phase 0
/// ships the signature only; the rule language, precedence engine, and
/// sealed deny floor are Phase 2 work (§13.2).
pub trait Policy: Send + Sync {
    fn decide(&self, input: &PolicyInput) -> PolicyDecision;
}
