//! The permission rule language and evaluation engine: given a `TaskParams`
//! describing what an action wants to do, a `Policy` decides whether it's
//! allowed, denied, or needs to ask — the single decision point every task
//! executor consults before acting.
//!
//! Phase 0 ships only the `Policy` trait and `TaskParams` enum (a stub
//! signature every downstream crate can compile against); the actual rule
//! language and evaluation engine are Phase 2 work. See
//! `docs/architecture/02-system-architecture.md` §5.2 and §6 (policy/config).
#![forbid(unsafe_code)]

pub mod approval;
pub mod config;
pub mod engine;
pub mod registry;
pub mod sealed;
pub mod shell;
pub mod trust;

mod policy_trait;
mod task_params;

pub use config::{compile_policy_layers, PolicyConfigError};
pub use engine::{
    ArgMatcher, ArgsPattern, CompiledRule, Decision, Outcome, PolicyEngine, Predicate, RuleId,
    Scope, TeamMembership,
};
pub use policy_trait::Policy;
pub use task_params::{
    FsOp, MemoryOp, Method, ParsedCommand, PathErr, PolicyInput, ProviderId, ServerId, Taint,
    TaskParams,
};
