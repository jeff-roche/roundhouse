//! Workflow definition and durable execution: multi-step flows built out of
//! `Task`s, resumable across daemon restarts because every step is an
//! event-sourced record, not in-memory state.
//!
//! Phase 0 only proves this crate compiles against `roundhouse-core`'s
//! `TaskKind`; no workflow engine exists yet — that's Phase 5 work. See
//! `docs/architecture/02-system-architecture.md` §5.2 and
//! `05-scheduling-and-workflows.md`.
#![forbid(unsafe_code)]

pub mod approval_policy;
pub mod caps;
pub mod compose;
pub mod control;
pub mod durability;
pub mod exec;
pub mod expr;
pub mod hitl;
pub mod job;
pub mod job_store;
pub mod ledger;
pub mod parking;
pub mod parse;
pub mod report;
pub mod retry;
pub mod runs;
pub mod worktree;

pub fn placeholder_step_kind() -> roundhouse_core::TaskKind {
    roundhouse_core::TaskKind::Flow
}
