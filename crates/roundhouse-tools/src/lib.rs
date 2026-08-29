//! Task executors: shell, filesystem (read/edit/find), http, web, git, and
//! memory — the code that actually performs an action once `roundhouse-policy`
//! has allowed it and `roundhouse-sandbox` has isolated it.
//!
//! Phase 0 only proves this crate compiles against the `roundhouse-policy`
//! and `roundhouse-sandbox` stub traits it will build real executors on top
//! of; no executor exists yet. See
//! `docs/architecture/02-system-architecture.md` §5.2 and
//! `10-implementation-phasing.md` §13.2 (Phase 1 executor list).
#![forbid(unsafe_code)]

mod edit;
mod error;
mod read;
mod shell;
mod write;

use roundhouse_policy::{ParsedCommand, TaskParams};
use roundhouse_sandbox::Isolate;
use std::sync::Arc;

pub use edit::{edit_file, EditOutcome};
pub use error::ToolError;
pub use read::read_file;
pub use shell::{run_shell, ShellOutput};
pub use write::write_file;

/// Proves roundhouse-tools compiles against both stub traits it will
/// implement executors on top of in Phase 1 (§13.2: shell/read/write/
/// edit/find executors).
pub fn describe_shell_task_params(program: &str, argv: Vec<String>) -> TaskParams {
    TaskParams::Shell(ParsedCommand { program: program.to_string(), argv })
}

pub fn declared_tier(isolate: &Arc<dyn Isolate>) -> roundhouse_core::Tier {
    isolate.declared()
}
