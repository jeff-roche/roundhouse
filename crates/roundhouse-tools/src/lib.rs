//! Task executors: shell, filesystem (read/edit/find), http, web, git, and
//! memory — the code that actually performs an action once `roundhouse-policy`
//! has allowed it and `roundhouse-sandbox` has isolated it.
//!
//! Phase 1 landed five real executors: [`read_file`], [`write_file`],
//! [`edit_file`], [`find_files`], and [`run_shell`]. `describe_shell_task_params`
//! and `declared_tier` below are Phase 0 leftovers proving this crate compiles
//! against the `roundhouse-policy`/`roundhouse-sandbox` stub traits; they are not
//! themselves executors. **No policy/sandbox gate is wired in front of the real
//! executors yet** — nothing here calls `Policy::decide` or an `Isolate` before
//! running, so callers are responsible for gating today (see the `TODO(Phase 2)`
//! at `roundhouse-daemon/src/demo.rs`'s `edit_file` call site). Wiring that gate
//! in front of every executor is Phase 2 work; see
//! `docs/architecture/02-system-architecture.md` §5.2 and
//! `docs/architecture/03-security-and-sandboxing.md` §6.2.
#![forbid(unsafe_code)]

mod edit;
mod error;
mod find;
mod read;
mod shell;
mod write;

use roundhouse_policy::{ParsedCommand, TaskParams};
use roundhouse_sandbox::Isolate;
use std::sync::Arc;

pub use edit::{edit_file, EditOutcome};
pub use error::ToolError;
pub use find::find_files;
pub use read::read_file;
pub use shell::{
    cancel_running_shell, run_shell, spawn_cancellable, spawn_test, CancelError, ExitDisposition,
    ShellHandle, ShellOutput,
};
pub use write::write_file;

/// Proves roundhouse-tools compiles against both stub traits it will
/// implement executors on top of in Phase 1 (§13.2: shell/read/write/
/// edit/find executors).
pub fn describe_shell_task_params(program: &str, argv: Vec<String>) -> TaskParams {
    TaskParams::Shell(ParsedCommand {
        program: program.to_string(),
        argv,
    })
}

pub fn declared_tier(isolate: &Arc<dyn Isolate>) -> roundhouse_core::Tier {
    isolate.declared()
}
