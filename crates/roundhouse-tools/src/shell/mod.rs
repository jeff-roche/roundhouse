//! Shell executor: direct exec without shell interpretation.
//!
//! This module has three execution modes:
//! - [`run_shell`] (below, Phase 1): "run to completion" — waits for the
//!   full `tokio::process::Command::output()` and cannot be cancelled
//!   mid-flight. Still the executor used by the demo/simple tool-call path.
//! - [`cancel`] (Phase 2, Task 4): cancellable execution via `process-wrap`,
//!   for callers that need to SIGTERM-then-SIGKILL a still-running shell
//!   task (and its whole process group, not just the direct child).
//! - [`execve_node`] (Phase 2, Task 13/14): the intended entry point for the
//!   policy-decided pipeline path — takes a
//!   `roundhouse_policy::shell::pipeline::ResolvedNode` (one already-parsed,
//!   already-policy-checked pipeline node) instead of a raw `program`/`argv`
//!   pair, and delegates straight to `run_shell`.

mod cancel;

use std::path::Path;

use tokio::process::Command;

use crate::error::ToolError;

pub use cancel::{
    cancel_running_shell, spawn_cancellable, CancelError, ExitDisposition, ShellHandle,
};

/// Output captured from a shell command execution.
#[derive(Debug)]
pub struct ShellOutput {
    /// Standard output bytes.
    pub stdout: Vec<u8>,
    /// Standard error bytes.
    pub stderr: Vec<u8>,
    /// Exit code of the process, or None if terminated by signal.
    pub exit_code: Option<i32>,
}

/// Runs `program` with `argv` via a direct exec — never through a shell interpreter.
/// Pipeline/redirection/interpreter classification (§6.3) is implemented by
/// `roundhouse-policy`'s `shell::pipeline`/`shell::interpreter` modules
/// (`resolve_nodes`, `decide_pipeline`, `is_interpreter`); this executor is the
/// bottom half only, given an already-resolved argv. [`execve_node`] (below) is
/// the entry point that takes a `ResolvedNode` straight from that classification.
///
/// This direct-exec approach structurally eliminates a whole class of command-injection
/// vulnerabilities: since `program` and `argv` go straight to the OS-level `execve()`
/// equivalent as discrete arguments, no argv element can ever be reinterpreted as shell
/// syntax (`;`, `|`, `$()`, backticks, etc. are all inert, literal characters). There is
/// no shell in the loop to perform reinterpretation.
///
/// **Fix round A (Phase 7, Task 5 finding F1):** the child's environment is now
/// `env_clear()`'d, with only `PATH` (read from THIS process's own environment, so
/// bare-name programs like `git` keep resolving) re-added. Before this fix, this
/// function spawned a bare `Command` that inherited the daemon's FULL environment —
/// including `ANTHROPIC_API_KEY` when set — into every child, a reproduced leak that
/// falsified `docs/architecture/03-security-and-sandboxing.md:318`'s "no key enters a
/// child environment" claim. No signature change: `execve_node` (below) and every
/// existing caller/test keep working unchanged, since `PATH` is exactly what a bare
/// program name needs and nothing else was ever load-bearing here.
pub async fn run_shell(
    program: &str,
    argv: &[String],
    cwd: &Path,
) -> Result<ShellOutput, ToolError> {
    let mut command = Command::new(program);
    command
        .args(argv)
        .current_dir(cwd)
        .kill_on_drop(true)
        .env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    let output = command
        .output()
        .await
        .map_err(|e| ToolError::Spawn(format!("{program}: {e}")))?;

    Ok(ShellOutput {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.status.code(),
    })
}

/// §6.3 step 8: execve a single already-resolved pipeline node directly —
/// a thin wrapper over [`run_shell`], not a parallel executor. No shell is
/// ever started, so aliases don't exist and there is no `sh -c` layer for an
/// argument to escape through; `run_shell` already provides that property,
/// this just gives Task 13/14's `ResolvedNode` a matching entry point.
///
/// `node.redirections` is intentionally unused here: wiring redirection
/// targets to real file descriptors is out of scope for this task (it
/// belongs to the later task-admission integration point) — the redirection
/// *decision* (whether the target is allowed) is already handled upstream by
/// `roundhouse_policy::shell::pipeline::decide_pipeline`.
pub async fn execve_node(
    node: &roundhouse_policy::shell::pipeline::ResolvedNode,
    cwd: &Path,
) -> Result<ShellOutput, ToolError> {
    run_shell(&node.resolved_program, &node.argv, cwd).await
}
