//! Shell executor: direct exec without shell interpretation.

use std::path::Path;

use tokio::process::Command;

use crate::error::ToolError;

/// Output captured from a shell command execution.
pub struct ShellOutput {
    /// Standard output bytes.
    pub stdout: Vec<u8>,
    /// Standard error bytes.
    pub stderr: Vec<u8>,
    /// Exit code of the process, or None if terminated by signal.
    pub exit_code: Option<i32>,
}

/// Runs `program` with `argv` via a direct exec — never through a shell interpreter.
/// Pipeline/redirection/interpreter classification (§6.3) is Phase 2's brush-parser work;
/// this executor is the bottom half only, given an already-resolved argv.
pub async fn run_shell(program: &str, argv: &[String], cwd: &Path) -> Result<ShellOutput, ToolError> {
    let output = Command::new(program)
        .args(argv)
        .current_dir(cwd)
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|e| ToolError::Spawn(format!("{program}: {e}")))?;

    Ok(ShellOutput {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.status.code(),
    })
}
