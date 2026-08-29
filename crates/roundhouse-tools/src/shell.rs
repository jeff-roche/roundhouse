//! Shell executor: direct exec without shell interpretation.

use std::path::Path;

use tokio::process::Command;

use crate::error::ToolError;

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
/// Pipeline/redirection/interpreter classification (§6.3) is Phase 2's brush-parser work;
/// this executor is the bottom half only, given an already-resolved argv.
///
/// This direct-exec approach structurally eliminates a whole class of command-injection
/// vulnerabilities: since `program` and `argv` go straight to the OS-level `execve()`
/// equivalent as discrete arguments, no argv element can ever be reinterpreted as shell
/// syntax (`;`, `|`, `$()`, backticks, etc. are all inert, literal characters). There is
/// no shell in the loop to perform reinterpretation.
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
