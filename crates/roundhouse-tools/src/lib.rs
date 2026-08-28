#![forbid(unsafe_code)]

use roundhouse_policy::{ParsedCommand, TaskParams};
use roundhouse_sandbox::Isolate;
use std::sync::Arc;

/// Proves roundhouse-tools compiles against both stub traits it will
/// implement executors on top of in Phase 1 (§13.2: shell/read/write/
/// edit/find executors).
pub fn describe_shell_task_params(program: &str, argv: Vec<String>) -> TaskParams {
    TaskParams::Shell(ParsedCommand { program: program.to_string(), argv })
}

pub fn declared_tier(isolate: &Arc<dyn Isolate>) -> roundhouse_core::Tier {
    isolate.declared()
}
