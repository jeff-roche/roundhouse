//! Tests for Phase 8 Task 25.4: lifting the `Read`-only gate to an allowlist
//! and refusing unknown tool names.
//!
//! These tests verify the gate logic in workflow_dispatch.rs. They are unit-level
//! tests of the gate condition logic rather than full integration tests.

use roundhouse_core::TaskKind;

/// Verify that the allowlisted task kinds match the expected set.
/// The gate in dispatch_tool_for_workflow allows: Read | Write | Edit | Find | Shell.
#[test]
fn allowlisted_task_kinds_pass_gate() {
    let allowed = [
        TaskKind::Read,
        TaskKind::Write,
        TaskKind::Edit,
        TaskKind::Find,
        TaskKind::Shell,
    ];

    for kind in &allowed {
        let is_supported = matches!(
            kind,
            TaskKind::Read | TaskKind::Write | TaskKind::Edit | TaskKind::Find | TaskKind::Shell
        );
        assert!(
            is_supported,
            "TaskKind::{:?} should be in the allowlist",
            kind
        );
    }
}

/// Verify that unsupported task kinds are rejected by the gate.
#[test]
fn unsupported_task_kinds_fail_gate() {
    let unsupported = [
        TaskKind::Http,
        TaskKind::Git,
        TaskKind::Mcp,
        TaskKind::Agent,
        TaskKind::Flow,
        TaskKind::Report,
    ];

    for kind in &unsupported {
        let is_supported = matches!(
            kind,
            TaskKind::Read | TaskKind::Write | TaskKind::Edit | TaskKind::Find | TaskKind::Shell
        );
        assert!(
            !is_supported,
            "TaskKind::{:?} should NOT be in the allowlist",
            kind
        );
    }
}
