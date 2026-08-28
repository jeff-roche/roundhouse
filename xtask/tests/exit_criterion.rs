use std::process::Command;

/// §13.2's Phase 0 exit criterion, verified directly rather than taken on
/// faith: "every downstream crate compiles against stub implementations of
/// these traits." `cargo check --workspace` is the literal check; this
/// test shells out to it so the exit criterion has its own CI-visible
/// pass/fail, not just an implicit side effect of other tests passing.
#[test]
fn cargo_check_workspace_succeeds() {
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let status = Command::new("cargo")
        .arg("check")
        .arg("--workspace")
        .arg("--all-targets")
        .current_dir(workspace_root)
        .status()
        .expect("cargo must be on PATH");
    assert!(status.success(), "cargo check --workspace --all-targets must succeed (Phase 0 exit criterion, §13.2)");
}
