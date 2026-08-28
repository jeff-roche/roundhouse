use std::fs;
use xtask::scan::{scan_dir_for, scan_workspace_for};

/// S-LOG-1's second enforcement leg (the private `Seal` field in
/// roundhouse-core is the first, compiler-checked leg — see
/// roundhouse-core's Task 4 trybuild test). This scan catches the case a
/// compiler check cannot: someone adding a *second* sealed constructor
/// path inside roundhouse-core itself that isn't `TaskRunner`.
#[test]
fn only_task_runner_rs_calls_event_new_sealed() {
    let hits = scan_workspace_for(|line| {
        if line.contains("Event::new_sealed") {
            Some("call to Event::new_sealed".to_string())
        } else {
            None
        }
    });
    let violations: Vec<_> = hits
        .into_iter()
        .filter(|(path, _)| {
            !path.ends_with("roundhouse-core/src/task_runner.rs")
                && !path.ends_with("roundhouse-core/src/event.rs")
        })
        .collect();
    assert!(
        violations.is_empty(),
        "Event::new_sealed must only be called from task_runner.rs (its own definition site in \
         event.rs is expected): {violations:?}"
    );
}

/// Positive test: verify the scanner actually DETECTS unauthorized
/// Event::new_sealed calls when present in a non-whitelisted file. This prevents
/// silent regressions where the detection logic could be broken by future refactors.
#[test]
fn scanner_detects_event_new_sealed_calls_when_present() {
    // Create a temporary test directory isolated from crates/ to avoid
    // interfering with other tests' scans of the live workspace.
    // Use std::env::temp_dir() so this never conflicts with production scanning.
    let thread_id = format!("{:?}", std::thread::current().id()).replace("ThreadId(", "").replace(")", "");
    let temp_root = std::env::temp_dir().join(format!("xtask_test_bypass_{}", thread_id));
    let _ = fs::remove_dir_all(&temp_root); // Clean up from any previous failed run
    fs::create_dir_all(&temp_root).expect("failed to create temp test directory");

    let test_file = temp_root.join("unauthorized.rs");
    fs::write(&test_file, "let event = Event::new_sealed(task_id, payload);")
        .expect("failed to write temp test file");

    // Scan only the isolated temp directory (not the live workspace)
    let hits = scan_dir_for(&temp_root, |line| {
        if line.contains("Event::new_sealed") {
            Some("call to Event::new_sealed".to_string())
        } else {
            None
        }
    });

    // Clean up temp directory
    let _ = fs::remove_dir_all(&temp_root);

    // Assert the violation WAS detected (this is the positive proof)
    assert!(
        !hits.is_empty(),
        "scanner should detect Event::new_sealed call in temporary test file"
    );
    assert!(
        hits.iter().any(|(path, _)| path.ends_with("unauthorized.rs")),
        "detected violation should include the temporary test file: {hits:?}"
    );
}
