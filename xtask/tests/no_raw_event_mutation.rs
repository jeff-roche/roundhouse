use std::fs;
use std::path::Path;
use xtask::scan::scan_workspace_for;

/// S-LOG-2's second enforcement leg (the SQLite trigger in
/// roundhouse-store is the first): even a helper that *tries* to run raw
/// UPDATE/DELETE against the events table never gets committed, because
/// this scan fails CI before it ships.
#[test]
fn no_file_contains_raw_update_events_sql() {
    let hits = scan_workspace_for(|line| {
        let upper = line.to_ascii_uppercase();
        if upper.contains("UPDATE EVENTS") && !upper.trim_start().starts_with("--") {
            Some("raw UPDATE against the events table".to_string())
        } else {
            None
        }
    });
    // The trigger definitions in migrations.rs legitimately mention
    // "BEFORE UPDATE ON events" — allow-list that one file, fail on any
    // other occurrence. Also allow-list append_only.rs (Task 10's test)
    // which deliberately contains UPDATE against events to prove the trigger
    // blocks it.
    let violations: Vec<_> = hits
        .into_iter()
        .filter(|(path, _)| {
            !path.ends_with("roundhouse-store/src/migrations.rs")
                && !path.ends_with("roundhouse-store/tests/append_only.rs")
        })
        .collect();
    assert!(violations.is_empty(), "raw UPDATE events found outside the trigger definition: {violations:?}");
}

#[test]
fn no_file_contains_raw_delete_from_events_sql() {
    let hits = scan_workspace_for(|line| {
        let upper = line.to_ascii_uppercase();
        if upper.contains("DELETE FROM EVENTS") && !upper.trim_start().starts_with("--") {
            Some("raw DELETE against the events table".to_string())
        } else {
            None
        }
    });
    // The trigger definitions in migrations.rs legitimately mention the
    // DELETE trigger — allow-list that one file, fail on any other.
    // Also allow-list append_only.rs (Task 10's test) which deliberately
    // contains DELETE against events to prove the trigger blocks it.
    let violations: Vec<_> = hits
        .into_iter()
        .filter(|(path, _)| {
            !path.ends_with("roundhouse-store/src/migrations.rs")
                && !path.ends_with("roundhouse-store/tests/append_only.rs")
        })
        .collect();
    assert!(violations.is_empty(), "raw DELETE FROM events found outside the trigger definition: {violations:?}");
}

/// Positive test: verify the scanner actually DETECTS raw UPDATE events
/// when present in a non-whitelisted file. This prevents silent regressions
/// where the detection logic could be broken by future refactors.
#[test]
fn scanner_detects_raw_update_events_when_present() {
    // Create a temporary test file under crates/ with a unique name (thread ID)
    // to avoid conflicts when tests run in parallel
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must live one directory below the workspace root");
    let thread_id = format!("{:?}", std::thread::current().id()).replace("ThreadId(", "").replace(")", "");
    let temp_dir = workspace_root.join("crates").join(format!("xtask_test_temp_update_{}", thread_id));
    let _ = fs::remove_dir_all(&temp_dir); // Clean up from any previous failed run
    fs::create_dir_all(&temp_dir).expect("failed to create temp test directory");

    let test_file = temp_dir.join("violation.rs");
    fs::write(&test_file, "let sql = \"UPDATE events SET payload = 'tampered'\";")
        .expect("failed to write temp test file");

    // Run the scanner with the UPDATE pattern check
    let hits = scan_workspace_for(|line| {
        let upper = line.to_ascii_uppercase();
        if upper.contains("UPDATE EVENTS") && !upper.trim_start().starts_with("--") {
            Some("raw UPDATE against the events table".to_string())
        } else {
            None
        }
    });

    // Apply the same allow-list filter as the real test
    let violations: Vec<_> = hits
        .into_iter()
        .filter(|(path, _)| {
            !path.ends_with("roundhouse-store/src/migrations.rs")
                && !path.ends_with("roundhouse-store/tests/append_only.rs")
        })
        .collect();

    // Clean up temp directory
    let _ = fs::remove_dir_all(&temp_dir);

    // Assert the violation WAS detected (this is the positive proof)
    assert!(
        !violations.is_empty(),
        "scanner should detect UPDATE events violation in temporary test file"
    );
    assert!(
        violations.iter().any(|(path, _)| path.ends_with("violation.rs")),
        "detected violation should include the temporary test file: {violations:?}"
    );
}

/// Positive test: verify the scanner actually DETECTS raw DELETE events
/// when present in a non-whitelisted file. This prevents silent regressions
/// where the detection logic could be broken by future refactors.
#[test]
fn scanner_detects_raw_delete_events_when_present() {
    // Create a temporary test file under crates/ with a unique name (thread ID)
    // to avoid conflicts when tests run in parallel
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must live one directory below the workspace root");
    let thread_id = format!("{:?}", std::thread::current().id()).replace("ThreadId(", "").replace(")", "");
    let temp_dir = workspace_root.join("crates").join(format!("xtask_test_temp_delete_{}", thread_id));
    let _ = fs::remove_dir_all(&temp_dir); // Clean up from any previous failed run
    fs::create_dir_all(&temp_dir).expect("failed to create temp test directory");

    let test_file = temp_dir.join("violation.rs");
    fs::write(&test_file, "let sql = \"DELETE FROM events WHERE session_id = 'x'\";")
        .expect("failed to write temp test file");

    // Run the scanner with the DELETE pattern check
    let hits = scan_workspace_for(|line| {
        let upper = line.to_ascii_uppercase();
        if upper.contains("DELETE FROM EVENTS") && !upper.trim_start().starts_with("--") {
            Some("raw DELETE against the events table".to_string())
        } else {
            None
        }
    });

    // Apply the same allow-list filter as the real test
    let violations: Vec<_> = hits
        .into_iter()
        .filter(|(path, _)| {
            !path.ends_with("roundhouse-store/src/migrations.rs")
                && !path.ends_with("roundhouse-store/tests/append_only.rs")
        })
        .collect();

    // Clean up temp directory
    let _ = fs::remove_dir_all(&temp_dir);

    // Assert the violation WAS detected (this is the positive proof)
    assert!(
        !violations.is_empty(),
        "scanner should detect DELETE FROM events violation in temporary test file"
    );
    assert!(
        violations.iter().any(|(path, _)| path.ends_with("violation.rs")),
        "detected violation should include the temporary test file: {violations:?}"
    );
}
