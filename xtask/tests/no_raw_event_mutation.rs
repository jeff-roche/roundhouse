use std::fs;
use xtask::scan::{scan_dir_for, scan_workspace_for};

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
    // Allow-list append_only.rs (Task 10's test), which deliberately
    // contains a raw UPDATE against events to prove the trigger blocks it.
    // migrations.rs is NOT allow-listed here (and doesn't need to be): its
    // trigger definitions read "BEFORE UPDATE ON events", which never
    // matches the "UPDATE EVENTS" substring this scan looks for — an
    // earlier draft of this test allow-listed it anyway, based on a comment
    // that assumed a match that never actually happens; removed rather than
    // left as dead, misleading configuration.
    let violations: Vec<_> = hits
        .into_iter()
        .filter(|(path, _)| !path.ends_with("roundhouse-store/tests/append_only.rs"))
        .collect();
    assert!(
        violations.is_empty(),
        "raw UPDATE events found outside the trigger definition: {violations:?}"
    );
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
    // Allow-list append_only.rs (Task 10's test), which deliberately
    // contains a raw DELETE against events to prove the trigger blocks it.
    // migrations.rs is NOT allow-listed here for the same reason given in
    // `no_file_contains_raw_update_events_sql` above: its trigger reads
    // "BEFORE DELETE ON events", which never matches "DELETE FROM EVENTS".
    let violations: Vec<_> = hits
        .into_iter()
        .filter(|(path, _)| !path.ends_with("roundhouse-store/tests/append_only.rs"))
        .collect();
    assert!(
        violations.is_empty(),
        "raw DELETE FROM events found outside the trigger definition: {violations:?}"
    );
}

/// Positive test: verify the scanner actually DETECTS raw UPDATE events
/// when present in a non-whitelisted file. This prevents silent regressions
/// where the detection logic could be broken by future refactors.
#[test]
fn scanner_detects_raw_update_events_when_present() {
    // Create a temporary test directory isolated from crates/ to avoid
    // interfering with other tests' scans of the live workspace.
    // Use std::env::temp_dir() so this never conflicts with production scanning.
    let thread_id = format!("{:?}", std::thread::current().id())
        .replace("ThreadId(", "")
        .replace(")", "");
    let temp_root = std::env::temp_dir().join(format!("xtask_test_update_{}", thread_id));
    let _ = fs::remove_dir_all(&temp_root); // Clean up from any previous failed run
    fs::create_dir_all(&temp_root).expect("failed to create temp test directory");

    let test_file = temp_root.join("violation.rs");
    fs::write(
        &test_file,
        "let sql = \"UPDATE events SET payload = 'tampered'\";",
    )
    .expect("failed to write temp test file");

    // Scan only the isolated temp directory (not the live workspace)
    let hits = scan_dir_for(&temp_root, |line| {
        let upper = line.to_ascii_uppercase();
        if upper.contains("UPDATE EVENTS") && !upper.trim_start().starts_with("--") {
            Some("raw UPDATE against the events table".to_string())
        } else {
            None
        }
    });

    // Clean up temp directory
    let _ = fs::remove_dir_all(&temp_root);

    // Assert the violation WAS detected (this is the positive proof)
    assert!(
        !hits.is_empty(),
        "scanner should detect UPDATE events violation in temporary test file"
    );
    assert!(
        hits.iter().any(|(path, _)| path.ends_with("violation.rs")),
        "detected violation should include the temporary test file: {hits:?}"
    );
}

/// Positive test: verify the scanner actually DETECTS raw DELETE events
/// when present in a non-whitelisted file. This prevents silent regressions
/// where the detection logic could be broken by future refactors.
#[test]
fn scanner_detects_raw_delete_events_when_present() {
    // Create a temporary test directory isolated from crates/ to avoid
    // interfering with other tests' scans of the live workspace.
    // Use std::env::temp_dir() so this never conflicts with production scanning.
    let thread_id = format!("{:?}", std::thread::current().id())
        .replace("ThreadId(", "")
        .replace(")", "");
    let temp_root = std::env::temp_dir().join(format!("xtask_test_delete_{}", thread_id));
    let _ = fs::remove_dir_all(&temp_root); // Clean up from any previous failed run
    fs::create_dir_all(&temp_root).expect("failed to create temp test directory");

    let test_file = temp_root.join("violation.rs");
    fs::write(
        &test_file,
        "let sql = \"DELETE FROM events WHERE session_id = 'x'\";",
    )
    .expect("failed to write temp test file");

    // Scan only the isolated temp directory (not the live workspace)
    let hits = scan_dir_for(&temp_root, |line| {
        let upper = line.to_ascii_uppercase();
        if upper.contains("DELETE FROM EVENTS") && !upper.trim_start().starts_with("--") {
            Some("raw DELETE against the events table".to_string())
        } else {
            None
        }
    });

    // Clean up temp directory
    let _ = fs::remove_dir_all(&temp_root);

    // Assert the violation WAS detected (this is the positive proof)
    assert!(
        !hits.is_empty(),
        "scanner should detect DELETE FROM events violation in temporary test file"
    );
    assert!(
        hits.iter().any(|(path, _)| path.ends_with("violation.rs")),
        "detected violation should include the temporary test file: {hits:?}"
    );
}
