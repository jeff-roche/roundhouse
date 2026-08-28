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
