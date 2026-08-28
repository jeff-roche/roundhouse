use xtask::scan::scan_workspace_for;

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
