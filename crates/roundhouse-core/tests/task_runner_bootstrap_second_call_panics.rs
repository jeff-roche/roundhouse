use roundhouse_core::TaskRunner;

/// S-LOG-1's single-issuance guarantee, other half: a second `bootstrap()`
/// call in the same process must panic rather than silently hand out a
/// second authority. Lives in its own file (its own process, per Cargo's
/// per-integration-test-file convention) so the two `bootstrap()` calls
/// below — first succeeds, second panics — run against a fresh, still-false
/// `BOOTSTRAPPED` static without racing `task_runner_single_issuance.rs`'s
/// own (unconditionally-successful) call in a different process.
#[test]
#[should_panic(expected = "TaskRunner::bootstrap() called more than once in this process")]
fn second_bootstrap_call_panics() {
    let _first = TaskRunner::bootstrap();
    let _second = TaskRunner::bootstrap();
}
