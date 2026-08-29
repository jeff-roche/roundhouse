use roundhouse_core::{Origin, SessionId, TaskId, TaskInput, TaskKind, TaskRunner, Timestamp};

#[test]
fn bootstrap_produces_a_working_runner_that_records_task_created() {
    // The second-call-panics half of S-LOG-1 (BOOTSTRAPPED is a process-wide
    // static, so it can't be tested from a second #[test] fn in *this* file
    // without racing this one) lives in its own file,
    // `task_runner_bootstrap_second_call_panics.rs` — each file under
    // `tests/` compiles to its own process, giving it a fresh, unbootstrapped
    // static to call `bootstrap()` twice against, in order, within one test.
    let runner = TaskRunner::bootstrap();
    let event = runner.record_task_created(
        SessionId::new(),
        1,
        Timestamp::from_unix_nanos(0),
        TaskId::new(),
        TaskKind::Shell,
        None,
        Origin::Model,
        TaskInput::Text("ls".into()),
        1,
    );
    assert_eq!(event.seq, 1);
}
