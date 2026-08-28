use roundhouse_core::{Origin, SessionId, TaskId, TaskInput, TaskKind, TaskRunner, Timestamp};

#[test]
fn bootstrap_produces_a_working_runner_that_records_task_created() {
    // NOTE: this test and the one below run in separate processes (cargo test
    // does that per-#[test] by default is false — see Step 3 for how this is
    // made safe with #[test] `#[ignore]`-free single-process ordering).
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
