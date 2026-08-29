use roundhouse_tui::{Coalescer, RopeStore, SessionSummary};
use std::time::{Duration, Instant};

#[test]
fn token_deltas_append_into_a_per_task_rope() {
    let mut ropes = RopeStore::new();
    ropes.append_delta("t1", "Hel");
    ropes.append_delta("t1", "lo");
    ropes.append_delta("t2", "other task");

    assert_eq!(ropes.get("t1"), Some("Hello"));
    assert_eq!(ropes.get("t2"), Some("other task"));
    assert_eq!(ropes.get("missing"), None);
}

#[test]
fn unfocused_session_summaries_coalesce_to_4hz() {
    let mut coalescer = Coalescer::new(Duration::from_millis(250));
    let base = Instant::now();
    let summary = |running: u32| SessionSummary {
        session_id: "s1".into(),
        running_tasks: running,
        blocked: false,
    };

    // First update for a session always emits immediately.
    assert_eq!(coalescer.offer(summary(1), base), Some(summary(1)));
    // A second update 100ms later is inside the 250ms window: coalesced away.
    assert_eq!(
        coalescer.offer(summary(2), base + Duration::from_millis(100)),
        None
    );
    // A third update past the 250ms window emits again.
    assert_eq!(
        coalescer.offer(summary(3), base + Duration::from_millis(260)),
        Some(summary(3))
    );
}
