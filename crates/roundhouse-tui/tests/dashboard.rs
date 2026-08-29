//! Headless proof that `Dashboard` really drives Tasks 19-20's dirty-flag /
//! rope / coalescer machinery from a live `ServerMessage` stream. Driving a
//! real interactive TTY isn't something an automated test can do, so this
//! renders against `TestBackend` and asserts on the resulting cell buffer.

use ratatui::backend::TestBackend;
use ratatui::Terminal;
use roundhouse_tui::{Dashboard, ServerMessage};

/// Collects the whole cell buffer into one string so a test can assert on
/// rendered text without caring which row it landed on.
fn rendered(terminal: &Terminal<TestBackend>) -> String {
    terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|c| c.symbol())
        .collect()
}

#[test]
fn task_delta_and_summary_render_into_the_real_dashboard() {
    let backend = TestBackend::new(60, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut dashboard = Dashboard::new();

    dashboard.apply(ServerMessage::TaskDelta {
        task_id: "t1".into(),
        text: "Edited main.rs".into(),
    });
    // `TestBackend` draws into memory, so the `io::Result` can't be `Err` here.
    assert!(
        dashboard.tick(&mut terminal).unwrap(),
        "first dirty tick must draw"
    );

    assert!(
        rendered(&terminal).contains("Edited main.rs"),
        "task log pane must show the delta text"
    );

    dashboard.apply(ServerMessage::SessionSummary {
        session_id: "s1".into(),
        running_tasks: 0,
        blocked: false,
    });
    assert!(
        dashboard.tick(&mut terminal).unwrap(),
        "second dirty tick must draw"
    );

    assert!(
        rendered(&terminal).contains("running: 0"),
        "status pane must show the session summary"
    );
}

/// Regression test for the coalescing-rejection path: a summary the `Coalescer`
/// refuses must be held and re-offered, not dropped. Before this, a second
/// summary arriving inside the 250ms window was lost forever, so if it was the
/// last one a session ever sent, the status pane stayed stale indefinitely.
#[test]
fn a_summary_refused_by_the_coalescer_is_retained_and_shown_on_a_later_tick() {
    let backend = TestBackend::new(60, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut dashboard = Dashboard::new();

    // First summary for this session always passes the coalescer.
    dashboard.apply(ServerMessage::SessionSummary {
        session_id: "s1".into(),
        running_tasks: 3,
        blocked: false,
    });
    assert!(dashboard.tick(&mut terminal).unwrap());
    assert!(rendered(&terminal).contains("running: 3"));

    // Second summary lands well inside the 250ms window, so it is refused.
    dashboard.apply(ServerMessage::SessionSummary {
        session_id: "s1".into(),
        running_tasks: 7,
        blocked: true,
    });
    assert!(
        !dashboard.tick(&mut terminal).unwrap(),
        "a refused summary must not dirty the status region yet"
    );
    assert!(
        rendered(&terminal).contains("running: 3"),
        "the stale summary is still what's on screen at this point"
    );

    // Once the interval elapses, the retained summary must surface on the next
    // tick even though no further message ever arrives. Sleeping is unavoidable
    // here: `Dashboard` reads `Instant::now()` internally so that callers don't
    // have to carry a clock.
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert!(
        dashboard.tick(&mut terminal).unwrap(),
        "the retained summary must be promoted and drawn"
    );
    let content = rendered(&terminal);
    assert!(
        content.contains("running: 7") && content.contains("blocked: true"),
        "status pane must show the newer summary, not the stale one: {content}"
    );
}
