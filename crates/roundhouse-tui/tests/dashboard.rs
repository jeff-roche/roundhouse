//! Headless proof that `Dashboard` really drives Tasks 19-20's dirty-flag /
//! rope / coalescer machinery from a live `ServerMessage` stream. Driving a
//! real interactive TTY isn't something an automated test can do, so this
//! renders against `TestBackend` and asserts on the resulting cell buffer.

use ratatui::backend::TestBackend;
use ratatui::Terminal;
use roundhouse_tui::{Dashboard, ServerMessage};

#[test]
fn task_delta_and_summary_render_into_the_real_dashboard() {
    let backend = TestBackend::new(60, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut dashboard = Dashboard::new();

    dashboard.apply(ServerMessage::TaskDelta {
        task_id: "t1".into(),
        text: "Edited main.rs".into(),
    });
    assert!(dashboard.tick(&mut terminal), "first dirty tick must draw");

    let content: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(
        content.contains("Edited main.rs"),
        "task log pane must show the delta text"
    );

    dashboard.apply(ServerMessage::SessionSummary {
        session_id: "s1".into(),
        running_tasks: 0,
        blocked: false,
    });
    assert!(dashboard.tick(&mut terminal), "second dirty tick must draw");

    let content: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(
        content.contains("running: 0"),
        "status pane must show the session summary"
    );
}
