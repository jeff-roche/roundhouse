//! Headless proof that `Dashboard` really drives Tasks 19-20's dirty-flag /
//! rope / coalescer machinery from a live `EventPayload` stream. Driving a
//! real interactive TTY isn't something an automated test can do, so this
//! renders against `TestBackend` and asserts on the resulting cell buffer.
//!
//! Rewritten for Phase 7 Task 2: these used to apply the retired,
//! daemon-pre-summarized `ServerMessage` directly; they now apply the raw
//! `roundhouse_core::EventPayload` variants `Dashboard::apply` reduces itself.

use ratatui::backend::TestBackend;
use ratatui::Terminal;
use roundhouse_core::{
    Delta, EventPayload, Handle, IsolationAttestation, SessionId, SessionState, Tier,
};
use roundhouse_tui::Dashboard;

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

fn task_started() -> EventPayload {
    EventPayload::TaskStarted {
        isolation: IsolationAttestation {
            tier: Tier::None,
            digest: "test".into(),
            net_enforced: false,
        },
        handle: None::<Handle>,
    }
}

#[test]
fn task_delta_and_summary_render_into_the_real_dashboard() {
    let backend = TestBackend::new(60, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut dashboard = Dashboard::new();
    let session = SessionId::new();

    dashboard.apply(
        session,
        EventPayload::TaskDelta {
            delta: Delta::Text {
                text: "Edited main.rs".into(),
            },
        },
    );
    // `TestBackend` draws into memory, so the `io::Result` can't be `Err` here.
    assert!(
        dashboard.tick(&mut terminal).unwrap(),
        "first dirty tick must draw"
    );

    assert!(
        rendered(&terminal).contains("Edited main.rs"),
        "task log pane must show the delta text"
    );

    // One task starting is this session's first-ever summary offer, which
    // always passes the coalescer immediately — the same "running: N" status
    // line the daemon used to hand-flatten into a
    // `ServerMessage::SessionSummary`, now reduced here from a raw
    // `TaskStarted` payload instead.
    dashboard.apply(session, task_started());
    assert!(
        dashboard.tick(&mut terminal).unwrap(),
        "second dirty tick must draw"
    );

    assert!(
        rendered(&terminal).contains("running: 1"),
        "status pane must show the session summary"
    );
}

/// Regression test for the coalescing-rejection path: a summary the `Coalescer`
/// refuses must be held and re-offered, not dropped. Before this, a second
/// summary arriving inside the 250ms window was lost forever, so if it was the
/// last one a session ever sent, the status pane stayed stale indefinitely.
#[test]
fn a_summary_refused_by_the_coalescer_is_retained_and_shown_on_a_later_tick() {
    // Wider than the other test in this file: the status line now includes a
    // real 36-character `SessionId` UUID (Phase 1's `ServerMessage` carried
    // a hand-picked short `String` like `"s1"`), and this test's final
    // assertion needs both "running: 3" and "blocked: true" to survive on
    // one line without truncation.
    let backend = TestBackend::new(100, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut dashboard = Dashboard::new();
    let session = SessionId::new();

    // The first offer `Dashboard` ever makes for a session always passes the
    // coalescer (nothing was ever emitted before), so exactly one
    // `task_started()` here is what brings `running_tasks` to 1 and gets
    // shown immediately.
    dashboard.apply(session, task_started());
    assert!(dashboard.tick(&mut terminal).unwrap());
    assert!(rendered(&terminal).contains("running: 1"));

    // Two more tasks start and the session is marked suspended, all well
    // inside the 250ms window — every one of these offers is refused, and
    // only the newest refused snapshot (running: 3, blocked: true) is
    // retained as `pending_summary`.
    dashboard.apply(session, task_started());
    dashboard.apply(session, task_started());
    dashboard.apply(
        session,
        EventPayload::SessionStateChanged {
            state: SessionState::Suspended,
            reason: None,
        },
    );
    assert!(
        !dashboard.tick(&mut terminal).unwrap(),
        "a refused summary must not dirty the status region yet"
    );
    assert!(
        rendered(&terminal).contains("running: 1"),
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
        content.contains("running: 3") && content.contains("blocked: true"),
        "status pane must show the newer summary, not the stale one: {content}"
    );
}
