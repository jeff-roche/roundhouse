//! The dashboard: the one place that turns a stream of `ServerMessage`s into
//! actual pixels, built on Tasks 19-20's `render_tick`/`RopeStore`/`Coalescer`.

use std::time::{Duration, Instant};

use ratatui::backend::Backend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::{Frame, Terminal};

use crate::{render_tick, Coalescer, DirtyFlags, Region, RopeStore, ServerMessage, SessionSummary};

/// Owns the dashboard's accumulated state (the per-task rope, the coalesced session
/// summary, and which region needs redrawing) so the exit criterion's "watch it edit a
/// file, see the task log" is driven through the real Tasks 19-20 dashboard/rendering
/// code path rather than a `println!` stand-in.
///
/// State lives here, not in `roundhouse-cli`, for two reasons: the borrow-checker
/// discipline `render_tick` needs (see [`Dashboard::tick`]) is subtle enough that it
/// should exist once, and keeping it in a library crate is what makes it testable
/// headlessly against `ratatui::backend::TestBackend` — a real `round` TTY session
/// can't be driven by an automated test.
pub struct Dashboard {
    /// Accumulated per-task text, keyed by task id (Task 20).
    ropes: RopeStore,
    /// Which regions still need a redraw (Task 19).
    flags: DirtyFlags,
    /// Rate limiter on session-summary redraws (Task 20).
    coalescer: Coalescer,
    /// The task whose rope the log pane currently shows. Phase 1 renders exactly
    /// one task at a time — the most recently updated one — because there is no
    /// session/task selection UI yet (Phase 5).
    last_task_id: Option<String>,
    /// The most recent summary that survived coalescing, or `None` before the
    /// first one arrives.
    summary: Option<SessionSummary>,
}

impl Dashboard {
    /// Creates an empty dashboard with nothing dirty, so the first `tick` before any
    /// message arrives costs zero draw calls (§11.2).
    pub fn new() -> Self {
        Self {
            ropes: RopeStore::new(),
            flags: DirtyFlags::new(),
            // §11.2's 4Hz cap on status-line redraws: a session whose tasks stream
            // fast must not be able to drive the terminal's write rate.
            coalescer: Coalescer::new(Duration::from_millis(250)),
            last_task_id: None,
            summary: None,
        }
    }

    /// Applies one incoming `ServerMessage`, updating state and marking the affected
    /// region dirty. `SessionSummary` updates go through the `Coalescer`, so a
    /// fast-updating session doesn't redraw its status line faster than 4Hz; a summary
    /// that gets coalesced away deliberately marks nothing dirty, which is the whole
    /// point — the next one that survives carries the newer state anyway.
    ///
    /// Takes the message by value: the rope and summary want owned `String`s, so
    /// borrowing here would only force the caller's copy to be cloned instead.
    pub fn apply(&mut self, message: ServerMessage) {
        match message {
            ServerMessage::TaskDelta { task_id, text } => {
                self.ropes.append_delta(&task_id, &text);
                self.last_task_id = Some(task_id);
                self.flags.mark(Region::Log);
            }
            ServerMessage::SessionSummary {
                session_id,
                running_tasks,
                blocked,
            } => {
                let summary = SessionSummary {
                    session_id,
                    running_tasks,
                    blocked,
                };
                if let Some(summary) = self.coalescer.offer(summary, Instant::now()) {
                    self.summary = Some(summary);
                    self.flags.mark(Region::Status);
                }
            }
        }
    }

    /// Runs one real render tick — the same `render_tick` Task 19 already unit-tests
    /// with `TestBackend`, now driven by this dashboard's real accumulated state
    /// instead of a synthetic draw closure. Returns `true` if a frame was drawn.
    ///
    /// Field-destructures `self` rather than reaching through `self.` inside the draw
    /// closure: `render_tick` already holds `&mut self.flags` for the duration of the
    /// call, so a closure that also captured `self` would be a second, overlapping
    /// borrow. Destructuring first splits the borrow into disjoint per-field borrows,
    /// which the borrow checker accepts.
    pub fn tick<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> bool {
        let Dashboard {
            flags,
            ropes,
            last_task_id,
            summary,
            ..
        } = self;
        render_tick(terminal, flags, |frame, _flags| {
            draw_dashboard(frame, ropes, last_task_id.as_deref(), summary);
        })
    }
}

impl Default for Dashboard {
    fn default() -> Self {
        Self::new()
    }
}

/// Draws the two Phase 1 panes: the task log on top, the session status line below.
///
/// Free function rather than a method so it can't accidentally re-borrow the whole
/// `Dashboard` from inside `render_tick`'s closure (see [`Dashboard::tick`]).
fn draw_dashboard(
    frame: &mut Frame,
    ropes: &RopeStore,
    last_task_id: Option<&str>,
    summary: &Option<SessionSummary>,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        // The status line is a fixed 3 rows (one text row plus its border); the log
        // pane takes whatever is left, with a 3-row floor so a very short terminal
        // degrades instead of producing a zero-height area.
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(frame.area());

    let log_text = last_task_id
        .and_then(|id| ropes.get(id))
        .unwrap_or("")
        .to_string();
    frame.render_widget(
        Paragraph::new(log_text).block(Block::default().title("Task Log").borders(Borders::ALL)),
        chunks[0],
    );

    let status_text = match summary {
        Some(s) => format!(
            "session {} — running: {} blocked: {}",
            s.session_id, s.running_tasks, s.blocked
        ),
        None => "no session yet".to_string(),
    };
    frame.render_widget(
        Paragraph::new(status_text).block(Block::default().title("Status").borders(Borders::ALL)),
        chunks[1],
    );
}
