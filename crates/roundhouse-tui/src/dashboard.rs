//! The dashboard: the one place that turns a stream of raw
//! `roundhouse_core::EventPayload`s into actual pixels, built on Tasks 19-20's
//! `render_tick`/`RopeStore`/`Coalescer`.
//!
//! Phase 1 built this against a hand-rolled, daemon-pre-summarized
//! `ServerMessage`. Phase 7 Task 2 retired that type: the daemon now forwards
//! `roundhouse-proto`'s real `ClientEvent::TaskEvent { payload, .. }`, so the
//! presentation-level reduction that used to happen daemon-side (flattening a
//! `Delta`/`EventPayload` down to `TaskDelta{task_id, text}` or
//! `SessionSummary{..}`) moves here, into [`Dashboard::apply`].

use std::collections::HashMap;
use std::time::{Duration, Instant};

use ratatui::backend::Backend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::{Frame, Terminal};

use roundhouse_core::{Delta, EventPayload, SessionId, SessionState};

use crate::{render_tick, Coalescer, DirtyFlags, Region, RopeStore, SessionSummary};

/// Owns the dashboard's accumulated state (the per-session rope, the coalesced
/// session summary, and which region needs redrawing) so the exit criterion's
/// "watch it edit a file, see the task log" is driven through the real Tasks
/// 19-20 dashboard/rendering code path rather than a `println!` stand-in.
///
/// State lives here, not in `roundhouse-cli`, for two reasons: the borrow-checker
/// discipline `render_tick` needs (see [`Dashboard::tick`]) is subtle enough that it
/// should exist once, and keeping it in a library crate is what makes it testable
/// headlessly against `ratatui::backend::TestBackend` — a real `round` TTY session
/// can't be driven by an automated test.
pub struct Dashboard {
    /// Accumulated per-session text (Phase 1's per-task rope moved to being
    /// keyed by session, since the real wire's `TaskDelta` payload carries no
    /// task id of its own — see `EventPayload::TaskDelta`).
    ropes: RopeStore,
    /// Which regions still need a redraw (Task 19).
    flags: DirtyFlags,
    /// Rate limiter on session-summary redraws (Task 20).
    coalescer: Coalescer,
    /// The session whose rope the log pane currently shows. Phase 1 renders
    /// exactly one session at a time — the most recently updated one —
    /// because there is no session/task selection UI yet (Phase 5).
    last_session_id: Option<SessionId>,
    /// Count of tasks currently believed running, per session. Incremented on
    /// `TaskStarted`, decremented (saturating) on `TaskCompleted`/`TaskFailed`/
    /// `TaskCancelled`, reset to zero when a session closes.
    running_tasks: HashMap<SessionId, u32>,
    /// Count of tasks currently believed suspended, per session. A counter,
    /// not a bool (ruling W1-R13): if tasks A and B both suspend and only A
    /// resumes, the session is still blocked on B. Incremented on
    /// `TaskSuspended`, decremented (saturating) on `TaskResumed`, reset to
    /// zero when a session closes.
    suspended_tasks: HashMap<SessionId, u32>,
    /// Whether the *session itself* (as opposed to any one task) is
    /// suspended, per `SessionStateChanged`. Kept separate from
    /// `suspended_tasks` rather than folded into one counter: a
    /// session-level suspension and a task-level one are different events at
    /// different granularities, and collapsing them would make "0 suspended
    /// tasks but session suspended" indistinguishable from "both clear." A
    /// session's overall blocked status (see `offer_summary`) is the OR of
    /// the two.
    session_suspended: HashMap<SessionId, bool>,
    /// The most recent summary that survived coalescing, or `None` before the
    /// first one arrives.
    summary: Option<SessionSummary>,
    /// The newest summary the `Coalescer` has so far refused, held for re-offer
    /// on a later tick. `Coalescer`'s contract is "the caller holds the latest
    /// summary and re-offers it on its own tick" — dropping a refused summary
    /// outright would mean that if nothing else ever arrives for that session,
    /// the status pane shows stale state forever.
    pending_summary: Option<SessionSummary>,
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
            last_session_id: None,
            running_tasks: HashMap::new(),
            suspended_tasks: HashMap::new(),
            session_suspended: HashMap::new(),
            summary: None,
            pending_summary: None,
        }
    }

    /// Applies one incoming `EventPayload` for `session_id`, updating state and
    /// marking the affected region dirty.
    ///
    /// This is the reduction the daemon used to do by hand before handing the
    /// TUI a pre-flattened `ServerMessage`: a `TaskDelta{delta: Delta::Text
    /// {text}}` appends to the session's rope; task/session lifecycle payloads
    /// that bear on "is this session running, and is it blocked" update the
    /// coalesced status line. `EventPayload` has variants (session
    /// configuration, messages, notes, losses, non-text deltas, …) with no
    /// presentation-level meaning yet — those fall through the trailing `_`
    /// arm untouched rather than requiring this match to enumerate every one
    /// of `EventPayload`'s ~18 variants by name.
    ///
    /// Takes the payload by value: the rope wants an owned `String` out of
    /// `Delta::Text`, so borrowing here would only force the caller's copy to
    /// be cloned instead.
    pub fn apply(&mut self, session_id: SessionId, payload: EventPayload) {
        match payload {
            EventPayload::TaskDelta {
                delta: Delta::Text { text },
            } => {
                self.ropes.append_delta(&session_id.to_string(), &text);
                self.last_session_id = Some(session_id);
                self.flags.mark(Region::Log);
            }
            EventPayload::TaskStarted { .. } => {
                *self.running_tasks.entry(session_id).or_insert(0) += 1;
                self.offer_summary(session_id);
            }
            EventPayload::TaskCompleted { .. }
            | EventPayload::TaskFailed { .. }
            | EventPayload::TaskCancelled { .. } => {
                let count = self.running_tasks.entry(session_id).or_insert(0);
                *count = count.saturating_sub(1);
                self.offer_summary(session_id);
            }
            EventPayload::TaskSuspended { .. } => {
                *self.suspended_tasks.entry(session_id).or_insert(0) += 1;
                self.offer_summary(session_id);
            }
            EventPayload::TaskResumed { .. } => {
                let count = self.suspended_tasks.entry(session_id).or_insert(0);
                *count = count.saturating_sub(1);
                self.offer_summary(session_id);
            }
            EventPayload::SessionStateChanged { state, .. } => {
                match state {
                    SessionState::Suspended => {
                        self.session_suspended.insert(session_id, true);
                    }
                    SessionState::Closed => {
                        self.reset_session(session_id);
                    }
                    SessionState::Created | SessionState::Running | SessionState::Cancelling => {
                        self.session_suspended.insert(session_id, false);
                    }
                }
                self.offer_summary(session_id);
            }
            // `roundhouse-core`'s dedicated terminal event (distinct from
            // `SessionStateChanged{state: Closed, ..}` above — nothing emits
            // this one yet, but the moment something does, this session's
            // `running_tasks`/blocked counters must not be left stuck at
            // whatever they last were, showing a permanently stale status
            // line.
            EventPayload::SessionClosed { .. } => {
                self.reset_session(session_id);
                self.offer_summary(session_id);
            }
            // Every other variant — non-text `Delta`s, session configuration,
            // policy decisions, messages, notes, losses, … — has no
            // presentation-level reduction in Phase 1's two-pane dashboard.
            _ => {}
        }
    }

    /// Zeroes every per-session counter this dashboard tracks: `running_tasks`,
    /// `suspended_tasks`, and `session_suspended`. Shared by
    /// `SessionStateChanged{state: Closed, ..}` and `SessionClosed` — both mean
    /// "this session is over," and a status line that kept showing a stale
    /// non-zero `running_tasks` or `blocked: true` after that would be a real
    /// misrepresentation of state, not just a cosmetic staleness.
    fn reset_session(&mut self, session_id: SessionId) {
        self.running_tasks.insert(session_id, 0);
        self.suspended_tasks.insert(session_id, 0);
        self.session_suspended.insert(session_id, false);
    }

    /// Offers `session_id`'s current `(running_tasks, blocked)` snapshot to
    /// the `Coalescer`, updating `summary`/`pending_summary` exactly as the
    /// old `ServerMessage::SessionSummary` arm used to. `blocked` is the OR of
    /// "at least one task is suspended" and "the session itself is suspended"
    /// — see `suspended_tasks`/`session_suspended`'s field docs for why these
    /// stay two separate pieces of state rather than one counter.
    fn offer_summary(&mut self, session_id: SessionId) {
        let running_tasks = *self.running_tasks.get(&session_id).unwrap_or(&0);
        let suspended_tasks = *self.suspended_tasks.get(&session_id).unwrap_or(&0);
        let session_suspended = *self.session_suspended.get(&session_id).unwrap_or(&false);
        let blocked = suspended_tasks > 0 || session_suspended;
        let summary = SessionSummary {
            session_id: session_id.to_string(),
            running_tasks,
            blocked,
        };
        // Clone only to keep a copy for the refusal path; `offer` consumes
        // its argument.
        if let Some(accepted) = self.coalescer.offer(summary.clone(), Instant::now()) {
            self.summary = Some(accepted);
            // Anything still pending is older than what was just accepted.
            self.pending_summary = None;
            self.flags.mark(Region::Status);
        } else {
            // Newest refused summary wins: an older pending one is strictly
            // less current, so replacing it loses nothing.
            self.pending_summary = Some(summary);
        }
    }

    /// Re-offers the newest refused summary, if any, promoting it once the
    /// `Coalescer`'s interval has elapsed.
    ///
    /// Called from [`Dashboard::tick`] rather than from a separate periodic timer:
    /// `tick` already runs after every applied message, which is exactly the
    /// "caller re-offers on its own tick" cadence `Coalescer` documents, and it
    /// keeps `Dashboard` free of any clock of its own.
    fn flush_pending_summary(&mut self) {
        let Some(pending) = self.pending_summary.take() else {
            return;
        };
        if let Some(accepted) = self.coalescer.offer(pending.clone(), Instant::now()) {
            self.summary = Some(accepted);
            self.flags.mark(Region::Status);
        } else {
            // Still inside the interval — put it back and try again next tick.
            self.pending_summary = Some(pending);
        }
    }

    /// Returns the accumulated rendered text for `session_id`'s rope, or an
    /// empty string if nothing has arrived for it yet.
    pub fn rendered_text_for(&self, session_id: SessionId) -> &str {
        self.ropes.get(&session_id.to_string()).unwrap_or("")
    }

    /// Runs one real render tick — the same `render_tick` Task 19 already unit-tests
    /// with `TestBackend`, now driven by this dashboard's real accumulated state
    /// instead of a synthetic draw closure. Returns `Ok(true)` if a frame was drawn,
    /// `Ok(false)` if nothing was dirty.
    ///
    /// Copies `last_session_id` out before destructuring: `SessionId` is
    /// `Copy`, so there is no borrow-checker reason to reach through `self`
    /// for it inside the draw closure, unlike `ropes`/`flags`/`summary` below.
    ///
    /// # Errors
    /// Propagates a backend write/flush failure from `render_tick` — see its doc
    /// comment for why that is a real, reachable condition on a live terminal,
    /// and why the error type is `B::Error` rather than `io::Error`.
    pub fn tick<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> Result<bool, B::Error> {
        // Before drawing: a summary the coalescer refused earlier may be due now.
        self.flush_pending_summary();
        let last_session_id = self.last_session_id;
        let Dashboard {
            flags,
            ropes,
            summary,
            ..
        } = self;
        render_tick(terminal, flags, |frame, _flags| {
            draw_dashboard(frame, ropes, last_session_id, summary);
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
    last_session_id: Option<SessionId>,
    summary: &Option<SessionSummary>,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        // The status line is a fixed 3 rows (one text row plus its border); the log
        // pane takes whatever is left, with a 3-row floor so a very short terminal
        // degrades instead of producing a zero-height area.
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(frame.area());

    let log_text = last_session_id
        .and_then(|id| ropes.get(&id.to_string()))
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
