//! Rate-limiting for session summary updates.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A per-session summary at a point in time.
///
/// `Coalescer` uses this to decide whether to emit an update or drop it.
/// It combines `session_id` with counts and status to represent the current
/// state of a session.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionSummary {
    /// Unique identifier for the session.
    pub session_id: String,
    /// Number of tasks currently running in this session.
    pub running_tasks: u32,
    /// True if the session is waiting on something external.
    pub blocked: bool,
}

/// Coalesces rapid-fire session summary updates down to a maximum frequency.
///
/// The daemon may receive many summary updates per second as tasks stream tokens.
/// `Coalescer` holds the *latest* summary for each session and emits it only when
/// the configured interval has elapsed since the last emission for that session.
/// This limits the TUI redraw rate to a target frequency (e.g., 4 Hz with a 250ms interval).
pub struct Coalescer {
    /// Emit at most once every `interval` per session.
    interval: Duration,
    /// Time of last emission per session ID.
    last_emitted: HashMap<String, Instant>,
}

impl Coalescer {
    /// Creates a new `Coalescer` with the given interval between emissions.
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            last_emitted: HashMap::new(),
        }
    }

    /// Offers a summary for potential emission.
    ///
    /// Returns `Some(summary)` if at least `interval` has elapsed since the last emission
    /// for this session (or this is the first update ever seen for it); otherwise the
    /// update is coalesced away and `None` is returned. The daemon holds the *latest*
    /// summary per session and calls `offer` with it on its own tick — an unfocused
    /// session therefore surfaces at most `interval`^-1 updates/sec regardless of how fast its tasks
    /// actually stream.
    ///
    /// Takes an explicit `now` parameter rather than reading the wall clock, so that
    /// tests are deterministic instead of timing-flaky — the daemon-side caller supplies
    /// `Instant::now()` on its own tick.
    pub fn offer(&mut self, summary: SessionSummary, now: Instant) -> Option<SessionSummary> {
        let due = match self.last_emitted.get(&summary.session_id) {
            None => true,
            Some(&last) => now.duration_since(last) >= self.interval,
        };
        if due {
            self.last_emitted.insert(summary.session_id.clone(), now);
            Some(summary)
        } else {
            None
        }
    }
}
