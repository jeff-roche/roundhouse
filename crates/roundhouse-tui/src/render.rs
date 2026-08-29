use ratatui::backend::Backend;
use ratatui::{Frame, Terminal};

use crate::dirty::DirtyFlags;

/// A 16ms tick that costs zero draw calls when nothing is dirty (§11.2).
///
/// Returns `Ok(true)` if a frame was drawn, `Ok(false)` if all regions are
/// clean and the tick was skipped (a no-op).
///
/// If any region is dirty, calls `draw` with the frame and dirty flags,
/// then clears all dirty flags before returning.
///
/// # Errors
/// Propagates whatever the backend's write/flush fails with. This is fallible
/// rather than infallible because a real backend genuinely fails: Rust ignores
/// `SIGPIPE` by default, so a closed stdout (`round | head -1`, a terminal that
/// went away, a full disk) reaches `CrosstermBackend::flush` as an ordinary
/// `io::Error`. An earlier version `.expect()`ed this away, which was sound only
/// while `TestBackend` was the sole caller.
///
/// The error type is `B::Error`, not `io::Error`: `Backend::Error` is an
/// associated type, and the two backends in play disagree about it —
/// `CrosstermBackend::Error` is `io::Error`, while `TestBackend::Error` is
/// `Infallible`. Threading it through keeps `TestBackend`'s infallibility
/// visible in the type instead of erasing it behind a conversion.
///
/// The dirty flags are deliberately **not** cleared on the error path: a frame
/// that failed to reach the terminal hasn't been rendered, so the affected
/// regions stay dirty and a caller that recovers redraws them.
pub fn render_tick<B: Backend>(
    terminal: &mut Terminal<B>,
    flags: &mut DirtyFlags,
    draw: impl FnOnce(&mut Frame, &DirtyFlags),
) -> Result<bool, B::Error> {
    if !flags.any_dirty() {
        return Ok(false);
    }
    terminal.draw(|frame| draw(frame, flags))?;
    flags.clear_all();
    Ok(true)
}
