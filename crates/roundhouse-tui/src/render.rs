use ratatui::backend::Backend;
use ratatui::{Frame, Terminal};

use crate::dirty::DirtyFlags;

/// A 16ms tick that costs zero draw calls when nothing is dirty (§11.2).
///
/// Returns `true` if a frame was drawn, `false` if all regions are clean
/// and the tick was skipped (a no-op).
///
/// If any region is dirty, calls `draw` with the frame and dirty flags,
/// then clears all dirty flags before returning.
pub fn render_tick<B: Backend>(
    terminal: &mut Terminal<B>,
    flags: &mut DirtyFlags,
    draw: impl FnOnce(&mut Frame, &DirtyFlags),
) -> bool {
    if !flags.any_dirty() {
        return false;
    }
    terminal
        .draw(|frame| draw(frame, flags))
        .expect("TestBackend draw never fails");
    flags.clear_all();
    true
}
