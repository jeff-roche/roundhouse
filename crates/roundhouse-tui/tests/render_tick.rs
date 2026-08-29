use ratatui::backend::TestBackend;
use ratatui::Terminal;
use roundhouse_tui::{render_tick, DirtyFlags, Region};
use std::cell::RefCell;

#[test]
fn idle_tick_with_nothing_dirty_never_draws() {
    let backend = TestBackend::new(40, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut flags = DirtyFlags::new();
    let draw_count = RefCell::new(0);

    // `TestBackend` writes into an in-memory buffer, so the `io::Result` here
    // genuinely cannot be `Err` — unwrapping is safe in a way it is not for the
    // real `CrosstermBackend` the CLI drives.
    let drew = render_tick(&mut terminal, &mut flags, |_frame, _flags| {
        *draw_count.borrow_mut() += 1;
    })
    .unwrap();

    assert!(!drew);
    assert_eq!(*draw_count.borrow(), 0);
}

#[test]
fn marking_a_region_dirty_draws_exactly_once_then_clears() {
    let backend = TestBackend::new(40, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut flags = DirtyFlags::new();
    flags.mark(Region::Log);
    let draw_count = RefCell::new(0);

    let drew = render_tick(&mut terminal, &mut flags, |_frame, _flags| {
        *draw_count.borrow_mut() += 1;
    })
    .unwrap();

    assert!(drew);
    assert_eq!(*draw_count.borrow(), 1);
    assert!(
        !flags.any_dirty(),
        "flags must clear after a completed render"
    );
}
