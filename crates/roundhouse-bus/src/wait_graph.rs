//! Task 3 minimal stub for the wait graph (§7.7 cycle detection).
//!
//! Task 8 replaces this with the full `WaitGraph` implementation. Until then,
//! `LocalBus` only needs a constructible, default-constructible placeholder to
//! hold in its single shared `Mutex<WaitGraph>` field.

pub struct WaitGraph;

impl WaitGraph {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WaitGraph {
    fn default() -> Self {
        Self::new()
    }
}
