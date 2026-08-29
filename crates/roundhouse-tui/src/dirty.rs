use std::collections::HashSet;

/// A UI region that may require a redraw.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Region {
    /// Attention banner/modal region.
    Attention,
    /// Session list sidebar.
    SessionList,
    /// Task log scrollable region.
    Log,
    /// Message composer region.
    Composer,
    /// Status bar region.
    Status,
}

/// Tracks which UI regions are dirty (require a redraw).
///
/// A region is marked dirty when its state changes. `render_tick` checks
/// if any region is dirty; if so, it draws a frame and clears all dirty flags.
/// If nothing is dirty, `render_tick` returns `Ok(false)` without drawing.
pub struct DirtyFlags {
    set: HashSet<Region>,
}

impl DirtyFlags {
    /// Create a new, clean dirty-flag tracker (nothing is dirty).
    pub fn new() -> Self {
        Self {
            set: HashSet::new(),
        }
    }

    /// Mark a region as dirty.
    pub fn mark(&mut self, region: Region) {
        self.set.insert(region);
    }

    /// Check if any region is dirty.
    pub fn any_dirty(&self) -> bool {
        !self.set.is_empty()
    }

    /// Clear all dirty flags.
    pub fn clear_all(&mut self) {
        self.set.clear();
    }
}

impl Default for DirtyFlags {
    fn default() -> Self {
        Self::new()
    }
}
