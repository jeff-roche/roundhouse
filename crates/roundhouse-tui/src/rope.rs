//! Per-task append-only text accumulation.

use std::collections::HashMap;

/// Per-task rope storage for accumulating deltas from streaming token messages.
///
/// `RopeStore` maintains a map of task IDs to accumulated text strings.
/// Each delta appends to the text for its task, and the caller can retrieve
/// the current accumulated text at any time.
pub struct RopeStore {
    /// Map from task ID to accumulated text.
    ropes: HashMap<String, String>,
}

impl RopeStore {
    /// Creates a new empty `RopeStore`.
    pub fn new() -> Self {
        Self { ropes: HashMap::new() }
    }

    /// Appends `text` to the rope for the given `task_id`.
    ///
    /// If no rope exists for this task yet, one is created.
    pub fn append_delta(&mut self, task_id: &str, text: &str) {
        self.ropes.entry(task_id.to_string()).or_default().push_str(text);
    }

    /// Retrieves the accumulated text for the given `task_id`, or `None` if not present.
    pub fn get(&self, task_id: &str) -> Option<&str> {
        self.ropes.get(task_id).map(String::as_str)
    }
}

impl Default for RopeStore {
    fn default() -> Self {
        Self::new()
    }
}
