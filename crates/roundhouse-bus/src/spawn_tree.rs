use dashmap::DashMap;
use roundhouse_core::SessionId;

/// §7.1 decision 4: "A Team owns addressing only. The spawn tree remains the sole
/// authority for lifecycle, cancellation, and budget." Distinct from `TeamRegistry` on
/// purpose — recorded by whichever code calls `agent_spawn` (Task 16) and gets back a
/// child `SessionId`, the same place that already separately registers the child's
/// mailbox (`agent_spawn` itself stays untouched — see Task 18's header note).
pub struct SpawnTree {
    children: DashMap<SessionId, ChildSlots>,
}

#[derive(Default)]
struct ChildSlots {
    children: Vec<SessionId>,
    reservations: Vec<SessionId>,
}

impl SpawnTree {
    pub fn new() -> Self {
        Self {
            children: DashMap::new(),
        }
    }

    pub fn record_child(&self, parent: SessionId, child: SessionId) {
        let mut slots = self.children.entry(parent).or_default();
        slots.reservations.retain(|candidate| *candidate != child);
        if !slots.children.contains(&child) {
            slots.children.push(child);
        }
    }

    /// Records `child` only while `parent` remains below `max_children`.
    ///
    /// The check and insertion share DashMap's entry lock so concurrent callers
    /// cannot both consume the final direct-child slot.
    pub fn reserve_child(
        &self,
        parent: SessionId,
        child: SessionId,
        max_children: u32,
    ) -> Option<()> {
        let mut slots = self.children.entry(parent).or_default();
        if slots.children.contains(&child) || slots.reservations.contains(&child) {
            return Some(());
        }
        let occupied = slots.children.len().checked_add(slots.reservations.len())?;
        if u32::try_from(occupied).ok()? >= max_children {
            return None;
        }
        slots.reservations.push(child);
        Some(())
    }

    /// Makes a durable child admission visible to runtime traversal.
    pub fn commit_child_reservation(&self, parent: SessionId, child: SessionId) {
        self.record_child(parent, child);
    }

    /// Releases an uncommitted admission after its durable transaction fails.
    pub fn release_child_reservation(&self, parent: SessionId, child: SessionId) {
        if let Some(mut slots) = self.children.get_mut(&parent) {
            slots.reservations.retain(|candidate| *candidate != child);
            if slots.children.is_empty() && slots.reservations.is_empty() {
                drop(slots);
                self.children.remove(&parent);
            }
        }
    }

    /// Returns the number of immediate children of `parent`.
    pub fn direct_children(&self, parent: SessionId) -> u32 {
        self.children.get(&parent).map_or(0, |slots| {
            u32::try_from(slots.children.len()).unwrap_or(u32::MAX)
        })
    }

    /// Returns child slots held by in-flight durable admissions.
    pub fn reserved_children(&self, parent: SessionId) -> u32 {
        self.children.get(&parent).map_or(0, |slots| {
            u32::try_from(slots.reservations.len()).unwrap_or(u32::MAX)
        })
    }

    /// Removes one immediate child. Repeated removal is intentionally a no-op
    /// so compensation after a failed durable admission is idempotent.
    pub fn remove_child(&self, parent: SessionId, child: SessionId) {
        if let Some(mut slots) = self.children.get_mut(&parent) {
            slots.children.retain(|candidate| *candidate != child);
            slots.reservations.retain(|candidate| *candidate != child);
            if slots.children.is_empty() && slots.reservations.is_empty() {
                drop(slots);
                self.children.remove(&parent);
            }
        }
    }

    /// Every session in `root`'s subtree, `root` itself excluded (callers that want
    /// "root + subtree" — i.e. `kill_subtree`, below — add `root` back explicitly).
    pub fn descendants(&self, root: SessionId) -> Vec<SessionId> {
        let mut out = Vec::new();
        let mut stack = self
            .children
            .get(&root)
            .map(|slots| slots.children.clone())
            .unwrap_or_default();
        while let Some(session) = stack.pop() {
            out.push(session);
            if let Some(slots) = self.children.get(&session) {
                stack.extend(slots.children.iter().copied());
            }
        }
        out
    }
}

impl Default for SpawnTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use roundhouse_core::SessionId;

    #[test]
    fn descendants_includes_the_whole_subtree_not_just_direct_children() {
        let tree = SpawnTree::new();
        let root = SessionId::new();
        let child = SessionId::new();
        let grandchild = SessionId::new();
        let sibling = SessionId::new();
        tree.record_child(root, child);
        tree.record_child(root, sibling);
        tree.record_child(child, grandchild);

        let mut descendants = tree.descendants(root);
        descendants.sort_by_key(|s| s.to_string());
        let mut expected = vec![child, grandchild, sibling];
        expected.sort_by_key(|s| s.to_string());
        assert_eq!(descendants, expected);
    }

    #[test]
    fn a_leaf_session_has_no_descendants() {
        let tree = SpawnTree::new();
        let leaf = SessionId::new();
        assert!(tree.descendants(leaf).is_empty());
    }

    #[test]
    fn direct_children_can_be_counted_and_removed_idempotently() {
        let tree = SpawnTree::new();
        let root = SessionId::new();
        let child = SessionId::new();
        tree.record_child(root, child);
        assert_eq!(tree.direct_children(root), 1);
        tree.remove_child(root, child);
        tree.remove_child(root, child);
        assert_eq!(tree.direct_children(root), 0);
    }

    #[test]
    fn reserving_the_last_direct_child_slot_is_atomic() {
        use std::sync::{Arc, Barrier};

        let tree = Arc::new(SpawnTree::new());
        let parent = SessionId::new();
        for _ in 0..7 {
            tree.record_child(parent, SessionId::new());
        }
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let tree = Arc::clone(&tree);
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                tree.reserve_child(parent, SessionId::new(), 8)
            }));
        }

        barrier.wait();
        let admitted = workers
            .into_iter()
            .filter_map(|worker| worker.join().expect("reservation worker"))
            .count();

        assert_eq!(admitted, 1);
        assert_eq!(tree.direct_children(parent), 7);
        assert_eq!(tree.reserved_children(parent), 1);
    }

    #[test]
    fn a_reservation_is_not_a_runtime_edge_until_it_is_committed() {
        let tree = SpawnTree::new();
        let parent = SessionId::new();
        let child = SessionId::new();

        assert!(tree.reserve_child(parent, child, 8).is_some());
        assert_eq!(tree.direct_children(parent), 0);
        assert_eq!(tree.reserved_children(parent), 1);

        tree.commit_child_reservation(parent, child);

        assert_eq!(tree.direct_children(parent), 1);
        assert_eq!(tree.reserved_children(parent), 0);
    }
}
