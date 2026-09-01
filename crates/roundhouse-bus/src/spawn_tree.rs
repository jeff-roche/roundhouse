use dashmap::DashMap;
use roundhouse_core::SessionId;

/// §7.1 decision 4: "A Team owns addressing only. The spawn tree remains the sole
/// authority for lifecycle, cancellation, and budget." Distinct from `TeamRegistry` on
/// purpose — recorded by whichever code calls `agent_spawn` (Task 16) and gets back a
/// child `SessionId`, the same place that already separately registers the child's
/// mailbox (`agent_spawn` itself stays untouched — see Task 18's header note).
pub struct SpawnTree {
    children: DashMap<SessionId, Vec<SessionId>>,
}

impl SpawnTree {
    pub fn new() -> Self {
        Self {
            children: DashMap::new(),
        }
    }

    pub fn record_child(&self, parent: SessionId, child: SessionId) {
        self.children.entry(parent).or_default().push(child);
    }

    /// Every session in `root`'s subtree, `root` itself excluded (callers that want
    /// "root + subtree" — i.e. `kill_subtree`, below — add `root` back explicitly).
    pub fn descendants(&self, root: SessionId) -> Vec<SessionId> {
        let mut out = Vec::new();
        let mut stack = self
            .children
            .get(&root)
            .map(|c| c.clone())
            .unwrap_or_default();
        while let Some(session) = stack.pop() {
            out.push(session);
            if let Some(grandchildren) = self.children.get(&session) {
                stack.extend(grandchildren.iter().copied());
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
}
