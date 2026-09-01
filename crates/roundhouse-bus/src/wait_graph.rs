//! Wait-graph interlocking (§7.7): synchronous deadlock refusal.
//!
//! `LocalBus` keeps a single `Mutex<WaitGraph>` of pending blocking waits. When a
//! session registers a wait, we run a DFS from the wait target back through the
//! existing wait-for edges; if we reach the waiter, the new edge would close a
//! cycle and the wait is refused synchronously, naming the peer that would
//! deadlock.

use crate::types::BusError;
use roundhouse_core::SessionId;
use smallvec::SmallVec;
use std::collections::HashMap;

/// §7.7, "the interlocking": "WaitGraph: HashMap<SessionId, SmallVec<[SessionId;4]>>;
/// registering a blocking wait does a DFS back to self and refuses synchronously."
pub struct WaitGraph {
    edges: HashMap<SessionId, SmallVec<[SessionId; 4]>>,
}

impl WaitGraph {
    pub fn new() -> Self {
        Self {
            edges: HashMap::new(),
        }
    }

    /// Registers `waiter` as blocked on `target`. Refuses synchronously if this edge
    /// would close a cycle back to `waiter` (waiter would deadlock).
    pub fn register_wait(&mut self, waiter: SessionId, target: SessionId) -> Result<(), BusError> {
        if let Some(cycle) = self.would_cycle(waiter, target) {
            return Err(BusError::WaitWouldDeadlock {
                waiter,
                blocked_on: target,
                cycle,
            });
        }
        self.edges.entry(waiter).or_default().push(target);
        Ok(())
    }

    pub fn clear_wait(&mut self, waiter: SessionId) {
        self.edges.remove(&waiter);
    }

    /// DFS from `target` following existing wait-for edges; if we reach `waiter`, adding
    /// `waiter -> target` would close a cycle. Returns the cycle path (waiter-first,
    /// each node appearing exactly once) if found, so the caller can build the "X is
    /// waiting on you" message.
    fn would_cycle(&self, waiter: SessionId, target: SessionId) -> Option<Vec<SessionId>> {
        let mut stack = vec![target];
        let mut visited = std::collections::HashSet::new();
        let mut parent: HashMap<SessionId, SessionId> = HashMap::new();

        while let Some(node) = stack.pop() {
            if node == waiter {
                // Walk the parent chain from `waiter` back to `target`, pushing each
                // *new* node as we go. `waiter` itself is only ever pushed once, as
                // the head of `path` below — an earlier version of this loop started
                // `cur` at `node` (== `waiter`) and pushed it again on the loop's
                // first iteration before advancing, producing a duplicate entry (e.g.
                // `[b, b, a]` instead of `[b, a]`). Starting the walk from
                // `parent[&waiter]` instead of from `waiter` itself avoids that.
                let mut path = vec![waiter];
                let mut cur = waiter;
                while cur != target {
                    cur = parent[&cur];
                    path.push(cur);
                }
                return Some(path);
            }
            if !visited.insert(node) {
                continue;
            }
            if let Some(children) = self.edges.get(&node) {
                for &child in children {
                    parent.entry(child).or_insert(node);
                    stack.push(child);
                }
            }
        }
        None
    }
}

impl Default for WaitGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use roundhouse_core::SessionId;

    #[test]
    fn direct_two_cycle_is_refused_naming_the_peer() {
        let mut wg = WaitGraph::new();
        let a = SessionId::new();
        let b = SessionId::new();

        // A waits on B first — this is fine, no cycle yet.
        wg.register_wait(a, b).unwrap();

        // Now B tries to wait on A: A -> B -> A is a cycle. Must be refused
        // synchronously, naming which peer would deadlock (§7.7).
        let err = wg.register_wait(b, a).unwrap_err();
        match err {
            crate::types::BusError::WaitWouldDeadlock {
                waiter,
                blocked_on,
                cycle,
            } => {
                assert_eq!(waiter, b);
                assert_eq!(blocked_on, a);
                // Exact path, not just "contains both" — a `[b, b, a]` duplicate of
                // the waiter would still pass a `contains`-only assertion, which is
                // exactly the bug this test caught: `would_cycle` used to push the
                // waiter twice (once as the path head, once again as the DFS's own
                // starting node). The real cycle here is just two sessions: `b`
                // (waiter) closing the loop directly back through `a` (target).
                assert_eq!(cycle, vec![b, a]);
            }
            other => panic!("expected WaitWouldDeadlock, got {other:?}"),
        }
    }

    #[test]
    fn longer_cycle_through_a_third_session_is_also_refused() {
        let mut wg = WaitGraph::new();
        let a = SessionId::new();
        let b = SessionId::new();
        let c = SessionId::new();

        wg.register_wait(a, b).unwrap(); // a -> b
        wg.register_wait(b, c).unwrap(); // b -> c
        let err = wg.register_wait(c, a).unwrap_err(); // c -> a closes a->b->c->a
        match err {
            crate::types::BusError::WaitWouldDeadlock {
                waiter,
                blocked_on,
                cycle,
            } => {
                assert_eq!(waiter, c);
                assert_eq!(blocked_on, a);
                // Exact order (waiter first, then the existing chain back to
                // target), no duplicated waiter — see the direct-two-cycle test's
                // comment for why this must be exact, not a `contains`-only check.
                assert_eq!(cycle, vec![c, b, a]);
            }
            other => panic!("expected WaitWouldDeadlock, got {other:?}"),
        }
    }

    #[test]
    fn independent_waits_with_no_cycle_are_allowed() {
        let mut wg = WaitGraph::new();
        let a = SessionId::new();
        let b = SessionId::new();
        let c = SessionId::new();
        wg.register_wait(a, b).unwrap();
        wg.register_wait(b, c).unwrap();
        // a -> b -> c, no cycle.
    }

    #[test]
    fn clearing_a_wait_allows_the_reverse_edge_afterward() {
        let mut wg = WaitGraph::new();
        let a = SessionId::new();
        let b = SessionId::new();
        wg.register_wait(a, b).unwrap();
        wg.clear_wait(a);
        wg.register_wait(b, a).unwrap(); // no longer a cycle since a's edge is gone
    }
}
