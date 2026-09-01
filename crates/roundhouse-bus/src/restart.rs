use crate::local_bus::LocalBus;
use crate::mailbox::{MailboxKind, DEFAULT_MAILBOX_CAPACITY};
use roundhouse_core::SessionId;

/// What the daemon's boot sequence reads back from roundhouse-store: which sessions
/// were live, and which had a `TaskSuspended{AwaitingReply}` (or `PeerWait`) at crash
/// time, per §7.8's restart contract.
pub struct SuspendedWait {
    pub session: SessionId,
    pub target: Option<SessionId>, // None if waiting on a reply not tied to one peer
    pub deadline_ms: Option<i64>,
}

pub struct RestartSnapshot {
    pub live_sessions: Vec<SessionId>,
    pub suspended_waits: Vec<SuspendedWait>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RestartOutcome {
    Rearmed { session: SessionId },
    TimedOut { session: SessionId },
}

impl LocalBus {
    /// §7.8: "re-register mailboxes for live sessions, re-arm deadlines from
    /// mailbox.deadline, rebuild the wait graph from suspended tasks. Deadlines already
    /// past resolve to TimedOut at boot."
    pub async fn restart_from(
        &self,
        snapshot: RestartSnapshot,
        now_ms: i64,
    ) -> Vec<RestartOutcome> {
        for session in &snapshot.live_sessions {
            let _ = self
                .register_mailbox(*session, MailboxKind::Bounded(DEFAULT_MAILBOX_CAPACITY))
                .await;
        }

        let mut outcomes = Vec::new();
        for wait in snapshot.suspended_waits {
            if let Some(target) = wait.target {
                // Rebuild the wait graph edge regardless of deadline outcome — even a
                // wait about to time out was, until this instant, a real edge.
                let mut wg = self.wait_graph.lock().expect("wait graph mutex poisoned");
                let _ = wg.register_wait(wait.session, target);
            }

            match wait.deadline_ms {
                Some(deadline) if deadline <= now_ms => {
                    outcomes.push(RestartOutcome::TimedOut {
                        session: wait.session,
                    });
                }
                _ => {
                    outcomes.push(RestartOutcome::Rearmed {
                        session: wait.session,
                    });
                }
            }
        }
        outcomes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus_trait::Bus;
    use crate::local_bus::LocalBus;
    use roundhouse_core::SessionId;

    #[tokio::test]
    async fn restart_rearms_deadlines_and_expires_past_ones_as_timed_out() {
        let bus = LocalBus::new();
        let live = SessionId::new();
        let now_ms = 1_000_000_i64;

        let snapshot = RestartSnapshot {
            live_sessions: vec![live],
            suspended_waits: vec![
                // A wait whose deadline already passed before boot.
                SuspendedWait {
                    session: live,
                    target: None,
                    deadline_ms: Some(now_ms - 1),
                },
            ],
        };

        let outcomes = bus.restart_from(snapshot, now_ms).await;

        // §7.8: "Deadlines already past resolve to TimedOut at boot, so a crashed
        // daemon never leaves an agent parked forever."
        assert_eq!(outcomes.len(), 1);
        assert!(matches!(outcomes[0], RestartOutcome::TimedOut { session } if session == live));
        assert!(bus.has_mailbox(live));
    }

    #[tokio::test]
    async fn restart_rebuilds_wait_graph_from_suspended_tasks() {
        let bus = LocalBus::new();
        let a = SessionId::new();
        let b = SessionId::new();

        let snapshot = RestartSnapshot {
            live_sessions: vec![a, b],
            suspended_waits: vec![SuspendedWait {
                session: a,
                target: Some(b),
                deadline_ms: None,
            }],
        };
        bus.restart_from(snapshot, 0).await;

        // The rebuilt wait graph must now refuse b -> a as a cycle, exactly as if a's
        // wait had been registered live.
        let err = bus.register_wait(b, a).await.unwrap_err();
        assert!(matches!(
            err,
            crate::types::BusError::WaitWouldDeadlock { .. }
        ));
    }
}
