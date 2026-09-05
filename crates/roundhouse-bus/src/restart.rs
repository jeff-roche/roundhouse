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

    #[tokio::test]
    async fn restart_registers_a_mailbox_for_every_live_session_in_the_snapshot() {
        let bus = LocalBus::new();
        let a = SessionId::new();
        let b = SessionId::new();
        let c = SessionId::new();

        let snapshot = RestartSnapshot {
            live_sessions: vec![a, b, c],
            suspended_waits: vec![],
        };
        let outcomes = bus.restart_from(snapshot, 0).await;

        assert!(outcomes.is_empty());
        assert!(bus.has_mailbox(a));
        assert!(bus.has_mailbox(b));
        assert!(bus.has_mailbox(c));
    }

    #[tokio::test]
    async fn a_rearmed_wait_with_no_deadline_and_a_target_rebuilds_the_edge() {
        let bus = LocalBus::new();
        let waiter = SessionId::new();
        let target = SessionId::new();

        let snapshot = RestartSnapshot {
            live_sessions: vec![waiter, target],
            suspended_waits: vec![SuspendedWait {
                session: waiter,
                target: Some(target),
                deadline_ms: None,
            }],
        };
        let outcomes = bus.restart_from(snapshot, 0).await;

        assert_eq!(outcomes, vec![RestartOutcome::Rearmed { session: waiter }]);
        // And the edge really was rebuilt, not just the outcome reported.
        let err = bus.register_wait(target, waiter).await.unwrap_err();
        assert!(matches!(
            err,
            crate::types::BusError::WaitWouldDeadlock { .. }
        ));
    }

    #[tokio::test]
    async fn a_wait_with_no_target_and_a_future_deadline_rearms_without_an_edge() {
        let bus = LocalBus::new();
        let session = SessionId::new();
        let now_ms = 1_000_000_i64;

        let snapshot = RestartSnapshot {
            live_sessions: vec![session],
            suspended_waits: vec![SuspendedWait {
                session,
                target: None,
                deadline_ms: Some(now_ms + 60_000), // an hour... well, a minute, in the future
            }],
        };
        let outcomes = bus.restart_from(snapshot, now_ms).await;

        assert_eq!(outcomes, vec![RestartOutcome::Rearmed { session }]);
        // No target means no wait-graph edge was ever attempted — a fresh wait
        // registration from `session` onto any other live session must still be
        // free to succeed (no phantom edge left behind).
        let other = SessionId::new();
        bus.register_wait(session, other).await.unwrap();
    }

    #[tokio::test]
    async fn restart_of_an_empty_snapshot_produces_no_mailboxes_and_no_outcomes() {
        let bus = LocalBus::new();
        let snapshot = RestartSnapshot {
            live_sessions: vec![],
            suspended_waits: vec![],
        };
        let outcomes = bus.restart_from(snapshot, 0).await;
        assert!(outcomes.is_empty());
    }

    /// Task 17's original plan prose named "kill and restart the bus mid-delivery,
    /// assert at-least-once redelivery still holds" as the test to write. Having
    /// re-read every piece this crate would need to make that true, it currently
    /// cannot be honestly demonstrated as a property of `restart_from` itself —
    /// this test proves *why*, precisely, rather than asserting a green result that
    /// doesn't back the claim. See the sibling test below for the strongest honest
    /// claim this crate's current shape *does* support.
    ///
    /// The gap: `Mailbox` is a purely in-memory `VecDeque<Envelope>`;
    /// `RestartSnapshot` carries only `live_sessions: Vec<SessionId>` and
    /// `suspended_waits: Vec<SuspendedWait>` — no envelope payloads anywhere in it;
    /// and `InMemoryEventSink` (the idempotency ledger) is likewise in-memory-only,
    /// with a real, durable `SqliteEventSink` living in roundhouse-store, outside
    /// this crate. A genuine process restart constructs a brand-new `LocalBus`;
    /// `restart_from` re-registers mailboxes for `live_sessions` via
    /// `register_mailbox`, which creates them empty — there was never any old
    /// content for it to carry over. So a message already sitting, unconsumed, in a
    /// mailbox at crash time is simply gone after a real restart; nothing in this
    /// crate's current shape can make it survive.
    #[tokio::test]
    async fn restart_from_does_not_carry_mailbox_contents_across_a_real_process_restart() {
        let old_bus = LocalBus::new();
        let sender = SessionId::new();
        let recipient = SessionId::new();
        old_bus
            .register_mailbox(recipient, MailboxKind::Bounded(64))
            .await
            .unwrap();
        old_bus
            .send(crate::types::Envelope {
                id: crate::types::MessageId(uuid::Uuid::new_v4()),
                from: sender,
                to: recipient,
                to_requested: crate::types::Address::Session { id: recipient },
                subject: "s".into(),
                body: "accepted before the crash".into(),
                attachments: vec![],
                expect_reply: None,
                in_reply_to: None,
                ttl_hops: 8,
                provenance: crate::types::Provenance {
                    origin: roundhouse_core::Origin::Peer,
                    trust: crate::types::Trust::Untrusted,
                    task: None,
                },
            })
            .await
            .unwrap();

        // A genuine crash+restart: a brand-new `LocalBus`, seeded only from what
        // `RestartSnapshot` actually carries — not the old, populated one.
        let new_bus = LocalBus::new();
        let outcomes = new_bus
            .restart_from(
                RestartSnapshot {
                    live_sessions: vec![recipient],
                    suspended_waits: vec![],
                },
                0,
            )
            .await;

        assert!(outcomes.is_empty());
        assert!(new_bus.has_mailbox(recipient)); // re-registered...
        assert!(new_bus.poll(recipient).await.unwrap().is_none()); // ...but empty: the message did not survive.
    }

    /// The strongest honest claim this crate's current shape *does* support for
    /// recovery: `requeue` — which already bypasses idempotency/ttl/rate-cap/damper
    /// and pushes straight to a mailbox — is the primitive a daemon-side replay of
    /// roundhouse-store's durable event log would hand a message back through,
    /// *after* `restart_from` has re-registered the mailbox. `send` cannot be that
    /// primitive: `EventSink::record_inbound` fires on *accept*, not *consume*, so
    /// with a real durable sink a message accepted-but-unconsumed at crash time
    /// would look like a duplicate (`is_duplicate` == true) to a replay that went
    /// through `send`, and would be silently dropped exactly when it's needed most.
    ///
    /// What would have to change for Task 17's literal claim to become true:
    /// `RestartSnapshot` would need a per-session list of pending envelopes (or the
    /// daemon-assembly layer would need to own calling `requeue` once per persisted-
    /// but-unconsumed message after `restart_from` returns, sourced from
    /// roundhouse-store's event log) — neither of which exists in this crate today.
    #[tokio::test]
    async fn requeue_not_restart_from_is_the_shape_a_durable_replay_path_would_use() {
        let bus = LocalBus::new();
        let sender = SessionId::new();
        let recipient = SessionId::new();

        bus.restart_from(
            RestartSnapshot {
                live_sessions: vec![recipient],
                suspended_waits: vec![],
            },
            0,
        )
        .await;
        assert!(bus.has_mailbox(recipient));
        assert!(bus.poll(recipient).await.unwrap().is_none());

        // What a store-replay path would do next: hand a persisted, previously-
        // accepted envelope back in via `requeue`, not `send`.
        let replayed_id = crate::types::MessageId(uuid::Uuid::new_v4());
        bus.requeue(crate::types::Envelope {
            id: replayed_id,
            from: sender,
            to: recipient,
            to_requested: crate::types::Address::Session { id: recipient },
            subject: "s".into(),
            body: "replayed from the durable event log".into(),
            attachments: vec![],
            expect_reply: None,
            in_reply_to: None,
            ttl_hops: 8,
            provenance: crate::types::Provenance {
                origin: roundhouse_core::Origin::Peer,
                trust: crate::types::Trust::Untrusted,
                task: None,
            },
        })
        .await
        .unwrap();

        let delivered = bus.poll(recipient).await.unwrap().unwrap();
        assert_eq!(delivered.id, replayed_id);
    }
}
