use crate::tools::message_wait::{EngineError, MessageWaitExecutor, TaskHandle};
use roundhouse_bus::spawn_tree::SpawnTree;
use roundhouse_bus::types::{Address, BusError, Envelope, MessageId, Provenance, Trust};
use roundhouse_bus::Bus;
use roundhouse_core::{CancelReason, Origin, SessionId, TaskId};
use std::sync::Arc;
use uuid::Uuid;

/// §7.7 break-glass 1/4: "answer as peer (injected reply, clearly marked in
/// provenance, not the peer's)." Delivered exactly like a real peer reply — same
/// mailbox, same `in_reply_to` matching `MessageWaitExecutor::wait` already does — the
/// only difference is `provenance.origin: Origin::User`, never `Origin::Peer`, so
/// nothing downstream (audit log, `render_inbound`, Task 14) can mistake this for the
/// peer's own words.
pub async fn answer_as_peer(
    bus: &dyn Bus,
    waiting_session: SessionId,
    in_reply_to: MessageId,
    body: String,
    human: SessionId,
) -> Result<(), BusError> {
    bus.send(Envelope {
        id: MessageId(Uuid::new_v4()),
        from: human,
        to: waiting_session,
        to_requested: Address::Session {
            id: waiting_session,
        },
        subject: "[human override] answer as peer".into(),
        body,
        attachments: vec![],
        expect_reply: None,
        in_reply_to: Some(in_reply_to),
        ttl_hops: 8,
        // §7.7: "clearly marked in provenance" — Trust::Trusted too, since this is
        // genuinely the human speaking, unlike an ordinary peer message (§6.8).
        provenance: Provenance {
            origin: Origin::User,
            trust: Trust::Trusted,
            task: None,
        },
    })
    .await
}

/// §7.7 break-glass 2/4: "release (unblock as TimedOut)." A thin, documented wrapper
/// over `MessageWaitExecutor::mark_released` — kept as its own free function so the
/// four break-glass operations have one obvious, uniformly-named call site each.
pub fn release(executor: &MessageWaitExecutor, task_id: TaskId) {
    executor.mark_released(task_id);
}

/// §7.7 break-glass 3/4: "cancel task."
pub fn cancel_task(task: &dyn TaskHandle) -> Result<(), EngineError> {
    task.cancel(CancelReason::User)
}

/// §7.7 break-glass 4/4: "kill subtree" — cancels `root` and every session in its
/// `SpawnTree` subtree. `resolve` maps a `SessionId` to its current `TaskHandle`, if
/// it still has one live (a daemon-runtime concern this plan doesn't otherwise model
/// as a static registry) — sessions that no longer resolve to a handle (already ended)
/// are skipped, not treated as an error. Returns every session actually cancelled, for
/// the caller's audit trail.
pub fn kill_subtree(
    tree: &SpawnTree,
    root: SessionId,
    resolve: &dyn Fn(SessionId) -> Option<Arc<dyn TaskHandle>>,
) -> Vec<SessionId> {
    let mut targets = tree.descendants(root);
    targets.push(root);

    let mut cancelled = Vec::new();
    for session in targets {
        if let Some(handle) = resolve(session) {
            if handle.cancel(CancelReason::User).is_ok() {
                cancelled.push(session);
            }
        }
    }
    cancelled
}

#[cfg(test)]
mod tests {
    use super::*;
    use roundhouse_bus::local_bus::LocalBus;
    use roundhouse_bus::mailbox::MailboxKind;
    use roundhouse_bus::spawn_tree::SpawnTree;
    use roundhouse_bus::types::{ExpectReply, MessageId, Quorum};
    use roundhouse_core::{CancelReason, Origin, SessionId, TaskId};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    struct FakeTaskHandle {
        id: TaskId,
        session: SessionId,
        cancelled: Mutex<Option<CancelReason>>,
    }

    impl crate::tools::message_wait::TaskHandle for FakeTaskHandle {
        fn id(&self) -> TaskId {
            self.id
        }
        fn session(&self) -> SessionId {
            self.session
        }
        fn suspend(
            &self,
            _reason: roundhouse_core::SuspendReason,
        ) -> Result<(), crate::tools::message_wait::EngineError> {
            Ok(())
        }
        fn resume(
            &self,
            _by: Origin,
            _resolved: serde_json::Value,
        ) -> Result<(), crate::tools::message_wait::EngineError> {
            Ok(())
        }
        fn cancel(
            &self,
            reason: CancelReason,
        ) -> Result<(), crate::tools::message_wait::EngineError> {
            *self.cancelled.lock().unwrap() = Some(reason);
            Ok(())
        }
    }

    #[tokio::test]
    async fn answer_as_peer_injects_a_reply_marked_human_not_the_peer() {
        let bus: Arc<dyn roundhouse_bus::Bus> = Arc::new(LocalBus::new());
        let waiting = SessionId::new();
        let human = SessionId::new();
        bus.register_mailbox(waiting, MailboxKind::Bounded(64))
            .await
            .unwrap();
        let pending_id = MessageId(Uuid::new_v4());

        answer_as_peer(
            bus.as_ref(),
            waiting,
            pending_id,
            "yes, proceed".into(),
            human,
        )
        .await
        .unwrap();

        let injected = bus.poll(waiting).await.unwrap().unwrap();
        assert_eq!(injected.in_reply_to, Some(pending_id));
        assert_eq!(injected.body, "yes, proceed");
        // §7.7: "clearly marked in provenance" — Origin::User, never Origin::Peer,
        // distinguishes a human override from the peer it stands in for.
        assert_eq!(injected.provenance.origin, Origin::User);
        assert_eq!(injected.from, human);
    }

    #[tokio::test]
    async fn answer_as_peer_resolves_a_live_wait_on_an_agent_peer() {
        let bus: Arc<dyn roundhouse_bus::Bus> = Arc::new(LocalBus::new());
        let waiter = SessionId::new();
        let peer = SessionId::new();
        let human = SessionId::new();
        bus.register_mailbox(waiter, MailboxKind::Bounded(64))
            .await
            .unwrap();
        bus.register_mailbox(peer, MailboxKind::Bounded(64))
            .await
            .unwrap();

        let task = Arc::new(FakeTaskHandle {
            id: TaskId::new(),
            session: waiter,
            cancelled: Mutex::new(None),
        });
        let executor = Arc::new(crate::tools::message_wait::MessageWaitExecutor::new(
            bus.clone(),
        ));
        let sent_id = MessageId(Uuid::new_v4());

        let wait_handle = {
            let executor = executor.clone();
            let task: Arc<dyn crate::tools::message_wait::TaskHandle> = task;
            tokio::spawn(async move {
                executor
                    .wait(
                        task,
                        waiter,
                        vec![peer],
                        vec![sent_id],
                        ExpectReply {
                            quorum: Quorum::Any,
                            deadline: None,
                        },
                    )
                    .await
            })
        };

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        answer_as_peer(
            bus.as_ref(),
            waiter,
            sent_id,
            "human override".into(),
            human,
        )
        .await
        .unwrap();

        let outcome = wait_handle.await.unwrap().unwrap();
        assert!(!outcome.timed_out);
        assert_eq!(outcome.replies.len(), 1);
        assert_eq!(outcome.replies[0].body, "human override");
        assert_eq!(outcome.replies[0].provenance.origin, Origin::User);
    }

    #[tokio::test]
    async fn release_unblocks_a_live_parked_wait_as_timed_out() {
        let bus: Arc<dyn roundhouse_bus::Bus> = Arc::new(LocalBus::new());
        let a = SessionId::new();
        let b = SessionId::new();
        bus.register_mailbox(a, MailboxKind::Bounded(64))
            .await
            .unwrap();
        bus.register_mailbox(b, MailboxKind::Bounded(64))
            .await
            .unwrap();

        let task = Arc::new(FakeTaskHandle {
            id: TaskId::new(),
            session: a,
            cancelled: Mutex::new(None),
        });
        let executor = Arc::new(crate::tools::message_wait::MessageWaitExecutor::new(
            bus.clone(),
        ));
        let task_id = task.id();

        let wait_handle = {
            let executor = executor.clone();
            let task: Arc<dyn crate::tools::message_wait::TaskHandle> = task;
            tokio::spawn(async move {
                executor
                    .wait(
                        task,
                        a,
                        vec![b],
                        vec![MessageId(Uuid::new_v4())],
                        ExpectReply {
                            quorum: Quorum::Any,
                            deadline: None,
                        },
                    )
                    .await
            })
        };

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        // Nobody ever replies and there is no deadline — without `release`, this wait
        // would park forever.
        release(&executor, task_id);

        let outcome = wait_handle.await.unwrap().unwrap();
        assert!(outcome.timed_out);
        assert!(outcome.replies.is_empty());
    }

    #[test]
    fn cancel_task_calls_through_to_the_task_handle() {
        let task = FakeTaskHandle {
            id: TaskId::new(),
            session: SessionId::new(),
            cancelled: Mutex::new(None),
        };
        cancel_task(&task).unwrap();
        // Phase 0's `CancelReason` derives `Debug`/`Clone` but not `PartialEq`
        // (`docs/superpowers/plans/2026-08-27-phase0-contracts.md`), so `matches!`
        // rather than `assert_eq!` is the correct comparison here.
        assert!(matches!(
            *task.cancelled.lock().unwrap(),
            Some(CancelReason::User)
        ));
    }

    #[test]
    fn kill_subtree_cancels_the_root_and_every_descendant_but_nothing_else() {
        let tree = SpawnTree::new();
        let root = SessionId::new();
        let child = SessionId::new();
        let grandchild = SessionId::new();
        let unrelated = SessionId::new();
        tree.record_child(root, child);
        tree.record_child(child, grandchild);

        let handles: HashMap<SessionId, Arc<FakeTaskHandle>> = [root, child, grandchild, unrelated]
            .into_iter()
            .map(|s| {
                (
                    s,
                    Arc::new(FakeTaskHandle {
                        id: TaskId::new(),
                        session: s,
                        cancelled: Mutex::new(None),
                    }),
                )
            })
            .collect();

        let cancelled = kill_subtree(&tree, root, &|s| {
            handles
                .get(&s)
                .map(|h| h.clone() as Arc<dyn crate::tools::message_wait::TaskHandle>)
        });

        assert_eq!(cancelled.len(), 3); // root + child + grandchild, not the unrelated session
        assert!(
            cancelled.contains(&root)
                && cancelled.contains(&child)
                && cancelled.contains(&grandchild)
        );
        for s in [root, child, grandchild] {
            // `matches!`, not `assert_eq!` — `CancelReason` has no `PartialEq` (Phase
            // 0's real derive list is `Debug, Clone, Serialize, Deserialize` only).
            assert!(matches!(
                *handles[&s].cancelled.lock().unwrap(),
                Some(CancelReason::User)
            ));
        }
        assert!(handles[&unrelated].cancelled.lock().unwrap().is_none());
    }
}
