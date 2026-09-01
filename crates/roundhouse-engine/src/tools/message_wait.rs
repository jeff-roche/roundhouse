//! `message_wait` tool executor (Task 13).

use roundhouse_bus::types::{BusError, Envelope, ExpectReply, MessageId, Quorum};
use roundhouse_bus::Bus;
use roundhouse_core::{Origin, SessionId, SuspendReason, TaskId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Not a Phase 0 core type. Phase 0 ships only `TaskRunner::record_*` (write-once event
/// logging) — no live per-task suspend/resume handle. This plan defines its own minimal
/// seam, local to this executor's only real consumer. `cancel` is added by Task 18
/// (G8's break-glass `cancel_task`/`kill_subtree`).
pub trait TaskHandle: Send + Sync {
    fn id(&self) -> TaskId;
    fn session(&self) -> SessionId;
    fn suspend(&self, reason: SuspendReason) -> Result<(), EngineError>;
    fn resume(&self, by: Origin, resolved: serde_json::Value) -> Result<(), EngineError>;
    fn cancel(&self, reason: roundhouse_core::CancelReason) -> Result<(), EngineError>;
}

#[derive(thiserror::Error, Debug)]
pub enum EngineError {
    #[error("session {0} has already ended")]
    SessionEnded(SessionId),
    #[error("task {0} is not in a suspendable state")]
    NotSuspendable(TaskId),
}

pub struct WaitOutcome {
    pub replies: Vec<Envelope>,
    pub timed_out: bool,
}

/// Phase 0's real `SuspendReason::AwaitingReply` carries no payload (§4.1). This
/// executor's own side table — keyed by `TaskId`, populated when a wait begins and
/// removed when it resolves/times out — is where `message_id`s/`quorum`/the fan-out
/// `targets` actually live while a wait is parked; nothing outside this executor needs
/// to read it.
struct PendingReply {
    #[allow(dead_code)]
    // read by future break-glass/inspection tooling (G8); not by this loop itself
    message_ids: Vec<MessageId>,
    #[allow(dead_code)]
    targets: Vec<SessionId>,
    #[allow(dead_code)]
    quorum: Quorum,
}

/// §8.11 describes one shared timer heap ("the same timer heap as triggers ... there is
/// exactly one scheduler in the system"), but that heap is a Phase 5/scheduling
/// deliverable Phase 4 has no access to. Rather than assume it, this executor
/// implements its own local, non-busy-spin deadline mechanism: a bounded sleep between
/// polls (never an immediate `yield_now()` re-spin, which is what an earlier draft did)
/// with an explicit deadline check each iteration. This is the more honest choice given
/// what Phase 4 actually has available — the loop below is a single, swappable seam if
/// a later phase wants to hand it the real shared heap instead.
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// §7.1 decision 3: "Request/reply is send + wait, not blocking RPC. The sender's task
/// parks in Suspended{AwaitingReply} — a first-class, inspectable, human-breakable
/// object." This executor reuses Phase 0/1's suspend/resume seam (via this plan's own
/// `TaskHandle`, above) — it does not invent a second suspension mechanism.
pub struct MessageWaitExecutor {
    bus: Arc<dyn Bus>,
    pending: Mutex<HashMap<TaskId, PendingReply>>,
}

impl MessageWaitExecutor {
    pub fn new(bus: Arc<dyn Bus>) -> Self {
        Self {
            bus,
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// `targets` are the resolved recipients of the `message_send` this wait blocks on
    /// (one for point-to-point, N for a `Team`/`Role` fan-out send, §7.5); `sent_ids`
    /// are the `MessageId`s `message_send`'s `SendOutcome` produced for them — a reply
    /// counts toward quorum iff its `in_reply_to` is one of them.
    ///
    /// §7.7's interlocking: registers a wait-graph edge against *every* target before
    /// parking, so a cycle through any one of them is refused synchronously — not just
    /// in tests that call `WaitGraph` directly (an earlier version of this executor
    /// never called `register_wait`/`clear_wait` at all). The edge(s) are cleared on
    /// every exit path — quorum met, deadline passed, or `task.suspend` reporting the
    /// session already ended — never left dangling.
    pub async fn wait(
        &self,
        task: Arc<dyn TaskHandle>,
        session: SessionId,
        targets: Vec<SessionId>,
        sent_ids: Vec<MessageId>,
        expect: ExpectReply,
    ) -> Result<WaitOutcome, BusError> {
        for &target in &targets {
            if let Err(e) = self.bus.register_wait(session, target).await {
                // Roll back before propagating — a partially-registered wait must not
                // linger in the graph. `clear_wait` removes every edge registered
                // under `session` in one call, so this is a full rollback, not partial.
                let _ = self.bus.clear_wait(session).await;
                return Err(e);
            }
        }

        self.pending
            .lock()
            .expect("pending-reply mutex poisoned")
            .insert(
                task.id(),
                PendingReply {
                    message_ids: sent_ids.clone(),
                    targets: targets.clone(),
                    quorum: expect.quorum,
                },
            );

        // §4.1: no payload on `AwaitingReply` — message_id/quorum/targets live in
        // `self.pending` (above), not in this enum variant.
        if task.suspend(SuspendReason::AwaitingReply).is_err() {
            self.pending
                .lock()
                .expect("pending-reply mutex poisoned")
                .remove(&task.id());
            let _ = self.bus.clear_wait(session).await;
            return Err(BusError::Undeliverable(
                roundhouse_bus::types::Undeliverable::Ended { session },
            ));
        }

        let needed = match expect.quorum {
            Quorum::Any => 1,
            // §7.3/§7.5: "All" now resolves against the real fan-out recipient count
            // this executor was given, completing the deferral this plan originally
            // flagged ("needs the caller to know roster size") — this executor is that
            // caller, and it now has real multi-recipient sends to resolve against.
            Quorum::All => targets.len().max(1) as u32,
            Quorum::AtLeast(n) => n,
        };

        // Which sender is expected to answer each outbound `MessageId`: a fan-out
        // send mints one id per recipient, so a reply counts toward quorum only if
        // it comes from the recipient that specific message was addressed to — a
        // forged reply from some other member (or a single member answering for the
        // whole team) must not satisfy `Quorum::All`.
        let expected_sender: HashMap<MessageId, SessionId> = sent_ids
            .iter()
            .copied()
            .zip(targets.iter().copied())
            .collect();

        let deadline = expect.deadline.map(unix_millis_to_instant);
        let mut replies = Vec::new();
        let timed_out = loop {
            if let Some(deadline) = deadline {
                if tokio::time::Instant::now() >= deadline {
                    break true;
                }
            }
            match self.bus.poll(session).await {
                Ok(Some(envelope))
                    if envelope
                        .in_reply_to
                        .map(|id| sent_ids.contains(&id))
                        .unwrap_or(false) =>
                {
                    if let Some(reply_to_id) = envelope.in_reply_to {
                        if expected_sender.get(&reply_to_id) == Some(&envelope.from) {
                            replies.push(envelope);
                            if replies.len() as u32 >= needed {
                                break false;
                            }
                        } else {
                            // Reply from the wrong sender — re-queue it rather than
                            // dropping it (it may still be a legitimate reply to
                            // some *other* wait on the same session), and sleep so a
                            // mailbox holding only non-matching messages can't
                            // busy-spin.
                            let _ = self.bus.requeue(envelope).await;
                            tokio::time::sleep(WAIT_POLL_INTERVAL).await;
                        }
                    }
                }
                Ok(Some(other)) => {
                    // A non-matching message (not an `in_reply_to` one of our sent
                    // ids) arrived while parked — re-queue so it isn't lost, then
                    // sleep to avoid busy-spin.
                    let _ = self.bus.requeue(other).await;
                    tokio::time::sleep(WAIT_POLL_INTERVAL).await;
                }
                Ok(None) => {
                    let sleep_for = match deadline {
                        Some(d) => d
                            .saturating_duration_since(tokio::time::Instant::now())
                            .min(WAIT_POLL_INTERVAL),
                        None => WAIT_POLL_INTERVAL,
                    };
                    tokio::time::sleep(sleep_for).await;
                }
                Err(e) => {
                    // A poll error is a hard exit, not a retry: clear the wait-graph
                    // edge and the pending-reply entry, resume the task with a
                    // `poll_failed` error frame, and propagate. Without this cleanup
                    // the edge would linger (a later wait would report a phantom
                    // deadlock) and `pending` would leak a stale entry.
                    let _ = self.bus.clear_wait(session).await;
                    self.pending
                        .lock()
                        .expect("pending-reply mutex poisoned")
                        .remove(&task.id());
                    let _ = task.resume(
                        Origin::System,
                        serde_json::json!({ "error": "poll_failed" }),
                    );
                    return Err(e);
                }
            }
        };

        // Clear the wait-graph edge and the pending-reply entry on every exit path —
        // success or timeout. (A human break-glass `release`, §7.7/G8, drives this
        // same pair of calls from outside this loop — see the break-glass task.)
        let _ = self.bus.clear_wait(session).await;
        self.pending
            .lock()
            .expect("pending-reply mutex poisoned")
            .remove(&task.id());

        let outcome = WaitOutcome { replies, timed_out };
        task.resume(
            Origin::Peer,
            serde_json::json!({ "replies": outcome.replies.len(), "timed_out": outcome.timed_out }),
        )
        .map_err(|_| {
            BusError::Undeliverable(roundhouse_bus::types::Undeliverable::Ended { session })
        })?;

        Ok(outcome)
    }
}

fn unix_millis_to_instant(deadline_ms: i64) -> tokio::time::Instant {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let remaining_ms = (deadline_ms - now_ms).max(0) as u64;
    tokio::time::Instant::now() + Duration::from_millis(remaining_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use roundhouse_bus::local_bus::LocalBus;
    use roundhouse_bus::mailbox::MailboxKind;
    use roundhouse_bus::teams::TeamRegistry;
    use roundhouse_bus::types::{
        Address, Envelope, ExpectReply, MessageId, Provenance, Quorum, Trust,
    };
    use roundhouse_core::{Origin, SessionId, TaskId, WorkspaceId};
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    struct FakeTaskHandle {
        id: TaskId,
        session: SessionId,
        suspended: Mutex<Option<roundhouse_core::SuspendReason>>,
        resumed: Mutex<Option<serde_json::Value>>,
        // Added by Task 18 (G8 break-glass): `cancel_task`/`kill_subtree` call
        // `TaskHandle::cancel`, so every `TaskHandle` implementor — including this
        // test double — needs it.
        cancelled: Mutex<Option<roundhouse_core::CancelReason>>,
    }

    impl TaskHandle for FakeTaskHandle {
        fn id(&self) -> TaskId {
            self.id
        }
        fn session(&self) -> SessionId {
            self.session
        }
        fn suspend(&self, reason: roundhouse_core::SuspendReason) -> Result<(), EngineError> {
            *self.suspended.lock().unwrap() = Some(reason);
            Ok(())
        }
        fn resume(&self, _by: Origin, resolved: serde_json::Value) -> Result<(), EngineError> {
            *self.resumed.lock().unwrap() = Some(resolved);
            Ok(())
        }
        fn cancel(&self, reason: roundhouse_core::CancelReason) -> Result<(), EngineError> {
            *self.cancelled.lock().unwrap() = Some(reason);
            Ok(())
        }
    }

    fn reply_envelope(
        from: SessionId,
        to: SessionId,
        in_reply_to: MessageId,
        body: &str,
    ) -> Envelope {
        Envelope {
            id: MessageId(Uuid::new_v4()),
            from,
            to,
            to_requested: Address::Session { id: to },
            subject: "re: question".into(),
            body: body.into(),
            attachments: vec![],
            expect_reply: None,
            in_reply_to: Some(in_reply_to),
            ttl_hops: 8,
            provenance: Provenance {
                origin: Origin::Peer,
                trust: Trust::Untrusted,
                task: None,
            },
        }
    }

    #[tokio::test]
    async fn quorum_any_resolves_on_first_reply_leaving_task_suspended_state_recorded() {
        let bus: Arc<dyn roundhouse_bus::Bus> = Arc::new(LocalBus::new());
        let waiter = SessionId::new();
        let peer = SessionId::new();
        bus.register_mailbox(waiter, MailboxKind::Bounded(64))
            .await
            .unwrap();
        bus.register_mailbox(peer, MailboxKind::Bounded(64))
            .await
            .unwrap();

        let task = Arc::new(FakeTaskHandle {
            id: TaskId::new(),
            session: waiter,
            suspended: Mutex::new(None),
            resumed: Mutex::new(None),
            cancelled: Mutex::new(None),
        });

        let sent_id = MessageId(Uuid::new_v4());
        // Simulate a reply already sitting in waiter's mailbox (peer replied fast).
        bus.send(reply_envelope(peer, waiter, sent_id, "42"))
            .await
            .unwrap();

        let executor = MessageWaitExecutor::new(bus.clone());
        let outcome = executor
            .wait(
                task.clone(),
                waiter,
                vec![peer],
                vec![sent_id],
                ExpectReply {
                    quorum: Quorum::Any,
                    deadline: None,
                },
            )
            .await
            .unwrap();

        assert_eq!(outcome.replies.len(), 1);
        assert_eq!(outcome.replies[0].body, "42");
        assert!(!outcome.timed_out);
        // §7.6: a reply arriving while parked renders as the tool_result of the pending
        // call — the resume path carries the reply payload, not a synthetic user turn.
        assert!(task.resumed.lock().unwrap().is_some());
    }

    #[tokio::test]
    async fn wait_registers_a_deadlock_edge_through_the_real_call_path_and_clears_it_after() {
        // §7.7: an earlier version of this executor never called
        // `register_wait`/`clear_wait` at all, so the deadlock guard only ever fired in
        // `roundhouse-bus`'s own unit tests that called `WaitGraph` directly. This test
        // drives the guard through `MessageWaitExecutor::wait` itself: while `a`'s wait
        // on `b` is live, `b` waiting on `a` must be refused as a cycle; once `a`'s wait
        // resolves, the edge is cleared and the same registration succeeds.
        let bus: Arc<dyn roundhouse_bus::Bus> = Arc::new(LocalBus::new());
        let a = SessionId::new();
        let b = SessionId::new();
        bus.register_mailbox(a, MailboxKind::Bounded(64))
            .await
            .unwrap();
        bus.register_mailbox(b, MailboxKind::Bounded(64))
            .await
            .unwrap();

        let task_a = Arc::new(FakeTaskHandle {
            id: TaskId::new(),
            session: a,
            suspended: Mutex::new(None),
            resumed: Mutex::new(None),
            cancelled: Mutex::new(None),
        });
        let executor = Arc::new(MessageWaitExecutor::new(bus.clone()));
        let sent_id = MessageId(Uuid::new_v4());

        let wait_handle = {
            let executor = executor.clone();
            tokio::spawn(async move {
                executor
                    .wait(
                        task_a,
                        a,
                        vec![b],
                        vec![sent_id],
                        ExpectReply {
                            quorum: Quorum::Any,
                            deadline: None,
                        },
                    )
                    .await
            })
        };

        // Give the spawned wait a moment to register its edge before probing it.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let err = bus.register_wait(b, a).await.unwrap_err();
        assert!(matches!(
            err,
            roundhouse_bus::types::BusError::WaitWouldDeadlock { .. }
        ));

        // Now b replies, a's wait resolves, and the edge is cleared.
        bus.send(reply_envelope(b, a, sent_id, "ok")).await.unwrap();

        let outcome = wait_handle.await.unwrap().unwrap();
        assert!(!outcome.timed_out);
        assert!(bus.register_wait(b, a).await.is_ok());
    }

    async fn three_member_team_with_registered_mailboxes() -> (
        Arc<dyn roundhouse_bus::Bus>,
        roundhouse_core::TeamId,
        WorkspaceId,
        SessionId,
        SessionId,
        SessionId,
        SessionId,
    ) {
        let local = LocalBus::new();
        let teams = Arc::new(TeamRegistry::new());
        let ws = WorkspaceId::new();
        let lead = SessionId::new();
        let team = teams
            .create_team(ws, "t".into(), "c".into(), lead, "lead".into())
            .unwrap();
        let m2 = SessionId::new();
        let m3 = SessionId::new();
        teams.join(team, m2, None).unwrap();
        teams.join(team, m3, None).unwrap();
        for &member in &[lead, m2, m3] {
            local
                .register_mailbox(member, MailboxKind::Bounded(64))
                .await
                .unwrap();
        }
        let asker = SessionId::new();
        local
            .register_mailbox(asker, MailboxKind::Bounded(64))
            .await
            .unwrap();
        let bus: Arc<dyn roundhouse_bus::Bus> = Arc::new(local.with_teams(teams));
        (bus, team, ws, asker, lead, m2, m3)
    }

    #[tokio::test]
    async fn fan_out_to_team_address_delivers_one_message_task_per_member() {
        let (bus, team, ws, asker, lead, m2, m3) =
            three_member_team_with_registered_mailboxes().await;

        let sent = crate::tools::message_send::message_send(
            bus.as_ref(),
            ws,
            asker,
            Address::Team { team },
            "status?".into(),
            "all good?".into(),
            vec![],
            Some(ExpectReply {
                quorum: Quorum::All,
                deadline: None,
            }),
            8,
        )
        .await
        .unwrap();

        // §7.1: "no envelope fan-out shortcut" — every recipient gets its own outbound
        // message task, so there are as many distinct MessageIds as recipients.
        assert_eq!(sent.recipients.len(), 3);
        assert_eq!(sent.message_ids.len(), 3);
        for &member in &[lead, m2, m3] {
            assert!(sent.recipients.contains(&member));
            assert!(bus.poll(member).await.unwrap().is_some());
        }
    }

    #[tokio::test]
    async fn quorum_all_unblocks_only_once_every_fanout_recipient_has_replied() {
        let (bus, team, ws, asker, lead, m2, m3) =
            three_member_team_with_registered_mailboxes().await;

        let sent = crate::tools::message_send::message_send(
            bus.as_ref(),
            ws,
            asker,
            Address::Team { team },
            "status?".into(),
            "all good?".into(),
            vec![],
            Some(ExpectReply {
                quorum: Quorum::All,
                deadline: None,
            }),
            8,
        )
        .await
        .unwrap();
        let id_by_recipient: std::collections::HashMap<SessionId, MessageId> = sent
            .recipients
            .iter()
            .copied()
            .zip(sent.message_ids.iter().copied())
            .collect();

        for &member in &[lead, m2, m3] {
            bus.send(reply_envelope(
                member,
                asker,
                id_by_recipient[&member],
                "yes",
            ))
            .await
            .unwrap();
        }

        let task = Arc::new(FakeTaskHandle {
            id: TaskId::new(),
            session: asker,
            suspended: Mutex::new(None),
            resumed: Mutex::new(None),
            cancelled: Mutex::new(None),
        });
        let executor = MessageWaitExecutor::new(bus.clone());
        let outcome = executor
            .wait(
                task,
                asker,
                sent.recipients.clone(),
                sent.message_ids.clone(),
                ExpectReply {
                    quorum: Quorum::All,
                    deadline: None,
                },
            )
            .await
            .unwrap();

        assert!(!outcome.timed_out);
        assert_eq!(outcome.replies.len(), 3);
    }

    #[tokio::test]
    async fn quorum_all_times_out_when_not_every_fanout_recipient_has_replied() {
        let (bus, team, ws, asker, lead, m2, _m3) =
            three_member_team_with_registered_mailboxes().await;

        let sent = crate::tools::message_send::message_send(
            bus.as_ref(),
            ws,
            asker,
            Address::Team { team },
            "status?".into(),
            "all good?".into(),
            vec![],
            Some(ExpectReply {
                quorum: Quorum::All,
                deadline: None,
            }),
            8,
        )
        .await
        .unwrap();
        let id_by_recipient: std::collections::HashMap<SessionId, MessageId> = sent
            .recipients
            .iter()
            .copied()
            .zip(sent.message_ids.iter().copied())
            .collect();

        // Only 2 of 3 reply — quorum: All must NOT unblock early on 2 when the fan-out
        // went to 3, so this must run out the clock rather than resolve.
        for &member in &[lead, m2] {
            bus.send(reply_envelope(
                member,
                asker,
                id_by_recipient[&member],
                "yes",
            ))
            .await
            .unwrap();
        }

        let deadline_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
            + 100;
        let task = Arc::new(FakeTaskHandle {
            id: TaskId::new(),
            session: asker,
            suspended: Mutex::new(None),
            resumed: Mutex::new(None),
            cancelled: Mutex::new(None),
        });
        let executor = MessageWaitExecutor::new(bus.clone());
        let outcome = executor
            .wait(
                task,
                asker,
                sent.recipients.clone(),
                sent.message_ids.clone(),
                ExpectReply {
                    quorum: Quorum::All,
                    deadline: Some(deadline_ms),
                },
            )
            .await
            .unwrap();

        assert!(outcome.timed_out);
        assert_eq!(outcome.replies.len(), 2);
    }

    #[tokio::test]
    async fn quorum_all_rejects_forged_replies_from_single_sender() {
        let (bus, team, ws, asker, lead, _m2, _m3) =
            three_member_team_with_registered_mailboxes().await;

        let sent = crate::tools::message_send::message_send(
            bus.as_ref(),
            ws,
            asker,
            Address::Team { team },
            "status?".into(),
            "all good?".into(),
            vec![],
            Some(ExpectReply {
                quorum: Quorum::All,
                deadline: None,
            }),
            8,
        )
        .await
        .unwrap();

        // Only lead replies, but sends 3 replies with different in_reply_to values
        // (forging the other members' responses)
        for &msg_id in &sent.message_ids {
            bus.send(reply_envelope(lead, asker, msg_id, "yes"))
                .await
                .unwrap();
        }

        let deadline_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
            + 200;
        let task = Arc::new(FakeTaskHandle {
            id: TaskId::new(),
            session: asker,
            suspended: Mutex::new(None),
            resumed: Mutex::new(None),
            cancelled: Mutex::new(None),
        });
        let executor = MessageWaitExecutor::new(bus.clone());
        let outcome = executor
            .wait(
                task,
                asker,
                sent.recipients.clone(),
                sent.message_ids.clone(),
                ExpectReply {
                    quorum: Quorum::All,
                    deadline: Some(deadline_ms),
                },
            )
            .await
            .unwrap();

        // Only 1 of 3 accepted (from lead for lead's message_id); the other 2 are
        // rejected because lead != expected sender for those message_ids.
        assert!(outcome.timed_out);
        assert_eq!(outcome.replies.len(), 1);
    }
}
