use crate::bus_trait::Bus;
use crate::event_sink::{EventSink, InMemoryEventSink};
use crate::handle_registry::HandleRegistry;
use crate::human_notifications::{HumanNotification, HumanNotificationRegistry};
use crate::mailbox::{Mailbox, MailboxKind};
use crate::rate_limit::{decrement_ttl, RateLimiter, RepetitionDamper};
use crate::teams::{TeamRegistry, TeamState};
use crate::types::{Address, BusError, Envelope, Undeliverable};
use crate::wait_graph::WaitGraph;
use async_trait::async_trait;
use dashmap::{DashMap, DashSet};
use roundhouse_core::{SessionId, WorkspaceId};
use std::sync::{Arc, Mutex};

/// §7.8: "A routed mpsc registry (LocalBus with DashMap of mailboxes, handles, teams,
/// plus the wait graph and the shared DB writer)."
pub struct LocalBus {
    pub(crate) mailboxes: DashMap<SessionId, Mutex<Mailbox>>,
    pub(crate) handles: HandleRegistry,
    pub(crate) wait_graph: Mutex<WaitGraph>,
    pub(crate) sink: Arc<dyn EventSink>,
    pub(crate) human_sessions: DashSet<SessionId>,
    pub(crate) human_notifications: HumanNotificationRegistry,
    pub(crate) teams: Arc<TeamRegistry>,
    pub(crate) rate_limiter: RateLimiter,
    pub(crate) damper: Mutex<RepetitionDamper>,
}

impl LocalBus {
    pub fn new() -> Self {
        Self {
            mailboxes: DashMap::new(),
            handles: HandleRegistry::new(),
            wait_graph: Mutex::new(WaitGraph::new()),
            sink: Arc::new(InMemoryEventSink::new()),
            human_sessions: DashSet::new(),
            human_notifications: HumanNotificationRegistry::new(),
            teams: Arc::new(TeamRegistry::new()),
            rate_limiter: RateLimiter::default(),
            damper: Mutex::new(RepetitionDamper::default()),
        }
    }

    /// Marks `session` as a human recipient: it never gets a `Mailbox` — `send`
    /// (below) routes anything addressed to it into `human_notifications` instead.
    /// Distinct from `register_mailbox` on purpose (§7.2's split delivery mechanism).
    pub fn register_human(&self, session: SessionId) {
        self.human_sessions.insert(session);
    }

    pub fn list_human_notifications(&self, session: SessionId) -> Vec<HumanNotification> {
        self.human_notifications.list(session)
    }

    pub fn drain_human_notifications(&self, session: SessionId) -> Vec<HumanNotification> {
        self.human_notifications.drain(session)
    }

    pub fn with_sink(mut self, sink: Arc<dyn EventSink>) -> Self {
        self.sink = sink;
        self
    }

    /// Shares one `TeamRegistry` between the `Bus` (for fan-out resolution) and
    /// whatever else holds it (e.g. `agent_spawn`/`team_create`, Tasks 15-16) — those
    /// call sites take `&TeamRegistry` directly, so callers pass the same `Arc` both
    /// places rather than the `Bus` and the rest of the daemon silently disagreeing
    /// about team membership.
    pub fn with_teams(mut self, teams: Arc<TeamRegistry>) -> Self {
        self.teams = teams;
        self
    }

    pub async fn register_mailbox(
        &self,
        session: SessionId,
        kind: MailboxKind,
    ) -> Result<(), BusError> {
        self.mailboxes
            .entry(session)
            .or_insert_with(|| Mutex::new(Mailbox::new(kind)));
        Ok(())
    }

    pub async fn deregister_mailbox(&self, session: SessionId) -> Result<(), BusError> {
        self.mailboxes.remove(&session);
        Ok(())
    }

    pub fn has_mailbox(&self, session: SessionId) -> bool {
        self.mailboxes.contains_key(&session)
    }

    /// §7.2/§7.5: the fan-out expansion Task 2's `HandleRegistry::resolve_address`
    /// explicitly defers to this layer.
    pub async fn resolve_recipients(
        &self,
        workspace: WorkspaceId,
        addr: &Address,
    ) -> Result<Vec<SessionId>, BusError> {
        match addr {
            Address::Team { team } => {
                if let Some(state) = self.teams.state(*team) {
                    if state == TeamState::Draining || state == TeamState::Closed {
                        return Err(BusError::TeamDraining { team: *team });
                    }
                }
                let roster = self
                    .teams
                    .roster(*team)
                    .ok_or_else(|| BusError::UnknownHandle {
                        workspace,
                        name: "<unknown team>".into(),
                    })?;
                Ok(roster
                    .into_iter()
                    .filter(|m| !m.ended)
                    .map(|m| m.session)
                    .collect())
            }
            Address::Role { team, role } => {
                if let Some(state) = self.teams.state(*team) {
                    if state == TeamState::Draining || state == TeamState::Closed {
                        return Err(BusError::TeamDraining { team: *team });
                    }
                }
                let roster = self
                    .teams
                    .roster(*team)
                    .ok_or_else(|| BusError::UnknownHandle {
                        workspace,
                        name: "<unknown team>".into(),
                    })?;
                Ok(roster
                    .into_iter()
                    .filter(|m| !m.ended && &m.role == role)
                    .map(|m| m.session)
                    .collect())
            }
            other => self
                .handles
                .resolve_address(workspace, other)
                .map(|id| vec![id]),
        }
    }

    /// §7.4: "FIFO per (sender, recipient) pair." A per-recipient VecDeque already
    /// gives FIFO for everything landing in that mailbox; because sends from a given
    /// sender are pushed in the order `send` is awaited (single mailbox lock per push),
    /// each (sender, recipient) sub-sequence within that queue is preserved without
    /// needing a separate index.
    ///
    /// §7.7: rate cap, repetition damper, and `ttl_hops` decrement, all checked before
    /// the message is queued — uniformly, regardless of whether the recipient is an
    /// ordinary session or a registered human (a spamming session shouldn't get to
    /// flood a human's notification feed either). Task 10 built and unit-tested all
    /// three in isolation; this is the first place anything actually calls them, which
    /// is exactly why `BusError::RateLimited`/`Repetitive`/`TtlExpired` were
    /// unreachable before this task (see `send_wiring_tests`, which exercises this
    /// through `send` itself rather than the isolated `rate_limit` functions).
    /// After those checks, human recipients (§7.2/Task 6) route to
    /// `human_notifications` instead of a `Mailbox` — checked *before* the mailbox
    /// lookup, since a human session never has one.
    pub async fn send(&self, envelope: Envelope) -> Result<(), BusError> {
        let to = envelope.to;
        let msg_id = envelope.id;

        let ttl_hops = decrement_ttl(envelope.ttl_hops)?;
        self.rate_limiter
            .try_acquire(envelope.from, std::time::Instant::now())?;
        {
            let mut damper = self
                .damper
                .lock()
                .expect("repetition damper mutex poisoned");
            damper.check_and_record(envelope.from, to, &envelope.subject)?;
        }

        let mut envelope = envelope;
        envelope.ttl_hops = ttl_hops;

        // §7.2: human recipients bypass the ordinary mailbox path entirely — no
        // capacity check, no idempotency/redelivery bookkeeping (a UI notification
        // feed has no "effectively-once observation" contract the way a Task-injected
        // reply does), just a durable, listable/drainable notification.
        if self.human_sessions.contains(&to) {
            self.human_notifications.push(
                to,
                HumanNotification {
                    from: envelope.from,
                    envelope,
                    ts_unix_ms: current_unix_millis(),
                },
            );
            return Ok(());
        }

        let mailbox =
            self.mailboxes
                .get(&to)
                .ok_or(BusError::Undeliverable(Undeliverable::Ended {
                    session: to,
                }))?;

        let mut guard = mailbox.lock().expect("mailbox mutex poisoned");

        if self.sink.is_duplicate(to, msg_id) {
            tracing::debug!(?to, msg_id = ?msg_id, "duplicate inbound message, dropped as idempotent redelivery");
            return Ok(());
        }

        guard.push(to, envelope)?;
        self.sink.record_inbound(to, msg_id);
        Ok(())
    }

    pub async fn poll(&self, session: SessionId) -> Result<Option<Envelope>, BusError> {
        let mailbox = self
            .mailboxes
            .get(&session)
            .ok_or(BusError::Undeliverable(Undeliverable::Ended { session }))?;
        let mut guard = mailbox.lock().expect("mailbox mutex poisoned");
        Ok(guard.pop_front())
    }

    /// Re-queue an envelope that was popped from a mailbox but not consumed (e.g. a
    /// non-matching reply during a quorum wait). Unlike `send`, this does not run the
    /// idempotency sink, ttl_hops decrement, rate cap, or repetition damper — the
    /// envelope is already in flight and was merely parked in the wrong place, so
    /// re-applying those checks would silently drop it (the sink would reject it as a
    /// duplicate). Pushes directly back to the mailbox (or a human's notification feed).
    pub async fn requeue(&self, envelope: Envelope) -> Result<(), BusError> {
        let to = envelope.to;
        if self.human_sessions.contains(&to) {
            self.human_notifications.push(
                to,
                HumanNotification {
                    from: envelope.from,
                    envelope,
                    ts_unix_ms: current_unix_millis(),
                },
            );
            return Ok(());
        }
        let mailbox =
            self.mailboxes
                .get(&to)
                .ok_or(BusError::Undeliverable(Undeliverable::Ended {
                    session: to,
                }))?;
        let mut guard = mailbox.lock().expect("mailbox mutex poisoned");
        guard.push_front(to, envelope)
    }
}

#[async_trait]
impl Bus for LocalBus {
    async fn send(&self, envelope: Envelope) -> Result<(), BusError> {
        LocalBus::send(self, envelope).await
    }

    async fn poll(&self, session: SessionId) -> Result<Option<Envelope>, BusError> {
        LocalBus::poll(self, session).await
    }

    async fn register_mailbox(
        &self,
        session: SessionId,
        kind: MailboxKind,
    ) -> Result<(), BusError> {
        LocalBus::register_mailbox(self, session, kind).await
    }

    async fn deregister_mailbox(&self, session: SessionId) -> Result<(), BusError> {
        LocalBus::deregister_mailbox(self, session).await
    }

    async fn register_wait(&self, waiter: SessionId, target: SessionId) -> Result<(), BusError> {
        let mut wg = self.wait_graph.lock().expect("wait graph mutex poisoned");
        wg.register_wait(waiter, target)
    }

    async fn clear_wait(&self, waiter: SessionId) -> Result<(), BusError> {
        let mut wg = self.wait_graph.lock().expect("wait graph mutex poisoned");
        wg.clear_wait(waiter);
        Ok(())
    }

    async fn resolve_address(
        &self,
        workspace: WorkspaceId,
        addr: &Address,
    ) -> Result<SessionId, BusError> {
        self.handles.resolve_address(workspace, addr)
    }

    async fn resolve_recipients(
        &self,
        workspace: WorkspaceId,
        addr: &Address,
    ) -> Result<Vec<SessionId>, BusError> {
        LocalBus::resolve_recipients(self, workspace, addr).await
    }

    async fn requeue(&self, envelope: Envelope) -> Result<(), BusError> {
        LocalBus::requeue(self, envelope).await
    }
}

impl Default for LocalBus {
    fn default() -> Self {
        Self::new()
    }
}

fn current_unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox::MailboxKind;
    use roundhouse_core::SessionId;

    #[tokio::test]
    async fn registering_a_mailbox_twice_is_idempotent() {
        let bus = LocalBus::new();
        let sid = SessionId::new();
        bus.register_mailbox(sid, MailboxKind::Bounded(64))
            .await
            .unwrap();
        bus.register_mailbox(sid, MailboxKind::Bounded(64))
            .await
            .unwrap();
        assert!(bus.has_mailbox(sid));
    }

    #[tokio::test]
    async fn deregistering_removes_the_mailbox() {
        let bus = LocalBus::new();
        let sid = SessionId::new();
        bus.register_mailbox(sid, MailboxKind::Bounded(64))
            .await
            .unwrap();
        bus.deregister_mailbox(sid).await.unwrap();
        assert!(!bus.has_mailbox(sid));
    }
}

#[cfg(test)]
mod send_tests {
    use super::*;
    use crate::mailbox::MailboxKind;
    use crate::types::{Address, Envelope, MessageId, Provenance, Trust};
    use roundhouse_core::{Origin, SessionId};
    use uuid::Uuid;

    fn envelope(from: SessionId, to: SessionId, seq: u8) -> Envelope {
        Envelope {
            id: MessageId(Uuid::new_v4()),
            from,
            to,
            to_requested: Address::Session { id: to },
            subject: "s".into(),
            body: format!("msg-{seq}"),
            attachments: vec![],
            expect_reply: None,
            in_reply_to: None,
            ttl_hops: 8,
            provenance: Provenance {
                origin: Origin::Peer,
                trust: Trust::Untrusted,
                task: None,
            },
        }
    }

    #[tokio::test]
    async fn fifo_ordering_is_per_sender_recipient_pair_not_global() {
        let bus = LocalBus::new();
        let a = SessionId::new();
        let b = SessionId::new();
        bus.register_mailbox(a, MailboxKind::Bounded(64))
            .await
            .unwrap();
        bus.register_mailbox(b, MailboxKind::Bounded(64))
            .await
            .unwrap();

        // Interleave two independent pairs: A->B and B->A.
        bus.send(envelope(a, b, 1)).await.unwrap();
        bus.send(envelope(b, a, 1)).await.unwrap();
        bus.send(envelope(a, b, 2)).await.unwrap();
        bus.send(envelope(b, a, 2)).await.unwrap();

        let b1 = bus.poll(b).await.unwrap().unwrap();
        let b2 = bus.poll(b).await.unwrap().unwrap();
        assert_eq!(b1.body, "msg-1");
        assert_eq!(b2.body, "msg-2");

        let a1 = bus.poll(a).await.unwrap().unwrap();
        let a2 = bus.poll(a).await.unwrap().unwrap();
        assert_eq!(a1.body, "msg-1");
        assert_eq!(a2.body, "msg-2");
    }

    #[tokio::test]
    async fn send_to_ended_session_is_synchronously_undeliverable() {
        let bus = LocalBus::new();
        let from = SessionId::new();
        let ended = SessionId::new(); // never registered = tombstoned/ended
        let err = bus.send(envelope(from, ended, 1)).await.unwrap_err();
        assert!(matches!(
            err,
            crate::types::BusError::Undeliverable(crate::types::Undeliverable::Ended { .. })
        ));
    }
}

#[cfg(test)]
mod backpressure_tests {
    use super::*;
    use crate::mailbox::MailboxKind;
    use crate::types::{Address, Envelope, MessageId, Provenance, Trust};
    use roundhouse_core::{Origin, SessionId};
    use uuid::Uuid;

    fn envelope(from: SessionId, to: SessionId, subject: &str) -> Envelope {
        Envelope {
            id: MessageId(Uuid::new_v4()),
            from,
            to,
            to_requested: Address::Session { id: to },
            subject: subject.into(),
            body: "x".into(),
            attachments: vec![],
            expect_reply: None,
            in_reply_to: None,
            ttl_hops: 8,
            provenance: Provenance {
                origin: Origin::Peer,
                trust: Trust::Untrusted,
                task: None,
            },
        }
    }

    #[tokio::test]
    async fn overflow_rejects_the_send_and_never_drops_the_oldest() {
        let bus = LocalBus::new();
        let from = SessionId::new();
        let to = SessionId::new();
        bus.register_mailbox(to, MailboxKind::Bounded(2))
            .await
            .unwrap();

        bus.send(envelope(from, to, "s")).await.unwrap();
        bus.send(envelope(from, to, "s")).await.unwrap();
        let err = bus.send(envelope(from, to, "s")).await.unwrap_err();
        assert!(matches!(
            err,
            crate::types::BusError::MailboxFull { capacity: 2, .. }
        ));

        // The two original messages are both still there — nothing was evicted.
        assert!(bus.poll(to).await.unwrap().is_some());
        assert!(bus.poll(to).await.unwrap().is_some());
        assert!(bus.poll(to).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn human_recipients_never_get_an_ordinary_mailbox_or_a_capacity_limit() {
        let bus = LocalBus::new();
        let human = SessionId::new();
        bus.register_human(human);

        // A distinct subject *and* sender per iteration: this test is only about the
        // human path itself, so it deliberately avoids tripping the repetition damper
        // (keyed on `(to, subject)`) and the per-sender rate cap (burst 10) that
        // Task 12 wires into `send` for real (§7.7).
        for i in 0..(crate::mailbox::DEFAULT_MAILBOX_CAPACITY * 4) {
            let from = SessionId::new();
            bus.send(envelope(from, human, &format!("s{i}")))
                .await
                .unwrap();
        }

        // §7.2: "never blocked by policy" — there is no capacity concept to violate
        // because a human recipient never gets an ordinary `Mailbox` in the first
        // place, not because its `Mailbox` happens to be `Unbounded`.
        assert!(!bus.has_mailbox(human));
        assert_eq!(
            bus.list_human_notifications(human).len(),
            crate::mailbox::DEFAULT_MAILBOX_CAPACITY * 4
        );
    }

    #[tokio::test]
    async fn draining_human_notifications_removes_them() {
        let bus = LocalBus::new();
        let from = SessionId::new();
        let human = SessionId::new();
        bus.register_human(human);
        bus.send(envelope(from, human, "heads up")).await.unwrap();

        let drained = bus.drain_human_notifications(human);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].from, from);
        assert!(bus.list_human_notifications(human).is_empty());
    }
}

#[cfg(test)]
mod send_wiring_tests {
    use super::*;
    use crate::mailbox::MailboxKind;
    use crate::teams::TeamRegistry;
    use crate::types::{Address, Envelope, MessageId, Provenance, Trust};
    use roundhouse_core::{Origin, SessionId, WorkspaceId};
    use std::sync::Arc;
    use uuid::Uuid;

    fn envelope(from: SessionId, to: SessionId, subject: &str, ttl_hops: u8) -> Envelope {
        Envelope {
            id: MessageId(Uuid::new_v4()),
            from,
            to,
            to_requested: Address::Session { id: to },
            subject: subject.into(),
            body: "x".into(),
            attachments: vec![],
            expect_reply: None,
            in_reply_to: None,
            ttl_hops,
            provenance: Provenance {
                origin: Origin::Peer,
                trust: Trust::Untrusted,
                task: None,
            },
        }
    }

    #[tokio::test]
    async fn send_enforces_the_rate_cap_for_real_not_just_in_rate_limit_tests() {
        let bus = LocalBus::new();
        let from = SessionId::new();
        let to = SessionId::new();
        bus.register_mailbox(to, MailboxKind::Bounded(64))
            .await
            .unwrap();

        // §7.7 default: 20/min, burst 10. Vary the subject per send so the
        // repetition damper (a separate check, exercised below) can't also trigger
        // here — this test isolates the rate cap specifically.
        for i in 0..10 {
            bus.send(envelope(from, to, &format!("s{i}"), 8))
                .await
                .unwrap();
        }
        let err = bus.send(envelope(from, to, "s10", 8)).await.unwrap_err();
        assert!(matches!(err, crate::types::BusError::RateLimited { .. }));
    }

    #[tokio::test]
    async fn send_enforces_the_repetition_damper_for_real() {
        let bus = LocalBus::new();
        let from = SessionId::new();
        let to = SessionId::new();
        bus.register_mailbox(to, MailboxKind::Bounded(64))
            .await
            .unwrap();

        // A fixed `from` + fixed subject trips the damper (keyed on (from, to,
        // subject)). Only 4 sends are needed — well under the rate cap's per-sender
        // burst of 10 — so this isolates the repetition damper alone.
        for _ in 0..3 {
            bus.send(envelope(from, to, "status-check", 8))
                .await
                .unwrap();
        }
        let err = bus
            .send(envelope(from, to, "status-check", 8))
            .await
            .unwrap_err();
        assert!(matches!(err, crate::types::BusError::Repetitive { .. }));
    }

    #[tokio::test]
    async fn send_decrements_ttl_hops_and_refuses_at_zero() {
        let bus = LocalBus::new();
        let from = SessionId::new();
        let to = SessionId::new();
        bus.register_mailbox(to, MailboxKind::Bounded(64))
            .await
            .unwrap();

        bus.send(envelope(from, to, "relay", 1)).await.unwrap();
        let delivered = bus.poll(to).await.unwrap().unwrap();
        // §7.7: "ttl_hops (default 8) decremented per relay" — message_send's doc
        // comment claimed this but the code never did it; this assertion is the
        // real, end-to-end proof that it now does.
        assert_eq!(delivered.ttl_hops, 0);

        let err = bus
            .send(envelope(from, to, "relay-again", 0))
            .await
            .unwrap_err();
        assert!(matches!(err, crate::types::BusError::TtlExpired));
    }

    #[tokio::test]
    async fn resolve_recipients_expands_a_team_address_to_every_roster_member() {
        let bus = LocalBus::new();
        let ws = WorkspaceId::new();
        let lead = SessionId::new();
        let teams = Arc::new(TeamRegistry::new());
        let team = teams
            .create_team(ws, "t".into(), "c".into(), lead, "lead".into())
            .unwrap();
        let worker_a = SessionId::new();
        let worker_b = SessionId::new();
        teams.join(team, worker_a, None).unwrap();
        teams.join(team, worker_b, None).unwrap();
        let bus = bus.with_teams(teams);

        let mut recipients = bus
            .resolve_recipients(ws, &Address::Team { team })
            .await
            .unwrap();
        recipients.sort_by_key(|s| s.to_string());
        let mut expected = vec![lead, worker_a, worker_b];
        expected.sort_by_key(|s| s.to_string());
        assert_eq!(recipients, expected);
    }

    #[tokio::test]
    async fn resolve_recipients_filters_a_role_address_to_matching_members_only() {
        let bus = LocalBus::new();
        let ws = WorkspaceId::new();
        let lead = SessionId::new();
        let teams = Arc::new(TeamRegistry::new());
        let team = teams
            .create_team(ws, "t".into(), "c".into(), lead, "lead".into())
            .unwrap();
        let worker = SessionId::new();
        teams.join(team, worker, Some("worker".into())).unwrap();
        let bus = bus.with_teams(teams);

        let recipients = bus
            .resolve_recipients(
                ws,
                &Address::Role {
                    team,
                    role: "worker".into(),
                },
            )
            .await
            .unwrap();
        assert_eq!(recipients, vec![worker]);
    }

    #[tokio::test]
    async fn resolve_recipients_refuses_a_draining_or_closed_team() {
        let bus = LocalBus::new();
        let ws = WorkspaceId::new();
        let lead = SessionId::new();
        let teams = Arc::new(TeamRegistry::new());
        let team = teams
            .create_team(ws, "t".into(), "c".into(), lead, "lead".into())
            .unwrap();
        let bus = bus.with_teams(teams.clone());

        // Active: resolves.
        assert!(bus
            .resolve_recipients(ws, &Address::Team { team })
            .await
            .is_ok());

        teams.begin_draining(team).unwrap();
        let err = bus
            .resolve_recipients(ws, &Address::Team { team })
            .await
            .unwrap_err();
        assert!(matches!(err, crate::types::BusError::TeamDraining { .. }));

        // Role addresses are refused the same way.
        let err = bus
            .resolve_recipients(
                ws,
                &Address::Role {
                    team,
                    role: "lead".into(),
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, crate::types::BusError::TeamDraining { .. }));

        // Closed teams (reaper path) too.
        teams.mark_member_ended(team, lead).unwrap();
        teams.reap_ended();
        let err = bus
            .resolve_recipients(ws, &Address::Team { team })
            .await
            .unwrap_err();
        assert!(matches!(err, crate::types::BusError::TeamDraining { .. }));
    }
}
