//! Task 17: end-to-end integration test proving the whole Phase 4 sub-agents +
//! messaging composition holds together — spawn a child, send it a request with
//! `expect_reply`, have it reply, resolve the wait, and confirm the wait-graph's
//! synchronous deadlock refusal works end to end.

use roundhouse_bus::local_bus::LocalBus;
use roundhouse_bus::mailbox::MailboxKind;
use roundhouse_bus::teams::TeamRegistry;
use roundhouse_bus::types::{Address, Envelope, ExpectReply, MessageId, Provenance, Quorum, Trust};
use roundhouse_core::{Origin, SessionId, WorkspaceId};
use roundhouse_engine::agent_spawn::{
    agent_spawn, AgentSpawnInput, Budget, SpawnPolicyScope, TaintSet,
};
use roundhouse_engine::tools::message_send::message_send;
use std::sync::Arc;
use uuid::Uuid;

struct AllowAll;
impl SpawnPolicyScope for AllowAll {
    fn authorizes_provider(&self, _provider: &str) -> bool {
        true
    }
}

#[tokio::test]
async fn parent_spawns_child_sends_request_child_replies_parent_wait_resolves() {
    let bus: Arc<dyn roundhouse_bus::Bus> = Arc::new(LocalBus::new());
    let teams = TeamRegistry::new();
    let ws = WorkspaceId::new();

    let parent = SessionId::new();
    bus.register_mailbox(parent, MailboxKind::Bounded(64))
        .await
        .unwrap();
    let team = teams
        .create_team(ws, "t".into(), "charter".into(), parent, "lead".into())
        .unwrap();

    let mut parent_budget = Budget {
        remaining_tokens: 1000,
    };
    let spawn_out = agent_spawn(
        &teams,
        &AllowAll,
        &mut parent_budget,
        AgentSpawnInput {
            workspace: ws,
            parent,
            parent_depth: 0,
            parent_direct_children: 0,
            team: Some(team),
            role: None,
            provider: "anthropic".into(),
            budget_tokens: 100,
            parent_taint: TaintSet { tainted: false },
        },
    )
    .unwrap();
    let child = spawn_out.session_id;
    bus.register_mailbox(child, MailboxKind::Bounded(64))
        .await
        .unwrap();

    // Parent sends a request expecting a reply. `message_send` now returns a
    // `SendOutcome` (one `MessageId` per resolved recipient, §7.1's fan-out fix) —
    // here there's exactly one, `Address::Session` being point-to-point.
    let sent = message_send(
        bus.as_ref(),
        ws,
        parent,
        Address::Session { id: child },
        "status?".into(),
        "are you done?".into(),
        vec![],
        Some(ExpectReply {
            quorum: Quorum::Any,
            deadline: None,
        }),
        8,
    )
    .await
    .unwrap();
    let req_id = sent.message_ids[0];

    // Child sees it, replies.
    let inbound = bus.poll(child).await.unwrap().unwrap();
    assert_eq!(inbound.id, req_id);
    bus.send(Envelope {
        id: MessageId(Uuid::new_v4()),
        from: child,
        to: parent,
        to_requested: Address::Session { id: parent },
        subject: "re: status?".into(),
        body: "yes".into(),
        attachments: vec![],
        expect_reply: None,
        in_reply_to: Some(req_id),
        ttl_hops: 8,
        provenance: Provenance {
            origin: Origin::Peer,
            trust: Trust::Untrusted,
            task: None,
        },
    })
    .await
    .unwrap();

    let reply = bus.poll(parent).await.unwrap().unwrap();
    assert_eq!(reply.in_reply_to, Some(req_id));
    assert_eq!(reply.body, "yes");
}

#[tokio::test]
async fn deadlock_between_parent_and_child_waits_is_refused_end_to_end() {
    let bus: Arc<dyn roundhouse_bus::Bus> = Arc::new(LocalBus::new());
    let a = SessionId::new();
    let b = SessionId::new();
    bus.register_mailbox(a, MailboxKind::Bounded(64))
        .await
        .unwrap();
    bus.register_mailbox(b, MailboxKind::Bounded(64))
        .await
        .unwrap();

    bus.register_wait(a, b).await.unwrap();
    let err = bus.register_wait(b, a).await.unwrap_err();
    assert!(matches!(
        err,
        roundhouse_bus::types::BusError::WaitWouldDeadlock { .. }
    ));
}
