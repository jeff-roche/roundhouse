//! Phase 5, Subsystem A, Task 4 (A4/G7 fix): exercises the real call path
//! end to end — `Binding::new` (Task 1) -> `bind_message_trigger` (Task 4,
//! which calls the real `Bus::register_mailbox`/`register_handle`) ->
//! `LocalBus::send` resolving the `Address::Handle` exactly like any other
//! message -> `poll_message_trigger` receiving it -> `record_trigger_event`
//! persisting the firing. No topic string appears anywhere in this path —
//! the exact gap A4 named (§7.3 deliberately cut topic pub/sub).
use chrono::Utc;
use roundhouse_bus::local_bus::LocalBus;
use roundhouse_bus::mailbox::MailboxKind;
use roundhouse_bus::types::{Envelope, MessageId, Provenance, Trust};
use roundhouse_bus::Bus;
use roundhouse_core::{Address, JobId, Origin, SessionId, WorkspaceId};
use roundhouse_sched::message_trigger::{bind_message_trigger, poll_message_trigger};
use roundhouse_sched::store::{open_test_db, record_trigger_event};
use roundhouse_sched::trigger::{Binding, TriggerEvent, TriggerSpec};
use uuid::Uuid;

#[tokio::test]
async fn a_message_send_to_the_bound_handle_fires_the_trigger_end_to_end() {
    let bus = LocalBus::new();
    let workspace = WorkspaceId::new();
    let address = Address::Handle {
        workspace,
        name: "nightly-digest-listener".to_string(),
    };
    let binding = Binding::new(
        JobId::new(),
        TriggerSpec::Message {
            address: address.clone(),
            filter: None,
        },
    );

    bind_message_trigger(&bus, &binding)
        .await
        .expect("binds the handle on the real bus trait");

    // The handle resolves daemon-side, exactly like any other address —
    // §7.2's "(workspace, name) -> SessionId resolved daemon-side at send time."
    let resolved = bus
        .resolve_address(workspace, &address)
        .await
        .expect("Address::Handle resolves");
    assert_eq!(resolved, binding.trigger_session_id());

    let sender = SessionId::new();
    bus.register_mailbox(sender, MailboxKind::Bounded(8))
        .await
        .unwrap();

    // A plain message_send, no special-cased trigger API. `to` is already
    // resolved (the real `Bus::send`/`Envelope` contract — address
    // expansion stays daemon-side, never redone by the sender).
    bus.send(Envelope {
        id: MessageId(Uuid::new_v4()),
        from: sender,
        to: resolved,
        to_requested: address,
        subject: "trigger".to_string(),
        body: "run now".to_string(),
        attachments: vec![],
        expect_reply: None,
        in_reply_to: None,
        ttl_hops: 8,
        provenance: Provenance {
            origin: Origin::Peer,
            trust: Trust::Untrusted,
            task: None,
        },
    })
    .await
    .expect("a plain message_send, no special-cased trigger API");

    let received = poll_message_trigger(&bus, &binding).await.unwrap();
    assert!(
        received.is_some(),
        "the trigger actually received the send, resolved via Address::Handle"
    );
    assert_eq!(received.unwrap().body, "run now");

    // The firing is persisted exactly like any other trigger (Task 4's own
    // record_trigger_event), so it shows up in the same dedupe/catch-up path.
    let mut conn = open_test_db();
    let now = Utc::now();
    let ev = TriggerEvent {
        binding_id: binding.id,
        idempotency_key: format!("{}-{}", binding.id, now.to_rfc3339()),
        scheduled_for: now,
        fired_at: now,
        is_catch_up: false,
        session_id: None,
    };
    assert!(record_trigger_event(&mut conn, &ev).unwrap());
}
