use roundhouse_acp::client::mapping::{map_update, AcpSessionUpdate};
use roundhouse_core::{Delta, EventPayload};

#[test]
fn agent_message_chunk_becomes_task_delta_text() {
    let payload = map_update(&AcpSessionUpdate::AgentMessageChunk {
        text: "hello".into(),
    })
    .expect("AgentMessageChunk must map to Some(EventPayload)");
    assert!(
        matches!(payload, EventPayload::TaskDelta { delta: Delta::Text { text } } if text == "hello")
    );
}

#[test]
fn agent_thought_chunk_becomes_task_delta_thinking() {
    let payload = map_update(&AcpSessionUpdate::AgentThoughtChunk {
        text: "thinking...".into(),
    })
    .expect("AgentThoughtChunk must map to Some(EventPayload)");
    assert!(matches!(
        payload,
        EventPayload::TaskDelta { delta: Delta::Thinking { text, signature: None } } if text == "thinking..."
    ));
}

#[test]
fn state_update_idle_with_stop_reason_becomes_task_completed() {
    let payload = map_update(&AcpSessionUpdate::StateUpdateIdle {
        stop_reason: "end_turn".into(),
    })
    .expect("StateUpdateIdle must map to Some(EventPayload)");
    assert!(matches!(payload, EventPayload::TaskCompleted { .. }));
}

#[test]
fn usage_update_is_never_emitted_as_a_forgeable_text_delta() {
    assert!(map_update(&AcpSessionUpdate::UsageUpdate {
        tokens: 42,
        cost_usd: 0.01,
    })
    .is_none());
}

#[test]
fn plan_update_is_never_emitted_as_a_forgeable_text_delta() {
    assert!(map_update(&AcpSessionUpdate::PlanUpdate {
        entries: vec!["step 1".into(), "step 2".into()],
    })
    .is_none());
}

#[test]
fn tool_call_update_retains_id_and_status_not_just_title() {
    let payload = map_update(&AcpSessionUpdate::ToolCallUpdate {
        id: "tc-1".into(),
        status: "running".into(),
        title: "Reading file.rs".into(),
    })
    .expect("ToolCallUpdate must map to Some(EventPayload)");
    match payload {
        EventPayload::TaskDelta {
            delta: Delta::Text { text },
        } => {
            assert!(text.contains("tc-1"), "text must retain id: {text}");
            assert!(text.contains("running"), "text must retain status: {text}");
            assert!(
                text.contains("Reading file.rs"),
                "text must retain title: {text}"
            );
        }
        other => panic!("expected TaskDelta::Text, got {other:?}"),
    }
}
