use roundhouse_acp::client::mapping::{map_update, AcpSessionUpdate};
use roundhouse_core::{Delta, EventPayload};

#[test]
fn agent_message_chunk_becomes_task_delta_text() {
    let payload = map_update(&AcpSessionUpdate::AgentMessageChunk {
        text: "hello".into(),
    });
    assert!(
        matches!(payload, EventPayload::TaskDelta { delta: Delta::Text { text } } if text == "hello")
    );
}

#[test]
fn agent_thought_chunk_becomes_task_delta_thinking() {
    let payload = map_update(&AcpSessionUpdate::AgentThoughtChunk {
        text: "thinking...".into(),
    });
    assert!(matches!(
        payload,
        EventPayload::TaskDelta { delta: Delta::Thinking { text, signature: None } } if text == "thinking..."
    ));
}

#[test]
fn state_update_idle_with_stop_reason_becomes_task_completed() {
    let payload = map_update(&AcpSessionUpdate::StateUpdateIdle {
        stop_reason: "end_turn".into(),
    });
    assert!(matches!(payload, EventPayload::TaskCompleted { .. }));
}
