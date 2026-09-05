//! Proves `Dashboard::apply` reduces a raw `roundhouse_core::EventPayload`
//! itself, with no daemon-side `ServerMessage` pre-summarization in front of
//! it — the precondition Phase 7 Task 2 exists to establish for Task 3's real
//! bidirectional accept loop.

use roundhouse_core::{Delta, EventPayload, SessionId};
use roundhouse_tui::Dashboard;

#[test]
fn dashboard_reduces_a_raw_task_delta_event_payload_without_a_pre_flattened_servermessage() {
    let mut dash = Dashboard::new();
    let session = SessionId::new();
    dash.apply(
        session,
        EventPayload::TaskDelta {
            delta: Delta::Text {
                text: "hello".into(),
            },
        },
    );
    assert!(
        dash.rendered_text_for(session).contains("hello"),
        "Dashboard must reduce raw EventPayload itself now — no daemon-side pre-summarization exists on the real wire"
    );
}
