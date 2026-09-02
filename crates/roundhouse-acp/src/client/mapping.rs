use roundhouse_core::{Delta, EventPayload, TaskOutput, Usage};

/// A deliberately simplified LOCAL mirror of the shapes an ACP client
/// eventually needs to turn into `EventPayload`s — not a 1:1 rename of any
/// single real SDK type. It exists so this mapping is unit-testable without
/// a live ACP connection, and so an SDK point release doesn't ripple through
/// this crate's unit tests, only through the (not-yet-built) adapter that
/// constructs this enum from the real wire types. Three things about that
/// relationship are worth recording precisely, because it is easy to
/// misdescribe:
///
/// - `StateUpdateIdle` has **no** v1 counterpart. Under the pinned SDK's v1
///   schema, end-of-turn is signalled by `PromptResponse.stop_reason` — a
///   *response field* returned from the `session/prompt` call, not a
///   `SessionUpdate` notification variant. It corresponds to v2's
///   `IdleStateUpdate` (an actual notification variant there). A future v1
///   adapter must therefore construct this variant from the prompt
///   response it receives, not from a `session/update` notification like
///   every other variant here.
/// - The real v1 chunk notifications (`AgentMessageChunk`,
///   `AgentThoughtChunk`) carry a `ContentChunk` wrapping a full
///   `ContentBlock` enum (text, image, audio, resource, ...) plus an
///   optional `message_id` — not a bare `String` as this enum's fields
///   suggest. A real adapter must `match` on `ContentBlock` to extract (or
///   reject) a text payload; that is not a field rename, it's a variant
///   dispatch this mirror deliberately elides.
/// - Building that real adapter — the code that consumes the pinned SDK's
///   actual notification/response types and produces an `AcpSessionUpdate`
///   — is daemon-owned integration work. No task in this subsystem builds
///   it; this module only covers the pure `AcpSessionUpdate -> EventPayload`
///   mapping once such an adapter (wherever it eventually lives) has
///   already produced one of these values.
#[derive(Debug, Clone, PartialEq)]
pub enum AcpSessionUpdate {
    AgentMessageChunk {
        text: String,
    },
    AgentThoughtChunk {
        text: String,
    },
    ToolCallUpdate {
        id: String,
        status: String,
        title: String,
    },
    PlanUpdate {
        entries: Vec<String>,
    },
    StateUpdateIdle {
        stop_reason: String,
    },
    UsageUpdate {
        tokens: u64,
        cost_usd: f64,
    },
}

/// §10.2's mapping table, implemented as one pure function per update kind.
/// The enclosing `chat` task id (and, for `ToolCallUpdate`'s first update, a
/// freshly-minted child task id) belongs to the caller's `Event` envelope —
/// task-id allocation needs store access this pure function doesn't have.
pub fn map_update(update: &AcpSessionUpdate) -> EventPayload {
    match update {
        AcpSessionUpdate::AgentMessageChunk { text } => EventPayload::TaskDelta {
            delta: Delta::Text { text: text.clone() },
        },
        AcpSessionUpdate::AgentThoughtChunk { text } => EventPayload::TaskDelta {
            delta: Delta::Thinking {
                text: text.clone(),
                signature: None,
            },
        },
        AcpSessionUpdate::ToolCallUpdate { title, .. } => EventPayload::TaskDelta {
            delta: Delta::Text {
                text: title.clone(),
            }, // first update also creates a child Task; that admission call is the caller's job (needs store access this pure function doesn't have)
        },
        AcpSessionUpdate::PlanUpdate { entries } => EventPayload::TaskDelta {
            delta: Delta::Text {
                text: entries.join("\n"),
            }, // real implementation emits a `plan` task (§4.2); simplified here to keep this function pure and store-independent
        },
        AcpSessionUpdate::StateUpdateIdle { stop_reason } => EventPayload::TaskCompleted {
            output: TaskOutput::Text(stop_reason.clone()),
            usage: Usage::default(),
        },
        AcpSessionUpdate::UsageUpdate { tokens, cost_usd } => EventPayload::TaskDelta {
            delta: Delta::Text {
                text: format!("usage: {tokens} tokens, ${cost_usd}"),
            }, // real implementation attaches Usage to the enclosing infer/chat task directly, not as a Delta — refined once Phase 4's Usage-on-task API is in scope for this crate
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_call_update_becomes_task_delta_text_of_title() {
        let payload = map_update(&AcpSessionUpdate::ToolCallUpdate {
            id: "tc-1".into(),
            status: "running".into(),
            title: "Reading file.rs".into(),
        });
        assert!(
            matches!(payload, EventPayload::TaskDelta { delta: Delta::Text { text } } if text == "Reading file.rs")
        );
    }

    #[test]
    fn plan_update_becomes_task_delta_text_of_joined_entries() {
        let payload = map_update(&AcpSessionUpdate::PlanUpdate {
            entries: vec!["step 1".into(), "step 2".into()],
        });
        assert!(
            matches!(payload, EventPayload::TaskDelta { delta: Delta::Text { text } } if text == "step 1\nstep 2")
        );
    }

    #[test]
    fn usage_update_becomes_task_delta_text_summary() {
        let payload = map_update(&AcpSessionUpdate::UsageUpdate {
            tokens: 42,
            cost_usd: 0.01,
        });
        assert!(
            matches!(payload, EventPayload::TaskDelta { delta: Delta::Text { text } } if text == "usage: 42 tokens, $0.01")
        );
    }
}
