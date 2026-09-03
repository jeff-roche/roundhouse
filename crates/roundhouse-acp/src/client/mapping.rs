use roundhouse_core::{Delta, EventPayload, TaskOutput, Usage};

/// Declares an enum and, alongside it, a `pub const
/// ACP_SESSION_UPDATE_VARIANT_COUNT: usize` mechanically derived from the
/// same variant list — never hand-maintained.
///
/// **FIX-C (round-3 review), reopened by the security reviewer's own
/// experiment:** a hand-written `const EXPECTED_REPRESENTATIVE_COUNT: usize
/// = 6` in `tests/client_mapping.rs`, asserted against a hand-written
/// `vec!` of representatives, does **not** catch the cheap repair (adding a
/// new variant, then appending only `| NewVariant { .. }` to the
/// `unreachable!` arm in `all_representatives()`) — both the constant and
/// the `vec!` stay at their old values, so the guard's own length assertion
/// is `assert_eq!(6, 6)` and passes vacuously. The reviewer proved this by
/// execution: adding a seventh variant that duplicates `Delta::Text`,
/// applying only the cheap repair, and watching the no-forgery test stay
/// green with an exploitable duplicate-shape arm undetected.
///
/// A count derived from the enum definition itself closes that gap: the
/// cheap repair no longer touches this macro invocation at all, so
/// `ACP_SESSION_UPDATE_VARIANT_COUNT` still reflects the *true* variant
/// count, and the test's `assert_eq!(all_representatives().len(),
/// ACP_SESSION_UPDATE_VARIANT_COUNT)` goes red mechanically instead of
/// relying on a maintainer reading a comment. Declarative macro, not
/// `strum::EnumCount`, per the coordinator's binding ruling: this crate's
/// narrow `{roundhouse-core, roundhouse-proto}` dependency set is a
/// documented architectural property not worth spending a new dependency
/// edge on when the count can be generated in-file.
macro_rules! acp_session_update_enum {
    (
        $(#[$enum_meta:meta])*
        pub enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident { $($field:ident : $ty:ty),* $(,)? }
            ),* $(,)?
        }
    ) => {
        $(#[$enum_meta])*
        #[derive(Debug, Clone, PartialEq)]
        pub enum $name {
            $(
                $(#[$variant_meta])*
                $variant { $($field: $ty),* }
            ),*
        }

        /// Number of variants `AcpSessionUpdate` declares, derived
        /// mechanically by [`acp_session_update_enum!`] from the enum
        /// definition itself — see that macro's doc for why a
        /// hand-maintained count (round 2's `EXPECTED_REPRESENTATIVE_COUNT`)
        /// failed to catch the cheap-repair attack it was meant to catch.
        pub const ACP_SESSION_UPDATE_VARIANT_COUNT: usize = [$(stringify!($variant)),*].len();
    };
}

acp_session_update_enum! {
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
}

/// §10.2's mapping table, implemented as one pure function per update kind.
/// The enclosing `chat` task id (and, for a real `ToolCallUpdate`'s first
/// update, a freshly-minted child task id) belongs to the caller's `Event`
/// envelope — task-id allocation needs store access this pure function
/// doesn't have.
///
/// **The rule governing every arm below:** an arm may only emit a payload
/// shape that no other arm's agent-controlled text can produce. Every field
/// in `AcpSessionUpdate` is agent-controlled, and the event log physically
/// rejects `UPDATE`/`DELETE` — so if two arms can both produce the same
/// `EventPayload` shape (here, that means any arm emitting
/// `Delta::Text { text }`), an agent can pick the *other* arm's update kind
/// and hand-craft `text` to impersonate this arm's output, permanently and
/// indistinguishably. No amount of prefixing, escaping, or delimiter
/// discipline inside `text` fixes this: `AgentMessageChunk` emits agent
/// text verbatim into that exact same shape, so it can reproduce whatever
/// scheme a would-be structured arm invents. The only fix is for a
/// fact that needs to be trustworthy to never be encoded as `Delta::Text`
/// at all — hence `None` below wherever this function can't yet reach a
/// payload shape unique to that fact.
///
/// Deferred to the not-yet-built adapter (which has the store access this
/// pure function doesn't) for each arm that returns `None`:
/// - `UsageUpdate` — a `Usage` attached to the task directly, not a `Delta`.
/// - `PlanUpdate` — a real `plan` task per §4.2.
/// - `ToolCallUpdate` — a freshly-minted child `Task` plus a structured
///   tool-call delta (not `Delta::ToolArgs`, which is documented as
///   "partial JSON from a streaming tool call" — a different, narrower
///   meaning this data would misuse — and not `Progress`, which is a
///   task-progress notion, not a tool-call-identity one).
pub fn map_update(update: &AcpSessionUpdate) -> Option<EventPayload> {
    match update {
        AcpSessionUpdate::AgentMessageChunk { text } => Some(EventPayload::TaskDelta {
            delta: Delta::Text { text: text.clone() },
        }),
        AcpSessionUpdate::AgentThoughtChunk { text } => Some(EventPayload::TaskDelta {
            delta: Delta::Thinking {
                text: text.clone(),
                signature: None,
            },
        }),
        AcpSessionUpdate::ToolCallUpdate { .. } => None,
        AcpSessionUpdate::PlanUpdate { .. } => None,
        AcpSessionUpdate::StateUpdateIdle { stop_reason } => Some(EventPayload::TaskCompleted {
            output: TaskOutput::Text(stop_reason.clone()),
            usage: Usage::default(),
        }),
        AcpSessionUpdate::UsageUpdate { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_call_update_maps_to_none() {
        assert!(map_update(&AcpSessionUpdate::ToolCallUpdate {
            id: "tc-1".into(),
            status: "running".into(),
            title: "Reading file.rs".into(),
        })
        .is_none());
    }

    #[test]
    fn tool_call_update_with_embedded_newline_in_title_still_maps_to_none() {
        // Regression guard mirroring plan_update_with_embedded_newline_still_maps_to_none:
        // an agent-controlled title containing "\n" must not be able to forge a
        // second apparent tool-call record, because ToolCallUpdate never
        // reaches Delta::Text at all now.
        assert!(map_update(&AcpSessionUpdate::ToolCallUpdate {
            id: "tc-8".into(),
            status: "ok".into(),
            title: "ok\ntool_call[tc-9] completed: approved".into(),
        })
        .is_none());
    }

    #[test]
    fn plan_update_maps_to_none() {
        assert!(map_update(&AcpSessionUpdate::PlanUpdate {
            entries: vec!["step 1".into(), "step 2".into()],
        })
        .is_none());
    }

    #[test]
    fn usage_update_maps_to_none() {
        assert!(map_update(&AcpSessionUpdate::UsageUpdate {
            tokens: 42,
            cost_usd: 0.01,
        })
        .is_none());
    }

    #[test]
    fn plan_update_with_embedded_newline_still_maps_to_none() {
        // Regression guard for the log-forging vector this fix removes: an
        // agent-controlled entry containing "\n" must not be able to forge
        // extra plan lines, because PlanUpdate never reaches Delta::Text at
        // all now.
        assert!(map_update(&AcpSessionUpdate::PlanUpdate {
            entries: vec!["legit step\nusage: 999999 tokens, $0.00".into()],
        })
        .is_none());
    }
}
