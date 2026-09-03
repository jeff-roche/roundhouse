//! §10.1's second load-bearing v2 detail: "Every enum is open; unknown
//! values must round-trip." Demonstrated here on `stopReason` (the field
//! §10.1's own capability table cites).
//!
//! Ruling C-P8: the real SDK's own open-enum idiom for this exact problem is
//! one flat enum — all known variants as ordinary unit variants, plus one
//! `#[serde(untagged)]` catch-all string variant appended at the end —
//! **not** a two-layer `Known(_) | Unknown(_)` wrapper. This mirrors
//! `agent_client_protocol::schema::v2::StopReason` variant-for-variant (see
//! the `From` conversion below, gated on `acp-v2` — since the whole `schema`
//! module already requires that feature, "this matches upstream" is proven
//! by the compiler rather than asserted in a comment).

use serde::{Deserialize, Serialize};

/// The real v2 `StopReason` variant set (five known reasons), plus `Other`
/// for anything this build doesn't yet recognize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// The active work ended successfully.
    EndTurn,
    /// The active work ended because the agent reached the maximum number of
    /// tokens.
    MaxTokens,
    /// The active work ended because the agent reached the maximum number of
    /// allowed agent requests before returning idle.
    MaxTurnRequests,
    /// The active work ended because the agent refused to continue.
    Refusal,
    /// Active session work was cancelled by the client via `session/cancel`.
    Cancelled,
    /// Custom or future stop reason. `#[serde(untagged)]` tries the known
    /// variants above first; any string that doesn't match one of them falls
    /// through to here, holding the original string so it re-serializes
    /// byte-for-byte — the round-trip §10.1 requires, instead of an error or
    /// a silently dropped value.
    #[serde(untagged)]
    Other(String),
}

/// Converts the pinned SDK's real `schema::v2::StopReason` into this crate's
/// local mirror, variant for variant. `schema::v2::StopReason` is
/// `#[non_exhaustive]`, so this match still needs a trailing wildcard arm for
/// forward-compatibility even though every variant that exists today is
/// listed explicitly — any future upstream addition falls back to `Other`
/// via its `Debug` representation rather than silently failing to compile a
/// new arm.
#[cfg(feature = "acp-v2")]
impl From<agent_client_protocol::schema::v2::StopReason> for StopReason {
    fn from(value: agent_client_protocol::schema::v2::StopReason) -> Self {
        use agent_client_protocol::schema::v2::StopReason as SdkStopReason;
        match value {
            SdkStopReason::EndTurn => StopReason::EndTurn,
            SdkStopReason::MaxTokens => StopReason::MaxTokens,
            SdkStopReason::MaxTurnRequests => StopReason::MaxTurnRequests,
            SdkStopReason::Refusal => StopReason::Refusal,
            SdkStopReason::Cancelled => StopReason::Cancelled,
            SdkStopReason::Other(s) => StopReason::Other(s),
            other => StopReason::Other(format!("{other:?}")),
        }
    }
}
