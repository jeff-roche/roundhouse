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
    ///
    /// **Hazard (Ruling C-P56, fix round 1):** the inner `String` is
    /// **untrusted peer input of unbounded length.** A 2,000,000-byte JSON
    /// string deserializes into this variant without error — nothing at
    /// this layer caps it, and nothing should: capping on construction was
    /// considered and rejected, because this variant must round-trip
    /// unknown wire values byte-for-byte (the §10.1 requirement this module
    /// exists to satisfy), and truncating would silently corrupt any
    /// legitimate value over the limit. `Debug` formatting does escape
    /// control characters, which closes the newline/log-forgery half of the
    /// hazard the same way `server::escape_and_cap_peer_str` does, but the
    /// *length* is not bounded anywhere between the wire and this type.
    /// **Any caller that renders this string into a log line, a TUI, or an
    /// event payload must escape and cap it itself first** — e.g. via
    /// `server::escape_and_cap_peer_str` — before doing so; this module
    /// deliberately does not do that on the caller's behalf.
    ///
    /// **Invariant (Ruling C-P58, fix round 1):** this variant holds only
    /// *unrecognized* wire values — it must never hold a string equal to one
    /// of the known variants' wire encoding (`"end_turn"`, `"max_tokens"`,
    /// `"max_turn_requests"`, `"refusal"`, `"cancelled"`), because two
    /// distinct Rust values (`Other("end_turn")` and `EndTurn`) would then
    /// share one wire encoding while comparing unequal by `==`. Every
    /// construction path within this crate preserves that invariant: never
    /// write `StopReason::Other(s)` directly for a string of unknown
    /// provenance — call [`StopReason::other`] instead, which normalizes a
    /// known wire value to its known variant. This variant stays `pub`
    /// (sealing it via `#[non_exhaustive]` was considered and rejected — it
    /// would block the SDK-mirroring flat idiom's own constructibility and
    /// legitimate test construction), so external code can still bypass
    /// `StopReason::other` and construct `StopReason::Other("end_turn")`
    /// directly; the invariant binds this crate's own code, not external
    /// callers.
    #[serde(untagged)]
    Other(String),
}

impl StopReason {
    /// Constructs a [`StopReason::Other`], first checking whether `value` is
    /// itself the wire encoding of a known variant — normalizing to that
    /// variant instead if so (Ruling C-P58). This is the constructor every
    /// in-crate call site that might hold a string of unknown provenance
    /// must use instead of writing `StopReason::Other(s)` directly, so that
    /// `Other` can never come to hold a value equal to one of the known
    /// variants' wire encoding (see that variant's own doc for why that
    /// matters).
    ///
    /// Reuses this type's own `Deserialize` implementation — which the
    /// `#[serde(untagged)]` shape already makes try each known variant
    /// before falling through to `Other` — instead of hand-duplicating the
    /// five wire strings in a second place where they could drift out of
    /// sync with `#[serde(rename_all = "snake_case")]` above.
    pub fn other(value: impl Into<String>) -> Self {
        let value = value.into();
        serde_json::from_value(serde_json::Value::String(value.clone()))
            .unwrap_or(StopReason::Other(value))
    }
}

/// Sentinel written into [`StopReason::Other`] when converting from a
/// pinned-SDK `schema::v2::StopReason` variant this crate does not (yet)
/// have a named arm for — see the `From` impl below.
///
/// **Ruling C-P57 (fix round 1):** previously this fallback wrote
/// `format!("{other:?}")` — the Rust `Debug` spelling of the unmapped SDK
/// variant (e.g. `"NewThing"` rather than the wire form `"new_thing"`),
/// which would silently break the byte-for-byte round-trip this module
/// exists to guarantee, and if the new variant carried a payload, `Debug`
/// would have embedded that payload's content into a string this crate then
/// emits outward on the wire. A fixed, non-peer-derived, non-SDK-payload-
/// derived sentinel instead injects nothing. ACP reserves values beginning
/// with `_` for implementation-specific extensions (see this file's
/// `StopReason::Other` upstream-mirrored doc), so this sentinel is
/// spec-legal.
const UNMAPPED_SDK_VARIANT_SENTINEL: &str = "_roundhouse_unmapped";

/// Converts the pinned SDK's real `schema::v2::StopReason` into this crate's
/// local mirror, variant for variant. `schema::v2::StopReason` is
/// `#[non_exhaustive]`, so this match still needs a trailing wildcard arm for
/// forward-compatibility even though every variant that exists today is
/// listed explicitly — any future upstream addition falls back to
/// [`UNMAPPED_SDK_VARIANT_SENTINEL`] (Ruling C-P57) rather than silently
/// failing to compile a new arm.
///
/// **On reachability of the wildcard arm (fix round 1):** verified directly
/// against the pinned `agent-client-protocol-schema` 1.5.0 source
/// (`src/v2/agent.rs`) that `schema::v2::StopReason` has exactly the six
/// variants matched below — five named plus `Other` — for this exact pinned
/// dependency version. The wildcard arm is therefore **not reachable by any
/// value constructible from this exact pinned SDK version**; it exists
/// solely because `#[non_exhaustive]` requires a match on this externally
/// defined enum to have a catch-all, guarding against a *future* SDK
/// version adding a variant. No test exercises this arm — doing so would
/// require either a fake/hand-rolled variant (which would not prove
/// anything about the real SDK type) or an SDK upgrade actually adding one;
/// neither is available here, so per the task instruction, this is stated
/// rather than faked with a test.
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
            // Ruling C-P58: route through `StopReason::other` rather than
            // `StopReason::Other(s)` directly — the SDK's own `Other` could
            // in principle carry a string equal to a known wire value (e.g.
            // if constructed programmatically upstream rather than via its
            // deserializer), and passing that straight through would create
            // exactly the Other-holding-a-known-value hazard this ruling
            // closes.
            SdkStopReason::Other(s) => StopReason::other(s),
            _ => StopReason::Other(UNMAPPED_SDK_VARIANT_SENTINEL.to_string()),
        }
    }
}
