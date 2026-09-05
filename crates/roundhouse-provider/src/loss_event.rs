//! `LossEvent`: a first-class, logged record of a downgrade a provider codec
//! could not carry forward faithfully (§9.1's thesis: "loss is a first-class,
//! logged event"). Referenced in ~15 comments across `roundhouse-provider`
//! and `roundhouse-conformance` since Phase 6, but never built until Phase 7
//! Task 13b.
//!
//! **Ruling R4**: the plan's original sketch specced
//! `record_loss(writer: &EventWriter, ..)`. That is impossible to build here
//! -- `EventWriter` lives in `roundhouse-store`, which already depends on
//! `roundhouse-provider`, so `roundhouse-provider` depending back on
//! `roundhouse-store` would be a Cargo dependency cycle. This module only
//! produces the value; turning it into a persisted event
//! (`EventPayload::Loss`, `crates/roundhouse-core/src/event.rs:188`) is a
//! caller's job, and actually writing it to the store is lane W1's engine
//! wiring, explicitly out of scope for this unit. See `into_payload`'s doc
//! comment for the frozen-contract gap this leaves at the `Provider` trait
//! boundary today.

use roundhouse_core::EventPayload;

/// A downgrade a codec applied while decoding or encoding, in enough detail
/// for an operator to tell one kind of loss apart from another on a
/// physically-immutable event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LossEvent {
    pub kind: LossKind,
    /// Free text describing the loss -- may quote back part of a provider
    /// error message verbatim. **Never treat this as safe to persist as-is**:
    /// `roundhouse-store`'s redaction pass (`crates/roundhouse-store/src/redact.rs`)
    /// routes `EventPayload::Loss.description` through the same live-secret
    /// redactor as `TaskFailed.error.message` -- but only once this value
    /// physically reaches that field via `into_payload`/persistence. This
    /// type itself does no redaction; it is not the persistence boundary.
    pub description: String,
    /// How many logical content blocks (§9.3's `ContentBlock`) the loss
    /// touched. For the two emit sites this task wires (a truncated or
    /// guardrail-interrupted turn), that is the one in-progress output turn
    /// being generated when the loss occurred -- `1`, not a count of
    /// previously-completed blocks, which are unaffected.
    pub blocks_affected: u32,
}

/// A short, machine-stable classification of a [`LossEvent`]. Doc'd on
/// `EventPayload::Loss` (`crates/roundhouse-core/src/event.rs:188`) as "a
/// short machine-stable tag" -- free text belongs in `LossEvent.description`,
/// never here.
///
/// Deliberately does NOT `#[derive(Debug)]` -- see the manual `impl Debug`
/// below.
#[derive(Clone, PartialEq, Eq)]
pub enum LossKind {
    DroppedThinkingSignature,
    DroppedCacheControl,
    SynthesizedToolCallId,
    UnsupportedToolChoice,
    TruncatedAtMaxTokens,
    ContentFiltered,
    GuardrailIntervened,
    /// A loss this codebase has no dedicated tag for yet. The wrapped
    /// `String` is free text and belongs in `description`, never in the
    /// persisted `kind` tag -- see [`LossKind::tag`] and Ruling R6.
    Other(String),
}

/// Fix round 1, Fix 2: makes Ruling R6 structural instead of merely
/// conventional. A derived `Debug` would print `Other("<wrapped text>")`
/// verbatim -- exactly the leak `tag()` exists to prevent, just reachable
/// through a different formatter (`{:?}`/`?loss.kind` in a `tracing` call,
/// instead of `{}`/`Display`). This manual impl makes every variant --
/// `Other` included -- print the same [`tag`](LossKind::tag) its persisted
/// `EventPayload::Loss.kind` uses, so there is no formatter left that can
/// leak `Other`'s wrapped text.
impl std::fmt::Debug for LossKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.tag())
    }
}

impl LossKind {
    /// The literal string persisted as `EventPayload::Loss.kind`.
    ///
    /// **Ruling R6**: `Other`'s wrapped text must never leak into this tag --
    /// it always serializes as the literal `"other"`, exactly like every
    /// other variant serializes as its own fixed name. The free text a
    /// caller wrapped in `Other(..)` belongs in `LossEvent.description` (the
    /// field commit 1's `roundhouse-store` redaction arm actually protects),
    /// not here: `redact_event_payload` redacts `description`, not `kind`,
    /// so a live secret that reached `kind` would persist unredacted.
    pub fn tag(&self) -> &'static str {
        match self {
            LossKind::DroppedThinkingSignature => "DroppedThinkingSignature",
            LossKind::DroppedCacheControl => "DroppedCacheControl",
            LossKind::SynthesizedToolCallId => "SynthesizedToolCallId",
            LossKind::UnsupportedToolChoice => "UnsupportedToolChoice",
            LossKind::TruncatedAtMaxTokens => "TruncatedAtMaxTokens",
            LossKind::ContentFiltered => "ContentFiltered",
            LossKind::GuardrailIntervened => "GuardrailIntervened",
            LossKind::Other(_) => "other",
        }
    }
}

impl LossEvent {
    /// Converts this value into the persisted `EventPayload::Loss` shape.
    /// Pure data mapping -- does not write anything anywhere; see this
    /// module's doc comment for why persistence is out of scope here.
    ///
    /// **Known gap, not fixed by this task**: `Provider::stream_chat`
    /// returns `Result<ChatStream, ProviderError>` (`crate::ir`, both frozen
    /// Phase 0 contracts), and `ChatStream`/`StreamEvent` are likewise
    /// frozen -- none of the three has a channel that can carry a
    /// `LossEvent` out of a codec's `stream_chat` implementation. Both of
    /// this task's emit sites (`codec::openai_responses::decode`,
    /// `codec::bedrock_converse::decode`) therefore surface the `LossEvent`
    /// as far as their own pure decode functions' return values (in-band,
    /// per Ruling R4) and log it via `tracing::warn!` at the `stream_chat`
    /// boundary rather than silently drop it -- but nothing today carries it
    /// onward to a real `EventWriter::append` call. Giving it a real path
    /// out of `stream_chat` (a new `Provider` method, a `ChatStream` field, a
    /// `StreamEvent` variant -- every option touches a frozen contract) is
    /// lane W1's engine-wiring call, not this unit's.
    pub fn into_payload(self) -> EventPayload {
        EventPayload::Loss {
            kind: self.kind.tag().to_string(),
            description: self.description,
            blocks_affected: self.blocks_affected,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn other_kind_serializes_as_the_literal_tag_other_not_its_wrapped_text() {
        // Ruling R6: free provider text in `LossKind::Other` must never
        // reach `EventPayload::Loss.kind` -- that field is unredacted by
        // design (only `description` is), so a live secret landing there
        // would be a redaction hole on day one.
        let event = LossEvent {
            kind: LossKind::Other("upstream said: sk-live-abc123 is over budget".into()),
            description: "upstream said: sk-live-abc123 is over budget".into(),
            blocks_affected: 1,
        };
        let payload = event.into_payload();
        match payload {
            EventPayload::Loss {
                kind,
                description,
                blocks_affected,
            } => {
                assert_eq!(
                    kind, "other",
                    "LossKind::Other must always serialize kind as the literal \"other\""
                );
                assert!(
                    description.contains("sk-live-abc123 is over budget"),
                    "the free text must land in description, not kind: {description}"
                );
                assert_eq!(blocks_affected, 1);
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn named_kinds_serialize_as_their_own_fixed_tag() {
        let event = LossEvent {
            kind: LossKind::TruncatedAtMaxTokens,
            description: "max_output_tokens".into(),
            blocks_affected: 1,
        };
        match event.into_payload() {
            EventPayload::Loss { kind, .. } => assert_eq!(kind, "TruncatedAtMaxTokens"),
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    /// Fix round 1, Fix 2: makes Ruling R6 structural, not just conventional
    /// -- a derived `Debug` on `LossKind` would print `Other`'s wrapped text
    /// verbatim through `{:?}`/`?loss.kind` (e.g. inside a future
    /// `tracing::warn!` call), reopening exactly the leak `tag()` exists to
    /// close for `Display`/persistence. The manual `impl Debug` must make
    /// `{:?}` agree with `tag()` for every variant, `Other` included.
    #[test]
    fn debug_format_never_leaks_others_wrapped_text() {
        let kind = LossKind::Other("upstream said: sk-live-abc123 is over budget".into());
        let debug_text = format!("{kind:?}");
        assert_eq!(
            debug_text, "other",
            "Debug must agree with tag(), not print the wrapped text"
        );
        assert!(!debug_text.contains("sk-live-abc123"));
    }
}
