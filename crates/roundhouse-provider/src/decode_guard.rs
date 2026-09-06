//! Structural guard against the exact defect this crate's decoders have
//! independently reintroduced (and been fixed for) multiple times: treating
//! a stream that never reached its own terminal event as a clean
//! completion.
//!
//! This codebase has **two** legitimate, tested, documented encodings for
//! "was the generation truncated", and this guard is deliberately used by
//! only one of them:
//!
//! - **strict-`Err`** (the "strict group": `anthropic_messages`,
//!   `openai_chat`, `cohere_v2`) — the decode function itself returns
//!   `Err(<the codec's own StreamFailureKind>::Truncated)` when its loop
//!   ends without ever observing [`StreamEvent::MessageStop`]. This
//!   module's [`DecodeLoopGuard`] is the shared, structural implementation
//!   of "did we ever see `MessageStop`" for this group — every codec here
//!   still owns its own `StreamFailure`/`StreamFailureKind` type (Ruling
//!   R1: no crate-level `StreamFailure` unification) and maps this guard's
//!   [`Truncated`] marker onto its own enum's own `Truncated` variant.
//!
//! - **absence-of-`MessageStop`** (the "absence group": `google_genai`,
//!   `openai_responses`, `bedrock_converse`) — the decode function returns
//!   `Ok(events)` unconditionally at a clean frame/body boundary and NEVER
//!   fabricates a `MessageStop` it did not actually observe on the wire.
//!   `roundhouse-engine`'s `compact.rs` (its `compact` returns `Ok(summary)`
//!   only if `MessageStop` was observed) is the downstream consumer that
//!   turns that absence into the truncation signal. These three codecs do
//!   **not** call `DecodeLoopGuard` — retrofitting them to error here would
//!   revert three prior, sanctioned, tested fix-round decisions in their
//!   own `decode.rs` files, and would change a contract owned by a
//!   different crate/lane (`roundhouse-engine`) from outside that lane.
//!
//! `roundhouse-conformance`'s `check_truncate_mid_stream` is what actually
//! makes the discipline mandatory across *both* groups: it fails a subject,
//! regardless of which group it belongs to, on the one outcome that is
//! never legitimate under either encoding — `Ok(events)` that contains a
//! fabricated `MessageStop`. See that check's own doc comment for the exact
//! property it proves.

use crate::stream_event::StreamEvent;

/// Observes decoded events and tracks whether [`StreamEvent::MessageStop`]
/// was ever seen. Deliberately not itself a `StreamFailure`/error enum
/// (Ruling R1): each strict-group codec maps [`Truncated`] onto its own,
/// independently evolving `StreamFailureKind`.
#[derive(Debug, Default)]
pub struct DecodeLoopGuard {
    saw_message_stop: bool,
}

/// A guard-local marker: "the decode loop ended without ever observing
/// `StreamEvent::MessageStop`". Carries no data of its own — each caller
/// maps it onto its own `StreamFailureKind::Truncated` (or equivalent),
/// attaching whatever diagnostic message/partial text its own
/// `StreamFailure` shape requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Truncated;

impl DecodeLoopGuard {
    /// Creates a guard that has not yet observed a terminal stop.
    pub fn new() -> Self {
        Self::default()
    }

    /// Observes one decoded event, updating internal state. Call once per
    /// event pushed into the decode loop's output — mirroring every
    /// `events.push(...)` call site in the strict-group codec's loop.
    pub fn observe(&mut self, event: &StreamEvent) {
        if matches!(event, StreamEvent::MessageStop) {
            self.saw_message_stop = true;
        }
    }

    /// Consumes the guard: `Ok(())` if `MessageStop` was ever observed,
    /// `Err(Truncated)` otherwise. Call once, after the decode loop exits.
    pub fn finish(self) -> Result<(), Truncated> {
        if self.saw_message_stop {
            Ok(())
        } else {
            Err(Truncated)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_guard_that_never_observed_message_stop_finishes_truncated() {
        let mut guard = DecodeLoopGuard::new();
        guard.observe(&StreamEvent::BlockStart {
            index: 0,
            kind: crate::stream_event::BlockKind::Text,
        });
        assert_eq!(guard.finish(), Err(Truncated));
    }

    #[test]
    fn a_guard_that_observed_message_stop_finishes_ok() {
        let mut guard = DecodeLoopGuard::new();
        guard.observe(&StreamEvent::BlockStart {
            index: 0,
            kind: crate::stream_event::BlockKind::Text,
        });
        guard.observe(&StreamEvent::MessageStop);
        assert_eq!(guard.finish(), Ok(()));
    }

    #[test]
    fn a_fresh_guard_with_no_events_observed_finishes_truncated() {
        let guard = DecodeLoopGuard::new();
        assert_eq!(guard.finish(), Err(Truncated));
    }
}
