//! Working context model for compaction (Task 8).
//!
//! A `WorkingContext` holds the conversation turns that are candidates for
//! summarization plus pinned memory lines that must survive compaction verbatim.
//! It materializes compacted snapshots as `Rendered` context states, each with a
//! deterministic, documentable token-count heuristic.
//!
//! Security / boundedness: `commit_compaction` collapses the working context
//! into the latest compacted state. Old turns and older states are discarded,
//! so pinned lines are not duplicated per state and the structure cannot grow
//! without bound.

use roundhouse_provider::{ContentBlock, Message, MessageRole};
use std::sync::Mutex;

/// Identifies a materialized context state produced by `commit_compaction`.
///
/// The wrapped id is private so callers cannot forge an id and bypass the
/// `materialize` lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextStateId(usize);

impl ContextStateId {
    pub(crate) fn new(raw: usize) -> Self {
        Self(raw)
    }
}

/// Budget ceiling, in abstract tokens, used to validate that a compacted context
/// state fits inside the target window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenBudget(pub u64);

/// A rendered, materialized context state: summary plus pinned memory.
pub struct Rendered {
    text: String,
}

impl Rendered {
    /// Deterministic token-count heuristic: ceiling of UTF-8 byte length / 4.
    ///
    /// This matches §15.4's "approximate" language: it is cheap, stable across
    /// runs, and independent of any provider tokenizer. Tests assert budgets
    /// against this value.
    pub fn token_count(&self) -> u64 {
        heuristic_token_count(&self.text)
    }

    /// Full textual rendering of the compacted context, including the summary
    /// and all pinned memory lines.
    pub fn render(&self) -> String {
        self.text.clone()
    }
}

fn heuristic_token_count(text: &str) -> u64 {
    (text.len() as u64).div_ceil(4)
}

/// Shared helper: renders summary + pinned memory into the same textual format
/// used by `materialize`. Kept as a pure function so callers can compute the
/// token count of a candidate compaction before mutating any state.
fn render_state_text(summary: &str, pinned: &[String]) -> String {
    let mut text = String::new();
    text.push_str("[summary]\n");
    text.push_str(summary);
    text.push_str("\n\n[pinned memory]\n");
    for line in pinned {
        text.push_str(line);
        text.push('\n');
    }
    text
}

#[derive(Debug)]
struct ContextState {
    id: ContextStateId,
    summary: String,
    pinned: Vec<String>,
}

struct Inner {
    turns: Vec<Message>,
    pinned: Vec<String>,
    states: Vec<ContextState>,
    next_id: usize,
}

/// Holds the conversation state that compaction operates on.
pub struct WorkingContext {
    inner: Mutex<Inner>,
}

impl WorkingContext {
    /// Creates a new working context from conversation turns and pinned memory lines.
    pub fn new(turns: Vec<Message>, pinned: Vec<String>) -> Self {
        Self {
            inner: Mutex::new(Inner {
                turns,
                pinned,
                states: Vec::new(),
                next_id: 0,
            }),
        }
    }

    /// Splits the context into the summarizable portion and the pinned lines.
    ///
    /// Pinned lines are set aside **before** the summarization request is built;
    /// they are carried through compaction verbatim and never sent to the provider.
    pub fn split_pinned(&self) -> (Vec<Message>, Vec<String>) {
        let inner = self.inner.lock().unwrap();
        (inner.turns.clone(), inner.pinned.clone())
    }

    /// Computes the token count of a candidate compaction without mutating state.
    pub fn candidate_token_count(summary: &str, pinned: &[String]) -> u64 {
        heuristic_token_count(&render_state_text(summary, pinned))
    }

    /// Records a new compacted context state from the provider-generated summary
    /// and the preserved pinned lines, returning its stable id.
    ///
    /// This call **collapses** the working context: old turns are replaced by the
    /// compacted summary and only the latest state is retained. Pinned lines are
    /// never trimmed.
    pub fn commit_compaction(
        &self,
        summary: &str,
        pinned: Vec<String>,
        _budget: TokenBudget,
    ) -> ContextStateId {
        let mut inner = self.inner.lock().unwrap();
        let id = ContextStateId::new(inner.next_id);
        inner.next_id += 1;

        // Collapse: the conversation history becomes the compacted summary.
        let compacted_turn = Message {
            role: MessageRole::Assistant,
            content: vec![ContentBlock::Text {
                text: format!("[summary]\n{summary}"),
                cache: None,
                citations: vec![],
            }],
        };

        inner.turns = vec![compacted_turn];
        inner.pinned = pinned.clone();
        inner.states.clear();
        inner.states.push(ContextState {
            id,
            summary: summary.to_string(),
            pinned,
        });

        id
    }

    /// Materializes a previously committed context state, if it exists.
    pub fn materialize(&self, id: ContextStateId) -> Option<Rendered> {
        let inner = self.inner.lock().unwrap();
        inner
            .states
            .iter()
            .find(|s| s.id == id)
            .map(|state| Rendered {
                text: render_state_text(&state.summary, &state.pinned),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use roundhouse_provider::{ContentBlock, Message, MessageRole};

    #[test]
    fn token_count_uses_bytes_div_four_ceiling() {
        // 0..4 bytes -> 1 token, 4..8 -> 2, etc.
        assert_eq!(Rendered { text: "".into() }.token_count(), 0);
        assert_eq!(Rendered { text: "a".into() }.token_count(), 1);
        assert_eq!(
            Rendered {
                text: "abcd".into()
            }
            .token_count(),
            1
        );
        assert_eq!(
            Rendered {
                text: "abcde".into()
            }
            .token_count(),
            2
        );
    }

    #[test]
    fn split_pinned_isolation() {
        let msg = Message {
            role: MessageRole::User,
            content: vec![ContentBlock::Text {
                text: "hi".into(),
                cache: None,
                citations: vec![],
            }],
        };
        let ctx = WorkingContext::new(vec![msg.clone()], vec!["pin".into()]);
        let (summarizable, pinned) = ctx.split_pinned();
        assert_eq!(summarizable.len(), 1);
        assert_eq!(pinned, vec!["pin".to_string()]);
    }

    #[test]
    fn candidate_token_count_matches_materialized_state() {
        let summary = "short summary";
        let pinned = vec!["line one".to_string(), "line two".to_string()];
        let ctx = WorkingContext::new(vec![], vec![]);
        let id = ctx.commit_compaction(summary, pinned.clone(), TokenBudget(1_000));
        let rendered = ctx.materialize(id).unwrap();
        assert_eq!(
            WorkingContext::candidate_token_count(summary, &pinned),
            rendered.token_count()
        );
    }
}
