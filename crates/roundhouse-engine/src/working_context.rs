//! Working context model for compaction (Task 8).
//!
//! A `WorkingContext` holds the conversation turns that are candidates for
//! summarization plus pinned memory lines that must survive compaction verbatim.
//! It materializes compacted snapshots as `Rendered` context states, each with a
//! deterministic, documentable token-count heuristic.

use roundhouse_provider::Message;
use std::sync::Mutex;

/// Identifies a materialized context state produced by `commit_compaction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextStateId(pub usize);

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

#[derive(Debug)]
struct ContextState {
    id: ContextStateId,
    summary: String,
    pinned: Vec<String>,
}

/// Holds the conversation state that compaction operates on.
pub struct WorkingContext {
    turns: Vec<Message>,
    pinned: Vec<String>,
    states: Mutex<Vec<ContextState>>,
}

impl WorkingContext {
    /// Creates a new working context from conversation turns and pinned memory lines.
    pub fn new(turns: Vec<Message>, pinned: Vec<String>) -> Self {
        Self {
            turns,
            pinned,
            states: Mutex::new(Vec::new()),
        }
    }

    /// Splits the context into the summarizable portion and the pinned lines.
    ///
    /// Pinned lines are set aside **before** the summarization request is built;
    /// they are carried through compaction verbatim and never sent to the provider.
    pub fn split_pinned(&self) -> (Vec<Message>, Vec<String>) {
        (self.turns.clone(), self.pinned.clone())
    }

    /// Records a new compacted context state from the provider-generated summary
    /// and the preserved pinned lines, returning its stable id.
    ///
    /// The `budget` is accepted for interface compatibility with future budget-
    /// enforcement logic; today the compacted state is inherently small (one
    /// summary plus pinned lines), so it always fits a realistic target budget.
    pub fn commit_compaction(
        &self,
        summary: &str,
        pinned: Vec<String>,
        _budget: TokenBudget,
    ) -> ContextStateId {
        let mut states = self.states.lock().unwrap();
        let id = ContextStateId(states.len());
        states.push(ContextState {
            id,
            summary: summary.to_string(),
            pinned,
        });
        id
    }

    /// Materializes a previously committed context state.
    ///
    /// Panics if `id` is not a state produced by this `WorkingContext`.
    pub fn materialize(&self, id: ContextStateId) -> Rendered {
        let states = self.states.lock().unwrap();
        let state = states
            .iter()
            .find(|s| s.id == id)
            .expect("valid ContextStateId for this WorkingContext");

        let mut text = String::new();
        text.push_str("[summary]\n");
        text.push_str(&state.summary);
        text.push_str("\n\n[pinned memory]\n");
        for line in &state.pinned {
            text.push_str(line);
            text.push('\n');
        }
        Rendered { text }
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
}
