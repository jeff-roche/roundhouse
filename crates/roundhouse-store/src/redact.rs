//! Aho-Corasick redaction at the persistence boundary (§6.7): a live secret value, once
//! it appears in one of the `EventPayload` fields `Redactor::redact_event_payload` actually
//! covers (see that method's doc comment for the exact list and, just as importantly, what
//! is NOT yet covered), must never physically reach the SQLite `events.payload` column.
//! Redaction runs inside `writer::append_one`/`append_batch`, BEFORE `serialize_payload` —
//! the stored row is always the already-redacted form, never the original.
//!
//! `EventWriter` holds a hot-swappable `Redactor` (`arc_swap::ArcSwap`, see `writer.rs`)
//! so the live secret-value list can be updated without restarting the writer task or
//! interrupting in-flight appends.
//!
//! This module also has a second, structurally different mechanism living alongside the
//! persistence-boundary pass: `Redactor::scan_outbound`/`SecretLeakDisposition`, which
//! never mutate a payload — they inspect an outbound provider payload and return a
//! policy-style `Ask`/`Deny` disposition. See `scan_outbound`'s own doc comment for its
//! (currently unwired) integration status.

use roundhouse_core::{
    Delta, EventPayload, NoteLevel, SessionId, TaskError, TaskId, TaskRunner, Timestamp,
};

use crate::pool::StorePool;
use crate::writer::EventWriter;
use crate::StoreError;

const REDACTED_PLACEHOLDER: &str = "[REDACTED]";

/// An Aho-Corasick automaton over live secret values. `redact`/`redact_event_payload` are
/// pure (never touch the database themselves) — the persistence-boundary guarantee comes
/// from *where* they're called (`writer::append_one`/`append_batch`, before
/// `serialize_payload`), not from anything in this type.
///
/// Two known, tracked gaps in what's actually implemented, vs. §6.7's frozen description:
///
/// - **Lossy against transformed secrets** (base64-encoded, chunk-split across multiple
///   deltas, etc.) — this is an exact-substring match over known live values, not a
///   semantic secret detector.
/// - **Literal-value matching only.** §6.7 describes the automaton as running "over live
///   secret values PLUS high-confidence patterns" (e.g. regex-shaped detection of
///   API-key-looking strings that were never registered as a known live value). Only the
///   literal-value half is implemented here — there is no pattern-based/heuristic
///   detection anywhere in this type. A string that looks exactly like a secret but was
///   never passed to `build` will not be redacted.
///
/// Neither gap is silent — both are documented here rather than fixed by this task; closing
/// them is real follow-up work, not something this type quietly claims to already do.
pub struct Redactor {
    automaton: aho_corasick::AhoCorasick,
}

impl Redactor {
    /// Built over live secret values. An empty slice (or a slice containing only
    /// empty-string values, which are filtered out before reaching the automaton — see
    /// below) produces an automaton that matches nothing — the safe default `spawn_writer`
    /// installs before any real secret value is known (see `writer.rs`), so redaction is
    /// always "on" (just a no-op) rather than absent until explicitly configured.
    ///
    /// Uses `MatchKind::LeftmostLongest` (not Aho-Corasick's default
    /// `LeftmostFirst`/standard semantics): with the default, two patterns where one is a
    /// prefix of the other (e.g. an old and new secret value that happen to share a
    /// prefix, plausible after a key rotation) can match the SHORTER pattern first and
    /// leave the longer secret's distinguishing suffix fully exposed in the output.
    /// Leftmost-longest always prefers the longest match starting at a given position,
    /// closing that gap.
    ///
    /// Empty-string values are filtered out before construction: an empty pattern matches
    /// at every position in the input, which degrades `redact` pathologically (observed:
    /// ~20x output amplification and near-total mangling of unrelated text on realistic
    /// input) rather than simply being a harmless no-op match. A secret value that
    /// resolves to an empty string is a plausible real input (e.g. an unset env var), so
    /// this is filtered defensively rather than assumed never to happen.
    pub fn build(secret_values: &[String]) -> Self {
        let patterns: Vec<&String> = secret_values.iter().filter(|s| !s.is_empty()).collect();
        let automaton = aho_corasick::AhoCorasickBuilder::new()
            .match_kind(aho_corasick::MatchKind::LeftmostLongest)
            .build(patterns)
            .expect("valid patterns");
        Self { automaton }
    }

    /// Replaces every match of a known secret value in `text` with `[REDACTED]`. Returns
    /// the redacted text and the number of matches replaced — 0 is a legitimate, visible
    /// result ("nothing matched"), not an error.
    pub fn redact(&self, text: &str) -> (String, u32) {
        let mut count = 0u32;
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        for m in self.automaton.find_iter(text) {
            out.push_str(&text[last..m.start()]);
            out.push_str(REDACTED_PLACEHOLDER);
            last = m.end();
            count += 1;
        }
        out.push_str(&text[last..]);
        (out, count)
    }

    /// Covers exactly three fields today: `TaskDelta{delta: Delta::Text}` (streamed
    /// model/tool text output), `Note.text`, and `TaskFailed.error.message` (an error
    /// message that quotes back part of the failing input, e.g. a shell command).
    ///
    /// **Known, tracked gap — NOT a safety property, just an honest inventory of what's
    /// unprotected today:** every other `EventPayload` field that can carry free text
    /// passes through completely unredacted (redaction count 0), including
    /// `TaskCreated.input` (a task's actual prompt/command, when `TaskInput::Text`),
    /// `TaskCompleted.output` (a task's actual output, same shape), `Delta::Thinking.text`,
    /// `Delta::ToolArgs.fragment`, `Delta::Stdout`/`Delta::Stderr` (raw byte arrays —
    /// substring text-matching doesn't apply to them the same way and would need a
    /// different approach), `TaskFailed.error.category`, `Message{envelope}`,
    /// `SessionStateChanged.reason`, `TaskSuspended.reason`, and `SessionCreated.spec`. A
    /// live secret in any of those fields reaches the append-only log unredacted and
    /// permanently, the moment something actually writes real (non-empty, non-placeholder)
    /// text into them. Not exploitable in the shipped daemon today only because current
    /// production code doesn't yet emit real text into most of these fields — expanding
    /// coverage to close this gap is real follow-up work, not something this method's
    /// current match arms claim to already handle.
    pub fn redact_event_payload(&self, payload: EventPayload) -> (EventPayload, u32) {
        match payload {
            EventPayload::TaskDelta {
                delta: Delta::Text { text },
            } => {
                let (redacted, n) = self.redact(&text);
                (
                    EventPayload::TaskDelta {
                        delta: Delta::Text { text: redacted },
                    },
                    n,
                )
            }
            EventPayload::Note { level, text } => {
                let (redacted, n) = self.redact(&text);
                (
                    EventPayload::Note {
                        level,
                        text: redacted,
                    },
                    n,
                )
            }
            EventPayload::TaskFailed { error, retryable } => {
                let (redacted_message, n) = self.redact(&error.message);
                (
                    EventPayload::TaskFailed {
                        error: TaskError {
                            message: redacted_message,
                            category: error.category,
                        },
                        retryable,
                    },
                    n,
                )
            }
            other => (other, 0),
        }
    }

    /// Runs the same automaton against an outbound provider payload — never mutates it
    /// (unlike `redact_event_payload`, which rewrites what gets stored): the point here is
    /// to decide whether the request may leave the daemon at all, not to launder it.
    ///
    /// A detected secret is recorded as a visible `Note` event (`NoteLevel::Warn`) — Phase
    /// 0's frozen `EventPayload` has no dedicated `SecretLeak` variant, so this is the
    /// audit-trail-visible stand-in (§6.7) — and returns a `SecretLeakDisposition` the
    /// caller must act on: `Ask` by default, `Deny` under `--profile hardened`.
    ///
    /// **Scope note (Task 19 addendum, Ruling 8):** the real integration point this is
    /// designed for, `roundhouse-provider::fallback::infer_with_fallback`, has no store
    /// handle today and is not called from any production code path yet. This method is
    /// therefore a correctly-shaped, independently-testable mechanism — not wired into
    /// that call site. A `Some(Deny)` is meant to short-circuit the outbound send entirely
    /// and a `Some(Ask)` is meant to route through `roundhouse-policy`'s
    /// `suspend_for_approval` path; wiring that up is explicit follow-up work for whichever
    /// task first makes `infer_with_fallback` a real, called function, not this one.
    pub async fn scan_outbound(
        &self,
        runner: &TaskRunner,
        writer: &EventWriter,
        session_id: SessionId,
        payload: &str,
        hardened: bool,
    ) -> Result<Option<SecretLeakDisposition>, StoreError> {
        let (_, count) = self.redact(payload);
        if count == 0 {
            return Ok(None);
        }

        let disposition = if hardened {
            SecretLeakDisposition::Deny
        } else {
            SecretLeakDisposition::Ask
        };
        // Wording must stay accurate for both dispositions: `Deny` genuinely blocks the
        // send, but `Ask` does not — it routes to a human-approval flow, it does not stop
        // the request outright. Claiming "blocked" in the `Ask` case would misdescribe
        // what actually happens in this durably persisted, UI-visible event.
        let disposition_text = match disposition {
            SecretLeakDisposition::Deny => "blocked (denied under --profile hardened)",
            SecretLeakDisposition::Ask => "held pending human approval before sending",
        };
        let event = runner.record_note(
            session_id,
            0, // placeholder seq — EventWriter::append assigns the real one
            now_ts(),
            None,
            NoteLevel::Warn,
            format!(
                "SecretLeak: outbound payload to provider matched {count} known secret \
                 value(s); {disposition_text}"
            ),
            1, // schema_v
        );
        writer.append(event).await?;

        Ok(Some(disposition))
    }
}

/// §6.7: "The same redactor runs on outbound provider payloads; a detected secret in a
/// prompt is a `SecretLeak` event (`Ask` by default, `Deny` under `--profile hardened`)."
/// Same `Ask`/`Deny` vocabulary as every other policy decision in this plan
/// (`roundhouse-policy`'s `PolicyDecision`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretLeakDisposition {
    Ask,
    Deny,
}

/// `Timestamp` (Phase 0, frozen) exposes only `from_unix_nanos`/`as_unix_nanos` — no
/// `now()`. Same pattern this crate's own tests already use (`tests/append.rs`,
/// `tests/session_events.rs`).
fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

/// Test-only escape hatch: reads the raw, unprocessed `payload` JSON column directly,
/// bypassing normal deserialization — the only way to prove a leaked secret value never
/// physically landed in the stored row, rather than merely trusting the redacted
/// `EventPayload` constructed in memory. `#[doc(hidden)] pub` (not `pub(crate)`) because
/// `tests/redaction.rs` is compiled as a separate crate and needs to reach it; this is
/// deliberately not part of this crate's public API surface.
///
/// Returns the most recently appended row for `(session_id, task_id)` (highest `seq`) —
/// a task typically has more than one event (`TaskCreated`, then `TaskDelta`/`Note`...),
/// and callers of this helper care about the payload they just appended, not an arbitrary
/// one among possibly several matching rows.
#[doc(hidden)]
pub async fn debug_read_raw_payload_text(
    store: &StorePool,
    session_id: SessionId,
    task_id: TaskId,
) -> Result<String, StoreError> {
    let conn = store.pool.get().await?;
    let session_id_str = session_id.to_string();
    let task_id_str = task_id.to_string();

    let row_result = conn
        .interact(move |c| -> Result<String, rusqlite::Error> {
            c.query_row(
                "SELECT payload FROM events WHERE session_id = ?1 AND task_id = ?2 \
                 ORDER BY seq DESC LIMIT 1",
                rusqlite::params![session_id_str, task_id_str],
                |row| row.get(0),
            )
        })
        .await
        .map_err(|e| StoreError::Interact(e.to_string()))?;

    row_result.map_err(StoreError::Sqlite)
}
