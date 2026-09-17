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
    Delta, EventPayload, NoteLevel, SessionId, TaskError, TaskId, TaskInput, TaskOutput,
    TaskRunner, Timestamp,
};

use crate::pool::StorePool;
use crate::writer::EventWriter;
use crate::StoreError;

const REDACTED_PLACEHOLDER: &str = "[REDACTED]";

/// Recursion depth cap for [`Redactor::redact_json_value`] (fix round B, M2
/// / ruling W1-R69) — see that method's own doc comment for the reproduced
/// stack overflow (depth 10,000) this closes and why the cap sits well
/// under `serde_json`'s own default parse recursion limit (128) rather than
/// relying on it.
const MAX_JSON_REDACT_DEPTH: usize = 64;

/// An Aho-Corasick automaton over live secret values. `redact`/`redact_event_payload` are
/// pure (never touch the database themselves) — the persistence-boundary guarantee comes
/// from *where* they're called (`writer::append_one`/`append_batch`, before
/// `serialize_payload`), not from anything in this type.
///
/// Two known, tracked gaps in what's actually implemented, vs. §6.7's frozen description:
///
/// - **Lossy against transformed secrets** (base64-encoded, etc.) — this is an
///   exact-substring match over known live values, not a semantic secret detector. The
///   chunk-split-across-multiple-deltas half of this gap (a secret straddling the boundary
///   between two streamed deltas, so neither delta's own payload contains the full match)
///   is closed for streaming callers by [`Self::safe_split_len`] plus
///   `EventWriter::redaction_holdback` (Task 19b, Phase 8 Task 19 lane B): a caller that
///   holds back at least `redaction_holdback()` bytes at every non-final split point, and
///   picks the split itself via `safe_split_len`, never emits a delta boundary strictly
///   inside a match. Base64-/otherwise-transformed secrets remain unaddressed by either
///   mechanism.
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
    /// The longest live secret value's byte length (0 when built with no non-empty
    /// patterns). Computed once here, at `build`, rather than walked out of the automaton
    /// on every call — `EventWriter::redaction_holdback` reads it via
    /// [`Self::max_pattern_len`] on every streamed flush, so it needs to be O(1).
    max_pattern_len: usize,
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
        let max_pattern_len = patterns.iter().map(|s| s.len()).max().unwrap_or(0);
        let automaton = aho_corasick::AhoCorasickBuilder::new()
            .match_kind(aho_corasick::MatchKind::LeftmostLongest)
            .build(patterns)
            .expect("valid patterns");
        Self {
            automaton,
            max_pattern_len,
        }
    }

    /// The longest live secret value's byte length, 0 for an empty/no-op redactor. See the
    /// field's own doc comment for why this is precomputed rather than derived on demand.
    pub(crate) fn max_pattern_len(&self) -> usize {
        self.max_pattern_len
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

    /// Byte-oriented counterpart to [`Self::redact`], for payload shapes that carry raw
    /// bytes rather than validated UTF-8 text (`Delta::Stdout`/`Delta::Stderr`): shell
    /// output can legitimately contain invalid UTF-8 sequences (binary output, a truncated
    /// multi-byte character at a chunk boundary, etc.), and this must redact known secret
    /// values in it without ever assuming (or requiring) the input decodes as `str`. Uses
    /// the same automaton, `MatchKind::LeftmostLongest` semantics, and `[REDACTED]`
    /// placeholder as `redact` — only the haystack/output type differs (`&[u8]`/`Vec<u8>`
    /// instead of `&str`/`String`).
    pub fn redact_bytes(&self, bytes: &[u8]) -> (Vec<u8>, u32) {
        let mut count = 0u32;
        let mut out = Vec::with_capacity(bytes.len());
        let mut last = 0;
        for m in self.automaton.find_iter(bytes) {
            out.extend_from_slice(&bytes[last..m.start()]);
            out.extend_from_slice(REDACTED_PLACEHOLDER.as_bytes());
            last = m.end();
            count += 1;
        }
        out.extend_from_slice(&bytes[last..]);
        (out, count)
    }

    /// Returns the largest `k <= min(max, bytes.len())` such that no automaton match over
    /// the WHOLE of `bytes` has `start < k < end` — i.e., a streaming caller that flushes
    /// `bytes[..k]` now and holds back `bytes[k..]` for the next chunk never cuts a live
    /// secret in half at the boundary.
    ///
    /// **Why holding back `redaction_holdback()` bytes alone isn't enough, and why this
    /// exists:** holding back the longest pattern's length minus one only bounds how far a
    /// match can straddle a FIXED boundary chosen without looking at the buffered bytes —
    /// it does not tell the caller where to put that boundary. A secret can still lie
    /// wholly inside the bytes a caller was about to flush and straddle whatever split
    /// point it naively picked (e.g. a fixed chunk size), landing half in one delta and
    /// half in the next; per-payload redaction (`redact`/`redact_event_payload`) matches
    /// neither half. This method picks the split point itself, so that can't happen.
    ///
    /// **Correctness argument (leftmost-longest, non-overlapping matches):**
    /// `AhoCorasick::find_iter` yields matches in strictly increasing `start` order, and
    /// (per its own contract) never overlapping — so `matches[i+1].start() >=
    /// matches[i].end() > matches[i].start()`. A single ordered pass therefore suffices:
    /// walk matches in order, and the moment a match's `start()` is `>= k` (the current
    /// candidate), every later match's `start()` is too (strictly increasing), so none of
    /// them can straddle `k` either — stop. Otherwise, if the match's `end()` is `> k`, it
    /// straddles the candidate; move `k` down to that match's `start()`. Because
    /// `matches[i+1].start() >= matches[i].end() > matches[i].start()` and we just set
    /// `k = matches[i].start()`, the very next match already satisfies the stop condition
    /// (`matches[i+1].start() > k`), so at most one adjustment ever happens.
    ///
    /// **Why callers can rely on this instead of re-scanning the NEXT chunk too:** any
    /// match that could extend past `bytes` (i.e. whose true end lies beyond what's
    /// buffered so far) necessarily starts at or after `bytes.len() - holdback` — a shorter
    /// match can't reach further than `holdback` (`redaction_holdback()`) bytes past its
    /// start. So as long as a caller only ever asks for `max <= bytes.len() - holdback`
    /// (never releasing the held-back tail early), a match this method can already see in
    /// full is the only kind that can straddle the returned `k` — there is nothing hiding
    /// just past the end of `bytes` that this pass could miss.
    pub fn safe_split_len(&self, bytes: &[u8], max: usize) -> usize {
        let mut k = max.min(bytes.len());
        for m in self.automaton.find_iter(bytes) {
            if m.start() >= k {
                break;
            }
            if m.end() > k {
                k = m.start();
            }
        }
        k
    }

    /// Covers six fields as of this merge (fix round A, Phase 7 Task 5, plus Phase 7
    /// Task 13b): `TaskDelta{delta: Delta::Text}` (streamed model/tool text output),
    /// `Note.text`, `TaskFailed.error.message` (an error message that quotes back part
    /// of the failing input, e.g. a shell command), `TaskCreated.input` (both
    /// `TaskInput::Text` and, recursively over every string leaf, `TaskInput::Json` —
    /// see [`Self::redact_json_value`]), `TaskCompleted.output` (both
    /// `TaskOutput::Text` and, likewise recursively, `TaskOutput::Json`), and
    /// `Loss.description` (free text that can carry a provider error message verbatim).
    /// `Loss.kind` is a short machine-stable tag, never free text, and is left
    /// untouched.
    ///
    /// **`TaskCreated`/`TaskCompleted` expansion, and why now:** the original version
    /// of this doc comment listed both as an open gap, "not exploitable ... only
    /// because current production code doesn't yet emit real text into most of these
    /// fields." `roundhouse-engine`'s agent-loop dispatch (`agent_loop.rs`'s
    /// `dispatch_builtin`) is exactly that follow-up: it records a model's raw tool-call
    /// arguments as `TaskInput::Json` (whole file contents on `write`, for instance) and
    /// a tool's result as `TaskOutput::Text` (full command stdout/stderr on `shell`) —
    /// real, model-influenced free text landing in this append-only, unscrubbable log
    /// for the first time. This closes that gap for those two fields.
    ///
    /// **Object KEYS in a `TaskInput`/`TaskOutput::Json` value are NOT redacted, only
    /// string VALUES (recursively, through arrays and nested objects).** The decision
    /// is a deliberate, accepted trade-off; **an earlier version of this comment's
    /// STATED REASON for it was factually wrong, and is corrected here (fix round B, M3
    /// / ruling W1-R69 — the third time this lane has hit a comment that misstates a
    /// security property, after W1-R39 and Task 6's M3).** The earlier claim was that
    /// object keys are "this codebase's own fixed field names … never model-echoed
    /// content a live secret could appear in." That is false: `dispatch_builtin`
    /// records the model's ENTIRE raw JSON argument object verbatim
    /// (`TaskInput::Json(input.clone())`) — nothing validates that it contains only the
    /// schema's named keys, so a model-authored object with an EXTRA key
    /// (`{"path": "x", "sk-live-abc123": "irrelevant"}`) would carry that key straight
    /// into the log, unredacted, verbatim, demonstrated. The decision to still not
    /// redact keys stands on a narrower, honest basis instead: redacting a key would
    /// corrupt the JSON's own shape (a key literally matching a secret substring stops
    /// being a stable, round-trippable field name), and no built-in tool's schema today
    /// gives the model a way to CHOOSE an arbitrary key that then gets read back by
    /// name — an extra key is inert cargo, not something anything downstream
    /// interprets. **That residual narrows to a real gap the moment MCP tool arguments
    /// (round C) make model-chosen keys routine** (an MCP tool's input schema can name
    /// an object-valued parameter with caller-chosen keys) — revisit then, not assumed
    /// safe indefinitely.
    ///
    /// **Known, tracked gap — NOT a safety property, just an honest inventory of what's
    /// still unprotected:** `TaskFailed.error.category`, `Message{envelope}`,
    /// `SessionStateChanged.reason`, `TaskSuspended.reason`, and `SessionCreated.spec`
    /// still pass through completely unredacted. A live secret in any of those fields
    /// reaches the append-only log unredacted and permanently, the moment something
    /// actually writes real (non-empty, non-placeholder) text into them.
    ///
    /// **Closed by this method (Phase 8 Task 19 lane B, Task 5):** `Delta::Thinking.text`
    /// and `Delta::ToolArgs.fragment` go through [`Self::redact`] like `Delta::Text`;
    /// `Delta::Stdout.bytes`/`Delta::Stderr.bytes` go through [`Self::redact_bytes`]
    /// instead, since raw shell output is not guaranteed to be valid UTF-8 and
    /// substring text-matching over `&str` doesn't apply to it directly. `Delta::Child`
    /// (a pointer, not text) and `Delta::Blob` (a content hash, not inline content — see
    /// this method's `TaskInput`/`TaskOutput::Blob` handling below for the same reasoning)
    /// are not scanned, matching every other blob-reference shape in this method.
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
            EventPayload::TaskDelta {
                delta: Delta::Thinking { text, signature },
            } => {
                let (redacted, n) = self.redact(&text);
                (
                    EventPayload::TaskDelta {
                        delta: Delta::Thinking {
                            text: redacted,
                            signature,
                        },
                    },
                    n,
                )
            }
            EventPayload::TaskDelta {
                delta: Delta::ToolArgs { fragment },
            } => {
                let (redacted, n) = self.redact(&fragment);
                (
                    EventPayload::TaskDelta {
                        delta: Delta::ToolArgs { fragment: redacted },
                    },
                    n,
                )
            }
            EventPayload::TaskDelta {
                delta: Delta::Stdout { bytes },
            } => {
                let (redacted, n) = self.redact_bytes(&bytes);
                (
                    EventPayload::TaskDelta {
                        delta: Delta::Stdout {
                            bytes: redacted.into(),
                        },
                    },
                    n,
                )
            }
            EventPayload::TaskDelta {
                delta: Delta::Stderr { bytes },
            } => {
                let (redacted, n) = self.redact_bytes(&bytes);
                (
                    EventPayload::TaskDelta {
                        delta: Delta::Stderr {
                            bytes: redacted.into(),
                        },
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
            EventPayload::TaskCreated {
                kind,
                parent,
                origin,
                input,
            } => {
                let (input, n) = match input {
                    TaskInput::Text(text) => {
                        let (redacted, n) = self.redact(&text);
                        (TaskInput::Text(redacted), n)
                    }
                    TaskInput::Json(value) => {
                        let (redacted, n) = self.redact_json_value(value);
                        (TaskInput::Json(redacted), n)
                    }
                    // No text to scan in a blob reference (it's a content
                    // hash + size, not inline text).
                    other @ TaskInput::Blob(_) => (other, 0),
                };
                (
                    EventPayload::TaskCreated {
                        kind,
                        parent,
                        origin,
                        input,
                    },
                    n,
                )
            }
            // Phase 7 Task 13b: `description` carries provider error text verbatim (e.g.
            // an upstream response body quoting back part of the request) — the same
            // free-text shape `TaskFailed.error.message` is redacted above. `kind` is a
            // short machine-stable tag (never free text — see `LossKind::Other`'s
            // handling in `roundhouse-provider`) and is left untouched.
            EventPayload::Loss {
                kind,
                description,
                blocks_affected,
            } => {
                let (redacted_description, n) = self.redact(&description);
                (
                    EventPayload::Loss {
                        kind,
                        description: redacted_description,
                        blocks_affected,
                    },
                    n,
                )
            }
            EventPayload::TaskCompleted {
                output,
                usage,
                trust,
            } => {
                let (output, n) = match output {
                    TaskOutput::Text(text) => {
                        let (redacted, n) = self.redact(&text);
                        (TaskOutput::Text(redacted), n)
                    }
                    TaskOutput::Json(value) => {
                        let (redacted, n) = self.redact_json_value(value);
                        (TaskOutput::Json(redacted), n)
                    }
                    other @ TaskOutput::Blob(_) => (other, 0),
                };
                (
                    EventPayload::TaskCompleted {
                        output,
                        usage,
                        trust,
                    },
                    n,
                )
            }
            other => (other, 0),
        }
    }

    /// Recursively redacts every string LEAF in a `serde_json::Value` — object/array
    /// structure and non-string scalars (numbers, bools, null) pass through unchanged,
    /// and object KEYS are deliberately never touched (see
    /// [`Self::redact_event_payload`]'s doc comment for why). Used for
    /// `TaskInput`/`TaskOutput::Json`, the two JSON-carrying payload shapes this
    /// module's Aho-Corasick substring automaton needs to reach inside of rather than
    /// skip over.
    fn redact_json_value(&self, value: serde_json::Value) -> (serde_json::Value, u32) {
        self.redact_json_value_at_depth(value, 0)
    }

    /// `depth`-tracking implementation of [`Self::redact_json_value`] (fix
    /// round B, M2 / ruling W1-R69): reproduced a real stack overflow at
    /// recursion depth 10,000 with no explicit bound of our own — today's
    /// safety rests entirely on `serde_json`'s own default parse recursion
    /// limit (128, confirmed: 120 parses, 128/200/5000 are rejected before
    /// this method ever runs), which is an undocumented dependency on a
    /// third-party default for a check on the hot path of every event
    /// write. [`MAX_JSON_REDACT_DEPTH`] is deliberately well under that
    /// limit, so this bound is reached first and on our own terms.
    ///
    /// At the cap, this does NOT recurse, serialize, or otherwise walk
    /// whatever remains below it — an earlier version of this fix tried
    /// serializing the remaining sub-value to a flat string and redacting
    /// that, but `serde_json::to_string` is ITSELF unbounded recursion over
    /// the very structure that's already too deep, so that "fix" merely
    /// moved the same stack overflow one call frame down (caught by this
    /// method's own test). Instead, the remaining sub-value is discarded
    /// outright and replaced with a fixed placeholder string — O(1), no
    /// further traversal of any kind, so no depth of nesting below the cap
    /// can affect this method's own stack usage. This means a secret nested
    /// past the cap is not redacted so much as REMOVED ENTIRELY, never
    /// round-tripped as structured JSON. Not reachable by any built-in tool
    /// call today (their JSON shapes are shallow, fixed-schema objects —
    /// see this module's `TaskCreated`/`TaskCompleted` doc comment), so
    /// this is a resource bound holding a line, not a live threat this fix
    /// round found exploited.
    fn redact_json_value_at_depth(
        &self,
        value: serde_json::Value,
        depth: usize,
    ) -> (serde_json::Value, u32) {
        if depth >= MAX_JSON_REDACT_DEPTH {
            // `value` may still be arbitrarily deep below this point.
            // `serde_json::Value` has no custom `Drop` (confirmed by
            // reading its source), so letting it fall out of scope here
            // and drop normally would hit the SAME stack overflow this
            // whole cap exists to prevent — verified empirically on an
            // explicit 2 MiB thread (the size `cargo test` gives each
            // test): a bare `drop()` of an already-built depth-10,000
            // `Value`, with NO redaction logic involved at all, survives;
            // a depth-50,000 one aborts (fix round C1, ruling W1-R75 — a
            // round B comment here cited depth 10,000 as the overflow
            // point, which does not reproduce; that number came from a
            // different, unrelated overflow in how round B's own TEST
            // fixture was built, not from dropping an already-built
            // value — see the test's own doc comment for the corrected
            // mechanism). The exact threshold is unimportant; what matters
            // is that ordinary recursive `Drop` on a sufficiently deep
            // value does overflow, at a depth this cap makes unreachable
            // in the first place. Tear it down iteratively, off the call
            // stack, instead of letting normal `Drop` recurse into it.
            drop_iteratively(value);
            return (
                serde_json::Value::String(
                    "[TRUNCATED: exceeded the JSON redaction depth cap]".to_string(),
                ),
                0,
            );
        }
        match value {
            serde_json::Value::String(s) => {
                let (redacted, n) = self.redact(&s);
                (serde_json::Value::String(redacted), n)
            }
            serde_json::Value::Array(items) => {
                let mut total = 0u32;
                let redacted = items
                    .into_iter()
                    .map(|v| {
                        let (v, n) = self.redact_json_value_at_depth(v, depth + 1);
                        total += n;
                        v
                    })
                    .collect();
                (serde_json::Value::Array(redacted), total)
            }
            serde_json::Value::Object(map) => {
                let mut total = 0u32;
                let redacted = map
                    .into_iter()
                    .map(|(k, v)| {
                        let (v, n) = self.redact_json_value_at_depth(v, depth + 1);
                        total += n;
                        (k, v)
                    })
                    .collect();
                (serde_json::Value::Object(redacted), total)
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

/// Tears down a `serde_json::Value` OFF the call stack, one level at a time,
/// via an explicit heap-allocated work-list — never Rust's default
/// (recursive) `Drop`. `Redactor::redact_json_value_at_depth` (M2, fix
/// round B, ruling W1-R69) uses this when it discards a sub-value at the
/// depth cap: `Value` has no custom `Drop` of its own, so a value that is
/// still arbitrarily deep below the cap would otherwise overflow the stack
/// on ordinary drop, defeating the entire point of capping traversal depth
/// in the first place (verified empirically, not assumed, on an explicit
/// 2 MiB thread: an already-built depth-10,000 `Value` survives a bare
/// `drop()`; an already-built depth-50,000 one aborts. See
/// `redact_json_value_at_depth`'s own doc comment, and the corresponding
/// test's, for fix round C1's correction of an earlier, wrong number here).
fn drop_iteratively(value: serde_json::Value) {
    let mut stack = vec![value];
    while let Some(v) = stack.pop() {
        match v {
            serde_json::Value::Array(items) => stack.extend(items),
            serde_json::Value::Object(map) => stack.extend(map.into_values()),
            // Scalars (String/Number/Bool/Null) drop trivially — no
            // nested `Value`s to worry about.
            _ => {}
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------------------
    // redact_bytes
    // -----------------------------------------------------------------------------------

    /// The core `redact_bytes` guarantee: a secret embedded in a byte stream that is NOT
    /// valid UTF-8 (a lone continuation byte on either side of the match) must still be
    /// found and replaced — `redact_bytes` operates on `&[u8]` directly and never assumes
    /// (or requires) the input decodes as `str`, unlike `redact`.
    #[test]
    fn redact_bytes_finds_a_secret_in_non_utf8_input_and_leaves_the_rest_untouched() {
        let redactor = Redactor::build(&["sk-live-abc123".to_string()]);
        let mut bytes = vec![0x80, 0xFF]; // invalid UTF-8 on its own
        bytes.extend_from_slice(b"sk-live-abc123");
        bytes.extend_from_slice(&[0xFE]);

        let (redacted, count) = redactor.redact_bytes(&bytes);

        assert_eq!(count, 1);
        let mut expected = vec![0x80, 0xFF];
        expected.extend_from_slice(REDACTED_PLACEHOLDER.as_bytes());
        expected.push(0xFE);
        assert_eq!(
            redacted, expected,
            "the non-UTF-8 bytes surrounding the match must survive untouched, and the \
             match itself must become the placeholder"
        );
    }

    #[test]
    fn redact_bytes_returns_zero_count_and_unchanged_bytes_when_nothing_matches() {
        let redactor = Redactor::build(&["sk-live-abc123".to_string()]);
        let bytes = vec![0x80, 0xFF, b'h', b'i'];

        let (redacted, count) = redactor.redact_bytes(&bytes);

        assert_eq!(count, 0);
        assert_eq!(redacted, bytes);
    }

    // -----------------------------------------------------------------------------------
    // safe_split_len
    // -----------------------------------------------------------------------------------

    /// The motivating case: a naive fixed split point that lands strictly inside a match
    /// must be moved back to the match's own start, never left where it would cut the
    /// secret in half.
    #[test]
    fn safe_split_len_moves_a_straddling_split_back_to_the_secrets_start() {
        let redactor = Redactor::build(&["sk-live-abc123".to_string()]);
        let bytes = b"prefix sk-live-abc123 suffix";
        let secret_start = bytes
            .windows(14)
            .position(|w| w == b"sk-live-abc123")
            .unwrap();
        let secret_end = secret_start + 14;
        let naive_split = secret_start + 5; // strictly inside the match

        let k = redactor.safe_split_len(bytes, naive_split);

        assert_eq!(
            k, secret_start,
            "a split point inside the match must move back to the match's own start"
        );
        assert!(k < secret_end);
    }

    /// A secret sitting entirely BEFORE the naive split point (fully flushed either way)
    /// must not move the split at all.
    #[test]
    fn safe_split_len_is_unaffected_by_a_secret_wholly_before_the_split() {
        let redactor = Redactor::build(&["sk-live-abc123".to_string()]);
        let bytes = b"sk-live-abc123 then plain text after it";
        let naive_split = bytes.len(); // well past the match's end

        let k = redactor.safe_split_len(bytes, naive_split);

        assert_eq!(k, naive_split.min(bytes.len()));
    }

    /// A secret sitting entirely AFTER the naive split point (not flushed yet either way)
    /// must not move the split at all.
    #[test]
    fn safe_split_len_is_unaffected_by_a_secret_wholly_after_the_split() {
        let redactor = Redactor::build(&["sk-live-abc123".to_string()]);
        let bytes = b"plain text before it, then sk-live-abc123";
        let naive_split = 10; // well before the match's start

        let k = redactor.safe_split_len(bytes, naive_split);

        assert_eq!(k, naive_split);
    }

    /// An empty redactor (no live secret values) matches nothing, so the split point is
    /// always exactly `min(max, bytes.len())` — never adjusted.
    #[test]
    fn safe_split_len_with_an_empty_redactor_returns_min_of_max_and_len() {
        let redactor = Redactor::build(&[]);
        let bytes = b"arbitrary content, no secrets here";

        assert_eq!(redactor.safe_split_len(bytes, 5), 5);
        assert_eq!(redactor.safe_split_len(bytes, 1_000), bytes.len());
        assert_eq!(redactor.safe_split_len(bytes, 0), 0);
    }

    /// Non-UTF-8 input must work exactly like valid UTF-8 input — `safe_split_len` never
    /// decodes its haystack as `str`.
    #[test]
    fn safe_split_len_works_on_non_utf8_input() {
        let redactor = Redactor::build(&["sk-live-abc123".to_string()]);
        let mut bytes = vec![0x80, 0xFF];
        let secret_start = bytes.len();
        bytes.extend_from_slice(b"sk-live-abc123");
        bytes.push(0xFE);
        let naive_split = secret_start + 5; // inside the match

        let k = redactor.safe_split_len(&bytes, naive_split);

        assert_eq!(k, secret_start);
    }

    // -----------------------------------------------------------------------------------
    // redact_event_payload: the new delta kinds
    // -----------------------------------------------------------------------------------

    #[test]
    fn thinking_delta_text_is_redacted_and_counted() {
        let redactor = Redactor::build(&["sk-live-abc123".to_string()]);
        let (redacted, count) = redactor.redact_event_payload(EventPayload::TaskDelta {
            delta: Delta::Thinking {
                text: "reasoning about sk-live-abc123 now".into(),
                signature: Some("sig".into()),
            },
        });
        assert_eq!(count, 1);
        match redacted {
            EventPayload::TaskDelta {
                delta: Delta::Thinking { text, signature },
            } => {
                assert!(!text.contains("sk-live-abc123"));
                assert!(text.contains("[REDACTED]"));
                assert_eq!(
                    signature,
                    Some("sig".into()),
                    "signature must round-trip untouched"
                );
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn tool_args_delta_fragment_is_redacted_and_counted() {
        let redactor = Redactor::build(&["sk-live-abc123".to_string()]);
        let (redacted, count) = redactor.redact_event_payload(EventPayload::TaskDelta {
            delta: Delta::ToolArgs {
                fragment: "{\"key\": \"sk-live-abc123\"".into(),
            },
        });
        assert_eq!(count, 1);
        match redacted {
            EventPayload::TaskDelta {
                delta: Delta::ToolArgs { fragment },
            } => {
                assert!(!fragment.contains("sk-live-abc123"));
                assert!(fragment.contains("[REDACTED]"));
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn stdout_delta_bytes_are_redacted_and_counted_including_non_utf8() {
        let redactor = Redactor::build(&["sk-live-abc123".to_string()]);
        let mut raw = vec![0x80, 0xFF];
        raw.extend_from_slice(b"sk-live-abc123");
        let (redacted, count) = redactor.redact_event_payload(EventPayload::TaskDelta {
            delta: Delta::Stdout { bytes: raw.into() },
        });
        assert_eq!(count, 1);
        match redacted {
            EventPayload::TaskDelta {
                delta: Delta::Stdout { bytes },
            } => {
                assert!(!bytes.windows(14).any(|w| w == b"sk-live-abc123"));
                assert!(bytes
                    .windows(REDACTED_PLACEHOLDER.len())
                    .any(|w| w == REDACTED_PLACEHOLDER.as_bytes()));
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn stderr_delta_bytes_are_redacted_and_counted_including_non_utf8() {
        let redactor = Redactor::build(&["sk-live-abc123".to_string()]);
        let mut raw = vec![0x80, 0xFF];
        raw.extend_from_slice(b"sk-live-abc123");
        let (redacted, count) = redactor.redact_event_payload(EventPayload::TaskDelta {
            delta: Delta::Stderr { bytes: raw.into() },
        });
        assert_eq!(count, 1);
        match redacted {
            EventPayload::TaskDelta {
                delta: Delta::Stderr { bytes },
            } => {
                assert!(!bytes.windows(14).any(|w| w == b"sk-live-abc123"));
                assert!(bytes
                    .windows(REDACTED_PLACEHOLDER.len())
                    .any(|w| w == REDACTED_PLACEHOLDER.as_bytes()));
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn stdout_delta_with_no_match_has_zero_count_and_unchanged_bytes() {
        let redactor = Redactor::build(&["sk-live-abc123".to_string()]);
        let raw = vec![0x80, 0xFF, b'o', b'k'];
        let (redacted, count) = redactor.redact_event_payload(EventPayload::TaskDelta {
            delta: Delta::Stdout {
                bytes: raw.clone().into(),
            },
        });
        assert_eq!(count, 0);
        match redacted {
            EventPayload::TaskDelta {
                delta: Delta::Stdout { bytes },
            } => assert_eq!(bytes.as_ref(), raw.as_slice()),
            other => panic!("unexpected payload: {other:?}"),
        }
    }
}
