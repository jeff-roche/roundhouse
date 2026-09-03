//! Cohere v2 `/v2/chat` wire-format codec. The task brief calls this surface
//! "Not spec-gated... a stable, well-documented shape," so this task doesn't
//! carry the formal fetched-OpenAPI-spec-verification gate/decision-doc the
//! other Phase 6 codec tasks do -- but REALITY-CORRECTIONS §13b names this
//! task explicitly ("binding on every remaining codec task (6, 7, 8, ...)"),
//! so every wire literal `decode.rs` matches on was still checked against the
//! real, fetched Cohere API reference rather than trusted from memory or the
//! task brief's unverified sketch:
//!
//! - `https://docs.cohere.com/reference/chat-stream` (fetched 2026-09-02):
//!   the 11 real SSE event `type` values -- `message-start`, `content-start`,
//!   `content-delta`, `content-end`, `citation-start`, `citation-end`,
//!   `tool-plan-delta`, `tool-call-start`, `tool-call-delta`,
//!   `tool-call-end`, `message-end` -- and verbatim example JSON for each,
//!   e.g. `content-start`: `{"delta":{"message":{"content":{"text":"",
//!   "type":"text"}}},"index":0,"type":"content-start"}`; `tool-call-start`:
//!   `{"delta":{"message":{"tool_calls":{"function":{"arguments":"","name":
//!   "..."},"id":"...","type":"function"}}},"index":0,"type":"tool-call-start"}`.
//!   Citations reuse the SAME `index` as the content block they annotate
//!   (verified from the fetched `citation-start` example), never a fresh one.
//! - `https://docs.cohere.com/reference/chat` (fetched 2026-09-02): the
//!   `finish_reason` enum's 6 real values (`COMPLETE`, `STOP_SEQUENCE`,
//!   `MAX_TOKENS`, `TOOL_CALL`, `ERROR`, `TIMEOUT`); the `messages[]`
//!   role/content shapes for `user`/`assistant`/`system`/`tool`, including
//!   the assistant content array's `"type": "thinking"` block (round-trips a
//!   prior turn's reasoning, unlike this crate's `google_genai`/
//!   `openai_responses` codecs, which fail closed on `Thinking` for their own
//!   documented reasons); the `tool_choice` enum's only two real values
//!   (`REQUIRED`/`NONE` -- there is no per-tool named-forcing mechanism, so
//!   `ToolChoice::Named` fails closed rather than silently widening the
//!   request into `"REQUIRED"`, per fix round 1's L4); and the `thinking`
//!   request field's shape (`{"type": "enabled"|"disabled", "token_budget":
//!   int}`).
//! - `https://docs.cohere.com/reference/errors` (fetched 2026-09-02): real
//!   Cohere error bodies are a plain `{"message": "..."}` string with no
//!   machine-readable code/type field at all -- see `profiles/cohere-v2.toml`'s
//!   own doc comment on what that means for this codec's `[errors]` table
//!   (deliberately empty, per fix round 1's L5).
//!
//! **A note for institutional memory (fix round 1, L12):** a `WebSearch`
//! query made during this task's initial verification pass returned a
//! plausible-looking summary claiming `finish_reason`'s real values are
//! LOWERCASE (`complete`, `max_tokens`, ...), sourced from a stale or
//! different page than the live reference. Re-fetching
//! `docs.cohere.com/reference/chat` directly and reading its own schema
//! section (not a search-engine summary of it) showed the real values are
//! UPPERCASE (`COMPLETE`, `MAX_TOKENS`, ...) -- confirmed independently by
//! two reviewers in fix round 1. The lesson: a search snippet is not the
//! same source as the page it summarizes, and a schema's own authoritative
//! enum beats any prose describing it, search-engine-summarized prose
//! included. The verified values are already committed in this module's
//! vendored `.txt` lists and doc comments; this paragraph exists only so a
//! future reader doesn't have to relearn why the check mattered.
//!
//! See `tests/cohere_v2_wire_literal_tripwire.rs` for the vendored literal
//! lists these values are checked against, and `tests/conformance_cohere_v2.rs`'s
//! module doc for where each cassette's bytes come from.
pub mod decode;
pub mod encode;
mod provider;

pub use provider::CohereV2Provider;

// Fix round 4, R4: `redact_transport_error_text` (and its `EMBEDDED_URL`
// regex, and its tests) used to live here. `openai_chat`'s `decode.rs` had
// its own, weaker claim -- it said its `Transport`-kind message was
// redacted against a full embedded URL (query string, userinfo) but only
// ever called `crate::audit::redact_error_body`, which doesn't strip either.
// Hoisted to `crate::audit::redact_transport_error_text` (a pure move, no
// logic changes -- see that module for the function and its tests, moved
// verbatim) so both codecs share the one real implementation instead of
// `openai_chat` growing a second, weaker one or the claim staying false.
// `decode.rs` and `provider.rs` in this module now import it from there.
