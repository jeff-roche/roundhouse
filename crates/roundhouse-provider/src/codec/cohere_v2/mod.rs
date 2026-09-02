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
//!   (`REQUIRED`/`NONE` -- there is no per-tool named-forcing mechanism, an
//!   API limitation this codec documents at its one call site rather than
//!   silently working around); and the `thinking` request field's shape
//!   (`{"type": "enabled"|"disabled", "token_budget": int}`).
//! - `https://docs.cohere.com/reference/errors` (fetched 2026-09-02): real
//!   Cohere error bodies are a plain `{"message": "..."}` string with no
//!   machine-readable code/type field at all -- see `profiles/cohere-v2.toml`'s
//!   own doc comment on what that means for this profile's `[errors]` table.
//!
//! See `tests/cohere_v2_wire_literal_tripwire.rs` for the vendored literal
//! lists these values are checked against, and `tests/conformance_cohere_v2.rs`'s
//! module doc for where each cassette's bytes come from.
pub mod decode;
pub mod encode;
mod provider;

pub use provider::CohereV2Provider;
