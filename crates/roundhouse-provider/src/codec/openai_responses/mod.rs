//! Open Responses (`github.com/openresponses/openresponses`, revision
//! `2026-04-24`) wire-format codec: request encoding, SSE streaming-response
//! decoding, and the live `Provider` adapter bridging the two over a real
//! `HttpTransport`. Verified against the real spec before being written — see
//! `docs/decisions/2026-08-27-open-responses-spec-verification.md` for the
//! fetch record and every divergence from the task brief's unverified sketch.
// `encode`/`decode` are `pub mod` (not re-exported flat) so
// `codec::openai_responses::encode::encode` and
// `codec::openai_responses::decode::decode_openai_responses_stream` are
// reachable directly, matching this task's own test files.
pub mod decode;
pub mod encode;
mod provider;

pub use provider::OpenAiResponsesProvider;
