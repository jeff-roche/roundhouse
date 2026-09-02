//! OpenAI `/v1/chat/completions` wire-format codec: request encoding (Task 7) and
//! SSE streaming-response decoding (Task 8) to/from the provider-agnostic IR.
//!
//! `provider` (Task 10) is the `Provider` trait wrapper Phase 1 never built for
//! this codec (unlike `anthropic_messages`) — one profile-parameterized adapter
//! reused unchanged by every `openai-chat` profile from here on (§9.1's "the
//! provider is data" thesis).

mod decode;
mod encode;
pub mod provider;
mod reasoning_field_validation;
pub use decode::decode_openai_chat_stream;
pub use encode::encode_openai_chat;
pub use provider::OpenAiChatProvider;
pub use reasoning_field_validation::{
    validate_openai_chat_reasoning_field, RESERVED_REASONING_FIELD_KEYS,
};
