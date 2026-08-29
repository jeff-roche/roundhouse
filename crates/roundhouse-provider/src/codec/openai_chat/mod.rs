//! OpenAI `/v1/chat/completions` wire-format codec: request encoding (Task 7) and
//! SSE streaming-response decoding (Task 8) to/from the provider-agnostic IR.

mod decode;
mod encode;
pub use decode::decode_openai_chat_stream;
pub use encode::encode_openai_chat;
