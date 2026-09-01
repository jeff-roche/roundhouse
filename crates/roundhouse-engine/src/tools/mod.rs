//! Tool executors that the engine dispatches to for tool-call task kinds.
//!
//! Phase 4 (sub-agents + messaging) adds the inter-agent `message_send`/`message_wait`
//! executors (Tasks 13); earlier phases' `read`/`write`/`edit`/`find`/`shell` executors
//! live in `roundhouse-tools`, a separate crate.

pub mod message_send;
pub mod message_wait;
pub mod peers;
pub mod team_close;
pub mod team_create;
