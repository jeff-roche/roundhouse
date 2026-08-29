//! Client↔daemon wire types and their JSON Schema emission, versioned via
//! `ApiVersion` so client and daemon can detect a protocol mismatch instead
//! of silently misinterpreting each other's messages.
//!
//! Phase 0 gives this crate real content: the request/event wire shapes and
//! `schemars` 1.2.2-based schema generation (`client_event_schema`) that
//! `roundhouse-tui`/`roundhouse-cli`/`roundhouse-web` all build on. See
//! `docs/architecture/02-system-architecture.md` §5.2 and §7 (protocols).
#![forbid(unsafe_code)]

mod schema;
mod wire;

pub use schema::{client_event_schema, client_request_schema};
pub use wire::{ApiVersion, ClientEvent, ClientRequest};
