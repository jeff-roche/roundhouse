//! Inter-agent messaging and teams: the routed registry (`Bus`) session
//! runtimes use to address each other by `Address`/`SessionId` — the only
//! thing a session touches for messaging, never a concrete `LocalBus`/
//! `RemoteBus` implementation.
//!
//! Phase 0 ships the `Bus` trait (`register`/`send`/`wait`/`resolve`, a
//! signature inferred from §7.8's prose — no explicit code block existed in
//! the spec to copy) and `Envelope`/`Undeliverable` wiring; no real
//! implementation exists yet, and this crate doesn't yet depend on
//! `roundhouse-store` for durable envelope persistence the way
//! `docs/architecture/02-system-architecture.md` §5.2's table eventually
//! calls for — that's Phase 4 work. See §5.2 and `04-messaging-and-teams.md`.
#![forbid(unsafe_code)]

mod bus_trait;
mod types;

pub use bus_trait::Bus;
pub use types::{BusError, Undeliverable};
