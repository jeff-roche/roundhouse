//! The `axum`-based web API and embedded web client assets — the browser
//! equivalent of `roundhouse-tui`, talking to the daemon over the same
//! `roundhouse-proto` wire types.
//!
//! Phase 0 only proves this crate compiles against `roundhouse-proto`'s
//! `ApiVersion`; no real API server or web client exists yet — that's
//! Phase 5 work. See `docs/architecture/02-system-architecture.md` §5.2
//! and `08-ui-design.md`.
#![forbid(unsafe_code)]

pub fn api_version() -> roundhouse_proto::ApiVersion {
    roundhouse_proto::ApiVersion::CURRENT
}
