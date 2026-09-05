//! The daemon's library half: the pieces of `round daemon` that are worth
//! testing without spawning the binary.
//!
//! `roundhouse-daemon` was binary-only through Phase 0, when it existed only to
//! prove the full dependency graph links. Phase 1's exit criterion needs the
//! wiring itself under test — an integration test can drive
//! [`demo::run_demo_session`] and [`socket_server::serve`] directly, but
//! it cannot drive a `main`. Hence this lib target; `src/main.rs` is now a thin
//! startup shell over it. See `docs/architecture/02-system-architecture.md` §5.2.
#![forbid(unsafe_code)]

pub mod boot;
pub mod demo;
pub mod mcp_config;
pub mod socket_server;
