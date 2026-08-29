//! The `ratatui`-based terminal client: what `round` attaches to for an
//! interactive session, talking to the daemon purely over
//! `roundhouse-proto`'s wire types.
//!
//! Phase 0 only proves this crate compiles against `roundhouse-proto`'s
//! schema emission; no real TUI exists yet — that's Phase 5 work. See
//! `docs/architecture/02-system-architecture.md` §5.2 and `08-ui-design.md`.
#![forbid(unsafe_code)]

mod client;
mod coalesce;
mod dashboard;
mod dirty;
mod protocol;
mod render;
mod rope;

pub use client::{connect, DaemonClient};
pub use coalesce::{Coalescer, SessionSummary};
pub use dashboard::Dashboard;
pub use dirty::{DirtyFlags, Region};
pub use protocol::{ServerMessage, TuiError};
pub use render::render_tick;
pub use rope::RopeStore;

pub fn client_schema() -> schemars::Schema {
    roundhouse_proto::client_event_schema()
}
