//! The `ratatui`-based terminal client: what `round` attaches to for an
//! interactive session, talking to the daemon purely over
//! `roundhouse-proto`'s wire types.
//!
//! Phase 1 built the real dashboard: [`Dashboard`] and [`render_tick`] render
//! the attached session, and [`DaemonClient`] (via [`connect`]) is the real
//! socket client. `client_schema()` below is a Phase 0 leftover proving this
//! crate compiles against `roundhouse-proto`'s schema emission. See
//! `docs/architecture/02-system-architecture.md` §5.2 and `08-ui-design.md`.
#![forbid(unsafe_code)]

mod client;
mod coalesce;
mod dashboard;
mod dirty;
mod paths;
mod protocol;
mod render;
mod rope;

pub use client::{connect, ConnectIntent, DaemonClient};
pub use coalesce::{Coalescer, SessionSummary};
pub use dashboard::Dashboard;
pub use dirty::{DirtyFlags, Region};
pub use paths::{default_runtime_dir, default_socket_path};
pub use protocol::TuiError;
pub use render::render_tick;
pub use rope::RopeStore;

pub fn client_schema() -> schemars::Schema {
    roundhouse_proto::client_event_schema()
}
