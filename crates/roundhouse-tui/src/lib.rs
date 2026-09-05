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

pub use client::{connect, connect_attach, connect_create, ConnectIntent, DaemonClient};
pub use coalesce::{Coalescer, SessionSummary};
pub use dashboard::Dashboard;
pub use dirty::{DirtyFlags, Region};
pub use paths::{default_runtime_dir, default_socket_path};
pub use protocol::TuiError;
pub use render::render_tick;
pub use rope::RopeStore;
/// Re-exported so `roundhouse-cli` (which depends on this crate but not
/// `roundhouse-core` directly — §5.2's `roundhouse-cli` row) can name the
/// type `connect_attach`'s `session_id` parameter needs, to support `round
/// attach --session ID` (Phase 7, Task 7), without adding a new internal
/// `roundhouse-cli -> roundhouse-core` Cargo edge (this crate already
/// depends on `roundhouse-core`, so re-exporting one of its types changes
/// nothing about the dependency graph `xtask/tests/workspace_shape.rs`
/// checks).
pub use roundhouse_core::SessionId;

pub fn client_schema() -> schemars::Schema {
    roundhouse_proto::client_event_schema()
}
