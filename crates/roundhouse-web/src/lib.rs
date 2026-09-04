//! The `axum`-based web API and embedded web client assets — the browser
//! equivalent of `roundhouse-tui`, talking to the daemon over the same
//! `roundhouse-proto` wire types.
//!
//! Task 30 (Phase 5, Subsystem D1) fills in the crate's entry seam: an
//! `axum::Router` serving the `rust-embed`-embedded client from
//! `assets/dist/`, with §11.1's SPA fallback. That is the whole scope —
//! **this crate binds no listener and starts no server**, and nothing links it
//! yet.
//!
//! Wiring it up is a separate, later piece of work, and it is not free: it has
//! to add the `roundhouse-daemon -> roundhouse-web` Cargo edge, update
//! `xtask/tests/workspace_shape.rs`'s exact-set assertion on the daemon's
//! dependencies, and update §5.2's daemon row in
//! `docs/architecture/02-system-architecture.md` — all three in one commit, or
//! the workspace-shape test fails. It also cannot happen before the
//! loopback-vs-LAN binding policy (§11.3) exists, and `roundhouse-daemon`'s
//! `main.rs` has no long-running accept loop to hang a listener off yet.
//!
//! Per ruling P10 the assets ship in the **daemon** binary: `roundhouse-web`
//! links into `roundhouse-daemon`, and `round daemon` (in `roundhouse-cli`)
//! spawns `round-daemon-internal` as a child process rather than linking the
//! daemon in.
//!
//! See `docs/architecture/02-system-architecture.md` §5.2 and `08-ui-design.md`
//! §11.1.
#![forbid(unsafe_code)]

pub mod assets;

pub use assets::{asset_router, WebAssets};

/// The wire-protocol version this crate's API speaks, shared with every other
/// client of `roundhouse-proto`.
pub fn api_version() -> roundhouse_proto::ApiVersion {
    roundhouse_proto::ApiVersion::CURRENT
}

/// Shared state handed to every route in [`build_router`].
///
/// Empty today: D1 serves only static embedded assets, which need no state.
/// It exists as the seam the later Subsystem D tasks add their fields to (an
/// SSE hub, the store handle) so that adding one is a field, not a change to
/// every handler signature in the crate.
#[derive(Clone, Debug, Default)]
pub struct AppState {}

/// The single router a future daemon listener would mount.
///
/// Today it is the asset router plus the shared state. Later Subsystem D tasks
/// `.nest()` their API routers here, **ahead of** the asset fallback, so that
/// an `/api/...` path never falls through to the `index.html` shell.
pub fn build_router(state: AppState) -> axum::Router {
    axum::Router::new()
        .with_state(state)
        .fallback(assets::serve_asset)
}
