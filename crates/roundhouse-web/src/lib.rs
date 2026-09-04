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
///
/// **Do not delete this as unused.** `xtask/tests/exit_criterion.rs` asserts a
/// required Cargo edge `roundhouse-web -> roundhouse-proto`, and this is the
/// only place in the crate that uses `roundhouse_proto`. Removing it makes the
/// dependency look dead, and dropping the dependency fails that test. Keep it
/// until a Subsystem D task gives the crate a real `roundhouse-proto` use
/// site — which D2 onwards will, since the API routers speak those wire types.
pub fn api_version() -> roundhouse_proto::ApiVersion {
    roundhouse_proto::ApiVersion::CURRENT
}

/// Shared state handed to every route in [`build_router`].
///
/// Empty today: D1 serves only static embedded assets, which need no state.
/// It exists as the seam the later Subsystem D tasks add their fields to (an
/// SSE hub, the store handle) so that adding one is a field, not a change to
/// every handler signature in the crate. That the seam actually carries state
/// to a handler is checked by
/// `tests/assets.rs::a_handler_taking_app_state_composes_with_the_asset_router`,
/// not just asserted here.
#[derive(Clone, Debug, Default)]
pub struct AppState {}

/// The single router a future daemon listener would mount.
///
/// Today it is the asset router plus the shared state. Later Subsystem D tasks
/// `.nest()` their API routers here, **ahead of** the asset fallback, so that
/// an `/api/...` path never falls through to the `index.html` shell.
///
/// **Nest before `with_state`, not after.** `with_state` applies the state to
/// the routes registered up to that point and turns the result into a
/// `Router<()>`; anything added afterwards can no longer take a
/// `State<AppState>` extractor. So a new router goes in between
/// [`assets::asset_router`] and `.with_state(state)` — which is also why
/// `asset_router` is generic over the state type.
/// `tests/assets.rs::a_handler_taking_app_state_composes_with_the_asset_router`
/// compiles exactly that composition, so this stops being prose the moment it
/// stops being true.
pub fn build_router(state: AppState) -> axum::Router {
    assets::asset_router().with_state(state)
}
