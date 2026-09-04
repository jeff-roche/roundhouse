//! The `axum`-based web API and embedded web client assets — the browser
//! equivalent of `roundhouse-tui`, talking to the daemon over the same
//! `roundhouse-proto` wire types.
//!
//! Task 30 (Phase 5, Subsystem D1) fills in the crate's entry seam: an
//! `axum::Router` serving the `rust-embed`-embedded client from
//! `assets/dist/`, with §11.1's SPA fallback. Task 31 (D2) added the first
//! API route: §11.3's SSE stream, with `Last-Event-ID` carrying the
//! `(session_id, seq)` cursor. Task 32 (D3) added the rest of §11.3 — the
//! per-session ring the cursor is answered from, inside the same hub, so a
//! reconnecting client's gap is replayed and `resync_required` is left naming
//! the one condition §11.3 gives it. See [`sse`]. **This crate still binds no
//! listener and starts no server**, and nothing links it yet.
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
pub mod sse;

pub use assets::{asset_router, WebAssets};

/// The wire-protocol version this crate's API speaks, shared with every other
/// client of `roundhouse-proto`.
///
/// Task 30 marked this "do not delete as unused", because it was then the
/// only use of `roundhouse_proto` in the crate and `xtask/tests/
/// exit_criterion.rs` asserts a required `roundhouse-web -> roundhouse-proto`
/// Cargo edge. **That prediction is now fulfilled and the note is relaxed:**
/// `sse::SessionUpdate` carries a `roundhouse_proto::ClientEvent` as the
/// payload of every SSE frame, so the dependency is load-bearing on its own.
/// This function stays because clients need to negotiate a wire version, not
/// because deleting it would break a test.
pub fn api_version() -> roundhouse_proto::ApiVersion {
    roundhouse_proto::ApiVersion::CURRENT
}

/// Shared state handed to every route in [`build_router`].
///
/// D1 created this empty, as the seam later Subsystem D tasks add their fields
/// to; D2 added the first one. `Clone + Debug + Default` is load-bearing, not
/// incidental: `axum` clones the state per request, and
/// `tests/assets.rs::a_handler_taking_app_state_composes_with_the_asset_router`
/// formats it with `{state:?}` and compares against a separately constructed
/// `AppState::default()` — which holds because [`sse::SseHub`]'s `Debug` is its
/// [`sse::Retention`] plus its per-session map, and that map is **empty until
/// something subscribes**. Two default hubs therefore format identically
/// without either one carrying per-instance identity. It is also why D3's ring
/// lives behind the hub's own interior mutability rather than being a `&mut`
/// field here: this type is cloned per request and can hold no exclusive state.
#[derive(Clone, Debug, Default)]
pub struct AppState {
    /// Per-session fan-out of appended events to open SSE connections, and the
    /// §11.3 ring each one replays from. **Nothing in this workspace publishes
    /// into it yet** — see [`sse`]'s module docs, which also record that it
    /// performs no redaction.
    pub sse: sse::SseHub,
}

/// The single router a future daemon listener would mount.
///
/// The asset router plus [`sse::router`] nested at `/api`, plus the shared
/// state. `axum` matches registered routes before a `fallback`, so nesting is
/// what puts `/api/sessions/{id}/events` **ahead of** the asset fallback and
/// stops it falling through to the `index.html` shell. An `/api/...` path with
/// no route still reaches the asset fallback, which 404s it.
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
    assets::asset_router()
        .nest("/api", sse::router())
        .with_state(state)
}
