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
//! the one condition §11.3 gives it. See [`sse`]. Task 33 (D4) added the rest
//! of §11.3's access scope: the opt-in LAN bind and its shared per-device
//! token, in [`lan_auth`], layered onto the `/api` nest by [`build_router`] —
//! which records why it is *not* layered over the whole router.
//! **This crate still binds no listener and starts no server**, and nothing
//! links it yet — so [`lan_auth::BindConfig::bind_addr`] has no caller.
//!
//! Wiring it up is a separate, later piece of work, and it is not free: it has
//! to add the `roundhouse-daemon -> roundhouse-web` Cargo edge, update
//! `xtask/tests/workspace_shape.rs`'s exact-set assertion on the daemon's
//! dependencies, and update §5.2's daemon row in
//! `docs/architecture/02-system-architecture.md` — all three in one commit, or
//! the workspace-shape test fails. The loopback-vs-LAN binding policy (§11.3)
//! that used to block it now exists — see [`lan_auth`] — but
//! `roundhouse-daemon`'s `main.rs` still has no long-running accept loop to
//! hang a listener off.
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
pub mod lan_auth;
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
/// The asset router plus `api_router` nested at `/api`, plus the shared
/// state. `axum` matches registered routes before a `fallback`, so nesting is
/// what puts `/api/sessions/{id}/events` **ahead of** the asset fallback and
/// stops it falling through to the `index.html` shell. An `/api/...` path with
/// no route is 404ed by `api_router`'s own fallback rather than by the asset
/// router's — see `api_not_found` for why that distinction is the gate's.
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
///
/// # The LAN gate goes on the `/api` nest, and the shell is served ungated
///
/// `bind` is taken by value-reference rather than defaulted because the caller
/// must *make* the loopback-vs-LAN decision to get a router at all; there is no
/// signature here that quietly serves the LAN ungated. See
/// [`lan_auth::BindConfig`] for why that decision and the token are one value.
///
/// When [`lan_auth::BindConfig::gate`] yields a gate it is layered onto
/// `api_router` **before** that router is nested. So the gated set is exactly
/// what `api_router` registers, and the ungated set is "whatever
/// [`assets::asset_router`] serves" — not a path-prefix string test on the outer
/// router, which is the loose form that drifts the moment a route is added.
///
/// **What constructs that, precisely, is `api_router` being the only place an
/// API route is registered** — see its docs, which is where the invariant lives
/// and where a new route goes. An earlier version of this paragraph said the
/// gated set was `/api/...` "by construction" while the construction actually
/// guaranteed only "whatever [`sse::router`] registers". Those coincided because
/// there was exactly one API router, and a set with one element makes a poor
/// invariant (ruling P88 §A): the very next task added a second API route, and
/// adding it the obvious way — a second `.nest("/api", …)` on the chain below —
/// would have served it **ungated** with no test in the suite failing.
///
/// ## The whole-surface gate was tried first, and it does not work
///
/// Recorded rather than deleted, because "one gate over everything" reads like
/// the safer choice and a reader who finds the gate on `/api` will otherwise
/// change it back. Until ruling P85 this was a single `.layer(...)` on the
/// finished `Router<()>`, wrapping the `/api` SSE routes and the embedded-asset
/// fallback alike. The failure is mechanical, not a matter of taste:
///
/// Under [`lan_auth::BindConfig::lan`] a browser's only way to present a
/// credential on a **document** request is `http://host:port/?access_token=…`.
/// There is no cookie (deliberately — see [`lan_auth`]), and a top-level
/// navigation sets no request header. That request serves `index.html`, whose
/// `<link rel="stylesheet" href="/app.css">` is a **subresource**: its URL is
/// written by the client *build*, not by the client *code*, so it can carry
/// neither the header nor the query parameter. It 401s, and the page never
/// boots. The real SolidJS client P12 defers emits hashed `/assets/*.js` and
/// `/assets/*.css` with exactly the same shape. The whole-surface gate
/// therefore left the LAN bind — the entire point of the feature — with **no
/// working browser configuration**, and the two repairs nearest to hand were
/// both forbidden (`Set-Cookie` is the ambient authority [`lan_auth`] exists
/// without; an asset exemption bolted on under time pressure gets written as a
/// loose path prefix).
///
/// What is given up by serving the shell ungated is bounded and small.
/// `assets/dist/` is **compile-time-constant public content**: the same bytes
/// in every install, embedded from the repo at build time, with no session
/// data, no secrets and no per-install configuration in them — a standing
/// constraint on whoever replaces the placeholder, stated in [`assets`]'s
/// module docs. An unauthenticated LAN peer therefore learns "a Roundhouse
/// instance is here", which the open TCP port already told them, plus client
/// code from an open-source repository. Every route that can disclose a
/// *session* is under `/api`, and `/api` is what stays gated.
///
/// `tests/lan_auth.rs::the_gate_is_on_api_and_the_asset_surface_is_ungated`
/// pins that boundary from both sides, so this stops being prose the moment it
/// stops being true.
///
/// The layer is absent — not merely inert — on the loopback path, so the
/// zero-configuration router has no authentication code in its request path at
/// all.
pub fn build_router(state: AppState, bind: &lan_auth::BindConfig) -> axum::Router {
    // Every API route is registered inside `api_router`, and therefore inside
    // this expression, where the gate is applied. **A new API router is merged
    // into `api_router`; it is never added to the outer chain below.** A second
    // `.nest("/api", …)` down there would sit outside this `match` and would be
    // served ungated (ruling P88 §A).
    let api = match bind.gate() {
        None => api_router(),
        Some(gate) => api_router().layer(axum::middleware::from_fn_with_state(
            gate,
            lan_auth::require_lan_token,
        )),
    };

    assets::asset_router().nest("/api", api).with_state(state)
}

/// **The single registration point for every API route in this crate**, nested
/// at `/api` and gated by [`build_router`].
///
/// Being the *only* such point is the security property, not an organisational
/// one (ruling P88 §A). [`build_router`] gates whatever this function returns,
/// so a route added here is gated by the same act that adds it. A route added
/// any other way — most plausibly a second `.nest("/api", …)` on
/// [`build_router`]'s outer chain — lands **outside** the gate, serving session
/// and workflow-run data to an unauthenticated LAN peer, and the existing
/// boundary test would not notice, because it can only probe paths it knows
/// about.
///
/// So: **a new API route goes in this function.** `merge` for another
/// `Router<AppState>` of top-level API paths, `nest` for a prefixed group. Both
/// keep it inside the returned value, which is the only thing that matters.
///
/// `tests/lan_auth.rs::the_gate_is_on_api_and_the_asset_surface_is_ungated`
/// asserts `401` on an `/api` path that matches **no** route at all, which is
/// what pins "the gate covers the nest" rather than "the gate covers the routes
/// that happened to exist when the test was written".
fn api_router() -> axum::Router<AppState> {
    sse::router().fallback(api_not_found)
}

/// `404` for an `/api` path that matches no API route.
///
/// **The point of it is the `401` it makes possible, not the `404`.** Without a
/// fallback of its own, a nested `axum::Router` hands an unmatched request back
/// to the outer router's fallback — [`assets::serve_asset`], which 404s it —
/// and it does so *outside* the gate [`build_router`] layered onto this router.
/// The gate would then cover exactly the paths [`api_router`] had registered at
/// the moment it was written, which is precisely the "invariant that holds
/// because a set has one element" ruling P88 §A is about. With this fallback the
/// `/api` nest answers every path under it, so the gate covers the **nest**, and
/// `tests/lan_auth.rs::the_gate_is_on_api_and_the_asset_surface_is_ungated` can
/// assert that by probing a path no route will ever match.
///
/// The status is unchanged from what the asset fallback produced for the same
/// path, so this is not a behaviour change for a client; only *which* layer
/// answers, and therefore whether the answer is gated.
async fn api_not_found() -> axum::response::Response {
    use axum::response::IntoResponse;
    (axum::http::StatusCode::NOT_FOUND, "no such API route\n").into_response()
}
