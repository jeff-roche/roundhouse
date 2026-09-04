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
//! which records why it is *not* layered over the whole router. Task 34 (D5)
//! added the second API route, §8.6's Runs inbox, in [`runs`] — and with it the
//! single `api_router` registration point every later API route goes through,
//! so that adding a route and being gated are one act (ruling P88 §A). Its fix
//! round added the second thing that registration point buys: an always-on
//! `Host` check (`host_guard`), because a parameterless `/api` read makes DNS
//! rebinding a working attack against the *ungated loopback* arm, which no
//! token and no CORS header can defend (ruling P93 §A).
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
mod host_guard;
pub mod lan_auth;
pub mod runs;
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
///
/// D5 added the second field under the same three constraints, which is what
/// makes it an `Option` and what makes it a [`roundhouse_store::StorePool`]
/// rather than a connection:
///
/// - **`Default`** rules out anything without one, which a bare
///   `rusqlite::Connection` (or an `Arc<Mutex<…>>` of one) has no way to
///   provide. An `Option` carries a `Default` naturally, and a router built
///   without a store answering "no store configured" is honest — see
///   [`runs`]'s handler for why that answer is a `503` and not an empty list.
/// - **`Debug`** holds because `deadpool_sqlite::Pool` implements it (checked,
///   not assumed: it needs `Manager: Debug` and `Manager::Type: Debug`, and
///   `rusqlite::Connection`'s `Debug` supplies the second), so
///   `roundhouse_store::StorePool` can derive it.
/// - **`Clone`** is `Pool`'s reference-counted handle clone, so cloning
///   `AppState` per request shares one pool rather than making another.
///
/// Opening a bare connection inside this crate instead would be the **third**
/// pool-construction path in this workspace, and `roundhouse-store`'s `pool.rs`
/// records that the second one was found silently skipping all three
/// `post_create` pragmas (`synchronous`, `busy_timeout`, `secure_delete`) until
/// both constructors were routed through one hook.
#[derive(Clone, Debug, Default)]
pub struct AppState {
    /// Per-session fan-out of appended events to open SSE connections, and the
    /// §11.3 ring each one replays from. **Nothing in this workspace publishes
    /// into it yet** — see [`sse`]'s module docs, which also record that it
    /// performs no redaction.
    pub sse: sse::SseHub,
    /// The daemon's store, when there is one. `None` is a router with no
    /// database behind it — every router in this crate's own test suite, and
    /// whatever a caller builds before it has opened one.
    ///
    /// **Nothing in this workspace constructs an `AppState` with a store in it
    /// yet**, because nothing links this crate at all; see this module's docs
    /// for what wiring the daemon up costs.
    pub store: Option<roundhouse_store::StorePool>,
    /// How many API requests may hold a [`store`](Self::store) connection at
    /// once. See [`ApiPoolPermits`] — the field exists so that a handler cannot
    /// starve the event-log writer, and its [`Default`] is the bound.
    pub api_pool_permits: ApiPoolPermits,
}

/// A bound on how many API requests may hold a store connection at once,
/// **shedding** rather than queueing when it is reached.
///
/// # The failure this exists to prevent
///
/// [`runs::router`]'s handler is the first thing in this workspace that takes a
/// [`roundhouse_store::StorePool`] connection *on request*, and the pool it
/// takes from is the one `roundhouse_store::writer` appends events through.
/// Measured, not assumed: `deadpool` 0.13.1's default `max_size` is
/// `CPU_COUNT * 2` (`deadpool::util::get_default_pool_max_size`) and
/// `Timeouts::default()` sets **no wait timeout**, and `roundhouse_store::open`
/// overrides neither. One `GET /api/runs` holds its connection for up to
/// `1 + 3 × MAX_INBOX_RUNS` queries.
///
/// So `CPU_COUNT * 2` concurrent requests — from an unauthenticated loopback
/// caller, a paired LAN device, or `HEAD` requests that pay the whole cost and
/// take no body — hold every connection in the pool, and every other caller,
/// **including an event append**, waits forever. Ruling P93 §B.
///
/// # Why a semaphore, and why `try_acquire`
///
/// Three alternatives were measured and rejected there, recorded so they are
/// not re-derived:
///
/// - **Setting `Timeouts.wait` in `roundhouse_store::open`** is one line, and
///   it converts the writer's benign wait under contention into a hard
///   `PoolTimeout` on the **write** path. That is worse than the problem.
/// - **`tokio::time::timeout` around `pool.get()`** bounds how long *one*
///   handler waits, not how many connections concurrent handlers already hold.
///   It misses the mechanism.
/// - **`tower::ConcurrencyLimitLayer`** queues rather than sheds, converting
///   starvation into unbounded queueing, and drags `tower` out of
///   dev-dependencies.
///
/// `try_acquire_owned` is what makes this shed: over the bound, the request is
/// answered `503` immediately instead of joining a queue with no end. That
/// matches [`runs`]'s existing convention, where `503` means "this surface is
/// not ready" rather than "your request is wrong".
///
/// # The default, and why it is a fraction rather than a constant
///
/// The pool's size is a function of the CPU count, so a fixed number would be
/// most of the pool on a small machine and a rounding error on a large one. The
/// default is a quarter of `deadpool`'s own default `max_size` — see
/// [`ApiPoolPermits::default`] — with a floor of one, so a single-core machine
/// can still answer.
///
/// `Default` is what [`AppState`] needs and is also what a caller should
/// normally use. [`ApiPoolPermits::new`] exists for a caller that has measured
/// something better, and for tests that need the shed path deterministically.
#[derive(Clone)]
pub struct ApiPoolPermits(std::sync::Arc<tokio::sync::Semaphore>);

impl ApiPoolPermits {
    /// A bound of exactly `permits` concurrent store-holding API requests.
    ///
    /// `0` is legal and means "shed everything", which is the only way to
    /// exercise the shed path without racing a real pool.
    pub fn new(permits: usize) -> Self {
        Self(std::sync::Arc::new(tokio::sync::Semaphore::new(permits)))
    }

    /// The permit for one request, or `None` if the bound is reached.
    ///
    /// The caller holds the returned value for as long as it holds a pool
    /// connection — which is why it is an owned permit and not a borrowed one:
    /// the handler's future outlives any borrow of the state.
    pub(crate) fn try_acquire(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        std::sync::Arc::clone(&self.0).try_acquire_owned().ok()
    }
}

impl Default for ApiPoolPermits {
    /// A quarter of `deadpool`'s default `max_size` of `CPU_COUNT * 2`, floored
    /// at one.
    ///
    /// The CPU count comes from `std::thread::available_parallelism`, which is
    /// not literally the `num_cpus::get()` `deadpool` uses: in a cgroup-limited
    /// container the std answer is the *smaller* of the two, which lowers this
    /// bound and never raises it past its intended fraction. That is the
    /// direction to be wrong in.
    fn default() -> Self {
        let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        Self::new((cpus / 2).max(1))
    }
}

impl std::fmt::Debug for ApiPoolPermits {
    /// Hand-written because [`AppState`] derives `Debug` and
    /// `tests/assets.rs::a_handler_taking_app_state_composes_with_the_asset_router`
    /// compares two independently constructed `AppState::default()` renderings.
    /// A derived `Debug` here would print `tokio::sync::Semaphore`'s internals,
    /// which are not part of this type's meaning; the number of permits still
    /// free is.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ApiPoolPermits")
            .field(&self.0.available_permits())
            .finish()
    }
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
        None => api_router(bind),
        Some(gate) => api_router(bind).layer(axum::middleware::from_fn_with_state(
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
///
/// # The `Host` check is here for the same reason, and it is always on
///
/// [`host_guard::require_expected_host`] refuses any request that addresses
/// this process by a name it does not bind to — the DNS-rebinding defence
/// ruling P93 §A requires, and the only thing standing between a page the
/// victim merely visited and the whole of `GET /api/runs`. It is layered
/// **here** rather than in [`build_router`] for exactly the reason the
/// registration point exists: a route added to this function is `Host`-checked
/// by the act of being added.
///
/// It is unconditional, unlike the LAN gate, because the arm that needs it is
/// the *ungated loopback* one: `/api/runs` takes no path segment, no query
/// parameter and no body, so a rebinding page needs to guess nothing.
///
/// `layer` and not `route_layer`: `axum::Router::layer` wraps the fallback and
/// the catch-all too (checked against axum 0.8.4's `Router::layer`, which maps
/// over `path_router`, `fallback_router` **and** `catch_all_fallback`), so
/// [`api_not_found`] is behind the check as well. `route_layer` maps only
/// `path_router` and would leave the fallback open — the same shape of hole
/// P88 §A is about.
///
/// The `Host` check sits **inside** the LAN gate, so on a LAN bind a request
/// with neither token nor correct `Host` is answered `401` and never reaches
/// the `403`. That order tells an unauthenticated caller less, and it is what
/// `tests/lan_auth.rs`'s boundary test observes.
fn api_router(bind: &lan_auth::BindConfig) -> axum::Router<AppState> {
    sse::router()
        .merge(runs::router())
        .fallback(api_not_found)
        .layer(axum::middleware::from_fn_with_state(
            bind.allowed_hosts(),
            host_guard::require_expected_host,
        ))
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
///
/// # `/api/` — exactly one trailing slash — does not reach this
///
/// [`build_router`] nests at `/api`, and `axum::Router::nest` registers
/// `prefix` and `prefix/{*rest}`: **not** `prefix + "/"`. Only `nest_service`
/// registers all three. `matchit` 0.8.4 backtracks, so `/api/` walks to the
/// intermediate `/` node under `api`, finds no value there, and falls back to
/// the **root catch-all** — [`assets::serve_asset`], outside the gate.
///
/// It really is that one path and not a prefix rule, which is worth stating
/// because the near-misses read as though they should escape too and do not.
/// Every one of these is asserted in the boundary test named below:
///
/// ```text
/// "/api"        -> gated       "/api/runs"    -> gated
/// "/api/"       -> serve_asset "/api/no-such" -> gated
/// "/api//"      -> gated       "/api/./runs"  -> gated
/// ```
///
/// `/api//` matches `/api/{*rest}` with a `rest` of `/`, and `matchit`
/// normalises no dot segment, so `/api/./runs` is simply a path no route
/// matches.
///
/// The consequence today is nil: `serve_asset` rejects the empty path segment
/// and answers a bare `404`, and ruling P85 already accepts the ungated asset
/// surface. What was wrong is that the invariant above was one path short of
/// true and nothing measured the gap.
/// `tests/lan_auth.rs::the_gate_is_on_api_and_the_asset_surface_is_ungated`
/// now pins both statuses — `/api` `401`, `/api/` `404` — so the day
/// `serve_asset` answers that path with something else, a test says so.
///
/// The three repairs are all worse: nesting at `"/api/"` is lateral (bare
/// `/api` then falls to the asset router); `nest_service` registers all three
/// but needs the inner router to be a `Service`, which a `Router<AppState>` is
/// not until `with_state` — inverting the nest-before-`with_state` rule above;
/// and a path-prefix test in the middleware is the loose textual form ruling
/// P85 rules out.
async fn api_not_found() -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        axum::http::StatusCode::NOT_FOUND,
        runs::error_body("no such API route"),
    )
        .into_response()
}
