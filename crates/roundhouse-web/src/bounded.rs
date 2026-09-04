//! The store pool, the bound on how many API requests may hold a connection
//! from it, and the one expression that reaches through the first — **in a leaf
//! module, which is the whole reason this file exists.**
//!
//! # Why a module and not a private field in the crate root
//!
//! Ruling P96 §C asked for a newtype around [`crate::AppState`]'s pool so that
//! `state.store.pool.get()` — a connection held outside [`ApiPoolPermits`], the
//! writer starvation of ruling P93 §B — would be a compile error rather than a
//! convention. D6 wrote that newtype in `lib.rs` and claimed the property held.
//! **It did not, and ruling P98 records why:** Rust privacy is *"the defining
//! module **and its descendants**"*, and `lib.rs` **is** the crate root, so a
//! private field declared there is readable from `interaction`, `runs`, `sse`
//! and every other handler module. Compiled, not recalled — a child module
//! reading a private field of a crate-root struct builds with exit 0.
//!
//! So the defining module has to be one with **no handler descendants**, which
//! is what this file is: it declares no `mod` of its own, and
//! `tests/bounded_reach.rs` fails if it ever does.
//!
//! # And the expression that unwraps the field lives here too — it has to
//!
//! P98's addendum warns that moving the type alone would move the code and keep
//! the hole, because `lib.rs` would then be this module's *parent* and could
//! still read the field. **Compiled rather than assumed, and it is the other way
//! round:** a parent is not a descendant, so the crate root cannot read it
//! either. `state.store.as_ref().unwrap().inner.pool.get()` written in `lib.rs`
//! is `error[E0616]`, exactly as it is from `runs.rs`.
//!
//! That makes the arrangement stronger than the warning assumed rather than more
//! fragile: the split it describes **does not compile**, so the one expression
//! that unwraps the field lives beside the field by construction and not because
//! someone remembered the rule. [`crate::AppState::store_connection`] delegates
//! to [`BoundedStore::connection`] below and never names the pool.
//!
//! `BoundedStore::inner` is consequently named in this file and nowhere else in
//! the crate — which follows from the two properties above and is **not**
//! something a `grep` shows: `grep '\.inner\b'` over `src/` also matches
//! `lan_auth::BindConfig`, which has an `inner` field of its own, three times.
//! `tests/bounded_reach.rs` checks the properties instead, and says why the grep
//! is not the test.

/// The store pool with its `Pool` handle **out of reach**, so that
/// [`BoundedStore::connection`] is not merely the convenient way to take a
/// connection but the only expressible one.
///
/// # Why a newtype rather than a doc note
///
/// A handler that called `state.store.pool.get()` directly would hold a
/// connection outside [`ApiPoolPermits`]' bound. [`crate::AppState::store`] is
/// `pub` — as it must be, since a future `roundhouse-daemon` constructs the
/// state by struct literal — and a `pub` field of type
/// [`roundhouse_store::StorePool`] hands every handler in this crate, and every
/// caller outside it, a `deadpool` `Pool` with a public `get`. The bound was
/// therefore held by nobody reaching for it, which is the same "invariant that
/// holds because nothing has tested it yet" shape ruling P88 §A is about, and
/// D6 adds four more `/api` handlers.
///
/// Wrapping the field is what makes it structural; **wrapping it in this
/// module** is what makes the wrapping worth anything. See the module docs: a
/// private field in `lib.rs` is readable from every handler module in the
/// crate, so the first version of this type closed nothing.
///
/// [`new`](Self::new) and [`connection`](Self::connection) are the whole
/// surface: a caller supplies a pool and gets back something it can only hand to
/// [`crate::AppState`], and the one thing it can then ask for is a connection
/// that already holds its permit. There is deliberately no accessor — an
/// `fn pool(&self)` here would restore exactly what the private field removes,
/// and unlike the field itself **that would not be caught by any test in this
/// crate** (see `tests/compile_fail.rs`, which says so rather than claiming
/// otherwise).
#[derive(Clone, Debug)]
pub struct BoundedStore {
    /// **Private to this leaf module, and that is the entire point of this
    /// type.** Read by [`BoundedStore::connection`] below, which pairs it with a
    /// permit, and by nothing else in this crate — because nothing else in this
    /// crate is a descendant of this module.
    ///
    /// Named `inner` rather than `pool` so that the one expression that reaches
    /// through it reads `self.inner.pool.get()` — the outer name says "this is
    /// the wrapper being unwrapped", and the inner one is
    /// [`roundhouse_store::StorePool`]'s own field.
    inner: roundhouse_store::StorePool,
}

/// Why [`BoundedStore::connection`] did not hand back a connection.
///
/// Two cases and not one because they are two different things for an operator
/// to do about: at the bound is load, and a pool failure is a broken database.
/// [`crate::AppState::store_connection`] is what turns them into the `503` and
/// the `500`, because the status and the body are a property of the `/api`
/// namespace rather than of the pool.
pub(crate) enum ConnectionRefusal {
    /// [`ApiPoolPermits`] had nothing left. Shed, not queued — see that type.
    AtBound,
    /// `deadpool` could not produce a connection.
    ///
    /// **The underlying error is discarded here rather than carried out**, for
    /// the reason `runs::internal_error` states: a pool error can carry the
    /// database path, and the response it would reach goes to whoever asked. A
    /// variant with no payload is what makes rendering it by accident
    /// impossible.
    PoolFailed,
}

impl BoundedStore {
    /// Puts `pool` behind the bound.
    ///
    /// The only constructor, and it takes the pool by value: whoever opened the
    /// store keeps their own clone if they want one (`StorePool` is a
    /// reference-counted handle), but the clone *inside* a [`crate::AppState`]
    /// is not reachable through it.
    pub fn new(pool: roundhouse_store::StorePool) -> Self {
        Self { inner: pool }
    }

    /// A connection **and** the permit bounding it, in one act.
    ///
    /// Takes `permits` rather than an already-taken
    /// `tokio::sync::OwnedSemaphorePermit`, which is not a stylistic choice: a
    /// caller that supplied its own permit could mint one from a semaphore of
    /// its own and be back outside the bound. Acquiring here is what makes the
    /// permit and the connection a single act with no ordering to get wrong.
    pub(crate) async fn connection(
        &self,
        permits: &ApiPoolPermits,
    ) -> Result<StoreConnection, ConnectionRefusal> {
        let Some(permit) = permits.try_acquire() else {
            return Err(ConnectionRefusal::AtBound);
        };

        match self.inner.pool.get().await {
            Ok(connection) => Ok(StoreConnection {
                connection,
                _permit: permit,
            }),
            Err(_error) => Err(ConnectionRefusal::PoolFailed),
        }
    }
}

/// A bound on how many API requests may hold a store connection at once,
/// **shedding** rather than queueing when it is reached.
///
/// # The failure this exists to prevent
///
/// [`crate::runs::router`]'s handler is the first thing in this workspace that
/// takes a [`roundhouse_store::StorePool`] connection *on request*, and the pool
/// it takes from is the one `roundhouse_store::writer` appends events through.
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
/// matches [`crate::runs`]'s existing convention, where `503` means "this
/// surface is not ready" rather than "your request is wrong".
///
/// # The default, and why it is a fraction rather than a constant
///
/// The pool's size is a function of the CPU count, so a fixed number would be
/// most of the pool on a small machine and a rounding error on a large one. The
/// default is a quarter of `deadpool`'s own default `max_size` — see
/// [`ApiPoolPermits::default`] — with a floor of one, so a single-core machine
/// can still answer.
///
/// `Default` is what [`crate::AppState`] needs and is also what a caller should
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

    /// What is left of the bound.
    ///
    /// Public because the bound's *size* is otherwise unmeasurable from
    /// outside, and it is a claim worth measuring: `tests/runs.rs::
    /// the_default_bound_is_well_below_the_pools_own_max_size` reads this and
    /// compares it against `pool.status().max_size`, which is the property
    /// [`Default`] exists to have rather than a number it happens to produce.
    pub fn available_permits(&self) -> usize {
        self.0.available_permits()
    }

    /// The permit for one request, or `None` if the bound is reached.
    ///
    /// The caller holds the returned value for as long as it holds a pool
    /// connection — which is why it is an owned permit and not a borrowed one:
    /// the handler's future outlives any borrow of the state.
    ///
    /// **Private, and in this module that means what it says.** Its one caller
    /// is [`BoundedStore::connection`] above; a permit is of no use to anything
    /// else, since taking one without then taking a connection bounds nothing.
    /// Keeping it beside the pool is what makes the two a single act rather than
    /// two a handler is trusted to perform in order — and keeping it in a *leaf*
    /// module is what stops "private" meaning "readable from every handler",
    /// which is exactly what it meant while this lived in `lib.rs` (ruling P98).
    fn try_acquire(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
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
    /// Hand-written because [`crate::AppState`] derives `Debug` and
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

/// A checked-out store connection that owns the permit bounding it.
///
/// Constructible only by [`BoundedStore::connection`], which is the point: a
/// connection cannot exist in this crate without the permit that accounts for
/// it, so the bound cannot be bypassed by forgetting a step.
///
/// **Field order is the drop order and is load-bearing.** Struct fields drop in
/// declaration order, so the connection goes back to the pool *before* the
/// permit is released. The other order would let a waiting request take the
/// freed permit and then block inside `pool.get()` on a connection that has not
/// been returned yet — bounding the permits but not the wait, which is the
/// failure this whole mechanism exists to prevent.
pub(crate) struct StoreConnection {
    connection: roundhouse_store::PooledConnection,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl std::ops::Deref for StoreConnection {
    type Target = roundhouse_store::PooledConnection;

    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}
