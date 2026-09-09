use std::path::Path;

use deadpool_sqlite::{Config, Hook, HookError, Pool, Runtime};

use crate::txn::BUSY_TIMEOUT;

/// The migration harness for this crate's SQLite schema. Wraps Phase 0's complete
/// migrations (events table with append-only triggers, tasks table, FTS5 index, and
/// blobs table) in a lazy static for use with `deadpool_sqlite`'s connection pool.
/// Initialize and run all migrations on first pool connection via `MIGRATIONS.to_latest()`.
pub static MIGRATIONS: once_cell::sync::Lazy<rusqlite_migration::Migrations<'static>> =
    once_cell::sync::Lazy::new(crate::migrations::migrations);

/// One writer task, WAL, per §5.3. Phase 0 wires the pool configuration;
/// the single-writer discipline itself (one dedicated task owning all
/// writes) is Phase 1's `roundhouse-store` event-append work (§13.2).
///
/// Fix round 2 (security re-review): this used to build its pool with
/// `Config::create_pool`, which attaches no `post_create` hook at all — the
/// one way to get a writable connection to this database that did **not**
/// get `synchronous`/`busy_timeout`/`secure_delete` set on it. It has no
/// caller today (a source-wide search found none), so nothing was actually
/// exposed to an unprotected connection, but it was "load-bearing-by-absence
/// in a way it was not before" once `secure_delete` started being relied on
/// for erasure (see [`connection_hooks`]'s doc comment): a future caller
/// reaching for the obvious pool constructor would silently get one. Routed
/// through the same [`connection_hooks`] `open()` uses, rather than left as
/// a documented gap, because the fix is exactly as small as the comment
/// would have been and actually closes it instead of describing it.
pub fn open_pool(path: &Path) -> Pool {
    let cfg = Config::new(path);
    cfg.builder(Runtime::Tokio1)
        .expect("deadpool-sqlite config is infallible for a plain path")
        .post_create(connection_hooks())
        .build()
        .expect("pool builder config is valid")
}

/// Test-only helper: an in-memory connection with migrations not yet
/// applied, for `to_latest` to run against directly in unit tests.
pub fn open_memory_connection() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory sqlite connection");
    conn.pragma_update(None, "journal_mode", "WAL").ok(); // no-op on :memory:, harmless
    conn
}

/// Error type for connection pool and storage operations. Variants correspond to:
/// - `Io`: filesystem errors (e.g., path doesn't exist or is unreadable)
/// - `Sqlite`: SQLite connection or query errors
/// - `Migration`: schema migration failures
/// - `Pool`: deadpool connection pool exhaustion or shutdown
/// - `Interact`: async executor (tokio) task panicked while interacting with the connection
/// - `NotFound`: a genuine domain-level lookup failure (e.g. no `TaskCompleted` event found
///   for a task) — distinct from `Interact`, which this crate's convention reserves for
///   interact-closure/panic failures specifically, not ordinary "no such row" outcomes.
/// - `Unattributable`: a completed task's `TaskOutput` exists but doesn't carry the
///   provider/model attribution `cost.rs`'s cost view needs (e.g. a chat task's
///   `TaskOutput::Text(String::new())`, per `roundhouse-engine`'s `chat.rs`). Deliberately
///   distinct from `NotFound`: this is the *expected*, common case for most completed
///   tasks in a real session, not a data-consistency error — callers that need to treat
///   it as non-fatal (`cost::session_cost_rollup`) match on this variant specifically
///   rather than on `NotFound`.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("migration error: {0}")]
    Migration(#[from] rusqlite_migration::Error),
    #[error("pool error: {0}")]
    Pool(#[from] deadpool_sqlite::PoolError),
    #[error("interact error: {0}")]
    Interact(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("unattributable: {0}")]
    Unattributable(String),
}

/// A WAL-mode SQLite connection pool. The `pool` field is public (not `pub(crate)`) because
/// integration tests in the `tests/` directory (compiled as a separate crate) need direct access
/// to call `.get().await` for connection acquisition. Each pooled connection is configured to
/// use SQLite's Write-Ahead Logging (WAL) mode for improved concurrency and `synchronous=NORMAL`
/// for reasonable durability-vs-performance trade-offs (via post_create hook).
///
/// `Clone` and `Debug` are both `deadpool_sqlite::Pool`'s own (Phase 5 Task 34).
/// `Pool` is documented as "can be cloned and transferred across thread
/// boundaries and uses reference counting for its internal state", so a clone is
/// another handle to the *same* pool, never a second pool — which matters here
/// specifically, because this file records that a second pool constructor was
/// once found silently skipping all three `post_create` pragmas. `Debug` is
/// derived so a handle can live in a `#[derive(Debug)]` struct
/// (`roundhouse_web::AppState`, whose `Debug` is load-bearing for its own
/// tests); it renders the pool's status and the connections' database paths,
/// and no row content.
#[derive(Debug, Clone)]
pub struct StorePool {
    pub pool: deadpool_sqlite::Pool,
}

/// One connection checked out of a [`StorePool`], returned to the pool when it
/// drops.
///
/// A re-export rather than a new type: it *is* `deadpool_sqlite::Object`, and
/// naming it here is what lets a caller store a checked-out connection in a
/// struct of its own without declaring a `deadpool-sqlite` edge. Phase 5 Task
/// 34's fix round added it for `roundhouse_web::StoreConnection`, which pairs a
/// connection with the semaphore permit bounding it so that the two cannot be
/// obtained separately (ruling P93 §B); that crate deliberately names neither
/// `rusqlite` nor `deadpool` (see its manifest), so these three aliases are the
/// whole surface it needs.
pub type PooledConnection = deadpool_sqlite::Object;

/// The connection a [`PooledConnection`]'s `interact` closure is handed.
///
/// The same kind of alias as [`PooledConnection`] above, added by Phase 5 Task
/// 35's third fix round and for the same reason: `roundhouse-web` declares no
/// `rusqlite` edge (ruling P86 removed it on purpose), so this is how it names
/// the type without one.
///
/// Until that round the name was not needed there, because the closure's
/// parameter type was *inferred* — `roundhouse_web::StoreConnection` `Deref`'d
/// to `deadpool`'s wrapper and `.interact` resolved through it. Ruling P103
/// removed that `Deref` so no upstream release can widen what a permitted
/// connection re-exposes, which means the wrapping crate now writes the
/// forwarding signature out, which means it has to be able to spell this.
pub type SqliteConnection = rusqlite::Connection;

/// Why a [`PooledConnection`]'s `interact` closure did not run to completion.
///
/// `deadpool`'s own error, aliased here for the reason
/// [`SqliteConnection`] gives — a caller that forwards `interact` names it in
/// its own signature and must not need a `deadpool-sqlite` edge to do so. It is
/// an error enum with no handle in it, so unlike `deadpool_sqlite::Object` it
/// re-exposes nothing.
pub type InteractError = deadpool_sqlite::InteractError;

/// The `post_create` hook shared by [`open`] and [`open_pool`] — every pooled
/// connection this crate hands out, migrated or not, gets the same three
/// pragmas. Extracted (fix round 2) so there is exactly one place that sets
/// them, after `open_pool` was found to be a second, hook-free pool
/// constructor that skipped all three silently.
fn connection_hooks() -> Hook {
    Hook::sync_fn(|conn, _metrics| {
        let conn = conn
            .lock()
            .map_err(|_| HookError::message("sync wrapper mutex poisoned"))?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(HookError::Backend)?;
        // Every pooled connection gets its own `busy_timeout` (SQLite pragmas are
        // per-connection, not per-database): without it, a connection that hits
        // `SQLITE_BUSY` (another connection holding the write lock) fails
        // immediately instead of retrying internally for a bounded window. The
        // writer task already has its own hand-rolled retry loop around
        // `SQLITE_BUSY` (see `writer.rs`'s append retry), but read-only callers —
        // e.g. `recovery.rs`'s scan — go straight through a pooled connection with
        // no such loop, so without this pragma they surface `SQLITE_BUSY` as a
        // hard error on any contention with the writer.
        conn.pragma_update(None, "busy_timeout", BUSY_TIMEOUT.as_millis() as u32)
            .map_err(HookError::Backend)?;
        // Also per-connection, and set here for that reason. As of store
        // migration 0007 this database holds one column
        // (`workflow_step_run.output`) whose stored value is deliberately
        // NOT redacted, because §8.13's fork inherits real step outputs.
        // Without `secure_delete`, freed cell content keeps its old bytes in
        // the page, so clearing an output can leave the previous value
        // sitting in the file. Measured directly with `sqlite3` (fix round 2,
        // M-1 — the full matrix, not one ordering) on exactly the path
        // `checkpoint_step` uses (`UPDATE … SET output = NULL`):
        //
        // - Pragma OFF: the canary was present in the main db file both
        //   before and after a TRUNCATE checkpoint of the clearing write.
        // - Pragma ON, clearing write NOT YET checkpointed: the canary is
        //   STILL present in the main db file. The cleared page goes to the
        //   `-wal` file as a new frame; the main file is only overwritten
        //   once that frame is checkpointed back.
        // - Pragma ON, clearing write backfilled by a PASSIVE checkpoint
        //   (what SQLite's autocheckpoint performs): the canary is gone from
        //   the main db file, but PASSIVE does not truncate or zero `-wal`,
        //   so the pre-clear page image's raw bytes are still physically
        //   present there.
        // - Pragma ON, clearing write backfilled by a TRUNCATE checkpoint:
        //   the canary is gone from both files.
        //
        // So this pragma bounds residue in the main database file only once
        // the clearing write has itself been checkpointed, and bounds
        // residue in `-wal` only once that checkpoint is a TRUNCATE (or a
        // later frame overwrites the same offset) — not on every ordinary
        // autocheckpoint. It costs additional page writes on delete and
        // update, unmeasured here.
        conn.pragma_update(None, "secure_delete", true)
            .map_err(HookError::Backend)
    })
}

/// Opens a WAL-mode SQLite connection pool at the given filesystem path. Applies all pending
/// schema migrations on the first connection. Every pooled connection is configured with
/// `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=5000ms`, and `secure_delete=ON`
/// for balanced performance, durability, `SQLITE_BUSY` tolerance on the read path, and
/// erasure of freed pages that may have held unredacted step output (migration 0007).
///
/// # Errors
/// Returns `StoreError::Io` if the path is invalid or inaccessible; `StoreError::Sqlite` if
/// SQLite connection fails; `StoreError::Migration` if schema migrations fail to apply;
/// `StoreError::Pool` if the connection pool creation or connection acquisition fails;
/// `StoreError::Interact` if the async executor panics while setting up pragmas.
pub async fn open(path: &Path) -> Result<StorePool, StoreError> {
    let cfg = Config::new(path.to_path_buf());
    let pool = cfg
        .builder(Runtime::Tokio1)
        .expect("deadpool-sqlite config is infallible for a plain path")
        .post_create(connection_hooks())
        .build()
        .expect("pool builder config is valid");

    let conn = pool.get().await?;
    conn.interact(|c| {
        c.pragma_update(None, "journal_mode", "WAL")?;
        c.pragma_update(None, "synchronous", "NORMAL")?;
        c.pragma_update(None, "busy_timeout", BUSY_TIMEOUT.as_millis() as u32)?;
        c.pragma_update(None, "secure_delete", true)?;
        MIGRATIONS.to_latest(c)?;
        // Security fix (Task 0.5 follow-up): backfill `tasks` rows for any task_id
        // already in the event log but missing from `tasks` — e.g. every task that
        // existed before migration 0003 first ran on this database. Idempotent and
        // cheap once complete; see `tasks_view::backfill_tasks_table`'s doc comment.
        crate::tasks_view::backfill_tasks_table(c)?;
        Ok::<_, StoreError>(())
    })
    .await
    .map_err(|e| StoreError::Interact(e.to_string()))??;

    Ok(StorePool { pool })
}
