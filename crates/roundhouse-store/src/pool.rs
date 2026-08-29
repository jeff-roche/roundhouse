use std::path::Path;

use deadpool_sqlite::{Config, Hook, HookError, Pool, Runtime};

/// The migration harness for this crate's SQLite schema. Wraps Phase 0's complete
/// migrations (events table with append-only triggers, tasks table, FTS5 index, and
/// blobs table) in a lazy static for use with `deadpool_sqlite`'s connection pool.
/// Initialize and run all migrations on first pool connection via `MIGRATIONS.to_latest()`.
pub static MIGRATIONS: once_cell::sync::Lazy<rusqlite_migration::Migrations<'static>> =
    once_cell::sync::Lazy::new(crate::migrations::migrations);

/// One writer task, WAL, per §5.3. Phase 0 wires the pool configuration;
/// the single-writer discipline itself (one dedicated task owning all
/// writes) is Phase 1's `roundhouse-store` event-append work (§13.2).
pub fn open_pool(path: &Path) -> Pool {
    let cfg = Config::new(path);
    cfg.create_pool(Runtime::Tokio1)
        .expect("deadpool-sqlite pool config is infallible for a plain path")
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
}

/// A WAL-mode SQLite connection pool. The `pool` field is public (not `pub(crate)`) because
/// integration tests in the `tests/` directory (compiled as a separate crate) need direct access
/// to call `.get().await` for connection acquisition. Each pooled connection is configured to
/// use SQLite's Write-Ahead Logging (WAL) mode for improved concurrency and `synchronous=NORMAL`
/// for reasonable durability-vs-performance trade-offs (via post_create hook).
pub struct StorePool {
    pub pool: deadpool_sqlite::Pool,
}

/// Opens a WAL-mode SQLite connection pool at the given filesystem path. Applies all pending
/// schema migrations on the first connection. Every pooled connection is configured with
/// `journal_mode=WAL` and `synchronous=NORMAL` for balanced performance and durability.
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
        .post_create(Hook::sync_fn(|conn, _metrics| {
            conn.lock()
                .map_err(|_| HookError::message("sync wrapper mutex poisoned"))?
                .pragma_update(None, "synchronous", "NORMAL")
                .map_err(HookError::Backend)
        }))
        .build()
        .expect("pool builder config is valid");

    let conn = pool.get().await?;
    conn.interact(|c| {
        c.pragma_update(None, "journal_mode", "WAL")?;
        c.pragma_update(None, "synchronous", "NORMAL")?;
        MIGRATIONS.to_latest(c)?;
        Ok::<_, StoreError>(())
    })
    .await
    .map_err(|e| StoreError::Interact(e.to_string()))??;

    Ok(StorePool { pool })
}
