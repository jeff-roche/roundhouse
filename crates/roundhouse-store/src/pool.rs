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
pub struct StorePool {
    pub pool: deadpool_sqlite::Pool,
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
        .post_create(Hook::sync_fn(|conn, _metrics| {
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
            conn.pragma_update(None, "busy_timeout", BUSY_TIMEOUT_MS)
                .map_err(HookError::Backend)?;
            // Also per-connection, and set here for that reason. As of store
            // migration 0007 this database holds one column
            // (`workflow_step_run.output`) whose stored value is deliberately
            // NOT redacted, because §8.13's fork inherits real step outputs.
            // Without `secure_delete`, freed cell content keeps its old bytes
            // in the page, so clearing an output leaves the previous value
            // sitting in the file. Measured, on exactly the path
            // `checkpoint_step` uses (`UPDATE … SET output = NULL`, then a
            // TRUNCATE checkpoint): a canary string was still present in the
            // db file's bytes with the pragma OFF and absent with it ON. What
            // that measurement does NOT cover: an un-checkpointed `-wal`
            // still holds the pre-clear page image, so this bounds residue in
            // the main database file, not in the WAL. It costs additional
            // page writes on delete and update, unmeasured here.
            conn.pragma_update(None, "secure_delete", true)
                .map_err(HookError::Backend)
        }))
        .build()
        .expect("pool builder config is valid");

    let conn = pool.get().await?;
    conn.interact(|c| {
        c.pragma_update(None, "journal_mode", "WAL")?;
        c.pragma_update(None, "synchronous", "NORMAL")?;
        c.pragma_update(None, "busy_timeout", BUSY_TIMEOUT_MS)?;
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

/// How long a connection blocks retrying internally on `SQLITE_BUSY` before
/// giving up and returning the error to the caller. A few seconds is enough to
/// ride out the single writer task's normal append latency without either
/// masking a genuinely stuck lock or making a contended read hang unreasonably.
const BUSY_TIMEOUT_MS: u32 = 5_000;
