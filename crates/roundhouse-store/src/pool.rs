use std::path::Path;

use deadpool_sqlite::{Config, Pool, Runtime};
use rusqlite_migration::{Migrations, M};

pub static MIGRATIONS: once_cell::sync::Lazy<Migrations<'static>> =
    once_cell::sync::Lazy::new(|| {
        Migrations::new(vec![M::up(include_str!(
            "../migrations/0001_events.sql"
        ))])
    });

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

pub struct StorePool {
    pub pool: deadpool_sqlite::Pool, // pub, not pub(crate): integration tests in tests/ (Tasks 1, 4) and recovery.rs both need direct access
}

pub async fn open(path: &Path) -> Result<StorePool, StoreError> {
    let cfg = Config::new(path.to_path_buf());
    let pool = cfg
        .create_pool(Runtime::Tokio1)
        .expect("deadpool-sqlite pool config is infallible for a plain path");

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
