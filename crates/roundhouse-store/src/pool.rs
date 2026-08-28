use deadpool_sqlite::{Config, Pool, Runtime};
use std::path::Path;

/// One writer task, WAL, per §5.3. Phase 0 wires the pool configuration;
/// the single-writer discipline itself (one dedicated task owning all
/// writes) is Phase 1's `roundhouse-store` event-append work (§13.2).
pub fn open_pool(path: &Path) -> Pool {
    let cfg = Config::new(path);
    cfg.create_pool(Runtime::Tokio1).expect("deadpool-sqlite pool config is infallible for a plain path")
}

/// Test-only helper: an in-memory connection with migrations not yet
/// applied, for `to_latest` to run against directly in unit tests.
pub fn open_memory_connection() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory sqlite connection");
    conn.pragma_update(None, "journal_mode", "WAL").ok(); // no-op on :memory:, harmless
    conn
}
