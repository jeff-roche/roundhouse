use rusqlite::{Connection, Transaction, TransactionBehavior};

/// §5.3's trap #2: "always use `BEGIN IMMEDIATE` for write transactions (a
/// deferred txn that later writes returns `SQLITE_BUSY_SNAPSHOT`, for which
/// the busy handler is *not* invoked)." Every write path in later phases
/// must call this, never `conn.transaction()` directly.
pub fn begin_immediate(conn: &mut Connection) -> rusqlite::Result<Transaction<'_>> {
    conn.transaction_with_behavior(TransactionBehavior::Immediate)
}
