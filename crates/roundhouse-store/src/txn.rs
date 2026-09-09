use rusqlite::{Connection, Transaction, TransactionBehavior};
use std::time::Duration;

pub(crate) const MAX_BUSY_RETRIES: u32 = 8;
pub(crate) const INITIAL_BACKOFF: Duration = Duration::from_millis(5);
pub(crate) const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// §5.3's trap #2: "always use `BEGIN IMMEDIATE` for write transactions (a
/// deferred txn that later writes returns `SQLITE_BUSY_SNAPSHOT`, for which
/// the busy handler is *not* invoked)." Every write path in later phases
/// must call this, never `conn.transaction()` directly.
pub fn begin_immediate(conn: &mut Connection) -> rusqlite::Result<Transaction<'_>> {
    conn.transaction_with_behavior(TransactionBehavior::Immediate)
}

/// Runs one write attempt without also waiting on SQLite's connection-level
/// busy handler. The caller owns the bounded retry loop; leaving the default
/// busy timeout enabled would multiply that loop's bound by five seconds per
/// attempt.
pub(crate) fn with_bounded_busy_attempt<T>(
    conn: &mut Connection,
    operation: impl FnOnce(&mut Connection) -> rusqlite::Result<T>,
) -> rusqlite::Result<T> {
    conn.busy_timeout(Duration::ZERO)?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| operation(conn)));
    let restore = conn.busy_timeout(BUSY_TIMEOUT);
    match result {
        Err(payload) => {
            std::panic::resume_unwind(payload);
        }
        Ok(Ok(value)) => restore.map(|()| value),
        Ok(Err(error)) => match restore {
            Ok(()) => Err(error),
            Err(restore_error) => Err(restore_error),
        },
    }
}

pub(crate) fn is_sqlite_busy(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(ffi_err, _)
            if ffi_err.code == rusqlite::ErrorCode::DatabaseBusy
    )
}
