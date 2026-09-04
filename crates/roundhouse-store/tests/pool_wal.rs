use roundhouse_store::{open, open_pool, StoreError};

#[tokio::test]
async fn opens_pool_and_enables_wal() -> Result<(), StoreError> {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");

    let store = open(&db_path).await?;
    let conn = store.pool.get().await.unwrap();

    let journal_mode: String = conn
        .interact(|c| c.query_row("PRAGMA journal_mode", [], |row| row.get(0)))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(journal_mode, "wal");
    Ok(())
}

/// Fix round 2: `open_pool` used to build its pool with `Config::create_pool`,
/// which attaches no `post_create` hook — so a connection obtained through it
/// got none of `synchronous`/`busy_timeout`/`secure_delete`, unlike every
/// connection `open()` hands out. Now both go through the same shared hook.
/// Pinned directly against the pragma values a connection actually reports,
/// not against the source not changing back.
#[tokio::test]
async fn open_pool_connections_get_the_same_pragmas_as_open() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");

    let pool = open_pool(&db_path);
    let conn = pool.get().await.unwrap();

    let secure_delete: i64 = conn
        .interact(|c| c.query_row("PRAGMA secure_delete", [], |row| row.get(0)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(secure_delete, 1, "open_pool must set secure_delete = ON");

    let synchronous: i64 = conn
        .interact(|c| c.query_row("PRAGMA synchronous", [], |row| row.get(0)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(synchronous, 1, "NORMAL is synchronous level 1");

    let busy_timeout: i64 = conn
        .interact(|c| c.query_row("PRAGMA busy_timeout", [], |row| row.get(0)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(busy_timeout, 5_000);
}
