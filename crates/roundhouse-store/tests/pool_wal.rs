use roundhouse_store::{open, StoreError};

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
