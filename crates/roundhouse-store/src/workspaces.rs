//! Persistence primitives for the daemon-owned workspace identity registry.

use crate::txn::{
    begin_immediate, is_sqlite_busy, with_bounded_busy_attempt, INITIAL_BACKOFF, MAX_BUSY_RETRIES,
};
use crate::{StoreError, StorePool};

/// A persisted workspace identity. The daemon validates the path fields before
/// exposing this row to execution code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRow {
    pub id: String,
    pub name: String,
    pub root_path: String,
    pub canonical_root: String,
    pub root_device: Option<i64>,
    pub root_inode: Option<i64>,
}

/// Loads every persisted workspace identity.
pub async fn workspace_rows(store: &StorePool) -> Result<Vec<WorkspaceRow>, StoreError> {
    let conn = store.pool.get().await?;
    let result = conn
        .interact(|connection| -> Result<Vec<WorkspaceRow>, rusqlite::Error> {
            let mut statement = connection.prepare(
                "SELECT workspace_id, name, root_path, canonical_root, root_device, root_inode \
                 FROM workspaces ORDER BY name",
            )?;
            let rows = statement
                .query_map([], |row| {
                    Ok(WorkspaceRow {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        root_path: row.get(2)?,
                        canonical_root: row.get(3)?,
                        root_device: row.get(4)?,
                        root_inode: row.get(5)?,
                    })
                })?
                .collect();
            rows
        })
        .await
        .map_err(|error| StoreError::Interact(error.to_string()))?;
    result.map_err(StoreError::Sqlite)
}

/// Inserts an immutable workspace identity.
pub async fn insert_workspace(store: &StorePool, row: &WorkspaceRow) -> Result<(), StoreError> {
    let conn = store.pool.get().await?;
    let mut attempt = 0;
    loop {
        attempt += 1;
        let row = row.clone();
        let result = conn
            .interact(move |connection| {
                with_bounded_busy_attempt(connection, |connection| {
                    let tx = begin_immediate(connection)?;
                    tx.execute(
                        "INSERT INTO workspaces \
                         (workspace_id, name, root_path, canonical_root, root_device, root_inode) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        rusqlite::params![
                            row.id,
                            row.name,
                            row.root_path,
                            row.canonical_root,
                            row.root_device,
                            row.root_inode
                        ],
                    )?;
                    tx.commit()
                })
            })
            .await
            .map_err(|error| StoreError::Interact(error.to_string()))?;

        match result {
            Ok(()) => return Ok(()),
            Err(error) if is_sqlite_busy(&error) && attempt < MAX_BUSY_RETRIES => {
                tokio::time::sleep(INITIAL_BACKOFF * 2u32.pow(attempt - 1)).await;
            }
            Err(error) => return Err(StoreError::Sqlite(error)),
        }
    }
}
