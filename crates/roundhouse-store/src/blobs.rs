use roundhouse_core::{Blake3Hash, BlobRef};
use rusqlite::{params, Connection, Transaction};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// §4.5 — git-style sharded-by-prefix layout, avoiding one directory with
/// millions of entries: the first two hex characters of the hash become a
/// subdirectory.
fn blob_path(state_dir: &Path, hash: &Blake3Hash) -> PathBuf {
    let hex = &hash.0;
    let shard = &hex[..hex.len().min(2)];
    state_dir.join("blobs").join(shard).join(hex)
}

/// Content-addresses `bytes` and writes it under
/// `<state_dir>/blobs/<hash[0..2]>/<hash>` via temp-file-then-rename, so a
/// crash mid-write never leaves a partial blob at its final path (§4.5). If
/// a blob with this hash is already on disk, the filesystem write is
/// skipped — identical bytes always collide to the same blob. This
/// function only writes the filesystem side; `record_blob_write` (below)
/// is the caller's separate step for the SQLite index and ref-count bump.
pub fn write_blob(state_dir: &Path, bytes: &[u8], mime: Option<String>) -> io::Result<BlobRef> {
    let hash = Blake3Hash(blake3::hash(bytes).to_hex().to_string());
    let final_path = blob_path(state_dir, &hash);
    if !final_path.exists() {
        if let Some(parent) = final_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp_path = final_path.with_extension("tmp");
        fs::write(&tmp_path, bytes)?;
        fs::rename(&tmp_path, &final_path)?;
    }
    Ok(BlobRef { hash, len: bytes.len() as u64, mime })
}

/// Reads a blob's raw bytes back off disk.
pub fn read_blob(state_dir: &Path, blob_ref: &BlobRef) -> io::Result<Vec<u8>> {
    fs::read(blob_path(state_dir, &blob_ref.hash))
}

/// Inserts (first reference) or bumps `ref_count` on (subsequent
/// references — including a duplicate write of identical content) the
/// `blobs` row for `blob_ref`. **Must be called in the same transaction the
/// caller uses to append the owning event** — never a separate one — per
/// §4.5's "a blob can never be referenced by an event that isn't durably
/// recorded, and vice versa." Phase 0 delivers this function; wiring the
/// call site into the real event-append transaction is Phase 1's
/// `roundhouse-store` work (the same deferral Task 10's Interfaces note
/// already states for the event-append path itself).
pub fn record_blob_write(txn: &Transaction, blob_ref: &BlobRef, now: i64) -> rusqlite::Result<()> {
    txn.execute(
        "INSERT INTO blobs (hash, len, mime, created_at, last_referenced_at, ref_count) \
         VALUES (?1, ?2, ?3, ?4, ?4, 1) \
         ON CONFLICT(hash) DO UPDATE SET ref_count = ref_count + 1, last_referenced_at = ?4",
        params![blob_ref.hash.0, blob_ref.len as i64, blob_ref.mime, now],
    )?;
    Ok(())
}

/// Decrements `ref_count` (e.g. when the session/event owning a reference
/// is closed or GC'd). Never deletes anything here — reaching
/// `ref_count == 0` only makes a blob GC-*eligible* (see
/// `gc_eligible_blobs`); actual deletion still waits out the grace period
/// (§4.5) and is a later phase's daemon-scheduled job.
pub fn decrement_ref_count(txn: &Transaction, hash: &Blake3Hash) -> rusqlite::Result<()> {
    txn.execute("UPDATE blobs SET ref_count = MAX(ref_count - 1, 0) WHERE hash = ?1", params![hash.0])?;
    Ok(())
}

/// §4.5's GC-eligibility rule, minus the daemon scheduling around it: every
/// blob with `ref_count == 0` whose `last_referenced_at` is at least
/// `grace_period_secs` old as of `now` (all as Unix-seconds `i64`, matching
/// this crate's other integer-timestamp columns). The daily background
/// task that calls this on a schedule, and the file deletion + `Note`-event
/// logging §4.5 requires on top of it, are `roundhouse-daemon` work for a
/// later phase — this task ships the pure query they'll call.
pub fn gc_eligible_blobs(conn: &Connection, now: i64, grace_period_secs: i64) -> rusqlite::Result<Vec<Blake3Hash>> {
    let mut stmt = conn.prepare("SELECT hash FROM blobs WHERE ref_count = 0 AND (?1 - last_referenced_at) >= ?2")?;
    let hashes = stmt
        .query_map(params![now, grace_period_secs], |row| row.get::<_, String>(0))?
        .map(|r| r.map(Blake3Hash))
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(hashes)
}

#[derive(Debug, thiserror::Error)]
pub enum QuotaError {
    #[error(
        "writing {attempted_bytes} more bytes would exceed the workspace's {quota_bytes}-byte \
         blob quota (currently at {current_usage_bytes})"
    )]
    WouldExceedQuota { current_usage_bytes: u64, attempted_bytes: u64, quota_bytes: u64 },
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// §4.5's per-workspace quota check, Phase-0-scoped: the caller supplies the
/// workspace's *current* blob usage. Computing that for real requires
/// joining `blobs` against the events/sessions that reference them per
/// workspace — the `blobs` table itself deliberately has no workspace
/// column (matching §4.5's schema exactly: a blob can be shared by more
/// than one workspace's sessions via content-addressed dedup, so "this
/// blob belongs to workspace X" isn't well-defined at the row level; only
/// "how many bytes does workspace X's *reachable* set of blobs sum to" is,
/// and answering that needs the event-append/query machinery Phase 1
/// builds). This function owns the one part of the quota rule that's pure
/// and Phase-0-ownable: reject a write that would exceed the quota,
/// structurally, before it happens. Reclaiming GC-eligible blobs first and
/// emitting the synchronous `Degradation` event on rejection (§4.5) both
/// require the daemon/event paths and are later-phase wiring.
pub fn write_blob_with_quota(
    state_dir: &Path,
    current_usage_bytes: u64,
    quota_bytes: u64,
    bytes: &[u8],
    mime: Option<String>,
) -> Result<BlobRef, QuotaError> {
    let attempted_bytes = bytes.len() as u64;
    if current_usage_bytes + attempted_bytes > quota_bytes {
        return Err(QuotaError::WouldExceedQuota { current_usage_bytes, attempted_bytes, quota_bytes });
    }
    Ok(write_blob(state_dir, bytes, mime)?)
}
