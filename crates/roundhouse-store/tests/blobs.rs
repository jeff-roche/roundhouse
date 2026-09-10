use roundhouse_core::{Blake3Hash, BlobRef};
use roundhouse_store::blobs::{
    decrement_ref_count, gc_eligible_blobs, read_blob, read_verified_blob, record_blob_write,
    write_blob, write_blob_with_quota, QuotaError, RecordBlobError,
};
use roundhouse_store::{begin_immediate, migrations, open_memory_connection};

fn seeded_conn() -> rusqlite::Connection {
    let mut conn = open_memory_connection();
    migrations().to_latest(&mut conn).unwrap();
    conn
}

#[test]
fn verified_blob_read_rejects_bytes_changed_after_the_reference_was_created() {
    let dir = tempfile::tempdir().unwrap();
    let blob = write_blob(dir.path(), b"original", None).unwrap();
    let path = dir
        .path()
        .join("blobs")
        .join(&blob.hash.as_str()[..2])
        .join(blob.hash.as_str());
    std::fs::write(path, b"tampered").unwrap();

    assert!(read_verified_blob(dir.path(), &blob).is_err());
}

#[test]
fn writing_identical_content_twice_produces_one_blob_with_ref_count_two() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = seeded_conn();

    let blob_a = write_blob(dir.path(), b"same content", Some("text/plain".into())).unwrap();
    {
        let txn = begin_immediate(&mut conn).unwrap();
        record_blob_write(&txn, dir.path(), &blob_a, 1_000).unwrap();
        txn.commit().unwrap();
    }

    let blob_b = write_blob(dir.path(), b"same content", Some("text/plain".into())).unwrap();
    assert_eq!(
        blob_a.hash, blob_b.hash,
        "identical bytes must collide to the same content address"
    );
    {
        let txn = begin_immediate(&mut conn).unwrap();
        record_blob_write(&txn, dir.path(), &blob_b, 2_000).unwrap();
        txn.commit().unwrap();
    }

    let ref_count: i64 = conn
        .query_row(
            "SELECT ref_count FROM blobs WHERE hash = ?1",
            [blob_a.hash.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        ref_count, 2,
        "two writes of the same content must bump ref_count to 2, not create two rows"
    );

    assert_eq!(read_blob(dir.path(), &blob_a).unwrap(), b"same content");
}

#[test]
fn a_blob_with_zero_ref_count_past_the_grace_period_is_gc_eligible() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = seeded_conn();

    let blob = write_blob(dir.path(), b"orphaned", None).unwrap();
    {
        let txn = begin_immediate(&mut conn).unwrap();
        record_blob_write(&txn, dir.path(), &blob, 1_000).unwrap();
        txn.commit().unwrap();
    }
    {
        let txn = begin_immediate(&mut conn).unwrap();
        decrement_ref_count(&txn, &blob.hash).unwrap();
        txn.commit().unwrap();
    }

    let seven_days = 7 * 24 * 3600;
    let too_soon = gc_eligible_blobs(&conn, 1_000 + 60, seven_days).unwrap();
    assert!(
        too_soon.is_empty(),
        "a blob still inside its grace period must not be GC-eligible yet"
    );

    let past_grace_period = 1_000 + seven_days + 60;
    let eligible = gc_eligible_blobs(&conn, past_grace_period, seven_days).unwrap();
    assert_eq!(
        eligible,
        vec![blob.hash],
        "a ref_count==0 blob past the grace period must be GC-eligible"
    );
}

#[test]
fn write_beyond_the_configured_quota_is_rejected() {
    let dir = tempfile::tempdir().unwrap();

    let result = write_blob_with_quota(dir.path(), 900, 1_000, &[0u8; 200], None);
    match result {
        Err(QuotaError::WouldExceedQuota {
            current_usage_bytes: 900,
            attempted_bytes: 200,
            quota_bytes: 1_000,
        }) => {}
        other => panic!("expected WouldExceedQuota, got {other:?}"),
    }

    // A write that fits within the remaining quota still succeeds.
    assert!(write_blob_with_quota(dir.path(), 100, 1_000, &[0u8; 200], None).is_ok());
}

#[test]
fn record_blob_write_rejects_a_blob_ref_whose_file_is_missing_on_disk() {
    // Security fix: record_blob_write must not trust a caller-supplied
    // BlobRef that didn't come from a real write_blob call in this process
    // (e.g. one reconstructed from persisted/external event data) — it
    // must verify the content-addressed file actually exists before
    // indexing it, or the `blobs` table can diverge from what's on disk.
    let dir = tempfile::tempdir().unwrap();
    let mut conn = seeded_conn();

    let phantom_hash = "c".repeat(64);
    let phantom = BlobRef {
        hash: Blake3Hash::from_hex(phantom_hash).unwrap(),
        len: 4,
        mime: None,
    };

    let txn = begin_immediate(&mut conn).unwrap();
    let result = record_blob_write(&txn, dir.path(), &phantom, 1_000);
    match result {
        Err(RecordBlobError::MissingFile { hash, .. }) => assert_eq!(hash, phantom.hash),
        other => panic!("expected RecordBlobError::MissingFile, got {other:?}"),
    }
}
