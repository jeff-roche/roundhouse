use roundhouse_core::{Blake3Hash, BlobRef, Delta, TaskInput, TaskOutput};

// The brief's original fixtures ("abc123", "deadbeef") predate the security
// fix that made `Blake3Hash` a validated type (exactly 64 lowercase hex
// chars, matching blake3's own digest length) rather than a bare-`pub`
// tuple struct — see roundhouse-core/src/blob.rs's doc comment for why.
// These are valid-shaped stand-ins, not real content hashes of anything.
const TEST_HASH_1: &str = "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4";
const TEST_HASH_2: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

#[test]
fn blob_ref_round_trips_through_json() {
    let blob = BlobRef {
        hash: Blake3Hash::from_hex(TEST_HASH_1).unwrap(),
        len: 42,
        mime: Some("text/plain".into()),
    };
    let json = serde_json::to_string(&blob).unwrap();
    let back: BlobRef = serde_json::from_str(&json).unwrap();
    assert_eq!(blob, back);
}

#[test]
fn task_input_output_and_delta_all_carry_a_blob_variant() {
    // §4.5: "adding a BlobRef variant to [TaskInput/TaskOutput/Delta] later,
    // after adapters and tools already assume inline payloads" is the cost
    // this task exists to avoid — so all three frozen types must have the
    // variant now, not just one of them.
    let blob = BlobRef { hash: Blake3Hash::from_hex(TEST_HASH_2).unwrap(), len: 1_000_000, mime: None };

    match TaskInput::Blob(blob.clone()) {
        TaskInput::Blob(b) => assert_eq!(b, blob),
        _ => unreachable!(),
    }
    match TaskOutput::Blob(blob.clone()) {
        TaskOutput::Blob(b) => assert_eq!(b, blob),
        _ => unreachable!(),
    }
    match Delta::Blob(blob.clone()) {
        Delta::Blob(b) => assert_eq!(b, blob),
        _ => unreachable!(),
    }
}

// --- Security fix coverage: Blake3Hash must validate on every path into
// existence, since roundhouse-store::blobs::blob_path joins its value
// directly onto a filesystem path. A test that only proves valid hashes
// still work wouldn't prove the path-traversal vulnerability is closed —
// these prove rejection actually fires, at both construction and
// deserialization.

#[test]
fn blake3_hash_rejects_a_path_traversal_string_at_construction() {
    let result = Blake3Hash::from_hex("../../../etc/passwd");
    assert!(result.is_err(), "a path-traversal string must never construct a Blake3Hash");
}

#[test]
fn blake3_hash_rejects_a_path_traversal_string_at_deserialization() {
    // This is the more dangerous path: a BlobRef arriving from persisted
    // event data or another process, deserialized via serde_json rather
    // than constructed in-process.
    let json = r#""../../../etc/passwd""#;
    let result: Result<Blake3Hash, _> = serde_json::from_str(json);
    assert!(
        result.is_err(),
        "deserializing a Blake3Hash from external/persisted data must validate, not silently \
         accept a path-traversal string that a later read_blob call would use to build a path"
    );
}

#[test]
fn blake3_hash_rejects_a_string_starting_with_a_multi_byte_utf8_character() {
    // Also proves the fix for the related panic: blob_path used to slice
    // the hex string at byte index 2 unconditionally, which panics
    // ("byte index 2 is not a char boundary") if the string starts with a
    // multi-byte UTF-8 character. Validating at construction means this
    // string is rejected here and can never reach blob_path unvalidated.
    let with_multibyte_prefix = format!("é{}", "a".repeat(63));
    assert!(Blake3Hash::from_hex(with_multibyte_prefix).is_err());
}

#[test]
fn blake3_hash_rejects_wrong_length_and_uppercase_strings() {
    assert!(Blake3Hash::from_hex("abc123").is_err(), "too short");
    assert!(Blake3Hash::from_hex("a".repeat(65)).is_err(), "too long");
    assert!(Blake3Hash::from_hex("A".repeat(64)).is_err(), "uppercase hex is not accepted");
}

#[test]
fn blake3_hash_accepts_a_valid_64_char_lowercase_hex_string() {
    assert!(Blake3Hash::from_hex(TEST_HASH_1).is_ok());
}
