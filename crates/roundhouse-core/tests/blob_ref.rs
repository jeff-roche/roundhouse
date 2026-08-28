use roundhouse_core::{Blake3Hash, BlobRef, Delta, TaskInput, TaskOutput};

#[test]
fn blob_ref_round_trips_through_json() {
    let blob = BlobRef { hash: Blake3Hash("abc123".into()), len: 42, mime: Some("text/plain".into()) };
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
    let blob = BlobRef { hash: Blake3Hash("deadbeef".into()), len: 1_000_000, mime: None };

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
