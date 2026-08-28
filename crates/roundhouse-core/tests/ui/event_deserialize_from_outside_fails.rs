// Proves `Event` cannot be reconstructed via `serde_json::from_str` from
// outside roundhouse-core either. This is the exact bypass a naive
// `#[derive(Deserialize)]` on `Event` (with `#[serde(skip, default)]` on
// the seal field) would have left open: the derive would still compile and
// run from any crate, `TaskRunner` untouched.
fn main() {
    let json = r#"{
        "session_id": "00000000-0000-0000-0000-000000000000",
        "seq": 1,
        "ts": 0,
        "task_id": null,
        "payload": {"Note": {"level": "Info", "text": "bypass attempt"}},
        "schema_v": 1
    }"#;
    let _event: roundhouse_core::Event = serde_json::from_str(json).unwrap();
}
