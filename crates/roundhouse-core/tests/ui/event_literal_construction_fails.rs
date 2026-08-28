// This file is compiled by `trybuild` as its own crate that merely
// *depends on* roundhouse-core — exactly the position every downstream
// crate (roundhouse-tools, roundhouse-mcp, ...) is in. It must fail to
// compile, proving Event cannot be struct-literal-constructed from outside
// roundhouse-core.
fn main() {
    let _event = roundhouse_core::Event {
        session_id: roundhouse_core::SessionId::new(),
        seq: 1,
        ts: roundhouse_core::Timestamp::from_unix_nanos(0),
        task_id: None,
        payload: roundhouse_core::EventPayload::Note {
            level: roundhouse_core::NoteLevel::Info,
            text: "bypass attempt".into(),
        },
        schema_v: 1,
    };
}
