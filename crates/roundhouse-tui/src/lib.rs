#![forbid(unsafe_code)]

pub fn client_schema() -> schemars::Schema {
    roundhouse_proto::client_event_schema()
}
