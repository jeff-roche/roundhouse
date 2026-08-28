use schemars::{schema_for, Schema};

/// The one schema-emission entry point downstream tooling (`round doctor`,
/// generated client SDKs, docs) calls. Kept as a function rather than a
/// static so future variants can be generated lazily without a startup cost.
pub fn client_event_schema() -> Schema {
    schema_for!(crate::wire::ClientEvent)
}

pub fn client_request_schema() -> Schema {
    schema_for!(crate::wire::ClientRequest)
}
