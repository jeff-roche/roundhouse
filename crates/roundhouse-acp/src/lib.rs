//! The ACP (Agent Client Protocol) client and server: lets Roundhouse act
//! as an ACP-speaking editor's agent, and lets Roundhouse itself drive
//! other ACP-speaking agents, over the same `agent-client-protocol` wire
//! format other editors and agents already use.
//!
//! Phase 0 only proves this crate compiles against `roundhouse-proto`'s
//! `ApiVersion` type (`negotiated_api_version` below); no real ACP
//! client/server exists yet — that's Phase 5 work. See
//! `docs/architecture/02-system-architecture.md` §5.2 and
//! `07-protocols-acp-mcp.md`.
#![forbid(unsafe_code)]

use roundhouse_proto::ApiVersion;

pub fn negotiated_api_version() -> ApiVersion {
    ApiVersion::CURRENT
}
