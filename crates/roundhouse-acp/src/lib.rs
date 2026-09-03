//! The ACP (Agent Client Protocol) client and server: lets Roundhouse act
//! as an ACP-speaking editor's agent, and lets Roundhouse itself drive
//! other ACP-speaking agents, over the same `agent-client-protocol` wire
//! format other editors and agents already use.
//!
//! Phase 5, Subsystem C landed this crate's contents. It is a library of
//! protocol-shaped pieces with no I/O and no live connection of its own:
//! driving an actual ACP session — spawning or attaching to a peer, running
//! the JSON-RPC loop, owning sessions — is daemon integration work, and this
//! crate depends only on `roundhouse-core` and `roundhouse-proto`.
//!
//! What is here, by module:
//!
//! - [`server`] — the incoming-permission surface: answering
//!   `session/request_permission` by selecting one of the options the peer
//!   itself offered (never a fabricated verdict enum), and normalizing a tool
//!   call for the policy engine. Despite the path, this is the ACP *client*
//!   role; see the module doc.
//! - [`decision`] — the one internal decision shape both crossing directions
//!   adapt into, including the structured error a denied tool call carries
//!   back into model context.
//! - [`elicit`] — normalizes ACP's and MCP's two divergent elicitation wire
//!   shapes into one request bound to `roundhouse-core`'s `elicit` task and
//!   suspend reason.
//! - [`client::mapping`] — the client-side direction: ACP `session/update`
//!   notifications mapped onto `roundhouse-core` `Delta`/`EventPayload`
//!   values, with the variant count derived from the enum itself so a new
//!   upstream variant cannot be waved through.
//! - [`version`] — per-connection protocol version negotiation read off the
//!   wire (never a static per-agent table), plus a local hint cache.
//! - `schema` — helpers over the SDK's v2 surface (tri-state
//!   `MaybeUndefined` merging, open-enum round-tripping). The whole module
//!   tree is gated behind this crate's `acp-v2` feature, so it is absent
//!   (and unlinkable from here) in a default build.
//! - [`mcp_over_acp`] — the in-process MCP tool registry a v2 ACP client
//!   serves over the existing channel; the transport half is daemon work.
//! - [`registry`] — the real `agentclientprotocol/registry` install index:
//!   fetch, cache, quarantine, and `resolve_launch`, the only route to an
//!   agent's launch configuration.
//! - [`peer_text`] — the crate's untrusted-text discipline: everything a
//!   peer or the registry controls is escaped and length-capped into an
//!   `EscapedPeerStr` before it can reach a log line or an error message.
//! - [`remote_claim`] — the marker recording that an external agent's
//!   declared tool call is unverified metadata.
//!
//! See `docs/architecture/02-system-architecture.md` §5.2 and
//! `07-protocols-acp-mcp.md`.
#![forbid(unsafe_code)]

pub mod client;
pub mod decision;
pub mod elicit;
pub mod mcp_over_acp;
pub mod peer_text;
pub mod registry;
pub mod remote_claim;
#[cfg(feature = "acp-v2")]
pub mod schema;
pub mod server;
pub mod version;

use roundhouse_proto::ApiVersion;

/// Roundhouse's own API version, as `roundhouse-proto` defines it — not an
/// ACP protocol version. ACP's per-connection version is negotiated on the
/// wire by [`version::negotiate`]; this is the Phase 0 seam that proves this
/// crate builds against `roundhouse-proto`, and it is unrelated to the
/// protocol handshake.
pub fn negotiated_api_version() -> ApiVersion {
    ApiVersion::CURRENT
}
