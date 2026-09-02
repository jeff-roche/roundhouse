//! Per-connection ACP protocol version negotiation, plus an opportunistic
//! hint cache.
//!
//! This module supplies exactly two things: [`negotiate`]/[`negotiate_response`]
//! (read the negotiated version off the wire, per §10.1/§10.2 of the phase
//! plan — never a static per-agent table) and [`VersionHintCache`] (a purely
//! local, in-memory optimization that lets a repeat connection to the same
//! agent binary/version skip a redundant negotiation round; losing it costs
//! nothing but that one round-trip).
//!
//! It does **not** itself pick which of `agent_client_protocol::schema::v1`
//! or `schema::v2` a connection speaks — that per-connection selection lives
//! in the daemon-owned ACP client loop, which is daemon integration work
//! outside this crate and outside this subsystem's task list (no task in
//! Subsystem C imports this module). Whatever call site eventually drives
//! that loop is expected to call [`negotiate_response`] on the SDK's real
//! `InitializeResponse` and act on the resulting [`AcpVersion`].

use agent_client_protocol::schema::v1::InitializeResponse;
use std::collections::HashMap;

/// Which ACP wire schema surface a connection negotiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpVersion {
    V1,
    V2,
}

/// §10.1/§10.2: negotiation reads the protocol's own `initialize` response —
/// a single integer, never a date, never a static per-agent table. v2 stays
/// behind this feature-flagged selection point because the spec itself says
/// not to ship it by default (§10.1) until it stabilizes.
///
/// The SDK's `ProtocolVersion` (`agent_client_protocol::schema::ProtocolVersion`)
/// wraps a `u16`, not a `u32` — this function's parameter type matches that.
pub fn negotiate(declared_protocol_version: u16) -> AcpVersion {
    match declared_protocol_version {
        2 => AcpVersion::V2,
        _ => AcpVersion::V1, // 1, and any value this build doesn't yet recognize
    }
}

/// Reads the negotiated version straight off the SDK's real `initialize`
/// response type (`agent_client_protocol::schema::v1::InitializeResponse`)
/// and delegates to [`negotiate`]. This is the only supported entry point
/// for negotiating against an actual ACP connection; [`negotiate`] itself
/// stays available for testing the integer-selection rule in isolation.
pub fn negotiate_response(resp: &InitializeResponse) -> AcpVersion {
    negotiate(resp.protocol_version.as_u16())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct HintKey {
    agent_binary: String,
    agent_version: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VersionHint {
    pub agent_binary: String,
    pub agent_version: String,
    pub observed: AcpVersion,
}

/// A purely local, opportunistic cache of observed negotiation results,
/// keyed by exact (binary, version) — never a maintained compatibility
/// table (§10.2/§10.4's explicit "nobody maintains this" decision). Losing
/// this cache (restart, new agent version) costs one redundant negotiation
/// round, nothing more.
#[derive(Debug, Default)]
pub struct VersionHintCache(HashMap<HintKey, AcpVersion>);

impl VersionHintCache {
    pub fn new() -> Self {
        VersionHintCache(HashMap::new())
    }
}

pub fn cache_hint(cache: &mut VersionHintCache, hint: VersionHint) {
    cache.0.insert(
        HintKey {
            agent_binary: hint.agent_binary,
            agent_version: hint.agent_version,
        },
        hint.observed,
    );
}

pub fn lookup_hint(
    cache: &VersionHintCache,
    agent_binary: &str,
    agent_version: &str,
) -> Option<AcpVersion> {
    cache
        .0
        .get(&HintKey {
            agent_binary: agent_binary.to_string(),
            agent_version: agent_version.to_string(),
        })
        .copied()
}
