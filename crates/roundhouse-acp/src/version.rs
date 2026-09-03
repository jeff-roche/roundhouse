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

use crate::peer_text::EscapedPeerStr;
use agent_client_protocol::schema::v1::InitializeResponse;
use std::collections::{HashMap, VecDeque};

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

/// **Task C8 (fold-in item):** `agent_binary`/`agent_version` are peer-self-
/// reported (via `InitializeResponse.agent_info`) — the same untrusted-text
/// class `crate::peer_text` exists for. Bare `pub String` fields were
/// reachable via this struct's derived `Debug`, which escapes control
/// characters (`String`'s own `Debug` impl does that) but does not cap
/// length, unlike [`EscapedPeerStr`]. `MAX_HINTS` below already bounds the
/// *count* of distinct hints kept; this bounds the *size* of each one.
///
/// **Fix round 2 (Item 6): these escaped, capped fields are for display
/// only — [`cache_hint`] does not key the cache on them.** It used to: the
/// cache key was built from `EscapedPeerStr::as_str()` (escaped *and*
/// capped to [`crate::peer_text::PEER_STR_MAX_LEN`] bytes), so two distinct
/// `(agent_binary, agent_version)` identities that happened to share their
/// first 128 escaped bytes collided into the same cache slot —
/// `lookup_hint` could then return a stale hint observed for a *different*
/// agent identity, silently, which is a wrong answer, not merely a lost
/// one (contradicting this module's own doc above: "losing a hint... costs
/// one redundant negotiation round, nothing more"). [`cache_hint`] and
/// [`lookup_hint`] now take the raw `agent_binary`/`agent_version` strings
/// directly and key on those — the same "key on the raw identity, escape
/// only for display" split `mcp_over_acp::InProcessMcpServer::register`
/// already establishes for tool names in this crate (its `BTreeMap` key is
/// the raw `String`; `escape_and_cap_peer_str` is applied only when
/// building the `DuplicateToolName` error's rendered message). This struct
/// keeps its escaped fields because a future caller logging *which* hint
/// was cached/reused still needs a safe-to-render form of the identity —
/// only the cache's own identity/lookup logic must not use it.
#[derive(Debug, Clone, PartialEq)]
pub struct VersionHint {
    pub agent_binary: EscapedPeerStr,
    pub agent_version: EscapedPeerStr,
    pub observed: AcpVersion,
}

/// Cap on the number of distinct (binary, version) hints kept at once. The
/// natural source for `agent_version` is `InitializeResponse.agent_info`,
/// which the connecting agent self-reports — an agent that reports a fresh
/// value per connection (accidentally or otherwise) would otherwise grow
/// this map without bound in a long-lived daemon.
/// `hint_cache_stays_bounded_when_an_agent_self_reports_unbounded_distinct_versions`
/// (`tests/version_negotiation.rs`) inserts past this cap and asserts the
/// map never exceeds it.
const MAX_HINTS: usize = 256;

/// A purely local, opportunistic cache of observed negotiation results,
/// keyed by exact (binary, version) — never a maintained compatibility
/// table (§10.2/§10.4's explicit "nobody maintains this" decision). Losing
/// a hint (restart, new agent version, or eviction under `MAX_HINTS`) costs
/// one redundant negotiation round, nothing more — so eviction just needs
/// to keep the map bounded, not be exact: on overflow this evicts the
/// oldest-inserted key (tracked by `order`), a plain FIFO with no attempt
/// at LRU/usage-based ranking.
#[derive(Debug, Default)]
pub struct VersionHintCache {
    hints: HashMap<HintKey, AcpVersion>,
    order: VecDeque<HintKey>,
}

impl VersionHintCache {
    pub fn new() -> Self {
        VersionHintCache {
            hints: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.hints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hints.is_empty()
    }
}

/// Fix round 2 (Item 6): `agent_binary`/`agent_version` are the **raw**
/// identity to key the cache on — see [`VersionHint`]'s doc for why this
/// changed from keying off `hint`'s escaped fields. `hint.observed` is the
/// only part of `hint` this function actually stores; its
/// `agent_binary`/`agent_version` fields exist for a caller that wants a
/// safe-to-render copy of the identity alongside the raw one, not for this
/// function's own bookkeeping. `HintKey` stays plain `String` internally
/// (it's a private hashmap key, never exposed) — deliberately not widened
/// to `EscapedPeerStr` just to match field-for-field, since that would need
/// `EscapedPeerStr: Hash`, which nothing else in the crate requires yet.
pub fn cache_hint(
    cache: &mut VersionHintCache,
    agent_binary: &str,
    agent_version: &str,
    hint: VersionHint,
) {
    let key = HintKey {
        agent_binary: agent_binary.to_string(),
        agent_version: agent_version.to_string(),
    };
    if !cache.hints.contains_key(&key) {
        if cache.hints.len() >= MAX_HINTS {
            if let Some(oldest) = cache.order.pop_front() {
                cache.hints.remove(&oldest);
            }
        }
        cache.order.push_back(key.clone());
    }
    cache.hints.insert(key, hint.observed);
}

/// Fix round 2 (Item 6): keys directly on the **raw** `agent_binary`/
/// `agent_version` — no escaping, matching [`cache_hint`]'s key exactly.
/// Before this round, this routed both parameters through
/// `escape_and_cap_peer_str` first, which is what caused two distinct
/// identities sharing an escaped-and-capped 128-byte prefix to collide into
/// the same slot (see [`VersionHint`]'s doc) — escaping was never necessary
/// for a `HashMap` key in the first place, since exact byte equality is all
/// a key needs, and it actively discarded the exactness a raw `String`
/// already had.
pub fn lookup_hint(
    cache: &VersionHintCache,
    agent_binary: &str,
    agent_version: &str,
) -> Option<AcpVersion> {
    cache
        .hints
        .get(&HintKey {
            agent_binary: agent_binary.to_string(),
            agent_version: agent_version.to_string(),
        })
        .copied()
}
