use roundhouse_core::Tier;
use serde::Serialize;
use thiserror::Error;

/// §6.4: "such tasks record `enforced_by = RemoteAgentClaim` — the external
/// agent's declared tool call is unverified metadata."
///
/// That `enforced_by` field does not exist anywhere in the codebase today:
/// `roundhouse_core::Provenance` is exactly `{ origin, trust, task }`
/// (`crates/roundhouse-core/src/task_meta.rs:28-37`), with no slot for it.
/// `Provenance` is the intended eventual destination for this value, but
/// wiring `EnforcedBy` onto it is out of scope for this crate (which may
/// not widen `roundhouse-core`'s frozen shape) — that is future daemon-side
/// provenance-extension work, not something this module claims to do.
/// `EnforcedBy` derives `Clone`/`Copy`/`Serialize` so that future extension
/// can carry it without this type needing to change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EnforcedBy(pub &'static str);

pub const REMOTE_AGENT_CLAIM: EnforcedBy = EnforcedBy("RemoteAgentClaim");

#[derive(Debug, Error, PartialEq)]
pub enum RemoteClaimError {
    #[error("ACP-client session tier {0:?} is below the required Tier::Sandbox floor")]
    TierTooLow(Tier),
}

/// §6.4: "Critical: ... an ACP-client session must additionally run at
/// tier `>= Sandbox`." Since an external agent's own permission claims are
/// unverified, the isolation boundary is what actually contains it —
/// policy alone is not enough for a session we don't control the
/// tool-call implementation of.
pub fn validate_acp_client_session_tier(tier: Tier) -> Result<(), RemoteClaimError> {
    if tier >= Tier::Sandbox {
        Ok(())
    } else {
        Err(RemoteClaimError::TierTooLow(tier))
    }
}
