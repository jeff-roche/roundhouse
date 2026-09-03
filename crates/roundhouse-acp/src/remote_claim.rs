use roundhouse_core::{Tier, Trust};
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
///
/// The inner value is private: [`REMOTE_AGENT_CLAIM`] is the only value of
/// this type this crate mints. A public field would let any crate fabricate
/// its own `EnforcedBy("LocalPolicy")` marker on an ACP task once one is
/// wired to `Provenance` — the whole point of this type is that only
/// `roundhouse-acp` gets to say a task's enforcement came from an unverified
/// remote agent claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EnforcedBy(&'static str);

impl EnforcedBy {
    /// The marker's wire/display form, e.g. for logging or `Serialize`
    /// consumers that want the raw string rather than the newtype.
    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

pub const REMOTE_AGENT_CLAIM: EnforcedBy = EnforcedBy("RemoteAgentClaim");

/// §6.8: "every content block carries `Provenance { origin, trust, task }`"
/// and untrusted covers "... ACP external agent claims ...". This is the
/// live, reachable mechanism (`roundhouse_core::Trust`, already `Provenance`'s
/// `trust` field, already wired by `roundhouse-mcp` for its own untrusted
/// content) that ACP-client-driven work should be marked with today, as
/// opposed to `EnforcedBy`/`Provenance.enforced_by` above, which does not
/// exist yet. An external agent's declared tool calls are unverified
/// metadata by definition, so they are always `Trust::Untrusted`.
pub fn acp_client_content_trust() -> Trust {
    Trust::Untrusted
}

#[derive(Debug, Error, PartialEq)]
pub enum RemoteClaimError {
    #[error("ACP-client session tier {0:?} is below the required Tier::Sandbox floor")]
    TierTooLow(Tier),
}

/// A `Tier` that has been checked to satisfy §6.4's "an ACP-client session
/// must additionally run at tier `>= Sandbox`" rule. The inner field is
/// private and the only constructor is [`TryFrom<Tier>`](TryFrom) (via
/// [`validate_acp_client_session_tier`]), so a bare, unvalidated `Tier`
/// cannot be mistaken for one that has cleared this floor: every future
/// ACP-client entry point should take `AcpClientTier`, never a bare `Tier`,
/// so "forgot to validate" is a compile error rather than a review miss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcpClientTier(Tier);

impl AcpClientTier {
    pub fn tier(&self) -> Tier {
        self.0
    }
}

impl TryFrom<Tier> for AcpClientTier {
    type Error = RemoteClaimError;

    fn try_from(tier: Tier) -> Result<Self, Self::Error> {
        if tier >= Tier::Sandbox {
            Ok(AcpClientTier(tier))
        } else {
            Err(RemoteClaimError::TierTooLow(tier))
        }
    }
}

/// §6.4: "Critical: ... an ACP-client session must additionally run at
/// tier `>= Sandbox`." Since an external agent's own permission claims are
/// unverified, the isolation boundary is what actually contains it —
/// policy alone is not enough for a session we don't control the
/// tool-call implementation of.
///
/// Implemented in terms of [`AcpClientTier`]'s `TryFrom` so the `>= Sandbox`
/// rule lives in exactly one place; this function stays available because
/// the plan names it directly, but new call sites should prefer
/// `AcpClientTier::try_from` so they end up holding the validated newtype.
pub fn validate_acp_client_session_tier(tier: Tier) -> Result<(), RemoteClaimError> {
    AcpClientTier::try_from(tier).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acp_client_tier_rejects_below_sandbox() {
        assert_eq!(
            AcpClientTier::try_from(Tier::None),
            Err(RemoteClaimError::TierTooLow(Tier::None))
        );
        assert_eq!(
            AcpClientTier::try_from(Tier::Worktree),
            Err(RemoteClaimError::TierTooLow(Tier::Worktree))
        );
    }

    #[test]
    fn acp_client_tier_accepts_sandbox_or_higher() {
        assert_eq!(
            AcpClientTier::try_from(Tier::Sandbox).unwrap().tier(),
            Tier::Sandbox
        );
        assert_eq!(
            AcpClientTier::try_from(Tier::Container).unwrap().tier(),
            Tier::Container
        );
        assert_eq!(
            AcpClientTier::try_from(Tier::Remote).unwrap().tier(),
            Tier::Remote
        );
    }

    #[test]
    fn acp_client_content_trust_is_always_untrusted() {
        assert_eq!(acp_client_content_trust(), Trust::Untrusted);
    }

    #[test]
    fn enforced_by_as_str_returns_the_marker_string() {
        assert_eq!(REMOTE_AGENT_CLAIM.as_str(), "RemoteAgentClaim");
    }
}
