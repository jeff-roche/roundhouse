use roundhouse_acp::remote_claim::{
    acp_client_content_trust, validate_acp_client_session_tier, AcpClientTier, RemoteClaimError,
};
use roundhouse_core::{Tier, Trust};

#[test]
fn acp_client_session_below_sandbox_tier_is_rejected() {
    assert!(matches!(
        validate_acp_client_session_tier(Tier::None),
        Err(RemoteClaimError::TierTooLow(Tier::None))
    ));
    assert!(matches!(
        validate_acp_client_session_tier(Tier::Worktree),
        Err(RemoteClaimError::TierTooLow(Tier::Worktree))
    ));
}

#[test]
fn sandbox_tier_or_higher_is_accepted() {
    assert!(validate_acp_client_session_tier(Tier::Sandbox).is_ok());
    assert!(validate_acp_client_session_tier(Tier::Container).is_ok());
    assert!(validate_acp_client_session_tier(Tier::Remote).is_ok());
}

#[test]
fn acp_client_tier_try_from_rejects_below_sandbox() {
    assert!(matches!(
        AcpClientTier::try_from(Tier::None),
        Err(RemoteClaimError::TierTooLow(Tier::None))
    ));
    assert!(matches!(
        AcpClientTier::try_from(Tier::Worktree),
        Err(RemoteClaimError::TierTooLow(Tier::Worktree))
    ));
}

#[test]
fn acp_client_tier_try_from_accepts_sandbox_or_higher() {
    for tier in [Tier::Sandbox, Tier::Container, Tier::Remote] {
        let validated = AcpClientTier::try_from(tier).expect("tier should be accepted");
        assert_eq!(validated.tier(), tier);
    }
}

#[test]
fn acp_client_content_is_always_marked_untrusted() {
    assert_eq!(acp_client_content_trust(), Trust::Untrusted);
}
