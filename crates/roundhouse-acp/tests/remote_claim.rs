use roundhouse_acp::remote_claim::{validate_acp_client_session_tier, RemoteClaimError};
use roundhouse_core::Tier;

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
