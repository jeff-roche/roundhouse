use roundhouse_core::{OnDegrade, SessionSpec, Tier};
use roundhouse_sandbox::isolate::BwrapLandlockIsolate;
use roundhouse_sandbox::probe::{MechanismProbeReport, MechanismStatus};
use roundhouse_sandbox::{Isolate, IsolationError};

fn degraded_probe() -> MechanismProbeReport {
    MechanismProbeReport {
        landlock: MechanismStatus::Degraded {
            reason: "BestEffort: missing TruncateFs".into(),
        },
        bwrap: MechanismStatus::Available,
        seccomp: MechanismStatus::Available,
        seatbelt: MechanismStatus::Unavailable {
            reason: "not macOS".into(),
        },
    }
}

fn seatbelt_only_probe() -> MechanismProbeReport {
    // Simulates macOS: Landlock is Linux-only and never reports Available there.
    MechanismProbeReport {
        landlock: MechanismStatus::Unavailable {
            reason: "Landlock is Linux-only".into(),
        },
        bwrap: MechanismStatus::Available,
        seccomp: MechanismStatus::Unavailable {
            reason: "seccomp is Linux-only".into(),
        },
        seatbelt: MechanismStatus::Available,
    }
}

#[tokio::test]
async fn prepare_errors_rather_than_warns_when_achieved_is_below_requested() {
    let isolate = BwrapLandlockIsolate::test_with_probe(degraded_probe());
    let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);

    let result = isolate.prepare(&spec).await;
    assert!(
        matches!(result, Err(IsolationError::DegradedBelowRequested)),
        "§6.5 rule 2: prepare() must error, not warn-and-continue, on a shortfall (frozen IsolationError variant)"
    );
    assert_eq!(
        isolate.last_shortfall(),
        Some((Tier::Worktree, Tier::Sandbox)),
        "the rich detail the frozen error variant has no field for must still be visible to the caller"
    );
}

#[tokio::test]
async fn allow_down_to_explicit_opt_in_succeeds_at_the_lower_tier_and_records_degradation() {
    let isolate = BwrapLandlockIsolate::test_with_probe(degraded_probe());
    let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::AllowDownTo(Tier::Worktree));

    let handle = isolate
        .prepare(&spec)
        .await
        .expect("explicit downgrade must be allowed");
    let attestation = isolate.attest(&handle);
    assert_eq!(attestation.tier, Tier::Worktree);
}

#[tokio::test]
async fn attestation_digest_is_available_for_every_prepared_handle() {
    let isolate = BwrapLandlockIsolate::test_with_probe(degraded_probe());
    let spec = SessionSpec::test_requesting(Tier::Worktree, OnDegrade::Refuse);
    let handle = isolate.prepare(&spec).await.unwrap();
    let attestation = isolate.attest(&handle);
    assert_eq!(attestation.tier, Tier::Worktree);
    assert!(
        !attestation.digest.is_empty(),
        "attest() must be written on every task row (§6.5 rule 4)"
    );
}

#[tokio::test]
async fn seatbelt_alone_achieves_sandbox_tier_on_a_landlock_less_host() {
    // Regression for audit finding 11: achieved_tier() previously consulted only
    // Landlock/bwrap, so macOS's Sandbox tier (Seatbelt + bwrap) was unreachable even
    // when Seatbelt actually probed Available.
    let isolate = BwrapLandlockIsolate::test_with_probe(seatbelt_only_probe());
    let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
    let handle = isolate
        .prepare(&spec)
        .await
        .expect("Seatbelt + bwrap must achieve Sandbox tier without Landlock");
    assert_eq!(isolate.attest(&handle).tier, Tier::Sandbox);
}
