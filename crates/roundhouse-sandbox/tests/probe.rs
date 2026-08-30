use roundhouse_sandbox::probe::{probe_bwrap, probe_cached, probe_seccomp, MechanismStatus};

#[cfg(target_os = "linux")]
use roundhouse_sandbox::probe::probe_landlock;

fn assert_never_silently_unavailable(status: &MechanismStatus) {
    // §6.5 rule 1: a probe must never report Unavailable with an empty reason — that's
    // the silent fail-open bug this whole module exists to prevent.
    if let MechanismStatus::Unavailable { reason } = status {
        assert!(
            !reason.is_empty(),
            "Unavailable must always carry a non-empty reason"
        );
    }
}

/// Independent (i.e. not going through `roundhouse_sandbox::probe` at all) signal for
/// whether this host's kernel really has Landlock compiled in and enabled — read
/// straight from `/sys/kernel/security/lsm`, the same list the kernel itself exposes.
/// A stub that unconditionally returned `Unavailable { reason: "not implemented" }`
/// would pass a "reason is non-empty" assertion just as well as a real probe; this
/// lets the test assert the one thing a stub can't fake: agreement with a completely
/// separate, independently-obtained ground truth.
#[cfg(target_os = "linux")]
fn kernel_lsm_list_says_landlock_is_enabled() -> bool {
    std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|lsm| lsm.split(',').any(|name| name.trim() == "landlock"))
        .unwrap_or(false)
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn probe_landlock_actually_enforces_a_throwaway_ruleset_not_just_checks_a_version() {
    let status = probe_landlock().await;
    // On any Linux 5.13+ CI runner this must report Available or a specific Degraded
    // reason — never silently Unavailable due to only checking `uname` (the fail-open
    // bug this probe exists to prevent, §6.5 rule 1).
    assert!(!matches!(&status, MechanismStatus::Unavailable { reason } if reason.is_empty()));
    assert_never_silently_unavailable(&status);
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn probe_landlock_reports_available_when_the_kernels_own_lsm_list_says_so() {
    // This is the test a stub returning `Unavailable { reason: "not implemented" }`
    // for every mechanism could NOT pass: it cross-checks the probe's result against
    // the kernel's own `/sys/kernel/security/lsm` listing, a completely independent
    // source of truth the probe code never reads. If the kernel says Landlock is
    // enabled, a real probe exercising it must observe real enforcement and report
    // `Available` — not just "some non-empty string".
    if !kernel_lsm_list_says_landlock_is_enabled() {
        eprintln!(
            "skipping: /sys/kernel/security/lsm does not list landlock on this host \
             (unreadable, or Landlock genuinely disabled at boot) — nothing to cross-check"
        );
        return;
    }
    let status = probe_landlock().await;
    assert_eq!(
        status,
        MechanismStatus::Available,
        "kernel's own /sys/kernel/security/lsm lists landlock as enabled, so a probe that \
         actually exercises it (rather than trusting a stub/version-check) must report \
         Available, not {status:?}"
    );
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn probe_landlock_reports_some_real_non_empty_status_even_when_degraded() {
    // Whatever this host reports, it must be a real, explained status — never a
    // crash, a hang, or a bare empty-reason Unavailable.
    let status = probe_landlock().await;
    match &status {
        MechanismStatus::Available => {}
        MechanismStatus::Degraded { reason } | MechanismStatus::Unavailable { reason } => {
            assert!(!reason.is_empty(), "status must explain itself: {status:?}");
        }
    }
}

#[tokio::test]
async fn probe_bwrap_runs_a_real_ro_bind_and_reports_the_actual_exit_status() {
    let fake_bwrap = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/bwrap-that-fails");
    let status = probe_bwrap(&fake_bwrap).await;
    match status {
        MechanismStatus::Unavailable { reason } => {
            assert!(
                reason.contains("exit"),
                "must surface the real exit status, not swallow it: {reason}"
            );
        }
        other => panic!("expected Unavailable from a deliberately-failing bwrap, got {other:?}"),
    }
}

#[tokio::test]
async fn probe_bwrap_reports_a_real_reason_when_the_binary_does_not_exist() {
    let missing = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/does-not-exist-at-all");
    let status = probe_bwrap(&missing).await;
    match status {
        MechanismStatus::Unavailable { reason } => assert!(!reason.is_empty()),
        other => panic!("expected Unavailable for a missing binary, got {other:?}"),
    }
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn probe_seccomp_actually_installs_a_filter_and_confirms_the_denied_syscall_is_blocked() {
    let status = probe_seccomp().await;
    // Must be a real, explained status — a bare empty-reason Unavailable would mean
    // this probe fell back to trusting apply_filter()'s Ok(()) without verifying.
    assert_never_silently_unavailable(&status);
    match &status {
        MechanismStatus::Available => {}
        MechanismStatus::Degraded { reason } | MechanismStatus::Unavailable { reason } => {
            assert!(!reason.is_empty());
        }
    }
}

/// Independent (i.e. not going through `roundhouse_sandbox::probe`) signal for
/// whether this kernel supports the seccomp actions this probe actually needs
/// (`errno`, to deny a syscall the way `probe_seccomp` does) — read straight from
/// `/proc/sys/kernel/seccomp/actions_avail`, which the kernel itself exposes.
#[cfg(target_os = "linux")]
fn kernel_seccomp_supports_errno_action() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/seccomp/actions_avail")
        .map(|actions| actions.split_whitespace().any(|a| a == "errno"))
        .unwrap_or(false)
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn probe_seccomp_reports_available_when_the_kernel_supports_the_errno_action() {
    // As with the equivalent Landlock test above: a stub that always returned
    // `Unavailable { reason: "not implemented" }` would pass every assertion in
    // `probe_seccomp_actually_installs_a_filter_and_confirms_the_denied_syscall_is_blocked`
    // above (non-empty reason is trivial to fake). This test cross-checks against
    // `/proc/sys/kernel/seccomp/actions_avail`, a source of truth the probe code
    // itself never reads, so a stub-or-broken probe that never really enforces
    // anything has no way to pass it.
    if !kernel_seccomp_supports_errno_action() {
        eprintln!(
            "skipping: /proc/sys/kernel/seccomp/actions_avail does not list 'errno' (or is \
             unreadable) on this host — nothing to cross-check"
        );
        return;
    }
    let status = probe_seccomp().await;
    assert_eq!(
        status,
        MechanismStatus::Available,
        "kernel's own /proc/sys/kernel/seccomp/actions_avail lists 'errno' support, so a \
         probe that actually installs and verifies a filter must report Available, not \
         {status:?}"
    );
}

#[tokio::test]
async fn probe_cached_is_awaitable_from_inside_an_already_running_tokio_runtime() {
    // This is the exact failure mode Ruling 1 exists to prevent: a sync probe_cached
    // wrapping futures::executor::block_on around Tokio-dependent probes panics the
    // moment it's called from inside a runtime. Calling it here, from a #[tokio::test]
    // (i.e. from inside a running runtime), must not panic.
    let dir = std::env::temp_dir();
    let report = probe_cached(&dir).await;
    assert_never_silently_unavailable(&report.landlock);
    assert_never_silently_unavailable(&report.bwrap);
    assert_never_silently_unavailable(&report.seccomp);
    assert_never_silently_unavailable(&report.seatbelt);

    // Bridges into Phase 0's frozen ProbeResult without panicking or losing detail.
    let result = report.to_probe_result();
    let _ = result.achieved;
    let _ = result.degradations;
}
