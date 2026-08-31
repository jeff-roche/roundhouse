//! Regression tests for Task 24's fix round 2 (security re-review of fix round 1).
//!
//! Covers the "Important" finding that `attest()`'s `net_enforced` was gated on
//! `bwrap_pid.is_some()` — which only proves `Command::spawn()`/fork succeeded, not
//! that bwrap's own namespace setup (the actual `unshare(2)` calls) did, and never
//! re-checks whether the sandboxed child is still even running by the time a given
//! `attest()` call happens. The real fix wires up bwrap's own `--info-fd`
//! confirmation (`bwrap::spawn_under_bwrap`) as the authoritative signal instead, and
//! `attest()` additionally re-checks liveness on every call.
//!
//! The specific "Operation not permitted" (unprivileged user namespaces disabled)
//! reproduction the reviewer used isn't reproducible in this environment (this host
//! has unprivileged user namespaces enabled), so this file instead pins the two
//! behaviors the fix actually changes and that *are* reproducible here: a
//! successful, still-running spawn genuinely confirms via info-fd (not just via
//! `bwrap_pid` being set), and `net_enforced` correctly reverts to `false` once the
//! sandboxed child has already exited on its own — a case fix-round-1's gate could
//! never represent at all, since `bwrap_pid.is_some()` stays true forever once set.
use roundhouse_core::{OnDegrade, SessionSpec, Tier};
use roundhouse_sandbox::isolate::BwrapLandlockIsolate;
use roundhouse_sandbox::probe::{MechanismProbeReport, MechanismStatus};
use roundhouse_sandbox::{CommandSpec, Isolate};
use std::path::Path;
use std::time::Duration;

fn bwrap_available() -> bool {
    std::process::Command::new("bwrap")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Bwrap + Seatbelt "available" (landlock/seccomp not) — the same shape
/// `isolate_fix_round_1.rs`'s `seatbelt_only_probe()` uses to reach `Tier::Sandbox`
/// via `achieved_tier()`'s `bwrap && (landlock || seatbelt)` fold without depending
/// on this host's real Landlock support. This crate's own tests treat
/// `MechanismStatus` values as declared inputs to that fold, not literal
/// platform-honest claims — `seatbelt` reporting `Available` on a non-macOS test host
/// is the established precedent for exercising the `Sandbox`-tier code path.
fn bwrap_and_seatbelt_probe() -> MechanismProbeReport {
    MechanismProbeReport {
        landlock: MechanismStatus::Unavailable {
            reason: "not exercised for this test".into(),
        },
        bwrap: MechanismStatus::Available,
        seccomp: MechanismStatus::Unavailable {
            reason: "not exercised for this test".into(),
        },
        seatbelt: MechanismStatus::Available,
    }
}

fn unique_tmp_workspace() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("roundhouse-fr3-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("create tmp workspace");
    dir
}

#[tokio::test]
async fn attest_reports_net_enforced_true_for_a_genuinely_confirmed_still_running_sandbox() {
    if !bwrap_available() {
        eprintln!("skipping: bwrap not available on this host");
        return;
    }
    let isolate = BwrapLandlockIsolate::test_with_probe_and_bwrap_path(
        bwrap_and_seatbelt_probe(),
        "bwrap".into(),
    );
    let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
    let handle = isolate.prepare(&spec).await.unwrap();

    let workspace = unique_tmp_workspace();
    let cmd = CommandSpec {
        program: "sleep".into(),
        argv: vec!["5".into()],
        cwd: Some(workspace.to_string_lossy().into_owned()),
    };
    let child = isolate
        .spawn(&handle, cmd)
        .await
        .expect("spawn should succeed and info-fd should confirm real namespace setup");

    // Give it a moment to actually be running, then attest while it's still alive.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        Path::new(&format!("/proc/{}", child.pid)).exists(),
        "sanity check: the spawned process should be alive right now"
    );

    let attestation = isolate.attest(&handle);
    assert_eq!(attestation.tier, Tier::Sandbox);
    assert!(
        attestation.net_enforced,
        "a genuinely spawned, still-running, info-fd-confirmed bwrap sandbox must \
         attest net_enforced=true"
    );

    isolate.teardown(handle).await.expect("teardown");
    let _ = std::fs::remove_dir_all(&workspace);
}

#[tokio::test]
async fn attest_reports_net_enforced_false_once_the_sandboxed_child_has_already_exited() {
    if !bwrap_available() {
        eprintln!("skipping: bwrap not available on this host");
        return;
    }
    let isolate = BwrapLandlockIsolate::test_with_probe_and_bwrap_path(
        bwrap_and_seatbelt_probe(),
        "bwrap".into(),
    );
    let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
    let handle = isolate.prepare(&spec).await.unwrap();

    let workspace = unique_tmp_workspace();
    // A command that exits almost immediately, so by the time we attest() it has
    // already exited on its own — no teardown() call, since teardown() removes the
    // handle from tracking entirely and this test specifically wants to attest a
    // handle whose process exited without ever being torn down.
    let cmd = CommandSpec {
        program: "true".into(),
        argv: vec![],
        cwd: Some(workspace.to_string_lossy().into_owned()),
    };
    let child = isolate
        .spawn(&handle, cmd)
        .await
        .expect("spawn should succeed and info-fd should confirm real namespace setup");

    // Poll briefly for the OS to finish reaping rather than asserting instantaneously.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let proc_path = format!("/proc/{}", child.pid);
    let mut alive = Path::new(&proc_path).exists();
    while alive && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
        alive = Path::new(&proc_path).exists();
    }
    assert!(
        !alive,
        "sanity check: `true` should have exited well within 3 seconds"
    );

    let attestation = isolate.attest(&handle);
    assert_eq!(
        attestation.tier,
        Tier::Sandbox,
        "tier is a declared/probed property and doesn't change just because the \
         child exited"
    );
    assert!(
        !attestation.net_enforced,
        "fix-round-1's bwrap_pid.is_some() gate could never represent this case at \
         all (bwrap_pid stays Some forever once set) — a task row attested after the \
         sandboxed child has already exited must not claim live network enforcement \
         that no longer exists"
    );

    let _ = std::fs::remove_dir_all(&workspace);
}
