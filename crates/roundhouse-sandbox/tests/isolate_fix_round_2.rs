//! Regression tests for Task 17's fix round 2 (scoped re-review of fix round 1).
//!
//! Covers:
//! - item 1: the bwrap post-spawn exit-status guard (`bwrap.rs::spawn_under_bwrap`)
//!   must genuinely catch a bwrap process that dies during its own setup, not just be
//!   documented as catching it. Measured over multiple runs, through both the direct
//!   `spawn_under_bwrap` entry point and the real public `Isolate::spawn` API, with
//!   two different real failure modes (a bad bind path, and a nonexistent program to
//!   exec).
//! - item 2: a seccomp-filter compile failure must not be silently swallowed by
//!   `.ok()` — see isolate.rs's `seccomp_bpf_for_spawn`, now `Result`-returning and
//!   propagated through `spawn()`'s `?`. (No dedicated test here: this crate has no
//!   hook to force a real `compile_baseline_seccomp_bpf` failure — e.g. faking an
//!   unsupported target arch — without invasive test-only surface area Task 17 didn't
//!   otherwise need; the fix is a type-level change — `Option` to `Result` — verified
//!   by the crate compiling and the existing happy-path seccomp test in
//!   `isolate_fix_round_1.rs` still passing against the new `Result`-based signature.)
use roundhouse_core::{OnDegrade, SessionSpec, Tier};
use roundhouse_sandbox::isolate::BwrapLandlockIsolate;
use roundhouse_sandbox::probe::{MechanismProbeReport, MechanismStatus};
use roundhouse_sandbox::{CommandSpec, Isolate, IsolationError};
use std::path::PathBuf;

fn bwrap_available() -> bool {
    std::process::Command::new("bwrap")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn all_real_probe() -> MechanismProbeReport {
    MechanismProbeReport {
        landlock: MechanismStatus::Unavailable {
            reason: "not exercised for this test".into(),
        },
        bwrap: MechanismStatus::Available,
        seccomp: MechanismStatus::Unavailable {
            reason: "not exercised for this test".into(),
        },
        seatbelt: MechanismStatus::Unavailable {
            reason: "not macOS".into(),
        },
    }
}

/// Direct entry point into the guard being fixed: `spawn_under_bwrap` with a bind
/// path that does not exist on disk, which makes real bwrap fail near-instantly
/// with "Can't find source path" — the exact motivating failure from fix-round-1's
/// finding 2, and the case the re-reviewer measured the old `yield_now()`-based
/// guard catching in 0 of 50 runs.
///
/// Runs the reproduction `RUNS` times in one test and asserts every single run is
/// caught as `Err`, rather than asserting it once — the whole point of this
/// regression test is that "worked once" was exactly the false signal that let the
/// broken fix-round-1 guard ship undetected.
#[tokio::test]
async fn spawn_under_bwrap_catches_a_bad_bind_path_setup_failure_consistently() {
    if !bwrap_available() {
        eprintln!("skipping: bwrap not available on this host");
        return;
    }
    const RUNS: usize = 10;
    let mut caught = 0usize;
    for i in 0..RUNS {
        let bad_path = PathBuf::from(format!(
            "/nonexistent-roundhouse-fixround2-path-{i}-{}",
            uuid::Uuid::new_v4()
        ));
        let cmd = CommandSpec {
            program: "true".into(),
            argv: vec![],
            cwd: None,
        };
        let result = roundhouse_sandbox::bwrap::spawn_under_bwrap(
            std::path::Path::new("bwrap"),
            &bad_path,
            cmd,
            None,
        )
        .await;
        match result {
            Err(IsolationError::Unsupported(_)) => caught += 1,
            other => eprintln!("run {i}: guard did NOT catch the setup failure, got {other:?}"),
        }
    }
    eprintln!("fix-round-2 measurement: caught {caught}/{RUNS} bad-bind-path setup failures");
    assert_eq!(
        caught, RUNS,
        "the bwrap exit-status guard must catch every one of {RUNS} runs of a real, \
         reproducible bwrap setup failure, not just some of them (fix-round-1's \
         yield_now()-based guard caught 0/50 of this exact failure)"
    );
}

/// Second, independent failure mode, driven through the real public `Isolate::spawn`
/// API (not the internal `spawn_under_bwrap` function directly): bwrap itself sets
/// up fine, but fails to exec a nonexistent program — a different, slightly later
/// point of failure than a bad bind path, exercised through the same guard.
#[tokio::test]
async fn isolate_spawn_catches_a_nonexistent_program_exec_failure_consistently() {
    if !bwrap_available() {
        eprintln!("skipping: bwrap not available on this host");
        return;
    }
    const RUNS: usize = 10;
    let mut caught = 0usize;
    for i in 0..RUNS {
        let isolate =
            BwrapLandlockIsolate::test_with_probe_and_bwrap_path(all_real_probe(), "bwrap".into());
        let spec = SessionSpec::test_requesting(Tier::Worktree, OnDegrade::Refuse);
        let handle = isolate.prepare(&spec).await.unwrap();
        let workspace =
            std::env::temp_dir().join(format!("roundhouse-fr2-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&workspace).unwrap();
        let cmd = CommandSpec {
            program: format!("/nonexistent-roundhouse-fixround2-program-{i}"),
            argv: vec![],
            cwd: Some(workspace.to_string_lossy().into_owned()),
        };
        let result = isolate.spawn(&handle, cmd).await;
        match result {
            Err(IsolationError::Unsupported(_)) => caught += 1,
            other => eprintln!(
                "run {i}: Isolate::spawn did NOT return Err for a dead bwrap process, got {other:?}"
            ),
        }
        let _ = std::fs::remove_dir_all(&workspace);
    }
    eprintln!(
        "fix-round-2 measurement: caught {caught}/{RUNS} nonexistent-program exec failures \
         through the real Isolate::spawn API"
    );
    assert_eq!(
        caught, RUNS,
        "Isolate::spawn must not return Ok(Child) for a bwrap process that already died \
         trying to exec a nonexistent program, in any of {RUNS} runs (re-reviewer measured \
         the fix-round-1 guard returning Ok in 10/10 runs of exactly this case)"
    );
}
