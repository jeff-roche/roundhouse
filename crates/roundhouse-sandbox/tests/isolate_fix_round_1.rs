//! Regression tests for Task 17's fix round 1 (peer/docs/security three-way review).
//!
//! Findings covered here:
//! - finding 2: `spawn()` must derive its bind path from `cmd.cwd` (available at
//!   spawn time), refuse when it's absent, and must actually work end-to-end against
//!   real bwrap once fixed.
//! - finding 3: `teardown()` must actually kill the live spawned process, not just
//!   drop bookkeeping.
//! - finding 4: `MechanismProbeReport::to_probe_result()` (probe.rs) and
//!   `BwrapLandlockIsolate::achieved_tier()` (isolate.rs) must not be able to
//!   disagree about the achieved tier.
//! - finding 1 (seccomp half): when the seccomp probe is `Available`,
//!   `Isolate::spawn` must actually apply a real seccomp-BPF filter to the spawned
//!   child, not just probe it as theoretically available.
//!
//! Tests that exec real `bwrap`/`python3` are skipped (with an explanatory
//! `eprintln!`, not silently) on hosts missing either — this crate's other real-exec
//! tests (`tests/probe.rs`) follow the same pattern.
use roundhouse_core::{OnDegrade, SessionSpec, Tier};
use roundhouse_sandbox::isolate::BwrapLandlockIsolate;
use roundhouse_sandbox::probe::{MechanismProbeReport, MechanismStatus};
use roundhouse_sandbox::{CommandSpec, Isolate, IsolationError};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn bwrap_and_python_available() -> bool {
    let bwrap_ok = std::process::Command::new("bwrap")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let python_ok = std::process::Command::new("python3")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    bwrap_ok && python_ok
}

fn seatbelt_only_probe() -> MechanismProbeReport {
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

fn all_real_probe() -> MechanismProbeReport {
    MechanismProbeReport {
        landlock: MechanismStatus::Unavailable {
            reason: "not exercised for this test".into(),
        },
        bwrap: MechanismStatus::Available,
        seccomp: MechanismStatus::Available,
        seatbelt: MechanismStatus::Unavailable {
            reason: "not macOS".into(),
        },
    }
}

fn unique_tmp_workspace() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("roundhouse-fr1-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("create tmp workspace");
    dir
}

// ---------------------------------------------------------------------------------
// Finding 2: spawn() derives its bind path from cmd.cwd, refuses when absent, and
// actually works end-to-end against real bwrap once fixed.
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn spawn_without_a_cwd_is_refused_rather_than_using_a_meaningless_path() {
    let isolate =
        BwrapLandlockIsolate::test_with_probe_and_bwrap_path(all_real_probe(), "bwrap".into());
    let spec = SessionSpec::test_requesting(Tier::Worktree, OnDegrade::Refuse);
    let handle = isolate.prepare(&spec).await.unwrap();

    let cmd = CommandSpec {
        program: "true".into(),
        argv: vec![],
        cwd: None,
        env: vec![],
    };
    let result = isolate.spawn(&handle, cmd).await;
    assert!(
        matches!(result, Err(IsolationError::Unsupported(_))),
        "spawn() must refuse rather than bind a meaningless path when cmd.cwd is None, got {result:?}"
    );
}

#[tokio::test]
async fn spawn_uses_cmd_cwd_as_the_real_bind_path_and_actually_runs_the_command() {
    if !bwrap_and_python_available() {
        eprintln!("skipping: bwrap and/or python3 not available on this host");
        return;
    }
    let isolate =
        BwrapLandlockIsolate::test_with_probe_and_bwrap_path(all_real_probe(), "bwrap".into());
    let spec = SessionSpec::test_requesting(Tier::Worktree, OnDegrade::Refuse);
    let handle = isolate.prepare(&spec).await.unwrap();

    let workspace = unique_tmp_workspace();
    let out_path = workspace.join("out.txt");
    let cmd = CommandSpec {
        program: "sh".into(),
        argv: vec!["-c".into(), "echo real-bind-worked > out.txt".into()],
        cwd: Some(workspace.to_string_lossy().into_owned()),
        env: vec![],
    };

    isolate
        .spawn(&handle, cmd)
        .await
        .expect("spawn should succeed once workspace_root is a real, bindable directory");

    // The spawned command runs concurrently; poll briefly for its output rather than
    // assuming it's instantaneous.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut seen = String::new();
    while std::time::Instant::now() < deadline {
        if let Ok(contents) = std::fs::read_to_string(&out_path) {
            seen = contents;
            if !seen.is_empty() {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        seen.trim(),
        "real-bind-worked",
        "fix-round-1 finding 2: spawn() must actually bind cmd.cwd and run the real \
         command under bwrap, not fail silently on a bogus workspace-derived path"
    );
    let _ = std::fs::remove_dir_all(&workspace);
}

// ---------------------------------------------------------------------------------
// Finding 3: teardown() actually kills the live spawned process.
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn teardown_kills_the_live_spawned_process() {
    if !bwrap_and_python_available() {
        eprintln!("skipping: bwrap not available on this host");
        return;
    }
    let isolate =
        BwrapLandlockIsolate::test_with_probe_and_bwrap_path(all_real_probe(), "bwrap".into());
    let spec = SessionSpec::test_requesting(Tier::Worktree, OnDegrade::Refuse);
    let handle = isolate.prepare(&spec).await.unwrap();

    let workspace = unique_tmp_workspace();
    let cmd = CommandSpec {
        program: "sleep".into(),
        argv: vec!["30".into()],
        cwd: Some(workspace.to_string_lossy().into_owned()),
        env: vec![],
    };
    let child = isolate
        .spawn(&handle, cmd)
        .await
        .expect("spawn should succeed");
    let pid = child.pid;
    let proc_path = format!("/proc/{pid}");

    // Give the process a moment to actually start before asserting it's alive.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        Path::new(&proc_path).exists(),
        "sanity check: the spawned bwrap process should be alive right after spawn"
    );

    isolate
        .teardown(handle)
        .await
        .expect("teardown should succeed");

    // Poll briefly for the OS to finish reaping rather than asserting instantaneously.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut alive = Path::new(&proc_path).exists();
    while alive && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
        alive = Path::new(&proc_path).exists();
    }
    assert!(
        !alive,
        "fix-round-1 finding 3: teardown() must actually kill the live process, not just \
         drop bookkeeping — tokio::process::Child has kill_on_drop=false by default"
    );
    let _ = std::fs::remove_dir_all(&workspace);
}

// ---------------------------------------------------------------------------------
// Finding 4: to_probe_result() and achieved_tier() cannot disagree.
// ---------------------------------------------------------------------------------

#[test]
fn to_probe_result_folds_seatbelt_in_the_same_way_achieved_tier_does() {
    // Before the fix, `to_probe_result()` considered only (landlock, bwrap) and
    // completely ignored Seatbelt, so a Seatbelt-only host folded to `Tier::None`
    // here while `achieved_tier()` (isolate.rs) correctly granted `Tier::Sandbox` —
    // a real internal self-contradiction between `Isolate::probe()` and
    // `Isolate::prepare()`.
    let report = seatbelt_only_probe();
    assert_eq!(
        report.to_probe_result().achieved,
        Tier::Sandbox,
        "to_probe_result() must fold bwrap + Seatbelt into Sandbox tier the same way \
         achieved_tier()'s bwrap && (landlock || seatbelt) logic does"
    );
}

#[tokio::test]
async fn probe_and_prepare_agree_on_a_seatbelt_only_host() {
    // `achieved_tier()` now delegates to `to_probe_result()`, so this is now
    // structurally guaranteed rather than something that could regress separately —
    // this test pins that guarantee at the `Isolate` level (`prepare()`/`attest()`),
    // complementing the unit-level `to_probe_result` test above.
    let isolate =
        BwrapLandlockIsolate::test_with_probe_and_bwrap_path(seatbelt_only_probe(), "bwrap".into());
    let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
    let handle = isolate
        .prepare(&spec)
        .await
        .expect("Seatbelt + bwrap must achieve Sandbox tier without Landlock");
    assert_eq!(isolate.attest(&handle).tier, Tier::Sandbox);
}

// ---------------------------------------------------------------------------------
// Finding 1 (seccomp half): spawn() actually applies a real seccomp-BPF filter to
// the spawned child when the seccomp probe is Available, not merely a theoretical
// capability.
// ---------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[tokio::test]
async fn spawn_applies_a_real_seccomp_filter_that_denies_ptrace_when_probed_available() {
    if !bwrap_and_python_available() {
        eprintln!("skipping: bwrap and/or python3 not available on this host");
        return;
    }
    let isolate =
        BwrapLandlockIsolate::test_with_probe_and_bwrap_path(all_real_probe(), "bwrap".into());
    let spec = SessionSpec::test_requesting(Tier::Worktree, OnDegrade::Refuse);
    let handle = isolate.prepare(&spec).await.unwrap();

    let workspace = unique_tmp_workspace();
    let out_path = workspace.join("ptrace_result.txt");
    // ptrace(PTRACE_TRACEME=0, 0, 0, 0) always succeeds (ret=0) unless something is
    // actively denying it — a real seccomp filter denying it must make this return
    // -1 with errno=EPERM (1), not merely "probe reported seccomp as available".
    let script = "import ctypes\n\
                  libc = ctypes.CDLL('libc.so.6', use_errno=True)\n\
                  r = libc.ptrace(0, 0, 0, 0)\n\
                  e = ctypes.get_errno()\n\
                  open('ptrace_result.txt', 'w').write(f'{r},{e}')\n";
    let cmd = CommandSpec {
        program: "python3".into(),
        argv: vec!["-c".into(), script.into()],
        cwd: Some(workspace.to_string_lossy().into_owned()),
        env: vec![],
    };

    isolate
        .spawn(&handle, cmd)
        .await
        .expect("spawn should succeed with a real seccomp filter applied");

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut seen = String::new();
    while std::time::Instant::now() < deadline {
        if let Ok(contents) = std::fs::read_to_string(&out_path) {
            if !contents.is_empty() {
                seen = contents;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        seen.trim(),
        "-1,1",
        "fix-round-1 finding 1: a real seccomp-BPF filter denying ptrace(2) must be \
         genuinely applied to the spawned child (ptrace() returning -1/EPERM=1), not \
         merely probed as theoretically available — got {seen:?} instead"
    );
    let _ = std::fs::remove_dir_all(&workspace);
}
