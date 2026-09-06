//! Task 27 (lane W5, ruling W5-9): real Landlock enforcement on the real spawned
//! child.
//!
//! **Why not `cat /etc/shadow`, the phase file's own Step 1 test.** That passes
//! vacuously: DAC already denies `/etc/shadow` to a non-root user, so the assertion
//! proves nothing about Landlock specifically. Ruling W5-9 corrects it: use two
//! tempdirs — the workspace, and an outside directory holding a file the daemon user
//! genuinely *can* read (a plain, owner-readable file this test itself creates) —
//! and assert that reading the outside file fails only when the Landlock wrapper is
//! actually applied. The second test below constructs the identical scenario with
//! Landlock forced `Unavailable` in the probe report (so `spawn()` never wraps the
//! command) and asserts the same read *succeeds* there — proving bwrap's own
//! `--ro-bind / /` genuinely exposes the outside file (real ambient DAC access, not
//! a typo'd path or a permissions mistake in the test itself), so the denial in the
//! first test is Landlock's doing, not an artifact of the test setup. A read
//! *inside* the workspace must still succeed in both cases — a ruleset that denied
//! everything would pass a one-sided version of this test while breaking every real
//! session.
//!
//! Skips cleanly (with an explanatory `eprintln!`, matching this crate's other
//! real-exec tests) when `bwrap` is missing from `$PATH` or the real Landlock probe
//! reports anything other than `Available` — CI is `ubuntu-latest`, where both are
//! expected to be true, but this must never silently pass by skipping there.
use roundhouse_core::{OnDegrade, SessionSpec, Tier};
use roundhouse_sandbox::isolate::BwrapLandlockIsolate;
use roundhouse_sandbox::probe::{self, MechanismProbeReport, MechanismStatus};
use roundhouse_sandbox::{CommandSpec, Isolate};
use std::path::PathBuf;
use std::time::Duration;

fn bwrap_available() -> bool {
    std::process::Command::new("bwrap")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn unique_tmp_dir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    dir
}

/// A script that (1) tries to read a file outside the workspace and records `cat`'s
/// real exit code, then (2) does the same for a file inside the workspace — both
/// redirected into files *inside* the workspace rather than `/dev/null`. `/dev/null`
/// writes are themselves granted under this ruleset as of fix round 1, item 3
/// (`isolate_landlock_fix_round_1.rs` exercises that directly) — kept as plain
/// workspace files here anyway, to keep this test's own two assertions decoupled from
/// that separate grant.
fn probe_script(
    outside_file: &std::path::Path,
    inside_file: &std::path::Path,
    workspace: &std::path::Path,
) -> String {
    format!(
        "cat {outside} >{ws}/outside_out.txt 2>{ws}/outside_err.txt; echo OUTSIDE_EXIT=$? >>{ws}/status.txt; \
         cat {inside} >{ws}/inside_out.txt 2>{ws}/inside_err.txt; echo INSIDE_EXIT=$? >>{ws}/status.txt",
        outside = outside_file.display(),
        inside = inside_file.display(),
        ws = workspace.display(),
    )
}

/// Polls `status.txt` until it has at least `expected_lines` lines or `timeout`
/// elapses, matching this crate's existing polling convention for observing a
/// spawned child's real side effects (`Isolate::spawn`'s `Child` carries only a
/// pid, not an exit status or output channel).
async fn poll_for_status(
    status_path: &std::path::Path,
    expected_lines: usize,
    timeout: Duration,
) -> String {
    let deadline = std::time::Instant::now() + timeout;
    let mut content = String::new();
    while std::time::Instant::now() < deadline {
        if let Ok(c) = std::fs::read_to_string(status_path) {
            content = c;
            if content.lines().count() >= expected_lines {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    content
}

#[tokio::test]
async fn landlock_wrapped_spawn_denies_a_genuinely_readable_outside_file_but_allows_reads_inside_the_workspace(
) {
    if !bwrap_available() {
        eprintln!("skipping: bwrap not available on this host");
        return;
    }
    let report = probe::probe_cached(&std::env::temp_dir()).await;
    if !matches!(report.landlock, MechanismStatus::Available) {
        eprintln!(
            "skipping: Landlock not Available on this host ({:?}) — the enforcement this test \
             checks cannot be exercised without it",
            report.landlock
        );
        return;
    }

    let isolate = BwrapLandlockIsolate::test_with_probe_and_bwrap_path(report, "bwrap".into());
    let spec = SessionSpec::test_requesting(Tier::Worktree, OnDegrade::Refuse);
    let handle = isolate
        .prepare(&spec)
        .await
        .expect("prepare should succeed: landlock alone achieves at least Worktree tier");

    let workspace = unique_tmp_dir("roundhouse-landlock-ws");
    let outside = unique_tmp_dir("roundhouse-landlock-outside");
    let outside_file = outside.join("readable.txt");
    let inside_file = workspace.join("inside.txt");
    // Plain, owner-readable files — genuinely readable by whatever user runs this
    // test, exactly the "daemon user genuinely can read" case Ruling W5-9 asks for,
    // as opposed to something DAC would already deny on its own.
    std::fs::write(&outside_file, "outside-marker").unwrap();
    std::fs::write(&inside_file, "inside-marker").unwrap();

    let status_path = workspace.join("status.txt");
    let cmd = CommandSpec {
        program: "sh".into(),
        argv: vec![
            "-c".into(),
            probe_script(&outside_file, &inside_file, &workspace),
        ],
        cwd: Some(workspace.to_string_lossy().into_owned()),
    };
    isolate
        .spawn(&handle, cmd)
        .await
        .expect("spawn should succeed under a real Landlock ruleset");

    let status = poll_for_status(&status_path, 2, Duration::from_secs(5)).await;
    assert!(
        status.contains("OUTSIDE_EXIT=1"),
        "real Landlock enforcement must deny reading a file outside the workspace, even one \
         DAC genuinely allows — status was: {status:?}"
    );
    assert!(
        status.contains("INSIDE_EXIT=0"),
        "the workspace root must remain fully readable/writable under the same ruleset — a \
         ruleset that denies everything would wrongly pass a one-sided version of this test \
         while breaking every real session — status was: {status:?}"
    );

    let _ = std::fs::remove_dir_all(&workspace);
    let _ = std::fs::remove_dir_all(&outside);
}

#[tokio::test]
async fn without_landlock_probed_available_the_same_outside_read_succeeds_proving_the_denial_above_is_real_enforcement(
) {
    if !bwrap_available() {
        eprintln!("skipping: bwrap not available on this host");
        return;
    }

    // Landlock forced Unavailable: `spawn()` must not wrap the command, so the only
    // thing standing between the sandboxed child and the outside file is bwrap's own
    // `--ro-bind / /` (which exposes the whole host filesystem read-only) plus
    // ordinary DAC permissions — both of which allow this read. This is the RED
    // state the test above's denial is measured against: if this one didn't also
    // succeed, the denial above could just as easily be a typo'd path or a DAC
    // permissions mistake in the test rather than real Landlock enforcement.
    let report = MechanismProbeReport {
        landlock: MechanismStatus::Unavailable {
            reason: "forced off for this test".into(),
        },
        bwrap: MechanismStatus::Available,
        seccomp: MechanismStatus::Unavailable {
            reason: "not exercised for this test".into(),
        },
        seatbelt: MechanismStatus::Unavailable {
            reason: "not macOS".into(),
        },
    };
    let isolate = BwrapLandlockIsolate::test_with_probe_and_bwrap_path(report, "bwrap".into());
    let spec = SessionSpec::test_requesting(Tier::Worktree, OnDegrade::Refuse);
    let handle = isolate
        .prepare(&spec)
        .await
        .expect("prepare should succeed");

    let workspace = unique_tmp_dir("roundhouse-landlock-ws-red");
    let outside = unique_tmp_dir("roundhouse-landlock-outside-red");
    let outside_file = outside.join("readable.txt");
    let inside_file = workspace.join("inside.txt");
    std::fs::write(&outside_file, "outside-marker").unwrap();
    std::fs::write(&inside_file, "inside-marker").unwrap();

    let status_path = workspace.join("status.txt");
    let cmd = CommandSpec {
        program: "sh".into(),
        argv: vec![
            "-c".into(),
            probe_script(&outside_file, &inside_file, &workspace),
        ],
        cwd: Some(workspace.to_string_lossy().into_owned()),
    };
    isolate
        .spawn(&handle, cmd)
        .await
        .expect("spawn should succeed under plain bwrap with no Landlock wrapper");

    let status = poll_for_status(&status_path, 2, Duration::from_secs(5)).await;
    assert!(
        status.contains("OUTSIDE_EXIT=0"),
        "without Landlock applied, bwrap's own --ro-bind / / plus real DAC permissions must \
         allow this read — status was: {status:?}"
    );
    assert!(status.contains("INSIDE_EXIT=0"), "status was: {status:?}");

    let _ = std::fs::remove_dir_all(&workspace);
    let _ = std::fs::remove_dir_all(&outside);
}
