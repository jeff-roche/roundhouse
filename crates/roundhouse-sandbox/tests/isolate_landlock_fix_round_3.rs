//! Regression test for Task 27's fix round 3 (Ruling W5-42), item 1: `read_exec` and
//! `dev_read_write` were missing `AccessFs::ReadDir`, so nothing that enumerates a
//! directory could run under the ruleset even though every individual file underneath
//! was already readable.
//!
//! **Attribution, restated from the fix-round-3 brief:** fix round 1's own brief
//! blamed this on the `/dev`/`/proc` denial that round fixed. That diagnosis came from
//! the security lens's first pass and was wrong — the real cause is the missing
//! `ReadDir`, isolated by the fix-round-3 review: `ls /usr/lib` (and CPython's
//! `FileFinder`, which calls `listdir()` on every `sys.path` entry to find its own
//! stdlib) got `Permission denied` even though `head -c 20 <a file under /usr/lib>`
//! succeeded. Fix round 1 met its own Definition of Done exactly (a `/dev/null`
//! consumer working); the finding as originally *stated* — "no real session can run
//! at Sandbox tier" — is what stayed open for any directory-enumerating workload.
//!
//! This test uses `ls /usr/lib` rather than `python3` as the reproduction: it isolates
//! the exact mechanism (`ReadDir` on a `SYSTEM_READ_EXEC_DIRS` entry) without depending
//! on a Python interpreter being installed in every environment this suite runs in.
use roundhouse_core::{OnDegrade, SessionSpec, Tier};
use roundhouse_sandbox::isolate::BwrapLandlockIsolate;
use roundhouse_sandbox::probe::{self, MechanismStatus};
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

async fn landlock_available_probe() -> Option<probe::MechanismProbeReport> {
    let report = probe::probe_cached(&std::env::temp_dir()).await;
    if matches!(report.landlock, MechanismStatus::Available) {
        Some(report)
    } else {
        None
    }
}

fn unique_tmp_dir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    dir
}

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
async fn landlock_wrapped_spawn_allows_directory_enumeration_while_still_denying_the_outside_file()
{
    if !bwrap_available() {
        eprintln!("skipping: bwrap not available on this host");
        return;
    }
    let Some(report) = landlock_available_probe().await else {
        eprintln!("skipping: Landlock not Available on this host");
        return;
    };

    let isolate = BwrapLandlockIsolate::test_with_probe_and_bwrap_path(report, "bwrap".into());
    let spec = SessionSpec::test_requesting(Tier::Worktree, OnDegrade::Refuse);
    let handle = isolate
        .prepare(&spec)
        .await
        .expect("prepare should succeed: landlock alone achieves at least Worktree tier");

    let workspace = unique_tmp_dir("roundhouse-landlock-fix3-ws");
    let outside = unique_tmp_dir("roundhouse-landlock-fix3-outside");
    let outside_file = outside.join("readable.txt");
    std::fs::write(&outside_file, "outside-marker").unwrap();

    let status_path = workspace.join("status.txt");
    // `ls /usr/lib` exercises exactly the missing `ReadDir` grant on a
    // `SYSTEM_READ_EXEC_DIRS` entry — before this fix, every file under `/usr/lib` was
    // individually readable (`ReadFile` was already granted) but enumerating the
    // directory itself was denied.
    let script = format!(
        "ls /usr/lib >{ws}/ls_out.txt 2>{ws}/ls_err.txt; echo LS_EXIT=$? >>{ws}/status.txt; \
         cat {outside} >{ws}/outside_out.txt 2>{ws}/outside_err.txt; echo OUTSIDE_EXIT=$? >>{ws}/status.txt",
        ws = workspace.display(),
        outside = outside_file.display(),
    );
    let cmd = CommandSpec {
        program: "sh".into(),
        argv: vec!["-c".into(), script],
        cwd: Some(workspace.to_string_lossy().into_owned()),
        env: vec![],
    };
    isolate
        .spawn(&handle, cmd)
        .await
        .expect("spawn should succeed under the widened ruleset");

    let status = poll_for_status(&status_path, 2, Duration::from_secs(5)).await;
    assert!(
        status.contains("LS_EXIT=0"),
        "enumerating /usr/lib must succeed now that ReadDir is granted alongside ReadFile \
         and Execute — status was: {status:?}"
    );
    assert!(
        status.contains("OUTSIDE_EXIT=1"),
        "granting ReadDir on the system directories must not weaken confinement — a file \
         outside the workspace must still be denied — status was: {status:?}"
    );

    let _ = std::fs::remove_dir_all(&workspace);
    let _ = std::fs::remove_dir_all(&outside);
}
