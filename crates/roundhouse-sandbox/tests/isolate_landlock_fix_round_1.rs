//! Regression tests for Task 27's fix round 1 (Ruling W5-40): three Importants the
//! security lens reproduced against the real Landlock wrapper, all latent today
//! because `Isolate::spawn` has no production caller yet.
//!
//! - Item 1: a workspace root of `/` used to make `round_landlock_exec.rs`'s ruleset
//!   restrict nothing at all, while `restrict_self()` still reported `FullyEnforced`
//!   and `spawn()` proceeded. `spawn_refuses_a_workspace_root_of_the_filesystem_root`
//!   proves `spawn()` now refuses this outright, before ever invoking real bwrap.
//! - Item 2: in the ordinary dev layout (daemon at `<repo>/target/debug/`, its sibling
//!   wrapper at `<repo>/target/debug/round-landlock-exec`, session workspace `<repo>`),
//!   the resolved wrapper binary sits inside the very directory its own ruleset makes
//!   fully read-write — a correctly confined child could overwrite it, and the next
//!   session would exec attacker code before any ruleset ever applies.
//!   `spawn_refuses_when_the_workspace_contains_the_wrapper_binary` reproduces the
//!   real filesystem layout (not a synthetic stand-in) and proves `spawn()` refuses.
//!   Neither of these two tests ever reaches real bwrap — `wrap_for_landlock_if_available`
//!   fails closed before `spawn_under_bwrap` is called, so there is no risk of actually
//!   overwriting anything in `target/debug/`.
//!
//!   **Fix round 3, item 4 (Ruling W5-42):** both of the tests above originally
//!   asserted only `result.is_err()`. That cannot detect a regression that deletes the
//!   `/`-specific guard alone: `wrapper_is_inside_workspace`'s check refuses `cwd = "/"`
//!   too, since every absolute wrapper path `starts_with("/")` — so
//!   `spawn_refuses_a_workspace_root_of_the_filesystem_root` would keep passing, for
//!   the wrong guard's reason, even with `validate_workspace_root`'s own `"/"` check
//!   deleted. Both tests now match on the specific error text each guard alone
//!   produces, so each fails if *its own* guard — and only its own — stops firing.
//! - Item 3: the ruleset used to deny `/dev` and `/proc` outright, so no real workload
//!   could run at Sandbox tier — reproduced pre-fix: `git --version` exited 128
//!   (`could not open '/dev/null'... Permission denied`), and reads under `/proc`
//!   were denied. `landlock_wrapped_spawn_allows_dev_null_and_proc_reads_while_still_denying_the_outside_file`
//!   demonstrates the fix (`/dev/null` and `/proc/version` now reachable) while
//!   re-asserting the original enforcement still holds (a file outside the workspace
//!   is still denied) — widening must not break confinement.
use roundhouse_core::{OnDegrade, SessionSpec, Tier};
use roundhouse_sandbox::isolate::BwrapLandlockIsolate;
use roundhouse_sandbox::probe::{self, MechanismStatus};
use roundhouse_sandbox::{CommandSpec, Isolate, IsolationError};
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

/// Mirrors `landlock_wrap.rs::wrapper_binary_path()`'s `test-util` grandparent
/// fallback: this test binary lives in `target/<profile>/deps/`, and Cargo places
/// `round-landlock-exec` directly in `target/<profile>/` — its grandparent. Computed
/// independently here, not by calling the crate's own `pub(crate)` function, so this
/// test exercises the real, observable filesystem layout rather than assuming the
/// function under test already agrees with itself.
fn resolved_wrapper_directory() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    let exe = std::fs::canonicalize(&exe).expect("canonicalize current_exe");
    let deps_dir = exe.parent().expect("test binary has a parent dir");
    deps_dir
        .parent()
        .expect("deps dir has a parent dir")
        .to_path_buf()
}

#[tokio::test]
async fn spawn_refuses_a_workspace_root_of_the_filesystem_root() {
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
        .expect("prepare should succeed");

    let cmd = CommandSpec {
        program: "true".into(),
        argv: vec![],
        cwd: Some("/".into()),
        env: vec![],
    };
    let result = isolate.spawn(&handle, cmd).await;
    // Fix round 3, item 4: match on the specific text `validate_workspace_root`'s own
    // "/" check produces, not just `is_err()` — a bare `is_err()` cannot distinguish
    // this guard from item 2's wrapper-containment guard, which also happens to fire
    // for `cwd = "/"` (every absolute wrapper path `starts_with("/")`), so it would
    // keep this test passing even if the "/" check itself were deleted.
    match result {
        Err(IsolationError::Unsupported(msg)) => {
            assert!(
                msg.contains("workspace root is \"/\""),
                "expected the \"/\"-specific guard (validate_workspace_root) to fire; got a \
                 different Unsupported message instead: {msg}"
            );
        }
        other => panic!(
            "spawn must refuse a workspace root of \"/\" with IsolationError::Unsupported \
             carrying the \"/\"-specific message, got: {other:?}"
        ),
    }
}

#[tokio::test]
async fn spawn_refuses_when_the_workspace_contains_the_wrapper_binary() {
    if !bwrap_available() {
        eprintln!("skipping: bwrap not available on this host");
        return;
    }
    let Some(report) = landlock_available_probe().await else {
        eprintln!("skipping: Landlock not Available on this host");
        return;
    };

    let workspace = resolved_wrapper_directory();
    let wrapper_path = workspace.join("round-landlock-exec");
    if !wrapper_path.is_file() {
        eprintln!(
            "skipping: {} not found — run `cargo build -p roundhouse-sandbox --bins` first \
             so this test can exercise the real ordinary-dev-layout scenario",
            wrapper_path.display()
        );
        return;
    }

    let isolate = BwrapLandlockIsolate::test_with_probe_and_bwrap_path(report, "bwrap".into());
    let spec = SessionSpec::test_requesting(Tier::Worktree, OnDegrade::Refuse);
    let handle = isolate
        .prepare(&spec)
        .await
        .expect("prepare should succeed");

    // This never reaches real bwrap: `wrap_for_landlock_if_available` must refuse
    // before `spawn_under_bwrap` is ever called, so nothing in `target/debug/` is
    // touched by this test.
    let cmd = CommandSpec {
        program: "true".into(),
        argv: vec![],
        cwd: Some(workspace.to_string_lossy().into_owned()),
        env: vec![],
    };
    let result = isolate.spawn(&handle, cmd).await;
    // Fix round 3, item 4: match on the specific text `wrapper_is_inside_workspace`'s
    // guard produces, so this test fails if *that* guard specifically stops firing —
    // this scenario's workspace root (`target/debug/`) is neither "/" nor a system
    // directory, so `validate_workspace_root` cannot be what's refusing here; a bare
    // `is_err()` would not distinguish that from this test's own intended guard.
    match result {
        Err(IsolationError::Unsupported(msg)) => {
            assert!(
                msg.contains("lies inside the workspace root"),
                "expected the wrapper-containment guard (wrapper_is_inside_workspace) to \
                 fire; got a different Unsupported message instead: {msg}"
            );
        }
        other => panic!(
            "spawn must refuse when the resolved wrapper binary ({}) lies inside the \
             workspace root ({}) with IsolationError::Unsupported carrying the \
             containment-specific message, got: {other:?}",
            wrapper_path.display(),
            workspace.display()
        ),
    }
}

#[tokio::test]
async fn landlock_wrapped_spawn_allows_dev_null_and_proc_reads_while_still_denying_the_outside_file(
) {
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

    let workspace = unique_tmp_dir("roundhouse-landlock-fix1-ws");
    let outside = unique_tmp_dir("roundhouse-landlock-fix1-outside");
    let outside_file = outside.join("readable.txt");
    std::fs::write(&outside_file, "outside-marker").unwrap();

    let status_path = workspace.join("status.txt");
    let script = format!(
        "echo devnull-marker >/dev/null 2>{ws}/devnull_err.txt; echo DEVNULL_EXIT=$? >>{ws}/status.txt; \
         cat /proc/version >{ws}/proc_out.txt 2>{ws}/proc_err.txt; echo PROC_EXIT=$? >>{ws}/status.txt; \
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

    let status = poll_for_status(&status_path, 3, Duration::from_secs(5)).await;
    assert!(
        status.contains("DEVNULL_EXIT=0"),
        "writing to /dev/null must succeed under the fix round 1 ruleset — status was: \
         {status:?}"
    );
    assert!(
        status.contains("PROC_EXIT=0"),
        "reading /proc/version must succeed under the fix round 1 ruleset — status was: \
         {status:?}"
    );
    assert!(
        status.contains("OUTSIDE_EXIT=1"),
        "widening /dev and /proc access must not weaken confinement — a file outside the \
         workspace must still be denied — status was: {status:?}"
    );

    let _ = std::fs::remove_dir_all(&workspace);
    let _ = std::fs::remove_dir_all(&outside);
}
