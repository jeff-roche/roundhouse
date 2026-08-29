//! Phase 2, Task 4: SIGTERM-then-SIGKILL cancellation of running shell
//! processes, via `process-wrap`'s process-group support.

use std::path::Path;
use std::time::Duration;

use roundhouse_tools::{cancel_running_shell, spawn_test, ExitDisposition};

#[tokio::test]
async fn sigterm_then_sigkill_on_unresponsive_process() {
    // Traps and ignores SIGTERM on the shell process ITSELF, forcing
    // `cancel_running_shell` down the SIGKILL escalation path once the
    // grace period elapses. Deliberately uses only shell builtins (`:`, a
    // no-op) rather than forking an external command like `sleep`: per
    // POSIX shell semantics, a `trap` set via the shell builtin does NOT
    // carry over to a separately forked/exec'd child process (which resets
    // trapped signals to their default disposition) — only the shell's own
    // signal disposition is affected. A builtin-only busy loop keeps this
    // whole process group down to the single trapping `sh` process, so the
    // group-wide SIGTERM sent by `cancel_running_shell` is genuinely
    // ignored rather than killing some other, non-trapping process in the
    // group.
    let mut handle = spawn_test("trap '' TERM; while :; do :; done")
        .await
        .unwrap();

    // Give the shell a moment to actually execute the `trap` builtin before
    // signalling it — otherwise a SIGTERM delivered in the tiny window
    // between spawn and the shell reaching that statement would fall back
    // to the default (terminate) disposition, defeating the point of this
    // test.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let disposition = cancel_running_shell(&mut handle, Duration::from_millis(200))
        .await
        .unwrap();

    assert_eq!(disposition, ExitDisposition::Killed);
}

#[tokio::test]
async fn sigterm_is_sufficient_for_a_cooperative_process() {
    // `sleep` has no SIGTERM handler, so the default disposition (terminate)
    // applies and the process should exit well within the grace period.
    let mut handle = spawn_test("sleep 30").await.unwrap();

    let disposition = cancel_running_shell(&mut handle, Duration::from_millis(500))
        .await
        .unwrap();

    assert_eq!(disposition, ExitDisposition::Terminated);
}

#[tokio::test]
async fn cancel_kills_the_whole_process_group_not_just_the_direct_child() {
    // `sh` here forks a grandchild (`sleep`, backgrounded) that is NOT the
    // direct child process-wrap knows about. Only a process-GROUP-wide
    // signal (not a signal to just the direct `sh` pid) can reach it.
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("grandchild.pid");
    let script = format!("sleep 30 & echo $! > {} ; wait", pid_file.display());

    let mut handle = spawn_test(&script).await.unwrap();

    let grandchild_pid = wait_for_pid_file(&pid_file).await;
    assert!(
        pid_running(grandchild_pid),
        "grandchild should be running before cancellation"
    );

    let disposition = cancel_running_shell(&mut handle, Duration::from_millis(500))
        .await
        .unwrap();
    assert_eq!(disposition, ExitDisposition::Terminated);

    // Give the kernel a moment to actually tear the grandchild down.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !pid_running(grandchild_pid),
        "grandchild must be killed along with the rest of the process group, \
         not just the direct `sh` child"
    );
}

/// Polls `path` until it contains a non-empty pid (written by the shell
/// script's `echo $! > path`), or panics after a generous timeout.
async fn wait_for_pid_file(path: &Path) -> i32 {
    for _ in 0..100 {
        if let Ok(contents) = std::fs::read_to_string(path) {
            let trimmed = contents.trim();
            if !trimmed.is_empty() {
                return trimmed
                    .parse()
                    .unwrap_or_else(|e| panic!("pid file contents {trimmed:?} not an i32: {e}"));
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("grandchild never wrote its pid to {}", path.display());
}

/// Linux-specific liveness check via `/proc/<pid>/stat`. Treats a zombie
/// (state `Z`, already signalled to death but not yet reaped by its parent)
/// the same as "not running" — what matters for this test is that the
/// process has actually stopped executing, not that its pid slot has been
/// fully reclaimed.
fn pid_running(pid: i32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    // Format is "pid (comm) state ...". `comm` can itself contain spaces or
    // parens, so split on the LAST ')' to reliably reach the state field.
    let Some((_, after_comm)) = stat.rsplit_once(')') else {
        return false;
    };
    let state = after_comm.trim_start().chars().next();
    !matches!(state, None | Some('Z'))
}
