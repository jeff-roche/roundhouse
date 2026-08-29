//! Phase 2, Task 4: SIGTERM-then-SIGKILL cancellation of running shell
//! processes, via `process-wrap`'s process-group support.

use std::path::Path;
use std::time::Duration;

use roundhouse_tools::{cancel_running_shell, spawn_cancellable, ExitDisposition, ShellHandle};

/// Test-only convenience: spawns `shell_command` via `sh -c` so tests can
/// write ordinary shell one-liners instead of constructing separate
/// program/argv pairs by hand. Deliberately NOT part of the library's public
/// surface (security-audit fix, Task 4 fix round): a `pub` function that
/// runs an arbitrary `&str` through a real shell interpreter would be a real
/// weakening of `run_shell`/`spawn_cancellable`'s "no shell in the loop"
/// property, enforceable only by a doc comment, not by the type system.
/// Living here instead means it can only ever be reached from this test
/// binary, with a `shell_command` that is always a fixed string literal in
/// test source, never data derived from an untrusted caller.
async fn spawn_sh(shell_command: &str) -> Result<ShellHandle, roundhouse_tools::ToolError> {
    spawn_cancellable(
        "sh",
        &["-c".to_string(), shell_command.to_string()],
        Path::new("."),
    )
    .await
}

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
    let mut handle = spawn_sh("trap '' TERM; while :; do :; done").await.unwrap();

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
    let mut handle = spawn_sh("sleep 30").await.unwrap();

    let disposition = cancel_running_shell(&mut handle, Duration::from_millis(500))
        .await
        .unwrap();

    assert_eq!(disposition, ExitDisposition::Terminated);
}

#[tokio::test]
async fn cancel_kills_the_whole_process_group_not_just_the_direct_child() {
    // `sh` here forks a grandchild (`sleep`, backgrounded) that is NOT the
    // direct child process-wrap knows about. Only a process-GROUP-wide
    // signal (not a signal to just the direct `sh` pid) can reach it. This
    // grandchild has the DEFAULT SIGTERM disposition, so it dies from the
    // initial signal — this test proves group-wide SIGTERM delivery, but
    // never exercises the SIGKILL-escalation path. See
    // `cancel_kills_an_unresponsive_grandchild_via_sigkill_escalation` below
    // for the escalation-path equivalent (security-audit fix, Task 4 fix
    // round: this was previously the ONLY group-kill test, and it happened
    // to never touch the exact path that turned out to be broken).
    //
    // The reported disposition here is genuinely NOT deterministically
    // `Terminated`, even though the grandchild is fully cooperative: `sh`
    // itself has no trap of its own, so the same group-wide SIGTERM that
    // hits `sleep` also hits `sh` while it's blocked in the `wait` builtin —
    // and a process with the default (unhandled) disposition is terminated
    // by a fatal signal immediately, with no opportunity to first return
    // from that blocked syscall and synchronously reap its own child. So
    // `sleep` is routinely orphaned and reparented to init for the brief
    // window before init gets around to reaping it, during which the
    // `group_is_empty` probe correctly reports "not empty yet" — which is
    // precisely the kind of honest-but-slightly-slower confirmation this
    // security-audit fix exists to produce, in contrast to the old code
    // trusting `wait()` resolving as sufficient proof on its own. Observed
    // in practice to consistently resolve as `Killed` (needing the retry
    // loop to observe init's reap), which is correct, not a regression —
    // asserting either outcome here keeps the test honest about that rather
    // than pinning down kernel-scheduling behavior this crate doesn't
    // control.
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("grandchild.pid");
    let script = format!("sleep 30 & echo $! > {} ; wait", pid_file.display());

    let mut handle = spawn_sh(&script).await.unwrap();

    let grandchild_pid = wait_for_pid_file(&pid_file).await;
    assert!(
        pid_running(grandchild_pid),
        "grandchild should be running before cancellation"
    );

    let disposition = cancel_running_shell(&mut handle, Duration::from_millis(500))
        .await
        .unwrap();
    assert!(
        matches!(
            disposition,
            ExitDisposition::Terminated | ExitDisposition::Killed
        ),
        "cancellation must succeed one way or the other, got {disposition:?}"
    );

    // `cancel_running_shell` now only returns `Ok(_)` once it has itself
    // confirmed (via a liveness probe) that the whole group is empty — so,
    // unlike before the security-audit fix, no extra sleep-and-recheck
    // should be needed here for the assertion below to hold, regardless of
    // which disposition was reported above.
    assert!(
        !pid_running(grandchild_pid),
        "grandchild must be killed along with the rest of the process group, \
         not just the direct `sh` child"
    );
}

#[tokio::test]
async fn cancel_kills_an_unresponsive_grandchild_via_sigkill_escalation() {
    // Security-audit fix, Task 4 fix round: this is the escalation-path
    // equivalent of the test above, and is an adaptation of the security
    // audit's own empirical repro of the Critical finding. The grandchild
    // here (a second `sh`, backgrounded) traps and ignores SIGTERM, so
    // `cancel_running_shell`'s initial SIGTERM does NOT bring the group
    // down — it kills the direct child (the outer `sh`, which has no trap of
    // its own and is just blocked in `wait`) but leaves the grandchild
    // running, orphaned and reparented to init the instant the outer `sh`
    // exits. Before the fix, `ChildWrapper::wait()` resolving for the outer
    // `sh` (whose own `waitpid(-pgid, ..)` reap loop then immediately saw
    // `ECHILD`, since the grandchild had *already* been reparented away) was
    // wrongly treated as proof the whole group had exited, so this exact
    // scenario used to report `Ok(Terminated)` in well under a millisecond
    // while the grandchild was still alive. The fix makes `wait()`
    // resolving irrelevant to that judgment — only the explicit `killpg`
    // liveness probe decides — so this must now correctly escalate to
    // SIGKILL and report `Killed`, with the grandchild actually dead by the
    // time this function returns.
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("grandchild.pid");
    let script = format!(
        "sh -c 'trap \"\" TERM; echo $$ > {} ; while :; do :; done' & wait",
        pid_file.display()
    );

    let mut handle = spawn_sh(&script).await.unwrap();

    let grandchild_pid = wait_for_pid_file(&pid_file).await;
    assert!(
        pid_running(grandchild_pid),
        "grandchild should be running before cancellation"
    );

    let disposition = cancel_running_shell(&mut handle, Duration::from_millis(200))
        .await
        .unwrap();

    assert_eq!(
        disposition,
        ExitDisposition::Killed,
        "an unresponsive grandchild must force the SIGKILL escalation path, \
         not be mistaken for a clean SIGTERM exit"
    );
    assert!(
        !pid_running(grandchild_pid),
        "the orphaned, SIGTERM-ignoring grandchild must be confirmed dead \
         before cancel_running_shell reports success at all — this is \
         exactly the gap the security audit found"
    );
}

/// Polls `path` until it contains a non-empty pid (written by the shell
/// script's `echo $! > path` or `echo $$ > path`), or panics after a
/// generous timeout.
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
/// the same as "not running" — what matters for these tests is that the
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
