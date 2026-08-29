//! Cancellable shell execution (Phase 2, Task 4).
//!
//! Unlike [`super::run_shell`]'s "run to completion" mode, [`spawn_cancellable`]
//! spawns a shell command into its own process GROUP (via `process-wrap`'s
//! `ProcessGroup` wrapper), so [`cancel_running_shell`] can later signal the
//! whole group — not just the direct child — with SIGTERM, escalating to
//! SIGKILL if the group hasn't exited within a grace period. This matters
//! for a shell task that itself spawns children (e.g. `sleep 30 & wait`):
//! signalling only the direct child would leave the grandchild running.
//!
//! ## `process-wrap` API note (judgment call, see task brief)
//!
//! The plan this task was drafted against assumed
//! `process_wrap::tokio::{TokioCommandWrap, TokioChildWrapper, ProcessGroup}`
//! and a `.start_kill_with_signal(...)` method. **Neither exists** in the
//! real `process-wrap` 10.0.0 API — verified by adding the crate and reading
//! its vendored source (`~/.cargo/registry/src/.../process-wrap-10.0.0/src/`),
//! not by transcribing the plan. The real types are
//! `process_wrap::tokio::{CommandWrap, ChildWrapper, ProcessGroup, KillOnDrop}`:
//! - `CommandWrap::with_new(program, |command| { .. })` builds a wrapped
//!   `tokio::process::Command`; `.wrap(ProcessGroup::leader())` puts the
//!   spawned process in a new process group with itself as leader
//!   (`setpgid(0, 0)` under the hood); `.spawn()` returns
//!   `io::Result<Box<dyn ChildWrapper>>`.
//! - `ChildWrapper::signal(&self, sig: i32) -> io::Result<()>` (Unix-only)
//!   sends an arbitrary signal. When the child was spawned under
//!   `ProcessGroup::leader()`, this is routed through `killpg(2)` internally
//!   (see `process_wrap`'s `ProcessGroupChild::signal_imp`) — i.e. to every
//!   process in the group, not just the direct child.
//! - `ChildWrapper::start_kill(&mut self) -> io::Result<()>` sends SIGKILL;
//!   for a `ProcessGroup`-wrapped child this is *also* `killpg`-routed
//!   (`ProcessGroupChild::start_kill` calls `self.signal_imp(Signal::SIGKILL)`).
//!
//! There is no `start_kill_with_signal` combining "signal X, then SIGKILL
//! after a grace period" in one call — that two-step escalation is exactly
//! what [`cancel_running_shell`] below implements: `signal(SIGTERM)`, then
//! (only if the group hasn't exited within `grace`) `start_kill()`.
//!
//! `process-wrap`'s safe wrapper API requires no `unsafe` on this crate's
//! side (confirmed by reading its source — the only `unsafe` in the crate is
//! internal to its own `libc::waitpid` call in `process_group.rs`, never
//! exposed to callers), so `#![forbid(unsafe_code)]` here is unaffected.

use std::path::Path;
use std::time::Duration;

use process_wrap::tokio::{ChildWrapper, CommandWrap, KillOnDrop, ProcessGroup};

use crate::error::ToolError;

/// A cancellable, still-running shell process, spawned into its own process
/// group (see the module docs) so [`cancel_running_shell`] can reach every
/// process it spawned, not just the direct child.
pub struct ShellHandle {
    child: Box<dyn ChildWrapper>,
}

/// How a cancelled [`ShellHandle`] actually stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitDisposition {
    /// The process group exited on its own after SIGTERM, within `grace`.
    Terminated,
    /// The process group ignored (or was too slow to respond to) SIGTERM;
    /// SIGKILL was required to bring it down.
    Killed,
}

/// Failure modes for [`cancel_running_shell`]. Deliberately distinct from
/// [`ToolError`] — this is a narrower, cancellation-specific error, not a
/// general executor error.
#[derive(Debug, thiserror::Error)]
pub enum CancelError {
    #[error("failed to signal the process group: {0}")]
    Signal(#[source] std::io::Error),
    #[error("failed to wait for the process group to exit: {0}")]
    Wait(#[source] std::io::Error),
}

/// Spawns `program`/`argv` — direct exec, exactly like [`super::run_shell`],
/// never through a shell interpreter — into its own process group, and
/// returns a [`ShellHandle`] that [`cancel_running_shell`] can later
/// terminate.
///
/// This is the real production spawn path for cancellable shell tasks (as
/// opposed to [`spawn_test`] below, which is test-only scaffolding).
pub async fn spawn_cancellable(
    program: &str,
    argv: &[String],
    cwd: &Path,
) -> Result<ShellHandle, ToolError> {
    let mut wrap = CommandWrap::with_new(program, |command| {
        command.args(argv).current_dir(cwd);
    });
    wrap.wrap(KillOnDrop).wrap(ProcessGroup::leader());

    let child = wrap
        .spawn()
        .map_err(|e| ToolError::Spawn(format!("{program}: {e}")))?;

    Ok(ShellHandle { child })
}

/// Test-only convenience: spawns `shell_command` via `sh -c` so tests can
/// write ordinary shell one-liners (`"trap '' TERM; sleep 30"`, `"sleep 30 &
/// wait"`, ...) instead of constructing separate program/argv pairs by hand.
///
/// Going through `sh -c` here does not reintroduce §6.3's "no shell
/// interpretation of untrusted, model-emitted commands" concern:
/// `shell_command` is always a fixed string literal baked into test source,
/// never data derived from an untrusted caller. Production callers use
/// [`spawn_cancellable`] directly with an already-resolved `program`/`argv`.
pub async fn spawn_test(shell_command: &str) -> Result<ShellHandle, ToolError> {
    spawn_cancellable(
        "sh",
        &["-c".to_string(), shell_command.to_string()],
        Path::new("."),
    )
    .await
}

/// Sends SIGTERM to `handle`'s whole process group, waiting up to `grace`
/// for it to exit. If it hasn't exited by then, escalates to SIGKILL (also
/// group-wide, see the module docs) and waits for that to take effect.
pub async fn cancel_running_shell(
    handle: &mut ShellHandle,
    grace: Duration,
) -> Result<ExitDisposition, CancelError> {
    handle
        .child
        .signal(libc::SIGTERM)
        .map_err(CancelError::Signal)?;

    match tokio::time::timeout(grace, handle.child.wait()).await {
        Ok(Ok(_status)) => Ok(ExitDisposition::Terminated),
        Ok(Err(e)) => Err(CancelError::Wait(e)),
        Err(_elapsed) => {
            handle.child.start_kill().map_err(CancelError::Signal)?;
            handle.child.wait().await.map_err(CancelError::Wait)?;
            Ok(ExitDisposition::Killed)
        }
    }
}
