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
//!   (`setpgid(0, 0)` under the hood, so the group id equals the leader's own
//!   pid); `.spawn()` returns `io::Result<Box<dyn ChildWrapper>>`.
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
//! (only if the group hasn't confirmed empty within `grace`) `start_kill()`.
//!
//! `process-wrap`'s safe wrapper API requires no `unsafe` on this crate's
//! side (confirmed by reading its source — the only `unsafe` in the crate is
//! internal to its own `libc::waitpid` call in `process_group.rs`, never
//! exposed to callers), so `#![forbid(unsafe_code)]` here is unaffected.
//! Likewise `nix::sys::signal::killpg` (used below for the liveness probe —
//! the same crate `process-wrap` itself depends on for its own signal
//! handling) is a safe wrapper over the underlying `unsafe` libc call.
//!
//! ## Security-audit fix: confirming a signal actually emptied the group
//!
//! An earlier version of this module treated `ChildWrapper::wait()`
//! resolving (or timing out) as proof of whether the process group was
//! dead. That's false in a reproducible case: `ProcessGroupChild::wait()`
//! awaits the direct child, then reaps any remaining group members via
//! `libc::waitpid(-pgid, ...)` — which only ever waits on the CALLER's own
//! children. If the direct child (e.g. `sh`) dies promptly on SIGTERM but
//! had already spawned a grandchild that ignores SIGTERM, that grandchild is
//! orphaned and reparented to init the instant `sh` exits — so
//! `waitpid(-pgid, ...)` immediately sees `ECHILD` ("no more of my children
//! left"), process-wrap treats that as a clean group exit, and `wait()`
//! returns successfully in microseconds while the grandchild is still very
//! much alive. The old code then reported `Ok(Terminated)` — a
//! success-shaped return masking a real failure to cancel, exactly the
//! "cancellation is advisory, not real" gap this task exists to close.
//!
//! The fix: `wait()`/its timeout are used only to decide *when* to check,
//! never *whether* the group is actually gone. The actual answer comes from
//! [`group_is_empty`], a signal-0 `killpg` (existence/permission probe, no
//! signal actually delivered) against the group id captured at spawn time.
//! `killpg`'s `ESRCH` means no process anywhere still has that process group
//! id — which stays true across reparenting, since reparenting changes a
//! process's parent, not its process group. `cancel_running_shell` only ever
//! reports `Ok(_)` once that probe has confirmed the group is empty; if
//! SIGKILL escalation still can't produce an empty group within a bounded
//! number of retries, it reports [`CancelError::GroupStillAlive`] instead of
//! a false success.

use std::path::Path;
use std::time::Duration;

use nix::errno::Errno;
use nix::sys::signal::killpg;
use nix::unistd::Pid;
use process_wrap::tokio::{ChildWrapper, CommandWrap, KillOnDrop, ProcessGroup};

use crate::error::ToolError;

/// How many times [`cancel_running_shell`] re-probes group liveness after
/// escalating to SIGKILL before giving up and reporting
/// [`CancelError::GroupStillAlive`]. SIGKILL cannot be blocked or ignored by
/// a process, so in practice the kernel finishes tearing every signalled
/// process down within microseconds to a few milliseconds; this bound (25
/// attempts at 20ms apart, 500ms total) is generous headroom for scheduling
/// jitter, not an expectation that it will ever be fully used.
const KILL_CONFIRM_ATTEMPTS: u32 = 25;
const KILL_CONFIRM_INTERVAL: Duration = Duration::from_millis(20);

/// A cancellable, still-running shell process, spawned into its own process
/// group (see the module docs) so [`cancel_running_shell`] can reach every
/// process it spawned, not just the direct child.
pub struct ShellHandle {
    child: Box<dyn ChildWrapper>,
    /// The process group id, captured once at spawn time. Equal to the
    /// leader's own pid under `ProcessGroup::leader()`'s `setpgid(0, 0)`,
    /// and stable for the handle's lifetime even after the leader exits —
    /// which is exactly why this, not anything derived from the leader
    /// `Child`'s own pid/state, is what [`group_is_empty`] probes.
    pgid: Pid,
}

impl ShellHandle {
    /// Takes the child's piped stdout/stderr handles so a caller can drain
    /// them concurrently with [`ShellHandle::wait`] (Fix round A, F6):
    /// `wait` alone never reads these pipes, so a chatty child could fill
    /// the OS pipe buffer and deadlock against a caller that isn't racing a
    /// timeout/cancellation signal at the same time it's waiting for exit.
    /// Must be called at most once, right after spawn, before `wait`/
    /// `cancel_running_shell` — the underlying `Option`s are taken, not
    /// cloned.
    pub fn take_stdio(
        &mut self,
    ) -> (
        Option<tokio::process::ChildStdout>,
        Option<tokio::process::ChildStderr>,
    ) {
        (self.child.stdout().take(), self.child.stderr().take())
    }

    /// Waits for the process to exit and returns its exit status —
    /// deliberately NOT `wait_with_output` (which takes `self` by value):
    /// a caller racing this against a timeout/cancellation signal in
    /// `tokio::select!` needs to retain `&mut self` afterward so it can
    /// still call [`cancel_running_shell`] on the same handle if a
    /// competing branch wins instead.
    pub async fn wait(&mut self) -> Result<std::process::ExitStatus, ToolError> {
        self.child.wait().await.map_err(ToolError::from)
    }
}

/// How a cancelled [`ShellHandle`] actually stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitDisposition {
    /// The process group exited on its own after SIGTERM, within `grace`.
    /// Confirmed via [`group_is_empty`], not merely inferred from `wait()`
    /// resolving (see the module docs' security-audit-fix note).
    Terminated,
    /// The process group ignored (or was too slow to respond to) SIGTERM;
    /// SIGKILL was required, and its effect was likewise confirmed via
    /// [`group_is_empty`] before being reported.
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
    #[error("failed to probe whether the process group is still alive: {0}")]
    Probe(#[source] std::io::Error),
    /// Cancellation could not be confirmed: SIGKILL was sent group-wide, but
    /// the liveness probe still found at least one live member after
    /// [`KILL_CONFIRM_ATTEMPTS`] retries. Reported as an error rather than a
    /// success — a cancellation whose effect can't be confirmed must not be
    /// reported as having worked.
    #[error(
        "process group did not become empty even after SIGKILL and repeated \
         liveness checks; cancellation could not be confirmed"
    )]
    GroupStillAlive,
}

/// Spawns `program`/`argv` — direct exec, exactly like [`super::run_shell`],
/// never through a shell interpreter — into its own process group, and
/// returns a [`ShellHandle`] that [`cancel_running_shell`] can later
/// terminate.
///
/// **Fix round A (Phase 7, Task 5, findings F1/F6):** `env` is an explicit
/// allowlist applied after `env_clear()` — the same shape
/// `roundhouse-mcp/src/transport/stdio.rs`'s `build_command` already uses
/// ("explicit allowlist only, never inherits the daemon's own env"). Before
/// this fix, this function spawned with the daemon's FULL environment
/// inherited (no `env_clear()` at all), which is exactly as leaky as
/// `run_shell` was for the same `ANTHROPIC_API_KEY` reproduction. stdout and
/// stderr are now piped (previously unset/inherited) so a caller can capture
/// them via [`ShellHandle::take_stdio`] — this handle has no other way to
/// report a completed process's output back to a caller.
pub async fn spawn_cancellable(
    program: &str,
    argv: &[String],
    cwd: &Path,
    env: &[(String, String)],
) -> Result<ShellHandle, ToolError> {
    let mut wrap = CommandWrap::with_new(program, |command| {
        command
            .args(argv)
            .current_dir(cwd)
            .env_clear()
            .envs(env.iter().cloned())
            // Fix round B, M1 (ruling W1-R69): without this, the child
            // inherits the DAEMON's own stdin (reproduced: a spawned child
            // saw the daemon's controlling tty). That's a real regression
            // from `run_shell`'s `.output()` (which gives a null stdin by
            // default) and from `roundhouse-mcp`'s `build_command` (which
            // this fix explicitly claims to copy and which pipes stdin
            // explicitly). It also feeds finding I1: under
            // `ProcessGroup::leader()`, a child that tries to read from a
            // terminal stdin raises SIGTTIN and STOPS rather than exiting —
            // a stopped child never reaches EOF on its own, so a dispatch
            // racing `wait()`/drains against a timeout would never see it
            // finish on that path either.
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
    });
    wrap.wrap(KillOnDrop).wrap(ProcessGroup::leader());

    let child = wrap
        .spawn()
        .map_err(|e| ToolError::Spawn(format!("{program}: {e}")))?;

    let pid = child
        .id()
        .ok_or_else(|| ToolError::Spawn(format!("{program}: spawned child has no pid")))?;
    // Safe under `ProcessGroup::leader()`: that wrapper's `setpgid(0, 0)`
    // makes the leader's own pid the process group id.
    let pgid = Pid::from_raw(pid as i32);

    Ok(ShellHandle { child, pgid })
}

/// Probes whether any process in `pgid`'s process group still exists, via a
/// signal-0 `killpg` — an existence/permission check that delivers no actual
/// signal. This is the only thing in this module that can truthfully answer
/// "is the group empty": `ChildWrapper::wait()`'s notion of "the group
/// exited" comes from `waitpid(-pgid, ...)`, which stops seeing a process
/// the instant it's reparented away from us (see the module docs), whereas a
/// process's process group id is unaffected by reparenting.
fn group_is_empty(pgid: Pid) -> Result<bool, CancelError> {
    match killpg(pgid, None) {
        Ok(()) => Ok(false),
        Err(Errno::ESRCH) => Ok(true),
        Err(e) => Err(CancelError::Probe(std::io::Error::from(e))),
    }
}

/// Sends SIGTERM to `handle`'s whole process group, waiting up to `grace`
/// for it to exit, then CONFIRMING via [`group_is_empty`] that the group is
/// actually gone before reporting success. If the group isn't confirmed
/// empty by then, escalates to SIGKILL (also group-wide) and re-confirms,
/// retrying up to [`KILL_CONFIRM_ATTEMPTS`] times before giving up with
/// [`CancelError::GroupStillAlive`].
pub async fn cancel_running_shell(
    handle: &mut ShellHandle,
    grace: Duration,
) -> Result<ExitDisposition, CancelError> {
    handle
        .child
        .signal(libc::SIGTERM)
        .map_err(CancelError::Signal)?;

    // `wait()` resolving (or timing out) only decides WHEN to check next —
    // never WHETHER the group is actually gone; see the module docs for why
    // that distinction is the whole point of this function's design.
    if let Ok(Err(e)) = tokio::time::timeout(grace, handle.child.wait()).await {
        return Err(CancelError::Wait(e));
    }

    if group_is_empty(handle.pgid)? {
        return Ok(ExitDisposition::Terminated);
    }

    // SIGTERM either timed out or left something behind (e.g. an orphaned
    // grandchild that ignored it) — escalate to SIGKILL, group-wide.
    handle.child.start_kill().map_err(CancelError::Signal)?;

    // Bounded best-effort wait for the direct child to be reaped. SIGKILL
    // can't be ignored, so this should resolve almost immediately; it must
    // not be allowed to hang forever if some layer above ever misbehaves.
    // The actual proof of the group's fate is still `group_is_empty` below,
    // not this call resolving.
    let _ = tokio::time::timeout(Duration::from_secs(5), handle.child.wait()).await;

    for attempt in 0..KILL_CONFIRM_ATTEMPTS {
        if group_is_empty(handle.pgid)? {
            return Ok(ExitDisposition::Killed);
        }
        if attempt + 1 < KILL_CONFIRM_ATTEMPTS {
            tokio::time::sleep(KILL_CONFIRM_INTERVAL).await;
        }
    }

    Err(CancelError::GroupStillAlive)
}
