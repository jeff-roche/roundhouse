//! Real syscall probes for each isolation mechanism.
//!
//! §6.5 rule 1: fail-open is made structurally impossible by actually exercising each
//! mechanism, not trusting a version check (`uname`) or an API call's return value at
//! face value. Every probe here either runs the real external binary and inspects its
//! real exit status (`bwrap`, Seatbelt), or actually installs a throwaway
//! enforcement policy and then performs the exact operation that policy is supposed to
//! deny, checking that the kernel really denied it (Landlock, seccomp).
//!
//! This is the one module in the entire workspace permitted `unsafe_code` (the crate
//! root keeps `#![deny(unsafe_code)]`, not `forbid`, specifically so this module can
//! locally re-`allow` it — see `lib.rs`). Note that `landlock::RulesetCreated::restrict_self`
//! and `seccompiler::apply_filter` are themselves *safe* Rust functions; they don't need
//! `unsafe` to call. The `unsafe` surface actually needed here is `fork`/`pipe`/`waitpid`
//! (and one raw `libc::syscall` invocation used only to *observe* seccomp's enforcement
//! decision): both Landlock's `restrict_self()` and an installed seccomp filter are
//! **irreversible** for the calling thread/process for the rest of its life, so this
//! module never calls them on a thread the async runtime intends to keep using. Instead
//! it forks a short-lived child, does the probe (and, critically, the verification) in
//! that child, reports the outcome back over a pipe, and the child exits immediately —
//! any Tokio blocking-pool worker thread that runs the parent-side logic is left
//! completely unaffected and reusable.
//!
//! **Why fork() and not just a direct call — the deadlock hazard this design exists to
//! avoid, and why it isn't fully eliminated either.** `fork()` in an already-multithreaded
//! process (which every Tokio program is) duplicates only the calling thread; every other
//! thread simply ceases to exist in the child, *including any thread that happened to be
//! holding a lock at the exact instant of the fork* (a malloc arena lock is the classic
//! example, but it applies to any mutex/lock the C or Rust runtime takes internally). That
//! lock is inherited in the child in its locked state, with no thread left alive that will
//! ever unlock it — so the first time the child's own code tries to take that same lock
//! (e.g. the next heap allocation), it deadlocks forever. Doing the *absolute minimum*
//! amount of work in the child before exiting (see `forked_probe::run`'s child branch)
//! narrows the window in which this can bite, but does not close it: the probe bodies
//! below still allocate (building a `Ruleset`/`SeccompFilter`, `String` formatting, the
//! pipe write) between `fork()` and `_exit()`, so a forked child can, in principle, still
//! wedge on an inherited-locked allocator. The `libc::alarm()` call in `forked_probe::run`
//! is the actual backstop for that residual risk: it does not prevent the deadlock, but it
//! guarantees the child is killed by the kernel (`SIGALRM`) within a bounded time either
//! way, so the parent's `read_to_end` can never block forever even if the mitigation above
//! fails. Do not "simplify" this back to a direct `spawn_blocking` call without preserving
//! that guarantee — a direct call permanently and irreversibly restricts whatever Tokio
//! blocking-pool thread happens to run it, and that thread is reused by unrelated work for
//! the rest of the process's life.
#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;

use roundhouse_core::Tier;
use tokio::process::Command;

use crate::types::ProbeResult;

/// Real, observed status of one isolation mechanism on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MechanismStatus {
    /// The mechanism was actually exercised and enforcement was actually observed.
    Available,
    /// The mechanism exists but enforcement was only partial, or verification
    /// succeeded on a weaker guarantee than requested. `reason` is always non-empty.
    Degraded { reason: String },
    /// The mechanism could not be exercised, or exercising it did not actually
    /// enforce anything. `reason` is always non-empty — never a bare `Unavailable`
    /// with no explanation, which is exactly the silent fail-open bug this probe
    /// module exists to prevent.
    Unavailable { reason: String },
}

/// Per-mechanism probe detail — deliberately **not** named `ProbeResult`, which Phase 0
/// already froze as a summary `{ achieved: Tier, degradations: Vec<String> }`. This is
/// the richer diagnostic (what a `round doctor`-style command wants to show);
/// `to_probe_result()` is the one place that folds it down into the frozen summary shape.
#[derive(Debug, Clone)]
pub struct MechanismProbeReport {
    pub landlock: MechanismStatus,
    pub bwrap: MechanismStatus,
    pub seccomp: MechanismStatus,
    pub seatbelt: MechanismStatus,
}

impl MechanismProbeReport {
    /// The achieved tier is the strongest tier this host's mechanisms actually
    /// support: `Sandbox` needs bwrap *and* (Landlock *or* Seatbelt) truly
    /// `Available`; any `Degraded`/`Unavailable` mechanism is recorded as a
    /// degradation, never silently dropped (§6.5 rule 1's "Landlock BestEffort is
    /// where fail-open hides").
    ///
    /// Fix-round-1 finding 4: this used to consider only `(landlock, bwrap)`,
    /// completely ignoring Seatbelt, while `isolate::BwrapLandlockIsolate::
    /// achieved_tier()` correctly used a 3-way `bwrap && (landlock || seatbelt)` OR.
    /// The two disagreeing (a Seatbelt-only host had `probe()` report `Tier::None`
    /// while `prepare()` granted `Tier::Sandbox`) was a real internal
    /// self-contradiction — a caller checking `probe()` before deciding whether to
    /// even try `prepare()` got the wrong answer. This is now the single source of
    /// truth for the fold: `achieved_tier()` calls this function and reads
    /// `.achieved` rather than duplicating the logic, so the two structurally
    /// cannot disagree again.
    pub fn to_probe_result(&self) -> ProbeResult {
        let mut degradations = Vec::new();
        for (name, status) in [
            ("landlock", &self.landlock),
            ("bwrap", &self.bwrap),
            ("seccomp", &self.seccomp),
            ("seatbelt", &self.seatbelt),
        ] {
            match status {
                MechanismStatus::Degraded { reason } => {
                    degradations.push(format!("{name}: degraded ({reason})"))
                }
                MechanismStatus::Unavailable { reason } => {
                    degradations.push(format!("{name}: unavailable ({reason})"))
                }
                MechanismStatus::Available => {}
            }
        }
        let bwrap_ok = matches!(self.bwrap, MechanismStatus::Available);
        let landlock_ok = matches!(self.landlock, MechanismStatus::Available);
        let seatbelt_ok = matches!(self.seatbelt, MechanismStatus::Available);
        let achieved = if bwrap_ok && (landlock_ok || seatbelt_ok) {
            Tier::Sandbox
        } else if bwrap_ok || landlock_ok || seatbelt_ok {
            Tier::Worktree
        } else {
            Tier::None
        };
        ProbeResult {
            achieved,
            degradations,
        }
    }
}

// ---------------------------------------------------------------------------------
// Forked-child probe harness (Linux only: this is what confines `unsafe_code` here).
// ---------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod forked_probe {
    use super::MechanismStatus;
    use std::io::{Read, Write};
    use std::os::unix::io::FromRawFd;

    /// Seconds a forked probe child is allowed to run before the kernel kills it with
    /// `SIGALRM`. This is the backstop for the residual fork-in-a-multithreaded-process
    /// deadlock risk documented on this module's doc comment: if the child ever does
    /// wedge (e.g. on an allocator lock inherited in a locked state), this guarantees
    /// the parent's blocking `read_to_end` below is unblocked by the pipe closing when
    /// the kernel reaps the child, rather than hanging forever. A few seconds is far
    /// more than any of these probes' real work needs.
    const CHILD_TIMEOUT_SECS: u32 = 5;

    /// Runs `body` inside a forked child process and returns the `MechanismStatus` it
    /// reports, communicated back over a pipe as a one-byte tag (0 = Available,
    /// 1 = Degraded, 2 = Unavailable) followed by the UTF-8 `reason` bytes.
    ///
    /// This exists so that Landlock's `restrict_self()` and an installed seccomp
    /// filter — both irreversible for the calling thread/process — are only ever
    /// applied to a throwaway child that exits immediately afterward, never to a
    /// thread the Tokio runtime intends to reuse. See this module's top doc comment
    /// for the full deadlock-hazard rationale and why `CHILD_TIMEOUT_SECS` exists.
    /// Opens a close-on-exec pipe, returning `(read_fd, write_fd)`.
    ///
    /// `O_CLOEXEC` is set so that any `exec`-based subprocess spawned elsewhere in
    /// this process (e.g. a concurrent `probe_bwrap`, or an unrelated agent shell
    /// tool) during the window these fds are open never inherits either end — an
    /// inherited write end would keep this pipe open (and `run`'s `read_to_end`
    /// blocked) until that unrelated process *also* exits, not just our own forked
    /// child. Split out from `run` so its exact fd-creation behavior (in
    /// particular, that `FD_CLOEXEC` really ends up set) is directly unit-testable
    /// without needing to race a real subprocess spawn against the fd-open window.
    pub(super) fn open_cloexec_pipe() -> Result<(i32, i32), String> {
        let mut fds = [-1i32; 2];
        // SAFETY: `fds` is a valid `&mut [c_int; 2]` (correct size/alignment for two
        // ints), exactly what POSIX `pipe2(2)` requires as its out-parameter. The
        // return value is checked before either fd is used.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(format!(
                "pipe2() failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok((fds[0], fds[1]))
    }

    pub(super) fn run(mechanism: &str, body: impl FnOnce() -> MechanismStatus) -> MechanismStatus {
        let (read_fd, write_fd) = match open_cloexec_pipe() {
            Ok(fds) => fds,
            Err(reason) => {
                return MechanismStatus::Unavailable {
                    reason: format!("{mechanism} probe: {reason}"),
                }
            }
        };

        // SAFETY: `fork()` duplicates the calling process. The child branch below
        // touches only process-local state (its own copy of `body`, the pipe fds,
        // and libc calls), never reaches back into the parent's Rust call stack
        // past this function, and terminates via `_exit` (on every path, including
        // a caught panic — see below) without unwinding into or running the
        // parent's destructors. This is the one place in the workspace that needs
        // a raw `fork()`: it's how Landlock/seccomp's irreversible enforcement is
        // confined to a throwaway process instead of poisoning a shared thread.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            // SAFETY: closing the two fds this function itself just opened via `pipe2()`.
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
            return MechanismStatus::Unavailable {
                reason: format!(
                    "{mechanism} probe: fork() failed: {}",
                    std::io::Error::last_os_error()
                ),
            };
        }

        if pid == 0 {
            // Child process: run the probe body, report the result over the pipe,
            // and exit without ever returning to the caller's stack frame. Nothing
            // below may return normally past this `if` block — every path must
            // reach `libc::_exit` directly.
            // SAFETY: `read_fd` is unused in the child; closing our copy of it does
            // not affect the parent's copy.
            unsafe { libc::close(read_fd) };
            // SAFETY: `alarm()` is async-signal-safe and takes no pointers; this
            // arms a `SIGALRM` that fires if this child is still alive after
            // `CHILD_TIMEOUT_SECS`, killing it with the default disposition (since
            // this process never installs a `SIGALRM` handler) so a wedged child
            // (e.g. deadlocked on an allocator lock inherited from `fork()`, per
            // this module's doc comment) can never hang the parent's read forever.
            unsafe { libc::alarm(CHILD_TIMEOUT_SECS) };

            // Replace the default panic hook with a no-op for the remainder of this
            // child's life: the default hook formats and prints a
            // location/backtrace message — which itself allocates and can take
            // locks — before unwinding ever reaches the `catch_unwind` below. A
            // no-op hook narrows the window in which a panic's own handling could
            // trigger the same inherited-lock deadlock this fork-based design
            // exists to avoid. This is ordinary safe `std` API, not part of the
            // unsafe surface below.
            std::panic::set_hook(Box::new(|_| {}));

            // Guard `body()` with `catch_unwind`: under `panic = "unwind"` (this
            // workspace's default profile), an uncaught panic here would unwind
            // *past* the `_exit` call below. Because this runs inside
            // `tokio::task::spawn_blocking`, that unwind is caught by Tokio's own
            // blocking-pool worker machinery in this copy-on-write child, which
            // then returns to its idle loop instead of exiting — leaving a live
            // orphaned process that never closes its copy of `write_fd`, which in
            // turn hangs the parent's `read_to_end` forever. Catching the panic
            // here and always falling through to `_exit` closes that hole
            // regardless of what `body` does.
            let status = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body))
                .unwrap_or_else(|payload| {
                    let msg = payload
                        .downcast_ref::<&str>()
                        .map(|s| s.to_string())
                        .or_else(|| payload.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "non-string panic payload".to_string());
                    MechanismStatus::Unavailable {
                        reason: format!("{mechanism} probe body panicked: {msg}"),
                    }
                });

            let (tag, reason): (u8, &str) = match &status {
                MechanismStatus::Available => (0, ""),
                MechanismStatus::Degraded { reason } => (1, reason.as_str()),
                MechanismStatus::Unavailable { reason } => (2, reason.as_str()),
            };
            let mut payload = Vec::with_capacity(1 + reason.len());
            payload.push(tag);
            payload.extend_from_slice(reason.as_bytes());
            // SAFETY: `write_fd` is a valid, owned fd returned by `pipe2()` above;
            // `File::from_raw_fd` takes ownership of it, so it is closed exactly
            // once when `file` drops a few lines down.
            let mut file = unsafe { std::fs::File::from_raw_fd(write_fd) };
            let _ = file.write_all(&payload);
            drop(file);
            // SAFETY: terminates only this forked child, on every path (normal
            // completion or caught panic) above. Uses `_exit` (not
            // `std::process::exit`/a normal return) so no `Drop` impls or atexit
            // handlers that logically belong to the parent process run a second
            // time in this copy-on-write child.
            unsafe { libc::_exit(0) };
        }

        // Parent process.
        // SAFETY: `write_fd` is unused in the parent; closing our copy of it does
        // not affect the child's copy (needed so `read_to_end` below observes EOF
        // once the child closes its own copy on exit).
        unsafe { libc::close(write_fd) };
        let mut buf = Vec::new();
        {
            // SAFETY: `read_fd` is a valid, owned fd returned by `pipe2()` above;
            // `File::from_raw_fd` takes ownership, closed when `file` drops at the
            // end of this block.
            let mut file = unsafe { std::fs::File::from_raw_fd(read_fd) };
            let _ = file.read_to_end(&mut buf);
        }
        let mut wait_status: i32 = 0;
        let waited = loop {
            // SAFETY: `pid` is the child this function just forked (no other code
            // can have reaped it), and `&mut wait_status` is a valid out-pointer
            // sized for a C `int`, exactly what `waitpid(2)` requires. Retried on
            // `EINTR` specifically (an interrupting signal delivered to this
            // process, unrelated to the child's own exit) so a spurious signal
            // doesn't turn an already-successful probe into a false `Unavailable`.
            let rc = unsafe { libc::waitpid(pid, &mut wait_status, 0) };
            if rc >= 0 {
                break rc;
            }
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return MechanismStatus::Unavailable {
                reason: format!("{mechanism} probe: waitpid() failed: {err}"),
            };
        };
        debug_assert_eq!(waited, pid);
        if buf.is_empty() {
            // The child died before writing anything (e.g. crashed, or was killed
            // outright — including by our own `CHILD_TIMEOUT_SECS` alarm, or by the
            // very mechanism being probed — instead of returning an error to it).
            // Report that fact explicitly rather than silently treating it as
            // Unavailable-with-no-explanation.
            return MechanismStatus::Unavailable {
                reason: format!(
                    "{mechanism} probe: child produced no report (raw wait status {wait_status:#x})"
                ),
            };
        }
        let reason = String::from_utf8_lossy(&buf[1..]).into_owned();
        match buf[0] {
            0 => MechanismStatus::Available,
            1 => MechanismStatus::Degraded { reason },
            _ => MechanismStatus::Unavailable { reason },
        }
    }
}

// ---------------------------------------------------------------------------------
// Landlock
// ---------------------------------------------------------------------------------

/// Actually enforces a throwaway Landlock ruleset — denying *all* handled filesystem
/// access with no exceptions — in a forked child, then actually attempts a filesystem
/// operation the ruleset should now deny and confirms the kernel really rejected it
/// with `EACCES`. Never trusts `restrict_self()`'s returned status enum on its own:
/// that's exactly the "believed the API, didn't check" fail-open bug this exists to
/// prevent (§6.5 rule 1).
#[cfg(target_os = "linux")]
pub async fn probe_landlock() -> MechanismStatus {
    tokio::task::spawn_blocking(|| forked_probe::run("landlock", landlock_probe_body))
        .await
        .unwrap_or_else(|e| MechanismStatus::Unavailable {
            reason: format!("landlock probe task panicked: {e}"),
        })
}

#[cfg(target_os = "linux")]
fn landlock_probe_body() -> MechanismStatus {
    use landlock::{Access, AccessFs, Ruleset, RulesetAttr, RulesetStatus, ABI};

    // ABI::V1 (Linux 5.13+) is the widest-compatibility baseline this crate exposes;
    // a stricter/higher ABI is negotiated automatically in best-effort mode when the
    // running kernel supports it, but V1 is what any 5.13+ host is guaranteed to
    // support, matching what this probe is required to detect.
    let abi = ABI::V1;
    let access_all = AccessFs::from_all(abi);

    let ruleset = match Ruleset::default().handle_access(access_all) {
        Ok(r) => r,
        Err(e) => {
            return MechanismStatus::Unavailable {
                reason: format!("handle_access failed: {e}"),
            }
        }
    };
    let created = match ruleset.create() {
        Ok(c) => c,
        Err(e) => {
            return MechanismStatus::Unavailable {
                reason: format!("ruleset create() failed: {e}"),
            }
        }
    };
    // Deliberately no `add_rule()`: a ruleset with zero granted path-beneath rules
    // denies every handled access right for every path, so restricting to it is as
    // strict a throwaway probe as this crate can construct.
    let restriction = match created.restrict_self() {
        Ok(r) => r,
        Err(e) => {
            return MechanismStatus::Unavailable {
                reason: format!("restrict_self() failed: {e}"),
            }
        }
    };

    // Trust, but verify: attempt the exact kind of access the ruleset should now
    // deny (opening a directory requires the ReadDir right, which `access_all`
    // includes and no rule grants), and check the kernel's real errno.
    let probe_open = std::fs::File::open("/");
    let landlock_actually_blocked =
        matches!(&probe_open, Err(e) if e.raw_os_error() == Some(libc::EACCES));

    match restriction.ruleset {
        RulesetStatus::FullyEnforced if landlock_actually_blocked => MechanismStatus::Available,
        RulesetStatus::FullyEnforced => MechanismStatus::Degraded {
            reason: format!(
                "restrict_self() reported FullyEnforced but opening '/' did not fail with \
                 EACCES afterward (got {probe_open:?}) — enforcement status was not real"
            ),
        },
        RulesetStatus::PartiallyEnforced if landlock_actually_blocked => {
            MechanismStatus::Degraded {
                reason: "kernel only partially enforced the requested access rights (best-effort \
                      downgrade), though the probed access was still denied"
                    .into(),
            }
        }
        RulesetStatus::PartiallyEnforced => MechanismStatus::Unavailable {
            reason: format!(
                "kernel only partially enforced the requested access rights, and opening '/' \
                 was not denied (got {probe_open:?})"
            ),
        },
        RulesetStatus::NotEnforced => MechanismStatus::Unavailable {
            reason: "Landlock is unsupported by the running kernel, or disabled at boot \
                      (ruleset not enforced at all)"
                .into(),
        },
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn probe_landlock() -> MechanismStatus {
    MechanismStatus::Unavailable {
        reason: "Landlock is Linux-only".into(),
    }
}

// ---------------------------------------------------------------------------------
// bwrap (bubblewrap)
// ---------------------------------------------------------------------------------

/// Actually runs `bwrap --ro-bind / / -- /bin/true` and reports the real process exit
/// status — never assumes bwrap works just because the binary exists on `PATH`. No
/// unsafe/fork needed here: bwrap runs as an ordinary subprocess, so any effect it has
/// is confined to that child process by the kernel already, not by us.
pub async fn probe_bwrap(bwrap_path: &Path) -> MechanismStatus {
    let output = Command::new(bwrap_path)
        .args(["--ro-bind", "/", "/", "--", "/bin/true"])
        .output()
        .await;
    match output {
        Ok(o) if o.status.success() => MechanismStatus::Available,
        Ok(o) => MechanismStatus::Unavailable {
            reason: format!(
                "bwrap probe exited {} (stderr: {})",
                o.status,
                String::from_utf8_lossy(&o.stderr).trim()
            ),
        },
        Err(e) => MechanismStatus::Unavailable {
            reason: format!("failed to exec bwrap at {}: {e}", bwrap_path.display()),
        },
    }
}

// ---------------------------------------------------------------------------------
// seccomp
// ---------------------------------------------------------------------------------

/// Actually installs a real seccomp-bpf filter in a forked child that denies exactly
/// one syscall (`getppid`, chosen because it's trivial, side-effect-free, and not on
/// any hot path a probe needs), then actually invokes that syscall and confirms the
/// kernel really returned the filter's configured errno — never trusts the API call
/// that installed the filter to have taken effect on its say-so alone.
pub async fn probe_seccomp() -> MechanismStatus {
    #[cfg(target_os = "linux")]
    {
        tokio::task::spawn_blocking(|| forked_probe::run("seccomp", seccomp_probe_body))
            .await
            .unwrap_or_else(|e| MechanismStatus::Unavailable {
                reason: format!("seccomp probe task panicked: {e}"),
            })
    }
    #[cfg(not(target_os = "linux"))]
    {
        MechanismStatus::Unavailable {
            reason: "seccomp is Linux-only".into(),
        }
    }
}

#[cfg(target_os = "linux")]
fn seccomp_probe_body() -> MechanismStatus {
    use seccompiler::{apply_filter, BpfProgram, SeccompAction, SeccompFilter};
    use std::convert::TryInto;

    let arch = match std::env::consts::ARCH.try_into() {
        Ok(a) => a,
        Err(e) => {
            return MechanismStatus::Unavailable {
                reason: format!(
                    "unsupported seccomp target arch {:?}: {e}",
                    std::env::consts::ARCH
                ),
            }
        }
    };

    // Every syscall not named below stays Allow (the child needs to keep running:
    // heap allocation, the pipe write, `_exit`, etc.); `getppid` alone is denied and
    // made to return EPERM.
    //
    // Deliberately NOT an empty map: this plan's own brief document shows
    // `SeccompFilter::new(...)` called with an empty rules map and
    // `mismatch_action = SeccompAction::Allow`. Since `mismatch_action` is what
    // applies to every syscall *not* present in the map, an empty map there means
    // literally every syscall falls through to Allow — a filter that installs
    // successfully but denies nothing at all, silently defeating this entire probe
    // (it would report `Available` having verified nothing). The map below must
    // contain at least one real syscall paired with a real deny action for this
    // probe to mean anything; do not "simplify" this back toward the brief's shown
    // empty-map snippet.
    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    rules.insert(libc::SYS_getppid, Vec::new());

    let filter = match SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    ) {
        Ok(f) => f,
        Err(e) => {
            return MechanismStatus::Unavailable {
                reason: format!("SeccompFilter::new failed: {e}"),
            }
        }
    };
    let bpf: BpfProgram = match filter.try_into() {
        Ok(b) => b,
        Err(e) => {
            return MechanismStatus::Unavailable {
                reason: format!("compiling seccomp filter to BPF failed: {e}"),
            }
        }
    };
    if let Err(e) = apply_filter(&bpf) {
        return MechanismStatus::Unavailable {
            reason: format!("apply_filter failed: {e}"),
        };
    }

    // Trust, but verify: call the syscall the filter should now deny, and check the
    // kernel's real errno rather than trusting `apply_filter`'s `Ok(())`.
    // SAFETY: `SYS_getppid` takes no arguments and has no side effects beyond
    // returning a pid (or, here, being intercepted by our own just-installed
    // filter); this is a bare raw-syscall invocation used only to observe the
    // kernel's post-filter enforcement decision.
    let rc = unsafe { libc::syscall(libc::SYS_getppid) };
    let errno = std::io::Error::last_os_error();
    let seccomp_actually_blocked = rc == -1 && errno.raw_os_error() == Some(libc::EPERM);

    if seccomp_actually_blocked {
        MechanismStatus::Available
    } else {
        MechanismStatus::Degraded {
            reason: format!(
                "seccomp filter installed successfully but getppid was not blocked with EPERM \
                 afterward (rc={rc}, errno={errno})"
            ),
        }
    }
}

/// Compiles a real, working seccomp-BPF program for use on the actual `Isolate::spawn`
/// path (`isolate.rs`/`bwrap.rs`), not the throwaway probe verification above.
///
/// Fix-round-1 finding 1: before this, `Tier::Sandbox` was attested even though
/// nothing anywhere actually installed a Landlock ruleset or seccomp filter on the
/// real spawned child — `restrict_self()`/`apply_filter()` only ever ran inside this
/// module's throwaway probe bodies. This function closes that gap for seccomp: it
/// compiles a real filter, and `bwrap.rs::spawn_under_bwrap` passes the compiled
/// program to bwrap's native `--seccomp FD` flag so it is genuinely applied to the
/// process bwrap execs, not merely probed as theoretically available.
///
/// Deliberately denies `ptrace(2)`, not `getppid` (which `seccomp_probe_body` above
/// denies, for that function's own, different purpose — a trivial, side-effect-free
/// syscall convenient to test in a throwaway forked child via a raw verification
/// syscall). `ptrace` is a real, security-meaningful syscall to restrict here: it is
/// the classic sandbox-escape/process-injection primitive (attaching to or tracing
/// another process), and none of this crate's actual sandboxed tool workloads
/// (`read`/`write`/`edit`/`find`/`shell`) have any legitimate reason to call it. This
/// is deliberately NOT a production-grade syscall allowlist/denylist — establishing
/// that genuine seccomp-BPF enforcement infrastructure is real and wired end-to-end
/// (compiled filter → real fd → bwrap → the actual exec'd child, empirically verified
/// against real bwrap 0.12.0 in fix-round-1: `ptrace(PTRACE_TRACEME, ...)` returns
/// `-1`/`EPERM` inside the sandbox, `0` outside it) is this round's scope; a full
/// syscall policy is tracked separately.
#[cfg(target_os = "linux")]
pub(crate) fn compile_baseline_seccomp_bpf() -> Result<Vec<u8>, String> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};
    use std::convert::TryInto;

    let arch = std::env::consts::ARCH.try_into().map_err(|e| {
        format!(
            "unsupported seccomp target arch {:?}: {e}",
            std::env::consts::ARCH
        )
    })?;

    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    rules.insert(libc::SYS_ptrace, Vec::new());

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(|e| format!("SeccompFilter::new failed: {e}"))?;

    let bpf: BpfProgram = filter
        .try_into()
        .map_err(|e| format!("compiling seccomp filter to BPF failed: {e}"))?;

    // The kernel's `struct sock_filter` is `{ u16 code; u8 jt; u8 jf; u32 k }` — 8
    // bytes, naturally aligned, no padding — and `seccompiler::backend::bpf::sock_filter`
    // has the identical `#[repr(C)]` layout, but this serializes field-by-field
    // instead of an `unsafe` transmute/byte-cast: this crate forbids new `unsafe`
    // outside `probe.rs`'s existing forked-probe machinery, and this function's
    // output feeds the real spawn path in `bwrap.rs`, not just another forked probe.
    let mut bytes = Vec::with_capacity(bpf.len() * 8);
    for insn in &bpf {
        bytes.extend_from_slice(&insn.code.to_ne_bytes());
        bytes.push(insn.jt);
        bytes.push(insn.jf);
        bytes.extend_from_slice(&insn.k.to_ne_bytes());
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------------
// Seatbelt (macOS)
// ---------------------------------------------------------------------------------

/// Actually runs `sandbox-exec` with a deny-all profile and reports the real exit
/// status. No unsafe/fork needed: `sandbox-exec` enforces on its own subprocess, not
/// on us.
#[cfg(target_os = "macos")]
pub async fn probe_seatbelt() -> MechanismStatus {
    let output = Command::new("sandbox-exec")
        .args(["-p", "(version 1)(deny default)", "/bin/true"])
        .output()
        .await;
    match output {
        Ok(o) if o.status.success() => MechanismStatus::Available,
        Ok(o) => MechanismStatus::Unavailable {
            reason: format!("sandbox-exec exited {}", o.status),
        },
        Err(e) => MechanismStatus::Unavailable {
            reason: format!("failed to exec sandbox-exec: {e}"),
        },
    }
}

#[cfg(not(target_os = "macos"))]
pub async fn probe_seatbelt() -> MechanismStatus {
    MechanismStatus::Unavailable {
        reason: "Seatbelt is macOS-only".into(),
    }
}

// ---------------------------------------------------------------------------------
// Cache key / cached aggregate probe
// ---------------------------------------------------------------------------------

/// Inputs that, if any of them change, must invalidate a cached `MechanismProbeReport`
/// (§6.5 rule 1: a kernel upgrade or a replaced bwrap binary invalidates the cache
/// automatically — never keep serving a probe result from before the change).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeCacheKey {
    pub kernel_release: String,
    pub binary_hashes: BTreeMap<String, [u8; 32]>,
    pub apparmor_sysctl: Option<String>,
}

/// Runs every mechanism probe and returns the aggregate report.
///
/// Genuinely `async fn`, `.await`ing each probe directly — no `futures::executor::block_on`.
/// `block_on`-wrapping Tokio-dependent async code panics the moment it's called from
/// inside an already-running Tokio runtime ("there is no reactor running"), which is
/// exactly how `Isolate::probe()` (already `async fn`, Phase 0-frozen) calls this.
///
/// `cache_dir` is accepted for the cache-key comparison (`ProbeCacheKey`) this function
/// will eventually consult, but that comparison is a follow-up optimization, not
/// required for the fail-closed correctness this task is scoped to: for now this always
/// re-probes for real.
pub async fn probe_cached(cache_dir: &Path) -> MechanismProbeReport {
    let _ = cache_dir;
    MechanismProbeReport {
        landlock: probe_landlock().await,
        bwrap: probe_bwrap(Path::new("/usr/libexec/roundhouse/bwrap")).await,
        seccomp: probe_seccomp().await,
        seatbelt: probe_seatbelt().await,
    }
}

// ---------------------------------------------------------------------------------
// Task 14 (lane W5, ruling W5-3): a second, unrelated reason this module needs to
// stay the crate's one `unsafe_code`-permitted module. `bounded_parse.rs`'s
// `run_bounded_subprocess` needs a Linux `RLIMIT_CPU` on the child it spawns, and
// the only way to install an `rlimit` before a `std::process::Command` execs is
// `CommandExt::pre_exec` — itself `unsafe`, for the same reason `fork()` above is:
// its closure runs in the forked child between `fork()` and `exec()`, a window
// where (per this module's top doc comment) some other thread's inherited,
// still-locked allocator mutex could wedge the first allocation the closure makes.
// `set_cpu_limit_pre_exec` keeps the closure itself allocation-free — the `rlimit`
// struct is built by the caller, before the fork, and the closure's only job is the
// syscall — so it does not introduce a second copy of that hazard, just reuses the
// module's existing justification for owning it.
// ---------------------------------------------------------------------------------

/// Installs a `RLIMIT_CPU` (Linux-only; see [`crate::bounded_parse`]'s module doc
/// for the non-Linux behaviour) of `limit` CPU-seconds on `cmd`, taking effect the
/// moment `cmd` execs. Both the soft and hard limit are set to the same value, so
/// the kernel delivers `SIGXCPU` essentially as soon as the limit is reached; since
/// [`crate::bounded_parse::run_bounded_subprocess`]'s helper children install no
/// `SIGXCPU` handler, the default disposition (terminate) applies, and the parent
/// observes it as a signal-terminated [`std::process::ExitStatus`]
/// (`BoundedParseError::ResourceExhausted`), not a graceful exit.
///
/// Sub-second `Duration`s are rounded up to 1 whole second — `RLIMIT_CPU` has no
/// finer resolution than whole seconds, and a limit of literal `0` risks reading
/// as "already exceeded" rather than "one second's grace" on some kernels.
///
/// A safe function despite installing an `unsafe` `pre_exec` hook internally: the
/// `rlimit` value is computed here, before any fork happens, so the closure
/// `pre_exec` runs later touches no caller-provided state and performs exactly one
/// syscall.
#[cfg(target_os = "linux")]
pub fn set_cpu_limit_pre_exec(cmd: &mut std::process::Command, limit: std::time::Duration) {
    use std::os::unix::process::CommandExt;

    let seconds = limit.as_secs().max(1);
    let rlim = libc::rlimit {
        rlim_cur: seconds,
        rlim_max: seconds,
    };

    // SAFETY: this closure runs in the forked child between `fork()` and `exec()`
    // (the same async-signal-safe-only window `forked_probe::run` documents at the
    // top of this file) and must not allocate or take a lock. `rlim` is a plain
    // `Copy` struct built above, outside the closure, so capturing it by value
    // allocates nothing; `libc::setrlimit` is the closure's only call and is on
    // POSIX's async-signal-safe function list. `std::io::Error::last_os_error()` on
    // the failure path reads `errno` and constructs a small enum — no allocation
    // either (`std::io::Error` on this path is a bare OS error code).
    unsafe {
        cmd.pre_exec(move || {
            if libc::setrlimit(libc::RLIMIT_CPU, &rlim) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
}

// ---------------------------------------------------------------------------------
// Internal regression tests for `forked_probe::run` itself (needs crate-internal
// access to the private `forked_probe` module, so this lives here rather than in
// `tests/probe.rs`).
// ---------------------------------------------------------------------------------

#[cfg(all(test, target_os = "linux"))]
mod forked_probe_regression_tests {
    use super::*;

    /// Fix-round-1 regression test for the security auditor's reproduced finding:
    /// a panic inside a forked probe body, invoked through `spawn_blocking` (the
    /// exact call pattern `probe_landlock`/`probe_seccomp` use), must not hang the
    /// parent forever. Before the fix, the panic unwound past `libc::_exit()`,
    /// Tokio's blocking-pool worker machinery caught the unwind inside the
    /// copy-on-write child and returned it to its idle loop instead of exiting, the
    /// child never closed its copy of the pipe's write end, and the parent's
    /// `read_to_end` blocked forever waiting for an EOF that would never come.
    ///
    /// This test itself is wrapped in a bounded `tokio::time::timeout` specifically
    /// so that a regression here fails the test suite loudly and fast instead of
    /// silently hanging CI forever — the exact failure mode this test exists to
    /// catch would otherwise manifest as an unexplained CI timeout with no signal
    /// pointing at this code.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_panicking_probe_body_does_not_hang_the_parent() {
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            tokio::task::spawn_blocking(|| {
                forked_probe::run("panic-regression", || {
                    panic!("deliberate panic to reproduce the security auditor's hang scenario")
                })
            }),
        )
        .await;

        let join_result = outcome.expect(
            "forked_probe::run must return within the timeout; a hang here means the \
             panic-hang regression (fix-round-1 finding 1) has come back",
        );
        let status =
            join_result.expect("the spawn_blocking task itself must not panic or be cancelled");

        match status {
            MechanismStatus::Unavailable { reason } => {
                assert!(
                    reason.contains("panicked"),
                    "reason should explain that the probe body panicked: {reason}"
                );
            }
            other => panic!("expected Unavailable from a panicking probe body, got {other:?}"),
        }
    }

    /// Fix-round-1 regression test for the security auditor's second reproduced
    /// finding: the probe pipe must be opened `O_CLOEXEC` so an unrelated
    /// subprocess spawned elsewhere in the daemon during the fd-open window never
    /// inherits it (an inherited write end would keep the parent's `read_to_end`
    /// blocked until that unrelated process also exits, not just our own forked
    /// child).
    ///
    /// A timing-based test that races a real subprocess spawn against
    /// `forked_probe::run`'s fd-open window would reproduce the auditor's exact
    /// scenario, but is inherently racy/flaky in CI (the window is microseconds
    /// wide). This test instead asserts the one fact that actually matters and is
    /// fully deterministic: immediately after `open_cloexec_pipe()` returns, both
    /// fds really do have `FD_CLOEXEC` set, checked via `fcntl(F_GETFD)` — the
    /// same kernel-level property that determines whether `exec` in any other
    /// thread of this process would inherit them. This is what plain `pipe()`
    /// (the pre-fix call) would have failed, and what `pipe2(..., O_CLOEXEC)`
    /// guarantees.
    #[test]
    fn probe_pipe_fds_are_close_on_exec() {
        let (read_fd, write_fd) = forked_probe::open_cloexec_pipe().expect("pipe2 must succeed");
        for fd in [read_fd, write_fd] {
            // SAFETY: `fd` is one of the two fds `open_cloexec_pipe()` just
            // returned, still open and owned by this test; `F_GETFD` takes no
            // pointer arguments and only reads the fd's flags.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(
                flags >= 0,
                "fcntl(F_GETFD) failed: {}",
                std::io::Error::last_os_error()
            );
            assert_ne!(
                flags & libc::FD_CLOEXEC,
                0,
                "fd {fd} is missing FD_CLOEXEC — an exec'd subprocess elsewhere in this \
                 process could inherit it and wedge forked_probe::run's read_to_end"
            );
            // SAFETY: closing fds this test itself opened via open_cloexec_pipe().
            unsafe { libc::close(fd) };
        }
    }

    /// A well-behaved (non-panicking) body still round-trips correctly through the
    /// same forked-child harness — establishes that the panic guard and alarm added
    /// in fix-round-1 didn't break the ordinary success path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_normal_probe_body_still_reports_available() {
        let status = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            tokio::task::spawn_blocking(|| {
                forked_probe::run("normal-regression", || MechanismStatus::Available)
            }),
        )
        .await
        .expect("must not hang")
        .expect("spawn_blocking must not panic");

        assert_eq!(status, MechanismStatus::Available);
    }
}
