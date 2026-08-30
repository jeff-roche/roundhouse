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
    /// support: `Sandbox` needs Landlock *and* bwrap both truly `Available`; any
    /// `Degraded`/`Unavailable` mechanism is recorded as a degradation, never
    /// silently dropped (§6.5 rule 1's "Landlock BestEffort is where fail-open
    /// hides").
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
        let achieved = match (&self.landlock, &self.bwrap) {
            (MechanismStatus::Available, MechanismStatus::Available) => Tier::Sandbox,
            (_, MechanismStatus::Available) | (MechanismStatus::Available, _) => Tier::Worktree,
            _ => Tier::None,
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

    /// Runs `body` inside a forked child process and returns the `MechanismStatus` it
    /// reports, communicated back over a pipe as a one-byte tag (0 = Available,
    /// 1 = Degraded, 2 = Unavailable) followed by the UTF-8 `reason` bytes.
    ///
    /// This exists so that Landlock's `restrict_self()` and an installed seccomp
    /// filter — both irreversible for the calling thread/process — are only ever
    /// applied to a throwaway child that exits immediately afterward, never to a
    /// thread the Tokio runtime intends to reuse.
    pub(super) fn run(mechanism: &str, body: impl FnOnce() -> MechanismStatus) -> MechanismStatus {
        let mut fds = [-1i32; 2];
        // SAFETY: `fds` is a valid `&mut [c_int; 2]` (correct size/alignment for two
        // ints), exactly what POSIX `pipe(2)` requires as its out-parameter. The
        // return value is checked before either fd is used.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return MechanismStatus::Unavailable {
                reason: format!(
                    "{mechanism} probe: pipe() failed: {}",
                    std::io::Error::last_os_error()
                ),
            };
        }
        let (read_fd, write_fd) = (fds[0], fds[1]);

        // SAFETY: `fork()` duplicates the calling process. The child branch below
        // touches only process-local state (its own copy of `body`, the pipe fds,
        // and libc calls), never reaches back into the parent's Rust call stack
        // past this function, and terminates via `_exit` without unwinding or
        // running the parent's destructors. This is the one place in the workspace
        // that needs a raw `fork()`: it's how Landlock/seccomp's irreversible
        // enforcement is confined to a throwaway process instead of poisoning a
        // shared thread.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            // SAFETY: closing the two fds this function itself just opened via `pipe()`.
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
            // and exit without ever returning to the caller's stack frame.
            // SAFETY: `read_fd` is unused in the child; closing our copy of it does
            // not affect the parent's copy.
            unsafe { libc::close(read_fd) };
            let status = body();
            let (tag, reason): (u8, &str) = match &status {
                MechanismStatus::Available => (0, ""),
                MechanismStatus::Degraded { reason } => (1, reason.as_str()),
                MechanismStatus::Unavailable { reason } => (2, reason.as_str()),
            };
            let mut payload = Vec::with_capacity(1 + reason.len());
            payload.push(tag);
            payload.extend_from_slice(reason.as_bytes());
            // SAFETY: `write_fd` is a valid, owned fd returned by `pipe()` above;
            // `File::from_raw_fd` takes ownership of it, so it is closed exactly
            // once when `file` drops a few lines down.
            let mut file = unsafe { std::fs::File::from_raw_fd(write_fd) };
            let _ = file.write_all(&payload);
            drop(file);
            // SAFETY: terminates only this forked child immediately after reporting
            // its result. Uses `_exit` (not `std::process::exit`/a normal return) so
            // no `Drop` impls or atexit handlers that logically belong to the parent
            // process run a second time in this copy-on-write child.
            unsafe { libc::_exit(0) };
        }

        // Parent process.
        // SAFETY: `write_fd` is unused in the parent; closing our copy of it does
        // not affect the child's copy (needed so `read_to_end` below observes EOF
        // once the child closes its own copy on exit).
        unsafe { libc::close(write_fd) };
        let mut buf = Vec::new();
        {
            // SAFETY: `read_fd` is a valid, owned fd returned by `pipe()` above;
            // `File::from_raw_fd` takes ownership, closed when `file` drops at the
            // end of this block.
            let mut file = unsafe { std::fs::File::from_raw_fd(read_fd) };
            let _ = file.read_to_end(&mut buf);
        }
        let mut wait_status: i32 = 0;
        // SAFETY: `pid` is the child this function just forked (no other code can
        // have reaped it), and `&mut wait_status` is a valid out-pointer sized for
        // a C `int`, exactly what `waitpid(2)` requires.
        let waited = unsafe { libc::waitpid(pid, &mut wait_status, 0) };
        if waited < 0 {
            return MechanismStatus::Unavailable {
                reason: format!(
                    "{mechanism} probe: waitpid() failed: {}",
                    std::io::Error::last_os_error()
                ),
            };
        }
        if buf.is_empty() {
            // The child died before writing anything (e.g. crashed, or was killed
            // outright by the very mechanism being probed instead of returning an
            // error to it). Report that fact explicitly rather than silently
            // treating it as Unavailable-with-no-explanation.
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
