//! §6.5: "we vendor bubblewrap's binary, not its namespace-creation logic" — this module
//! execs the vendored static bwrap binary rather than reimplementing namespace/mount
//! setup. Fixes audit finding 11's undefined `spawn_under_bwrap`.
use crate::{Child, CommandSpec, IsolationError};
use command_fds::{CommandFdExt, FdMapping};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::{Child as TokioChild, Command};

/// The child-side fd bwrap is told (`--info-fd <INFO_FD>`) to write its readiness
/// JSON to, right after namespace/mount setup completes and right before it execs
/// the real sandboxed command — see the long comment below on why this is the
/// authoritative signal `spawn_under_bwrap` waits on, not a guess or a fixed number
/// picked for no reason. Distinct from fd 0, which the seccomp path below already
/// uses for a different purpose.
const INFO_FD: i32 = 100;

/// How long to wait for bwrap's `--info-fd` write (or the pipe closing with no data,
/// on a setup failure) before giving up. §6.5/fix-round-2 rationale: a *successful*
/// setup writes and closes this near-instantly (sub-millisecond in practice, per the
/// same measurements that motivated the exit-status poll below) — this is a safety
/// net against a wedged bwrap process, not the expected common-case latency.
const INFO_FD_TIMEOUT: Duration = Duration::from_secs(5);

/// Returns the frozen `Child{pid}` shape (what `Isolate::spawn`'s signature
/// requires), the live `tokio::process::Child` (which the caller must keep alive
/// somewhere — `BwrapLandlockIsolate` stores it in `HandleMeta` — so tokio can still
/// reap the process; dropping it immediately would orphan/zombie the child), and a
/// `bool` that is `true` only if bwrap itself confirmed, via `--info-fd`, that its
/// namespace/mount setup actually completed for this specific process (fix-round-2;
/// see the long comment on the info-fd wiring below for why this is the field
/// `isolate.rs::attest()` must key `net_enforced` off of, not `bwrap_pid.is_some()`).
///
/// `workspace_root` is the real path bwrap binds onto itself (read-write) inside the
/// sandbox — fix-round-1 finding 2: this used to be derived from `spec.workspace`
/// (`WorkspaceId`, a bare UUID with no path-resolution mechanism anywhere in this
/// codebase) at `prepare()` time, so every real invocation passed `--bind <uuid>
/// <uuid>` to bwrap, which fails immediately with "Can't find source path" — bwrap
/// never even reached namespace setup. There is still no `WorkspaceId` → real path
/// resolver anywhere in this workspace, so the caller (`isolate.rs::spawn`) now
/// derives this from `cmd.cwd`, the real, caller-supplied working directory that's
/// actually available at `spawn()` time, and refuses up front if it's absent.
///
/// `seccomp_bpf`, if present, is a compiled seccomp-BPF program
/// (`probe::compile_baseline_seccomp_bpf`) to actually apply to the spawned child via
/// bwrap's native `--seccomp FD` flag — see the comment on the fd-passing mechanism
/// below for how this is done without `unsafe` and its one known limitation.
pub async fn spawn_under_bwrap(
    bwrap_path: &Path,
    workspace_root: &PathBuf,
    cmd: CommandSpec,
    seccomp_bpf: Option<Vec<u8>>,
) -> Result<(Child, TokioChild, bool), IsolationError> {
    let mut command = Command::new(bwrap_path);
    command
        .arg("--ro-bind")
        .arg("/")
        .arg("/")
        // Fix-round-1 finding 5: without these, the sandboxed child saw the full host
        // `/proc` (every other process's `/proc/<pid>/{comm,cmdline,environ}` readable
        // — a real information-disclosure gap for a "Sandbox"-tier child) and had no
        // writable `/dev` at all (`/dev` was only readable, as part of the read-only
        // `/` bind above, breaking any workload that writes to e.g. `/dev/null`).
        // `--proc`/`--dev` are bwrap's standard, well-known way to give the sandboxed
        // process its own isolated procfs and a minimal writable dev tree instead.
        .arg("--proc")
        .arg("/proc")
        .arg("--dev")
        .arg("/dev")
        .arg("--bind")
        .arg(workspace_root)
        .arg(workspace_root)
        .arg("--unshare-all")
        // Today this fully unshares network (`--unshare-all` includes network) — no
        // proxy binding exists yet. A later task (§6.6) will replace this with a bound
        // loopback-proxy socket, which is what will make `Attestation.net_enforced`
        // (see the comment on that field in `isolate.rs::attest`) true rather than
        // aspirational.
        .arg("--die-with-parent");

    // Fix-round-2 security-review finding: `bwrap_pid.is_some()` (this function
    // succeeding at all) proves `Command::spawn()`/fork succeeded — it does NOT
    // prove bwrap's own namespace setup (the actual `unshare(2)` calls and mount
    // setup) succeeded. Reproduced: a bwrap process that starts, then immediately
    // fails with "Creating new namespace failed: Operation not permitted" (the most
    // common real-world bwrap failure — unprivileged user namespaces disabled) can
    // still race past the exit-status poll below and yield `Ok`, silently claiming
    // network enforcement that was never actually established.
    //
    // Real fix, not a timing guess: bwrap's own `--info-fd FD` mechanism writes a
    // JSON blob to `FD` exactly once namespace/mount setup has genuinely completed
    // and bwrap is about to exec the real sandboxed command — never earlier, and
    // never at all if setup fails first. Wiring an fd for it and waiting for either
    // that data or the pipe closing empty (setup died before writing) is a
    // deterministic confirmation, not a fixed-window race — closing exactly the gap
    // the exit-status poll below cannot close (see that poll's own comment for what
    // it's for instead: a *different*, complementary check for LATE failures, like a
    // nonexistent program to exec, which happen strictly after this info-fd write).
    //
    // `std::os::unix::net::UnixStream::pair()` (std, no extra dependency, no
    // `unsafe` in this crate) gives a connected fd pair; `command-fds` (`unsafe`
    // confined to that dependency, not this crate — same posture as
    // `landlock`/`seccompiler` above) safely hands the write end to the child as fd
    // `INFO_FD` without disturbing fd 0/1/2 or the seccomp-fd path below.
    let (info_read, info_write) = std::os::unix::net::UnixStream::pair()
        .map_err(|e| IsolationError::Unsupported(format!("failed to create info-fd pipe: {e}")))?;
    info_read.set_nonblocking(true).map_err(|e| {
        IsolationError::Unsupported(format!("failed to configure info-fd pipe: {e}"))
    })?;
    let mut info_read = tokio::net::UnixStream::from_std(info_read).map_err(|e| {
        IsolationError::Unsupported(format!("failed to register info-fd pipe with tokio: {e}"))
    })?;
    command
        .fd_mappings(vec![FdMapping {
            parent_fd: info_write.into(),
            child_fd: INFO_FD,
        }])
        .map_err(|e| {
            IsolationError::Unsupported(format!("failed to map info-fd into bwrap's fd table: {e}"))
        })?;
    command.arg("--info-fd").arg(INFO_FD.to_string());

    if let Some(bpf_bytes) = seccomp_bpf {
        // bwrap's `--seccomp FD` needs a real, open file descriptor holding the
        // compiled BPF program. There is no safe, stable std/tokio API to hand an
        // *arbitrary* fd number to a spawned child (that needs `unsafe`
        // `CommandExt::pre_exec`, or a third-party crate wrapping the same) — but
        // `Command`'s stdio (`stdin`/`stdout`/`stderr`) IS a safe, stable channel for
        // handing the child a pre-opened `File`. So: write the compiled program to a
        // throwaway temp file, open it, wire it up as the spawned bwrap process's own
        // stdin (fd 0), and tell bwrap to read its seccomp program from fd 0
        // (`--seccomp 0`). Empirically verified (fix-round-1) against real bwrap
        // 0.12.0: this genuinely applies — `ptrace()` inside the sandbox returns
        // `-1`/`EPERM`, `0` outside it.
        //
        // KNOWN LIMITATION, not silently swallowed: bwrap consumes and closes this fd
        // during its own setup, before it execs the real command — empirically
        // verified the exec'd command's own fd 0 comes back closed/invalid (`EBADF`
        // on read), not the real inherited stdin. So whenever a seccomp filter is
        // applied, the *sandboxed command loses real stdin*. `CommandSpec` has no
        // stdin field yet, so nothing currently depends on real stdin reaching the
        // sandboxed process, but this is a real behavior change future callers must
        // know about — preserving real stdin alongside a passed seccomp fd (e.g. via
        // a small setns/pre-exec helper, or an `unsafe`-free extra-fd-passing crate)
        // is a tracked follow-up, not attempted here.
        let tmp_path =
            std::env::temp_dir().join(format!("roundhouse-seccomp-{}.bpf", uuid::Uuid::new_v4()));
        std::fs::write(&tmp_path, &bpf_bytes).map_err(|e| {
            IsolationError::Unsupported(format!("failed to write seccomp program: {e}"))
        })?;
        let file = std::fs::File::open(&tmp_path).map_err(|e| {
            IsolationError::Unsupported(format!("failed to open seccomp program: {e}"))
        })?;
        // Safe to unlink now: the already-open fd keeps the file's contents alive on
        // Linux until the fd itself is closed; this just avoids leaving the compiled
        // program sitting on disk under a predictable-ish temp path.
        let _ = std::fs::remove_file(&tmp_path);
        command.arg("--seccomp").arg("0");
        command.stdin(Stdio::from(file));
    }

    command.arg("--").arg(&cmd.program).args(&cmd.argv);
    if let Some(cwd) = &cmd.cwd {
        command.current_dir(cwd);
    }
    let mut child = command
        .spawn()
        .map_err(|e| IsolationError::Unsupported(format!("failed to spawn under bwrap: {e}")))?;
    let pid = child.id().ok_or_else(|| {
        IsolationError::Unsupported("bwrap child exited before its pid was observable".into())
    })?;

    // `command-fds`' `fd_mappings` docs: the parent (us) keeps its own copy of the
    // info-fd write end open, via the closure captured inside `command`, until
    // `command` itself is dropped — NOT just until `spawn()` returns. If we don't
    // drop it explicitly here, our own dangling copy of the write end would keep
    // `info_read` from ever seeing EOF below, even after bwrap closes its own copy,
    // defeating the entire point of waiting for the pipe to close.
    drop(command);

    // Fix-round-2 security-review finding: wait for bwrap's own `--info-fd`
    // confirmation BEFORE the exit-status poll below — this is the deterministic
    // check for whether namespace/mount setup itself completed (see the long
    // comment above where `INFO_FD`/the pipe are set up for the full rationale).
    // Either real data arrives (setup completed, bwrap is about to exec the real
    // command) or the pipe closes with nothing in it (setup died first) — no fixed
    // window to race against for this specific question, unlike the poll below.
    let mut info_buf = Vec::new();
    let info_confirmed =
        match tokio::time::timeout(INFO_FD_TIMEOUT, info_read.read_to_end(&mut info_buf)).await {
            Ok(Ok(_)) => !info_buf.is_empty(),
            Ok(Err(_)) => false, // pipe-level error reading it back — treat as unconfirmed
            Err(_) => false,     // timed out — treat as unconfirmed (a wedged/hung setup)
        };
    if !info_confirmed {
        // No confirmation ever arrived: either bwrap died before completing its own
        // namespace/mount setup (the common case — e.g. "Creating new namespace
        // failed: Operation not permitted" when unprivileged user namespaces are
        // disabled, or the same bad-bind-path failure the poll below also catches,
        // just caught here deterministically instead of by racing a timing window),
        // or it's hung. Either way, don't let the caller believe a sandboxed process
        // is genuinely running when its namespace setup was never confirmed.
        let _ = child.start_kill(); // best-effort: nothing to clean up if it already died
        return Err(IsolationError::Unsupported(
            "bwrap's --info-fd never confirmed namespace/mount setup completed for this \
             process — treating this as a setup failure rather than trusting an unconfirmed \
             spawn"
                .into(),
        ));
    }

    // Fix-round-1 finding 2 (second half): previously `spawn()` only checked whether
    // the OS could fork/exec the `bwrap` binary at all — never bwrap's own exit
    // status — so a bwrap process that died on its own setup failure (e.g. the
    // "Can't find source path" case that motivated this whole fix) still produced
    // `Ok(Child{pid})`, leaving the caller believing a sandboxed task was running
    // when it never was.
    //
    // Fix-round-2 (Task 24) note: the info-fd check above already deterministically
    // rules out early (pre-setup-completion) failures like a bad bind path or a
    // namespace-creation failure — by the time execution reaches here,
    // `info_confirmed` was `true`, so namespace/mount setup genuinely completed.
    // This poll's remaining, still-needed job is catching LATE failures: bwrap's own
    // exec of the real target command failing (e.g. a nonexistent program), which
    // happens strictly after the info-fd write and so info-fd confirmation can't see
    // it. Kept as the same timing-window poll as before for that narrower purpose.
    //
    // Fix-round-2 (Task 17) correction: fix-round-1 shipped a single `tokio::task::yield_now()`
    // (one scheduler tick, ~10us) followed by one `try_wait()`, documented as
    // "catching every near-instant setup failure" — that claim did not hold up under
    // measurement. Instrumented timing showed bwrap actually takes ~1.5ms to die on
    // a bad `--bind` path — two orders of magnitude longer than one `yield_now()`
    // tick — so the guard caught the deliberately-reproduced failure in 0 of 50 runs,
    // not "most" of them. This is now a short bounded poll instead: check
    // immediately (free in the success case if bwrap is somehow already gone), then
    // back off over a few short sleeps totaling ~15ms — comfortably above the
    // measured ~1.5ms failure latency with margin, while still bounding the added
    // latency on every successful spawn (the overwhelmingly common case) to at most
    // ~15ms. Measured over multiple runs (fix-round-2): 10/10 for a bad bind path via
    // `spawn_under_bwrap` directly, and 10/10 for a nonexistent exec target through
    // the real `Isolate::spawn` API — see `tests/isolate_fix_round_2.rs`. This is
    // still not a mathematical guarantee — a setup failure slower than ~15ms would
    // still return `Ok` — but it is a real, measured margin over the actual observed
    // failure latency, not merely an assertion of one.
    //
    // Only a *non-zero* exit within the window counts as a setup failure — bwrap's
    // own top-level process exit code mirrors the real command's when it isn't
    // reparented under `--as-pid-1`, so a real command that itself finishes within
    // this same short window (a fast `echo`, a short script, `true`) exits bwrap with
    // status 0 and must NOT be misreported as a setup failure (fix-round-2 caught this
    // exact regression: the first version of this fix treated *any* exit within the
    // window as failure, breaking two passing real-exec tests that happened to finish
    // fast). Residual, accepted ambiguity: a real command that itself legitimately
    // fails with a non-zero exit within this same short window is indistinguishable
    // from a bwrap setup failure by exit code alone (bwrap's stderr, which would
    // disambiguate the two, isn't captured here) — but `Isolate::spawn`'s frozen
    // `Child{pid}` return type has no channel to report "ran and exited non-zero"
    // separately from this error today regardless, so collapsing the two cases here
    // is not a regression relative to what this contract can already represent.
    const EXIT_CHECK_DELAYS_MS: &[u64] = &[0, 1, 2, 4, 8];
    let mut setup_failure_status = None;
    for delay_ms in EXIT_CHECK_DELAYS_MS {
        if *delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(*delay_ms)).await;
        }
        match child.try_wait() {
            Ok(Some(status)) if !status.success() => {
                setup_failure_status = Some(status);
                break;
            }
            Ok(Some(_)) => break, // exited, but successfully — a fast real command, not a setup failure
            Ok(None) => {}        // still running past its own setup — keep polling
            Err(e) => {
                return Err(IsolationError::Unsupported(format!(
                    "failed to check bwrap's post-spawn status: {e}"
                )));
            }
        }
    }
    if let Some(status) = setup_failure_status {
        return Err(IsolationError::Unsupported(format!(
            "bwrap exited immediately during setup with a non-zero status ({status}) instead \
             of running the sandboxed command — this is a setup failure (e.g. an unbindable \
             path), not a fast-exiting real workload"
        )));
    }

    // `info_confirmed` is always `true` here — the early-return above already
    // handled the `false` case — so this is a real, not aspirational, confirmation
    // that bwrap's namespace/mount setup completed for this specific process.
    Ok((Child { pid }, child, info_confirmed))
}
