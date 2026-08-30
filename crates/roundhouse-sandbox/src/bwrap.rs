//! §6.5: "we vendor bubblewrap's binary, not its namespace-creation logic" — this module
//! execs the vendored static bwrap binary rather than reimplementing namespace/mount
//! setup. Fixes audit finding 11's undefined `spawn_under_bwrap`.
use crate::{Child, CommandSpec, IsolationError};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::{Child as TokioChild, Command};

/// Returns both the frozen `Child{pid}` shape (what `Isolate::spawn`'s signature
/// requires) and the live `tokio::process::Child` (which the caller must keep alive
/// somewhere — `BwrapLandlockIsolate` stores it in `HandleMeta` — so tokio can still
/// reap the process; dropping it immediately would orphan/zombie the child).
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
) -> Result<(Child, TokioChild), IsolationError> {
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

    // Fix-round-1 finding 2 (second half): previously `spawn()` only checked whether
    // the OS could fork/exec the `bwrap` binary at all — never bwrap's own exit
    // status — so a bwrap process that died on its own setup failure (e.g. the
    // "Can't find source path" case that motivated this whole fix) still produced
    // `Ok(Child{pid})`, leaving the caller believing a sandboxed task was running
    // when it never was.
    //
    // Fix-round-2 correction: fix-round-1 shipped a single `tokio::task::yield_now()`
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

    Ok((Child { pid }, child))
}
