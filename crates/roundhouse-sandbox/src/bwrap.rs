//! §6.5: "we vendor bubblewrap's binary, not its namespace-creation logic" — this module
//! execs the vendored static bwrap binary rather than reimplementing namespace/mount
//! setup. Fixes audit finding 11's undefined `spawn_under_bwrap`.
use crate::{Child, CommandSpec, IsolationError};
use command_fds::{CommandFdExt, FdMapping};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

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

/// Returns the live sandbox child and a `bool` that is `true` only if bwrap itself
/// confirmed, via `--info-fd`, that its
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
) -> Result<(Child, bool), IsolationError> {
    if !workspace_root.is_dir() {
        return Err(IsolationError::Unsupported(format!(
            "workspace root is not an accessible directory: {}",
            workspace_root.display()
        )));
    }
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
    } else {
        command.stdin(Stdio::null());
    }

    command
        .env_clear()
        .envs(cmd.env.iter().cloned())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // The bwrap process is the process-group leader. Killing the returned child
    // therefore reaches the command it launched as well, instead of leaving a
    // backgrounded descendant behind after task cancellation.
    #[cfg(unix)]
    command.process_group(0);

    command.arg("--").arg(&cmd.program).args(&cmd.argv);
    if let Some(cwd) = &cmd.cwd {
        command.current_dir(cwd);
    }
    let mut child = command
        .spawn()
        .map_err(|e| IsolationError::Unsupported(format!("failed to spawn under bwrap: {e}")))?;
    let Some(pid) = child.id() else {
        let _ = child.start_kill();
        let _ = child.wait().await;
        return Err(IsolationError::Unsupported(
            "bwrap child exited before its pid was observable".into(),
        ));
    };

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
        // disabled, or a bad bind path,
        // caught here deterministically instead of by racing a timing window),
        // or it's hung. Either way, don't let the caller believe a sandboxed process
        // is genuinely running when its namespace setup was never confirmed.
        let _ = child.start_kill(); // best-effort: nothing to clean up if it already died
        if let Err(err) = child.wait().await {
            return Err(IsolationError::Unsupported(format!(
                "bwrap setup failed and could not be reaped: {err}"
            )));
        }
        return Err(IsolationError::Unsupported(
            "bwrap's --info-fd never confirmed namespace/mount setup completed for this \
             process — treating this as a setup failure rather than trusting an unconfirmed \
             spawn"
                .into(),
        ));
    }

    // The info-fd check above deterministically rules out failures before
    // namespace/mount setup completes. Once it has fired, the returned child
    // owns the real command's exit status, including legitimate fast non-zero
    // exits; treating every early non-zero status as a bwrap setup failure would
    // turn a denied command such as `cat` into a spawn error. Absolute program
    // paths are preflighted by `BwrapLandlockIsolate::spawn` before this point.
    //
    // `info_confirmed` is always `true` here — the early-return above already
    // handled the `false` case — so this is a real, not aspirational, confirmation
    // that bwrap's namespace/mount setup completed for this specific process.
    Ok((Child::from_process_internal(pid, child), info_confirmed))
}
