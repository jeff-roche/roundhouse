//! A generic, **synchronous**, resource-bounded subprocess primitive (Task 14,
//! lane W5). Spawns any program, feeds it `stdin`, and returns its `stdout`
//! bytes — or a typed error — once one of three independent bounds is hit:
//! a CPU-time ceiling (Linux only, via [`crate::probe::set_cpu_limit_pre_exec`]),
//! a wall-clock ceiling (every platform), or an output-size ceiling (every
//! platform).
//!
//! # What this does NOT bound: memory / address space (ruling W5-25, finding 4)
//!
//! **These are the complete three bounds — CPU, wall-clock, output size —
//! and memory/address space is a real, uncovered fourth axis, stated
//! plainly rather than left for a reader to discover.** A security review
//! found no `RLIMIT_AS`/`RLIMIT_DATA` installed anywhere in this module and
//! flagged the omission; ruling W5-25 decided against adding one this
//! round (not against ever adding one): `RLIMIT_AS` counts *virtual*
//! address space and interacts badly with allocator reservations (glibc's
//! per-thread arenas, jemalloc worse), so there is no obviously-generous
//! number, and guessing low kills a legitimate parse in CI rather than
//! stopping an attacker. `RLIMIT_DATA` is the better-targeted primitive but
//! its coverage of `mmap`-backed allocations depends on kernel >=4.7
//! semantics, and the natural regression test for either (a child
//! allocating until killed) is a flake generator, not a reliable CI check.
//! Shipping an untuned memory rlimit now would trade a real but bounded gap
//! for a mistuned one with worse failure modes.
//!
//! Practical exposure today is small for this primitive's first caller:
//! `roundhouse-flow`'s `expansion::check_expansion` runs *inside* the
//! bounded child, before the typed deserialize, and caps expanded weight
//! before any large allocation happens; the review measured the largest
//! reachable helper output at 1.92 MB. **Named follow-up, not implemented
//! here:** a tuned `RLIMIT_DATA`, landing with its own measurement pass
//! against real workloads rather than a guess. Until then, a sufficiently
//! memory-hungry child is only caught if it also runs long enough to hit
//! `wall_limit`/`cpu_limit` or writes enough to hit `max_output_bytes` —
//! not by anything in this module that bounds memory directly.
//!
//! # Why this exists (ruling W5-2)
//!
//! `roundhouse-flow`'s workflow-YAML parser measured `serde_yaml`/
//! `unsafe-libyaml`'s anchor/alias expansion at up to 287.8 seconds of pinned
//! CPU for a document smaller than this project's own reference fixture, and
//! a separate residual (an admitted-but-slow integer-decode shape) at
//! ~9.4 seconds even after every in-process guard `roundhouse-flow` could
//! build. No in-process meter can bound this, because the cost lives inside
//! a synchronous, non-cancellable third-party deserializer with ~190
//! `unsafe` blocks of its own. The structural fix is to run that
//! deserializer in a separate, resource-capped **process** instead of
//! bounding it in-process — which is what this module is generic
//! infrastructure for. `roundhouse-flow` is this primitive's first caller
//! (see `crates/roundhouse-flow/src/parse/helper.rs`), but this module
//! itself has no idea what YAML is: it takes a program and bytes, and
//! returns bytes.
//!
//! # Why synchronous (ruling W5-2)
//!
//! `roundhouse-flow::parse::parse_workflow` is a sync function with sync
//! callers all the way up (`compose::register_as_tool`,
//! `exec::run_loop::run_workflow`, `Executor::new`) and no `tokio`
//! dependency at all. Making this primitive `async` would force `tokio`
//! into `roundhouse-flow` and every executor path — a blast radius far
//! larger than the DoS fix itself. This function is built on
//! `std::process::Command`, polls with `try_wait`, and **never blocks on a
//! Tokio runtime thread** — the daemon (a future caller) can and must call
//! this from `spawn_blocking` or an equivalent dedicated thread, never a
//! direct `.await`, exactly because it is a real blocking call.
//!
//! # Why bytes, not `T: DeserializeOwned` (ruling W5-2)
//!
//! Deserializing here would require `serde`/`serde_json` (or similar) as a
//! dependency of this crate. `roundhouse-sandbox` has neither today, and
//! this primitive is not YAML-shaped — a future caller with a different
//! untrusted-format problem (a second YAML surface, a size-unbounded
//! third-party format, ...) can reuse it exactly as-is. The caller
//! deserializes; `roundhouse-flow` already depends on `serde_json` and
//! `serde_yaml`.
//!
//! # The stdin/stdout pipe deadlock, and how this avoids it
//!
//! Writing all of `stdin` from the calling thread before ever reading
//! `stdout` deadlocks the moment both exceed one pipe buffer (commonly
//! 64 KiB on Linux): the child fills its stdout pipe and blocks on `write`,
//! while the parent is still blocked on its own `write` to the child's
//! stdin, and neither side is reading anything. This function avoids that
//! by writing stdin, and reading stdout and stderr, on three separate
//! threads (via [`std::thread::scope`]) that all run concurrently with the
//! `try_wait` polling loop on the calling thread — see
//! `tests/bounded_parse.rs`'s
//! `a_large_round_trip_does_not_deadlock_on_the_stdin_stdout_pipe` for the
//! regression test.
//!
//! # Non-Linux behaviour (ruling W5-3)
//!
//! `libc` — and therefore [`crate::probe::set_cpu_limit_pre_exec`] — is a
//! Linux-only dependency of this crate. Off Linux this function still
//! spawns the child, still enforces `wall_limit` and `max_output_bytes` in
//! full, and simply carries no `RLIMIT_CPU`: a real, smaller bound, never a
//! silent no-op.

use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// How often the calling thread polls the child for exit while also
/// checking the wall-clock and output-size bounds. Small enough that a
/// bound firing is detected promptly (the flooding-output test asserts the
/// call returns in well under a second past the cap), large enough not to
/// spin a core purely on polling.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// How much of the child's stderr this function will buffer for a
/// [`BoundedParseError::HelperCrashed`] message. Independent of, and much
/// smaller than, the caller-supplied `max_output_bytes` (which bounds
/// stdout — the actual payload) — stderr here is diagnostic text, not
/// data, and is never returned to the caller on success.
const STDERR_CAPTURE_CAP: usize = 64 * 1024;

/// Why [`run_bounded_subprocess`] did not return the child's stdout.
#[derive(Debug, thiserror::Error)]
pub enum BoundedParseError {
    /// The child could not even be spawned (binary missing, not
    /// executable, permission denied, ...). Never confused with a bound
    /// firing: this is an infrastructure failure, not a rejection of the
    /// child's behaviour.
    #[error("failed to spawn {program}: {source}")]
    Spawn {
        program: String,
        #[source]
        source: io::Error,
    },

    /// The child was still running once `wall_limit` elapsed and was
    /// killed. The only bound enforced on every platform without
    /// exception (ruling W5-3) — the backstop for CPU-cheap stalls (e.g.
    /// blocked I/O) that `RLIMIT_CPU` cannot see, and the only bound at
    /// all on non-Linux hosts.
    #[error("helper process exceeded the {wall_limit:?} wall-clock bound and was killed")]
    Timeout { wall_limit: Duration },

    /// The child was terminated by a signal this function did not send
    /// itself (Linux: typically `SIGXCPU`, delivered when `RLIMIT_CPU` is
    /// reached, or a subsequent `SIGKILL` if the process is slow to die).
    /// Distinguished from [`BoundedParseError::Timeout`] by *who* killed
    /// it: a self-inflicted kill (timeout or output overflow) is
    /// classified before this function ever inspects the exit status, so
    /// reaching this variant means the kernel — not this function — ended
    /// the child.
    #[error("helper process was killed by signal {signal} (resource limit exceeded)")]
    ResourceExhausted { signal: i32 },

    /// The child's stdout **or stderr** exceeded its cap and was killed
    /// before finishing — `max_output_bytes` names whichever limit was
    /// actually crossed: the caller-supplied stdout cap, or (ruling
    /// W5-25, finding 5) `STDERR_CAPTURE_CAP` if stderr was the one that
    /// overflowed. Independent of `wall_limit`/CPU: a child that floods
    /// output cheaply (e.g. `yes`) must not be allowed to run for the full
    /// wall-clock allowance just because it isn't CPU-bound.
    #[error("helper process emitted more than {max_output_bytes} output bytes; killed")]
    OutputTooLarge {
        /// The cap that was actually crossed — not necessarily
        /// `run_bounded_subprocess`'s caller-supplied stdout cap; see the
        /// variant doc above.
        max_output_bytes: usize,
    },

    /// The child exited on its own, without being killed by either bound
    /// above, but with a failure status. `stderr` (bounded to
    /// `STDERR_CAPTURE_CAP`) is included for diagnosis.
    #[error("helper process exited with {status}: {stderr}")]
    HelperCrashed { status: String, stderr: String },
}

/// Runs `program` with `args`, feeding it `stdin` and returning its stdout
/// bytes, subject to three independent bounds: `cpu_limit` CPU-seconds
/// (Linux only — see the module doc comment), `wall_limit` of real time,
/// and `max_output_bytes` of stdout. Synchronous; never spawns a Tokio
/// task and never blocks on one — see the module doc comment for why a
/// caller inside an async runtime must run this on a dedicated thread
/// (e.g. `spawn_blocking`), not `.await` it directly.
pub fn run_bounded_subprocess(
    program: &Path,
    args: &[&OsStr],
    stdin_bytes: &[u8],
    cpu_limit: Duration,
    wall_limit: Duration,
    max_output_bytes: usize,
) -> Result<Vec<u8>, BoundedParseError> {
    let mut command = Command::new(program);
    command.args(args);
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    // Ruling W5-25, finding 3: this primitive's own children read nothing
    // from the process environment (`roundhouse-flow`'s helper resolves
    // itself via `current_exe()`, never `$PATH`), and the daemon's
    // environment is exactly where secrets like `ANTHROPIC_API_KEY` live.
    // A new spawn site inheriting the whole thing by default is a
    // foothold-to-disclosure path a future helper substitution could use;
    // `env_clear()` closes it. `std::process::Command` on Unix resolves a
    // bare (slash-free) program name against the *caller's* real `PATH`
    // before exec, not the child's cleared environment, so this does not
    // break locating bare-name test children like `cat`/`sh`/`sleep`/`yes`
    // (verified: every existing test in this module still passes).
    command.env_clear();

    #[cfg(target_os = "linux")]
    crate::probe::set_cpu_limit_pre_exec(&mut command, cpu_limit);
    #[cfg(not(target_os = "linux"))]
    {
        // No RLIMIT_CPU off Linux (ruling W5-3): `cpu_limit` plays no part
        // here, so the wall-clock and output bounds below carry the whole
        // load. Named explicitly rather than silently unused so a reader
        // does not mistake this for an oversight.
        let _ = cpu_limit;
    }

    // Ruling W5-25, finding 2: makes the child the leader of its own new
    // process group (pgid == its own pid), so a subsequent kill can target
    // the whole group — everything the child forks — not just the one
    // process `Child::kill()` names. Safe Rust; no `unsafe` needed here.
    // See `kill_child_and_descendants` and `crate::probe::kill_process_group`'s
    // doc for why one `fork()` inside the child would otherwise defeat every
    // bound this primitive enforces. Gated the same as `RLIMIT_CPU` above
    // (ruling W5-3's off-Linux convention): off Linux this primitive still
    // enforces `wall_limit` and `max_output_bytes` on the direct child, just
    // without group-wide reach.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    let mut child = command.spawn().map_err(|source| BoundedParseError::Spawn {
        program: program.display().to_string(),
        source,
    })?;

    let stdin = child.stdin.take();
    let mut stdout = child.stdout.take().expect("stdout was requested as piped");
    let mut stderr = child.stderr.take().expect("stderr was requested as piped");

    let output_exceeded = AtomicBool::new(false);
    let stderr_exceeded = AtomicBool::new(false);

    let (outcome, stdout_buf, stderr_buf) = thread::scope(|scope| {
        // Writes stdin (if any) and then drops it, closing the pipe and
        // sending EOF to the child — on its own thread so a large stdin
        // write can never block behind an unread, filling stdout pipe.
        scope.spawn(move || {
            if let Some(mut pipe) = stdin {
                // A short or failed write here means the child exited (or
                // was killed) before consuming all of stdin, e.g. `EPIPE`.
                // That is an expected shutdown race, not a defect in this
                // function: the caller finds out what happened from the
                // exit-status/bound classification below, not from this
                // write's result.
                let _ = pipe.write_all(stdin_bytes);
            }
        });

        // Reads stdout on its own thread, independent of the stdin writer
        // and the wait-loop below, so all three run concurrently.
        let stdout_reader =
            scope.spawn(|| read_capped(&mut stdout, max_output_bytes, &output_exceeded));
        let stderr_reader =
            scope.spawn(|| read_capped(&mut stderr, STDERR_CAPTURE_CAP, &stderr_exceeded));

        let outcome = wait_bounded(
            &mut child,
            wall_limit,
            max_output_bytes,
            &output_exceeded,
            &stderr_exceeded,
        );

        // Ruling W5-25, finding 8a: `.join()`'s `Err` (the reader thread
        // panicked) used to be silently swallowed by `unwrap_or_default`,
        // which would turn a panicking reader into a successful-looking
        // `Ok(vec![])` for a child that exited 0 with real output — silent
        // truncation instead of a propagated error. Unreachable today
        // (`read_capped` has no panicking operations), so a `debug_assert`
        // is proportionate: it makes a future regression loud in tests and
        // debug builds without adding a new public `BoundedParseError`
        // variant for a case that cannot happen yet.
        let stdout_join = stdout_reader.join();
        debug_assert!(
            stdout_join.is_ok(),
            "read_capped's stdout reader thread panicked; read_capped has no \
             panicking operations today, so reaching this means that invariant broke"
        );
        let stdout_buf = stdout_join.unwrap_or_default();

        let stderr_join = stderr_reader.join();
        debug_assert!(
            stderr_join.is_ok(),
            "read_capped's stderr reader thread panicked; see the stdout debug_assert above"
        );
        let stderr_buf = stderr_join.unwrap_or_default();

        (outcome, stdout_buf, stderr_buf)
    });

    match outcome {
        WaitOutcome::TimedOut => Err(BoundedParseError::Timeout { wall_limit }),
        WaitOutcome::OutputExceeded { limit } => Err(BoundedParseError::OutputTooLarge {
            max_output_bytes: limit,
        }),
        WaitOutcome::Exited(status) => {
            // Ruling W5-25, finding 1: `wait_bounded`'s poll loop checks
            // `try_wait()` before `output_exceeded`, so a child that
            // overshoots `max_output_bytes` by less than one pipe buffer
            // and exits promptly can be reaped as `Exited` before that
            // loop ever notices the flag — `classify_exit` on its own has
            // no way to know the cap was exceeded. By the time
            // `thread::scope` above returns, `stdout_reader` has already
            // been joined (finished reading, and setting the flag if it
            // saw more than `max_output_bytes`), so re-checking the flag
            // here, once, before classifying the exit, is authoritative
            // regardless of which way the exit-vs-flag race went inside
            // the poll loop. This must win over a successful exit status:
            // an attacker-controlled child cannot un-exceed the cap by
            // also exiting 0.
            if output_exceeded.load(Ordering::SeqCst) {
                Err(BoundedParseError::OutputTooLarge { max_output_bytes })
            } else {
                classify_exit(status, stdout_buf, stderr_buf)
            }
        }
    }
}

/// What ended the wait loop in [`run_bounded_subprocess`]. `OutputExceeded`
/// carries which cap fired (`max_output_bytes` for stdout,
/// `STDERR_CAPTURE_CAP` for stderr — ruling W5-25, finding 5) so the
/// caller's error message names the byte count that was actually crossed.
enum WaitOutcome {
    Exited(ExitStatus),
    TimedOut,
    OutputExceeded { limit: usize },
}

/// Polls `child` until it exits on its own, `wall_limit` elapses, or either
/// `output_exceeded` or `stderr_exceeded` is set by its respective
/// concurrent reader — killing (and reaping, so no zombie is left behind)
/// the child on any of the latter three paths before returning.
///
/// **`stderr_exceeded` is consulted here since ruling W5-25, finding 5** —
/// before, nothing read it: a child that flooded stderr past
/// `STDERR_CAPTURE_CAP` stopped being drained, blocked on its own `write`
/// once the pipe filled, and simply sat until `wall_limit` fired instead of
/// getting the same prompt kill a stdout flood already got. Fail-closed
/// either way (the wall-clock bound still applied), so this is a
/// promptness fix, not a bypass fix like finding 1's.
///
/// **Residual (f), found during this round's self-review, not fixed:** the
/// `Exited` arm below returns as soon as `try_wait()` reports the *direct*
/// child gone — it does not call [`kill_child_and_descendants`] first. A
/// child that forks a descendant, hands it the inherited stdout write end,
/// and then exits itself (e.g. `sh -c "sleep infinity &"`) leaves that
/// descendant holding the pipe open with nothing left to kill it: this loop
/// has already returned, and `run_bounded_subprocess`'s `thread::scope`
/// blocks forever inside `read_capped`'s `.read()` waiting for an EOF the
/// orphan never sends — a hang with *no* bound applying at all, not even
/// `wall_limit`. Distinct from finding 2 (which covers the three paths that
/// already call `kill_child_and_descendants`: timeout, stdout overflow,
/// stderr overflow) and from the item-2 residual above (a `setsid` escapee):
/// this one is reachable through the *ordinary* exit path with no evasion
/// needed, for any child that legitimately backgrounds work and returns
/// before that work finishes. Not fixed this round — ruling W5-25 scoped
/// item 2 to "the kill paths" and adding a `killpg` here changes the
/// contract for a child that intentionally backgrounds a helper and exits
/// (killing a legitimate grandchild is different from killing a hung one),
/// which needs its own ruling rather than a silent addition in a Minor-item
/// pass.
fn wait_bounded(
    child: &mut Child,
    wall_limit: Duration,
    max_output_bytes: usize,
    output_exceeded: &AtomicBool,
    stderr_exceeded: &AtomicBool,
) -> WaitOutcome {
    let start = Instant::now();
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return WaitOutcome::Exited(status);
        }
        if output_exceeded.load(Ordering::SeqCst) {
            kill_child_and_descendants(child);
            let _ = child.wait();
            return WaitOutcome::OutputExceeded {
                limit: max_output_bytes,
            };
        }
        if stderr_exceeded.load(Ordering::SeqCst) {
            kill_child_and_descendants(child);
            let _ = child.wait();
            return WaitOutcome::OutputExceeded {
                limit: STDERR_CAPTURE_CAP,
            };
        }
        if start.elapsed() >= wall_limit {
            kill_child_and_descendants(child);
            let _ = child.wait();
            return WaitOutcome::TimedOut;
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// Kills `child` — and, on Linux, every process in its process group, not
/// only the one process `Child::kill()` names (ruling W5-25, finding 2).
/// `run_bounded_subprocess` puts the child in its own new group
/// (`CommandExt::process_group(0)`) precisely so this can reach anything it
/// forked: without it, a descendant survives the direct child being
/// killed, keeps the stdout/stderr pipes' write ends open, and
/// `run_bounded_subprocess`'s `thread::scope` would block forever joining
/// readers that are waiting for an EOF that a still-running orphan never
/// sends — hanging the parent *after* this function believes it has
/// enforced a bound.
///
/// **Residual, recorded rather than chased (explicitly out of scope this
/// round):** a descendant that calls `setsid` itself leaves the group and
/// escapes this kill. Closing that needs a different mechanism (e.g. a
/// PID-namespace or cgroup boundary), not a bigger `killpg` call.
fn kill_child_and_descendants(child: &mut Child) {
    #[cfg(target_os = "linux")]
    {
        crate::probe::kill_process_group(child.id() as i32);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = child.kill();
    }
}

/// Reads `pipe` to EOF, capping the buffered total at `cap` bytes. Sets
/// `exceeded` and stops reading (without erroring) the moment `cap` is
/// passed — [`wait_bounded`] is what turns that into an actual kill; this
/// function's job is only to never buffer past the cap and to never block
/// forever on a pipe nobody upstream is going to close (a killed child's
/// pipe closes with an `Ok(0)` or an `Err`, either of which ends the loop).
fn read_capped(pipe: &mut impl Read, cap: usize, exceeded: &AtomicBool) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > cap {
                    exceeded.store(true, Ordering::SeqCst);
                    break;
                }
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    buf
}

/// Classifies a child that exited **on its own** (never reached when this
/// function killed the child itself — those paths return
/// [`BoundedParseError::Timeout`]/[`BoundedParseError::OutputTooLarge`]
/// before ever inspecting an exit status).
fn classify_exit(
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
) -> Result<Vec<u8>, BoundedParseError> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return Err(BoundedParseError::ResourceExhausted { signal });
        }
    }
    if !status.success() {
        return Err(BoundedParseError::HelperCrashed {
            status: status.to_string(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        });
    }
    Ok(stdout)
}
