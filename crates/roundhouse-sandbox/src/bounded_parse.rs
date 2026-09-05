//! A generic, **synchronous**, resource-bounded subprocess primitive (Task 14,
//! lane W5). Spawns any program, feeds it `stdin`, and returns its `stdout`
//! bytes — or a typed error — once one of three independent bounds is hit:
//! a CPU-time ceiling (Linux only, via [`crate::probe::set_cpu_limit_pre_exec`]),
//! a wall-clock ceiling (every platform), or an output-size ceiling (every
//! platform).
//!
//! **Descendants do not outlive a call to [`run_bounded_subprocess`]**
//! (ruling W5-26, fix round 3, Linux only): on every exit path — the child
//! finishing on its own included, not only a bound firing — this function
//! kills the child's entire process group before returning, so a
//! grandchild the direct child forked and backgrounded (a `git` credential
//! helper or hook, for example) cannot keep running, and cannot keep this
//! call's own stdout/stderr pipes open, past the point this function
//! returns. See `kill_child_and_descendants` and `wait_bounded`'s doc
//! comment for the mechanism and its one accepted residual (a `setsid`
//! escapee, or a vanishingly narrow PID-recycling race on the group-kill
//! itself).
//!
//! **The corollary, stated rather than left to be inferred (ruling W5-28,
//! item 3): output a descendant would have written *after* the direct child
//! exited is discarded, and the call still returns `Ok`.** The group kill
//! on the success path can land mid-write, so a partial result is
//! returnable as success and which bytes make it back is not deterministic
//! for a child that backgrounds work writing to the shared stdout pipe.
//! That is the designed trade (ruling W5-26): bounded, all-or-nothing
//! execution is what this primitive advertises, and waiting on a descendant
//! the direct child chose not to wait for would mean no bound applied at
//! all. A caller that needs a descendant's output must have the direct
//! child wait for it.
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
//! `libc` — and therefore [`crate::probe::set_cpu_limit_pre_exec`] and the
//! process-group kill described above — is a Linux-only dependency of this
//! crate. Off Linux, `CommandExt::process_group(0)` is never set and
//! `kill_child_and_descendants` falls back to a plain `Child::kill()` on
//! the direct child only, so **"descendants do not outlive the call" is a
//! Linux-only guarantee.** `wall_limit` and `max_output_bytes` are still
//! enforced against the direct child's own output and the wall clock in
//! full — a real, smaller bound, never a silent no-op for the direct
//! child — but a child that forks a descendant holding an inherited pipe
//! open can still block `run_bounded_subprocess` past `wall_limit` off
//! Linux, on both the timeout path and the clean-exit path this file's
//! tests exercise. **Any** of the three inherited pipe ends is enough
//! (ruling W5-28, item 4): a descendant holding the **stdin read end**
//! blocks the scoped writer thread exactly as one holding the
//! stdout/stderr write end blocks a scoped reader thread. Same class, same
//! `killpg` closes it on Linux, same gap off it. No caller of this
//! primitive spawns a forking child off Linux today, so this is a real,
//! named gap rather than an exercised one, not a claim that it can't
//! happen.

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
///
/// **This is an internal capture-buffer size, not a bound (ruling W5-28,
/// item 1).** `max_output_bytes` is a limit the *caller* declares and is
/// therefore a caller-visible failure when crossed; this constant is a
/// number this module picked for a diagnostic string. Past it, stderr is
/// **drained and discarded** by `read_stderr_draining` — read so the child
/// can never block on an undrained pipe, thrown away so nothing past the
/// cap is buffered — and crossing it never kills the child and never
/// affects the verdict. A child that does its job, is chatty on a
/// diagnostic stream, and exits 0 succeeds. A *runaway* stderr writer is
/// still bounded, by `wall_limit` and `RLIMIT_CPU`, which is where a
/// runaway belongs.
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

    /// The child's **stdout** exceeded the caller-supplied
    /// `max_output_bytes` cap and it was killed before finishing.
    /// Independent of `wall_limit`/CPU: a child that floods output cheaply
    /// (e.g. `yes`) must not be allowed to run for the full wall-clock
    /// allowance just because it isn't CPU-bound.
    ///
    /// **Stdout only (ruling W5-28, item 1).** A stderr flood is never
    /// reported here: `STDERR_CAPTURE_CAP` is an internal capture-buffer
    /// size, not a bound the caller declared, so stderr past it is drained
    /// and discarded rather than turned into a failure — see that
    /// constant's doc comment.
    #[error("helper process emitted more than {max_output_bytes} output bytes; killed")]
    OutputTooLarge {
        /// The caller-supplied stdout cap that was crossed — the same
        /// `max_output_bytes` that was passed to
        /// [`run_bounded_subprocess`].
        max_output_bytes: usize,
    },

    /// The child exited on its own, without being killed by either bound
    /// above, but with a failure status. `stderr` (truncated to the first
    /// `STDERR_CAPTURE_CAP` bytes the child wrote; anything past that was
    /// drained and discarded) is included for diagnosis.
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
    // `env_clear()` closes it. Directly covered by
    // `tests/bounded_parse.rs`'s
    // `a_child_cannot_see_the_parents_environment`.
    //
    // **What this does to bare program names (ruling W5-28, item 2 — the
    // previous comment here had this backwards).** `std::process::Command`
    // does *not* resolve a bare (slash-free) name against the caller's real
    // `PATH`: std installs the cleared `envp` as the child's `environ`
    // before `execvp`, so `execvp` falls back to glibc's
    // `confstr(_CS_PATH)` default — `/bin:/usr/bin` — and a program that
    // lives anywhere else fails to spawn with `NotFound`. Verified
    // empirically against a program on the caller's `PATH` but outside the
    // default path, with and without a `pre_exec` hook attached (this
    // module's exact configuration). The behaviour is *tighter* than the
    // old comment claimed, so nothing here is broken by it: every child in
    // this module's tests (`sh`, `cat`, `yes`, `sleep`, `head`) happens to
    // live in the default path — which is exactly why "all existing tests
    // still pass" concealed the wrong claim for two rounds.
    //
    // A future caller that genuinely needs `PATH` resolution must pass an
    // explicit `.env("PATH", <allowlist>)` rather than reverting
    // `env_clear()` — losing the whole-environment isolation to locate one
    // binary is not a trade this primitive should make. Task 34 is the live
    // case: `git` is often in `/usr/local/bin`, and its credential helpers
    // and hooks are themselves `PATH`-resolved.
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

    // Ruling W5-26 (fix round 3): captured once, immediately after spawn,
    // rather than re-read via `child.id()` at each kill site below.
    // `Child::id()` is just a stored field (Rust does not re-query the OS
    // for it), so re-reading it later would not itself be wrong — this is
    // about tying every kill call to the pgid this call actually created
    // at spawn time, so the accepted-residual note on `kill_child_and_descendants`
    // below is precisely about *this* value, not about whatever `id()`
    // might return if `Child`'s internals ever changed.
    let pgid = child.id() as i32;
    // Ruling W5-28, item 6: unreachable in practice (`pid_max` is capped at
    // 2^22 on 64-bit Linux, so this cast never goes negative), but the
    // consequence if it ever were is severe enough to make the invariant
    // explicit at the point of capture: `killpg` with a non-positive pgid
    // signals the *caller's own* process group, so the daemon calling this
    // would SIGKILL itself.
    debug_assert!(pgid > 0, "pgid must be a real, positive process-group id");

    let stdin = child.stdin.take();
    let mut stdout = child.stdout.take().expect("stdout was requested as piped");
    let mut stderr = child.stderr.take().expect("stderr was requested as piped");

    let output_exceeded = AtomicBool::new(false);

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
        // Stderr gets the *draining* reader, not `read_capped`: it keeps
        // reading to EOF past `STDERR_CAPTURE_CAP` and throws the excess
        // away, so a chatty child can never block on an undrained pipe and
        // a chatty child also never fails the call (ruling W5-28, item 1).
        let stderr_reader = scope.spawn(|| read_stderr_draining(&mut stderr, STDERR_CAPTURE_CAP));

        let outcome = wait_bounded(&mut child, pgid, wall_limit, &output_exceeded);

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
            "read_stderr_draining's reader thread panicked; see the stdout debug_assert above"
        );
        let stderr_buf = stderr_join.unwrap_or_default();

        (outcome, stdout_buf, stderr_buf)
    });

    match outcome {
        WaitOutcome::TimedOut => Err(BoundedParseError::Timeout { wall_limit }),
        WaitOutcome::OutputExceeded => Err(BoundedParseError::OutputTooLarge { max_output_bytes }),
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
/// carries no cap: stdout's caller-supplied `max_output_bytes` is the only
/// cap that can produce it (ruling W5-28, item 1 removed stderr from the
/// verdict entirely), and the one call site already has that value in
/// scope.
enum WaitOutcome {
    Exited(ExitStatus),
    TimedOut,
    OutputExceeded,
}

/// Polls `child` until it exits on its own, `wall_limit` elapses, or
/// `output_exceeded` is set by the concurrent stdout reader — killing (and
/// reaping, so no zombie is left behind) the child on either of the latter
/// two paths before returning.
///
/// **Stderr takes no part in this loop (ruling W5-28, item 1).** It used to:
/// ruling W5-25, finding 5 added a `stderr_exceeded` arm that killed the
/// child the moment it wrote past `STDERR_CAPTURE_CAP`, reported as
/// `OutputTooLarge`. That fixed a real problem — before it, an over-cap
/// stderr simply stopped being drained, so the child blocked on its own
/// `write` once the pipe filled and sat until `wall_limit` — but it fixed
/// it by promoting an *internal capture-buffer size* to a caller-visible
/// bound, which also made the verdict racy: the `Exited` arm below never
/// re-checked `stderr_exceeded`, so a child that flooded stderr and exited 0
/// promptly returned `Ok` when `try_wait()` won the poll and
/// `Err(OutputTooLarge)` when the flag won. W5-28 removed the failure mode
/// rather than making it deterministic: `read_stderr_draining` keeps reading
/// past the cap and discards the excess, so the child still never blocks on
/// an undrained pipe, and nothing about stderr can kill the child or decide
/// the verdict.
///
/// **Ruling W5-26 (fix round 3) — the `Exited` arm now also tears down the
/// process group, closing what fix round 2's report recorded as residual
/// (f).** Before this fix, the arm returned the instant `try_wait()`
/// reaped the *direct* child, without calling
/// [`kill_child_and_descendants`] first. A child that forks a descendant,
/// hands it the inherited stdout write end, and exits itself before that
/// descendant does (e.g. `sh -c "sleep 30 &"` — no foreground command left,
/// so the shell exits 0 immediately once the background job is launched)
/// left that descendant holding the pipe open with nothing left to close
/// it: `run_bounded_subprocess`'s `thread::scope` blocked forever inside
/// `read_capped`'s `.read()` waiting for an EOF the orphan never sends — an
/// unbounded hang with *no* bound applying at all, reachable with no
/// adversarial behaviour, just an ordinary child that legitimately
/// backgrounds work and returns before that work finishes.
/// `run_bounded_subprocess` is a synchronous, all-or-nothing,
/// resource-bounded execution: a descendant outliving the call already
/// violates the contract this function advertises, so terminating the
/// group on **every** exit path — not only the three paths that already
/// killed on a bound firing — is the correct semantics, not a policy
/// tradeoff. **Descendants do not outlive a call to
/// [`run_bounded_subprocess`].**
///
/// **Accepted residual, documented rather than chased:** `try_wait()`
/// reaps the direct child before this arm issues the group-wide kill, so
/// the `killpg(pgid, ...)` below targets a pgid whose leader is already
/// gone. If that exact PID value were recycled and made the leader of an
/// unrelated new process group in the (microseconds-wide) window between
/// the reap and the `killpg` call, this would signal the wrong group.
/// Against a large PID space this is a vanishingly narrow race, and every
/// supervisor that calls `killpg` after reaping (rather than detecting exit
/// without reaping, e.g. via `waitid(..., WNOWAIT)`) has the identical
/// window — closing it needs a different wait primitive, not a bigger
/// `killpg` call, and is not attempted here.
fn wait_bounded(
    child: &mut Child,
    pgid: i32,
    wall_limit: Duration,
    output_exceeded: &AtomicBool,
) -> WaitOutcome {
    let start = Instant::now();
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            // Ruling W5-26: the direct child exiting on its own is not
            // proof nothing it forked is still running — see this
            // function's doc comment for why the group is torn down here
            // too, and the accepted residual around the reap-then-kill
            // ordering.
            kill_child_and_descendants(child, pgid);
            return WaitOutcome::Exited(status);
        }
        if output_exceeded.load(Ordering::SeqCst) {
            kill_child_and_descendants(child, pgid);
            let _ = child.wait();
            return WaitOutcome::OutputExceeded;
        }
        if start.elapsed() >= wall_limit {
            kill_child_and_descendants(child, pgid);
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
/// Called from every path that ends [`wait_bounded`]'s loop (ruling W5-26,
/// fix round 3 added the `Exited` path to that list — see `wait_bounded`'s
/// doc comment for why a cleanly-exiting direct child is not proof nothing
/// it forked is still running).
///
/// **Residual, recorded rather than chased (explicitly out of scope this
/// round):** a descendant that calls `setsid` itself leaves the group and
/// escapes this kill. Closing that needs a different mechanism (e.g. a
/// PID-namespace or cgroup boundary), not a bigger `killpg` call.
///
/// `pgid` is the value [`run_bounded_subprocess`] captured immediately
/// after spawning `child` (ruling W5-26) — not re-read from `child.id()`
/// here, so every call site is provably using the pgid this call actually
/// created, regardless of whether `child` has since been reaped. See
/// `wait_bounded`'s doc comment for the accepted PID-recycling residual
/// this implies.
fn kill_child_and_descendants(child: &mut Child, pgid: i32) {
    #[cfg(target_os = "linux")]
    {
        // The process group, not `child` itself, is what needs signalling
        // here — `child` stays a parameter only for the non-Linux fallback
        // below, so it is otherwise unused on this path.
        let _ = &child;
        crate::probe::kill_process_group(pgid);
    }
    #[cfg(not(target_os = "linux"))]
    {
        // No process-group support off Linux (ruling W5-3): `pgid` plays
        // no part here, so the direct `Child::kill()` carries the whole
        // load, same as before this round.
        let _ = pgid;
        let _ = child.kill();
    }
}

/// Reads `pipe` (the child's **stdout**) to EOF, capping the buffered total
/// at `cap` bytes. Sets `exceeded` and stops reading (without erroring) the
/// moment `cap` is passed — [`wait_bounded`] is what turns that into an
/// actual kill; this function's job is only to never buffer past the cap and
/// to never block forever on a pipe nobody upstream is going to close (a
/// killed child's pipe closes with an `Ok(0)` or an `Err`, either of which
/// ends the loop).
///
/// Stopping the read is correct *here* precisely because crossing the cap is
/// a bound violation: [`wait_bounded`] kills the child within one
/// `POLL_INTERVAL`, so nothing is left blocked on a pipe that will never be
/// read again. Stderr, which is not a bound and gets no kill, needs the
/// opposite behaviour and uses [`read_stderr_draining`] instead.
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

/// Reads `pipe` (the child's **stderr**) to EOF, buffering only the first
/// `cap` bytes and **discarding everything past them** (ruling W5-28,
/// item 1).
///
/// The two halves of that are both load-bearing. *Reading* to EOF regardless
/// of the cap is what keeps a chatty child from blocking on its own `write`
/// once the stderr pipe fills — the problem ruling W5-25, finding 5
/// identified. *Discarding* rather than killing is what keeps
/// `STDERR_CAPTURE_CAP` an internal buffer size instead of a caller-visible
/// bound: a child that did its job and exited 0 must not fail the call for
/// having been verbose on a diagnostic stream, and a runaway stderr writer
/// is caught by `wall_limit`/`RLIMIT_CPU` like any other runaway.
///
/// The truncation is exact — the returned buffer is never longer than `cap`
/// — so a [`BoundedParseError::HelperCrashed`] message is deterministic in
/// size, and the *first* bytes are the ones kept, which is where a helper's
/// tagged diagnostic line lives.
fn read_stderr_draining(pipe: &mut impl Read, cap: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() < cap {
                    let keep = n.min(cap - buf.len());
                    buf.extend_from_slice(&chunk[..keep]);
                }
                // Anything past `cap` is deliberately dropped on the floor:
                // it was read (so the child never blocks) but not retained.
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
