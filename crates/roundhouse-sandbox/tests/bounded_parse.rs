//! Tests for the generic, synchronous, resource-bounded subprocess primitive
//! (Task 14, ruling W5-5). This is deliberately the *generic* test: every
//! child here is an ordinary shell/coreutils program with no idea it is
//! "parsing" anything, because `run_bounded_subprocess` itself doesn't know
//! what YAML is — it bounds CPU, wall-clock and output size for any child,
//! full stop. The YAML-specific DoS/regression tests live in
//! `crates/roundhouse-flow/tests/` instead, because that's where
//! `CARGO_BIN_EXE_round-yaml-parse-helper` actually resolves (ruling W5-5 —
//! `CARGO_BIN_EXE_*` is only set for bins in the *same package* as the test
//! binary, and the helper lives in `roundhouse-flow`, not here).

use std::ffi::OsStr;
use std::path::Path;
use std::time::{Duration, Instant};

use roundhouse_sandbox::bounded_parse::{run_bounded_subprocess, BoundedParseError};

const CPU_LIMIT: Duration = Duration::from_secs(1);
const WALL_LIMIT: Duration = Duration::from_secs(3);
const MAX_OUTPUT: usize = 4096;

/// The well-behaved case: proves the bound doesn't reject or mangle
/// ordinary work. `cat` reads stdin and writes it back byte-for-byte.
#[test]
fn a_well_behaved_child_echoes_its_input_and_returns_ok() {
    let input = b"hello, bounded subprocess\n".to_vec();
    let result = run_bounded_subprocess(
        Path::new("cat"),
        &[],
        &input,
        CPU_LIMIT,
        WALL_LIMIT,
        MAX_OUTPUT,
    );
    assert_eq!(
        result.expect("a well-behaved echo must succeed"),
        input,
        "stdout must match stdin exactly"
    );
}

/// The classic stdin/stdout pipe deadlock: `cat` will not produce any
/// output until it has read *all* of stdin (well, it interleaves, but a
/// naive implementation that writes all of stdin from the calling thread
/// before ever reading stdout will deadlock once both the stdin write and
/// the stdout read exceed one pipe buffer's capacity, typically 64 KiB on
/// Linux). 4 MiB safely exceeds that in both directions.
#[test]
fn a_large_round_trip_does_not_deadlock_on_the_stdin_stdout_pipe() {
    let input = vec![b'x'; 4 * 1024 * 1024];
    let result = run_bounded_subprocess(
        Path::new("cat"),
        &[],
        &input,
        Duration::from_secs(5),
        Duration::from_secs(15),
        8 * 1024 * 1024,
    );
    assert_eq!(
        result.expect("a large round-trip through `cat` must not deadlock"),
        input
    );
}

/// A CPU burner: on Linux, `RLIMIT_CPU` (set via `probe::set_cpu_limit_pre_exec`)
/// fires well before the wall-clock backstop, so this should report
/// `ResourceExhausted`. Off Linux, `cpu_limit` is not enforced (ruling
/// W5-3 — "a real bound, not a skip"), so only the wall-clock kill applies
/// and `Timeout` is the expected outcome instead.
#[test]
fn a_cpu_burning_child_is_killed_well_before_the_wall_clock_ceiling() {
    let start = Instant::now();
    let result = run_bounded_subprocess(
        Path::new("sh"),
        &[OsStr::new("-c"), OsStr::new("while :; do :; done")],
        &[],
        Duration::from_secs(1),
        Duration::from_secs(6),
        MAX_OUTPUT,
    );
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(6),
        "must not run to the wall-clock ceiling: took {elapsed:?}"
    );
    assert!(
        matches!(
            result,
            Err(BoundedParseError::ResourceExhausted { .. })
                | Err(BoundedParseError::Timeout { .. })
        ),
        "unexpected result: {result:?}"
    );
}

/// A sleeper never burns CPU, so `RLIMIT_CPU` never fires — only the
/// external wall-clock kill can stop it. Proves the call returns *well*
/// before the child's own `sleep 30` would finish on its own.
#[test]
fn a_sleeping_child_is_killed_at_the_wall_clock_bound_not_left_running() {
    let start = Instant::now();
    let result = run_bounded_subprocess(
        Path::new("sleep"),
        &[OsStr::new("30")],
        &[],
        Duration::from_secs(1),
        Duration::from_secs(1),
        MAX_OUTPUT,
    );
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "must be killed well before `sleep 30` finishes on its own: took {elapsed:?}"
    );
    assert!(
        matches!(result, Err(BoundedParseError::Timeout { .. })),
        "unexpected result: {result:?}"
    );
}

/// An output flood: `yes` writes forever. Proves `max_output_bytes` is a
/// real, independently-enforced cap — this child neither burns CPU nor
/// runs past the wall clock; only the output cap can stop it, and it must
/// do so promptly rather than waiting for the wall-clock ceiling.
#[test]
fn a_flooding_child_is_killed_once_output_exceeds_the_cap() {
    let start = Instant::now();
    let result = run_bounded_subprocess(
        Path::new("yes"),
        &[],
        &[],
        Duration::from_secs(5),
        Duration::from_secs(10),
        4096,
    );
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "must be killed promptly once the output cap is hit, not at the wall-clock ceiling: took {elapsed:?}"
    );
    assert!(
        matches!(result, Err(BoundedParseError::OutputTooLarge { .. })),
        "unexpected result: {result:?}"
    );
}

/// Ruling W5-25, finding 5 — before this fix, `stderr_exceeded` was set by
/// the stderr reader thread and never consulted anywhere, so a child that
/// flooded stderr past the (private, 64 KiB) capture cap simply blocked on
/// its own `write` once the pipe filled and sat until `wall_limit`, rather
/// than getting the same prompt kill a stdout flood already got. Fail-
/// closed either way, so this proves promptness, not a bypass: `yes 1>&2`
/// floods stderr forever while stdout stays empty, so only the newly
/// consulted flag can be what ends this call before the 10 s wall clock.
#[test]
fn a_child_that_floods_stderr_is_also_killed_promptly_not_at_the_wall_clock_ceiling() {
    let start = Instant::now();
    let result = run_bounded_subprocess(
        Path::new("sh"),
        &[OsStr::new("-c"), OsStr::new("yes 1>&2")],
        &[],
        Duration::from_secs(5),
        Duration::from_secs(10),
        4096,
    );
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "must be killed promptly once the stderr capture cap is hit, not at the \
         wall-clock ceiling: took {elapsed:?}"
    );
    match result {
        Err(BoundedParseError::OutputTooLarge { max_output_bytes }) => {
            assert_ne!(
                max_output_bytes, 4096,
                "the reported cap must be the stderr capture cap, not the unrelated \
                 stdout cap this call passed in — stdout never received any bytes"
            );
        }
        other => panic!("unexpected result: {other:?}"),
    }
}

/// Ruling W5-25, finding 1 — the security lens's fail-open finding,
/// verified here rather than taken on trust (the lens was read-only and
/// built no test). `wait_bounded`'s poll loop checks `try_wait()` before
/// `output_exceeded`, and the `Exited` arm hands straight to
/// `classify_exit`, which never consults the flag at all: a child that
/// overshoots `max_output_bytes` by less than one pipe buffer (~64 KiB on
/// Linux) can have its whole write already sitting in the kernel pipe
/// buffer, exit with status 0, and be reaped by `try_wait()` before the
/// flag is ever checked on the success path — returning `Ok` with a
/// buffer that exceeds the declared cap. `head -c 4096 /dev/zero` writes
/// one 4096-byte payload (comfortably under a 64 KiB pipe, so the write
/// never blocks) against a 100-byte cap, then exits immediately: the exact
/// "small overshoot, prompt exit" shape the finding names.
#[test]
fn a_small_output_overshoot_with_a_prompt_exit_is_still_rejected() {
    let start = Instant::now();
    let result = run_bounded_subprocess(
        Path::new("sh"),
        &[OsStr::new("-c"), OsStr::new("head -c 4096 /dev/zero")],
        &[],
        Duration::from_secs(5),
        Duration::from_secs(10),
        100,
    );
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "a prompt-exiting child must not need the wall-clock ceiling to be rejected: took {elapsed:?}"
    );
    assert!(
        matches!(result, Err(BoundedParseError::OutputTooLarge { .. })),
        "a small overshoot from a child that exits promptly must still be rejected as \
         OutputTooLarge, never silently accepted with a buffer over the declared cap — \
         got {result:?}"
    );
}

/// Ruling W5-25, finding 2 — process-group kill. `sh` forks a background
/// `sleep 30`, then execs a foreground `sleep 30` of its own; both share
/// `sh`'s process group. `wall_limit` (1s) fires long before either sleep
/// would exit on its own, so this proves `kill_child_and_descendants`
/// actually reaches the *backgrounded* sibling, not just the process
/// `Child::kill()` would name: pre-fix, killing only the foreground `sh`
/// leaves the background `sleep 30` holding the inherited stdout pipe's
/// write end open, so `read_capped`'s reader thread never sees EOF and
/// `thread::scope` blocks for the remainder of that sleep — this test's own
/// 5s ceiling would be blown by roughly the width of the background sleep's
/// remaining lifetime. Post-fix, `killpg` closes both write ends at once,
/// the reader hits EOF immediately, and the call returns at the wall-clock
/// ceiling.
#[test]
fn a_backgrounded_sibling_process_is_also_killed_not_left_holding_the_pipe_open() {
    let start = Instant::now();
    let result = run_bounded_subprocess(
        Path::new("sh"),
        &[OsStr::new("-c"), OsStr::new("sleep 30 & sleep 30")],
        &[],
        Duration::from_secs(5),
        Duration::from_secs(1),
        4096,
    );
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "a backgrounded sibling must not be left holding the stdout pipe open past \
         the wall-clock ceiling: took {elapsed:?}"
    );
    assert!(
        matches!(result, Err(BoundedParseError::Timeout { .. })),
        "unexpected result: {result:?}"
    );
}

/// A program that doesn't exist must be a clean, typed error — never a
/// panic, and never silently treated as any of the resource-bound variants.
#[test]
fn a_nonexistent_program_returns_a_clean_spawn_error_not_a_panic() {
    let result = run_bounded_subprocess(
        Path::new("round-sandbox-test-definitely-does-not-exist-xyz"),
        &[],
        &[],
        CPU_LIMIT,
        WALL_LIMIT,
        MAX_OUTPUT,
    );
    assert!(
        matches!(result, Err(BoundedParseError::Spawn { .. })),
        "unexpected result: {result:?}"
    );
}
