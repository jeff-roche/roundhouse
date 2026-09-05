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
