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
use std::sync::mpsc;
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

/// Ruling W5-28, item 1 — **this test's expectation was deliberately
/// revised.** It was added in fix round 2 for ruling W5-25, finding 5, and
/// asserted that flooding stderr past the (private, 64 KiB) capture cap was
/// reported to the caller as `OutputTooLarge` naming that cap. W5-28 ruled
/// that wrong: `max_output_bytes` is a bound the *caller* declares, while
/// the stderr capture cap is an internal buffer size this module chose, and
/// promoting the latter to a caller-visible failure both conflated the two
/// and left the verdict racy (`wait_bounded`'s `Exited` arm never re-checked
/// the stderr flag, so a prompt-exiting flooder returned `Ok` or
/// `OutputTooLarge` depending on which side won a 5 ms poll).
///
/// The half of finding 5 that was real — the child must never block on an
/// undrained stderr pipe — is what this now pins. 1 MiB is far past the
/// capture cap *plus* one 64 KiB reader chunk *plus* a 64 KiB kernel pipe
/// buffer, so pre-W5-28 (and pre-W5-25) code would have wedged the child on
/// its own `write` until the 10 s wall clock fired, failing both assertions
/// below. Post-W5-28 the excess is read and thrown away, the child runs to
/// completion, exits 0, and the call succeeds with an empty stdout.
#[test]
fn a_stderr_flood_is_drained_and_discarded_rather_than_failing_the_call() {
    let start = Instant::now();
    let result = run_bounded_subprocess(
        Path::new("sh"),
        &[
            OsStr::new("-c"),
            OsStr::new("head -c 1048576 /dev/zero >&2"),
        ],
        &[],
        Duration::from_secs(5),
        Duration::from_secs(10),
        4096,
    );
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "the child must not block on an undrained stderr pipe until the wall-clock \
         ceiling: took {elapsed:?}"
    );
    assert_eq!(
        result.expect(
            "a child that floods a diagnostic stream and exits 0 has done its job — \
             an internal capture-buffer size must not fail the call (ruling W5-28, item 1)"
        ),
        Vec::<u8>::new(),
        "stdout received no bytes, so it must come back empty"
    );
}

/// The other half of ruling W5-28, item 1: dropping the stderr *bound* must
/// not turn into dropping the stderr *cap*. The buffer is still hard-limited
/// — bytes past the capture cap are read (so the child never blocks) and
/// then discarded, never accumulated — so the diagnostic string a caller
/// gets back stays bounded no matter how much the child wrote.
///
/// The child writes 1 MiB of NUL bytes to stderr and then exits 3, which is
/// the only path that surfaces stderr to the caller at all
/// (`HelperCrashed`). NUL is single-byte in UTF-8, so `from_utf8_lossy`
/// preserves the byte count exactly and the length assertion below is a
/// direct read of how much was retained.
#[test]
fn stderr_is_still_truncated_to_the_capture_cap_in_the_crash_message() {
    let result = run_bounded_subprocess(
        Path::new("sh"),
        &[
            OsStr::new("-c"),
            OsStr::new("head -c 1048576 /dev/zero >&2; exit 3"),
        ],
        &[],
        Duration::from_secs(5),
        Duration::from_secs(10),
        4096,
    );
    match result {
        Err(BoundedParseError::HelperCrashed { stderr, .. }) => {
            assert!(
                !stderr.is_empty(),
                "the first bytes the child wrote must still be captured for diagnosis"
            );
            assert!(
                stderr.len() <= 64 * 1024,
                "stderr must be truncated to the capture cap, not buffered in full: \
                 kept {} of the 1 MiB the child wrote",
                stderr.len()
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

/// Ruling W5-26 (fix round 3) — residual (f), escalated in fix round 2's
/// report and ruled a real defect in scope to fix, not a policy tradeoff to
/// leave documented. `wait_bounded`'s `Exited` arm used to return the
/// instant `try_wait()` reaped the *direct* child, without killing the
/// process group first. `sh -c "sleep 30 &"` backgrounds a descendant that
/// inherits the stdout pipe's write end, then the shell itself exits 0
/// immediately (there is no foreground command left to run) — leaving that
/// descendant holding the pipe open with nothing left to close it.
/// Pre-fix, `read_capped`'s reader thread never sees EOF and
/// `run_bounded_subprocess` never returns at all: an unbounded hang with no
/// bound applying, in a function whose whole contract is "returns within
/// `wall_limit`".
///
/// This runs the call on its own thread and enforces a **hard, test-level
/// timeout** via `mpsc::Receiver::recv_timeout`, deliberately independent
/// of `run_bounded_subprocess`'s own `wall_limit` (3s here) — the defect
/// under test is exactly "the internal bound never fires", so relying on
/// that same bound to end this test would prove nothing. A regression here
/// fails this test at the 10s hard timeout instead of wedging the whole
/// suite (and CI) indefinitely; the leaked, still-hung background thread is
/// reaped when the test binary process exits.
#[test]
fn a_backgrounded_descendant_does_not_outlive_the_call_even_when_the_direct_child_exits_cleanly() {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result = run_bounded_subprocess(
            Path::new("sh"),
            &[OsStr::new("-c"), OsStr::new("sleep 30 &")],
            &[],
            Duration::from_secs(5),
            Duration::from_secs(3),
            4096,
        );
        // If the hard timeout below already fired, the receiver is gone —
        // ignore the send failure rather than panicking on this thread.
        let _ = tx.send(result);
    });

    let result = rx.recv_timeout(Duration::from_secs(10)).expect(
        "run_bounded_subprocess must return well within 10s even when the direct child \
         exits cleanly while a backgrounded descendant still holds the stdout pipe open \
         — a hang here means residual (f) / ruling W5-26 regressed",
    );
    assert_eq!(
        result.expect(
            "a cleanly-exiting child with a backgrounded descendant must still \
             succeed, once the whole group is properly torn down"
        ),
        Vec::<u8>::new(),
        "the shell itself never writes to stdout; stdout must be empty, not a hang"
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

/// Ruling W5-28, item 8 — a **direct** test for `env_clear()`. Until now its
/// only coverage was "every existing test still passes", which item 2 of the
/// same ruling demonstrated is not coverage at all: those tests pass for a
/// reason unrelated to the environment (their children all live in the
/// default system path), and they passed identically while the comment
/// explaining `env_clear()` was factually wrong.
///
/// What this closes is a credential-disclosure vector — the module doc names
/// `ANTHROPIC_API_KEY` as exactly the kind of thing living in the daemon's
/// environment — and the regression it catches is mundane: someone
/// reordering `env_clear()` after `spawn()`, or dropping it while chasing a
/// `NotFound` from the tighter `PATH` behaviour item 2 documents. Either
/// would go completely undetected today.
///
/// The parent's own read of the variable is asserted first so the test
/// cannot pass vacuously by never having set it. Nothing here races other
/// tests in this binary: every spawn in this file goes through
/// `env_clear()`, so no other test can observe the parent's environment
/// either way.
#[test]
fn a_child_cannot_see_the_parents_environment() {
    const NAME: &str = "ROUNDHOUSE_SANDBOX_ENV_CLEAR_PROBE";

    std::env::set_var(NAME, "a-secret-the-child-must-never-see");
    assert_eq!(
        std::env::var(NAME).as_deref(),
        Ok("a-secret-the-child-must-never-see"),
        "the parent must actually hold this variable, or the assertion below \
         would pass without proving anything"
    );

    let result = run_bounded_subprocess(
        Path::new("sh"),
        &[
            OsStr::new("-c"),
            OsStr::new("printf %s \"${ROUNDHOUSE_SANDBOX_ENV_CLEAR_PROBE:-<unset>}\""),
        ],
        &[],
        CPU_LIMIT,
        WALL_LIMIT,
        MAX_OUTPUT,
    );

    assert_eq!(
        result.expect("the probe child must run and exit cleanly"),
        b"<unset>".to_vec(),
        "the child inherited the parent's environment — `env_clear()` is not being \
         applied, and any secret in the daemon's environment is exposed to every \
         child this primitive spawns"
    );
}
