//! Task 14 (lane W5): `parse_workflow` now routes the actual `serde_yaml`
//! deserialization through `round-yaml-parse-helper`, spawned under
//! `roundhouse_sandbox::bounded_parse::run_bounded_subprocess`. This is the
//! YAML-specific half of the test split ruling W5-5 calls for — the
//! generic primitive's own tests live in
//! `crates/roundhouse-sandbox/tests/bounded_parse.rs`, because
//! `CARGO_BIN_EXE_round-yaml-parse-helper` (used indirectly here, via
//! `parse_workflow` itself resolving the sibling binary at
//! `parse::helper`'s test-util fallback) is only set for a test binary in
//! the same package as the `[[bin]]` it names — `roundhouse-sandbox` has no
//! access to it at all.
//!
//! Scope note (ruling W5-6): this task does **not** close Phase 5's parked
//! over-rejection regression (the bracket/comment false positive in
//! `nesting_depth_bound_violation`) — that guard is untouched, still
//! best-effort, still capable of over-rejecting. What this task closes is
//! the *cost* side: a document that gets past all three in-process guards
//! and would previously have run `serde_yaml::from_str` in-process with no
//! further bound.

use roundhouse_flow::parse::parse_workflow;
use std::time::{Duration, Instant};

/// Same generator as `tests/parse_top_level.rs`'s `hex_zero_run`
/// (duplicated rather than shared — these are separate test binaries): one
/// anchored `0x<zeros>1` integer scalar aliased `k` times in a flat flow
/// sequence. This is `roundhouse-flow`'s own documented "accepted residual"
/// shape (`src/parse/mod.rs`'s axis inventory, integer-decode row, ruling
/// P63): it is deliberately tuned to pass `MAX_YAML_BYTES`,
/// `nesting_depth_bound_violation` and `expansion::check_expansion`
/// (`MAX_EXPANDED_WEIGHT`/`MAX_INTEGER_SCALAR_VISITS`) — i.e. it is
/// **admitted**, not rejected, by every guard that ran before Task 14 — and
/// still costs multiple real seconds inside `serde_yaml`'s
/// `from_str_radix` re-scan on every alias expansion, because those guards
/// charge a flat per-visit weight that does not scale with the token's
/// length. That is exactly the residual this task's out-of-process bound
/// closes: measured against the pre-Task-14 code path (see the report for
/// the exact RED timing), this shape took multiple seconds in-process with
/// nothing left to stop it.
fn hex_zero_run(zeros: usize, k: usize) -> String {
    let mut y = String::with_capacity(zeros + 3 * k + 256);
    y.push_str(
        "name: t\nversion: 1\npermissions:\n  unattended: { escalate: fail }\nsteps:\n  - id: s\n",
    );
    y.push_str("    f: &f 0x");
    for _ in 0..zeros {
        y.push('0');
    }
    y.push_str("1\n    b: [");
    for i in 0..k {
        if i > 0 {
            y.push(',');
        }
        y.push_str("*f");
    }
    y.push_str("]\n");
    y
}

#[test]
fn an_admitted_but_expensive_alias_document_is_killed_within_a_few_seconds_not_left_running() {
    let pathological = hex_zero_run(230_000, 10_000);
    // Sanity: this must actually be *admitted* past every pre-parse guard,
    // not rejected by one of them — otherwise this test would pass for the
    // wrong reason (a cheap rejection, not the out-of-process bound firing
    // on a document guards let through).
    assert!(pathological.len() <= roundhouse_flow::parse::MAX_YAML_BYTES);

    let start = Instant::now();
    let result = parse_workflow(&pathological);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(10),
        "must be killed well within the out-of-process bound, not left running \
         in-process for the multiple seconds this shape costs unbounded: took {elapsed:?}"
    );
    assert!(
        result.is_err(),
        "an admitted-but-pathologically-expensive document must be rejected once \
         it exceeds the out-of-process resource bound, not silently succeed slowly"
    );
}

#[test]
fn the_frozen_reference_fixture_still_parses_successfully_through_the_out_of_process_path() {
    let normal = include_str!("fixtures/pr_review.yaml");
    let start = Instant::now();
    let result = parse_workflow(normal);
    let elapsed = start.elapsed();

    assert!(
        result.is_ok(),
        "the out-of-process bound must not be so tight it rejects the project's own \
         reference fixture: {:?}",
        result.err()
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "an ordinary small workflow must not pay anywhere near the resource \
         ceiling just to round-trip through the helper: took {elapsed:?}"
    );
}
