//! Task 14 (lane W5): `parse_workflow` now routes the actual typed
//! `serde_yaml::from_slice::<WorkflowDef>` deserialization through
//! `round-yaml-parse-helper`, spawned under
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
//! best-effort, still capable of over-rejecting.
//!
//! **A second, narrower scope gap found while writing this test, not
//! authorized by the brief to fix here (see the task report):**
//! `expansion::check_expansion` — the fast-path guard that runs *before*
//! `parse_via_helper` — constructs a real `serde_yaml::Deserializer` and
//! walks it via `deserialize_any`, so for a numeric scalar it incurs
//! `serde_yaml`'s real `from_str_radix`/`dec2flt` decode (the same
//! O(token-length) cost the typed deserialize pays), once per alias
//! expansion, **in process**, before `parse_via_helper` is ever called.
//! `src/parse/mod.rs`'s own "structural doubling" paragraph already says an
//! admitted document costs "roughly twice its metered walk" — this task
//! moves only the *second* walk (the typed deserialize) out of process.
//! The *first* walk's identical per-decode cost is untouched and remains
//! exactly as unbounded as before Task 14. This test's payload is sized so
//! that walk still finishes in a few seconds rather than dozens, but the
//! test does not (and cannot, without changing `expansion.rs`, which
//! ruling W5-6 did not authorize) prove that first walk is bounded — only
//! that the second one now is.

use roundhouse_flow::parse::parse_workflow;
use roundhouse_flow::parse::ParseError;
use std::time::{Duration, Instant};

/// Same generator as `tests/parse_top_level.rs`'s `hex_zero_run`
/// (duplicated rather than shared — these are separate test binaries): one
/// anchored `0x<zeros>1` integer scalar aliased `k` times in a flat flow
/// sequence. This is `roundhouse-flow`'s own documented "accepted residual"
/// shape (`src/parse/mod.rs`'s axis inventory, integer-decode row, ruling
/// P63): it is deliberately tuned to pass `MAX_YAML_BYTES`,
/// `nesting_depth_bound_violation` and `expansion::check_expansion`
/// (`MAX_EXPANDED_WEIGHT`/`MAX_INTEGER_SCALAR_VISITS`) — i.e. it is
/// **admitted**, not rejected, by every guard that ran before Task 14.
///
/// Sized at 150,000 zeros / 6,000 aliases rather than the 262,143-byte,
/// 43,673-alias maximiser the axis inventory measures at 9,435.7 ms
/// (release) / tens of seconds (debug): this shape's *typed-deserialize*
/// half alone reliably exceeds `helper::HELPER_CPU_LIMIT` (2s) with a
/// comfortable margin, while keeping the *first* (in-process,
/// `expansion::check_expansion`) walk's identical decode cost — see the
/// module doc comment above — down to single-digit seconds rather than
/// dozens, so this test stays fast without changing what it proves.
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
fn an_admitted_but_expensive_alias_document_is_rejected_by_the_out_of_process_bound() {
    let pathological = hex_zero_run(150_000, 6_000);
    // Sanity: this must actually be *admitted* past every pre-parse guard,
    // not rejected by one of them — otherwise this test would pass for the
    // wrong reason (a cheap rejection, not the out-of-process bound firing
    // on a document guards let through).
    assert!(pathological.len() <= roundhouse_flow::parse::MAX_YAML_BYTES);

    let start = Instant::now();
    let result = parse_workflow(&pathological);
    let elapsed = start.elapsed();

    // A generous sanity ceiling, not a precision timing assertion: the
    // *first* (in-process) walk's cost is untouched by this task (see the
    // module doc comment) and is not itself bounded by anything this test
    // can assert on, so this only guards against a genuine hang — it is
    // not proof the whole call is fast, only that it terminates.
    assert!(
        elapsed < Duration::from_secs(60),
        "must terminate, not hang: took {elapsed:?}"
    );
    // The real assertion: the *typed-deserialize* half was killed by the
    // out-of-process bound specifically — not merely "some error", which
    // would also pass for the wrong reason (e.g. `HelperUnavailable` from
    // a missing binary, an infrastructure failure this test is not about).
    assert!(
        matches!(result, Err(ParseError::ExceededParseResourceBound(_))),
        "expected the out-of-process resource bound to fire, got {result:?}"
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
