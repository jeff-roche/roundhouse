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
//! **Task 14 fix round 1 (ruling W5-20) closed the gap this file's own
//! comment used to record here.** `expansion::check_expansion` — the
//! fast-path guard that used to run *before* `parse_via_helper`, in this
//! process — is itself a real `serde_yaml` walk over attacker-controlled
//! input (it builds a real `serde_yaml::Deserializer` and drives
//! `deserialize_any`, paying the same `from_str_radix`/`dec2flt` decode
//! cost per alias expansion that the typed deserialize pays). It now runs
//! *inside* `round-yaml-parse-helper`, alongside the typed deserialize, so
//! both of `src/parse/mod.rs`'s "structural doubling" walks are under the
//! same `RLIMIT_CPU` bound. `an_admitted_but_expensive_alias_document_is_rejected_by_the_out_of_process_bound`
//! below now asserts a tight wall-clock ceiling rather than only a 60s
//! hang-guard, because there is no longer an unbounded in-process cost the
//! assertion has to stay clear of.

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
/// Sized at 230,000 zeros / 10,000 aliases — the orchestrator's original
/// pre-fix measurement payload (see the module doc comment above) —
/// restored by Task 14 fix round 1: both `serde_yaml` walks now run inside
/// the same bounded child, under the same `RLIMIT_CPU`, so there is no
/// longer an unbounded in-process first walk whose cost this test had to
/// stay under. The shape reliably exceeds `helper::HELPER_CPU_LIMIT` (2s)
/// well before either walk completes.
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
    let pathological = hex_zero_run(230_000, 10_000);
    // Sanity: this must actually be *admitted* past every pre-parse guard,
    // not rejected by one of them — otherwise this test would pass for the
    // wrong reason (a cheap rejection, not the out-of-process bound firing
    // on a document guards let through).
    assert!(pathological.len() <= roundhouse_flow::parse::MAX_YAML_BYTES);

    let start = Instant::now();
    let result = parse_workflow(&pathological);
    let elapsed = start.elapsed();

    // Task 14 fix round 1 (ruling W5-20): now a meaningful precision
    // assertion, not just a hang-guard. Before this fix round,
    // `expansion::check_expansion` ran unbounded in this process ahead of
    // the helper, so the whole call's wall-clock time was dominated by an
    // in-process cost this test could not bound — hence the old 60s
    // hang-guard. Now both `serde_yaml` walks run inside the same bounded
    // child, under the same `RLIMIT_CPU`, so the whole `parse_workflow`
    // call should finish in roughly `helper::HELPER_CPU_LIMIT` (2s) plus
    // process-spawn/stdin-write/signal-delivery overhead. **Measured on the
    // implementer's machine, debug build, five consecutive runs:
    // 2.0075-2.0100s** — the 2-second CPU bound is what fires here (not
    // the 5s wall-clock backstop), confirming this payload's cost is
    // genuinely CPU-bound rather than blocked on I/O. 8s leaves generous
    // headroom above the measured figure for a loaded CI box (roughly 4x)
    // while remaining far tighter than the old 60s hang-guard or the
    // 10-11s the orchestrator measured failing against this same payload
    // before this fix round landed.
    assert!(
        elapsed < Duration::from_secs(8),
        "expected the whole call to finish in roughly the CPU bound plus spawn overhead \
         now that no unbounded walk remains in this process, took {elapsed:?}"
    );
    // The real assertion: the out-of-process bound fired specifically —
    // not merely "some error", which would also pass for the wrong reason
    // (e.g. `HelperUnavailable` from a missing binary, an infrastructure
    // failure this test is not about).
    assert!(
        matches!(result, Err(ParseError::ExceededParseResourceBound(_))),
        "expected the out-of-process resource bound to fire, got {result:?}"
    );
}

#[test]
fn a_moderate_fan_out_of_cheap_scalars_is_rejected_by_the_moved_guard_not_the_resource_bound() {
    // Ruling W5-20: "`check_expansion` is NOT redundant with the CPU
    // bound — do not drop it in favour of the bound. A moderate fan-out of
    // cheap scalars can exceed `MAX_EXPANDED_WEIGHT` while staying well
    // under 2 CPU-seconds; only the guard rejects that shape." This test
    // pins exactly that, now that the guard runs inside the bounded child
    // rather than in this process: the failure mode must still be
    // `ExpandsTooLarge`, fired cheaply by the guard doing its own job in
    // its new home — not `ExceededParseResourceBound`, which would mean
    // the guard stopped running (or stopped mattering) and the CPU bound
    // is doing the guard's job for it, which the ruling says it cannot.
    //
    // Same construction as `tests/parse_top_level.rs`'s
    // `a_large_anchored_scalar_aliased_many_times_is_rejected` (one
    // anchored 60,000-byte scalar aliased 40,000 times in a flat
    // sequence, so `serde_yaml`'s own alias-jump guard never fires):
    // measured there at 3.2ms release / 23.3ms debug through the whole
    // `parse_workflow` call, when the check ran in the parent — cheap
    // scalars (a repeated literal byte), a large fan-out, nowhere near the
    // 2-second CPU bound.
    let l = 60_000usize;
    let k = 40_000usize;
    let mut yaml = format!(
        "name: t\nversion: 1\nsecrets: &big [\"{}\"]\npermissions:\n  unattended: {{ escalate: fail }}\nsteps:\n  - id: s\n    b: [",
        "z".repeat(l)
    );
    for i in 0..k {
        if i > 0 {
            yaml.push(',');
        }
        yaml.push_str("*big");
    }
    yaml.push_str("]\n");
    assert!(
        yaml.len() < roundhouse_flow::parse::MAX_YAML_BYTES,
        "payload must stay under the byte cap so this exercises the expansion-weight \
         ceiling, not MAX_YAML_BYTES: {} bytes",
        yaml.len()
    );

    let start = Instant::now();
    let result = parse_workflow(&yaml);
    let elapsed = start.elapsed();

    assert!(
        matches!(result, Err(ParseError::ExpandsTooLarge { .. })),
        "expected the moved expansion-weight guard to fire inside the child as \
         ExpandsTooLarge, got {result:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "the guard's own rejection must land well under the CPU bound it now shares a \
         process with, proving it fires on its own terms rather than being caught by \
         the resource bound instead: took {elapsed:?}"
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
