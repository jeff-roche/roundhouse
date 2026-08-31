// crates/roundhouse-policy/tests/shell_bakeoff.rs
//
// ============================================================================
// KNOWN RED: `brush_parser_false_opaque_rate_is_within_the_15_percent_gate`
// below is CURRENTLY, GENUINELY, KNOWINGLY FAILING as of this file's authorship
// (commit d05b292 and this follow-up). This is a tracked, decision-pending
// state per §6.12 — not an accidental regression, not flaky, and not a bug in
// this test file or the corpus. Measured real rate: ~18.8% (12/64 `ShouldParse`
// entries wrongly HardDeny'd), over the 15% threshold.
//
// ROOT CAUSE (confirmed by security review): this codebase's own
// `parameter_expr_is_opaque` function in
// `crates/roundhouse-policy/src/shell/classify.rs` is deliberately
// over-conservative — it blanket-denies any non-plain `${...}` parameter
// expansion form (array indexing, `${var:-default}`-style defaults,
// `${var#prefix}`/`${var%%suffix}` stripping, etc.) regardless of whether the
// expansion's payload actually contains anything dangerous. This is NOT a
// `brush-parser` parsing limitation: brush-parser successfully parses all of
// these into complete, structured AST data; the classifier's own
// post-parse policy just refuses to treat that structured data as safe.
//
// Consequently, §6.12's literal "switch to `yash-syntax`" remedy (see the
// assertion message below, which still states that rule verbatim because it
// is §6.12's locked text) does NOT apply to this specific failure and must
// NOT be triggered off of this gate's current result — switching parsers
// would not move this number at all. `yash-syntax` is a stricter POSIX
// parser with fewer bash extensions than `brush-parser`, so it would do
// *worse* on these constructs, not better.
//
// The real fix — narrowing the classifier's over-conservative
// parameter-expansion handling, which must be done carefully since a naive
// "just scan the payload for `$(`/backtick" approach was already proven
// unsafe by security review — is being tracked separately as "the
// shell-classifier parameter-expansion follow-up" (no permanent task number
// yet in the plan document).
//
// The corpus and the 15% threshold must NEVER be weakened to force this test
// to pass. If you are reading this because the test is red: that is
// expected and correct right now. The fix is narrowing the classifier, not
// adjusting the gate.
// ============================================================================
mod fixtures {
    pub mod shell_bakeoff_corpus;
}
use fixtures::shell_bakeoff_corpus::{Expectation, BAKEOFF_CORPUS};
use roundhouse_policy::shell::classify::{parse_command, Classification, SessionEnv};
use roundhouse_policy::shell::opaque::{classify_shell, find_opaque_nodes, ShellClassification};

/// §6.12's locked decision rule, made an executable gate: run every corpus entry
/// through the REAL `brush-parser`-backed classifier (Task 11) via its real production
/// entry point, `classify_shell` — the full pipeline (size/structural guard → parse →
/// opaque-detection → variable resolution) a live task would actually go through — and
/// compute the false-Opaque rate over exactly the entries that should have parsed
/// cleanly. GenuinelyOpaque entries are excluded from the rate on purpose — Opaque is
/// the *correct* answer for those, so counting them would understate the real rate.
#[test]
fn brush_parser_false_opaque_rate_is_within_the_15_percent_gate() {
    let should_parse: Vec<_> = BAKEOFF_CORPUS
        .iter()
        .filter(|e| matches!(e.expectation, Expectation::ShouldParse))
        .collect();
    assert!(
        should_parse.len() >= 40,
        "corpus must have a meaningful ShouldParse sample, not a token handful"
    );

    let env = SessionEnv::default();
    let false_opaque_count = should_parse
        .iter()
        .filter(|e| {
            matches!(
                classify_shell(e.command, &env),
                ShellClassification::HardDeny(_)
            )
        })
        .count();

    let rate = false_opaque_count as f64 / should_parse.len() as f64;

    // KNOWN RED (see the module-level comment at the top of this file for full
    // detail): this assertion is currently, genuinely failing at ~18.8% (12/64).
    // Root cause is this crate's own over-conservative `parameter_expr_is_opaque`
    // in `shell/classify.rs`, NOT a `brush-parser` gap — the "switch to
    // yash-syntax" remedy the message below states (§6.12's locked text) does
    // NOT apply to this failure and must not be triggered off of it. Do not
    // weaken the corpus or the 0.15 threshold to force a pass; the real fix is
    // the tracked shell-classifier parameter-expansion follow-up.
    assert!(
        rate <= 0.15,
        "brush-parser's false-Opaque rate against this corpus is {:.1}% (over the 15% \
         gate §6.12 locks in) — {false_opaque_count}/{} entries that should have parsed \
         cleanly were classified Opaque. Per the decision rule already recorded in \
         03-security-and-sandboxing.md §6.12/§6.3: SWITCH THE DEFAULT SHELL PARSER FROM \
         `brush-parser` TO `yash-syntax` and accept its bash-extension gaps as Opaque by \
         design, rather than patching a POSIX parser to understand bash. Do not silently \
         patch around individual failures in this corpus — re-run this gate after the \
         parser swap to confirm it clears 15%.",
        rate * 100.0,
        should_parse.len(),
    );
}

/// A sanity companion to the gate above: every GenuinelyOpaque entry must still actually
/// classify Opaque, for the right reason — otherwise the corpus itself would be lying
/// about what's genuinely opaque and the false-Opaque rate above would be meaningless.
///
/// `classify_shell`'s `HardDeny` collapses all six opaque reasons into one generic code,
/// so the granular reason has to come from `find_opaque_nodes` run directly on the
/// parsed AST (via the lower-level `parse_command`), not from `classify_shell` itself.
#[test]
fn genuinely_opaque_corpus_entries_classify_opaque_for_the_stated_reason() {
    for entry in BAKEOFF_CORPUS {
        if let Expectation::GenuinelyOpaque(expected_reason) = entry.expectation {
            let Classification::Program(parsed) = parse_command(entry.command) else {
                panic!(
                    "corpus entry {:?} failed to parse at all — the corpus annotation is wrong \
                     (a GenuinelyOpaque entry must be syntactically valid shell that's opaque \
                     for a semantic reason, not a parse failure)",
                    entry.command
                );
            };
            let nodes = find_opaque_nodes(&parsed.program_ast);
            assert!(
                nodes.iter().any(|n| n.reason == expected_reason),
                "corpus entry {:?} was marked GenuinelyOpaque({:?}) but find_opaque_nodes found no \
                 matching node (found reasons: {:?})",
                entry.command,
                expected_reason,
                nodes.iter().map(|n| n.reason).collect::<Vec<_>>(),
            );
        }
    }
}
