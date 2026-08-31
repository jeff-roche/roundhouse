// crates/roundhouse-policy/tests/shell_bakeoff.rs
//
// ============================================================================
// FIXED by task-22.5 (see `.superpowers/sdd/2026-08-27-phase2-robustness/
// task-22.5-report.md`): this gate previously, genuinely failed at ~18.8%
// (12/64 `ShouldParse` entries wrongly HardDeny'd), over the 15% threshold.
//
// ROOT CAUSE (confirmed by security review): this codebase's own
// `parameter_expr_is_opaque` function in
// `crates/roundhouse-policy/src/shell/classify.rs` was deliberately
// over-conservative — it blanket-denied any non-plain `${...}` parameter
// expansion form (array indexing, `${var:-default}`-style defaults,
// `${var#prefix}`/`${var%%suffix}` stripping, etc.) regardless of whether the
// expansion's payload actually contained anything dangerous. This was NOT a
// `brush-parser` parsing limitation: brush-parser successfully parses all of
// these into complete, structured AST data; the classifier's own
// post-parse policy simply refused to treat that structured data as safe.
//
// §6.12's literal "switch to `yash-syntax`" remedy (see the assertion
// message below, which still states that rule verbatim because it is
// §6.12's locked text) did NOT apply to this specific failure — switching
// parsers would not have moved this number at all. `yash-syntax` is a
// stricter POSIX parser with fewer bash extensions than `brush-parser`, so
// it would have done *worse* on these constructs, not better.
//
// task-22.5 narrowed `parameter_expr_is_opaque` to an allowlist (gated on
// `indirect: false` AND every payload string being `$`-free — NOT a deny-scan
// for `$(`/backtick, which was separately proven unsafe against real bash)
// and widened `is_expandable_piece`/`expand_piece` in lockstep. Measured
// resulting rate: 10.9% (7/64), comfortably under the 15% gate. The 7
// remaining false-Opaque entries are legitimately, honestly opaque given this
// codebase's current `SessionEnv` model: array-indexed/all-indices parameter
// forms (no array model, and array expansion produces multiple argv words),
// positional parameters (`$1`, no positional context at classify time), and
// one entry with a real `$(true)` command substitution.
//
// The corpus and the 15% threshold must NEVER be weakened to force this test
// to pass.
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

    // Fixed by task-22.5 (see the module-level comment at the top of this file):
    // measured real rate is now 10.9% (7/64), comfortably under the 15% gate.
    // If this assertion goes red again, the "switch to yash-syntax" remedy the
    // message below states (§6.12's locked text) very likely does NOT apply —
    // check `crates/roundhouse-policy/src/shell/classify.rs`'s
    // `parameter_expr_is_allowlisted`/`is_expandable_piece`/`expand_piece` for a
    // regression first, the same way task-22.5's own investigation did. Do not
    // weaken the corpus or the 0.15 threshold to force a pass.
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
