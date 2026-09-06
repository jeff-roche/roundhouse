use roundhouse_policy::engine::{CompiledRule, Outcome, PolicyEngine, Predicate, Scope};
use roundhouse_policy::trust::{apply_project_scope_trust, record_explicit_trust, TrustStore};
use roundhouse_policy::{ParsedCommand, TaskParams};
use std::path::PathBuf;
use tempfile::TempDir;

fn allow_rule(program: &str) -> CompiledRule {
    CompiledRule::test_new(Scope::Project, Outcome::Allow, Predicate::program(program))
}
fn deny_rule(program: &str) -> CompiledRule {
    CompiledRule::test_new(Scope::Project, Outcome::Deny, Predicate::program(program))
}

fn force_push_predicate() -> Predicate {
    Predicate::argv_prefix("git", &["push", "--force"])
}

fn force_push_params() -> TaskParams {
    TaskParams::Shell(ParsedCommand {
        program: "git".to_string(),
        argv: vec!["push".to_string(), "--force".to_string()],
    })
}

#[test]
fn first_use_with_no_trust_record_drops_project_scope_allow_rules() {
    let state_dir = TempDir::new().unwrap();
    let store = TrustStore::new(state_dir.path().to_path_buf());
    let repo_root = PathBuf::from("/repos/example");
    let policy_text = "allow cargo test";

    let effective = apply_project_scope_trust(
        &repo_root,
        policy_text,
        vec![allow_rule("cargo"), deny_rule("rm")],
        &store,
    );

    assert!(
        !effective.iter().any(|r| r.outcome() == Outcome::Allow),
        "first use is narrow-by-default: no Allow rule applies until a human trusts this exact file"
    );
    assert!(
        effective.iter().any(|r| r.outcome() == Outcome::Deny),
        "Deny rules are never gated — narrowing is always safe"
    );
}

#[test]
fn widening_the_policy_file_without_a_trust_update_is_refused() {
    let state_dir = TempDir::new().unwrap();
    let store = TrustStore::new(state_dir.path().to_path_buf());
    let repo_root = PathBuf::from("/repos/example");

    // Establish an initial trusted baseline with `git` allowed.
    let baseline_text = "allow git status";
    let baseline_rules = vec![allow_rule("git")];
    record_explicit_trust(&repo_root, baseline_text, &baseline_rules, &store).unwrap();

    // The agent (who can write this file) adds a new, broader Allow rule.
    let widened_text = "allow git status\nallow curl";
    let widened_rules = vec![allow_rule("git"), allow_rule("curl")];
    let effective = apply_project_scope_trust(&repo_root, widened_text, widened_rules, &store);

    let allowed_programs: Vec<_> = effective
        .iter()
        .filter(|r| r.outcome() == Outcome::Allow)
        .filter_map(|r| match r.predicate() {
            Predicate::Shell { program, .. } => Some(program.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        allowed_programs,
        vec!["git".to_string()],
        "the new `curl` Allow rule must be refused — it widens beyond the last-trusted version, with no human trust update recorded"
    );
}

#[test]
fn narrowing_the_policy_file_is_accepted_automatically_no_human_needed() {
    let state_dir = TempDir::new().unwrap();
    let store = TrustStore::new(state_dir.path().to_path_buf());
    let repo_root = PathBuf::from("/repos/example");

    let baseline_text = "allow git status\nallow curl";
    record_explicit_trust(
        &repo_root,
        baseline_text,
        &[allow_rule("git"), allow_rule("curl")],
        &store,
    )
    .unwrap();

    // The agent (or a human) removes the `curl` rule — this only narrows, so it applies
    // immediately with no separate trust step, and becomes the new trusted baseline.
    let narrowed_text = "allow git status";
    let effective =
        apply_project_scope_trust(&repo_root, narrowed_text, vec![allow_rule("git")], &store);
    assert_eq!(
        effective.len(),
        1,
        "a purely-narrowing change applies without requiring a trust update"
    );

    let record = store.load(&repo_root).unwrap().unwrap();
    assert_eq!(
        record.trusted_policy_hash,
        blake3::hash(narrowed_text.as_bytes()).to_hex().to_string(),
        "narrowing auto-advances the trusted hash"
    );
}

#[test]
fn explicit_trust_update_unlocks_the_wider_rules() {
    let state_dir = TempDir::new().unwrap();
    let store = TrustStore::new(state_dir.path().to_path_buf());
    let repo_root = PathBuf::from("/repos/example");

    record_explicit_trust(&repo_root, "allow git status", &[allow_rule("git")], &store).unwrap();

    let widened_text = "allow git status\nallow curl";
    let widened_rules = vec![allow_rule("git"), allow_rule("curl")];

    // A human reviews the diff out of band and explicitly records trust in the new file.
    record_explicit_trust(&repo_root, widened_text, &widened_rules, &store).unwrap();

    let effective = apply_project_scope_trust(&repo_root, widened_text, widened_rules, &store);
    assert_eq!(
        effective
            .iter()
            .filter(|r| r.outcome() == Outcome::Allow)
            .count(),
        2,
        "after an explicit trust update, the previously-refused wider rule now applies"
    );
}

#[test]
fn a_second_call_on_an_unchanged_untrusted_file_does_not_self_grant() {
    // This is the exact bug the security review caught: the first call correctly
    // refuses Allow rules and persists an (empty-trust) record at the current hash; a
    // naive "hash unchanged -> apply verbatim" fast path on the SECOND call would then
    // grant everything, without any human ever recording trust. Reproduce it across a
    // fresh `TrustStore` instance too, to prove this isn't an in-memory-only fix but
    // survives what a daemon restart looks like (state read fresh from disk).
    let state_dir = TempDir::new().unwrap();
    let repo_root = PathBuf::from("/repos/example");
    let policy_text = "allow git status\nallow curl";
    let rules = || vec![allow_rule("git"), allow_rule("curl")];

    let store1 = TrustStore::new(state_dir.path().to_path_buf());
    let run1 = apply_project_scope_trust(&repo_root, policy_text, rules(), &store1);
    assert!(
        !run1.iter().any(|r| r.outcome() == Outcome::Allow),
        "run 1 (first use) must refuse all Allow rules"
    );

    // Fresh TrustStore over the same on-disk state dir — simulates a daemon restart.
    let store2 = TrustStore::new(state_dir.path().to_path_buf());
    let run2 = apply_project_scope_trust(&repo_root, policy_text, rules(), &store2);
    assert!(
        !run2.iter().any(|r| r.outcome() == Outcome::Allow),
        "run 2, same unchanged untrusted file, must STILL refuse all Allow rules — no \
         human trust decision was ever recorded"
    );
}

#[test]
fn a_corrupt_trust_record_is_not_silently_clobbered_and_stays_fail_closed() {
    let state_dir = TempDir::new().unwrap();
    let repo_root = PathBuf::from("/repos/example");
    let store = TrustStore::new(state_dir.path().to_path_buf());

    // Establish a real trusted baseline first, then corrupt the file on disk directly
    // (simulating a torn write from a crash mid-`save`, or hostile same-user tampering).
    record_explicit_trust(&repo_root, "allow git status", &[allow_rule("git")], &store).unwrap();
    let path = state_dir
        .path()
        .join("workspaces")
        .join(
            blake3::hash(repo_root.to_string_lossy().as_bytes())
                .to_hex()
                .as_str(),
        )
        .join("policy_trust.toml");
    std::fs::write(&path, b"this is not valid toml {{{").unwrap();

    let widened_text = "allow git status\nallow curl";
    let widened_rules = vec![allow_rule("git"), allow_rule("curl")];

    let run1 = apply_project_scope_trust(&repo_root, widened_text, widened_rules.clone(), &store);
    assert!(
        !run1.iter().any(|r| r.outcome() == Outcome::Allow),
        "a corrupt trust record must fail closed, refusing all Allow rules"
    );

    // Crucially: the corrupt file must still be corrupt afterward — a corrupt record is
    // not first-use, and must not be silently overwritten with a fresh, empty-trust
    // baseline (which would then let the very next call self-grant, per the bug above).
    let contents_after = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        contents_after, "this is not valid toml {{{",
        "a corrupt trust record must not be clobbered by apply_project_scope_trust"
    );

    let run2 = apply_project_scope_trust(&repo_root, widened_text, widened_rules, &store);
    assert!(
        !run2.iter().any(|r| r.outcome() == Outcome::Allow),
        "a second call against the still-corrupt record must also stay fail-closed"
    );
}

#[test]
fn removing_a_trusted_deny_rule_widens_the_real_effective_decision_and_is_fully_gated() {
    let state_dir = TempDir::new().unwrap();
    let repo_root = PathBuf::from("/repos/example");
    let store = TrustStore::new(state_dir.path().to_path_buf());

    // Baseline: `git` is broadly trusted-Allow (any argv), constrained by a trusted Deny
    // on the specific `git push --force` invocation.
    let baseline_text = "allow git\ndeny git push --force";
    let baseline_rules = vec![
        allow_rule("git"),
        CompiledRule::test_new(Scope::Project, Outcome::Deny, force_push_predicate()),
    ];
    record_explicit_trust(&repo_root, baseline_text, &baseline_rules, &store).unwrap();
    let baseline_record = store.load(&repo_root).unwrap().unwrap();

    // Sanity: the real PolicyEngine actually denies this before the attack — Deny always
    // wins over a matching Allow in `PolicyEngine::decide`, regardless of order.
    assert_eq!(
        PolicyEngine::from_rules(baseline_rules)
            .decide(&force_push_params())
            .outcome,
        Outcome::Deny
    );

    // The agent removes only the `deny git push --force` line — no new Allow rule
    // appears at all, and the surviving `Allow git` rule is unchanged.
    let deny_removed_text = "allow git";
    let deny_removed_rules = vec![allow_rule("git")];
    let effective =
        apply_project_scope_trust(&repo_root, deny_removed_text, deny_removed_rules, &store);

    assert!(
        !effective.iter().any(|r| r.outcome() == Outcome::Allow),
        "a disappearing trusted restriction must drop ALL Project-scope Allow rules, not \
         just refuse newly-added ones — the surviving broad `Allow git` rule could still \
         cover the action the deleted Deny used to block"
    );

    // The real check the earlier (round-1) version of this test missed: verify the
    // ACTUAL effective decision through the real PolicyEngine, not just rule counts.
    let real_decision = PolicyEngine::from_rules(effective).decide(&force_push_params());
    assert_ne!(
        real_decision.outcome,
        Outcome::Allow,
        "the real PolicyEngine::decide must not grant `git push --force` just because the \
         Deny rule that used to block it was quietly deleted from the file"
    );

    // The trusted baseline must stay exactly where it was, so this keeps being flagged as
    // widened on every subsequent call until a human explicitly re-trusts it.
    let record_after = store.load(&repo_root).unwrap().unwrap();
    assert_eq!(
        record_after.trusted_policy_hash, baseline_record.trusted_policy_hash,
        "removing a trusted Deny rule must NOT auto-advance the trusted hash — it widens \
         effective permissions and requires an explicit human trust decision"
    );
}

#[test]
fn rewriting_a_trusted_deny_as_ask_on_the_same_predicate_is_widening_and_is_gated() {
    let state_dir = TempDir::new().unwrap();
    let repo_root = PathBuf::from("/repos/example");
    let store = TrustStore::new(state_dir.path().to_path_buf());

    let baseline_text = "allow git\ndeny git push --force";
    let baseline_rules = vec![
        allow_rule("git"),
        CompiledRule::test_new(Scope::Project, Outcome::Deny, force_push_predicate()),
    ];
    record_explicit_trust(&repo_root, baseline_text, &baseline_rules, &store).unwrap();
    let baseline_record = store.load(&repo_root).unwrap().unwrap();

    // The agent rewrites the SAME predicate's outcome from Deny to Ask — a hard refusal
    // becomes a prompt a human or automation could accept. The signature set the naive
    // "collapse every non-Allow outcome into one tag" scheme used is bit-for-bit
    // unchanged; only the real outcome differs.
    let rewritten_text = "allow git\nask git push --force";
    let rewritten_rules = vec![
        allow_rule("git"),
        CompiledRule::test_new(Scope::Project, Outcome::Ask, force_push_predicate()),
    ];
    let effective = apply_project_scope_trust(&repo_root, rewritten_text, rewritten_rules, &store);

    assert!(
        !effective.iter().any(|r| r.outcome() == Outcome::Allow),
        "loosening a trusted Deny to Ask on the same predicate must be gated exactly like \
         any other widening — an absolute refusal becoming a user-approvable prompt is a \
         real widening"
    );
    assert!(
        !effective.iter().any(|r| r.outcome() == Outcome::Ask),
        "the widened Ask rule itself must also be dropped, not just Allow rules — a live \
         Ask rule would still MATCH `git push --force`, which is exactly what the next \
         assertion below proves matters"
    );

    // The real check the earlier version of this test missed: an Ask rule that survives
    // and still matches is not neutralized by unattended mode's no-human-to-ask
    // downgrade, because that downgrade only fires when NO rule matched at all
    // (`decide_unattended`'s `d.rule.is_none()` check) — a live, matching Ask rule left
    // in place would leave `git push --force` at Ask even unattended, never a real Deny.
    let real_decision = PolicyEngine::from_rules(effective).decide_unattended(&force_push_params());
    assert_eq!(
        real_decision.outcome,
        Outcome::Deny,
        "with no live Project-scope rule left to match `git push --force`, unattended \
         mode's no-human-to-ask downgrade must produce a real Deny — this only holds if \
         the widened Ask rule was dropped alongside Allow, not left in place still matching"
    );

    let record_after = store.load(&repo_root).unwrap().unwrap();
    assert_eq!(
        record_after.trusted_policy_hash, baseline_record.trusted_policy_hash,
        "a Deny-to-Ask rewrite on a trusted predicate must NOT auto-advance the trusted \
         hash — this must keep being flagged until a human explicitly re-trusts it"
    );
}

#[test]
fn reordering_two_tied_specificity_rules_flips_the_real_decision_and_is_gated() {
    let state_dir = TempDir::new().unwrap();
    let repo_root = PathBuf::from("/repos/example");
    let store = TrustStore::new(state_dir.path().to_path_buf());

    // Two rules with the IDENTICAL predicate (bare `git`, any argv). Neither Allow nor
    // Ask ever hard-wins over the other in `PolicyEngine::decide` (only Deny does) — a
    // tie on scope/specificity is broken purely by relative order (a stable sort over
    // the rules as given). Baseline: `ask git` listed before `allow git`, so it decides
    // Ask.
    let ask_first_text = "ask git\nallow git";
    let ask_first_rules = vec![
        CompiledRule::test_new(Scope::Project, Outcome::Ask, Predicate::program("git")),
        allow_rule("git"),
    ];
    record_explicit_trust(&repo_root, ask_first_text, &ask_first_rules, &store).unwrap();
    let baseline_record = store.load(&repo_root).unwrap().unwrap();

    let bare_git = TaskParams::Shell(ParsedCommand {
        program: "git".to_string(),
        argv: vec![],
    });
    assert_eq!(
        PolicyEngine::from_rules(ask_first_rules)
            .decide(&bare_git)
            .outcome,
        Outcome::Ask,
        "sanity: with `ask git` listed first, the real PolicyEngine decides Ask on a tie"
    );

    // The agent swaps the two lines — same set of rules, same signatures, only the
    // relative order changed.
    let swapped_text = "allow git\nask git";
    let swapped_rules = vec![
        allow_rule("git"),
        CompiledRule::test_new(Scope::Project, Outcome::Ask, Predicate::program("git")),
    ];

    // The ungated counterfactual: prove the reorder really does flip the real decision on
    // its own, so this test isn't vacuous (i.e. it isn't accidentally passing because the
    // swap never mattered to `PolicyEngine::decide` in the first place).
    assert_eq!(
        PolicyEngine::from_rules(swapped_rules.clone())
            .decide(&bare_git)
            .outcome,
        Outcome::Allow,
        "sanity: with the lines swapped and NO trust gate involved, the real PolicyEngine \
         really does flip to Allow on the same tie — proving the gate below is doing real \
         work, not passing vacuously"
    );

    let effective = apply_project_scope_trust(&repo_root, swapped_text, swapped_rules, &store);

    assert!(
        !effective.iter().any(|r| r.outcome() == Outcome::Allow),
        "a pure reorder of tied-specificity rules must be gated as widening — order alone \
         can flip PolicyEngine::decide's outcome even though the signature SET is identical"
    );

    let real_decision = PolicyEngine::from_rules(effective).decide(&bare_git);
    assert_ne!(
        real_decision.outcome,
        Outcome::Allow,
        "the real PolicyEngine::decide must not grant a bare `git` invocation just because \
         the trusted `ask git`/`allow git` lines were swapped"
    );

    let record_after = store.load(&repo_root).unwrap().unwrap();
    assert_eq!(
        record_after.trusted_policy_hash, baseline_record.trusted_policy_hash,
        "a reorder-only change must NOT auto-advance the trusted hash"
    );
}

#[test]
fn reordering_via_the_file_order_field_alone_is_gated_even_when_vec_position_is_unchanged() {
    // The mechanical twin of the previous test, targeting the actual bug the security
    // review's round-3 finding named: PolicyEngine::decide's real tie-break key is each
    // rule's `file_order` FIELD, never the `Vec`'s iteration order. This test keeps the
    // `Vec` in byte-identical order throughout and only swaps `file_order` values, to
    // prove the trust gate reads the field the real engine reads, not incidental Vec
    // position.
    let state_dir = TempDir::new().unwrap();
    let repo_root = PathBuf::from("/repos/example");
    let store = TrustStore::new(state_dir.path().to_path_buf());

    let mut ask_rule =
        CompiledRule::test_new(Scope::Project, Outcome::Ask, Predicate::program("git"));
    let mut allow_git = allow_rule("git");
    ask_rule.test_set_file_order(0);
    allow_git.test_set_file_order(1);
    // Vec position: [ask_rule, allow_git] — same as the file_order order, so this
    // baseline is unambiguous either way.
    let baseline_rules = vec![ask_rule.clone(), allow_git.clone()];
    record_explicit_trust(&repo_root, "ask git\nallow git", &baseline_rules, &store).unwrap();
    let baseline_record = store.load(&repo_root).unwrap().unwrap();

    let bare_git = TaskParams::Shell(ParsedCommand {
        program: "git".to_string(),
        argv: vec![],
    });
    assert_eq!(
        PolicyEngine::from_rules(baseline_rules)
            .decide(&bare_git)
            .outcome,
        Outcome::Ask
    );

    // The attack: swap the FIELD values, not the Vec positions. The Vec still iterates
    // [ask_rule, allow_git] in that exact order — byte-identical to the baseline — but
    // `allow_git` now carries the lower `file_order`, so it wins the real tie-break.
    let mut swapped_ask = ask_rule;
    let mut swapped_allow = allow_git;
    swapped_ask.test_set_file_order(1);
    swapped_allow.test_set_file_order(0);
    let attacked_rules = vec![swapped_ask, swapped_allow]; // same Vec order as baseline_rules

    assert_eq!(
        PolicyEngine::from_rules(attacked_rules.clone())
            .decide(&bare_git)
            .outcome,
        Outcome::Allow,
        "sanity: file_order alone (not Vec position) really does flip the real decision"
    );

    let effective =
        apply_project_scope_trust(&repo_root, "allow git\nask git", attacked_rules, &store);

    assert!(
        effective
            .iter()
            .all(|r| r.outcome() != Outcome::Allow && r.outcome() != Outcome::Ask),
        "a file_order-only reorder (identical Vec position) must be caught exactly like a \
         Vec-position reorder — the trust gate must key its ordering on file_order, not on \
         incidental Vec iteration order"
    );

    let record_after = store.load(&repo_root).unwrap().unwrap();
    assert_eq!(
        record_after.trusted_policy_hash, baseline_record.trusted_policy_hash,
        "a file_order-only reorder must NOT auto-advance the trusted hash"
    );
}
