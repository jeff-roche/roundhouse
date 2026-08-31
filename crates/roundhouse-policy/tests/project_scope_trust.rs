use roundhouse_policy::engine::{CompiledRule, Outcome, Predicate, Scope};
use roundhouse_policy::trust::{apply_project_scope_trust, record_explicit_trust, TrustStore};
use std::path::PathBuf;
use tempfile::TempDir;

fn allow_rule(program: &str) -> CompiledRule {
    CompiledRule::test_new(Scope::Project, Outcome::Allow, Predicate::program(program))
}
fn deny_rule(program: &str) -> CompiledRule {
    CompiledRule::test_new(Scope::Project, Outcome::Deny, Predicate::program(program))
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
        !effective.iter().any(|r| r.outcome == Outcome::Allow),
        "first use is narrow-by-default: no Allow rule applies until a human trusts this exact file"
    );
    assert!(
        effective.iter().any(|r| r.outcome == Outcome::Deny),
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
        .filter(|r| r.outcome == Outcome::Allow)
        .filter_map(|r| match &r.predicate {
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
    let effective = apply_project_scope_trust(&repo_root, narrowed_text, vec![allow_rule("git")], &store);
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
        effective.iter().filter(|r| r.outcome == Outcome::Allow).count(),
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
        !run1.iter().any(|r| r.outcome == Outcome::Allow),
        "run 1 (first use) must refuse all Allow rules"
    );

    // Fresh TrustStore over the same on-disk state dir — simulates a daemon restart.
    let store2 = TrustStore::new(state_dir.path().to_path_buf());
    let run2 = apply_project_scope_trust(&repo_root, policy_text, rules(), &store2);
    assert!(
        !run2.iter().any(|r| r.outcome == Outcome::Allow),
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
        .join(blake3::hash(repo_root.to_string_lossy().as_bytes()).to_hex().as_str())
        .join("policy_trust.toml");
    std::fs::write(&path, b"this is not valid toml {{{").unwrap();

    let widened_text = "allow git status\nallow curl";
    let widened_rules = vec![allow_rule("git"), allow_rule("curl")];

    let run1 = apply_project_scope_trust(&repo_root, widened_text, widened_rules.clone(), &store);
    assert!(
        !run1.iter().any(|r| r.outcome == Outcome::Allow),
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
        !run2.iter().any(|r| r.outcome == Outcome::Allow),
        "a second call against the still-corrupt record must also stay fail-closed"
    );
}

#[test]
fn removing_a_trusted_deny_rule_is_a_widening_and_is_gated_like_any_other() {
    let state_dir = TempDir::new().unwrap();
    let repo_root = PathBuf::from("/repos/example");
    let store = TrustStore::new(state_dir.path().to_path_buf());

    // Baseline: `git` is trusted-Allow, constrained by a trusted Deny on `curl`.
    let baseline_text = "allow git status\ndeny curl";
    let baseline_rules = vec![allow_rule("git"), deny_rule("curl")];
    record_explicit_trust(&repo_root, baseline_text, &baseline_rules, &store).unwrap();
    let baseline_record = store.load(&repo_root).unwrap().unwrap();

    // The agent removes only the `deny curl` line — no new Allow rule appears at all.
    let deny_removed_text = "allow git status";
    let deny_removed_rules = vec![allow_rule("git")];
    let effective = apply_project_scope_trust(&repo_root, deny_removed_text, deny_removed_rules, &store);

    let allowed_programs: Vec<_> = effective
        .iter()
        .filter(|r| r.outcome == Outcome::Allow)
        .filter_map(|r| match &r.predicate {
            Predicate::Shell { program, .. } => Some(program.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        allowed_programs,
        vec!["git".to_string()],
        "removing a trusted Deny must not itself grant any new Allow rule"
    );

    // The real check: this must NOT have been treated as pure narrowing. The trusted
    // baseline must stay exactly where it was (the deny-removed file's hash must NOT
    // become the new trusted hash) so this keeps being flagged as widened until a human
    // explicitly re-trusts it.
    let record_after = store.load(&repo_root).unwrap().unwrap();
    assert_eq!(
        record_after.trusted_policy_hash, baseline_record.trusted_policy_hash,
        "removing a trusted Deny rule must NOT auto-advance the trusted hash — it widens \
         effective permissions and requires an explicit human trust decision"
    );
}
