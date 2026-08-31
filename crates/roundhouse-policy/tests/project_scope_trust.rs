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

    let record = store.load(&repo_root).unwrap();
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
