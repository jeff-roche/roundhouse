use roundhouse_core::Tier;
use roundhouse_policy::engine::{CompiledRule, Outcome, PolicyEngine, Predicate, Scope};
use roundhouse_policy::sealed::SealedContext;
use roundhouse_policy::shell::classify::SessionEnv;
use roundhouse_policy::shell::interpreter::is_interpreter;
use roundhouse_policy::shell::pipeline::decide_shell_command;
use std::collections::HashSet;
use std::path::PathBuf;

fn ctx() -> SealedContext {
    SealedContext {
        state_dir: PathBuf::from("/tmp/state"),
        daemon_binary: PathBuf::from("/usr/libexec/roundhouse/round-daemon"),
        resolved_mcp_servers: HashSet::new(),
        requested_tier: Tier::Sandbox,
        attested_tier: Tier::Sandbox,
    }
}

#[test]
fn python_is_forced_ask_even_with_a_broad_allow_rule() {
    let policy = PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Workspace,
        Outcome::Allow,
        Predicate::program("python"),
    )]);
    let decision = decide_shell_command(
        &policy,
        false,
        &ctx(),
        "python script.py",
        &SessionEnv::default(),
    );
    assert_eq!(
        decision.outcome,
        Outcome::Ask,
        "interpreter programs are Ask regardless of allowlist match (§6.3 step 6)"
    );
}

#[test]
fn allow_interpreter_flag_on_the_rule_opts_out() {
    let policy = PolicyEngine::from_rules(vec![CompiledRule::test_new_with_interpreter_flag(
        Scope::Workspace,
        Outcome::Allow,
        "python",
        true,
    )]);
    let decision = decide_shell_command(
        &policy,
        false,
        &ctx(),
        "python script.py",
        &SessionEnv::default(),
    );
    assert_eq!(decision.outcome, Outcome::Allow);
}

#[test]
fn argv_prefix_never_matches_via_raw_string_substring() {
    assert!(is_interpreter("python"));
    assert!(!is_interpreter("git")); // git is not on the interpreter list
}

// --- Fix Round 1 regressions -----------------------------------------------

#[test]
fn explicit_deny_on_an_interpreter_program_still_denies() {
    // Fix Round 1 Important 4 (security auditor, empirically reproduced):
    // the interpreter gate in `Predicate::matches`'s `Shell` arm
    // unconditionally returned "no match" for an interpreter program unless
    // `allow_interpreter` was set — including for a rule whose OWN outcome
    // is `Deny`. That meant an operator-authored `Deny python` rule never
    // matched at all, and the decision fell through to the unmatched
    // default (`Ask`) instead of `Deny` — silently weakening an explicit
    // deny into a mere approval prompt.
    let policy = PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Workspace,
        Outcome::Deny,
        Predicate::program("python"),
    )]);
    let decision = decide_shell_command(
        &policy,
        false,
        &ctx(),
        "python evil.py",
        &SessionEnv::default(),
    );
    assert_eq!(
        decision.outcome,
        Outcome::Deny,
        "an explicit Deny rule targeting an interpreter program must still deny, \
         not fall through to the Ask default"
    );
}

#[test]
fn interpreter_gate_recognizes_path_qualified_and_python3_forms() {
    // Fix Round 1 Important 3 (security auditor, empirically reproduced):
    // `is_interpreter` did raw string equality with no basename
    // normalization (unlike `sealed::sealed_program`'s existing
    // `Path::new(program).file_name()` pattern), so a path-qualified
    // invocation of a broadly-allowed interpreter evaded the gate.
    let policy = PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Workspace,
        Outcome::Allow,
        Predicate::program("/usr/bin/python3"),
    )]);
    let decision = decide_shell_command(
        &policy,
        false,
        &ctx(),
        "/usr/bin/python3 -c whatever",
        &SessionEnv::default(),
    );
    assert_eq!(
        decision.outcome,
        Outcome::Ask,
        "a path-qualified python3 invocation must still be recognized as an \
         interpreter and forced to Ask, not silently Allowed"
    );
}
