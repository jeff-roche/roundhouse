use roundhouse_core::Tier;
use roundhouse_policy::engine::{CompiledRule, Outcome, PolicyEngine, Predicate, Scope};
use roundhouse_policy::sealed::SealedContext;
use roundhouse_policy::shell::classify::SessionEnv;
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

fn policy_allowing_git_status_denying_rm() -> PolicyEngine {
    PolicyEngine::from_rules(vec![
        CompiledRule::test_new(
            Scope::Project,
            Outcome::Allow,
            Predicate::argv_prefix("git", &["status"]),
        ),
        CompiledRule::test_new(Scope::Project, Outcome::Deny, Predicate::program("rm")),
    ])
}

#[test]
fn conjunction_fails_closed_on_the_second_node_and_or() {
    // The exact headline case from the audit (finding 1) and §6.3/13.3: a
    // conjunction is not automatically opaque, but it runs only if EVERY
    // node independently matches Allow. Before the fix, this resolved to
    // Allow because the `rm` iteration was checked against node 0 (`git`)
    // instead of itself.
    let policy = policy_allowing_git_status_denying_rm();
    let decision = decide_shell_command(
        &policy,
        false,
        &ctx(),
        "git status && rm -rf /",
        &SessionEnv::default(),
    );
    assert_eq!(
        decision.outcome,
        Outcome::Deny,
        "must fail on the second node, not be allowed because node one matched"
    );
}

#[test]
fn conjunction_with_semicolon_also_fails_closed() {
    let policy = policy_allowing_git_status_denying_rm();
    let decision = decide_shell_command(
        &policy,
        false,
        &ctx(),
        "git status; rm -rf /",
        &SessionEnv::default(),
    );
    assert_eq!(decision.outcome, Outcome::Deny);
}

#[test]
fn naive_substring_matching_would_wrongly_allow_this_and_must_not() {
    // A rule permitting `ls` must never match because the raw string
    // contains "ls" as a substring inside an unrelated program name —
    // matching is on parsed (resolved_program, argv), never
    // substring/prefix on the raw string (§6.3 step 7).
    let policy = PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Project,
        Outcome::Allow,
        Predicate::program("ls"),
    )]);
    let decision = decide_shell_command(
        &policy,
        false,
        &ctx(),
        "falsely_ls_named_binary --danger",
        &SessionEnv::default(),
    );
    assert_ne!(
        decision.outcome,
        Outcome::Allow,
        "substring match on raw text must never grant Allow"
    );
}

#[test]
fn redirection_target_is_evaluated_as_a_synthetic_write_task() {
    let policy = PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Project,
        Outcome::Allow,
        Predicate::program("echo"),
    )]);
    let home = roundhouse_policy::sealed::home_dir().unwrap();
    let cmdline = format!("echo secret > {}/.ssh/authorized_keys", home.display());
    let decision = decide_shell_command(&policy, false, &ctx(), &cmdline, &SessionEnv::default());
    assert_eq!(
        decision.outcome,
        Outcome::Deny,
        "the redirection target hits the sealed floor even though the bare argv is allowed"
    );
}

#[test]
fn opaque_construct_inside_a_pipeline_is_hard_denied_by_the_composed_entry_point() {
    // Regression for audit finding 11: calling decide_pipeline directly
    // would skip classify_shell's step-1-3 Opaque hard-deny entirely. Every
    // real caller and every test must go through decide_shell_command
    // instead.
    let policy = PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Project,
        Outcome::Allow,
        Predicate::program("sh"),
    )]);
    let decision = decide_shell_command(
        &policy,
        false,
        &ctx(),
        "echo $(whoami)",
        &SessionEnv::default(),
    );
    assert_eq!(
        decision.outcome,
        Outcome::Deny,
        "Opaque must hard-deny even when a downstream rule would otherwise Allow the resolved program"
    );
}
