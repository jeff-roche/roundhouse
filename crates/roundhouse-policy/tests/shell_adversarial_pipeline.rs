use roundhouse_core::Tier;
use roundhouse_policy::engine::{CompiledRule, Outcome, PolicyEngine, Predicate, Scope};
use roundhouse_policy::sealed::SealedContext;
use roundhouse_policy::shell::classify::SessionEnv;
use roundhouse_policy::shell::pipeline::decide_shell_command;
use roundhouse_policy::FsOp;
use std::collections::HashSet;
use std::path::PathBuf;

fn ctx() -> SealedContext {
    SealedContext {
        state_dir: PathBuf::from("/tmp/state"),
        daemon_binary: PathBuf::from("/usr/libexec/roundhouse/round-daemon"),
        resolved_mcp_servers: HashSet::new(),
        requested_tier: Tier::Sandbox,
        attested_tier: Tier::Sandbox,
        home: roundhouse_policy::sealed::home_dir(),
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
    let decision = decide_shell_command(&policy, &ctx(), &cmdline, &SessionEnv::default());
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
    let decision = decide_shell_command(&policy, &ctx(), "echo $(whoami)", &SessionEnv::default());
    assert_eq!(
        decision.outcome,
        Outcome::Deny,
        "Opaque must hard-deny even when a downstream rule would otherwise Allow the resolved program"
    );
}

// --- Fix Round 1 regressions -----------------------------------------------

#[test]
fn arithmetic_for_loop_body_commands_are_policy_checked() {
    // Fix Round 1 Critical 1 (peer reviewer, empirically reproduced):
    // `walk_compound_command` had a no-op arm for `ArithmeticForClause`
    // (grouped with `Arithmetic`, which correctly has no executable
    // commands) — but the C-style `for ((;;))` form has its own
    // `body: DoGroupCommand` full of real `SimpleCommand`s, and it was
    // never walked. `resolve_nodes` returned only the `echo start` node,
    // so `rm -rf /tmp/pwned` inside the loop body was never turned into a
    // `ResolvedNode` and never checked against policy at all — it silently
    // resolved to `Allow` regardless of any `Deny rm` rule.
    let policy = PolicyEngine::from_rules(vec![
        CompiledRule::test_new(Scope::Project, Outcome::Allow, Predicate::program("echo")),
        CompiledRule::test_new(Scope::Project, Outcome::Deny, Predicate::program("rm")),
    ]);
    let decision = decide_shell_command(
        &policy,
        &ctx(),
        "echo start && for ((i=0;i<1;i++)); do rm -rf /tmp/pwned; done",
        &SessionEnv::default(),
    );
    assert_eq!(
        decision.outcome,
        Outcome::Deny,
        "a command inside a C-style for ((;;)) loop body must be walked and \
         policy-checked, not silently invisible to decide_pipeline"
    );
}

#[test]
fn output_and_error_redirection_hits_the_sealed_floor() {
    // Fix Round 1 Critical 2 (security auditor, empirically reproduced):
    // `collect_redirect` only handled `IoRedirect::File(_, _, Filename(w))`
    // — `&>`/`&>>` (`IoRedirect::OutputAndError`) produced zero
    // `Redirection`s, so this synthetic write target was never evaluated
    // against policy at all, even though it writes to the exact same path a
    // plain `>` would.
    let policy = PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Project,
        Outcome::Allow,
        Predicate::program("echo"),
    )]);
    let home = roundhouse_policy::sealed::home_dir().unwrap();
    let cmdline = format!("echo secret &> {}/.ssh/authorized_keys", home.display());
    let decision = decide_shell_command(&policy, &ctx(), &cmdline, &SessionEnv::default());
    assert_eq!(
        decision.outcome,
        Outcome::Deny,
        "&> must be evaluated as a write redirection target, not silently dropped"
    );
}

#[test]
fn duplicate_output_word_redirection_hits_the_sealed_floor() {
    // Fix Round 1 Critical 2, second bypass form: `>&file` (a
    // `IoFileRedirectTarget::Duplicate` word that resolves to a path rather
    // than a bare fd) was also silently dropped by the pre-fix
    // `collect_redirect`, which only matched the `Filename` target variant.
    let policy = PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Project,
        Outcome::Allow,
        Predicate::program("echo"),
    )]);
    let home = roundhouse_policy::sealed::home_dir().unwrap();
    let cmdline = format!("echo secret >& {}/.ssh/authorized_keys", home.display());
    let decision = decide_shell_command(&policy, &ctx(), &cmdline, &SessionEnv::default());
    assert_eq!(
        decision.outcome,
        Outcome::Deny,
        ">&file (word-form duplicate target) must be evaluated as a write \
         redirection target, not silently dropped"
    );
}

#[test]
fn input_redirection_is_evaluated_as_a_read_not_a_write() {
    // Fix Round 1 Important 5 (peer AND security reviewers, independently
    // cross-confirmed): `collect_redirect` hardcoded `FsOp::Write` for
    // every `Filename` target regardless of the real `IoFileRedirectKind`,
    // so `cat < secret_path` was evaluated as a WRITE to `secret_path`
    // instead of a READ — a Read-scoped Deny rule could never match it.
    let dir = std::env::temp_dir().join(format!(
        "rh_test_read_redirect_{}_{}",
        std::process::id(),
        line!()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let secret = dir.join("id_rsa");
    std::fs::write(&secret, b"shh").expect("write temp secret file");

    let policy = PolicyEngine::from_rules(vec![
        CompiledRule::test_new(
            Scope::Project,
            Outcome::Deny,
            Predicate::FsPrefix {
                op: FsOp::Read,
                prefix: dir.clone(),
            },
        ),
        CompiledRule::test_new(Scope::Project, Outcome::Allow, Predicate::program("cat")),
    ]);
    let cmdline = format!("cat < {}", secret.display());
    let decision = decide_shell_command(&policy, &ctx(), &cmdline, &SessionEnv::default());

    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        decision.outcome,
        Outcome::Deny,
        "an input (`<`) redirection must be evaluated as FsOp::Read, not FsOp::Write, \
         so a Read-scoped Deny rule can actually match it"
    );
}
