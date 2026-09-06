//! Task 26 (W4): three AST walkers (`shell/pipeline.rs`, `shell/opaque.rs`,
//! `shell/classify.rs`) are each supposed to independently walk into a
//! C-style `for ((;;))` clause's body — `pipeline.rs`'s `walk_compound_command`
//! already does (its own "fix-round-1 Critical 1"), but `opaque.rs`'s
//! `find_opaque_in_compound_command`, and `classify.rs`'s
//! `expand_in_compound_command` and `any_word_piece_in_compound_command`,
//! all still treated `ArithmeticForClause` as a no-op — so a dangerous
//! construct hidden inside a C-style for-loop body was invisible to two of
//! the three walkers meant to independently agree on it.
//!
//! Per Ruling W4-4, this is driven through each walker's real public entry
//! point — `roundhouse_policy::shell::parse` and `walks_dangerous_command`
//! do not exist:
//! - `pipeline.rs`: `shell::pipeline::decide_shell_command` (the composed
//!   entry point every real caller uses — see
//!   `tests/shell_adversarial_pipeline.rs`).
//! - `opaque.rs`: `shell::opaque::classify_shell` (see
//!   `tests/shell_adversarial_opaque.rs`).
//! - `classify.rs`: `shell::classify::parse_command` +
//!   `ParsedShellAst::contains_unresolved_command_substitution` (see
//!   `tests/shell_parse_and_expand.rs`), called directly — bypassing
//!   `opaque.rs`'s own hard-deny — to prove `classify.rs`'s own walker
//!   independently sees the same construct; and `parse_command` +
//!   `resolve_variable_expansions` + `pipeline::decide_pipeline` to prove
//!   `classify.rs`'s variable-expansion walker descends into the loop body
//!   too (`expand_in_compound_command`'s other no-op site).

use roundhouse_core::Tier;
use roundhouse_policy::engine::{CompiledRule, Outcome, PolicyEngine, Predicate, Scope};
use roundhouse_policy::sealed::SealedContext;
use roundhouse_policy::shell::classify::{parse_command, Classification, SessionEnv};
use roundhouse_policy::shell::opaque::{classify_shell, ShellClassification};
use roundhouse_policy::shell::pipeline::{decide_pipeline, decide_shell_command};
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

fn policy_denying_rm() -> PolicyEngine {
    PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Project,
        Outcome::Deny,
        Predicate::program("rm"),
    )])
}

/// `pipeline.rs`'s own walker (already fixed) must still see a dangerous
/// command hidden inside a C-style for-loop body.
#[test]
fn pipeline_walker_sees_a_dangerous_command_inside_a_c_style_for_loop_body() {
    let decision = decide_shell_command(
        &policy_denying_rm(),
        &ctx(),
        "for ((i=0; i<1; i++)); do rm -rf /tmp/pwned1; done",
        &SessionEnv::default(),
    );
    assert_eq!(
        decision.outcome,
        Outcome::Deny,
        "pipeline.rs must walk a C-style for-loop body"
    );
}

/// Nested case: a C-style for-loop inside another compound command (an
/// if-clause), so the fix is not a single-level special case.
#[test]
fn pipeline_walker_sees_a_dangerous_command_inside_a_nested_c_style_for_loop_body() {
    let decision = decide_shell_command(
        &policy_denying_rm(),
        &ctx(),
        "if true; then for ((i=0; i<1; i++)); do rm -rf /tmp/pwned2; done; fi",
        &SessionEnv::default(),
    );
    assert_eq!(
        decision.outcome,
        Outcome::Deny,
        "pipeline.rs must walk a C-style for-loop body nested inside another compound command"
    );
}

/// `opaque.rs`'s `find_opaque_nodes` (via `classify_shell`) must walk into a
/// C-style for-loop body to find an irreducibly opaque construct (a command
/// substitution) hidden there — before the fix, `find_opaque_in_compound_command`
/// treated `ArithmeticForClause` as a no-op, so this hard-deny was silently
/// skipped for anything hidden inside the loop.
#[test]
fn opaque_walker_sees_a_command_substitution_inside_a_c_style_for_loop_body() {
    let result = classify_shell(
        "for ((i=0; i<1; i++)); do echo $(rm -rf /tmp/pwned3); done",
        &SessionEnv::default(),
    );
    match result {
        ShellClassification::HardDeny(hint) => {
            assert_eq!(hint.error, "opaque_shell_construct");
        }
        ShellClassification::Program(_) => panic!(
            "opaque.rs must walk into a C-style for-loop body and hard-deny the \
             command substitution hidden there"
        ),
    }
}

/// Nested case for the opaque walker: the C-style for-loop is itself inside
/// a brace group.
#[test]
fn opaque_walker_sees_a_command_substitution_inside_a_nested_c_style_for_loop_body() {
    let result = classify_shell(
        "{ for ((i=0; i<1; i++)); do echo $(rm -rf /tmp/pwned4); done; }",
        &SessionEnv::default(),
    );
    assert!(
        matches!(result, ShellClassification::HardDeny(_)),
        "opaque.rs must walk a C-style for-loop body nested inside a brace group"
    );
}

/// `classify.rs`'s own independent walker (`any_word_piece_in_compound_command`,
/// reached via `ParsedShellAst::contains_unresolved_command_substitution`)
/// must also see a command substitution hidden inside a C-style for-loop
/// body — called directly here, bypassing `opaque.rs`'s hard-deny entirely,
/// to prove `classify.rs`'s walker independently agrees rather than piggy-
/// backing on `opaque.rs`'s own (separately tested) fix.
#[test]
fn classify_walker_sees_unresolved_command_substitution_inside_a_c_style_for_loop_body() {
    let Classification::Program(cmd) =
        parse_command("for ((i=0; i<1; i++)); do echo $(rm -rf /tmp/pwned5); done")
    else {
        panic!("expected parseable")
    };
    assert!(
        cmd.contains_unresolved_command_substitution(),
        "classify.rs's any_word_piece_in_compound_command must walk a C-style \
         for-loop body"
    );
}

/// `classify.rs`'s variable-expansion walker (`expand_in_compound_command`'s
/// other no-op site) must also descend into a C-style for-loop body — proven
/// end-to-end: a plain `$VAR` inside the loop body must be resolved to its
/// literal value before `pipeline.rs`'s (already-correct) node walk ever
/// sees it, so a policy rule matching the *expanded* value fires.
#[test]
fn classify_walker_expands_plain_variables_inside_a_c_style_for_loop_body() {
    let mut env = SessionEnv::default();
    env.set("DANGER", "/tmp/pwned6");

    let Classification::Program(mut cmd) =
        parse_command("for ((i=0; i<1; i++)); do rm -rf $DANGER; done")
    else {
        panic!("expected parseable")
    };
    roundhouse_policy::shell::classify::resolve_variable_expansions(&mut cmd.program_ast, &env);

    let policy = PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Project,
        Outcome::Deny,
        Predicate::argv_prefix("rm", &["-rf", "/tmp/pwned6"]),
    )]);
    let decision = decide_pipeline(&policy, &ctx(), &cmd);

    assert_eq!(
        decision.outcome,
        Outcome::Deny,
        "classify.rs's expand_in_compound_command must resolve $DANGER inside \
         the C-style for-loop body before the pipeline walk sees it"
    );
}
