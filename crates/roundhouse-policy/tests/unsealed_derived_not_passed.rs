//! Task 25 (Phase 7 lane W0 unit 2): `decide_sealed`, `decide_pipeline`, and
//! `decide_shell_command` must derive `unsealed` from the `PolicyEngine` they
//! are given, never accept it as a caller-supplied bool — that parameter is
//! exactly the API shape that made Phase 2's round-1 divergence possible
//! (`PolicyEngine::unsealed()` is the one correct source; see `engine.rs`).
//!
//! Each test below asserts BOTH directions on the same rule set: the sealed
//! (default) engine must still deny via the sealed floor even though a
//! config rule would otherwise explicitly allow the command, and only
//! flipping the ENGINE's `with_unsealed(true)` — not a parameter — may fall
//! through to that config rule. Asserting only the unsealed direction would
//! still pass even if the function ignored `unsealed` entirely and just
//! always ran `decide`/config matching; the sealed-direction assertion is
//! what pins the derivation to the real source.
//!
//! Compiling this file at all is also load-bearing: it calls all three
//! functions at their new, `unsealed`-free arities.

use roundhouse_core::Tier;
use roundhouse_policy::engine::{CompiledRule, Outcome, PolicyEngine, Predicate, Scope};
use roundhouse_policy::sealed::{home_dir, SealedContext};
use roundhouse_policy::shell::classify::SessionEnv;
use roundhouse_policy::shell::opaque::{classify_shell, ShellClassification};
use roundhouse_policy::shell::pipeline::{decide_pipeline, decide_shell_command};
use roundhouse_policy::{FsOp, TaskParams};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

fn ctx() -> SealedContext {
    SealedContext {
        state_dir: PathBuf::from("/tmp/roundhouse-test-state"),
        daemon_binary: PathBuf::from("/usr/libexec/roundhouse/round-daemon"),
        resolved_mcp_servers: HashSet::new(),
        requested_tier: Tier::Sandbox,
        attested_tier: Tier::Sandbox,
        home: home_dir(),
    }
}

fn ssh_write_allow_rule(home: &Path) -> CompiledRule {
    CompiledRule::test_new(
        Scope::Project,
        Outcome::Allow,
        Predicate::fs_write_prefix(home.join(".ssh").to_str().unwrap()),
    )
}

#[test]
fn decide_sealed_derives_unsealed_from_the_engine_not_a_parameter() {
    let home = home_dir().expect("HOME must be set for this test");
    let params = TaskParams::Fs {
        op: FsOp::Write,
        path: PathBuf::from("~/.ssh/authorized_keys"),
        canonical: Ok(home.join(".ssh/authorized_keys")),
    };

    // Compile-shape: decide_sealed now takes only (&self, &TaskParams,
    // &SealedContext) — no caller-supplied `unsealed` bool.
    let sealed = PolicyEngine::from_rules(vec![ssh_write_allow_rule(&home)]);
    let decision = sealed.decide_sealed(&params, &ctx());
    assert_eq!(
        decision.outcome,
        Outcome::Deny,
        "sealed floor must still win over an explicit config Allow rule when the \
         engine was built without with_unsealed(true)"
    );
    assert_eq!(decision.rule.unwrap().0, "sealed:ssh-write");

    let unsealed = PolicyEngine::from_rules(vec![ssh_write_allow_rule(&home)]).with_unsealed(true);
    let decision = unsealed.decide_sealed(&params, &ctx());
    assert_eq!(
        decision.outcome,
        Outcome::Allow,
        "flipping the ENGINE's with_unsealed(true) — not a parameter — must be what \
         falls through to the config Allow rule"
    );
}

/// `/usr/bin/sudo` hits `sealed:priv-escalation-program` (§6.2) regardless of
/// any config rule. Deliberately NOT a filesystem-write command: `decide_pipeline`
/// canonicalizes redirection targets for real, so a redirection-based fixture
/// would need an actually-existing target file to ever reach `Outcome::Allow`.
/// A plain program/argv match has no such filesystem dependency.
const PRIV_ESCALATION_PROGRAM: &str = "/usr/bin/sudo";

fn engine_allowing_sudo() -> PolicyEngine {
    PolicyEngine::from_rules(vec![CompiledRule::test_new(
        Scope::Project,
        Outcome::Allow,
        Predicate::program(PRIV_ESCALATION_PROGRAM),
    )])
}

#[test]
fn decide_shell_command_derives_unsealed_from_the_engine_not_a_parameter() {
    let cmdline = format!("{PRIV_ESCALATION_PROGRAM} whoami");
    let env = SessionEnv::default();

    // Compile-shape: decide_shell_command now takes only
    // (&PolicyEngine, &SealedContext, &str, &SessionEnv) — no `unsealed` bool.
    let sealed = engine_allowing_sudo();
    let decision = decide_shell_command(&sealed, &ctx(), &cmdline, &env);
    assert_eq!(
        decision.outcome,
        Outcome::Deny,
        "the priv-escalation program must still hit the sealed floor when the \
         engine was built without with_unsealed(true)"
    );
    assert_eq!(decision.rule.unwrap().0, "sealed:priv-escalation-program");

    let unsealed = engine_allowing_sudo().with_unsealed(true);
    let decision = decide_shell_command(&unsealed, &ctx(), &cmdline, &env);
    assert_eq!(
        decision.outcome,
        Outcome::Allow,
        "flipping the ENGINE's with_unsealed(true) must be what falls through to \
         the config Allow rule"
    );
}

#[test]
fn decide_pipeline_derives_unsealed_from_the_engine_not_a_parameter() {
    let cmdline = format!("{PRIV_ESCALATION_PROGRAM} whoami");
    let env = SessionEnv::default();
    let ast = match classify_shell(&cmdline, &env) {
        ShellClassification::Program(cmd) => cmd,
        ShellClassification::HardDeny(_) => {
            panic!("expected a Program classification for {cmdline:?}")
        }
    };

    // Compile-shape: decide_pipeline now takes only
    // (&PolicyEngine, &SealedContext, &ParsedShellAst) — no `unsealed` bool.
    let sealed = engine_allowing_sudo();
    let decision = decide_pipeline(&sealed, &ctx(), &ast);
    assert_eq!(
        decision.outcome,
        Outcome::Deny,
        "the priv-escalation program must still hit the sealed floor when the \
         engine was built without with_unsealed(true)"
    );
    assert_eq!(decision.rule.unwrap().0, "sealed:priv-escalation-program");

    let unsealed = engine_allowing_sudo().with_unsealed(true);
    let decision = decide_pipeline(&unsealed, &ctx(), &ast);
    assert_eq!(
        decision.outcome,
        Outcome::Allow,
        "flipping the ENGINE's with_unsealed(true) must be what falls through to \
         the config Allow rule"
    );
}
