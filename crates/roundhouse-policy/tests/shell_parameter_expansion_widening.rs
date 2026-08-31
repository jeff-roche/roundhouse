// crates/roundhouse-policy/tests/shell_parameter_expansion_widening.rs
//
// Regression coverage for task-22.5 (see
// `.superpowers/sdd/2026-08-27-phase2-robustness/task-22.5-report.md`): widening
// `parameter_expr_is_opaque` from a blanket "any non-plain `${...}` form is opaque" rule
// to an allowlist (`indirect: false` AND every payload string is `$`-free), widened in
// exact lockstep with `is_expandable_piece`/`expand_piece` so accepted forms actually
// resolve instead of reaching argv as unexpanded literal text.
//
// Two things this file exists to prove, per the task-22.5 brief's Step 4:
// 1. The three real bypasses the security review demonstrated against actual bash
//    5.3.15 are STILL correctly hard-denied under the new allowlist design (none of
//    them are anywhere close to being accidentally let through).
// 2. The newly-accepted safe forms actually resolve to the correct argv text end to
//    end, not just "don't hard-deny."

use roundhouse_policy::shell::classify::{
    parse_command, resolve_variable_expansions, Classification, SessionEnv,
};
use roundhouse_policy::shell::opaque::{classify_shell, ShellClassification};

fn resolved_argv(cmd: &str, env: &SessionEnv) -> Vec<String> {
    let Classification::Program(mut parsed) = parse_command(cmd) else {
        panic!("expected {cmd:?} to parse")
    };
    resolve_variable_expansions(&mut parsed.program_ast, env);
    parsed.first_node_argv()
}

// ---------------------------------------------------------------------------
// 1. The three real bypasses must still be denied.
// ---------------------------------------------------------------------------

/// Bypass #1: `${x@P}` (`Transform{op: PromptExpand}`) has an EMPTY string payload, but
/// real bash performs command substitution on the *variable's own value* during prompt
/// expansion — invisible to any scan of the expansion's own source text. `Transform` is
/// never in the allowlist at all, regardless of payload, so this must still hard-deny.
#[test]
fn prompt_expand_transform_is_still_hard_denied() {
    let env = SessionEnv::default();
    for cmd in ["echo \"${x@P}\"", "echo ${x@P}", "echo \"${x@Q}\""] {
        assert!(
            matches!(classify_shell(cmd, &env), ShellClassification::HardDeny(_)),
            "{cmd:?} (a Transform parameter expansion) must still be hard-denied"
        );
    }
}

/// Bypass #2: `${arr[$(id)]}` / `${arr[$y]}` — array subscripts are arithmetic contexts
/// that recursively re-evaluate a variable's VALUE, so an injection can hide one level
/// of indirection behind what a naive same-string scan would check. `NamedWithIndex` is
/// excluded from the allowlist by the `Parameter::Named(_)`-only restriction, so both
/// forms must still hard-deny regardless of what the index expression contains.
#[test]
fn array_index_parameter_forms_are_still_hard_denied() {
    let env = SessionEnv::default();
    for cmd in [
        "echo \"${arr[$(id)]}\"",
        "echo \"${arr[$y]}\"",
        "echo \"${arr[1]}\"",
    ] {
        assert!(
            matches!(classify_shell(cmd, &env), ShellClassification::HardDeny(_)),
            "{cmd:?} (a NamedWithIndex parameter expansion) must still be hard-denied"
        );
    }
}

/// Bypass #3: `${x:$z:2}` (`Substring`) — the substring offset is also an arithmetic
/// context, so a variable-controlled offset can smuggle an injection the same way the
/// array-subscript case does. `Substring` is not in the allowlist at all.
#[test]
fn substring_parameter_expansion_is_still_hard_denied() {
    let env = SessionEnv::default();
    for cmd in ["echo \"${x:$z:2}\"", "echo \"${x:0:2}\""] {
        assert!(
            matches!(classify_shell(cmd, &env), ShellClassification::HardDeny(_)),
            "{cmd:?} (a Substring parameter expansion) must still be hard-denied"
        );
    }
}

/// A default value that itself contains a real command substitution must still
/// hard-deny: the `$` in `$(id)` disqualifies the whole `UseDefaultValues` expression
/// from the allowlist (the `$`-ban, not a `$(`-specific scan, is what closes this).
#[test]
fn default_value_containing_command_substitution_is_still_hard_denied() {
    let env = SessionEnv::default();
    for cmd in [
        "echo \"${X:-$(id)}\"",
        "echo \"${X:=$(id)}\"",
        "echo \"${X:+$(id)}\"",
        "echo \"${X#$(id)}\"",
        "echo \"${X%%$(id)}\"",
    ] {
        assert!(
            matches!(classify_shell(cmd, &env), ShellClassification::HardDeny(_)),
            "{cmd:?} (a payload containing a bare `$`) must still be hard-denied"
        );
    }
}

/// An indirect reference must stay denied even for otherwise-allowlisted shapes — the
/// target name is computed at runtime and can't be statically resolved here.
#[test]
fn indirect_reference_is_still_hard_denied() {
    let env = SessionEnv::default();
    for cmd in ["echo \"${!x}\"", "echo \"${!x:-default}\""] {
        assert!(
            matches!(classify_shell(cmd, &env), ShellClassification::HardDeny(_)),
            "{cmd:?} (indirect: true) must still be hard-denied"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. The newly-accepted safe forms must actually resolve correctly.
// ---------------------------------------------------------------------------

#[test]
fn use_default_values_resolves_correctly() {
    let env = SessionEnv::default();
    assert_eq!(
        resolved_argv("echo \"${x:-default}\"", &env),
        vec!["echo", "default"],
        "unset var must fall through to the default"
    );
    assert!(
        matches!(
            classify_shell("echo \"${x:-default}\"", &env),
            ShellClassification::Program(_)
        ),
        "must not be hard-denied"
    );

    let mut env = SessionEnv::default();
    env.set("x", "set-value");
    assert_eq!(
        resolved_argv("echo \"${x:-default}\"", &env),
        vec!["echo", "set-value"],
        "set-and-non-empty var must win over the default"
    );

    // `:-` (UnsetOrNull) treats present-but-empty the same as unset...
    let mut env = SessionEnv::default();
    env.set("x", "");
    assert_eq!(
        resolved_argv("echo \"${x:-default}\"", &env),
        vec!["echo", "default"],
        "`:-` must treat an empty value the same as unset"
    );
    // ...but bare `-` (Unset) only treats a genuinely absent variable as unset.
    assert_eq!(
        resolved_argv("echo \"${x-default}\"", &env),
        vec!["echo", ""],
        "bare `-` must NOT treat a present-but-empty value as unset"
    );
}

#[test]
fn assign_default_values_resolves_the_value_without_the_assignment_side_effect() {
    let env = SessionEnv::default();
    assert_eq!(
        resolved_argv("echo \"${x:=default}\"", &env),
        vec!["echo", "default"]
    );
    // The classifier operates on a read-only snapshot: resolving `${x:=default}` must
    // not mutate `env`'s view of `x` for a later expansion in the same command.
    assert_eq!(env.get("x"), None);
}

#[test]
fn use_alternative_value_resolves_correctly() {
    let env = SessionEnv::default();
    assert_eq!(
        resolved_argv("echo \"${x:+alt}\"", &env),
        vec!["echo", ""],
        "unset var must resolve to empty, not the alternative"
    );

    let mut env = SessionEnv::default();
    env.set("x", "anything");
    assert_eq!(
        resolved_argv("echo \"${x:+alt}\"", &env),
        vec!["echo", "alt"],
        "set-and-non-empty var must resolve to the alternative"
    );
}

#[test]
fn parameter_length_resolves_correctly() {
    let mut env = SessionEnv::default();
    env.set("x", "hello");
    assert_eq!(resolved_argv("echo \"${#x}\"", &env), vec!["echo", "5"]);

    let env = SessionEnv::default();
    assert_eq!(
        resolved_argv("echo \"${#missing}\"", &env),
        vec!["echo", "0"]
    );
}

#[test]
fn prefix_and_suffix_pattern_stripping_resolves_correctly() {
    let mut env = SessionEnv::default();
    env.set("f", "foo.tar.gz");

    assert_eq!(
        resolved_argv("echo \"${f#*.}\"", &env),
        vec!["echo", "tar.gz"],
        "`#` removes the SMALLEST matching prefix"
    );
    assert_eq!(
        resolved_argv("echo \"${f##*.}\"", &env),
        vec!["echo", "gz"],
        "`##` removes the LARGEST matching prefix"
    );
    assert_eq!(
        resolved_argv("echo \"${f%.*}\"", &env),
        vec!["echo", "foo.tar"],
        "`%` removes the SMALLEST matching suffix"
    );
    assert_eq!(
        resolved_argv("echo \"${f%%.*}\"", &env),
        vec!["echo", "foo"],
        "`%%` removes the LARGEST matching suffix"
    );

    // No match: value passes through unmodified.
    let mut env = SessionEnv::default();
    env.set("f", "no-dots-here");
    assert_eq!(
        resolved_argv("echo \"${f#*.}\"", &env),
        vec!["echo", "no-dots-here"]
    );

    for cmd in [
        "echo \"${f#*.}\"",
        "echo \"${f##*.}\"",
        "echo \"${f%.*}\"",
        "echo \"${f%%.*}\"",
    ] {
        assert!(
            matches!(classify_shell(cmd, &env), ShellClassification::Program(_)),
            "{cmd:?} must not be hard-denied"
        );
    }
}
