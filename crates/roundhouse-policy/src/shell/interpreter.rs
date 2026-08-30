//! §6.3 step 6: some resolved programs are themselves interpreters — running
//! their own script payload with its own, entirely separate, escalation
//! surface (`python -c ...`, `perl -e ...`, `env sh -c ...`, ...). This
//! module never analyses that payload; the classification is a pure lookup
//! on the resolved program name, and a match forces `Predicate::Shell` to
//! fall through to no-match (which the caller turns into `Ask`) unless the
//! rule explicitly opts out with `allow_interpreter: true`.

/// Resolved program names treated as interpreters. Matched exactly against
/// `ResolvedNode::resolved_program` / `ParsedCommand::program` — never a
/// substring or prefix check on the raw command line.
pub const INTERPRETER_PROGRAMS: &[&str] = &[
    "sh", "bash", "python", "perl", "awk", "xargs", "env", "node", "make", "ssh",
];

/// True if `program` is a recognized interpreter. We do not analyse the
/// payload of an interpreter invocation — matching is purely on the resolved
/// program name (§6.3 step 6).
pub fn is_interpreter(program: &str) -> bool {
    INTERPRETER_PROGRAMS.contains(&program)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_known_interpreters() {
        assert!(is_interpreter("python"));
        assert!(is_interpreter("sh"));
        assert!(!is_interpreter("git"));
    }
}
