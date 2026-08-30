//! §6.3 step 6: some resolved programs are themselves interpreters — running
//! their own script payload with its own, entirely separate, escalation
//! surface (`python -c ...`, `perl -e ...`, `env sh -c ...`, ...). This
//! module never analyses that payload; the classification is a pure lookup
//! on the resolved program name, and a match forces `Predicate::Shell` to
//! fall through to no-match (which the caller turns into `Ask`) unless the
//! rule explicitly opts out with `allow_interpreter: true`.

/// Resolved program *basenames* treated as interpreters. Matched exactly
/// against a basename — never a substring or prefix check on the raw command
/// line, and never on a full path (see [`is_interpreter`]'s normalization).
pub const INTERPRETER_PROGRAMS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "python", "python3", "perl", "ruby", "php", "lua", "awk",
    "xargs", "env", "node", "make", "ssh",
];

/// True if `program` is a recognized interpreter.
///
/// `program` is normalized to its basename first (`Path::new(program)
/// .file_name()`, mirroring `sealed::sealed_program`'s existing pattern)
/// before the lookup, so a path-qualified invocation (`/usr/bin/python`,
/// `./bin/bash`) is recognized exactly the same as the bare name (Important
/// 3): comparing the raw, unnormalized string would let a rule authored
/// against a path-qualified program name silently evade the interpreter gate
/// even though the resolved program is unambiguously an interpreter.
///
/// We do not analyse the payload of an interpreter invocation — beyond this
/// basename lookup, matching is purely on the resolved program name (§6.3
/// step 6).
pub fn is_interpreter(program: &str) -> bool {
    let basename = std::path::Path::new(program)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(program);
    INTERPRETER_PROGRAMS.contains(&basename)
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

    #[test]
    fn recognizes_interpreters_by_basename_even_when_path_qualified() {
        assert!(is_interpreter("/usr/bin/python"));
        assert!(is_interpreter("/bin/bash"));
        assert!(is_interpreter("python3"));
        assert!(is_interpreter("/usr/bin/python3"));
        assert!(!is_interpreter("/usr/bin/git"));
    }
}
