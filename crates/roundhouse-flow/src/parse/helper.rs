//! Locates and invokes `round-yaml-parse-helper`, the out-of-process YAML
//! deserializer [`super::parse_workflow`] runs the real `serde_yaml` parse
//! through (Task 14, lane W5). See `super`'s module doc comment for why
//! this exists at all; this module is just the plumbing: find the sibling
//! binary, run it under `roundhouse_sandbox::bounded_parse`'s resource
//! bound, and turn whatever comes back into a [`super::ParseError`].
//!
//! # Never falls back to in-process parsing (ruling W5-3)
//!
//! If the helper binary cannot be found or spawned, [`parse_via_helper`]
//! returns [`super::ParseError::HelperUnavailable`] — it does not retry
//! in-process. A silent fallback would reintroduce exactly the unbounded
//! `serde_yaml::from_str` call this task exists to remove from the
//! reachable path.
//!
//! # The verdict protocol (Task 14 fix round 1, ruling W5-20)
//!
//! Since fix round 1, the helper also runs `expansion::check_expansion`
//! (see `crate::parse::expansion`'s module doc for why that check moved
//! into the bounded child) before its typed deserialize. `check_expansion`
//! can find [`super::ParseError::TooManyNumericScalars`] or
//! [`super::ParseError::ExpandsTooLarge`] shapes, and a bare process exit
//! code cannot carry either variant's data — so the helper always exits
//! `0` (success, stdout carries the re-serialized YAML) or `1` (failure),
//! and on failure encodes *which* existing `ParseError` variant applies as
//! a one-line tagged prefix on stderr, matched here by
//! [`map_helper_failure`]:
//!
//! - `ROUND_VERDICT:EXPANDS_TOO_LARGE` — [`super::ParseError::ExpandsTooLarge`].
//!   No further data needed: `actual_bytes` is the caller's own `yaml.len()`
//!   and `max` is [`super::MAX_EXPANDED_WEIGHT`], both already known here.
//! - `ROUND_VERDICT:TOO_MANY_NUMERIC_SCALARS:<kind>` — `<kind>` is `float`
//!   or `integer` — [`super::ParseError::TooManyNumericScalars`]. `max` is
//!   not sent either: `check_expansion`'s own float/integer ceiling
//!   arithmetic is exactly [`super::MAX_FLOAT_SCALAR_VISITS`] /
//!   [`super::MAX_INTEGER_SCALAR_VISITS`], both public constants derived
//!   from the same [`super::MAX_EXPANDED_WEIGHT`] the helper is called
//!   with, so recomputing here cannot drift from what the child used.
//! - `ROUND_VERDICT:YAML_ERROR:<line-or-dash>:<col-or-dash>:<message>` — a
//!   genuine YAML syntax error `check_expansion` caught on its own copy of
//!   the real deserializer. A `serde_yaml::Error` cannot cross a process
//!   boundary (no public constructor reattaches a `Location` to a bare
//!   message), so the child sends the `Display` text and, when the
//!   original error had one, its `(line, column)` pair as plain data
//!   instead — see [`super::YamlFailure::FromHelper`].
//! - Anything else is a plain human-readable message (the helper's own
//!   re-serialization failure, an unreadable-stdin error, ...),
//!   reconstructed as [`super::YamlFailure::FromHelper`] with no location —
//!   exactly [`super::ParseError::Yaml`]'s old `HelperCrashed` handling,
//!   unchanged for every shape this protocol doesn't need to name.
//!
//! **Why this cannot be spoofed into acceptance.** These tags are only
//! ever read from [`roundhouse_sandbox::bounded_parse::BoundedParseError::HelperCrashed`],
//! which [`roundhouse_sandbox::bounded_parse::run_bounded_subprocess`] only
//! produces for a **non-zero** exit — reaching this code at all already
//! means the document was rejected. Document content the helper might echo
//! into a message (e.g. an unknown YAML tag name) can only ever appear
//! *after* one of the two fixed prefixes the helper itself writes first
//! (`ROUND_VERDICT:YAML_ERROR:` for every `Malformed` case), so it cannot
//! forge the *exact* `ROUND_VERDICT:EXPANDS_TOO_LARGE` line or the
//! `ROUND_VERDICT:TOO_MANY_NUMERIC_SCALARS:` prefix from inside a message —
//! at worst a spoofed tail changes *which rejection* is reported, never
//! whether the document is rejected.
//!
//! **Keep [`VERDICT_EXPANDS_TOO_LARGE`], [`VERDICT_TOO_MANY_NUMERIC_SCALARS_PREFIX`]
//! and [`VERDICT_YAML_ERROR_PREFIX`] byte-for-byte identical to the copies
//! in `src/bin/round_yaml_parse_helper.rs`** — this module and that binary
//! are the two sides of the same protocol, deliberately not sharing a
//! `pub` constant (that would widen this crate's public surface for a
//! detail only these two files need).

use std::ffi::OsStr;
use std::path::PathBuf;
use std::time::Duration;

use roundhouse_sandbox::bounded_parse::{run_bounded_subprocess, BoundedParseError};

use super::{ParseError, YamlFailure};

/// See `src/bin/round_yaml_parse_helper.rs`'s copy — the two must match.
const VERDICT_EXPANDS_TOO_LARGE: &str = "ROUND_VERDICT:EXPANDS_TOO_LARGE";
/// See `src/bin/round_yaml_parse_helper.rs`'s copy — the two must match.
const VERDICT_TOO_MANY_NUMERIC_SCALARS_PREFIX: &str = "ROUND_VERDICT:TOO_MANY_NUMERIC_SCALARS:";
/// See `src/bin/round_yaml_parse_helper.rs`'s copy — the two must match.
const VERDICT_YAML_ERROR_PREFIX: &str = "ROUND_VERDICT:YAML_ERROR:";

/// The `[[bin]] name` in this crate's `Cargo.toml` (ruling W5-4's `round-`
/// prefix convention).
const HELPER_BINARY_NAME: &str = "round-yaml-parse-helper";

/// CPU-seconds allowed the helper (Linux only — see
/// `roundhouse_sandbox::bounded_parse`'s module doc for non-Linux
/// behaviour). Generous against any legitimate workflow — the frozen §8.9
/// fixture parses in microseconds — and small against the residual this
/// closes: `src/parse/mod.rs`'s axis inventory measures the worst
/// *admitted* document (one that already passed every in-process guard) at
/// ~9.4s release / double-digit seconds debug, which this cap kills at 2
/// CPU-seconds regardless.
const HELPER_CPU_LIMIT: Duration = Duration::from_secs(2);

/// Wall-clock allowed the helper — the only bound enforced on every
/// platform (ruling W5-3), and the backstop for a CPU-cheap stall (e.g.
/// blocked I/O) `RLIMIT_CPU` cannot see. Kept a few seconds above
/// [`HELPER_CPU_LIMIT`] so a CPU-bound child is normally caught by the
/// tighter, more specific bound first.
const HELPER_WALL_LIMIT: Duration = Duration::from_secs(5);

/// Ceiling on the helper's re-serialized YAML output. Deliberately well
/// above [`super::MAX_EXPANDED_WEIGHT`] (the ceiling on admitted expanded
/// weight, in the same rough units as re-serialized bytes) rather than
/// tuned tightly to it: this is a backstop against a compromised or buggy
/// helper emitting unbounded output, not the primary bound on document
/// size — that's `MAX_YAML_BYTES`, applied before this function is ever
/// called, plus `expansion::check_expansion` (Task 14 fix round 1, ruling
/// W5-20), applied by the helper itself before it re-serializes anything,
/// i.e. inside the same call this ceiling also bounds.
const HELPER_MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

/// Runs `yaml` through `round-yaml-parse-helper` under
/// `roundhouse_sandbox::bounded_parse::run_bounded_subprocess`, returning
/// the helper's re-serialized, alias-free YAML bytes on success. Never
/// parses in-process, on any error path — see the module doc comment.
pub(super) fn parse_via_helper(yaml: &str) -> Result<Vec<u8>, ParseError> {
    let helper_path = helper_binary_path()?;

    run_bounded_subprocess(
        &helper_path,
        &[] as &[&OsStr],
        yaml.as_bytes(),
        HELPER_CPU_LIMIT,
        HELPER_WALL_LIMIT,
        HELPER_MAX_OUTPUT_BYTES,
    )
    .map_err(|err| match err {
        BoundedParseError::Spawn { program, source } => {
            ParseError::HelperUnavailable(format!("failed to spawn {program}: {source}"))
        }
        BoundedParseError::HelperCrashed { stderr, .. } => map_helper_failure(yaml, &stderr),
        other @ (BoundedParseError::Timeout { .. }
        | BoundedParseError::ResourceExhausted { .. }
        | BoundedParseError::OutputTooLarge { .. }) => {
            ParseError::ExceededParseResourceBound(other)
        }
    })
}

/// Maps `round-yaml-parse-helper`'s stderr on a non-zero exit back to the
/// existing `ParseError` variant it names — see the module doc comment for
/// the wire format and why a spoofed message can only change which
/// rejection is reported, never whether the document is rejected.
fn map_helper_failure(yaml: &str, stderr: &str) -> ParseError {
    let text = stderr.trim_end_matches(['\n', '\r']);

    if text == VERDICT_EXPANDS_TOO_LARGE {
        return ParseError::ExpandsTooLarge {
            actual_bytes: yaml.len(),
            max: super::MAX_EXPANDED_WEIGHT,
        };
    }

    if let Some(kind) = text.strip_prefix(VERDICT_TOO_MANY_NUMERIC_SCALARS_PREFIX) {
        return match kind {
            "float" => ParseError::TooManyNumericScalars {
                kind: "float",
                max: super::MAX_FLOAT_SCALAR_VISITS,
            },
            "integer" => ParseError::TooManyNumericScalars {
                kind: "integer",
                max: super::MAX_INTEGER_SCALAR_VISITS,
            },
            // Defensive only: the helper (the only writer of this prefix)
            // never emits a third kind. Falls through to a plain Yaml
            // error rather than panicking on an untrusted child's output.
            other => ParseError::Yaml(YamlFailure::FromHelper {
                message: format!(
                    "round-yaml-parse-helper reported an unrecognised numeric-scalar kind {other:?}"
                ),
                location: None,
            }),
        };
    }

    if let Some(rest) = text.strip_prefix(VERDICT_YAML_ERROR_PREFIX) {
        // "<line-or-dash>:<col-or-dash>:<message>" — split into at most 3
        // parts so a colon inside the message itself (common in
        // `serde_yaml`'s own error text) is never mistaken for a field
        // separator.
        let mut parts = rest.splitn(3, ':');
        let line = parts.next().unwrap_or("-");
        let col = parts.next().unwrap_or("-");
        let message = parts.next().unwrap_or("").to_string();
        let location = match (line.parse::<usize>(), col.parse::<usize>()) {
            (Ok(l), Ok(c)) => Some((l, c)),
            _ => None,
        };
        return ParseError::Yaml(YamlFailure::FromHelper { message, location });
    }

    // Anything else is a plain human-readable message (e.g. the helper's
    // own re-serialization failure) — the same `HelperCrashed` handling
    // this crate had before fix round 1, just without a location.
    ParseError::Yaml(YamlFailure::FromHelper {
        message: text.to_string(),
        location: None,
    })
}

/// Resolves `round-yaml-parse-helper`'s path: a sibling of
/// [`std::env::current_exe`], following the same shape as
/// `crates/roundhouse-cli/src/commands/daemon.rs`'s `daemon_binary_path`
/// (canonicalize, then join the binary name) — no `$PATH` search, no
/// environment-variable override in production (ruling W5-4).
///
/// Under this crate's `test-util` feature *only*, additionally falls back
/// to the **grandparent** of `current_exe()`: a `tests/*.rs` integration
/// test binary lives in `target/debug/deps/`, whose *sibling* directory is
/// still `target/debug/deps/` (where no `[[bin]]` output is ever placed),
/// but whose *grandparent* is `target/debug/` — exactly where Cargo places
/// `round-yaml-parse-helper`. This is what keeps the existing fixture
/// tests under `tests/` passing with zero edits.
///
/// **The fallback is gated by [`is_inside_a_target_tree`], not
/// `debug_assertions` (ruling W5-25, finding 4).** `test-util` is not a
/// default feature, so an ordinary `cargo build --release` never compiles
/// this branch in at all — but `cargo build --release --all-features` is a
/// plausible packaging command that does, and release test builds are
/// real, so gating on `debug_assertions` would not have closed this.
/// Without the containment check, an absent sibling in that build would
/// resolve the fallback to the *installed* binary's own grandparent — e.g.
/// `/usr/local/round-yaml-parse-helper` for a binary installed to
/// `/usr/local/bin`, and `/usr/local` is group/user-writable on
/// Homebrew-style installs, making an absent file there a foothold for a
/// substituted helper. Requiring the resolved candidate to sit inside a
/// `target` tree is what the fallback is actually for; anywhere else, it
/// declines rather than trusting the path.
fn helper_binary_path() -> Result<PathBuf, ParseError> {
    let exe = std::env::current_exe().map_err(|err| {
        ParseError::HelperUnavailable(format!("could not resolve current_exe(): {err}"))
    })?;
    let exe = std::fs::canonicalize(&exe).map_err(|err| {
        ParseError::HelperUnavailable(format!(
            "could not canonicalize current_exe() {}: {err}",
            exe.display()
        ))
    })?;
    let dir = exe.parent().ok_or_else(|| {
        ParseError::HelperUnavailable(format!(
            "{} has no parent directory; cannot locate {HELPER_BINARY_NAME}",
            exe.display()
        ))
    })?;

    let sibling = dir.join(HELPER_BINARY_NAME);
    if sibling.is_file() {
        return Ok(sibling);
    }

    #[cfg(feature = "test-util")]
    {
        if let Some(grandparent) = dir.parent() {
            let candidate = grandparent.join(HELPER_BINARY_NAME);
            if candidate.is_file() && is_inside_a_target_tree(&candidate) {
                return Ok(candidate);
            }
        }
    }

    Err(ParseError::HelperUnavailable(format!(
        "{HELPER_BINARY_NAME} not found next to {} (or, under the test-util feature, in its \
         parent directory) — is roundhouse built/installed correctly?",
        exe.display()
    )))
}

/// True if `path` has a path component literally named `target` — see
/// [`helper_binary_path`]'s doc for why the `test-util` fallback candidate
/// must clear this before being trusted (ruling W5-25, finding 4). Cargo's
/// build output always sits under a `target/` root regardless of profile
/// or workspace layout, so this is a cheap, name-based containment check
/// rather than a hardcoded absolute path — it stays correct for any
/// `CARGO_TARGET_DIR` and any workspace nesting depth.
///
/// **Its boundary, written down rather than left to be inferred (ruling
/// W5-28, item 5).** Being name-based, it accepts *any* canonical path with
/// a component literally named `target` — including an install prefix that
/// happens to contain one, e.g. a binary installed to `/opt/target/bin/`.
/// Such a layout would re-open the very `test-util` fallback this check
/// exists to close. That is accepted, not overlooked, and the heuristic is
/// deliberately **not** tightened: reaching it needs that unusual install
/// layout *and* a build with the non-default `test-util` feature compiled in
/// *and* an attacker-writable absent sibling at the fallback location, and
/// ruling W5-25 asked for exactly this cheap containment check rather than a
/// stricter one. A stricter alternative (matching Cargo's own target
/// directory rather than the name) would be the fix if the threat model ever
/// changes; today it would buy nothing over the three conditions above.
#[cfg(feature = "test-util")]
fn is_inside_a_target_tree(path: &std::path::Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == std::ffi::OsStr::new("target"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // These pin `map_helper_failure`'s wire-format parsing directly —
    // nothing in `tests/*.rs` exercises this function on its own, since
    // every fixture test that reaches `TooManyNumericScalars` accepts
    // `TooManyNumericScalars | ExpandsTooLarge` and so would not notice a
    // `"float"` -> `MAX_INTEGER_SCALAR_VISITS` mix-up. `yaml` only matters
    // for its `.len()` in the `EXPANDS_TOO_LARGE` case, so an empty string
    // is fine everywhere else.

    #[test]
    fn expands_too_large_tag_reconstructs_actual_bytes_from_the_caller_and_max_from_the_constant() {
        let yaml = "0123456789";
        let err = map_helper_failure(yaml, VERDICT_EXPANDS_TOO_LARGE);
        match err {
            ParseError::ExpandsTooLarge { actual_bytes, max } => {
                assert_eq!(actual_bytes, yaml.len());
                assert_eq!(max, super::super::MAX_EXPANDED_WEIGHT);
            }
            other => panic!("expected ExpandsTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn expands_too_large_tag_tolerates_a_trailing_newline() {
        let text = format!("{VERDICT_EXPANDS_TOO_LARGE}\n");
        assert!(matches!(
            map_helper_failure("", &text),
            ParseError::ExpandsTooLarge { .. }
        ));
    }

    #[test]
    fn float_kind_maps_to_the_float_ceiling_not_the_integer_one() {
        let text = format!("{VERDICT_TOO_MANY_NUMERIC_SCALARS_PREFIX}float");
        match map_helper_failure("", &text) {
            ParseError::TooManyNumericScalars { kind, max } => {
                assert_eq!(kind, "float");
                assert_eq!(max, super::super::MAX_FLOAT_SCALAR_VISITS);
                assert_ne!(max, super::super::MAX_INTEGER_SCALAR_VISITS);
            }
            other => panic!("expected TooManyNumericScalars, got {other:?}"),
        }
    }

    #[test]
    fn integer_kind_maps_to_the_integer_ceiling_not_the_float_one() {
        let text = format!("{VERDICT_TOO_MANY_NUMERIC_SCALARS_PREFIX}integer");
        match map_helper_failure("", &text) {
            ParseError::TooManyNumericScalars { kind, max } => {
                assert_eq!(kind, "integer");
                assert_eq!(max, super::super::MAX_INTEGER_SCALAR_VISITS);
                assert_ne!(max, super::super::MAX_FLOAT_SCALAR_VISITS);
            }
            other => panic!("expected TooManyNumericScalars, got {other:?}"),
        }
    }

    #[test]
    fn an_unrecognised_numeric_scalar_kind_falls_back_to_a_plain_yaml_error_rather_than_panicking()
    {
        let text = format!("{VERDICT_TOO_MANY_NUMERIC_SCALARS_PREFIX}complex");
        match map_helper_failure("", &text) {
            ParseError::Yaml(YamlFailure::FromHelper { message, location }) => {
                assert!(message.contains("complex"));
                assert_eq!(location, None);
            }
            other => panic!("expected a fallback Yaml error, got {other:?}"),
        }
    }

    #[test]
    fn yaml_error_tag_with_digits_reconstructs_a_location() {
        let text = format!("{VERDICT_YAML_ERROR_PREFIX}4:7:did not find expected ',' or '}}'");
        match map_helper_failure("", &text) {
            ParseError::Yaml(YamlFailure::FromHelper { message, location }) => {
                assert_eq!(location, Some((4, 7)));
                assert_eq!(message, "did not find expected ',' or '}'");
            }
            other => panic!("expected a Yaml error with a location, got {other:?}"),
        }
    }

    #[test]
    fn yaml_error_tag_with_dashes_reconstructs_no_location() {
        let text = format!("{VERDICT_YAML_ERROR_PREFIX}-:-:some message with no position");
        match map_helper_failure("", &text) {
            ParseError::Yaml(YamlFailure::FromHelper { message, location }) => {
                assert_eq!(location, None);
                assert_eq!(message, "some message with no position");
            }
            other => panic!("expected a Yaml error with no location, got {other:?}"),
        }
    }

    #[test]
    fn a_colon_inside_the_yaml_error_message_does_not_get_mistaken_for_a_field_separator() {
        let text =
            format!("{VERDICT_YAML_ERROR_PREFIX}2:9:mapping values are not allowed here: extra");
        match map_helper_failure("", &text) {
            ParseError::Yaml(YamlFailure::FromHelper { message, location }) => {
                assert_eq!(location, Some((2, 9)));
                assert_eq!(message, "mapping values are not allowed here: extra");
            }
            other => panic!("expected the message to keep its embedded colon, got {other:?}"),
        }
    }

    #[test]
    fn plain_untagged_text_falls_through_to_a_location_less_yaml_error() {
        match map_helper_failure(
            "",
            "round-yaml-parse-helper: failed to re-serialize expanded YAML: some inner cause",
        ) {
            ParseError::Yaml(YamlFailure::FromHelper { message, location }) => {
                assert_eq!(location, None);
                assert_eq!(
                    message,
                    "round-yaml-parse-helper: failed to re-serialize expanded YAML: some inner cause"
                );
            }
            other => panic!("expected a plain fallback Yaml error, got {other:?}"),
        }
    }

    // Ruling W5-25, finding 4: pins `is_inside_a_target_tree`'s containment
    // check directly, so a future edit can't silently widen it back into
    // trusting an arbitrary grandparent path.
    #[cfg(feature = "test-util")]
    #[test]
    fn a_target_tree_path_is_accepted() {
        assert!(is_inside_a_target_tree(std::path::Path::new(
            "/home/me/repo/target/debug/round-yaml-parse-helper"
        )));
    }

    #[cfg(feature = "test-util")]
    #[test]
    fn an_installed_path_outside_any_target_tree_is_rejected() {
        assert!(!is_inside_a_target_tree(std::path::Path::new(
            "/usr/local/round-yaml-parse-helper"
        )));
    }
}
