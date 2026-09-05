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
/// above [`super::MAX_EXPANDED_WEIGHT`] (the in-process ceiling on
/// admitted expanded weight, in the same rough units as re-serialized
/// bytes) rather than tuned tightly to it: this is a backstop against a
/// compromised or buggy helper emitting unbounded output, not the primary
/// bound on document size — that's `MAX_YAML_BYTES` plus the expansion
/// checks, both already applied before this function is ever called.
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
            if candidate.is_file() {
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
