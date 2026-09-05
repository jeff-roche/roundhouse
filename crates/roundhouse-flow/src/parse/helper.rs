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

use std::ffi::OsStr;
use std::path::PathBuf;
use std::time::Duration;

use roundhouse_sandbox::bounded_parse::{run_bounded_subprocess, BoundedParseError};

use super::ParseError;

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
        BoundedParseError::HelperCrashed { stderr, .. } => {
            // The helper's only reason to exit non-zero is invalid YAML
            // (see `src/bin/round_yaml_parse_helper.rs`) — reconstructed
            // via `serde::de::Error::custom` so a helper-side syntax error
            // surfaces identically to an in-process one.
            use serde::de::Error as _;
            ParseError::Yaml(serde_yaml::Error::custom(stderr))
        }
        other @ (BoundedParseError::Timeout { .. }
        | BoundedParseError::ResourceExhausted { .. }
        | BoundedParseError::OutputTooLarge { .. }) => {
            ParseError::ExceededParseResourceBound(other)
        }
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
