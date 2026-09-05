//! `round-yaml-parse-helper`: the out-of-process YAML-parsing helper Task 14
//! (lane W5) spawns from `roundhouse_flow::parse::helper` under
//! `roundhouse_sandbox::bounded_parse::run_bounded_subprocess`'s CPU/
//! wall-clock/output-size bound. See `crate::parse::mod`'s module doc
//! comment for why this exists and what it closes.
//!
//! Reads stdin to EOF, then:
//!
//! 1. **Task 14 fix round 1 (ruling W5-20):** runs
//!    [`roundhouse_flow::parse::check_expansion`] — the same fast-path
//!    expansion-weight guard `parse_workflow` used to call directly, before
//!    this binary existed. It moved here because it is itself a real
//!    `serde_yaml` walk over attacker-controlled input (builds a real
//!    `serde_yaml::Deserializer` and drives `deserialize_any`), so leaving
//!    it in the daemon's own process left half of the DoS this task exists
//!    to close unbounded. See `expansion`'s module doc for the mechanism
//!    and `parse::helper`'s module doc for the verdict wire format below.
//! 2. On `Verdict::WithinBudget`, `serde_yaml::from_str`s stdin into a
//!    `serde_yaml::Value` and writes it back out re-serialized as YAML.
//!    Deliberately that — not a JSON round trip — because `WorkflowDef`
//!    carries raw `serde_yaml::Value` fields (`steps`/`catch`/`finally`);
//!    round-tripping through `serde_yaml` on both ends means those fields
//!    are always populated from YAML, never silently switched to a
//!    JSON-sourced `Deserialize` path. Deserializing into a `Value` and
//!    re-serializing is also what actually pays (and confines) the
//!    expensive part: `serde_yaml` deserialization is what walks and
//!    materializes every anchor/alias expansion, and a `Value` carries no
//!    anchors or aliases of its own once built, so the parent's own
//!    `serde_yaml::from_slice::<WorkflowDef>` on this binary's stdout is a
//!    plain linear parse of an alias-free document, not a second unmetered
//!    walk of the original alias structure.
//!
//! # Exit codes and the verdict protocol
//!
//! Exit code 0: stdout carries the re-serialized, alias-free YAML.
//! Exit code 1: the document was rejected, for one of the reasons named by
//! a one-line tagged prefix on stderr — see
//! `roundhouse_flow::parse::helper`'s module doc comment for the exact
//! format and why `roundhouse_flow::parse::helper::parse_via_helper` (the
//! parent-side half of this protocol) can map a spoofed tail to a
//! different rejection but never to acceptance.
//!
//! # Dependencies
//!
//! Links `roundhouse_flow`'s library (for [`roundhouse_flow::parse::check_expansion`]
//! and [`roundhouse_flow::parse::Verdict`] — the whole point of fix round 1
//! is that this binary calls the *one* implementation of the guard rather
//! than a second copy of it) and, transitively through that, everything
//! `roundhouse-flow` itself depends on, `roundhouse-sandbox` included. No
//! `tokio`: nothing this binary does needs it.

use std::io::{self, Read, Write};

use roundhouse_flow::parse::{check_expansion, Verdict, MAX_EXPANDED_WEIGHT};

/// See `roundhouse_flow::parse::helper`'s copy — the two must match.
const VERDICT_EXPANDS_TOO_LARGE: &str = "ROUND_VERDICT:EXPANDS_TOO_LARGE";
/// See `roundhouse_flow::parse::helper`'s copy — the two must match.
const VERDICT_TOO_MANY_NUMERIC_SCALARS_PREFIX: &str = "ROUND_VERDICT:TOO_MANY_NUMERIC_SCALARS:";
/// See `roundhouse_flow::parse::helper`'s copy — the two must match.
const VERDICT_YAML_ERROR_PREFIX: &str = "ROUND_VERDICT:YAML_ERROR:";

fn main() {
    let mut input = Vec::new();
    if let Err(err) = io::stdin().lock().read_to_end(&mut input) {
        eprintln!("round-yaml-parse-helper: failed to read stdin: {err}");
        std::process::exit(1);
    }

    // `check_expansion` takes `&str`; every real caller
    // (`roundhouse_flow::parse::parse_workflow`) hands this binary the
    // bytes of an already-valid `&str`, so invalid UTF-8 here means
    // something upstream is broken, not a document shape this protocol
    // needs a dedicated tag for — it falls through to the same untagged,
    // location-less error path as any other unexpected failure.
    let yaml = match std::str::from_utf8(&input) {
        Ok(yaml) => yaml,
        Err(err) => {
            eprintln!("round-yaml-parse-helper: stdin is not valid UTF-8: {err}");
            std::process::exit(1);
        }
    };

    match check_expansion(yaml, MAX_EXPANDED_WEIGHT) {
        Verdict::WithinBudget => {}
        Verdict::TooManyNumericScalars { kind, .. } => {
            eprintln!("{VERDICT_TOO_MANY_NUMERIC_SCALARS_PREFIX}{kind}");
            std::process::exit(1);
        }
        Verdict::OverBudget => {
            eprintln!("{VERDICT_EXPANDS_TOO_LARGE}");
            std::process::exit(1);
        }
        Verdict::Malformed(err) => {
            // `serde_yaml::Error` cannot cross the process boundary (no
            // public constructor reattaches a `Location` to a bare
            // message — see `parse::helper`'s module doc), so the line and
            // column, when there are any, are sent as plain integers ahead
            // of the message text rather than losing them.
            match err.location() {
                Some(loc) => {
                    eprintln!(
                        "{VERDICT_YAML_ERROR_PREFIX}{}:{}:{err}",
                        loc.line(),
                        loc.column()
                    );
                }
                None => eprintln!("{VERDICT_YAML_ERROR_PREFIX}-:-:{err}"),
            }
            std::process::exit(1);
        }
    }

    let value: serde_yaml::Value = match serde_yaml::from_str(yaml) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };

    let output = match serde_yaml::to_string(&value) {
        Ok(output) => output,
        Err(err) => {
            eprintln!("round-yaml-parse-helper: failed to re-serialize expanded YAML: {err}");
            std::process::exit(1);
        }
    };

    if let Err(err) = io::stdout().lock().write_all(output.as_bytes()) {
        eprintln!("round-yaml-parse-helper: failed to write stdout: {err}");
        std::process::exit(1);
    }
}
