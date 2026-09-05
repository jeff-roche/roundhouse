//! `round-yaml-parse-helper`: the out-of-process YAML-parsing helper Task 14
//! (lane W5) spawns from `roundhouse_flow::parse::helper` under
//! `roundhouse_sandbox::bounded_parse::run_bounded_subprocess`'s CPU/
//! wall-clock/output-size bound. See `crate::parse::mod`'s module doc
//! comment for why this exists and what it closes.
//!
//! Does nothing but: read stdin to EOF, `serde_yaml::from_slice` it into a
//! `serde_yaml::Value`, and write that value back out as YAML. Deliberately
//! that — not a JSON round trip — because `WorkflowDef` carries raw
//! `serde_yaml::Value` fields (`steps`/`catch`/`finally`); round-tripping
//! through `serde_yaml` on both ends means those fields are always
//! populated from YAML, never silently switched to a JSON-sourced
//! `Deserialize` path. Deserializing into a `Value` and re-serializing is
//! also what actually pays (and confines) the expensive part: `serde_yaml`
//! deserialization is what walks and materializes every anchor/alias
//! expansion, and a `Value` carries no anchors or aliases of its own once
//! built, so the parent's own `serde_yaml::from_slice::<WorkflowDef>` on
//! this binary's stdout is a plain linear parse of an alias-free document,
//! not a second unmetered walk of the original alias structure.
//!
//! Exit code 0: stdout carries the re-serialized, alias-free YAML.
//! Exit code 1: stdin was not valid YAML (or, in the rarer
//! re-serialization-failure case, something in-tree does not round-trip);
//! stderr carries a human-readable message. `roundhouse_flow::parse::helper`
//! reconstructs a `serde_yaml::Error` from that message via
//! `serde::de::Error::custom`, so a helper-side syntax error surfaces to
//! callers exactly like an in-process one (`ParseError::Yaml`).
//!
//! Kept dependency-free beyond what `roundhouse-flow` already links for
//! parsing (`serde_yaml`): no `tokio`, and deliberately no
//! `roundhouse-sandbox` — the sandbox crate is what spawns and bounds this
//! binary; this binary has no business knowing that.

use std::io::{self, Read, Write};

fn main() {
    let mut input = Vec::new();
    if let Err(err) = io::stdin().lock().read_to_end(&mut input) {
        eprintln!("round-yaml-parse-helper: failed to read stdin: {err}");
        std::process::exit(1);
    }

    let value: serde_yaml::Value = match serde_yaml::from_slice(&input) {
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
