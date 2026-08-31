use std::fs;
use std::path::Path;

// This is a frozen-shape guard: its entire purpose is catching
// UNAUTHORIZED changes to the workspace's crate list, so an edit to this
// list is itself something that should draw attention, not slip through
// quietly. `crates/roundhouse-secrets` below is a deliberate, authorized
// addition (Task 18) — it's now an official row in the architecture doc's
// crate table (`docs/architecture/02-system-architecture.md` §5.2), not an
// accidental extra member. Any other change to this list should be treated
// with the same scrutiny this comment is calling out for that one.
const EXPECTED_MEMBERS: &[&str] = &[
    "crates/roundhouse-core",
    "crates/roundhouse-proto",
    "crates/roundhouse-store",
    "crates/roundhouse-policy",
    "crates/roundhouse-secrets",
    "crates/roundhouse-sandbox",
    "crates/roundhouse-provider",
    "crates/roundhouse-tools",
    "crates/roundhouse-mcp",
    "crates/roundhouse-acp",
    "crates/roundhouse-bus",
    "crates/roundhouse-engine",
    "crates/roundhouse-config",
    "crates/roundhouse-flow",
    "crates/roundhouse-sched",
    "crates/roundhouse-daemon",
    "crates/roundhouse-tui",
    "crates/roundhouse-cli",
    "crates/roundhouse-web",
    // `crates/roundhouse-net` below is a deliberate, authorized addition
    // (Task 23, Phase 2) — the daemon-owned network egress boundary (§6.6),
    // now an official row in the architecture doc's crate table
    // (`docs/architecture/02-system-architecture.md` §5.2), not an
    // accidental extra member.
    "crates/roundhouse-net",
    "xtask",
];

#[test]
fn workspace_lists_all_expected_crates() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("read root Cargo.toml");
    let parsed: toml::Value = manifest.parse().expect("parse root Cargo.toml");
    let members = parsed["workspace"]["members"]
        .as_array()
        .expect("workspace.members must be an array")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    for expected in EXPECTED_MEMBERS {
        assert!(
            members.iter().any(|m| m == expected),
            "workspace.members is missing {expected}"
        );
    }
    assert_eq!(
        members.len(),
        EXPECTED_MEMBERS.len(),
        "unexpected extra/missing member"
    );
}

#[test]
fn workspace_forbids_unsafe_code_by_default() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("read root Cargo.toml");
    let parsed: toml::Value = manifest.parse().expect("parse root Cargo.toml");
    assert_eq!(
        parsed["workspace"]["lints"]["rust"]["unsafe_code"].as_str(),
        Some("forbid"),
        "workspace.lints.rust.unsafe_code must be \"forbid\""
    );
}
