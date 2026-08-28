use std::fs;
use std::path::Path;

const EXPECTED_MEMBERS: &[&str] = &[
    "crates/roundhouse-core",
    "crates/roundhouse-proto",
    "crates/roundhouse-store",
    "crates/roundhouse-policy",
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
];

#[test]
fn workspace_lists_all_eighteen_crates() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
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
    assert_eq!(members.len(), EXPECTED_MEMBERS.len(), "unexpected extra/missing member");
}

#[test]
fn workspace_forbids_unsafe_code_by_default() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("read root Cargo.toml");
    let parsed: toml::Value = manifest.parse().expect("parse root Cargo.toml");
    assert_eq!(
        parsed["workspace"]["lints"]["rust"]["unsafe_code"].as_str(),
        Some("forbid"),
        "workspace.lints.rust.unsafe_code must be \"forbid\""
    );
}
