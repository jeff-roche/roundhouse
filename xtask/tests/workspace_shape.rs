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
    // `crates/roundhouse-conformance` below is a deliberate, authorized
    // addition (Phase 6 Task 3) — the shared provider-adapter conformance
    // suite (§9.10), now an official row in the architecture doc's crate
    // table (`docs/architecture/02-system-architecture.md` §5.2), not an
    // accidental extra member. A prior version of that table carried this
    // row before the crate existed and had it removed pending Task 3; this
    // re-adds it now that the crate is real.
    "crates/roundhouse-conformance",
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

/// Reads `path`'s `[dependencies]` table and returns the sorted names of
/// every `roundhouse-*` dependency it declares. A straightforward
/// TOML-parsing check, consistent with `workspace_lists_all_expected_crates`
/// above, rather than anything fancier — this only needs to catch drift
/// between the architecture doc's dependency table and each crate's real
/// `Cargo.toml`, not model Cargo's full dependency resolution.
fn real_internal_deps(manifest_path: &Path) -> Vec<String> {
    let manifest = fs::read_to_string(manifest_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", manifest_path.display()));
    let parsed: toml::Value = manifest
        .parse()
        .unwrap_or_else(|e| panic!("parse {}: {e}", manifest_path.display()));
    let mut deps: Vec<String> = parsed
        .get("dependencies")
        .and_then(|d| d.as_table())
        .map(|table| {
            table
                .keys()
                .filter(|name| name.starts_with("roundhouse-"))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    deps.sort();
    deps
}

#[test]
fn the_architecture_doc_table_itself_not_just_a_hardcoded_mirror_of_it_matches_real_cargo_toml_deps(
) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let doc_path = root.join("docs/architecture/02-system-architecture.md");
    let doc_text = fs::read_to_string(&doc_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", doc_path.display()));
    let parsed = xtask::doc_table_parser::parse_dependency_table(&doc_text)
        .expect("§5.2's table should parse cleanly");

    for (crate_name, doc_deps) in &parsed {
        let manifest_path = root.join("crates").join(crate_name).join("Cargo.toml");
        let real_deps = real_internal_deps(&manifest_path);
        let mut doc_deps_sorted = doc_deps.clone();
        doc_deps_sorted.sort();
        assert_eq!(
            doc_deps_sorted, real_deps,
            "{crate_name}'s doc-table dependency set {doc_deps_sorted:?} does not match its \
             real Cargo.toml roundhouse-* dependencies {real_deps:?}"
        );
    }

    // Coverage: every workspace member under `crates/` must have a row in
    // the doc table, so a newly added crate without a table row fails
    // loudly instead of silently escaping this guard.
    for member in EXPECTED_MEMBERS {
        if *member == "xtask" {
            // `xtask` is a workspace member but is not a `crates/` member
            // and has no row in §5.2's table — excluded explicitly and by
            // name (not by a `starts_with("crates/")` filter, which could
            // also hide a future non-`crates/`, non-`xtask` member that
            // should have a row and doesn't).
            continue;
        }
        let crate_name = member
            .strip_prefix("crates/")
            .unwrap_or_else(|| panic!("unexpected EXPECTED_MEMBERS entry {member}"));
        assert!(
            parsed.contains_key(crate_name),
            "{crate_name} is a workspace member under crates/ but has no row in \
             docs/architecture/02-system-architecture.md §5.2's table"
        );
    }
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
