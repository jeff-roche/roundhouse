use std::fs;
use std::path::Path;
use std::process::Command;

/// §13.2's Phase 0 exit criterion, verified directly rather than taken on
/// faith: "every downstream crate compiles against stub implementations of
/// these traits." `cargo check --workspace` alone is not sufficient proof —
/// an empty crate skeleton with no dependencies and an empty `lib.rs` also
/// compiles trivially, so a compile-only check would keep passing even if
/// the wiring in this task were reverted. This test therefore has two legs:
/// (1) each downstream crate's `Cargo.toml` actually declares the
/// dependency edges §5.2 requires, and (2) the whole workspace, including
/// all targets, compiles. Only both together are the real exit criterion.
#[test]
fn downstream_crates_declare_required_dependency_edges() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();

    // (crate, required path-dependency edges per §5.2 / this task's brief)
    const REQUIRED_EDGES: &[(&str, &[&str])] = &[
        (
            "roundhouse-tools",
            &["roundhouse-core", "roundhouse-sandbox", "roundhouse-policy"],
        ),
        ("roundhouse-mcp", &["roundhouse-core", "roundhouse-policy"]),
        ("roundhouse-acp", &["roundhouse-core", "roundhouse-proto"]),
        (
            "roundhouse-engine",
            &[
                "roundhouse-core",
                "roundhouse-store",
                "roundhouse-policy",
                "roundhouse-sandbox",
                "roundhouse-provider",
                "roundhouse-bus",
            ],
        ),
        (
            "roundhouse-flow",
            &["roundhouse-core", "roundhouse-engine", "roundhouse-store"],
        ),
        (
            "roundhouse-sched",
            &["roundhouse-core", "roundhouse-engine", "roundhouse-store"],
        ),
        (
            "roundhouse-daemon",
            &[
                "roundhouse-core",
                "roundhouse-proto",
                "roundhouse-store",
                "roundhouse-policy",
                "roundhouse-sandbox",
                "roundhouse-provider",
                "roundhouse-tools",
                "roundhouse-mcp",
                "roundhouse-acp",
                "roundhouse-bus",
                "roundhouse-engine",
                "roundhouse-flow",
                "roundhouse-sched",
            ],
        ),
        ("roundhouse-tui", &["roundhouse-proto"]),
        // Deliberately NOT roundhouse-daemon: §5.2's non-negotiable rule is
        // that nothing depends on roundhouse-daemon or roundhouse-cli as a
        // Cargo edge (see this task's brief for the resolved ambiguity).
        ("roundhouse-cli", &["roundhouse-proto", "roundhouse-tui"]),
        ("roundhouse-web", &["roundhouse-proto"]),
    ];

    for (krate, required_deps) in REQUIRED_EDGES {
        let manifest_path = workspace_root.join("crates").join(krate).join("Cargo.toml");
        let manifest = fs::read_to_string(&manifest_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", manifest_path.display()));
        let parsed: toml::Value = manifest
            .parse()
            .unwrap_or_else(|e| panic!("parse {}: {e}", manifest_path.display()));
        let deps_table = parsed
            .get("dependencies")
            .and_then(|d| d.as_table())
            .unwrap_or_else(|| panic!("{krate}'s Cargo.toml has no [dependencies] table"));

        for dep in *required_deps {
            assert!(
                deps_table.contains_key(*dep),
                "{krate}'s Cargo.toml [dependencies] is missing required edge `{dep}` \
                 (§5.2 dependency table) — cargo check succeeding alone does not prove \
                 the wiring exists, since an unwired crate also compiles trivially"
            );
        }
    }
}

/// The other leg of the exit criterion: `cargo check --workspace` is the
/// literal check §13.2 names; this test shells out to it so the exit
/// criterion has its own CI-visible pass/fail, not just an implicit side
/// effect of other tests passing.
#[test]
fn cargo_check_workspace_succeeds() {
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let status = Command::new("cargo")
        .arg("check")
        .arg("--workspace")
        .arg("--all-targets")
        .current_dir(workspace_root)
        .status()
        .expect("cargo must be on PATH");
    assert!(
        status.success(),
        "cargo check --workspace --all-targets must succeed (Phase 0 exit criterion, §13.2)"
    );
}
