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

/// The expected internal (`roundhouse-*`) dependency edges for each real
/// workspace crate, matching `docs/architecture/02-system-architecture.md`
/// §5.2's crate-dependency table as corrected by the final Phase 2
/// whole-branch-review cleanup. This is a deliberate, hardcoded mirror of
/// that table — not derived from it — so a future edit to either the table
/// or a crate's real `Cargo.toml` dependencies that isn't also reflected
/// here fails this test loudly, the way doc drift like the one this test
/// was added to catch should have been caught before it could land.
///
/// `xtask` itself and `roundhouse-core` (no internal deps) are omitted —
/// `roundhouse-core`'s empty edge set is still checked via `expect(&[])`
/// falling out of `.unwrap_or(&[])` below for any crate not listed here
/// with a nonempty real dependency set, so leaving it out is fine, but it's
/// listed explicitly for clarity.
const EXPECTED_EDGES: &[(&str, &[&str])] = &[
    ("roundhouse-core", &[]),
    ("roundhouse-proto", &["roundhouse-core"]),
    (
        "roundhouse-store",
        &["roundhouse-core", "roundhouse-provider"],
    ),
    (
        "roundhouse-policy",
        &["roundhouse-core", "roundhouse-store"],
    ),
    ("roundhouse-sandbox", &["roundhouse-core"]),
    ("roundhouse-provider", &["roundhouse-core"]),
    // Deliberate, authorized addition (Phase 6 Task 3): the shared
    // provider-adapter conformance suite (§9.10) depends on
    // `roundhouse-provider` for the `Provider`/IR types it exercises and on
    // `roundhouse-core` for `Usage` (which is not re-exported from
    // `roundhouse-provider`'s crate root). `roundhouse-provider` only
    // *dev*-depends back (see its own Cargo.toml comment), so this edge
    // stays acyclic.
    (
        "roundhouse-conformance",
        &["roundhouse-core", "roundhouse-provider"],
    ),
    (
        "roundhouse-tools",
        &[
            "roundhouse-core",
            "roundhouse-sandbox",
            "roundhouse-policy",
            "roundhouse-net",
        ],
    ),
    // `roundhouse-provider` below is a deliberate, authorized addition
    // (Task 1, Phase 3; plan correction dated 2026-08-28) — `ContentBlock`/
    // `MediaSource` live in `roundhouse-provider` (src/ir.rs), not
    // `roundhouse-core`, and the doc table row was updated in the same
    // commit per this test's keep-both-in-sync rule.
    (
        "roundhouse-mcp",
        &[
            "roundhouse-core",
            "roundhouse-policy",
            "roundhouse-provider",
        ],
    ),
    ("roundhouse-acp", &["roundhouse-core", "roundhouse-proto"]),
    ("roundhouse-bus", &["roundhouse-core"]),
    (
        "roundhouse-engine",
        &[
            "roundhouse-core",
            "roundhouse-store",
            "roundhouse-policy",
            "roundhouse-net",
            "roundhouse-sandbox",
            "roundhouse-provider",
            "roundhouse-bus",
        ],
    ),
    ("roundhouse-config", &[]),
    // `roundhouse-provider` below is a deliberate, authorized addition
    // (Phase 6 Task 2) — the six concrete `CredentialProvider`
    // implementations (§9.9) live here and implement
    // `roundhouse_provider::credential::CredentialProvider` directly;
    // acyclic because this crate already reaches `roundhouse-provider`
    // transitively through the `roundhouse-store` edge below.
    (
        "roundhouse-secrets",
        &[
            "roundhouse-config",
            "roundhouse-core",
            "roundhouse-provider",
            "roundhouse-store",
        ],
    ),
    (
        "roundhouse-flow",
        &["roundhouse-core", "roundhouse-engine", "roundhouse-store"],
    ),
    // `roundhouse-bus` below is a deliberate, authorized addition (Task 1,
    // Phase 5, Subsystem A): a `Message` trigger's `Binding` doubles as the
    // addressable recipient for a bus mailbox, and Task 4's
    // `bind_message_trigger`/`poll_message_trigger` call the `Bus` trait
    // directly — the doc table row was updated in the same commit per this
    // test's keep-both-in-sync rule.
    (
        "roundhouse-sched",
        &[
            "roundhouse-core",
            "roundhouse-engine",
            "roundhouse-store",
            "roundhouse-bus",
        ],
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
            "roundhouse-config",
            "roundhouse-tui",
        ],
    ),
    ("roundhouse-tui", &["roundhouse-proto"]),
    ("roundhouse-cli", &["roundhouse-proto", "roundhouse-tui"]),
    // Phase 5 Task 31 (Subsystem D2): `roundhouse-core` is a deliberate,
    // tracked deviation from this table's original `proto`-only row for
    // `roundhouse-web`, authorised by ruling P9. §11.3's SSE cursor is
    // `(session_id, seq)` and `SessionId` lives in `roundhouse-core`;
    // `roundhouse-proto` uses it without re-exporting it. See
    // `crates/roundhouse-web/Cargo.toml`'s own comment on the edge.
    // Phase 5 Task 34 (Subsystem D5): `roundhouse-flow` and `roundhouse-store`
    // join `roundhouse-core` as tracked deviations from the original
    // `proto`-only row, on the same ruling P9. §8.6's Runs inbox query lives in
    // `roundhouse-flow` (ruling P86 — it already owns `WorkflowRun`/`Report`
    // and the `roundhouse-store` edge, so this crate writes no SQL), and
    // `AppState` carries a `roundhouse_store::StorePool`. See
    // `crates/roundhouse-web/Cargo.toml`'s own comments on both edges.
    (
        "roundhouse-web",
        &[
            "roundhouse-core",
            "roundhouse-flow",
            "roundhouse-proto",
            "roundhouse-store",
        ],
    ),
    ("roundhouse-net", &["roundhouse-core", "roundhouse-store"]),
];

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
fn crate_dependency_edges_match_the_architecture_doc() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();

    for (crate_name, expected_edges) in EXPECTED_EDGES {
        let manifest_path = root.join("crates").join(crate_name).join("Cargo.toml");
        let mut expected: Vec<String> = expected_edges.iter().map(|s| s.to_string()).collect();
        expected.sort();
        let actual = real_internal_deps(&manifest_path);
        assert_eq!(
            actual, expected,
            "{crate_name}'s real Cargo.toml roundhouse-* dependencies {actual:?} do not \
             match the expected edges {expected:?} (kept in sync with \
             docs/architecture/02-system-architecture.md §5.2 — update EXPECTED_EDGES here \
             AND that table together, never one without the other)"
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
