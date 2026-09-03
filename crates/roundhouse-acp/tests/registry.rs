//! Task C8 (G7 part 2): consuming `agentclientprotocol/registry` instead of
//! a hardcoded launch-config table.
//!
//! Deliberately deviates from the task brief's literal test bodies where the
//! coordinator's rulings (`ACP-REGISTRY-FORMAT.md`, Ruling C-P13 in
//! particular) override it:
//! - `distribution` is modeled as a struct of the three real shapes
//!   (`npx`/`uvx`/`binary`), not the brief's flattened `{command, args}` —
//!   verified against the live index, two real agents (`kilo`, `sigit`)
//!   publish *both* `binary` and `npx` simultaneously, so a strictly
//!   mutually-exclusive enum at the per-agent field would reject real data.
//!   `resolve_launch` is what returns the single, mutually-exclusive
//!   `LaunchConfig` enum the ruling asks for.
//! - `resolve_launch` returns `Result<LaunchConfig, ResolveError>`, not
//!   `Option<LaunchConfig>` — `Option` cannot distinguish "not in the
//!   registry" from "quarantined" from "matched, but the only distribution
//!   is an unverifiable binary", and Ruling C-P13(c)/(d) requires those to
//!   be surfaced distinctly rather than all collapsing to `None`.
//! - Resolution is gated on a cached quarantine list being present at all
//!   (Ruling C-P13(d)): with no quarantine cache on disk, `resolve_launch`
//!   fails closed even for an agent that is, in fact, in the registry and
//!   not quarantined. Tests that want a successful resolution must
//!   therefore seed the quarantine cache (possibly empty) explicitly.
//!
//! **Fix round 1 (coordinator review):**
//! - Item 3 flipped `resolve_distribution`'s preference order: a
//!   `sha256`-bearing `Binary` for the current platform is now preferred
//!   over `Npx`/`Uvx`, not the other way around —
//!   `resolve_launch_prefers_a_checksum_pinned_binary_over_npx_when_an_agent_publishes_both`
//!   (renamed from `..._prefers_npx_over_binary_...`) now asserts the
//!   opposite outcome from before.
//! - Item 6 made [`roundhouse_acp::registry::LaunchConfig`]'s payload
//!   private — every assertion that used to construct a `LaunchConfig::Npx {
//!   .. }` / `LaunchConfig::Binary { .. }` literal and compare it with
//!   `assert_eq!` now reads the resolved value back through its accessor
//!   methods (`is_npx()`, `package()`, `args()`, `env()`, `target()`,
//!   `archive()`, `sha256()`, `cmd()`) instead.

use roundhouse_acp::registry::{
    BinaryTarget, Distribution, PackageDistribution, Quarantine, Registry, RegistryAgent,
    RegistryCache, ResolveError,
};
use std::collections::BTreeMap;
use std::time::Duration;

fn npx_agent(id: &str, package: &str) -> RegistryAgent {
    RegistryAgent {
        id: id.to_string(),
        name: id.to_string(),
        distribution: Distribution {
            npx: Some(PackageDistribution {
                package: package.to_string(),
                args: vec![],
                env: BTreeMap::new(),
            }),
            uvx: None,
            binary: BTreeMap::new(),
        },
    }
}

fn sample_registry() -> Registry {
    Registry {
        agents: vec![
            npx_agent("claude-acp", "@agentclientprotocol/claude-agent-acp@0.73.0"),
            RegistryAgent {
                id: "codex".to_string(),
                name: "Codex".to_string(),
                distribution: Distribution {
                    npx: Some(PackageDistribution {
                        package: "@openai/codex-acp".to_string(),
                        args: vec!["acp".to_string()],
                        env: BTreeMap::new(),
                    }),
                    uvx: None,
                    binary: BTreeMap::new(),
                },
            },
        ],
    }
}

fn empty_quarantine() -> Quarantine {
    Quarantine::default()
}

#[test]
fn resolve_launch_reads_from_the_registry_not_a_hardcoded_table() {
    let dir = tempfile::tempdir().unwrap();
    let cache = RegistryCache::new(
        dir.path().join("registry.json"),
        dir.path().join("quarantine.json"),
        Duration::from_secs(3600),
    );
    cache.store(&sample_registry()).unwrap();
    cache.store_quarantine(&empty_quarantine()).unwrap();

    let launch = cache
        .resolve_launch("codex")
        .expect("codex is in the fetched registry and not quarantined");
    assert!(launch.is_npx());
    assert_eq!(launch.package(), Some("@openai/codex-acp"));
    assert_eq!(launch.args(), &["acp".to_string()]);
    assert_eq!(launch.env(), &BTreeMap::new());

    let err = cache
        .resolve_launch("some-agent-not-in-the-registry")
        .expect_err(
            "no fallback to a hardcoded table — an unlisted agent simply isn't resolvable this way",
        );
    assert!(
        matches!(err, ResolveError::NotInRegistry { .. }),
        "expected NotInRegistry, got {err:?}"
    );
}

#[test]
fn cache_round_trips_through_disk() {
    let dir = tempfile::tempdir().unwrap();
    let cache = RegistryCache::new(
        dir.path().join("registry.json"),
        dir.path().join("quarantine.json"),
        Duration::from_secs(3600),
    );
    assert!(cache.load_cached().is_none(), "nothing fetched yet");
    cache.store(&sample_registry()).unwrap();
    let loaded = cache.load_cached().expect("just stored");
    assert_eq!(loaded.agents.len(), 2);
}

#[test]
fn load_cached_returns_none_once_the_ttl_has_elapsed_but_allow_stale_still_returns_it() {
    let dir = tempfile::tempdir().unwrap();
    // Zero TTL: the entry is stale the instant it's written.
    let cache = RegistryCache::new(
        dir.path().join("registry.json"),
        dir.path().join("quarantine.json"),
        Duration::from_secs(0),
    );
    cache.store(&sample_registry()).unwrap();
    assert!(
        cache.load_cached().is_none(),
        "a zero-TTL entry must already read as stale"
    );
    assert_eq!(
        cache
            .load_cached_allow_stale()
            .expect("stale entry must still be readable explicitly")
            .agents
            .len(),
        2
    );
}

#[test]
fn resolve_launch_fails_closed_when_the_quarantine_list_has_never_been_cached() {
    // Ruling C-P13(d): "If the quarantine list cannot be fetched AND no
    // cached copy exists, resolve_launch fails closed rather than resolving
    // unquarantined." Even a perfectly good, unquarantined registry entry
    // must not resolve while there is no quarantine data at all on disk.
    let dir = tempfile::tempdir().unwrap();
    let cache = RegistryCache::new(
        dir.path().join("registry.json"),
        dir.path().join("quarantine.json"),
        Duration::from_secs(3600),
    );
    cache.store(&sample_registry()).unwrap();
    // Deliberately never calling cache.store_quarantine(..).

    let err = cache
        .resolve_launch("codex")
        .expect_err("must fail closed with no quarantine cache present, not silently resolve");
    assert!(
        matches!(err, ResolveError::QuarantineUnavailable),
        "expected QuarantineUnavailable, got {err:?}"
    );
}

#[test]
fn resolve_launch_rejects_a_quarantined_agent_even_though_it_is_in_the_registry() {
    let dir = tempfile::tempdir().unwrap();
    let cache = RegistryCache::new(
        dir.path().join("registry.json"),
        dir.path().join("quarantine.json"),
        Duration::from_secs(3600),
    );
    cache.store(&sample_registry()).unwrap();
    let mut quarantine = Quarantine::default();
    quarantine.insert("codex".to_string(), "Timeout after 120s".to_string());
    cache.store_quarantine(&quarantine).unwrap();

    let err = cache
        .resolve_launch("codex")
        .expect_err("a quarantined agent must not resolve, even though it is in the registry");
    assert!(
        matches!(err, ResolveError::Quarantined { .. }),
        "expected Quarantined, got {err:?}"
    );
}

#[test]
fn resolve_launch_prefers_a_checksum_pinned_binary_over_npx_when_an_agent_publishes_both() {
    // Fix round 1, Item 3: real data, discovered against the live index —
    // `kilo` and `sigit` publish both `binary` and `npx` distribution
    // simultaneously, and both publish a full `sha256`-bearing binary map.
    // This models that exact shape and asserts the resolver now prefers the
    // checksum-pinned binary over the unverified, install-script-executing
    // `npx` channel — the reverse of this test's original assertion, which
    // preferred `npx` (the coordinator's review found that order inverted
    // the actual integrity argument: a `Binary` with no `sha256` is refused
    // as unverifiable two lines below where `npx`, which carries no digest
    // at all, was unconditionally preferred).
    let dir = tempfile::tempdir().unwrap();
    let cache = RegistryCache::new(
        dir.path().join("registry.json"),
        dir.path().join("quarantine.json"),
        Duration::from_secs(3600),
    );
    let target = roundhouse_acp::registry::current_platform_target();
    let mut binary = BTreeMap::new();
    binary.insert(
        target.to_string(),
        BinaryTarget {
            archive: "https://example.invalid/kilo.tar.gz".to_string(),
            sha256: Some("a".repeat(64)),
            cmd: "./kilo".to_string(),
            args: vec![],
            env: BTreeMap::new(),
        },
    );
    let agent = RegistryAgent {
        id: "kilo".to_string(),
        name: "Kilo".to_string(),
        distribution: Distribution {
            npx: Some(PackageDistribution {
                package: "@kilocode/cli@7.5.9".to_string(),
                args: vec!["acp".to_string()],
                env: BTreeMap::new(),
            }),
            uvx: None,
            binary,
        },
    };
    cache
        .store(&Registry {
            agents: vec![agent],
        })
        .unwrap();
    cache.store_quarantine(&empty_quarantine()).unwrap();

    let launch = cache.resolve_launch("kilo").unwrap();
    assert!(
        launch.is_binary(),
        "expected the checksum-pinned binary to be preferred over npx"
    );
    assert_eq!(launch.target(), Some(target));
    assert_eq!(
        launch.archive(),
        Some("https://example.invalid/kilo.tar.gz")
    );
    assert_eq!(launch.sha256(), Some("a".repeat(64).as_str()));
    assert_eq!(launch.cmd(), Some("./kilo"));
    assert_eq!(launch.args(), &[] as &[String]);
    assert_eq!(launch.env(), &BTreeMap::new());
}

#[test]
fn resolve_launch_resolves_a_binary_only_agent_for_the_current_platform() {
    let dir = tempfile::tempdir().unwrap();
    let cache = RegistryCache::new(
        dir.path().join("registry.json"),
        dir.path().join("quarantine.json"),
        Duration::from_secs(3600),
    );
    let target = roundhouse_acp::registry::current_platform_target();
    let mut binary = BTreeMap::new();
    binary.insert(
        target.to_string(),
        BinaryTarget {
            archive: "https://example.invalid/agent.tar.gz".to_string(),
            sha256: Some("b".repeat(64)),
            cmd: "./agent".to_string(),
            args: vec!["serve".to_string()],
            env: BTreeMap::new(),
        },
    );
    let agent = RegistryAgent {
        id: "binary-only-agent".to_string(),
        name: "Binary Only".to_string(),
        distribution: Distribution {
            npx: None,
            uvx: None,
            binary,
        },
    };
    cache
        .store(&Registry {
            agents: vec![agent],
        })
        .unwrap();
    cache.store_quarantine(&empty_quarantine()).unwrap();

    let launch = cache.resolve_launch("binary-only-agent").unwrap();
    assert!(launch.is_binary());
    assert_eq!(launch.target(), Some(target));
    assert_eq!(
        launch.archive(),
        Some("https://example.invalid/agent.tar.gz")
    );
    assert_eq!(launch.sha256(), Some("b".repeat(64).as_str()));
    assert_eq!(launch.cmd(), Some("./agent"));
    assert_eq!(launch.args(), &["serve".to_string()]);
    assert_eq!(launch.env(), &BTreeMap::new());
}

#[test]
fn resolve_launch_surfaces_a_binary_with_no_sha256_as_unverifiable_not_none() {
    // Ruling C-P13(c): "A Binary entry with no sha256 MUST be surfaced as
    // unverifiable rather than silently resolved." `sha256` is genuinely
    // optional in the upstream schema, and on the live index several real
    // agents (e.g. `cursor`, `devin`, `junie`) ship binary targets with no
    // `sha256` at all.
    let dir = tempfile::tempdir().unwrap();
    let cache = RegistryCache::new(
        dir.path().join("registry.json"),
        dir.path().join("quarantine.json"),
        Duration::from_secs(3600),
    );
    let target = roundhouse_acp::registry::current_platform_target();
    let mut binary = BTreeMap::new();
    binary.insert(
        target.to_string(),
        BinaryTarget {
            archive: "https://example.invalid/no-checksum.tar.gz".to_string(),
            sha256: None,
            cmd: "./no-checksum".to_string(),
            args: vec![],
            env: BTreeMap::new(),
        },
    );
    let agent = RegistryAgent {
        id: "unverifiable-agent".to_string(),
        name: "Unverifiable".to_string(),
        distribution: Distribution {
            npx: None,
            uvx: None,
            binary,
        },
    };
    cache
        .store(&Registry {
            agents: vec![agent],
        })
        .unwrap();
    cache.store_quarantine(&empty_quarantine()).unwrap();

    let err = cache
        .resolve_launch("unverifiable-agent")
        .expect_err("a binary with no sha256 must not silently resolve");
    assert!(
        matches!(err, ResolveError::UnverifiableBinary { .. }),
        "expected UnverifiableBinary, got {err:?}"
    );
}

#[test]
fn resolve_launch_reports_no_usable_distribution_when_only_a_foreign_platform_binary_exists() {
    let dir = tempfile::tempdir().unwrap();
    let cache = RegistryCache::new(
        dir.path().join("registry.json"),
        dir.path().join("quarantine.json"),
        Duration::from_secs(3600),
    );
    let current = roundhouse_acp::registry::current_platform_target();
    let foreign = [
        "darwin-aarch64",
        "darwin-x86_64",
        "linux-aarch64",
        "linux-x86_64",
        "windows-aarch64",
        "windows-x86_64",
    ]
    .into_iter()
    .find(|t| *t != current)
    .unwrap();
    let mut binary = BTreeMap::new();
    binary.insert(
        foreign.to_string(),
        BinaryTarget {
            archive: "https://example.invalid/foreign.tar.gz".to_string(),
            sha256: Some("c".repeat(64)),
            cmd: "./foreign".to_string(),
            args: vec![],
            env: BTreeMap::new(),
        },
    );
    let agent = RegistryAgent {
        id: "foreign-only-agent".to_string(),
        name: "Foreign Only".to_string(),
        distribution: Distribution {
            npx: None,
            uvx: None,
            binary,
        },
    };
    cache
        .store(&Registry {
            agents: vec![agent],
        })
        .unwrap();
    cache.store_quarantine(&empty_quarantine()).unwrap();

    let err = cache.resolve_launch("foreign-only-agent").unwrap_err();
    assert!(
        matches!(err, ResolveError::NoUsableDistribution { .. }),
        "expected NoUsableDistribution, got {err:?}"
    );
}

#[test]
fn registry_deserialization_tolerates_unknown_top_level_and_extension_keys() {
    // Ruling C-P13(a): the live index does not validate against its own
    // `registry.schema.json` (top-level `extensions` vs `additionalProperties:
    // false`) — a strict validator would reject every real fetch. Verified
    // directly against the live index 2026-09-02: its top-level keys are
    // exactly {version, agents, extensions}.
    let json = r#"{
        "version": "1.0.0",
        "extensions": [],
        "some_future_sibling_key": {"anything": true},
        "agents": [
            {
                "id": "claude-acp",
                "name": "Claude Agent",
                "version": "0.73.0",
                "description": "ACP wrapper for Anthropic's Claude",
                "repository": "https://github.com/agentclientprotocol/claude-agent-acp",
                "authors": ["Anthropic"],
                "license": "proprietary",
                "distribution": {
                    "npx": {"package": "@agentclientprotocol/claude-agent-acp@0.73.0"}
                },
                "icon": "https://cdn.agentclientprotocol.com/registry/v1/latest/claude-acp.svg"
            }
        ]
    }"#;
    let registry: Registry =
        serde_json::from_str(json).expect("must tolerate unknown sibling keys");
    assert_eq!(registry.agents.len(), 1);
    assert_eq!(registry.agents[0].id, "claude-acp");
}

#[test]
fn distribution_deserialization_rejects_an_unknown_key() {
    let json = r#"{"npx": {"package": "x"}, "docker": {"image": "y"}}"#;
    let result: Result<Distribution, _> = serde_json::from_str(json);
    assert!(
        result.is_err(),
        "an unrecognized distribution key must be rejected, not silently dropped"
    );
}

#[test]
fn distribution_deserialization_rejects_an_empty_object() {
    let json = r#"{}"#;
    let result: Result<Distribution, _> = serde_json::from_str(json);
    assert!(
        result.is_err(),
        "distribution must have at least one of npx/uvx/binary"
    );
}

#[test]
fn agent_id_pattern_is_enforced_at_deserialize_time() {
    let json = r#"{
        "agents": [
            {
                "id": "Not_Valid!",
                "name": "Bad",
                "distribution": {"npx": {"package": "x"}}
            }
        ]
    }"#;
    let result: Result<Registry, _> = serde_json::from_str(json);
    assert!(
        result.is_err(),
        "an id not matching ^[a-z][a-z0-9-]*$ must be rejected"
    );
}

#[test]
fn package_distribution_deserialization_rejects_an_unknown_field() {
    let json = r#"{"package": "x", "extra_unexpected_field": true}"#;
    let result: Result<PackageDistribution, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

#[test]
fn binary_target_deserialization_rejects_an_unknown_field() {
    let json = r#"{"archive": "https://x", "cmd": "./x", "unexpected": 1}"#;
    let result: Result<BinaryTarget, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

// ---- Item 4: launch fields (package/cmd/env) must be validated, not just id ----

#[test]
fn distribution_deserialization_rejects_an_npx_package_with_a_leading_dash() {
    // The brief's own concrete example: `npx <package>` consumes a
    // leading-`-` string as its own flag, not a package name.
    let json = r#"{"npx": {"package": "--node-options=--require=/tmp/x.js"}}"#;
    let result: Result<Distribution, _> = serde_json::from_str(json);
    assert!(
        result.is_err(),
        "a package name npx would consume as a flag must be rejected"
    );
}

#[test]
fn distribution_deserialization_rejects_an_absolute_binary_cmd() {
    let json = r#"{"binary": {"linux-x86_64": {"archive": "https://x", "cmd": "/bin/sh"}}}"#;
    let result: Result<Distribution, _> = serde_json::from_str(json);
    assert!(result.is_err(), "an absolute cmd must be rejected");
}

#[test]
fn distribution_deserialization_rejects_a_binary_cmd_that_traverses_out_of_the_extraction_directory(
) {
    let json =
        r#"{"binary": {"linux-x86_64": {"archive": "https://x", "cmd": "../../etc/passwd"}}}"#;
    let result: Result<Distribution, _> = serde_json::from_str(json);
    assert!(
        result.is_err(),
        "a cmd containing a `..` segment must be rejected"
    );
}

#[test]
fn distribution_deserialization_rejects_a_forbidden_env_key_on_npx() {
    let json = r#"{"npx": {"package": "x", "env": {"LD_PRELOAD": "/tmp/evil.so"}}}"#;
    let result: Result<Distribution, _> = serde_json::from_str(json);
    assert!(result.is_err(), "LD_PRELOAD must be rejected");
}

#[test]
fn distribution_deserialization_rejects_a_forbidden_env_key_on_a_binary_target() {
    let json = r#"{"binary": {"linux-x86_64": {"archive": "https://x", "cmd": "./agent", "env": {"NODE_OPTIONS": "--require=/tmp/x.js"}}}}"#;
    let result: Result<Distribution, _> = serde_json::from_str(json);
    assert!(result.is_err(), "NODE_OPTIONS must be rejected");
}

#[test]
fn distribution_deserialization_accepts_real_live_shapes_with_a_relative_windows_style_cmd() {
    // Real upstream value: `./bin\devin.exe` — mixed separator, still
    // relative, no `..` segment. Item 4's validation must not be so strict
    // it rejects real, currently-listed registry entries.
    let json =
        r#"{"binary": {"windows-x86_64": {"archive": "https://x", "cmd": "./bin\\devin.exe"}}}"#;
    let result: Result<Distribution, _> = serde_json::from_str(json);
    assert!(
        result.is_ok(),
        "a real relative windows-style cmd must not be rejected: {result:?}"
    );
}

// ---- Item 7(a): resolve_launch must resolve using a stale registry cache,
// not only a fresh one ----

#[test]
fn resolve_launch_resolves_using_a_stale_registry_cache_not_only_a_fresh_one() {
    // Pins Ruling C-P13(e): resolve_launch must call
    // load_cached_allow_stale, not load_cached — a mutation swapping the two
    // passed the rest of this module's suite because every other
    // resolve_launch test uses a cache whose TTL has not yet elapsed.
    let dir = tempfile::tempdir().unwrap();
    let cache = RegistryCache::new(
        dir.path().join("registry.json"),
        dir.path().join("quarantine.json"),
        Duration::from_secs(0), // zero TTL: the entry reads as stale immediately
    );
    cache.store(&sample_registry()).unwrap();
    cache.store_quarantine(&empty_quarantine()).unwrap();

    let launch = cache
        .resolve_launch("codex")
        .expect("a stale-but-present registry cache must still resolve, per C-P13(e)");
    assert!(launch.is_npx());
}
