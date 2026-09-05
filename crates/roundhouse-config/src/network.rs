//! Parses the `[network] allowed_hosts = [...]` TOML section out of layered
//! config into a plain, self-contained [`NetworkConfig`] — a
//! `Vec<String>`-shaped allowlist and nothing more. This crate must stay
//! free of every `roundhouse-*` dependency (`docs/architecture/
//! 02-system-architecture.md` §5.2's `roundhouse-config` row), so converting
//! this into a real `roundhouse_net::policy::EgressPolicy` happens *above*
//! this crate, in `roundhouse-engine` — see
//! `roundhouse_engine::egress_policy_from_allowed_hosts`.
//!
//! # Security review fix round 1 (same defect class as `mcp_config.rs`'s
//! ruling W1-R16) — `[network] allowed_hosts` is a widening primitive
//!
//! `ConfigScope`'s own doc comment states outright that §6.2's narrow-only,
//! trust-gated precedence for project-scoped config ("Project scope may
//! narrow, never widen, unless the user has recorded a trust decision") is
//! "not implemented anywhere in this crate" — `ConfigLoader::load`'s plain
//! layered TOML merge (`merge_into` in `loader.rs`) replaces a wider
//! scope's value for a key with a narrower scope's value wholesale. An
//! egress allowlist is exactly the widening-sensitive key §6.2 is worried
//! about: if `[network] allowed_hosts` were read out of a `LoadedConfig`
//! built the ordinary way (which merges in `<repo_root>/.roundhouse/
//! config.toml` at `ConfigScope::Project`), cloning a hostile repository
//! and opening a session inside it would let that repo authorize its own
//! exfiltration destination — an operator's real allowlist silently
//! replaced (or padded) by whatever the repo's own config says.
//!
//! Unlike `mcp_config.rs`'s fix (structurally drop `Project` scope
//! entirely, because a merged `LoadedConfig` carries no per-key
//! provenance), this module implements §6.2's actual narrow-only rule for
//! real: [`load_network_config`] loads each configured scope through its
//! **own**, single-layer `ConfigLoader` (never the shared multi-layer
//! merge), so it always knows exactly which scope contributed which value.
//! `Builtin`/`UserGlobal` layers may *establish* (or replace) the
//! allowlist; `Project`/`Workspace` layers may only **intersect** it with
//! whatever they list, narrowing but never adding a host the wider scope
//! didn't already allow. Critically, this holds even when the wider scope
//! never set `allowed_hosts` at all (baseline `[]`, the fail-closed
//! default): intersecting `[]` with anything a project layer supplies is
//! still `[]` — a project config cannot *establish* the allowlist, only
//! ever shrink one that already exists. See this module's tests for the
//! load-bearing case (`user_unset_project_widens_is_still_denied`).
//!
//! This deliberately takes `layers: Vec<(ConfigScope, PathBuf)>`, not a
//! pre-merged `&LoadedConfig` (the brief's original sketch) — a merged
//! `LoadedConfig` has already thrown away per-scope provenance, which is
//! the one piece of information this narrow-only rule needs. Same shape of
//! deviation as `mcp_config.rs`'s `load_mcp_servers`, for the same reason.

use crate::loader::{ConfigError, ConfigLoader};
use crate::scope::ConfigScope;
use serde::Deserialize;
use std::path::PathBuf;

/// Failure loading or parsing the `[network]` config section.
#[derive(Debug, thiserror::Error)]
pub enum NetworkConfigError {
    #[error("failed to read/parse a config layer: {0}")]
    Load(#[from] ConfigError),
    #[error("failed to parse [network] config: {0}")]
    Parse(#[from] toml::de::Error),
}

/// A session's egress allowlist, sourced from config — a plain
/// `Vec<String>`-shaped type with no `roundhouse-*` dependency (see this
/// module's doc comment for why). Converting this into a real
/// `roundhouse_net::policy::EgressPolicy` is the caller's job, above this
/// crate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkConfig {
    pub allowed_hosts: Vec<String>,
}

/// The raw `[network]` TOML table. `allowed_hosts` is `Option` — absent
/// means "this scope said nothing about the allowlist" (never narrows,
/// never establishes), which is a different, load-bearing state from
/// `Some(vec![])` ("this scope explicitly narrowed to nothing").
#[derive(Debug, Deserialize, Default)]
struct NetworkSection {
    #[serde(default)]
    allowed_hosts: Option<Vec<String>>,
}

/// Reads one scope's `[network] allowed_hosts`, in isolation, via its own
/// single-layer `ConfigLoader` — never through the shared multi-layer
/// merge, so the result is unambiguously "what this one scope's file (if
/// any) says," with no risk of a narrower scope's value already having
/// silently replaced it. Returns `Ok(None)` when the file doesn't exist or
/// doesn't set `[network] allowed_hosts` at all.
fn hosts_for_layer(
    scope: ConfigScope,
    path: &std::path::Path,
) -> Result<Option<Vec<String>>, NetworkConfigError> {
    if !path.exists() {
        return Ok(None);
    }
    let loaded = ConfigLoader::new()
        .with_layer(scope, path.to_path_buf())
        .load()?;
    match loaded.get("network") {
        None => Ok(None),
        Some(value) => {
            let section: NetworkSection = value.clone().try_into()?;
            Ok(section.allowed_hosts)
        }
    }
}

/// Builds a [`NetworkConfig`] honoring §6.2's narrow-only rule for
/// project-scoped config (see this module's doc comment for the full
/// rationale and the attack it closes):
///
/// - `layers` is typically `roundhouse_config::default_layers(project_root)`.
/// - A `Builtin`/`UserGlobal` layer's `allowed_hosts`, when present,
///   **replaces** the running allowlist outright (a wider scope is allowed
///   to widen — that's what "wider" means).
/// - A `Project`/`Workspace` layer's `allowed_hosts`, when present, is
///   **intersected** with the running allowlist — it can only remove
///   hosts, never add one the wider scope didn't already allow. This holds
///   even if no wider scope ever set anything (running allowlist `[]`):
///   intersecting `[]` with anything is still `[]`.
/// - **Fix round 1 (W1-R21 as amended by W1-R26):** the intersection
///   normalizes both sides (lowercase, strip one trailing DNS root-anchor
///   dot — see [`entry_covers`]/[`normalize_for_compare`]) **for the
///   comparison only**. The string that survives into the result is
///   always the WIDER scope's own original text, never the narrower
///   scope's — `retain` only ever removes from the wider scope's own
///   `Vec<String>`, so `result ⊆ wider-scope strings` holds *by
///   construction*, not merely by testing (see this module's tests for
///   the load-bearing case). Wildcard vs. literal is handled explicitly:
///   a project wildcard covering a wider literal retains the wider
///   literal; a wider wildcard with only a project literal beneath it
///   retains nothing (a documented, tested over-deny).
/// - No layer setting `allowed_hosts` at all (or no layers present)
///   defaults to an empty allowlist — fail-closed, per Phase 2's rule.
///   `roundhouse_net::policy::EgressPolicy::matches` returns `false` for
///   every host against an empty `allowed_hosts` (confirmed by reading
///   `EgressPolicy::matches`'s `Vec::iter().any(..)` body: an empty vector
///   makes `any` vacuously `false`), so an empty [`NetworkConfig`]
///   genuinely denies all egress rather than being read as "unset, allow
///   all."
pub fn load_network_config(
    layers: Vec<(ConfigScope, PathBuf)>,
) -> Result<NetworkConfig, NetworkConfigError> {
    let mut sorted = layers;
    sorted.sort_by_key(|(scope, _)| *scope);

    let mut allowed_hosts: Vec<String> = Vec::new();
    for (scope, path) in &sorted {
        let Some(hosts) = hosts_for_layer(*scope, path)? else {
            continue;
        };
        match scope {
            ConfigScope::Builtin | ConfigScope::UserGlobal => {
                allowed_hosts = hosts;
            }
            ConfigScope::Project | ConfigScope::Workspace => {
                // W1-R21 as amended by W1-R26: `retain` only ever REMOVES
                // strings already present in `allowed_hosts` (the WIDER
                // scope's own `Vec<String>`) — it never inserts anything
                // from `hosts` (the narrower, project-authored list). That
                // is what makes `result ⊆ wider-scope strings` hold *by
                // construction*, not merely by testing: no string a
                // hostile repo authored can ever reach the final
                // allowlist, regardless of how `entry_covers` below
                // decides a match. `entry_covers` is consulted only to
                // decide WHETHER to keep a wider entry, never to supply
                // its replacement text.
                allowed_hosts.retain(|wider_entry| {
                    hosts
                        .iter()
                        .any(|narrower_entry| entry_covers(narrower_entry, wider_entry))
                });
            }
        }
    }

    Ok(NetworkConfig { allowed_hosts })
}

/// Lowercases and strips a single trailing `.` (the DNS root-anchor form),
/// for the COMPARISON below only — never applied to anything that ends up
/// in a [`NetworkConfig`]'s `allowed_hosts`. Deliberately duplicated here
/// rather than imported: `roundhouse-config` must carry zero
/// `roundhouse-*` dependencies (verified twice in this lane; see this
/// module's own doc comment), so this cannot call
/// `roundhouse_net::policy::normalize_host` directly. Keep this in sync
/// with that function's shape — same two steps, same order — if it ever
/// changes.
fn normalize_for_compare(host: &str) -> String {
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

/// W1-R26's binding wildcard-vs-literal shape, made explicit rather than
/// inferred from string equality:
///
/// - `narrower_entry` is one entry from the Project/Workspace layer being
///   applied; `wider_entry` is one entry already present in the running
///   (wider-scope) allowlist, considered as a candidate to keep.
/// - If `narrower_entry` is a literal, it covers `wider_entry` only when
///   they name the same host after normalization (case, trailing dot) —
///   this is what lets `"API.GitHub.com"` (wider) and `"api.github.com"`
///   (narrower) recognize each other as the same host without moving
///   either string into the result.
/// - If `narrower_entry` is a `"*.suffix"` wildcard, it covers
///   `wider_entry` when `wider_entry` (normalized) equals `suffix` or ends
///   in `.suffix` — mirroring `roundhouse_net::policy::HostPattern::
///   wildcard_suffix`'s own match semantics (`policy.rs:110-116`), so a
///   **project wildcard covering a wider literal retains the wider
///   literal** (the case the security lens asked to see stated, not
///   inferred).
/// - The reverse is NOT symmetric: a **literal** `narrower_entry` never
///   covers a **wildcard-shaped** `wider_entry` (e.g. narrower
///   `"api.github.com"` against wider `"*.github.com"`) — a single literal
///   cannot cover a wildcard's whole scope, and this function may never
///   invent a new, narrower string that was not already the wider scope's
///   own text. So **a wider wildcard with only a project literal beneath
///   it retains nothing** — a documented, tested over-deny, not an
///   accident.
/// - A narrower wildcard with an empty suffix (e.g. a project author's
///   `"*."`/`"*.."` typo) covers every `wider_entry`, same as
///   `HostPattern::wildcard_suffix("")`'s own documented "matches
///   everything" behavior. This is safe here specifically because
///   `retain` above never inserts: at worst this makes a project layer
///   fail to narrow anything, which is not the widening attack this
///   module exists to prevent. Contrast `roundhouse-engine`'s
///   `egress_policy_from_allowed_hosts` (W1-R23), which guards this exact
///   empty-suffix case for a different reason — there an empty suffix
///   becomes a live, ALLOW-ALL pattern in the final `EgressPolicy` itself,
///   which is a real fail-open; here it can only ever suppress narrowing.
fn entry_covers(narrower_entry: &str, wider_entry: &str) -> bool {
    let wider_n = normalize_for_compare(wider_entry);
    let narrower_n = normalize_for_compare(narrower_entry);
    match narrower_n.strip_prefix("*.") {
        Some(suffix) => {
            suffix.is_empty() || wider_n == suffix || wider_n.ends_with(&format!(".{suffix}"))
        }
        None => narrower_n == wider_n,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &std::path::Path, name: &str, contents: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn absent_network_section_means_empty_allowlist_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "config.toml", "");
        let cfg = load_network_config(vec![(ConfigScope::UserGlobal, path)]).unwrap();
        assert!(cfg.allowed_hosts.is_empty());
    }

    #[test]
    fn a_user_global_allowlist_is_honored() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "config.toml",
            "[network]\nallowed_hosts = [\"api.github.com\", \"crates.io\"]\n",
        );
        let cfg = load_network_config(vec![(ConfigScope::UserGlobal, path)]).unwrap();
        assert_eq!(
            cfg.allowed_hosts,
            vec!["api.github.com".to_string(), "crates.io".to_string()]
        );
    }

    #[test]
    fn a_project_scoped_host_that_is_already_in_the_user_allowlist_survives_intersection() {
        let dir = tempfile::tempdir().unwrap();
        let user = write(
            dir.path(),
            "user.toml",
            "[network]\nallowed_hosts = [\"api.github.com\", \"crates.io\"]\n",
        );
        let project = write(
            dir.path(),
            "project.toml",
            "[network]\nallowed_hosts = [\"api.github.com\"]\n",
        );
        let cfg = load_network_config(vec![
            (ConfigScope::UserGlobal, user),
            (ConfigScope::Project, project),
        ])
        .unwrap();
        assert_eq!(cfg.allowed_hosts, vec!["api.github.com".to_string()]);
    }

    /// The load-bearing test: a project layer trying to ADD a host the user
    /// never allowed must never be honored, even (especially) when the user
    /// layer never set `allowed_hosts` at all — the fail-closed default
    /// (`[]`) must not be treated as "unset, so the project's list wins."
    /// This directly reproduces the attack the security review named: a
    /// cloned repo's `.roundhouse/config.toml` trying to add its own
    /// exfiltration destination to the egress allowlist.
    #[test]
    fn user_unset_project_widening_is_still_denied() {
        let dir = tempfile::tempdir().unwrap();
        let user = write(dir.path(), "user.toml", "");
        let project = write(
            dir.path(),
            "project.toml",
            "[network]\nallowed_hosts = [\"evil.example.com\"]\n",
        );
        let cfg = load_network_config(vec![
            (ConfigScope::UserGlobal, user),
            (ConfigScope::Project, project),
        ])
        .unwrap();
        assert!(
            cfg.allowed_hosts.is_empty(),
            "a project-scoped config must never be able to ESTABLISH an \
             allowlist entry the user never granted"
        );
    }

    /// Same attack, but the user *did* set an allowlist: the project layer
    /// tries to pad it with an extra host rather than only narrowing it.
    #[test]
    fn a_project_scoped_config_cannot_widen_a_populated_user_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let user = write(
            dir.path(),
            "user.toml",
            "[network]\nallowed_hosts = [\"api.github.com\"]\n",
        );
        let project = write(
            dir.path(),
            "project.toml",
            "[network]\nallowed_hosts = [\"api.github.com\", \"evil.example.com\"]\n",
        );
        let cfg = load_network_config(vec![
            (ConfigScope::UserGlobal, user),
            (ConfigScope::Project, project),
        ])
        .unwrap();
        assert_eq!(cfg.allowed_hosts, vec!["api.github.com".to_string()]);
    }

    #[test]
    fn a_project_layer_that_never_mentions_network_leaves_the_user_allowlist_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let user = write(
            dir.path(),
            "user.toml",
            "[network]\nallowed_hosts = [\"api.github.com\"]\n",
        );
        let project = write(dir.path(), "project.toml", "[other]\nkey = \"value\"\n");
        let cfg = load_network_config(vec![
            (ConfigScope::UserGlobal, user),
            (ConfigScope::Project, project),
        ])
        .unwrap();
        assert_eq!(cfg.allowed_hosts, vec!["api.github.com".to_string()]);
    }

    #[test]
    fn a_malformed_network_table_is_a_parse_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        // `allowed_hosts` as a table instead of an array of strings.
        let path = write(
            dir.path(),
            "config.toml",
            "[network]\n[network.allowed_hosts]\nnot = \"an array\"\n",
        );
        let result = load_network_config(vec![(ConfigScope::UserGlobal, path)]);
        assert!(matches!(result, Err(NetworkConfigError::Parse(_))));
    }

    // --- W1-R21 as amended by W1-R26: normalize for the COMPARISON only;
    // the retained string is always the wider scope's own. ---

    /// A case-differing project entry must still narrow-intersect against a
    /// wider entry (both name the same real host once normalized) — but the
    /// text that survives into the result must be the WIDER scope's own
    /// original spelling, never the project's. Before this fix, the
    /// intersection compared raw strings, so `"API.GitHub.com"` (wider) and
    /// `"api.github.com"` (project) compared unequal and intersected to
    /// `[]`, silently defeating a legitimate multi-scope config.
    #[test]
    fn case_differing_entries_are_recognized_as_the_same_host_but_the_wider_spelling_survives() {
        let dir = tempfile::tempdir().unwrap();
        let user = write(
            dir.path(),
            "user.toml",
            "[network]\nallowed_hosts = [\"API.GitHub.com\"]\n",
        );
        let project = write(
            dir.path(),
            "project.toml",
            "[network]\nallowed_hosts = [\"api.github.com\"]\n",
        );
        let cfg = load_network_config(vec![
            (ConfigScope::UserGlobal, user),
            (ConfigScope::Project, project),
        ])
        .unwrap();
        assert_eq!(
            cfg.allowed_hosts,
            vec!["API.GitHub.com".to_string()],
            "the surviving string must be the WIDER scope's own spelling, not the project's"
        );
    }

    /// Same defect, trailing-dot form (`roundhouse-net::normalize_host`
    /// strips exactly one trailing DNS root-anchor dot before lowercasing —
    /// this module inlines the same two-step shape for the comparison
    /// only, per W1-R26, without importing `roundhouse-net`).
    #[test]
    fn trailing_dot_entries_are_recognized_as_the_same_host_but_the_wider_spelling_survives() {
        let dir = tempfile::tempdir().unwrap();
        let user = write(
            dir.path(),
            "user.toml",
            "[network]\nallowed_hosts = [\"crates.io.\"]\n",
        );
        let project = write(
            dir.path(),
            "project.toml",
            "[network]\nallowed_hosts = [\"crates.io\"]\n",
        );
        let cfg = load_network_config(vec![
            (ConfigScope::UserGlobal, user),
            (ConfigScope::Project, project),
        ])
        .unwrap();
        assert_eq!(cfg.allowed_hosts, vec!["crates.io.".to_string()]);
    }

    /// W1-R26's explicit wildcard-vs-literal shape, case 1: a PROJECT
    /// wildcard covering a WIDER literal retains the wider literal.
    #[test]
    fn a_project_wildcard_covering_a_wider_literal_retains_the_wider_literal() {
        let dir = tempfile::tempdir().unwrap();
        let user = write(
            dir.path(),
            "user.toml",
            "[network]\nallowed_hosts = [\"api.github.com\"]\n",
        );
        let project = write(
            dir.path(),
            "project.toml",
            "[network]\nallowed_hosts = [\"*.github.com\"]\n",
        );
        let cfg = load_network_config(vec![
            (ConfigScope::UserGlobal, user),
            (ConfigScope::Project, project),
        ])
        .unwrap();
        assert_eq!(cfg.allowed_hosts, vec!["api.github.com".to_string()]);
    }

    /// W1-R26's explicit wildcard-vs-literal shape, case 2: a WIDER wildcard
    /// with only a project LITERAL beneath it retains NOTHING — an
    /// over-deny that is now a documented, tested choice rather than an
    /// accident. A project literal cannot cover the wider wildcard's full
    /// scope, and this module may never invent a new string (like
    /// `"api.github.com"` narrowed from `"*.github.com"`) that was not
    /// already the wider scope's own text.
    #[test]
    fn a_wider_wildcard_with_only_a_project_literal_beneath_it_retains_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let user = write(
            dir.path(),
            "user.toml",
            "[network]\nallowed_hosts = [\"*.github.com\"]\n",
        );
        let project = write(
            dir.path(),
            "project.toml",
            "[network]\nallowed_hosts = [\"api.github.com\"]\n",
        );
        let cfg = load_network_config(vec![
            (ConfigScope::UserGlobal, user),
            (ConfigScope::Project, project),
        ])
        .unwrap();
        assert!(
            cfg.allowed_hosts.is_empty(),
            "a project literal must never be treated as covering a wider wildcard's full scope"
        );
    }

    /// The invariant W1-R26 exists to protect: `result ⊆ wider-scope
    /// strings`. Exercised across every scenario above plus a case
    /// specifically shaped to catch a fix that "helpfully" moves a
    /// project-authored (but normalized-equal) string into the result
    /// instead of retaining the wider scope's own text — that would still
    /// look correct under a naive `==` check on lowercased forms, but would
    /// plant a project-authored `String` value in the final allowlist,
    /// which is the exact widening-shaped regression W1-R26 forbids.
    #[test]
    fn result_is_always_a_subset_of_the_wider_scopes_own_strings() {
        let dir = tempfile::tempdir().unwrap();
        let user = write(
            dir.path(),
            "user.toml",
            "[network]\nallowed_hosts = [\"API.GitHub.com\", \"*.Example.COM.\"]\n",
        );
        let project = write(
            dir.path(),
            "project.toml",
            "[network]\nallowed_hosts = [\"api.github.com\", \"sub.example.com\"]\n",
        );
        let wider_strings = ["API.GitHub.com".to_string(), "*.Example.COM.".to_string()];
        let cfg = load_network_config(vec![
            (ConfigScope::UserGlobal, user),
            (ConfigScope::Project, project),
        ])
        .unwrap();
        for host in &cfg.allowed_hosts {
            assert!(
                wider_strings.contains(host),
                "result entry {host:?} is not one of the wider scope's own strings verbatim \
                 ({wider_strings:?}) — a project-authored string reached the final allowlist"
            );
        }
    }
}
