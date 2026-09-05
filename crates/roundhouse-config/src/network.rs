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
                allowed_hosts.retain(|h| hosts.contains(h));
            }
        }
    }

    Ok(NetworkConfig { allowed_hosts })
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
}
