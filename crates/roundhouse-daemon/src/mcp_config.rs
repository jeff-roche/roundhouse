//! Parses the `[[mcp_server]]` TOML array-of-tables out of layered config
//! into typed `roundhouse_mcp::config::McpServerConfig`s.
//!
//! This typed parse cannot live in `roundhouse-config` itself:
//! `McpServerConfig` is defined in `roundhouse-mcp`, and `roundhouse-config`
//! must stay free of every `roundhouse-*` dependency
//! (`docs/architecture/02-system-architecture.md` §5.2's `roundhouse-config`
//! row: "no internal `roundhouse-*` dependency") — giving it a
//! `roundhouse-mcp` edge just to parse this one table would invert the
//! intended layering (config loading sits *below* every typed consumer, not
//! depending on one of them). `roundhouse-daemon` already depends on both
//! crates (see its own `Cargo.toml`), so the typed deserialize lives here:
//! `roundhouse_config::LoadedConfig::get` stays untyped (`&toml::Value`),
//! and this module is the first typed consumer of that value for MCP server
//! configuration.
//!
//! # Security review fix round 1 (ruling W1-R16) — `[[mcp_server]]` is
//! **user-scope only**, structurally
//!
//! `roundhouse_config::ConfigScope`'s own doc comment states outright that
//! §6.2's narrow-only, trust-gated precedence for project-scoped config
//! ("Project scope may narrow, never widen, unless the user has recorded a
//! trust decision") is "not implemented anywhere in this crate" — plain
//! layered TOML merge is all `ConfigLoader` does, and a narrower scope's
//! value for a key REPLACES a wider scope's value wholesale (`merge_into`
//! in `roundhouse-config/src/loader.rs`). `McpServerConfig::Stdio.command`
//! is exec'd by the daemon. So if `[[mcp_server]]` were read out of a
//! `LoadedConfig` built from `roundhouse_config::default_layers(Some(repo_root))`
//! (which includes `<repo_root>/.roundhouse/config.toml` at
//! `ConfigScope::Project`), cloning a hostile repository and opening a
//! session inside it would let that repo's own config silently REPLACE
//! (not merge with) the operator's `[[mcp_server]]` list — including
//! swapping a hash-pinned entry for an unpinned one — and the daemon would
//! exec whatever `command` that repo chose, as the daemon's own user.
//!
//! The fix here is NOT "read the merged config and then filter": `LoadedConfig`
//! exposes no per-key provenance (`scopes_present` says which scopes
//! contributed to the merge as a whole, not which scope won any given key),
//! so filtering after the fact cannot distinguish a `[[mcp_server]]` array
//! contributed by the user layer from one contributed (or silently
//! replaced) by the project layer. Instead, [`load_mcp_servers_from_layers`]
//! builds its OWN `ConfigLoader`, keeping only `ConfigScope::UserGlobal`
//! layers and dropping every other scope BEFORE any file is ever read — so
//! a project-scoped `[[mcp_server]]` table is structurally unreachable, not
//! merely unused by convention. This must hold even if a caller mistakenly
//! passes project-scoped layers in (see that function's own doc comment
//! and its test proving this).
//!
//! **Phase 7, Task 7 (CF-11(b) / Task 4's M2):** the drop above protects
//! against a correctly-labeled `Project` layer, but not against a caller
//! that mislabels a project-controlled path as `UserGlobal` in the first
//! place — [`load_mcp_servers`] (below) is the fix for that: it takes a
//! `project_root`, not a caller-labeled `layers` list, and builds the real
//! layers itself.

use roundhouse_config::{ConfigLoader, ConfigScope};
use roundhouse_mcp::config::McpServerConfig;
use std::path::{Path, PathBuf};

/// Failure loading or parsing `[[mcp_server]]` config.
#[derive(Debug, thiserror::Error)]
pub enum McpConfigError {
    #[error("failed to read/parse a config layer: {0}")]
    Load(#[from] roundhouse_config::ConfigError),
    #[error("failed to parse [[mcp_server]] config: {0}")]
    Parse(#[from] toml::de::Error),
}

impl McpConfigError {
    /// A short, static, never-attacker-influenced name for the SHAPE of
    /// this error — never this error's own `Display` (fix round 3, MUST 3).
    ///
    /// `toml::de::Error`'s `Display` embeds a verbatim snippet of the
    /// offending source line at the parse-error location — for
    /// `[[mcp_server]]` config specifically, that line can be a
    /// `env = [["KEY", "sk-…"]]` entry, i.e. one of the operator's own real
    /// secret values, appearing in the config file precisely because it is
    /// the operator's OWN config (project-scoped `[[mcp_server]]` layers are
    /// structurally dropped before any file is ever read — see this
    /// module's own doc comment — so this is not the hostile-cloned-repo
    /// attack; it is CF-11(c) for the operator's own config, same as
    /// `NetworkConfigError::kind`). Mirrors that method's shape exactly.
    pub fn kind(&self) -> &'static str {
        match self {
            McpConfigError::Load(roundhouse_config::ConfigError::Io { .. }) => "io_error",
            McpConfigError::Load(roundhouse_config::ConfigError::Parse { .. }) => {
                "toml_parse_error"
            }
            McpConfigError::Load(roundhouse_config::ConfigError::NotARegularFile { .. }) => {
                "not_a_regular_file"
            }
            McpConfigError::Load(roundhouse_config::ConfigError::TooLarge { .. }) => "too_large",
            McpConfigError::Parse(_) => "mcp_server_section_parse_error",
        }
    }
}

/// Builds `layers` itself via [`roundhouse_config::default_layers`], so
/// there is no `ConfigScope` label for a caller to attach — and therefore
/// none to get wrong (Phase 7, Task 7, CF-11(b) / Task 4's M2).
///
/// **Why this replaces a caller-supplied `Vec<(ConfigScope, PathBuf)>`:**
/// [`load_mcp_servers_from_layers`] already structurally drops every
/// non-`UserGlobal` layer (W1-R16), but that guard only helps if the
/// LABELS attached to `layers` are themselves trustworthy. A caller that
/// hand-built
/// `vec![(ConfigScope::UserGlobal, repo_root.join(".roundhouse/config.toml"))]`
/// — mislabeling a project-controlled path as the wider, trusted scope —
/// would sail straight through that filter with no compiler or test
/// objection, reintroducing the exact hostile-repo attack this module
/// exists to prevent. `roundhouse_config::default_layers` is the one
/// trusted source of scope labels; this function calls it internally so
/// there is no label left for a real caller (`roundhouse-daemon`'s
/// `main.rs`, the first and only production caller) to get wrong.
pub fn load_mcp_servers(
    project_root: Option<&Path>,
) -> Result<Vec<McpServerConfig>, McpConfigError> {
    load_mcp_servers_from_layers(roundhouse_config::default_layers(project_root))
}

/// Reads every `[[mcp_server]]` table out of the **user-global** config
/// layer only, and deserializes it into `McpServerConfig`. An absent
/// `mcp_server` key means "no MCP servers configured" (`Ok(vec![])`), not
/// an error — most sessions run with none.
///
/// Takes a caller-labeled `layers` list directly — see [`load_mcp_servers`]'s
/// doc comment for why a real production caller should use that safe
/// wrapper instead. This function still drops every layer whose
/// `ConfigScope` is not `UserGlobal` before any file is read, regardless of
/// what `layers` actually contains (ruling W1-R16, see this module's doc
/// comment) — that half of the defense is unconditional and holds
/// regardless of which entry point is used; only the "can a caller attach
/// the wrong label in the first place" half is what [`load_mcp_servers`]
/// additionally closes. Kept `pub` (rather than `pub(crate)`/test-only) for
/// this module's own tests, which need to inject arbitrary per-scope paths
/// to prove the drop is unconditional.
///
/// `#[doc(hidden)]` (fix round 1, MUST 5's principle applied symmetrically —
/// the reviewer named `roundhouse-config`'s equivalent function by name, but
/// the same "no label to get wrong" requirement applies here too): keeps
/// this raw, caller-labeled function off the surface `cargo doc`/IDE
/// autocomplete would otherwise offer as readily as [`load_mcp_servers`].
#[doc(hidden)]
pub fn load_mcp_servers_from_layers(
    layers: Vec<(ConfigScope, PathBuf)>,
) -> Result<Vec<McpServerConfig>, McpConfigError> {
    let mut loader = ConfigLoader::new();
    for (scope, path) in layers {
        if scope == ConfigScope::UserGlobal {
            loader = loader.with_layer(scope, path);
        }
        // Every other scope (Project, Workspace, Builtin) is deliberately
        // dropped, never loaded — W1-R16.
    }
    let loaded = loader.load()?;
    match loaded.get("mcp_server") {
        None => Ok(Vec::new()),
        Some(value) => Ok(value.clone().try_into()?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_mcp_server_key_means_no_servers_configured() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "").unwrap();
        let servers = load_mcp_servers_from_layers(vec![(ConfigScope::UserGlobal, path)]).unwrap();
        assert!(servers.is_empty());
    }

    #[test]
    fn parses_a_configured_mcp_server_array_of_tables_from_user_scope() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
[[mcp_server]]
id = "github"

[mcp_server.transport]
kind = "stdio"
command = "mcp-server-github"
args = ["--read-only"]
env = [["GITHUB_TOKEN_REF", "keyring:github"]]
"#,
        )
        .unwrap();
        let servers = load_mcp_servers_from_layers(vec![(ConfigScope::UserGlobal, path)]).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].id.0, "github");
        match &servers[0].transport {
            roundhouse_mcp::config::McpTransportKind::Stdio { command, args, .. } => {
                assert_eq!(command, "mcp-server-github");
                assert_eq!(args, &vec!["--read-only".to_string()]);
            }
        }
    }

    #[test]
    fn a_malformed_mcp_server_table_is_a_parse_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        // Missing the required `transport` field entirely.
        std::fs::write(&path, "[[mcp_server]]\nid = \"github\"\n").unwrap();
        let result = load_mcp_servers_from_layers(vec![(ConfigScope::UserGlobal, path)]);
        assert!(matches!(result, Err(McpConfigError::Parse(_))));
    }

    /// W1-R16, the load-bearing test: a project-scoped `[[mcp_server]]`
    /// entry — even a hostile one, exec-targeting `command` included — must
    /// never be honored, structurally, regardless of what a caller passes
    /// in as `layers`. This directly exercises the attack the security
    /// review named: a cloned repo's `.roundhouse/config.toml` trying to
    /// smuggle in (or replace) an MCP server config.
    #[test]
    fn a_project_scoped_mcp_server_entry_is_never_honored() {
        let dir = tempfile::tempdir().unwrap();
        let user_path = dir.path().join("user-config.toml");
        let project_path = dir.path().join("project-config.toml");

        // The operator's real, trusted config: one legitimate server.
        std::fs::write(
            &user_path,
            r#"
[[mcp_server]]
id = "github"

[mcp_server.transport]
kind = "stdio"
command = "mcp-server-github"
args = []
env = []
"#,
        )
        .unwrap();

        // A hostile project layer trying to replace it with an exec target
        // of its own choosing.
        std::fs::write(
            &project_path,
            r#"
[[mcp_server]]
id = "evil"

[mcp_server.transport]
kind = "stdio"
command = "/tmp/exfiltrate.sh"
args = []
env = []
"#,
        )
        .unwrap();

        let servers = load_mcp_servers_from_layers(vec![
            (ConfigScope::UserGlobal, user_path),
            (ConfigScope::Project, project_path),
        ])
        .unwrap();

        // Only the user-scoped server ever surfaces — the project-scoped
        // one (even alone, it would normally win a plain narrower-wins
        // merge) never reaches the parse at all.
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].id.0, "github");
    }
}
