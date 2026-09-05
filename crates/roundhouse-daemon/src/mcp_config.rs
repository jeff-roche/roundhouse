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
//! replaced) by the project layer. Instead, [`load_mcp_servers`] builds its
//! OWN `ConfigLoader`, keeping only `ConfigScope::UserGlobal` layers and
//! dropping every other scope BEFORE any file is ever read — so a
//! project-scoped `[[mcp_server]]` table is structurally unreachable, not
//! merely unused by convention. This must hold even if a caller mistakenly
//! passes project-scoped layers in (see `load_mcp_servers`'s own doc
//! comment and its test proving this).

use roundhouse_config::{ConfigLoader, ConfigScope};
use roundhouse_mcp::config::McpServerConfig;
use std::path::PathBuf;

/// Failure loading or parsing `[[mcp_server]]` config.
#[derive(Debug, thiserror::Error)]
pub enum McpConfigError {
    #[error("failed to read/parse a config layer: {0}")]
    Load(#[from] roundhouse_config::ConfigError),
    #[error("failed to parse [[mcp_server]] config: {0}")]
    Parse(#[from] toml::de::Error),
}

/// Reads every `[[mcp_server]]` table out of the **user-global** config
/// layer only, and deserializes it into `McpServerConfig`. An absent
/// `mcp_server` key means "no MCP servers configured" (`Ok(vec![])`), not
/// an error — most sessions run with none.
///
/// `layers` is typically `roundhouse_config::default_layers(project_root)`
/// — but every layer whose `ConfigScope` is not `UserGlobal` is dropped
/// here before any file is read, regardless of what `layers` actually
/// contains (ruling W1-R16, see this module's doc comment). This makes it
/// safe to pass `default_layers(Some(repo_root))`'s full result straight
/// through: the project-scoped layer it includes can never reach the
/// `[[mcp_server]]` parse, even if a future caller forgets to filter it out
/// itself.
pub fn load_mcp_servers(
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
        let servers = load_mcp_servers(vec![(ConfigScope::UserGlobal, path)]).unwrap();
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
        let servers = load_mcp_servers(vec![(ConfigScope::UserGlobal, path)]).unwrap();
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
        let result = load_mcp_servers(vec![(ConfigScope::UserGlobal, path)]);
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

        let servers = load_mcp_servers(vec![
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
