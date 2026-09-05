//! Parses the `[[mcp_server]]` TOML array-of-tables out of a loaded, layered
//! config into typed `roundhouse_mcp::config::McpServerConfig`s.
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

use roundhouse_config::LoadedConfig;
use roundhouse_mcp::config::McpServerConfig;

/// The `[[mcp_server]]` table(s) present in a loaded config failed to
/// deserialize into `McpServerConfig`.
#[derive(Debug, thiserror::Error)]
#[error("failed to parse [[mcp_server]] config: {0}")]
pub struct McpConfigError(#[from] toml::de::Error);

/// Reads every `[[mcp_server]]` table out of `loaded` and deserializes it
/// into `McpServerConfig`. An absent `mcp_server` key means "no MCP servers
/// configured" (`Ok(vec![])`), not an error — most sessions run with none.
pub fn load_mcp_servers(loaded: &LoadedConfig) -> Result<Vec<McpServerConfig>, McpConfigError> {
    match loaded.get("mcp_server") {
        None => Ok(Vec::new()),
        Some(value) => Ok(value.clone().try_into()?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use roundhouse_config::{ConfigLoader, ConfigScope};

    #[test]
    fn absent_mcp_server_key_means_no_servers_configured() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "").unwrap();
        let loaded = ConfigLoader::new()
            .with_layer(ConfigScope::Project, &path)
            .load()
            .unwrap();
        assert!(load_mcp_servers(&loaded).unwrap().is_empty());
    }

    #[test]
    fn parses_a_configured_mcp_server_array_of_tables() {
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
        let loaded = ConfigLoader::new()
            .with_layer(ConfigScope::Project, &path)
            .load()
            .unwrap();
        let servers = load_mcp_servers(&loaded).unwrap();
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
        let loaded = ConfigLoader::new()
            .with_layer(ConfigScope::Project, &path)
            .load()
            .unwrap();
        assert!(load_mcp_servers(&loaded).is_err());
    }
}
