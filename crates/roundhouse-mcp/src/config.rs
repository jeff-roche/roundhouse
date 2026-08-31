use roundhouse_policy::ServerId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerConfig {
    pub id: ServerId,
    pub transport: McpTransportKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpTransportKind {
    Stdio {
        command: String,
        args: Vec<String>,
        /// Explicit allowlist only — never inherits the daemon's own env.
        /// (§6.7: MCP stdio servers are spawned by the daemon outside the
        /// session's namespace; nothing here is session-derived.)
        env: Vec<(String, String)>,
        /// §6.5 hardened profile: "MCP servers pinned by binary hash."
        /// Hex-encoded blake3 digest of the `command` binary's bytes,
        /// verified at spawn time (`StdioMcpTransport::spawn`, Task 6)
        /// before the process is ever started. `None` outside
        /// `--profile hardened`, where pinning is not required.
        /// `#[serde(default)]` keeps existing configs without this field
        /// parseable — an absent pin is "not hardened," not an error.
        #[serde(default)]
        pinned_binary_hash: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_stdio_config_from_json() {
        let json = r#"{
            "id": "github",
            "transport": {
                "kind": "stdio",
                "command": "mcp-server-github",
                "args": ["--read-only"],
                "env": [["GITHUB_TOKEN_REF", "keyring:github"]]
            }
        }"#;
        let cfg: McpServerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.id.0, "github");
        match cfg.transport {
            McpTransportKind::Stdio {
                command,
                args,
                env,
                pinned_binary_hash,
            } => {
                assert_eq!(command, "mcp-server-github");
                assert_eq!(args, vec!["--read-only".to_string()]);
                assert_eq!(
                    env,
                    vec![("GITHUB_TOKEN_REF".to_string(), "keyring:github".to_string())]
                );
                // finding 5: absent from the JSON above — `#[serde(default)]`
                // must make that "not pinned," not a deserialize error.
                assert_eq!(pinned_binary_hash, None);
            }
        }
    }

    #[test]
    fn deserializes_a_hardened_pin_when_present() {
        let json = r#"{
            "id": "github",
            "transport": {
                "kind": "stdio",
                "command": "mcp-server-github",
                "args": [],
                "env": [],
                "pinned_binary_hash": "deadbeef"
            }
        }"#;
        let cfg: McpServerConfig = serde_json::from_str(json).unwrap();
        match cfg.transport {
            McpTransportKind::Stdio {
                pinned_binary_hash, ..
            } => {
                assert_eq!(pinned_binary_hash, Some("deadbeef".to_string()));
            }
        }
    }
}
