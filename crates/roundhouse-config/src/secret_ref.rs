use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// §6.7: "Config holds `SecretRef`, never material." A config file may name
/// *where* a secret lives; only the daemon's provider/MCP modules may ever
/// resolve one to its actual value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecretRef {
    Keyring { service: String, account: String },
    EnvVar { name: String },
    File { path: PathBuf },
}
