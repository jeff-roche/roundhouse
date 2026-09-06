//! Dependency-free parsing for operator policy files. Compilation into the
//! executable policy engine is deliberately owned by `roundhouse-policy`.

use crate::{ConfigError, ConfigScope};
use serde::Deserialize;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyFile {
    #[serde(default)]
    pub rule: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub outcome: PolicyRuleOutcome,
    /// The initial file format intentionally supports the concrete built-in
    /// operation required for the first deployed admission journey.
    pub read: PathBuf,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyRuleOutcome {
    Allow,
    Ask,
    Deny,
}

#[derive(Debug, Clone)]
pub struct PolicyLayer {
    pub scope: ConfigScope,
    pub path: PathBuf,
    pub contents: String,
    pub file: PolicyFile,
}

pub fn load_policy_files(project_root: Option<&Path>) -> Result<Vec<PolicyLayer>, ConfigError> {
    let mut layers = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        layers.push((
            ConfigScope::UserGlobal,
            PathBuf::from(home).join(".config/roundhouse/policy.toml"),
        ));
    }
    if let Some(root) = project_root {
        layers.push((ConfigScope::Project, root.join(".roundhouse/policy.toml")));
    }
    load_policy_files_from_layers(layers)
}

/// Parses explicitly-labelled policy paths.  Kept separate from
/// [`load_policy_files`] so tests and higher-level composition can exercise
/// the exact regular-file and malformed-input behaviour without mutating the
/// process environment that supplies the user-global default path.
pub fn load_policy_files_from_layers(
    layers: Vec<(ConfigScope, PathBuf)>,
) -> Result<Vec<PolicyLayer>, ConfigError> {
    let mut parsed = Vec::new();
    for (scope, path) in layers {
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(source) => return Err(ConfigError::Io { path, source }),
        };
        if !metadata.is_file() {
            return Err(ConfigError::NotARegularFile { path });
        }
        let contents = std::fs::read_to_string(&path).map_err(|source| ConfigError::Io {
            path: path.clone(),
            source,
        })?;
        let file = toml::from_str(&contents).map_err(|source| ConfigError::Parse {
            path: path.clone(),
            source,
        })?;
        parsed.push(PolicyLayer {
            scope,
            path,
            contents,
            file,
        });
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn absent_policy_files_produce_no_rules() {
        let dir = tempdir().unwrap();
        assert!(load_policy_files_from_layers(vec![(
            ConfigScope::UserGlobal,
            dir.path().join("missing-policy.toml"),
        )])
        .unwrap()
        .is_empty());
    }

    #[test]
    fn malformed_policy_file_is_an_error_not_an_empty_policy() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, "[[rule]\noutcome = [").unwrap();
        assert!(matches!(
            load_policy_files_from_layers(vec![(ConfigScope::Project, path)]),
            Err(ConfigError::Parse { .. })
        ));
    }
}
