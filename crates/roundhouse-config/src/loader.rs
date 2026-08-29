use crate::scope::ConfigScope;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse config file {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
}

#[derive(Debug, Clone)]
pub struct LoadedConfig {
    value: toml::Value,
    pub scopes_present: Vec<ConfigScope>,
}

impl LoadedConfig {
    pub fn get(&self, key: &str) -> Option<&toml::Value> {
        self.value.get(key)
    }
}

#[derive(Debug, Clone, Default)]
pub struct ConfigLoader {
    layers: Vec<(ConfigScope, PathBuf)>,
}

impl ConfigLoader {
    pub fn new() -> Self {
        Self { layers: Vec::new() }
    }

    pub fn with_layer(mut self, scope: ConfigScope, path: impl Into<PathBuf>) -> Self {
        self.layers.push((scope, path.into()));
        self
    }

    /// Reads every present layer, sorts narrowest-last, and deep-merges them
    /// so a layer overrides only the keys it actually sets (§6.2 precedence:
    /// narrower wins, but only where it says something).
    pub fn load(&self) -> Result<LoadedConfig, ConfigError> {
        let mut sorted = self.layers.clone();
        sorted.sort_by_key(|(scope, _)| *scope);

        let mut merged = toml::Value::Table(toml::map::Map::new());
        let mut scopes_present = Vec::new();

        for (scope, path) in &sorted {
            if !path.exists() {
                continue;
            }
            let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
                path: path.clone(),
                source,
            })?;
            let value: toml::Value = text.parse().map_err(|source| ConfigError::Parse {
                path: path.clone(),
                source,
            })?;
            merge_into(&mut merged, value);
            scopes_present.push(*scope);
        }

        Ok(LoadedConfig {
            value: merged,
            scopes_present,
        })
    }
}

fn merge_into(base: &mut toml::Value, overlay: toml::Value) {
    match overlay {
        toml::Value::Table(overlay_table) => {
            if !matches!(base, toml::Value::Table(_)) {
                *base = toml::Value::Table(toml::map::Map::new());
            }
            let toml::Value::Table(base_table) = base else {
                unreachable!("just normalized `base` to Table above");
            };
            for (key, value) in overlay_table {
                match base_table.get_mut(&key) {
                    Some(existing) => merge_into(existing, value),
                    None => {
                        base_table.insert(key, value);
                    }
                }
            }
        }
        other => *base = other,
    }
}

/// The conventional on-disk locations for Roundhouse's config layers, per
/// this plan's Global Constraints (`.roundhouse/` project-scoped,
/// `~/.config/roundhouse/` user-scoped). This crate's own tests inject
/// explicit paths instead of calling this — it exists for `roundhouse-daemon`
/// to call at real startup.
pub fn default_layers(project_root: Option<&Path>) -> Vec<(ConfigScope, PathBuf)> {
    let mut layers = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        layers.push((
            ConfigScope::UserGlobal,
            PathBuf::from(home).join(".config/roundhouse/config.toml"),
        ));
    }
    if let Some(root) = project_root {
        layers.push((ConfigScope::Project, root.join(".roundhouse/config.toml")));
    }
    layers
}
