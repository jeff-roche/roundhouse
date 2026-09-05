use crate::scope::ConfigScope;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Ceiling on a single config layer's file size (Phase 7, Task 7, CF-11(a)).
/// A real config file is a few KiB at most; 1 MiB matches the precedent
/// this workspace already sets for "generous for any legitimate input,
/// fixed regardless of what an attacker sends" caps elsewhere
/// (`roundhouse-daemon::socket_server::MAX_FRAME_BYTES`,
/// `roundhouse_acp::registry::MAX_RESPONSE_BYTES`).
const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;

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
    /// CF-11(a): `path` is not a regular file — most concretely, a symlink.
    /// A committed `.roundhouse/config.toml` symlink (e.g. to `/dev/zero`)
    /// in a cloned repository would otherwise be silently followed by
    /// `read_to_string`, which never reaches EOF against a device file —
    /// an unbounded-memory hang the moment a real project root is loaded
    /// (Phase 7 Task 7 is the first production caller to do so). Refusing
    /// any non-regular-file layer outright, via `symlink_metadata` (which
    /// does NOT follow the link, unlike the `path.exists()` this replaced),
    /// closes this before the file is ever opened.
    #[error(
        "refusing to load {path}: it is not a regular file (symlinks are rejected outright — a \
         config layer must never be a symlink to something else, especially in a project a \
         hostile third party might have authored)"
    )]
    NotARegularFile { path: PathBuf },
    /// CF-11(a): a defense-in-depth cap for a legitimate-looking regular
    /// file that is nonetheless far larger than any real config file could
    /// need to be.
    #[error(
        "refusing to load {path}: it is {len} bytes, over the {MAX_CONFIG_FILE_BYTES}-byte \
         config file cap"
    )]
    TooLarge { path: PathBuf, len: u64 },
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
            // `symlink_metadata`, never `path.exists()`/`fs::metadata`: it does
            // NOT follow a symlink, so a config layer that is itself a symlink
            // (e.g. a cloned repo's committed `.roundhouse/config.toml -> /dev/zero`)
            // is caught here, before anything ever opens it — see
            // `ConfigError::NotARegularFile`'s own doc comment (CF-11(a)).
            let meta = match std::fs::symlink_metadata(path) {
                Ok(meta) => meta,
                Err(err) if err.kind() == ErrorKind::NotFound => continue,
                Err(source) => {
                    return Err(ConfigError::Io {
                        path: path.clone(),
                        source,
                    })
                }
            };
            if !meta.is_file() {
                return Err(ConfigError::NotARegularFile { path: path.clone() });
            }
            if meta.len() > MAX_CONFIG_FILE_BYTES {
                return Err(ConfigError::TooLarge {
                    path: path.clone(),
                    len: meta.len(),
                });
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
