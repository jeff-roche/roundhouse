//! Task C8 (G7, part 2): consuming the real `agentclientprotocol/registry`
//! install index instead of hardcoding agent launch configs (§10.3).
//!
//! **This module follows the coordinator's rulings for this task, which
//! override the task brief's literal shape in several places** — see
//! `ACP-REGISTRY-FORMAT.md` (a verified 2026-09-01 snapshot of the live
//! registry's format) for the source of truth this was built against, and
//! this module's own re-verification against the live index on 2026-09-02
//! (recorded inline below where it changed a design decision).
//!
//! ## What differs from the brief, and why
//!
//! - **`distribution` is a struct, not a mutually-exclusive enum**, even
//!   though Ruling C-P13(b) describes it as "a typed enum over exactly the
//!   three real variants." Re-fetching the live index
//!   (`https://cdn.agentclientprotocol.com/registry/v1/latest/registry.json`,
//!   39 agents) and checking for agents whose `distribution` object has more
//!   than one key found two: `kilo` and `sigit`, both of which publish
//!   `binary` *and* `npx` simultaneously. The upstream JSON Schema
//!   (`agent.schema.json`) agrees: `distribution` is `type: object,
//!   minProperties: 1, additionalProperties: false` over the three
//!   properties, not a discriminated union — an agent may legitimately
//!   publish more than one. A strictly mutually-exclusive enum at this field
//!   would reject two real, currently-listed agents. [`Distribution`] is
//!   instead a struct with one optional/collection field per real shape
//!   (`npx: Option<PackageDistribution>`, `uvx: Option<PackageDistribution>`,
//!   `binary: BTreeMap<String, BinaryTarget>` keyed by platform target), each
//!   of the three per-shape structs `deny_unknown_fields` and the struct as a
//!   whole rejects an unrecognized fourth key and an empty object (both
//!   verified in this module's tests) — the part of Ruling C-P13(b) that
//!   *is* upheld literally. [`LaunchConfig`], what [`RegistryCache::resolve_launch`]
//!   actually returns, **is** the mutually-exclusive three-variant enum the
//!   ruling asks for — it is the single distribution method chosen for one
//!   resolution, not the set of everything an agent publishes.
//! - **`resolve_launch` returns `Result<LaunchConfig, ResolveError>`, not
//!   `Option<LaunchConfig>`.** `Option` cannot distinguish "this agent isn't
//!   in the registry" from "this agent is quarantined" from "this agent
//!   matched, but its only distribution is a `Binary` with no `sha256`" —
//!   and Ruling C-P13(c)/(d) require exactly those distinctions to be
//!   surfaced, not silently folded into `None`.
//! - **Every `ResolveError` variant that carries registry- or
//!   quarantine-derived text carries it as [`crate::peer_text::EscapedPeerStr`],
//!   not a bare `String`]** — an agent id, a quarantine reason string, and a
//!   binary target string are all fetched over HTTP from a third party (this
//!   crate's untrusted-text class, per `peer_text`'s own module doc, written
//!   specifically anticipating this task). `agent_id` as an *input parameter*
//!   to [`RegistryCache::resolve_launch`] is not treated this way: it is the
//!   caller's (the daemon's) own query, not registry-derived text.
//!
//! ## Verified quirks of the live registry (informational, not enforced here)
//!
//! - The top level actually has `{version, agents, extensions}` — `extensions`
//!   is not declared in `registry.schema.json`'s `additionalProperties: false`
//!   object, so the live index does not even validate against its own
//!   published schema. [`Registry`] deliberately has no
//!   `#[serde(deny_unknown_fields)]` so it tolerates `extensions` and any
//!   future sibling key (Ruling C-P13(a)).
//! - `sha256` is genuinely optional on a binary target — of the 39 live
//!   agents' binary distributions, several (e.g. `cursor`, `devin`, `junie`,
//!   `stakpak`, `crow-cli`) ship every one of their platform targets with no
//!   `sha256` at all. [`RegistryCache::resolve_launch`] surfaces that case as
//!   [`ResolveError::UnverifiableBinary`] rather than resolving it (Ruling
//!   C-P13(c)).
//! - The quarantine list lives at
//!   `https://raw.githubusercontent.com/agentclientprotocol/registry/main/quarantine.json`
//!   — the same-shaped path under the `cdn.agentclientprotocol.com` host used
//!   for the registry index itself 404s for `quarantine.json` (re-verified
//!   here); [`DEFAULT_QUARANTINE_URL`] uses the raw GitHub URL Ruling
//!   C-P13(d) specifies.

use crate::peer_text::{escape_and_cap_peer_str, EscapedPeerStr};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Pinned default registry index URL (Ruling C-P13(f): configurable, with a
/// pinned default; the fetch itself is opt-in — nothing in this module
/// fetches on construction). Verified reachable (HTTP 200, 39 agents)
/// 2026-09-01/2026-09-02.
pub const DEFAULT_REGISTRY_URL: &str =
    "https://cdn.agentclientprotocol.com/registry/v1/latest/registry.json";

/// Pinned default quarantine list URL (Ruling C-P13(d)/(f)). Deliberately
/// the raw GitHub path, not the `cdn.agentclientprotocol.com` host the
/// registry index itself uses — the CDN path for `quarantine.json` 404s
/// (re-verified here 2026-09-02).
pub const DEFAULT_QUARANTINE_URL: &str =
    "https://raw.githubusercontent.com/agentclientprotocol/registry/main/quarantine.json";

/// One `npx`/`uvx` package distribution entry — schema's `packageDistribution`
/// (`package` required; `args`/`env` optional, defaulting to empty).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageDistribution {
    pub package: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

/// One platform's binary distribution target — schema's `binaryTarget`.
/// `sha256` is genuinely optional upstream (see module doc); `cmd`/`archive`
/// are required.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryTarget {
    pub archive: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub cmd: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

/// An agent's published distribution methods. See the module doc for why
/// this is a struct (an agent may publish more than one method at once) and
/// not the mutually-exclusive enum a literal reading of Ruling C-P13(b)
/// would suggest.
///
/// Deserializes through [`RawDistribution`], which `deny_unknown_fields` and
/// is validated by [`TryFrom`] to reject an empty object — "distribution has
/// at least one variant" (Ruling C-P13(a)), enforced in the type system: a
/// `Distribution` value cannot exist with all three fields empty.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "RawDistribution")]
pub struct Distribution {
    pub npx: Option<PackageDistribution>,
    pub uvx: Option<PackageDistribution>,
    pub binary: BTreeMap<String, BinaryTarget>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDistribution {
    #[serde(default)]
    npx: Option<PackageDistribution>,
    #[serde(default)]
    uvx: Option<PackageDistribution>,
    #[serde(default)]
    binary: BTreeMap<String, BinaryTarget>,
}

impl TryFrom<RawDistribution> for Distribution {
    type Error = String;

    fn try_from(raw: RawDistribution) -> Result<Self, Self::Error> {
        if raw.npx.is_none() && raw.uvx.is_none() && raw.binary.is_empty() {
            return Err("distribution must have at least one of npx, uvx, or binary".to_string());
        }
        Ok(Distribution {
            npx: raw.npx,
            uvx: raw.uvx,
            binary: raw.binary,
        })
    }
}

/// One registry entry. Only the fields this crate actually uses are
/// modeled — `version`, `description`, `repository`, `authors`, `license`,
/// `license_url`, and `icon` all appear on live entries and are silently
/// ignored on deserialize (no `deny_unknown_fields` here), matching the
/// brief's "adjust `RegistryAgent`'s fields to match [what's needed]" note
/// and Registry's own top-level tolerance.
///
/// Deserializes through [`RawRegistryAgent`] and validates `id` against the
/// schema's `^[a-z][a-z0-9-]*$` pattern (Ruling C-P13(a)) — checked directly
/// against all 39 live ids, all of which match.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "RawRegistryAgent")]
pub struct RegistryAgent {
    pub id: String,
    pub name: String,
    pub distribution: Distribution,
}

#[derive(Debug, Clone, Deserialize)]
struct RawRegistryAgent {
    id: String,
    name: String,
    distribution: Distribution,
}

impl TryFrom<RawRegistryAgent> for RegistryAgent {
    type Error = String;

    fn try_from(raw: RawRegistryAgent) -> Result<Self, Self::Error> {
        if !is_valid_agent_id(&raw.id) {
            return Err(format!(
                "invalid agent id (must match ^[a-z][a-z0-9-]*$): {}",
                escape_and_cap_peer_str(&raw.id)
            ));
        }
        Ok(RegistryAgent {
            id: raw.id,
            name: raw.name,
            distribution: raw.distribution,
        })
    }
}

fn is_valid_agent_id(id: &str) -> bool {
    let mut chars = id.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// The full registry index. No `deny_unknown_fields`: the live index's
/// top level is `{version, agents, extensions}`, and `extensions` is not
/// declared in the upstream `registry.schema.json`'s own
/// `additionalProperties: false` object — the live data does not validate
/// against its own published schema, so this type must tolerate `extensions`
/// and any future sibling key rather than reject every real fetch (Ruling
/// C-P13(a)).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Registry {
    pub agents: Vec<RegistryAgent>,
}

/// The quarantine list: agent id -> human-readable reason it is excluded
/// from resolution. A flat, open-ended map — there is no fixed schema to
/// validate beyond "string to string".
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Quarantine(BTreeMap<String, String>);

impl Quarantine {
    pub fn insert(&mut self, agent_id: String, reason: String) {
        self.0.insert(agent_id, reason);
    }

    pub fn is_quarantined(&self, agent_id: &str) -> bool {
        self.0.contains_key(agent_id)
    }

    pub fn reason(&self, agent_id: &str) -> Option<&str> {
        self.0.get(agent_id).map(String::as_str)
    }
}

/// The single, resolved launch method for one agent — what
/// [`RegistryCache::resolve_launch`] actually returns. This is the
/// mutually-exclusive three-variant enum Ruling C-P13(b) describes.
///
/// `Binary`'s fields are exactly what `resolve_launch` is allowed to return
/// per Ruling C-P13(c): the caller (daemon, out of scope for this crate) owns
/// downloading `archive`, verifying it against `sha256`, extracting it, and
/// running `cmd`/`args`/`env` — nothing here does any of that, or turns this
/// into anything spawnable.
#[derive(Debug, Clone, PartialEq)]
pub enum LaunchConfig {
    Npx {
        package: String,
        args: Vec<String>,
        env: BTreeMap<String, String>,
    },
    Uvx {
        package: String,
        args: Vec<String>,
        env: BTreeMap<String, String>,
    },
    Binary {
        target: String,
        archive: String,
        sha256: Option<String>,
        cmd: String,
        args: Vec<String>,
        env: BTreeMap<String, String>,
    },
}

/// Why [`RegistryCache::resolve_launch`] did not resolve to a [`LaunchConfig`].
///
/// Every variant that carries registry- or quarantine-derived text carries
/// it as [`EscapedPeerStr`], not a bare `String` — see this module's doc and
/// `peer_text`'s own doc for why that fetched-over-HTTP-from-a-third-party
/// text must never reach a log line or error message unescaped.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ResolveError {
    #[error("agent {agent_id} is not present in the cached registry")]
    NotInRegistry { agent_id: EscapedPeerStr },
    #[error("agent {agent_id} is quarantined: {reason}")]
    Quarantined {
        agent_id: EscapedPeerStr,
        reason: EscapedPeerStr,
    },
    /// Ruling C-P13(d): "If the quarantine list cannot be fetched AND no
    /// cached copy exists, resolve_launch fails closed rather than resolving
    /// unquarantined." No agent id to report here — this fires before the
    /// registry is even consulted.
    #[error(
        "quarantine list unavailable (no fetch has ever succeeded and no cached copy exists) \
         — failing closed rather than resolving an agent that might be quarantined"
    )]
    QuarantineUnavailable,
    #[error("agent {agent_id} has no distribution this resolver can use for the current platform")]
    NoUsableDistribution { agent_id: EscapedPeerStr },
    /// Ruling C-P13(c): a `Binary` entry with no `sha256` must be surfaced
    /// this way, not silently resolved.
    #[error(
        "agent {agent_id}'s binary distribution for target {target} has no sha256 checksum \
         — unverifiable, not resolved"
    )]
    UnverifiableBinary {
        agent_id: EscapedPeerStr,
        target: EscapedPeerStr,
    },
}

/// Errors from fetching or reading registry/quarantine JSON.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("http error fetching registry data: {0}")]
    Http(#[from] reqwest::Error),
    #[error("invalid registry json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("registry cache io error: {0}")]
    Io(#[from] std::io::Error),
}

/// The current process's platform, expressed as the registry's own target
/// naming scheme (`darwin-aarch64`, `linux-x86_64`, etc. — see
/// `ACP-REGISTRY-FORMAT.md`'s "Platform Targets" list). `pub` so a caller
/// (or a test, to stay portable across whatever machine/CI runs it) can
/// determine what [`RegistryCache::resolve_launch`] will look for without
/// duplicating this mapping.
///
/// Returns `"unsupported"` — a sentinel that cannot match any of the six
/// real target keys — for any OS/arch combination the registry has no
/// naming scheme for, rather than panicking or guessing.
pub fn current_platform_target() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "darwin-aarch64",
        ("macos", "x86_64") => "darwin-x86_64",
        ("linux", "aarch64") => "linux-aarch64",
        ("linux", "x86_64") => "linux-x86_64",
        ("windows", "aarch64") => "windows-aarch64",
        ("windows", "x86_64") => "windows-x86_64",
        _ => "unsupported",
    }
}

/// §10.3: "Consume it rather than hardcoding agent launch configs." Fetches
/// the real registry over HTTP.
///
/// Ruling C-P11: `async`, using reqwest's default async client — never
/// `reqwest::blocking` (this crate has no `blocking` feature enabled; see
/// `Cargo.toml`). The stated consumer, `roundhouse-daemon`, is tokio-based,
/// and `reqwest::blocking` panics when called from inside a tokio runtime.
pub async fn fetch_registry(url: &str) -> Result<Registry, RegistryError> {
    let body = reqwest::get(url).await?.text().await?;
    Ok(serde_json::from_str(&body)?)
}

/// Fetches the quarantine list over HTTP. Same async-only rationale as
/// [`fetch_registry`].
pub async fn fetch_quarantine(url: &str) -> Result<Quarantine, RegistryError> {
    let body = reqwest::get(url).await?.text().await?;
    Ok(serde_json::from_str(&body)?)
}

fn read_cached_json<T: DeserializeOwned>(path: &Path, ttl: Option<Duration>) -> Option<T> {
    let metadata = std::fs::metadata(path).ok()?;
    if let Some(ttl) = ttl {
        let modified = metadata.modified().ok()?;
        if SystemTime::now().duration_since(modified).ok()? > ttl {
            return None; // stale — caller should re-fetch and store() again
        }
    }
    let contents = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&contents).ok()
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(value).map_err(std::io::Error::other)?;
    std::fs::write(path, body)
}

/// A local, TTL'd cache of the registry, plus a separately-cached quarantine
/// list, so a transient network failure or the registry's own downtime never
/// blocks resolving an already-known, non-quarantined agent — and so this
/// isn't a network round-trip on every single session spawn.
///
/// The registry and quarantine caches are independent files (Ruling
/// C-P13(f): both URLs, and by extension both cache locations, are
/// caller-configured). The quarantine cache has no TTL concept: Ruling
/// C-P13(d) only ever asks whether a cached copy exists at all, never
/// whether it is fresh.
pub struct RegistryCache {
    registry_path: PathBuf,
    quarantine_path: PathBuf,
    ttl: Duration,
}

impl RegistryCache {
    pub fn new(registry_path: PathBuf, quarantine_path: PathBuf, ttl: Duration) -> Self {
        Self {
            registry_path,
            quarantine_path,
            ttl,
        }
    }

    /// The registry as cached on disk, or `None` if nothing has been stored
    /// yet or the stored copy is older than this cache's TTL. Use
    /// [`Self::load_cached_allow_stale`] to read the cached copy regardless
    /// of age.
    pub fn load_cached(&self) -> Option<Registry> {
        read_cached_json(&self.registry_path, Some(self.ttl))
    }

    /// The registry as cached on disk regardless of age — even if the TTL
    /// has elapsed. [`Self::resolve_launch`] and [`Self::finish_registry_refresh`]
    /// (via [`Self::refresh_registry`]) both use this: a registry entry that
    /// is merely old is still far more useful than refusing to resolve at
    /// all (Ruling C-P13(e)).
    pub fn load_cached_allow_stale(&self) -> Option<Registry> {
        read_cached_json(&self.registry_path, None)
    }

    pub fn store(&self, registry: &Registry) -> std::io::Result<()> {
        write_json(&self.registry_path, registry)
    }

    fn load_quarantine_cached(&self) -> Option<Quarantine> {
        read_cached_json(&self.quarantine_path, None)
    }

    pub fn store_quarantine(&self, quarantine: &Quarantine) -> std::io::Result<()> {
        write_json(&self.quarantine_path, quarantine)
    }

    /// Fetches a fresh registry from `url` and stores it; if the fetch
    /// fails, serves the existing stale cache instead of propagating the
    /// error (Ruling C-P13(e): "the fetch path serves the stale cache when a
    /// fresh fetch fails", implemented for real rather than only claimed in
    /// a doc comment). Only returns `Err` when the fetch failed *and* there
    /// is no cached copy — fresh or stale — to fall back to.
    pub async fn refresh_registry(&self, url: &str) -> Result<Registry, RegistryError> {
        self.finish_registry_refresh(fetch_registry(url).await)
    }

    /// The sync half of [`Self::refresh_registry`], split out so it can be
    /// unit-tested without a network call (see this module's tests) — it
    /// takes an already-obtained fetch result rather than performing the
    /// fetch itself.
    fn finish_registry_refresh(
        &self,
        fetched: Result<Registry, RegistryError>,
    ) -> Result<Registry, RegistryError> {
        match fetched {
            Ok(registry) => {
                self.store(&registry)?;
                Ok(registry)
            }
            Err(err) => self.load_cached_allow_stale().ok_or(err),
        }
    }

    /// Same stale-survives-fetch-failure behavior as [`Self::refresh_registry`],
    /// for the quarantine list.
    pub async fn refresh_quarantine(&self, url: &str) -> Result<Quarantine, RegistryError> {
        self.finish_quarantine_refresh(fetch_quarantine(url).await)
    }

    fn finish_quarantine_refresh(
        &self,
        fetched: Result<Quarantine, RegistryError>,
    ) -> Result<Quarantine, RegistryError> {
        match fetched {
            Ok(quarantine) => {
                self.store_quarantine(&quarantine)?;
                Ok(quarantine)
            }
            Err(err) => self.load_quarantine_cached().ok_or(err),
        }
    }

    /// The actual "resolve an agent's launch command instead of a
    /// hardcoded table" §10.3 requires. No fallback to a hardcoded table:
    /// an agent id not present in the cached registry is simply not
    /// resolvable this way (that is the entire point of this task).
    ///
    /// Reads whatever registry/quarantine data is cached on disk regardless
    /// of TTL freshness (Ruling C-P13(e)'s resilience story: an expired
    /// cache should not itself block resolving an already-known agent —
    /// staleness only ever gates whether [`Self::load_cached`] considers the
    /// data "fresh enough to skip a re-fetch", a decision that belongs to
    /// the caller deciding whether to call [`Self::refresh_registry`], not to
    /// this method). Quarantine has no such staleness question at all
    /// (Ruling C-P13(d)): its cache either exists or it doesn't.
    pub fn resolve_launch(&self, agent_id: &str) -> Result<LaunchConfig, ResolveError> {
        let quarantine = self
            .load_quarantine_cached()
            .ok_or(ResolveError::QuarantineUnavailable)?;
        if let Some(reason) = quarantine.reason(agent_id) {
            return Err(ResolveError::Quarantined {
                agent_id: escape_and_cap_peer_str(agent_id),
                reason: escape_and_cap_peer_str(reason),
            });
        }

        let registry =
            self.load_cached_allow_stale()
                .ok_or_else(|| ResolveError::NotInRegistry {
                    agent_id: escape_and_cap_peer_str(agent_id),
                })?;
        let agent = registry
            .agents
            .iter()
            .find(|a| a.id.as_str() == agent_id)
            .ok_or_else(|| ResolveError::NotInRegistry {
                agent_id: escape_and_cap_peer_str(agent_id),
            })?;

        resolve_distribution(agent)
    }
}

/// Picks one [`LaunchConfig`] out of an agent's (possibly multiple)
/// published [`Distribution`] methods. Preference order — `npx`, then
/// `uvx`, then `binary` for the current platform — is a design choice made
/// here, not something the schema or Ruling C-P13 dictates: package-manager
/// distributions need no download-and-verify step, so they are preferred
/// over a binary when an agent (like the live `kilo`/`sigit` entries)
/// publishes both.
fn resolve_distribution(agent: &RegistryAgent) -> Result<LaunchConfig, ResolveError> {
    if let Some(npx) = &agent.distribution.npx {
        return Ok(LaunchConfig::Npx {
            package: npx.package.clone(),
            args: npx.args.clone(),
            env: npx.env.clone(),
        });
    }
    if let Some(uvx) = &agent.distribution.uvx {
        return Ok(LaunchConfig::Uvx {
            package: uvx.package.clone(),
            args: uvx.args.clone(),
            env: uvx.env.clone(),
        });
    }
    let target = current_platform_target();
    if let Some(binary) = agent.distribution.binary.get(target) {
        if binary.sha256.is_none() {
            return Err(ResolveError::UnverifiableBinary {
                agent_id: escape_and_cap_peer_str(&agent.id),
                target: escape_and_cap_peer_str(target),
            });
        }
        return Ok(LaunchConfig::Binary {
            target: target.to_string(),
            archive: binary.archive.clone(),
            sha256: binary.sha256.clone(),
            cmd: binary.cmd.clone(),
            args: binary.args.clone(),
            env: binary.env.clone(),
        });
    }

    Err(ResolveError::NoUsableDistribution {
        agent_id: escape_and_cap_peer_str(&agent.id),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_registry() -> Registry {
        Registry {
            agents: vec![RegistryAgent {
                id: "codex".to_string(),
                name: "Codex".to_string(),
                distribution: Distribution {
                    npx: Some(PackageDistribution {
                        package: "@openai/codex-acp".to_string(),
                        args: vec![],
                        env: BTreeMap::new(),
                    }),
                    uvx: None,
                    binary: BTreeMap::new(),
                },
            }],
        }
    }

    // A serde_json syntax error, built with no network access, standing in
    // for "the fetch failed" in the tests below — see
    // `finish_registry_refresh`/`finish_quarantine_refresh`'s doc for why
    // they're split out from their async callers specifically so this is
    // possible.
    fn synthetic_fetch_failure() -> RegistryError {
        serde_json::from_str::<Registry>("not json")
            .unwrap_err()
            .into()
    }

    #[test]
    fn finish_registry_refresh_serves_the_stale_cache_when_the_fetch_fails() {
        let dir = tempfile::tempdir().unwrap();
        // ttl=0: the stored entry reads as stale immediately, and this must
        // not matter to the fallback path.
        let cache = RegistryCache::new(
            dir.path().join("registry.json"),
            dir.path().join("quarantine.json"),
            Duration::from_secs(0),
        );
        cache.store(&sample_registry()).unwrap();

        let result = cache.finish_registry_refresh(Err(synthetic_fetch_failure()));
        assert_eq!(
            result
                .expect("must fall back to the stale cache")
                .agents
                .len(),
            1
        );
    }

    #[test]
    fn finish_registry_refresh_propagates_the_error_when_there_is_no_cache_at_all() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RegistryCache::new(
            dir.path().join("registry.json"),
            dir.path().join("quarantine.json"),
            Duration::from_secs(3600),
        );
        // Nothing ever stored.
        let result = cache.finish_registry_refresh(Err(synthetic_fetch_failure()));
        assert!(
            result.is_err(),
            "with no cache to fall back to, the original fetch error must propagate"
        );
    }

    #[test]
    fn finish_registry_refresh_stores_and_returns_a_successful_fetch() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RegistryCache::new(
            dir.path().join("registry.json"),
            dir.path().join("quarantine.json"),
            Duration::from_secs(3600),
        );
        let result = cache.finish_registry_refresh(Ok(sample_registry()));
        assert!(result.is_ok());
        assert_eq!(cache.load_cached().unwrap().agents.len(), 1);
    }

    #[test]
    fn finish_quarantine_refresh_serves_the_stale_cache_when_the_fetch_fails() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RegistryCache::new(
            dir.path().join("registry.json"),
            dir.path().join("quarantine.json"),
            Duration::from_secs(3600),
        );
        let mut quarantine = Quarantine::default();
        quarantine.insert("crow-cli".to_string(), "ACP initialize fails".to_string());
        cache.store_quarantine(&quarantine).unwrap();

        let result = cache.finish_quarantine_refresh(Err(synthetic_fetch_failure()));
        assert!(result
            .expect("must fall back to the stale cache")
            .is_quarantined("crow-cli"));
    }

    #[test]
    fn finish_quarantine_refresh_propagates_the_error_when_there_is_no_cache_at_all() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RegistryCache::new(
            dir.path().join("registry.json"),
            dir.path().join("quarantine.json"),
            Duration::from_secs(3600),
        );
        let result = cache.finish_quarantine_refresh(Err(synthetic_fetch_failure()));
        assert!(result.is_err());
    }

    #[test]
    fn current_platform_target_returns_one_of_the_six_real_targets_on_a_supported_platform() {
        // Not a claim that every possible build target is covered — only
        // that on whatever platform actually runs this test, the mapping
        // produces a real registry target string rather than the
        // "unsupported" sentinel.
        let target = current_platform_target();
        let real_targets = [
            "darwin-aarch64",
            "darwin-x86_64",
            "linux-aarch64",
            "linux-x86_64",
            "windows-aarch64",
            "windows-x86_64",
        ];
        assert!(
            real_targets.contains(&target),
            "expected one of {real_targets:?} on this platform, got {target:?}"
        );
    }
}
