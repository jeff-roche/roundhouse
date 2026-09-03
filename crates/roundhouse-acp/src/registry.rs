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
//!
//! ## Fix round 1 (coordinator review of this task)
//!
//! - **Item 1 — hardened fetch.** [`fetch_registry`]/[`fetch_quarantine`] no
//!   longer build a default `reqwest` client per call (no timeout, redirect
//!   `Policy::limited(10)` with `https_only: false`, unbounded body read, no
//!   `error_for_status`, verified against the vendored `reqwest-0.13.4`
//!   source). They now take a caller-supplied `&reqwest::Client`;
//!   [`build_registry_http_client`] is the one hardened client this module
//!   builds, and [`RegistryCache::new`] builds and stores one so every
//!   `RegistryCache`-driven fetch is hardened without the caller having to
//!   remember to do it. See [`build_registry_http_client`]'s doc for the
//!   settings and [`MAX_RESPONSE_BYTES`] for the measured size cap.
//! - **Item 2 — `RegistryError::Json` no longer carries a bare
//!   `serde_json::Error`.** Its `Display` interpolates the *decoded* JSON
//!   key verbatim for a `deny_unknown_fields` violation — measured: a
//!   registry payload with a newline- and ANSI-escape-bearing unknown field
//!   name produced raw control characters (a forgeable audit line, ANSI
//!   injected into the `round` TUI) in the rendered message. `Json` is now
//!   built only via [`RegistryError::from_json_error`], which routes the
//!   parser's own message through [`escape_and_cap_peer_str`] before it is
//!   ever placed in a field this type's `Display` reads. (My earlier
//!   judgment call that this was "the deserialization library's own syntax
//!   diagnostic" and out of scope was reviewed and overruled: what matters
//!   is that these are third-party HTTP-fetched bytes reaching a rendered
//!   sink through a `pub` error type this module added, not who authored
//!   the format string.)
//! - **Item 3 — checksum-pinned binaries are now preferred over unverified
//!   package-manager installs.** [`resolve_distribution`] used to prefer
//!   `Npx`/`Uvx` (no digest at all, and `npx` executes install scripts —
//!   the live quarantine list's `"agoragentic-acp": "Postinstall script"`
//!   entry is exactly this hazard already exercised) over a `sha256`-bearing
//!   `Binary`, while the very next check refused a `Binary` for lacking that
//!   digest. Both real agents that publish more than one method (`kilo`,
//!   `sigit`) ship a full binary map with `sha256` on every platform target,
//!   so the old order discarded the checksum-pinned channel in both real
//!   cases. Reversed: a `sha256`-bearing `Binary` for the current platform
//!   is now preferred; `Npx`/`Uvx` are the fallback when no verifiable
//!   binary exists for this platform.
//! - **Item 4 — launch fields are now validated, not just `id`.**
//!   `package`, `cmd`, and `env` all reach a future command line; `id` never
//!   does. See [`is_plausible_package_name`], [`is_safe_relative_cmd`], and
//!   [`forbidden_env_key`] plus their call sites in
//!   `TryFrom<RawDistribution>`.
//! - **Item 5 — an empty quarantine fetch can no longer permanently disarm
//!   quarantine.** [`RegistryCache::finish_quarantine_refresh`] refuses to
//!   overwrite a non-empty cached quarantine list with an empty freshly
//!   fetched one (a `{}` response — from a repo rename, CDN stub, or proxy
//!   interstitial that happens to parse — used to be persisted
//!   unconditionally, and Ruling C-P13(d)'s fail-closed path can never fire
//!   again once *any* cached copy exists).
//! - **Item 6 — [`LaunchConfig`]'s payload is now private.** See its own doc
//!   for why: it used to be a `pub` enum with `pub` fields, directly
//!   assemblable by any caller who also had a `Registry` (itself `pub` all
//!   the way down), which meant possessing a `LaunchConfig` did not imply it
//!   came from [`RegistryCache::resolve_launch`] — a caller could skip
//!   quarantine, the sha256 rule, and the platform check entirely.
//! - **Item 7 — atomic cache writes, plus two previously-unpinned
//!   behaviors.** [`write_json`] now writes to `<path>.tmp` then
//!   `std::fs::rename`s over the real path, so a crash or concurrent writer
//!   cannot leave a truncated cache file readable as one. Two mutations that
//!   survived this module's suite before this round now have dedicated
//!   tests: `resolve_launch` reading a stale cache
//!   (`resolve_launch_resolves_using_a_stale_registry_cache_not_only_a_fresh_one`
//!   in `tests/registry.rs`) and the `id`-field escape site
//!   (`invalid_agent_id_error_escapes_the_offending_id_rather_than_interpolating_it_raw`
//!   in this module's own tests).
//! - **Item 8 — the empty-distribution invariant's doc no longer overclaims
//!   structural enforcement.** `Distribution`'s fields stay `pub` (unlike
//!   `LaunchConfig`'s — the blast radius differs: an empty `Distribution`
//!   degrades to `ResolveError::NoUsableDistribution`, no panic, no unsafe
//!   resolve, and it is otherwise a plain data carrier tests legitimately
//!   construct directly), and its doc now says "enforced at deserialize
//!   time" rather than "enforced in the type system."

use crate::peer_text::{escape_and_cap_peer_str, EscapedPeerStr};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// How long [`build_registry_http_client`]'s client waits for a TCP+TLS
/// connection before giving up. Same value and rationale as
/// `roundhouse-provider`'s `reqwest_transport.rs` `CONNECT_TIMEOUT` and
/// `roundhouse-tools`'s `http.rs` `CONNECT_TIMEOUT`: generous enough for a
/// cold handshake over a slow link, short enough that an unroutable host
/// fails the refresh instead of hanging it.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Total request deadline (connect through body-read) for a registry or
/// quarantine fetch. The live registry index measured 52,974 bytes on
/// 2026-09-01/2026-09-02 (see module doc); 30s is far more than transferring
/// that much data over any real link takes, while still bounding a stalled
/// or adversarially slow-drip response — a request timeout, not merely a
/// read-inactivity timeout, matters here specifically because
/// [`fetch_json_capped`] reads the body in a loop that could otherwise be
/// kept alive indefinitely by a peer trickling bytes just fast enough to
/// reset a per-chunk timer.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Hard cap, in bytes, on a fetched registry or quarantine response body.
/// Per the quantitative-claim rule: the live registry index
/// (`https://cdn.agentclientprotocol.com/registry/v1/latest/registry.json`)
/// measured 52,974 bytes on 2026-09-01/2026-09-02 (see module doc and
/// `ACP-REGISTRY-FORMAT.md`). This cap is roughly 20x that — enough headroom
/// for the real index to grow substantially before this module has to be
/// revisited, while still bounding a hostile or misconfigured endpoint from
/// streaming an unbounded response into memory. [`fetch_json_capped`]
/// enforces it both against a declared `Content-Length` (fails fast, before
/// reading any body) and against the running total while reading
/// (`Content-Length` can be absent or wrong).
const MAX_RESPONSE_BYTES: usize = 1_048_576;

/// Environment variable names a registry entry's `env` map is not allowed to
/// set (Item 4). Every one of these controls what code loads into, or where,
/// a spawned process looks for its own libraries or interpreter — the same
/// hazard the standing `AcpAgent::spawn` prohibition on this crate exists to
/// prevent, arriving here from the registry side instead of the spawn side.
/// Checked case-insensitively in [`forbidden_env_key`]: environment variable
/// names are case-sensitive on POSIX but not on Windows, and this module
/// must not depend on which platform eventually spawns the process.
const FORBIDDEN_ENV_KEYS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "NODE_OPTIONS",
    "PYTHONPATH",
    "PERL5LIB",
    "PATH",
];

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
/// is validated by [`TryFrom`] to reject an empty object and, as of fix
/// round 1 (Item 4), an implausible `npx`/`uvx` package name, an unsafe
/// `binary` `cmd`, or a forbidden `env` key — "distribution has at least one
/// variant" (Ruling C-P13(a)) and these newer checks are all **enforced at
/// deserialize time**, not structurally: `npx`, `uvx`, and `binary` stay
/// `pub` fields (unlike [`LaunchConfig`]'s, see its doc for why that one
/// *is* structural), so `Distribution { npx: None, uvx: None, binary:
/// BTreeMap::new() }` remains directly constructible outside the
/// deserialize path — this doc previously overclaimed "enforced in the type
/// system," which was true only of the `serde(try_from)` path. The
/// consequence of that gap is benign and stays that way: an empty or
/// invalid `Distribution` built directly (as this module's own tests
/// legitimately do) degrades [`resolve_distribution`] to
/// `ResolveError::NoUsableDistribution`, never a panic or an unsafe resolve.
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
        if let Some(npx) = &raw.npx {
            validate_package_distribution("npx", npx)?;
        }
        if let Some(uvx) = &raw.uvx {
            validate_package_distribution("uvx", uvx)?;
        }
        for (target, binary) in &raw.binary {
            validate_binary_target(target, binary)?;
        }
        Ok(Distribution {
            npx: raw.npx,
            uvx: raw.uvx,
            binary: raw.binary,
        })
    }
}

/// Item 4: validates the two launch fields a `PackageDistribution` exposes
/// that actually reach a future command line (`package`, `env`) — `kind` is
/// `"npx"` or `"uvx"`, used only to make the error message say which.
fn validate_package_distribution(kind: &str, dist: &PackageDistribution) -> Result<(), String> {
    if !is_plausible_package_name(&dist.package) {
        return Err(format!(
            "{kind} package name is not a plausible npm/PyPI package identifier: {}",
            escape_and_cap_peer_str(&dist.package)
        ));
    }
    if let Some(key) = forbidden_env_key(&dist.env) {
        return Err(format!(
            "{kind} env sets a forbidden variable: {}",
            escape_and_cap_peer_str(key)
        ));
    }
    Ok(())
}

/// Item 4: validates a `BinaryTarget`'s `cmd` and `env` — `target` is the
/// platform key (e.g. `"linux-x86_64"`), included in the error message and
/// escaped like any other registry-controlled string.
fn validate_binary_target(target: &str, binary: &BinaryTarget) -> Result<(), String> {
    if !is_safe_relative_cmd(&binary.cmd) {
        return Err(format!(
            "binary target {}'s cmd is not a safe relative path (must not be absolute or contain a `..` segment): {}",
            escape_and_cap_peer_str(target),
            escape_and_cap_peer_str(&binary.cmd)
        ));
    }
    if let Some(key) = forbidden_env_key(&binary.env) {
        return Err(format!(
            "binary target {}'s env sets a forbidden variable: {}",
            escape_and_cap_peer_str(target),
            escape_and_cap_peer_str(key)
        ));
    }
    Ok(())
}

/// Item 4: minimal plausibility check for an `npx`/`uvx` `package` field —
/// "reject a package outside the npm/PyPI name grammar (at minimum, reject a
/// leading `-`)." Deliberately not a full npm/PyPI name validator, only the
/// part that is load-bearing for safety: `npx`/`uvx` invoke the string as
/// `npx <package> [args]` / `uvx <package> [args]`, so a leading `-` is
/// consumed as a flag rather than a package name — the concrete example in
/// this task's brief is `--node-options=--require=/tmp/x.js`. Embedded
/// control characters or whitespace have no legitimate place in a real
/// package identifier either.
fn is_plausible_package_name(package: &str) -> bool {
    !package.is_empty()
        && !package.starts_with('-')
        && !package.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// Item 4: whether a binary target's `cmd` is safe to treat as "the
/// extracted archive's own relative executable path" — not absolute, and no
/// path segment is `..`. Live values are all relative (`./kilo`,
/// `./bin\devin.exe`), so this is a real grammar the live data actually
/// follows, not a hypothetical one; checked against both `/` and `\`
/// separators since real entries use either.
fn is_safe_relative_cmd(cmd: &str) -> bool {
    if cmd.is_empty() || Path::new(cmd).is_absolute() {
        return false;
    }
    !cmd.split(['/', '\\']).any(|segment| segment == "..")
}

/// Item 4: the first (if any) of an `env` map's keys that appears in
/// [`FORBIDDEN_ENV_KEYS`], checked case-insensitively.
fn forbidden_env_key(env: &BTreeMap<String, String>) -> Option<&str> {
    env.keys().map(String::as_str).find(|key| {
        FORBIDDEN_ENV_KEYS
            .iter()
            .any(|forbidden| key.eq_ignore_ascii_case(forbidden))
    })
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

    /// `true` if this quarantine list names no agents at all. Used by
    /// [`RegistryCache::finish_quarantine_refresh`] (Item 5) to decide
    /// whether a freshly-fetched quarantine list is allowed to overwrite a
    /// cached one.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The single, resolved launch method for one agent — what
/// [`RegistryCache::resolve_launch`] actually returns. This is the
/// mutually-exclusive three-variant enum Ruling C-P13(b) describes.
///
/// **Fix round 1 (Item 6): the payload is a private inner enum
/// ([`LaunchConfigKind`]), reached only through the accessor methods below —
/// not a `pub` enum with `pub` fields.** Before this round, `Registry.agents`
/// / `RegistryAgent.distribution` / `Distribution`'s own `npx`/`uvx`/`binary`
/// fields were already all `pub`, so a caller holding any fetched `Registry`
/// could assemble a `LaunchConfig::Binary { .. }` directly — skipping
/// quarantine, the `sha256` rule, and the platform check this module exists
/// to enforce. `resolve_launch` would then be one convenience among several
/// ways to obtain a `LaunchConfig`, rather than the only way. Because
/// `LaunchConfigKind` is private and this type exposes no public
/// constructor, the mere existence of a `LaunchConfig` value now implies it
/// was produced by [`resolve_distribution`] (called only from
/// [`RegistryCache::resolve_launch`]) — the identical argument, and the
/// identical fix shape, as [`crate::peer_text::EscapedPeerStr`]'s private
/// inner field: "the constructor escapes/validates it" was insufficient
/// there for the same reason a `pub`-fielded enum here would have been.
///
/// `Binary`'s fields are exactly what `resolve_launch` is allowed to return
/// per Ruling C-P13(c): the caller (daemon, out of scope for this crate) owns
/// downloading `archive`, verifying it against `sha256`, extracting it, and
/// running `cmd`/`args`/`env` — nothing here does any of that, or turns this
/// into anything spawnable.
#[derive(Debug, Clone, PartialEq)]
pub struct LaunchConfig(LaunchConfigKind);

#[derive(Debug, Clone, PartialEq)]
enum LaunchConfigKind {
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

impl LaunchConfig {
    /// Private — see the type's doc. Only [`resolve_distribution`] calls
    /// this.
    fn npx(package: String, args: Vec<String>, env: BTreeMap<String, String>) -> Self {
        Self(LaunchConfigKind::Npx { package, args, env })
    }

    /// Private — see the type's doc. Only [`resolve_distribution`] calls
    /// this.
    fn uvx(package: String, args: Vec<String>, env: BTreeMap<String, String>) -> Self {
        Self(LaunchConfigKind::Uvx { package, args, env })
    }

    /// Private — see the type's doc. Only [`resolve_distribution`] calls
    /// this.
    #[allow(clippy::too_many_arguments)]
    fn binary(
        target: String,
        archive: String,
        sha256: Option<String>,
        cmd: String,
        args: Vec<String>,
        env: BTreeMap<String, String>,
    ) -> Self {
        Self(LaunchConfigKind::Binary {
            target,
            archive,
            sha256,
            cmd,
            args,
            env,
        })
    }

    /// `true` for a value produced from an agent's `npx` distribution.
    pub fn is_npx(&self) -> bool {
        matches!(self.0, LaunchConfigKind::Npx { .. })
    }

    /// `true` for a value produced from an agent's `uvx` distribution.
    pub fn is_uvx(&self) -> bool {
        matches!(self.0, LaunchConfigKind::Uvx { .. })
    }

    /// `true` for a value produced from an agent's `binary` distribution.
    pub fn is_binary(&self) -> bool {
        matches!(self.0, LaunchConfigKind::Binary { .. })
    }

    /// The package identifier to pass to `npx`/`uvx`. `None` for `Binary`.
    pub fn package(&self) -> Option<&str> {
        match &self.0 {
            LaunchConfigKind::Npx { package, .. } | LaunchConfigKind::Uvx { package, .. } => {
                Some(package)
            }
            LaunchConfigKind::Binary { .. } => None,
        }
    }

    /// Extra command-line arguments. Present (possibly empty) on every
    /// variant.
    pub fn args(&self) -> &[String] {
        match &self.0 {
            LaunchConfigKind::Npx { args, .. }
            | LaunchConfigKind::Uvx { args, .. }
            | LaunchConfigKind::Binary { args, .. } => args,
        }
    }

    /// Extra environment variables. Present (possibly empty) on every
    /// variant.
    pub fn env(&self) -> &BTreeMap<String, String> {
        match &self.0 {
            LaunchConfigKind::Npx { env, .. }
            | LaunchConfigKind::Uvx { env, .. }
            | LaunchConfigKind::Binary { env, .. } => env,
        }
    }

    /// The registry's platform-target string this was resolved for (e.g.
    /// `"linux-x86_64"`). `None` unless this is `Binary`.
    pub fn target(&self) -> Option<&str> {
        match &self.0 {
            LaunchConfigKind::Binary { target, .. } => Some(target),
            _ => None,
        }
    }

    /// The archive download URL. `None` unless this is `Binary`.
    pub fn archive(&self) -> Option<&str> {
        match &self.0 {
            LaunchConfigKind::Binary { archive, .. } => Some(archive),
            _ => None,
        }
    }

    /// The archive's SHA-256 checksum. `None` unless this is `Binary` — and,
    /// per Ruling C-P13(c), always `Some` when it is: a `Binary` with no
    /// `sha256` for the current platform is surfaced as
    /// [`ResolveError::UnverifiableBinary`] rather than ever reaching this
    /// type.
    pub fn sha256(&self) -> Option<&str> {
        match &self.0 {
            LaunchConfigKind::Binary { sha256, .. } => sha256.as_deref(),
            _ => None,
        }
    }

    /// The command to run after extracting `archive`. `None` unless this is
    /// `Binary`.
    pub fn cmd(&self) -> Option<&str> {
        match &self.0 {
            LaunchConfigKind::Binary { cmd, .. } => Some(cmd),
            _ => None,
        }
    }
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
///
/// **Fix round 1 (Item 2): `Json` no longer wraps a bare `serde_json::Error`
/// via `#[from]`.** `serde_json`'s `deny_unknown_fields` diagnostic
/// interpolates the *decoded* JSON key verbatim into its `Display` — measured
/// against this crate's own `deny_unknown_fields` structs: a 50,000-character
/// attacker-chosen field name produced a 50,079-byte rendered error, and a
/// field name containing `\n` and `\u{1b}` produced raw newlines and a raw
/// ANSI escape in the rendered text (a forgeable audit line, and ANSI
/// injected into whatever renders this — the `round` TUI, most concretely).
/// These are third-party HTTP-fetched bytes reaching a rendered sink through
/// a `pub` error type this module adds — the same untrusted-text class
/// [`crate::peer_text`] exists for. `Json` is now only ever constructed via
/// [`RegistryError::from_json_error`], which extracts `line`/`column` (plain
/// numbers, safe to interpolate as-is) and routes the parser's own message
/// through [`escape_and_cap_peer_str`] before it reaches a field this type's
/// `Display` reads.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("http error fetching registry data: {0}")]
    Http(#[from] reqwest::Error),
    #[error("invalid registry json at line {line} column {column}: {detail}")]
    Json {
        detail: EscapedPeerStr,
        line: usize,
        column: usize,
    },
    #[error("registry cache io error: {0}")]
    Io(#[from] std::io::Error),
    /// Item 1: the fetched body exceeded [`MAX_RESPONSE_BYTES`] — either a
    /// declared `Content-Length` over the cap (checked before any body is
    /// read) or the running total while streaming the body exceeded it
    /// (`Content-Length` can be absent or wrong). `url` is the
    /// caller-supplied fetch URL, not registry-derived text, so it is not
    /// routed through `EscapedPeerStr`.
    #[error("response from {url} exceeded the {limit}-byte size cap (received at least {received} bytes)")]
    ResponseTooLarge {
        url: String,
        limit: usize,
        received: usize,
    },
}

impl RegistryError {
    /// The one place a `serde_json::Error` becomes a `RegistryError::Json` —
    /// see the variant's doc for why this exists instead of `#[from]`.
    fn from_json_error(err: serde_json::Error) -> Self {
        RegistryError::Json {
            line: err.line(),
            column: err.column(),
            detail: escape_and_cap_peer_str(&err.to_string()),
        }
    }
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

/// Item 1: builds the one hardened `reqwest::Client` this module ever
/// constructs — [`RegistryCache::new`] builds and stores one, so every fetch
/// driven through a `RegistryCache` is hardened without the caller having to
/// remember to ask for it. [`fetch_registry`]/[`fetch_quarantine`] also
/// accept a client as a parameter rather than building their own, precisely
/// so a caller cannot be stuck with `reqwest::get`'s unhardened default (no
/// timeout; redirect `Policy::limited(10)` with `https_only: false`,
/// allowing a hostile redirect to downgrade the fetch to plaintext) —
/// verified against the vendored `reqwest-0.13.4` source
/// (`async_impl/client.rs:299-314`, `redirect.rs:161-163,279`).
///
/// - `.https_only(true)`: registry content carries no signature of its own —
///   HTTPS is the sole integrity control, so a downgrade to `http://` (via a
///   misconfigured URL or a redirect) must fail outright rather than silently
///   serve attacker-interceptable content.
/// - `.redirect(redirect::Policy::limited(2))`: some redirection is
///   legitimate (the registry is CDN-fronted), but `reqwest`'s own default of
///   10 is far more hops than any legitimate single-CDN redirect chain needs;
///   combined with `https_only(true)` above, a redirect can no longer be used
///   to downgrade the scheme.
/// - `.connect_timeout(CONNECT_TIMEOUT)` / `.timeout(FETCH_TIMEOUT)`: see
///   those constants' docs.
///
/// Panics only if the TLS backend cannot initialize at all — a
/// process-startup environment failure, not something request or response
/// data can trigger — matching the same `.expect(...)` convention
/// `roundhouse-provider`'s `reqwest_transport.rs` and `roundhouse-tools`'s
/// `http.rs` already use for their own `reqwest::Client` construction.
pub fn build_registry_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::limited(2))
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(FETCH_TIMEOUT)
        .build()
        .expect("TLS backend initialization")
}

/// Item 1: fetches `url` through `client`, enforcing [`MAX_RESPONSE_BYTES`]
/// and treating a 4xx/5xx status as an error (`.error_for_status()` — the
/// original implementation had neither, so a 404/500 error page's body went
/// straight to `serde_json`), then deserializes the (capped) body as `T`.
/// Shared by [`fetch_registry`] and [`fetch_quarantine`].
async fn fetch_json_capped<T: DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
) -> Result<T, RegistryError> {
    let mut response = client.get(url).send().await?.error_for_status()?;

    if let Some(len) = response.content_length() {
        if len as usize > MAX_RESPONSE_BYTES {
            return Err(RegistryError::ResponseTooLarge {
                url: url.to_string(),
                limit: MAX_RESPONSE_BYTES,
                received: len as usize,
            });
        }
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(RegistryError::ResponseTooLarge {
                url: url.to_string(),
                limit: MAX_RESPONSE_BYTES,
                received: body.len(),
            });
        }
    }

    serde_json::from_slice(&body).map_err(RegistryError::from_json_error)
}

/// §10.3: "Consume it rather than hardcoding agent launch configs." Fetches
/// the real registry over HTTP through `client` — see
/// [`build_registry_http_client`] for the hardening this requires, and
/// [`fetch_json_capped`] for the size cap and status/error handling.
///
/// Ruling C-P11: `async`, using reqwest's default async client — never
/// `reqwest::blocking` (this crate has no `blocking` feature enabled; see
/// `Cargo.toml`). The stated consumer, `roundhouse-daemon`, is tokio-based,
/// and `reqwest::blocking` panics when called from inside a tokio runtime.
pub async fn fetch_registry(
    client: &reqwest::Client,
    url: &str,
) -> Result<Registry, RegistryError> {
    fetch_json_capped(client, url).await
}

/// Fetches the quarantine list over HTTP through `client`. Same rationale as
/// [`fetch_registry`].
pub async fn fetch_quarantine(
    client: &reqwest::Client,
    url: &str,
) -> Result<Quarantine, RegistryError> {
    fetch_json_capped(client, url).await
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

/// Item 7: writes `<path>.tmp` then `std::fs::rename`s it over `path`, so a
/// crash or a concurrent writer can never leave a truncated file readable as
/// the real cache — the failure direction was already safe (a truncated
/// pretty-printed JSON object never re-parses, so the cache degrades to
/// "nothing cached" rather than corrupting silently), but a bare `fs::write`
/// left a window where a reader could observe a partially-written file. The
/// rename is atomic within the same filesystem, which `<path>.tmp` always is
/// by construction (same directory as `path`).
fn write_json<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(value).map_err(std::io::Error::other)?;
    let mut tmp_path = path.as_os_str().to_os_string();
    tmp_path.push(".tmp");
    let tmp_path = PathBuf::from(tmp_path);
    std::fs::write(&tmp_path, body)?;
    std::fs::rename(&tmp_path, path)
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
    /// Item 1: built once by [`Self::new`] via [`build_registry_http_client`]
    /// and reused by every [`Self::refresh_registry`]/
    /// [`Self::refresh_quarantine`] call, so a `RegistryCache` is always
    /// hardened without its caller having to remember to ask for it, and so
    /// the underlying connection pool is reused across refreshes rather than
    /// paying a fresh TLS handshake every time.
    client: reqwest::Client,
}

impl RegistryCache {
    pub fn new(registry_path: PathBuf, quarantine_path: PathBuf, ttl: Duration) -> Self {
        Self {
            registry_path,
            quarantine_path,
            ttl,
            client: build_registry_http_client(),
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
        self.finish_registry_refresh(fetch_registry(&self.client, url).await)
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
        self.finish_quarantine_refresh(fetch_quarantine(&self.client, url).await)
    }

    /// Item 5: refuses to persist an *empty* freshly-fetched quarantine list
    /// over a *non-empty* cached one. Before this guard, any response that
    /// happened to parse as `{}` — a repo rename, a CDN stub, a proxy
    /// interstitial, all made more likely by this round's Item 1 not yet
    /// existing (no `error_for_status` meant even a 404 body could reach
    /// here) — was persisted unconditionally, and once *any* quarantine
    /// cache exists, Ruling C-P13(d)'s fail-closed
    /// (`ResolveError::QuarantineUnavailable`) path can never fire again: a
    /// disarmed quarantine looks identical to a cache that has always been
    /// legitimately empty. The guard only applies to this automatic refresh
    /// path — [`Self::store_quarantine`] itself stays unconditional, which is
    /// the "explicit override" an operator or test that genuinely wants to
    /// force an empty quarantine can still reach for.
    fn finish_quarantine_refresh(
        &self,
        fetched: Result<Quarantine, RegistryError>,
    ) -> Result<Quarantine, RegistryError> {
        match fetched {
            Ok(quarantine) => {
                if quarantine.is_empty() {
                    if let Some(cached) = self.load_quarantine_cached() {
                        if !cached.is_empty() {
                            return Ok(cached);
                        }
                    }
                }
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
/// published [`Distribution`] methods.
///
/// **Fix round 1 (Item 3): a `sha256`-bearing `Binary` for the current
/// platform is now preferred over `Npx`/`Uvx`; package managers are the
/// fallback, used only when no verifiable binary exists for this platform.**
/// The previous order (`npx` > `uvx` > `binary`) inverted the actual
/// integrity argument: `Npx`/`Uvx` carry no digest at all *and* `npx`
/// executes install scripts — the live quarantine list's
/// `"agoragentic-acp": "Postinstall script"` entry is exactly this hazard
/// already having been exercised — while the very next check below refuses a
/// `Binary` specifically for lacking a `sha256`. Verified against live data:
/// the only two agents that reach this function with more than one
/// distribution method (`kilo`, `sigit`) each publish a full `binary` map
/// with `sha256` on every platform target, so the old order discarded the
/// checksum-pinned channel in both real cases that exist. A `Binary` present
/// for the current platform but missing `sha256` is still surfaced as
/// [`ResolveError::UnverifiableBinary`], never silently skipped in favor of
/// package managers — that would just move the same hazard one branch later.
fn resolve_distribution(agent: &RegistryAgent) -> Result<LaunchConfig, ResolveError> {
    let target = current_platform_target();
    let binary_for_platform = agent.distribution.binary.get(target);

    if let Some(binary) = binary_for_platform {
        if let Some(sha256) = &binary.sha256 {
            return Ok(LaunchConfig::binary(
                target.to_string(),
                binary.archive.clone(),
                Some(sha256.clone()),
                binary.cmd.clone(),
                binary.args.clone(),
                binary.env.clone(),
            ));
        }
    }

    if let Some(npx) = &agent.distribution.npx {
        return Ok(LaunchConfig::npx(
            npx.package.clone(),
            npx.args.clone(),
            npx.env.clone(),
        ));
    }
    if let Some(uvx) = &agent.distribution.uvx {
        return Ok(LaunchConfig::uvx(
            uvx.package.clone(),
            uvx.args.clone(),
            uvx.env.clone(),
        ));
    }

    if binary_for_platform.is_some() {
        // Present for this platform, but the `sha256` check above didn't
        // return — it must be missing, and there was no package-manager
        // fallback either.
        return Err(ResolveError::UnverifiableBinary {
            agent_id: escape_and_cap_peer_str(&agent.id),
            target: escape_and_cap_peer_str(target),
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
        RegistryError::from_json_error(serde_json::from_str::<Registry>("not json").unwrap_err())
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

    // ---- Item 2: RegistryError::Json must never carry raw registry bytes ----

    #[test]
    fn registry_error_json_escapes_a_control_character_bearing_field_name() {
        // A malicious registry response whose `deny_unknown_fields` violation
        // involves a field name carrying a newline and an ANSI escape
        // introducer, expressed as real JSON escape sequences (JSON's
        // \n and \u001b) so this is valid JSON that decodes to a key
        // containing actual control characters -- measured (see module
        // doc) to produce a raw newline and a raw control character in
        // serde_json::Error's own Display before this fix.
        let malicious = "{\"package\": \"x\", \"x\\n\\u001b[31m[audit] ALLOW ALL\": true}";
        let err = serde_json::from_str::<PackageDistribution>(malicious).unwrap_err();
        let wrapped = RegistryError::from_json_error(err);
        let rendered = wrapped.to_string();
        assert!(
            !rendered.contains('\n'),
            "a raw newline must not survive into RegistryError::Json's Display: {rendered:?}"
        );
        assert!(
            !rendered.contains('\u{1b}'),
            "a raw ANSI escape must not survive into RegistryError::Json's Display: {rendered:?}"
        );
    }

    #[test]
    fn invalid_agent_id_error_escapes_the_offending_id_rather_than_interpolating_it_raw() {
        // Pins the escape_and_cap_peer_str(&raw.id) call site in
        // TryFrom<RawRegistryAgent> — the coordinator's reviewer mutated this
        // to `&raw.id` (dropping the escape) and the rest of the suite still
        // passed, because no other test exercised an id containing a raw
        // control character.
        let json = r#"{"id": "bad\nid[audit] fake", "name": "x", "distribution": {"npx": {"package": "p"}}}"#;
        let err = serde_json::from_str::<RegistryAgent>(json).unwrap_err();
        let msg = err.to_string();
        assert!(
            !msg.contains('\n'),
            "a raw newline from the invalid id must not survive into the error message: {msg:?}"
        );
        assert!(
            msg.contains("\\n"),
            "the escaped form must appear instead: {msg:?}"
        );
    }

    // ---- Item 5: an empty quarantine fetch must not disarm a non-empty cache ----

    #[test]
    fn finish_quarantine_refresh_refuses_to_overwrite_a_nonempty_cache_with_an_empty_fetch() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RegistryCache::new(
            dir.path().join("registry.json"),
            dir.path().join("quarantine.json"),
            Duration::from_secs(3600),
        );
        let mut quarantine = Quarantine::default();
        quarantine.insert("crow-cli".to_string(), "ACP initialize fails".to_string());
        cache.store_quarantine(&quarantine).unwrap();

        // A `{}` response — deserializes cleanly to an empty Quarantine.
        let result = cache.finish_quarantine_refresh(Ok(Quarantine::default()));
        assert!(
            result
                .expect("must not error, just refuse to disarm")
                .is_quarantined("crow-cli"),
            "the returned value must still be the non-empty cached quarantine, not the empty fetch"
        );

        // The guard must also apply to what's actually persisted on disk —
        // not just the in-memory return value — otherwise the next process
        // to start up would load the (wrongly) disarmed cache from disk.
        let still_cached = cache
            .load_quarantine_cached()
            .expect("quarantine cache file must still exist");
        assert!(
            still_cached.is_quarantined("crow-cli"),
            "the on-disk quarantine cache must not have been overwritten with the empty fetch"
        );
    }

    #[test]
    fn finish_quarantine_refresh_accepts_an_empty_fetch_when_the_cache_was_already_empty_or_absent()
    {
        // The Item 5 guard must not make an empty quarantine unreachable
        // forever — only refuse to *regress* a non-empty cache.
        let dir = tempfile::tempdir().unwrap();
        let cache = RegistryCache::new(
            dir.path().join("registry.json"),
            dir.path().join("quarantine.json"),
            Duration::from_secs(3600),
        );
        let result = cache.finish_quarantine_refresh(Ok(Quarantine::default()));
        assert!(result.unwrap().is_empty());
    }
}
