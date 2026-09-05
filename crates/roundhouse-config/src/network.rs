//! Parses the `[network] allowed_hosts = [...]` TOML section out of layered
//! config into a plain, self-contained [`NetworkConfig`] — a
//! `Vec<String>`-shaped allowlist and nothing more. This crate must stay
//! free of every `roundhouse-*` dependency (`docs/architecture/
//! 02-system-architecture.md` §5.2's `roundhouse-config` row), so converting
//! this into a real `roundhouse_net::policy::EgressPolicy` happens *above*
//! this crate, in `roundhouse-engine` — see
//! `roundhouse_engine::egress_policy_from_allowed_hosts`.
//!
//! # Security review fix round 1 (same defect class as `mcp_config.rs`'s
//! ruling W1-R16) — `[network] allowed_hosts` is a widening primitive
//!
//! `ConfigScope`'s own doc comment states outright that §6.2's narrow-only,
//! trust-gated precedence for project-scoped config ("Project scope may
//! narrow, never widen, unless the user has recorded a trust decision") is
//! "not implemented anywhere in this crate" — `ConfigLoader::load`'s plain
//! layered TOML merge (`merge_into` in `loader.rs`) replaces a wider
//! scope's value for a key with a narrower scope's value wholesale. An
//! egress allowlist is exactly the widening-sensitive key §6.2 is worried
//! about: if `[network] allowed_hosts` were read out of a `LoadedConfig`
//! built the ordinary way (which merges in `<repo_root>/.roundhouse/
//! config.toml` at `ConfigScope::Project`), cloning a hostile repository
//! and opening a session inside it would let that repo authorize its own
//! exfiltration destination — an operator's real allowlist silently
//! replaced (or padded) by whatever the repo's own config says.
//!
//! Unlike `mcp_config.rs`'s fix (structurally drop `Project` scope
//! entirely, because a merged `LoadedConfig` carries no per-key
//! provenance), this module implements §6.2's actual narrow-only rule for
//! real: [`load_network_config_from_layers`] loads each configured scope
//! through its **own**, single-layer `ConfigLoader` (never the shared
//! multi-layer merge), so it always knows exactly which scope contributed
//! which value. `Builtin`/`UserGlobal` layers may *establish* (or replace)
//! the allowlist; `Project`/`Workspace` layers may only **intersect** it
//! with whatever they list, narrowing but never adding a host the wider
//! scope didn't already allow. Critically, this holds even when the wider
//! scope never set `allowed_hosts` at all (baseline `[]`, the fail-closed
//! default): intersecting `[]` with anything a project layer supplies is
//! still `[]` — a project config cannot *establish* the allowlist, only
//! ever shrink one that already exists. See this module's tests for the
//! load-bearing case (`user_unset_project_widens_is_still_denied`).
//!
//! [`load_network_config_from_layers`] deliberately takes
//! `layers: Vec<(ConfigScope, PathBuf)>`, not a pre-merged `&LoadedConfig`
//! (the brief's original sketch) — a merged `LoadedConfig` has already
//! thrown away per-scope provenance, which is the one piece of information
//! this narrow-only rule needs. Same shape of deviation as `mcp_config.rs`'s
//! `load_mcp_servers`, for the same reason.
//!
//! **Phase 7, Task 7 (CF-11(b) / Task 4's M2):** that caller-labeled
//! `layers` parameter is exactly the shape a real production caller could
//! mislabel — hand-building
//! `vec![(ConfigScope::UserGlobal, repo_root.join(".roundhouse/config.toml"))]`
//! would reintroduce the whole widening attack this module exists to
//! prevent, with no compiler or test objection. [`load_network_config`]
//! (below) is the fix: it takes a `project_root` and builds `layers` itself
//! via [`default_layers`], the one trusted source of scope labels, so there
//! is no label left for a caller to get wrong. Use it, not
//! [`load_network_config_from_layers`], from any real production call site.

use crate::loader::{default_layers, ConfigError, ConfigLoader};
use crate::scope::ConfigScope;
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Failure loading or parsing the `[network]` config section.
#[derive(Debug, thiserror::Error)]
pub enum NetworkConfigError {
    #[error("failed to read/parse a config layer: {0}")]
    Load(#[from] ConfigError),
    #[error("failed to parse [network] config: {0}")]
    Parse(#[from] toml::de::Error),
}

/// A session's egress allowlist, sourced from config — a plain
/// `Vec<String>`-shaped type with no `roundhouse-*` dependency (see this
/// module's doc comment for why). Converting this into a real
/// `roundhouse_net::policy::EgressPolicy` is the caller's job, above this
/// crate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkConfig {
    pub allowed_hosts: Vec<String>,
}

/// The raw `[network]` TOML table. `allowed_hosts` is `Option` — absent
/// means "this scope said nothing about the allowlist" (never narrows,
/// never establishes), which is a different, load-bearing state from
/// `Some(vec![])` ("this scope explicitly narrowed to nothing").
#[derive(Debug, Deserialize, Default)]
struct NetworkSection {
    #[serde(default)]
    allowed_hosts: Option<Vec<String>>,
}

impl NetworkConfigError {
    /// A short, static, never-attacker-influenced name for the SHAPE of
    /// this error — deliberately never the error's own `Display` (fix
    /// round 2, MUST 1). `ConfigError::Parse`'s `Display` (and, one layer
    /// up, `NetworkConfigError::Parse`'s) embeds `toml::de::Error`'s own
    /// rendering, which includes a verbatim snippet of the offending
    /// file's text at the parse-error location. For a rejected PROJECT
    /// layer, that text is authored by whoever wrote the cloned
    /// repository — logging it is a real ANSI/terminal-escape injection
    /// primitive into the operator's own terminal, proven against the
    /// built binary (a `.roundhouse/config.toml` with clear-screen and
    /// cursor-home sequences rendered a credible fake password prompt the
    /// moment the log line ran). `pub` so both this crate's own logging
    /// and `roundhouse-daemon`'s (the operator's OWN `[network]` config
    /// error, at boot — CF-11(c) applies there too, and copy-pasted or
    /// journal-displayed operator config is not immune to the same class
    /// of injection) can log a fact about the error without ever risking
    /// its `Display`.
    pub fn kind(&self) -> &'static str {
        match self {
            NetworkConfigError::Load(ConfigError::Io { .. }) => "io_error",
            NetworkConfigError::Load(ConfigError::Parse { .. }) => "toml_parse_error",
            NetworkConfigError::Load(ConfigError::NotARegularFile { .. }) => "not_a_regular_file",
            NetworkConfigError::Load(ConfigError::TooLarge { .. }) => "too_large",
            NetworkConfigError::Parse(_) => "network_section_parse_error",
        }
    }
}

/// Reads one scope's `[network] allowed_hosts`, in isolation, via its own
/// single-layer `ConfigLoader` — never through the shared multi-layer
/// merge, so the result is unambiguously "what this one scope's file (if
/// any) says," with no risk of a narrower scope's value already having
/// silently replaced it. Returns `Ok(None)` when the file doesn't exist or
/// doesn't set `[network] allowed_hosts` at all.
fn hosts_for_layer(
    scope: ConfigScope,
    path: &std::path::Path,
) -> Result<Option<Vec<String>>, NetworkConfigError> {
    if !path.exists() {
        return Ok(None);
    }
    let loaded = ConfigLoader::new()
        .with_layer(scope, path.to_path_buf())
        .load()?;
    match loaded.get("network") {
        None => Ok(None),
        Some(value) => {
            let section: NetworkSection = value.clone().try_into()?;
            Ok(section.allowed_hosts)
        }
    }
}

/// Builds `layers` itself via [`default_layers`], so there is no
/// `ConfigScope` label for a caller to attach — and therefore none to get
/// wrong (Phase 7, Task 7, CF-11(b) / Task 4's M2).
///
/// **Why this replaces a caller-supplied `Vec<(ConfigScope, PathBuf)>`:**
/// `default_layers` is the one trusted source of scope labels — it always
/// tags the `$HOME`-derived path `UserGlobal` and the `project_root`-derived
/// path `Project`. A caller that instead hand-built
/// `vec![(ConfigScope::UserGlobal, repo_root.join(".roundhouse/config.toml"))]`
/// (mislabeling a project-controlled path as the wider, trusted scope) would
/// reintroduce the exact widening attack [`load_network_config_from_layers`]'s
/// narrow-only intersection logic exists to prevent, with no compiler or
/// test able to catch the mistake. `roundhouse-daemon`'s `main.rs` is this
/// crate's first and only production caller, which is why the fix is here
/// rather than left as a documented caller obligation.
///
/// [`load_network_config_from_layers`] remains available, unchanged, for
/// tests that need to inject arbitrary per-scope paths to exercise the
/// narrow-only intersection rule directly (its own test module does exactly
/// that, and so does this crate's `tests/network_policy_config.rs`) — this
/// wrapper is what a real caller should reach for.
pub fn load_network_config(
    project_root: Option<&Path>,
) -> Result<NetworkConfig, NetworkConfigError> {
    load_network_config_from_layers(default_layers(project_root))
}

/// The narrow-only intersection logic itself, taking a caller-labeled list
/// of layers directly. See [`load_network_config`]'s doc comment for why a
/// real production caller should use that safe wrapper instead of this
/// function — this one trusts whatever `ConfigScope` label `layers` already
/// carries, which is exactly the shape a hostile caller (or a careless
/// future one) could get wrong.
///
/// Honors §6.2's narrow-only rule for project-scoped config (see this
/// module's doc comment for the full rationale and the attack it closes):
///
/// - A `Builtin`/`UserGlobal` layer's `allowed_hosts`, when present,
///   **replaces** the running allowlist outright (a wider scope is allowed
///   to widen — that's what "wider" means).
/// - A `Project`/`Workspace` layer's `allowed_hosts`, when present, is
///   **intersected** with the running allowlist — it can only remove
///   hosts, never add one the wider scope didn't already allow. This holds
///   even if no wider scope ever set anything (running allowlist `[]`):
///   intersecting `[]` with anything is still `[]`.
/// - **Fix round 1 (W1-R21 as amended by W1-R26):** the intersection
///   normalizes both sides (lowercase, strip one trailing DNS root-anchor
///   dot — see [`entry_covers`]/[`normalize_for_compare`]) **for the
///   comparison only**. The string that survives into the result is
///   always the WIDER scope's own original text, never the narrower
///   scope's — `retain` only ever removes from the wider scope's own
///   `Vec<String>`, so `result ⊆ wider-scope strings` holds *by
///   construction*, not merely by testing (see this module's tests for
///   the load-bearing case). Wildcard vs. literal is handled explicitly:
///   a project wildcard covering a wider literal retains the wider
///   literal; a wider wildcard with only a project literal beneath it
///   retains nothing (a documented, tested over-deny).
/// - No layer setting `allowed_hosts` at all (or no layers present)
///   defaults to an empty allowlist — fail-closed, per Phase 2's rule.
///   `roundhouse_net::policy::EgressPolicy::matches` returns `false` for
///   every host against an empty `allowed_hosts` (confirmed by reading
///   `EgressPolicy::matches`'s `Vec::iter().any(..)` body: an empty vector
///   makes `any` vacuously `false`), so an empty [`NetworkConfig`]
///   genuinely denies all egress rather than being read as "unset, allow
///   all."
///
/// `pub(crate)`, dropped from this crate's root re-export (fix round 1,
/// MUST 5), and no longer merely `#[doc(hidden)]` (fix round 2, MUST 4):
/// CF-11(b)'s whole point was "no label to get wrong," and `#[doc(hidden)]`
/// alone never delivered that — it is documentation-only and leaves the
/// item fully callable via its full path
/// (`roundhouse_config::network::load_network_config_from_layers`) from any
/// crate, which the previous `tests/network_policy_config.rs` compiling and
/// calling it that way proved directly. `pub(crate)` is the real fix: this
/// function is now unreachable from outside this crate by any path,
/// qualified or not. Its tests (previously that external integration file,
/// standing in for "an external caller using the public API") were moved
/// into this module's own `#[cfg(test)]` block below, which can still call
/// a `pub(crate)` item directly — the raw, per-scope-labeled shape this
/// function exposes was never something a real external caller should
/// reach for anyway (see [`load_network_config`]'s doc comment), so nothing
/// of value was lost by no longer exercising it from outside the crate.
pub(crate) fn load_network_config_from_layers(
    layers: Vec<(ConfigScope, PathBuf)>,
) -> Result<NetworkConfig, NetworkConfigError> {
    let mut sorted = layers;
    sorted.sort_by_key(|(scope, _)| *scope);

    let mut allowed_hosts: Vec<String> = Vec::new();
    for (scope, path) in &sorted {
        let hosts = match hosts_for_layer(*scope, path) {
            Ok(Some(hosts)) => hosts,
            Ok(None) => continue,
            // Fix round 1 (SHOULD item): a rejected NARROWER (Project/
            // Workspace) layer — a symlink, an oversized file, malformed
            // TOML — must not collapse the WIDER scope's own, already-valid
            // allowlist to nothing. A hostile cloned repository's
            // `.roundhouse/config.toml` being, say, a symlink to `/dev/zero`
            // (CF-11(a)'s attack) must not ALSO be able to turn "deny one
            // specific egress narrowing" into "deny all egress for this
            // session," which is the practical effect a hard error here
            // would have — this loop's caller (`load_network_config`)
            // otherwise falls back to `NetworkConfig::default()` (empty,
            // deny-all) on ANY error from this function. Treating a broken
            // narrower layer as "contributes nothing" (same as absent) is
            // the honest, minimal-blast-radius response: the operator's own
            // wider allowlist survives untouched, and the broken project
            // layer simply fails to narrow it — which is a safe direction
            // to fail in (an over-permissive project layer was never
            // capable of being honored here anyway, per the narrow-only
            // rule this function already enforces).
            //
            // A rejected WIDER (Builtin/UserGlobal) layer — the operator's
            // OWN config — is NOT given this treatment: that error still
            // propagates, since silently ignoring a broken operator config
            // would mask a real mistake the operator needs to see, not an
            // attack to defend against.
            Err(err) => match scope {
                ConfigScope::Project | ConfigScope::Workspace => {
                    // Fix round 2, MUST 1: `error = %err` used to render
                    // this error's own `Display`, and `NetworkConfigError::Parse`/
                    // `ConfigError::Parse`'s `Display` (via `toml::de::Error`)
                    // embeds a verbatim snippet of the OFFENDING FILE'S OWN
                    // TEXT at the error location — for this exact code
                    // path, a hostile PROJECT config's own content, chosen
                    // by whoever authored the cloned repository. Proven
                    // against the built binary: a `.roundhouse/config.toml`
                    // containing raw ANSI escape sequences (clear-screen,
                    // cursor-home) rendered a credible fake password prompt
                    // in the operator's terminal the moment this line ran.
                    // `error_kind` below names only the error SHAPE — never
                    // any text the parser extracted from the file — so
                    // nothing this daemon did not itself author can ever
                    // reach a terminal through this log line.
                    tracing::warn!(
                        scope = ?scope,
                        path = %path.display(),
                        error_kind = err.kind(),
                        "a narrower [network] config layer failed to load; treating it as \
                         absent rather than discarding the wider scope's own allowlist"
                    );
                    continue;
                }
                ConfigScope::Builtin | ConfigScope::UserGlobal => return Err(err),
            },
        };
        match scope {
            ConfigScope::Builtin | ConfigScope::UserGlobal => {
                allowed_hosts = hosts;
            }
            ConfigScope::Project | ConfigScope::Workspace => {
                // W1-R21 as amended by W1-R26: `retain` only ever REMOVES
                // strings already present in `allowed_hosts` (the WIDER
                // scope's own `Vec<String>`) — it never inserts anything
                // from `hosts` (the narrower, project-authored list). That
                // is what makes `result ⊆ wider-scope strings` hold *by
                // construction*, not merely by testing: no string a
                // hostile repo authored can ever reach the final
                // allowlist, regardless of how `entry_covers` below
                // decides a match. `entry_covers` is consulted only to
                // decide WHETHER to keep a wider entry, never to supply
                // its replacement text.
                allowed_hosts.retain(|wider_entry| {
                    hosts
                        .iter()
                        .any(|narrower_entry| entry_covers(narrower_entry, wider_entry))
                });
            }
        }
    }

    Ok(NetworkConfig { allowed_hosts })
}

/// Lowercases and strips a single trailing `.` (the DNS root-anchor form),
/// for the COMPARISON below only — never applied to anything that ends up
/// in a [`NetworkConfig`]'s `allowed_hosts`. Deliberately duplicated here
/// rather than imported: `roundhouse-config` must carry zero
/// `roundhouse-*` dependencies (verified twice in this lane; see this
/// module's own doc comment), so this cannot call
/// `roundhouse_net::policy::normalize_host` directly. Keep this in sync
/// with that function's shape — same two steps, same order — if it ever
/// changes.
fn normalize_for_compare(host: &str) -> String {
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

/// W1-R26's binding wildcard-vs-literal shape, made explicit rather than
/// inferred from string equality:
///
/// - `narrower_entry` is one entry from the Project/Workspace layer being
///   applied; `wider_entry` is one entry already present in the running
///   (wider-scope) allowlist, considered as a candidate to keep.
/// - If `narrower_entry` is a literal, it covers `wider_entry` only when
///   they name the same host after normalization (case, trailing dot) —
///   this is what lets `"API.GitHub.com"` (wider) and `"api.github.com"`
///   (narrower) recognize each other as the same host without moving
///   either string into the result.
/// - If `narrower_entry` is a `"*.suffix"` wildcard, it covers
///   `wider_entry` when `wider_entry` (normalized) equals `suffix` or ends
///   in `.suffix` — mirroring `roundhouse_net::policy::HostPattern::
///   wildcard_suffix`'s own match semantics (`policy.rs:110-116`), so a
///   **project wildcard covering a wider literal retains the wider
///   literal** (the case the security lens asked to see stated, not
///   inferred).
/// - The reverse is NOT symmetric: a **literal** `narrower_entry` never
///   covers a **wildcard-shaped** `wider_entry` (e.g. narrower
///   `"api.github.com"` against wider `"*.github.com"`) — a single literal
///   cannot cover a wildcard's whole scope, and this function may never
///   invent a new, narrower string that was not already the wider scope's
///   own text. So **a wider wildcard with only a project literal beneath
///   it retains nothing** — a documented, tested over-deny, not an
///   accident.
/// - A narrower wildcard with an empty suffix (e.g. a project author's
///   `"*."`/`"*.."` typo) covers every `wider_entry`, same as
///   `HostPattern::wildcard_suffix("")`'s own documented "matches
///   everything" behavior. This is safe here specifically because
///   `retain` above never inserts: at worst this makes a project layer
///   fail to narrow anything, which is not the widening attack this
///   module exists to prevent. Contrast `roundhouse-engine`'s
///   `egress_policy_from_allowed_hosts` (W1-R23), which guards this exact
///   empty-suffix case for a different reason — there an empty suffix
///   becomes a live, ALLOW-ALL pattern in the final `EgressPolicy` itself,
///   which is a real fail-open; here it can only ever suppress narrowing.
fn entry_covers(narrower_entry: &str, wider_entry: &str) -> bool {
    let wider_n = normalize_for_compare(wider_entry);
    let narrower_n = normalize_for_compare(narrower_entry);
    match narrower_n.strip_prefix("*.") {
        Some(suffix) => {
            suffix.is_empty() || wider_n == suffix || wider_n.ends_with(&format!(".{suffix}"))
        }
        None => narrower_n == wider_n,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fix round 3, MUST 2 self-review: serializes the two tests in this
    /// module that exercise the SAME `tracing::warn!` callsite (the
    /// rejected-narrower-layer branch) where exactly one of them
    /// (`the_real_log_call_site_never_emits_the_hostile_files_own_bytes`)
    /// installs a real subscriber via `tracing::subscriber::with_default`
    /// and the other does not. `tracing`'s callsite-interest cache is
    /// process-global, not per-thread — `cargo test`'s default parallel
    /// test execution can run both on different OS threads at the same
    /// time, and empirically (reproduced once via a full `cargo test
    /// --workspace` run, though not reliably in isolation) that races the
    /// interest cache and can make the tracing-subscriber test observe NO
    /// captured output at all, even though the log call genuinely ran.
    /// Acquiring this lock at the top of both tests removes the race by
    /// construction — they simply never run concurrently with each other.
    static CALLSITE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn write(dir: &std::path::Path, name: &str, contents: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    /// Fix round 2, MUST 4: folded in from the now-deleted
    /// `tests/network_policy_config.rs` — the one case there that wasn't
    /// already duplicated by an existing test here: zero layers at all
    /// (as opposed to `absent_network_section_means_empty_allowlist_fail_
    /// closed` below, which has one present layer whose file just doesn't
    /// set `[network]`).
    #[test]
    fn no_layers_at_all_default_to_a_fail_closed_empty_allowlist() {
        let cfg = load_network_config_from_layers(vec![]).unwrap();
        assert_eq!(cfg, NetworkConfig::default());
        assert!(cfg.allowed_hosts.is_empty());
    }

    #[test]
    fn absent_network_section_means_empty_allowlist_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "config.toml", "");
        let cfg = load_network_config_from_layers(vec![(ConfigScope::UserGlobal, path)]).unwrap();
        assert!(cfg.allowed_hosts.is_empty());
    }

    #[test]
    fn a_user_global_allowlist_is_honored() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "config.toml",
            "[network]\nallowed_hosts = [\"api.github.com\", \"crates.io\"]\n",
        );
        let cfg = load_network_config_from_layers(vec![(ConfigScope::UserGlobal, path)]).unwrap();
        assert_eq!(
            cfg.allowed_hosts,
            vec!["api.github.com".to_string(), "crates.io".to_string()]
        );
    }

    #[test]
    fn a_project_scoped_host_that_is_already_in_the_user_allowlist_survives_intersection() {
        let dir = tempfile::tempdir().unwrap();
        let user = write(
            dir.path(),
            "user.toml",
            "[network]\nallowed_hosts = [\"api.github.com\", \"crates.io\"]\n",
        );
        let project = write(
            dir.path(),
            "project.toml",
            "[network]\nallowed_hosts = [\"api.github.com\"]\n",
        );
        let cfg = load_network_config_from_layers(vec![
            (ConfigScope::UserGlobal, user),
            (ConfigScope::Project, project),
        ])
        .unwrap();
        assert_eq!(cfg.allowed_hosts, vec!["api.github.com".to_string()]);
    }

    /// The load-bearing test: a project layer trying to ADD a host the user
    /// never allowed must never be honored, even (especially) when the user
    /// layer never set `allowed_hosts` at all — the fail-closed default
    /// (`[]`) must not be treated as "unset, so the project's list wins."
    /// This directly reproduces the attack the security review named: a
    /// cloned repo's `.roundhouse/config.toml` trying to add its own
    /// exfiltration destination to the egress allowlist.
    #[test]
    fn user_unset_project_widening_is_still_denied() {
        let dir = tempfile::tempdir().unwrap();
        let user = write(dir.path(), "user.toml", "");
        let project = write(
            dir.path(),
            "project.toml",
            "[network]\nallowed_hosts = [\"evil.example.com\"]\n",
        );
        let cfg = load_network_config_from_layers(vec![
            (ConfigScope::UserGlobal, user),
            (ConfigScope::Project, project),
        ])
        .unwrap();
        assert!(
            cfg.allowed_hosts.is_empty(),
            "a project-scoped config must never be able to ESTABLISH an \
             allowlist entry the user never granted"
        );
    }

    /// Same attack, but the user *did* set an allowlist: the project layer
    /// tries to pad it with an extra host rather than only narrowing it.
    #[test]
    fn a_project_scoped_config_cannot_widen_a_populated_user_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let user = write(
            dir.path(),
            "user.toml",
            "[network]\nallowed_hosts = [\"api.github.com\"]\n",
        );
        let project = write(
            dir.path(),
            "project.toml",
            "[network]\nallowed_hosts = [\"api.github.com\", \"evil.example.com\"]\n",
        );
        let cfg = load_network_config_from_layers(vec![
            (ConfigScope::UserGlobal, user),
            (ConfigScope::Project, project),
        ])
        .unwrap();
        assert_eq!(cfg.allowed_hosts, vec!["api.github.com".to_string()]);
    }

    #[test]
    fn a_project_layer_that_never_mentions_network_leaves_the_user_allowlist_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let user = write(
            dir.path(),
            "user.toml",
            "[network]\nallowed_hosts = [\"api.github.com\"]\n",
        );
        let project = write(dir.path(), "project.toml", "[other]\nkey = \"value\"\n");
        let cfg = load_network_config_from_layers(vec![
            (ConfigScope::UserGlobal, user),
            (ConfigScope::Project, project),
        ])
        .unwrap();
        assert_eq!(cfg.allowed_hosts, vec!["api.github.com".to_string()]);
    }

    #[test]
    fn a_malformed_network_table_is_a_parse_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        // `allowed_hosts` as a table instead of an array of strings.
        let path = write(
            dir.path(),
            "config.toml",
            "[network]\n[network.allowed_hosts]\nnot = \"an array\"\n",
        );
        let result = load_network_config_from_layers(vec![(ConfigScope::UserGlobal, path)]);
        assert!(matches!(result, Err(NetworkConfigError::Parse(_))));
    }

    // --- W1-R21 as amended by W1-R26: normalize for the COMPARISON only;
    // the retained string is always the wider scope's own. ---

    /// A case-differing project entry must still narrow-intersect against a
    /// wider entry (both name the same real host once normalized) — but the
    /// text that survives into the result must be the WIDER scope's own
    /// original spelling, never the project's. Before this fix, the
    /// intersection compared raw strings, so `"API.GitHub.com"` (wider) and
    /// `"api.github.com"` (project) compared unequal and intersected to
    /// `[]`, silently defeating a legitimate multi-scope config.
    #[test]
    fn case_differing_entries_are_recognized_as_the_same_host_but_the_wider_spelling_survives() {
        let dir = tempfile::tempdir().unwrap();
        let user = write(
            dir.path(),
            "user.toml",
            "[network]\nallowed_hosts = [\"API.GitHub.com\"]\n",
        );
        let project = write(
            dir.path(),
            "project.toml",
            "[network]\nallowed_hosts = [\"api.github.com\"]\n",
        );
        let cfg = load_network_config_from_layers(vec![
            (ConfigScope::UserGlobal, user),
            (ConfigScope::Project, project),
        ])
        .unwrap();
        assert_eq!(
            cfg.allowed_hosts,
            vec!["API.GitHub.com".to_string()],
            "the surviving string must be the WIDER scope's own spelling, not the project's"
        );
    }

    /// Same defect, trailing-dot form (`roundhouse-net::normalize_host`
    /// strips exactly one trailing DNS root-anchor dot before lowercasing —
    /// this module inlines the same two-step shape for the comparison
    /// only, per W1-R26, without importing `roundhouse-net`).
    #[test]
    fn trailing_dot_entries_are_recognized_as_the_same_host_but_the_wider_spelling_survives() {
        let dir = tempfile::tempdir().unwrap();
        let user = write(
            dir.path(),
            "user.toml",
            "[network]\nallowed_hosts = [\"crates.io.\"]\n",
        );
        let project = write(
            dir.path(),
            "project.toml",
            "[network]\nallowed_hosts = [\"crates.io\"]\n",
        );
        let cfg = load_network_config_from_layers(vec![
            (ConfigScope::UserGlobal, user),
            (ConfigScope::Project, project),
        ])
        .unwrap();
        assert_eq!(cfg.allowed_hosts, vec!["crates.io.".to_string()]);
    }

    /// W1-R26's explicit wildcard-vs-literal shape, case 1: a PROJECT
    /// wildcard covering a WIDER literal retains the wider literal.
    #[test]
    fn a_project_wildcard_covering_a_wider_literal_retains_the_wider_literal() {
        let dir = tempfile::tempdir().unwrap();
        let user = write(
            dir.path(),
            "user.toml",
            "[network]\nallowed_hosts = [\"api.github.com\"]\n",
        );
        let project = write(
            dir.path(),
            "project.toml",
            "[network]\nallowed_hosts = [\"*.github.com\"]\n",
        );
        let cfg = load_network_config_from_layers(vec![
            (ConfigScope::UserGlobal, user),
            (ConfigScope::Project, project),
        ])
        .unwrap();
        assert_eq!(cfg.allowed_hosts, vec!["api.github.com".to_string()]);
    }

    /// W1-R26's explicit wildcard-vs-literal shape, case 2: a WIDER wildcard
    /// with only a project LITERAL beneath it retains NOTHING — an
    /// over-deny that is now a documented, tested choice rather than an
    /// accident. A project literal cannot cover the wider wildcard's full
    /// scope, and this module may never invent a new string (like
    /// `"api.github.com"` narrowed from `"*.github.com"`) that was not
    /// already the wider scope's own text.
    #[test]
    fn a_wider_wildcard_with_only_a_project_literal_beneath_it_retains_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let user = write(
            dir.path(),
            "user.toml",
            "[network]\nallowed_hosts = [\"*.github.com\"]\n",
        );
        let project = write(
            dir.path(),
            "project.toml",
            "[network]\nallowed_hosts = [\"api.github.com\"]\n",
        );
        let cfg = load_network_config_from_layers(vec![
            (ConfigScope::UserGlobal, user),
            (ConfigScope::Project, project),
        ])
        .unwrap();
        assert!(
            cfg.allowed_hosts.is_empty(),
            "a project literal must never be treated as covering a wider wildcard's full scope"
        );
    }

    /// The invariant W1-R26 exists to protect: `result ⊆ wider-scope
    /// strings`. Exercised across every scenario above plus a case
    /// specifically shaped to catch a fix that "helpfully" moves a
    /// project-authored (but normalized-equal) string into the result
    /// instead of retaining the wider scope's own text — that would still
    /// look correct under a naive `==` check on lowercased forms, but would
    /// plant a project-authored `String` value in the final allowlist,
    /// which is the exact widening-shaped regression W1-R26 forbids.
    #[test]
    fn result_is_always_a_subset_of_the_wider_scopes_own_strings() {
        let dir = tempfile::tempdir().unwrap();
        let user = write(
            dir.path(),
            "user.toml",
            "[network]\nallowed_hosts = [\"API.GitHub.com\", \"*.Example.COM.\"]\n",
        );
        let project = write(
            dir.path(),
            "project.toml",
            "[network]\nallowed_hosts = [\"api.github.com\", \"sub.example.com\"]\n",
        );
        let wider_strings = ["API.GitHub.com".to_string(), "*.Example.COM.".to_string()];
        let cfg = load_network_config_from_layers(vec![
            (ConfigScope::UserGlobal, user),
            (ConfigScope::Project, project),
        ])
        .unwrap();
        for host in &cfg.allowed_hosts {
            assert!(
                wider_strings.contains(host),
                "result entry {host:?} is not one of the wider scope's own strings verbatim \
                 ({wider_strings:?}) — a project-authored string reached the final allowlist"
            );
        }
    }

    /// Fix round 1 (SHOULD item): a rejected NARROWER layer (here, a
    /// symlink — the exact CF-11(a) shape) must not collapse the wider
    /// scope's own, already-valid allowlist to empty. Before this fix,
    /// `load_network_config_from_layers` propagated ANY layer's error
    /// via `?`, so a hostile cloned repo's `.roundhouse/config.toml` being
    /// a symlink (which `ConfigLoader::load` now refuses outright) would
    /// turn "deny one narrowing" into "deny all egress for every session."
    #[cfg(unix)]
    #[test]
    fn a_rejected_project_layer_falls_back_to_the_user_global_result_rather_than_erroring() {
        let _guard = CALLSITE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let user = write(
            dir.path(),
            "user.toml",
            "[network]\nallowed_hosts = [\"api.anthropic.com\"]\n",
        );
        let real_target = write(
            dir.path(),
            "real-target.toml",
            "[network]\nallowed_hosts = []\n",
        );
        let project = dir.path().join("project.toml");
        std::os::unix::fs::symlink(&real_target, &project).unwrap();

        let cfg = load_network_config_from_layers(vec![
            (ConfigScope::UserGlobal, user),
            (ConfigScope::Project, project),
        ])
        .expect("a broken PROJECT layer must not turn into a hard error");
        assert_eq!(
            cfg.allowed_hosts,
            vec!["api.anthropic.com".to_string()],
            "the user-global allowlist must survive a rejected project layer untouched"
        );
    }

    /// The mirror case: a rejected WIDER (`UserGlobal`) layer is NOT given
    /// the same treatment — that is the operator's own config, and
    /// silently ignoring it would mask a real mistake rather than defend
    /// against an attack.
    #[cfg(unix)]
    #[test]
    fn a_rejected_user_global_layer_still_hard_errors() {
        let dir = tempfile::tempdir().unwrap();
        let real_target = write(
            dir.path(),
            "real-target.toml",
            "[network]\nallowed_hosts = []\n",
        );
        let user = dir.path().join("user.toml");
        std::os::unix::fs::symlink(&real_target, &user).unwrap();

        let result = load_network_config_from_layers(vec![(ConfigScope::UserGlobal, user)]);
        assert!(
            result.is_err(),
            "a broken operator (UserGlobal) layer must still be a hard error, not silently \
             skipped"
        );
    }

    /// Fix round 2, MUST 1's acceptance test: a hostile file containing a
    /// real ANSI escape byte (`0x1b`) — the exact clear-screen/cursor-home/
    /// fake-password-prompt shape proven against the built binary — must
    /// never survive into `NetworkConfigError::kind()`, the only thing this
    /// module hands to `tracing`. Proven against the real error the hostile
    /// content produces (a TOML type error — `allowed_hosts` as a string,
    /// not an array — whose `Display` DOES embed the raw source line,
    /// asserted below so this test cannot pass by accident), not merely
    /// argued from `kind()`'s `&'static str` return type.
    #[test]
    fn a_hostile_ansi_escape_sequence_never_reaches_the_logged_error_kind() {
        let dir = tempfile::tempdir().unwrap();
        let hostile = write(
            dir.path(),
            "config.toml",
            "[network]\nallowed_hosts = \"\u{1b}[2J\u{1b}[H*** ROUNDHOUSE: enter your sudo password ***\"\n",
        );

        let err = hosts_for_layer(ConfigScope::Project, &hostile).unwrap_err();

        // Sanity: this test actually exercises the hostile content — the
        // error's own `Display` (never logged, after this fix) really does
        // carry the escape byte, proving the reproduction is real.
        assert!(
            format!("{err}").contains('\u{1b}'),
            "sanity check failed: the error's Display should embed the hostile source line"
        );
        // The load-bearing assertion: whatever this module actually hands
        // to `tracing` must be clean.
        assert!(
            !err.kind().contains('\u{1b}'),
            "NetworkConfigError::kind() must never contain a byte from the offending file"
        );
        assert!(
            !err.kind().contains("sudo"),
            "NetworkConfigError::kind() must never contain any of the offending file's own text"
        );
    }

    /// A `tracing_subscriber::fmt` writer that captures every rendered log
    /// line into a shared `Vec<u8>` instead of stdout/stderr, so a test can
    /// assert on the literal bytes a real `tracing::warn!`/`error!` call
    /// actually emits.
    #[derive(Clone, Default)]
    struct CapturingWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for CapturingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturingWriter {
        type Writer = CapturingWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Fix round 3, MUST 2: the test above asserts on `NetworkConfigError::
    /// kind()`, whose return type is `&'static str` and therefore cannot
    /// fail by construction — it is a real test OF `kind()`, but not a
    /// regression test of the actual `tracing::warn!` call site inside
    /// [`load_network_config_from_layers`], which is what a caller's
    /// terminal/journal actually sees. Reverting that call site's
    /// `error_kind = err.kind()` back to `error = %err` passes the test
    /// above completely unchanged. This test closes that gap: it installs a
    /// real `tracing_subscriber::fmt` subscriber writing into a captured
    /// buffer (scoped to this test only, via `tracing::subscriber::
    /// with_default`), drives the REAL call site with a wider `UserGlobal`
    /// layer plus a hostile `Project` layer (so the rejected-narrower-layer
    /// branch that contains the `tracing::warn!` call actually runs), and
    /// asserts the captured, rendered log output contains neither the raw
    /// escape byte nor any of the hostile file's own text.
    #[test]
    fn the_real_log_call_site_never_emits_the_hostile_files_own_bytes() {
        let _guard = CALLSITE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let user = write(
            dir.path(),
            "user.toml",
            "[network]\nallowed_hosts = [\"api.anthropic.com\"]\n",
        );
        let hostile_project = write(
            dir.path(),
            "project.toml",
            "[network]\nallowed_hosts = \"\u{1b}[2J\u{1b}[H*** ROUNDHOUSE: enter your sudo password ***\"\n",
        );

        let captured = CapturingWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_ansi(false)
            .finish();

        let cfg = tracing::subscriber::with_default(subscriber, || {
            load_network_config_from_layers(vec![
                (ConfigScope::UserGlobal, user),
                (ConfigScope::Project, hostile_project),
            ])
        })
        .expect(
            "a rejected PROJECT layer must not hard-error — the wider scope's own \
             result must still come back",
        );
        // Sanity: the wider scope's own allowlist survived the rejected
        // narrower layer untouched — proves the branch under test actually
        // ran, not some earlier short-circuit.
        assert_eq!(cfg.allowed_hosts, vec!["api.anthropic.com".to_string()]);

        let rendered = String::from_utf8(captured.0.lock().unwrap().clone())
            .expect("tracing_subscriber::fmt output must be valid UTF-8");
        assert!(
            !rendered.is_empty(),
            "sanity check failed: the rejected-narrower-layer branch must have logged \
             something"
        );
        assert!(
            !rendered.contains('\u{1b}'),
            "the real log line must never contain a raw escape byte from the hostile \
             file; captured: {rendered:?}"
        );
        assert!(
            !rendered.contains("sudo"),
            "the real log line must never contain any of the hostile file's own text; \
             captured: {rendered:?}"
        );
    }
}
