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
//!   [`disallowed_env_key`] plus their call sites in
//!   `TryFrom<RawDistribution>`. (This last link said `forbidden_env_key`
//!   until fix round 4 — the denylist-era name of a function fix round 2
//!   replaced; it referred to nothing that exists.)
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
//!
//! ## Fix round 2 (coordinator review of fix round 1)
//!
//! - **Item 1 — the sha256 preference had a fallback that undid it.**
//!   Round 1's `UnverifiableBinary` check for a `Binary` present on this
//!   platform but missing `sha256` sat *after* the `npx`/`uvx` early
//!   returns in [`resolve_distribution`] — so for any agent publishing both
//!   a no-`sha256` binary and a package-manager fallback, resolution never
//!   reached that check and silently fell through to the unverified
//!   channel, exactly the hazard round 1's own doc said it did not. The
//!   check now runs first — see [`resolve_distribution`]'s doc.
//! - **Item 2 — the HTTP hardening was entirely unmeasured.** No test
//!   referenced `MAX_RESPONSE_BYTES`, `build_registry_http_client`,
//!   `fetch_registry`, `fetch_quarantine`, `fetch_json_capped`, or
//!   `ResponseTooLarge`; five mutations against them survived the full
//!   suite (`https_only(false)`; redirect limit `2` → `100`; `.timeout()`
//!   removed; `MAX_RESPONSE_BYTES` → `usize::MAX` and → `0`;
//!   `error_for_status()` removed). [`RegistryHttpPolicy`] pins the four
//!   constant-valued settings against literals in a direct test;
//!   [`accumulate_capped`] pulls the byte-cap arithmetic out into a pure,
//!   socket-free-testable function that [`fetch_json_capped`] actually
//!   calls for its real enforcement (not a parallel, disconnected copy).
//! - **Item 3 — the `env` denylist became an allowlist.** A coordinator
//!   probe of 42 keys found round 1's ten-entry `FORBIDDEN_ENV_KEYS`
//!   denylist both arbitrary and unboundedly incomplete — see
//!   [`ALLOWED_ENV_KEYS`]'s doc for the full list of what got through, and
//!   why a denylist for this hazard class can never be complete by
//!   construction. `env` keys are now validated against a small, closed,
//!   measured allowlist instead.
//! - **Item 4 — validation grammar gaps in `cmd` and `package`.**
//!   [`is_safe_relative_cmd`] used to validate a `binary` target's `cmd`
//!   with `Path::new(cmd).is_absolute()` — POSIX host semantics applied to
//!   cross-platform data, so a `windows-*` target's `cmd` could carry
//!   `\Windows\System32\cmd.exe`, `C:evil.exe`, `\\server\share\evil.exe`,
//!   or `\\?\C:\...` straight past validation on this (Linux) build, each
//!   escaping the extraction directory on the platform the entry's own key
//!   names; it also let control characters, newlines, and shell
//!   metacharacters through that [`is_plausible_package_name`] rejected one
//!   field over. `is_plausible_package_name` itself did not constrain
//!   `package` to a package identifier at all — a URL- or path-shaped spec
//!   (`../../../tmp/evil`, `/tmp/evil`, `file:/tmp/evil`,
//!   `git+ssh://attacker/x`, `https://attacker.example/x.tgz`) passed, and
//!   `npx` accepts every one of those as an installable spec, fetching and
//!   executing code from entirely outside the npm registry. Both functions
//!   now reject these shapes explicitly — see their docs — while
//!   `args` values stay deliberately out of scope (they land after the
//!   package, reaching the agent rather than `npx`/`uvx`, a materially
//!   weaker position, and a free-form argument grammar was not asked for).
//! - **Item 5 — a false doc claim, a one-sided test, and an unvalidated
//!   digest.** [`write_json`]'s doc claimed a concurrent writer could not
//!   leave a truncated cache file readable as one; both writers actually
//!   shared the same fixed `<path>.tmp`, so two concurrent `store()` calls
//!   could interleave inside it before either rename. Fixed with
//!   [`unique_tmp_path`] (pid + a per-process counter) plus an
//!   `fsync`-before-rename. The
//!   `registry_error_json_escapes_a_control_character_bearing_field_name`
//!   test (this module's tests) asserted only the *absence* of a raw
//!   newline/ANSI escape, so replacing the whole `detail` with `""` would
//!   have survived it — it now also asserts the escaped forms are
//!   *present*, matching its sibling id test. `sha256: Some("")` used to
//!   pass `Option::is_some()` in `resolve_distribution`, looking
//!   checksum-pinned with a value no verifier could use;
//!   [`is_valid_sha256_hex`] closes that in `validate_binary_target`. The
//!   inert `#[allow(clippy::too_many_arguments)]` on `LaunchConfig::binary`
//!   (6 parameters, one below clippy's 7-argument default threshold) is
//!   removed — clippy stays clean without it.
//! - **Item 6 (`version.rs`, not this file) — `VersionHintCache` no longer
//!   keys on escaped-and-capped text.** See `version.rs`'s own "fix round
//!   2" doc.
//!
//! ## Fix round 3 (coordinator review of fix round 2)
//!
//! - **Item 1 — [`is_plausible_package_name`] now rejects npm/npx's
//!   schemeless GitHub shorthand.** Round 2 closed scheme-qualified
//!   (`git+ssh://...`) and path-shaped (leading `.`/`/`/`~`, or `..`) specs,
//!   but not a bare `user/repo` (optionally `#commit-ish`) — npm/npx resolve
//!   that as a GitHub tarball, the same "fetch and run attacker-controlled
//!   code, outside the npm registry" capability as the shapes round 2
//!   already closed, one syntax removed. A `/` is now legal only as the
//!   single separator of a leading `@scope/name`; `#` is rejected outright.
//! - **Item 2 — [`accumulate_capped`]'s O(n²) regression, fixed.** Round 2's
//!   own fix, taken literally ("extract the accumulation into a pure helper
//!   over a chunk-length iterator"), had [`fetch_capped_bytes`]'s
//!   predecessor call `accumulate_capped` once *per chunk*, each call
//!   re-folding the *entire* prefix of chunk lengths seen so far — O(n²)
//!   where round 1's original inline counter was O(n), measured at ×4 wall
//!   time per doubling of chunk count, extrapolating to ≈125s of CPU for a 1
//!   MiB body delivered as 1-byte chunks (which the size cap alone permits)
//!   — a chunked response framed this way would burn a tokio worker at
//!   ~100% for the full [`FETCH_TIMEOUT`] on every refresh. `accumulate_capped`
//!   now takes a `running: usize` seed and folds only the chunk(s) newly
//!   passed to each call; [`fetch_capped_bytes`] carries the total forward
//!   itself instead of keeping a `Vec` of every chunk length seen (which
//!   itself grew to several megabytes for a 1 MiB body) — restoring O(n)
//!   while keeping the same pure, directly-testable shape.
//! - **Item 3 — one invalid registry entry can no longer take down the whole
//!   registry.** [`Registry`]'s `Deserialize` was derived, and `serde`'s
//!   `Vec<T>` deserialization aborts the entire sequence on its first
//!   failing element — measured: a single agent using one `env` key not yet
//!   on [`ALLOWED_ENV_KEYS`] took every other agent in the same document
//!   down with it (a synthetic 3-agent registry with one bad entry: zero of
//!   three survived, not two), and because
//!   [`RegistryCache::finish_registry_refresh`] falls back to the stale
//!   cache on any parse error, this degraded silently — an ever-staler
//!   cache, no operator-visible signal. [`Registry`] now has a hand-written
//!   `Deserialize` impl that deserializes `agents` element-wise via
//!   [`partition_registry_agents`], keeping every entry that validates and
//!   dropping the rest individually, each with a warning naming the dropped
//!   entry's `id` (or `"<no id>"` if even that could not be read) — never
//!   silently. (Round 3 emitted those warnings with `eprintln!`; fix round 4,
//!   Item 2 below, returns them instead.) This is the *type's* own
//!   `Deserialize`, so it
//!   applies uniformly to a fresh fetch (via [`parse_registry_tolerant`],
//!   used by [`fetch_registry`] so its warnings can be surfaced) and to an
//!   ordinary cache-file read. Per-field validation itself is unchanged and
//!   stays exactly as strict as before — this only narrows the blast radius
//!   of one entry's failure from "the whole registry" to "this one entry."
//! - **Item 4 — status handling pinned for real; the HTTP policy's pin
//!   scoped honestly.** (a) `.error_for_status()?` — folded into a single
//!   `?`, indistinguishable in a diff from any other fallible call —
//!   removed cleanly and survived the full suite before this round.
//!   Reimplemented as the pure, dedicated [`ensure_success_status`], called
//!   against the real, awaited response status in [`fetch_capped_bytes`], so
//!   removing that call site now kills its own tests. (b)
//!   [`fetch_capped_bytes`] now reads its size cap from
//!   [`RegistryHttpPolicy::hardened`] rather than the free-standing
//!   [`MAX_RESPONSE_BYTES`] constant directly, making `max_response_bytes`
//!   the one setting this module's pin genuinely covers end to end (flowing
//!   into the thoroughly-tested [`accumulate_capped`], not an opaque
//!   `reqwest::Client`) — [`RegistryHttpPolicy`]'s doc is reworded to say
//!   exactly that, and to disclose plainly that the other four settings
//!   (`https_only`, `redirect_limit`, `connect_timeout`, `timeout`) are
//!   pinned only at the struct-literal level: `reqwest::Client` exposes no
//!   getters, so no test here can observe whether a built client actually
//!   applies them without a live socket, which this task's standing
//!   conventions forbid in tests.
//! - **Item 5 — two claimed properties, now actually tested.**
//!   [`is_valid_sha256_hex`] mutated to `value.len() == 64` (dropping the
//!   hex-digit check) survived the full suite — every existing test
//!   exercised length only. [`disallowed_env_key`] mutated to
//!   `key.trim().eq_ignore_ascii_case(allowed)` also survived — every
//!   existing negative test used a name nowhere near the six allowed ones,
//!   so trimming/case-folding never changed an outcome. Both now have a
//!   dedicated test using, respectively, a 64-character non-hex string and a
//!   case/whitespace-varied form of a real *allowed* key.
//! - **Item 6 — [`fetch_registry`]/[`fetch_quarantine`] narrowed from `pub`
//!   to `pub(crate)`.** [`RegistryCache`] is the sole intended entry point
//!   and already always uses [`build_registry_http_client`]'s hardened
//!   client; a `pub` caller could otherwise pass an unhardened
//!   `reqwest::Client::new()` and silently lose `https_only`, the redirect
//!   limit, and both timeouts.
//!
//! ## Fix round 4 (coordinator review of fix round 3)
//!
//! - **Item 1 — round 3's per-entry tolerance opened an id-shadowing hole,
//!   now closed.** [`Registry`] has no duplicate-id rejection and
//!   [`RegistryCache::resolve_launch`] is first-match-wins. Before round 3, a
//!   document containing an invalid entry failed `Vec<RegistryAgent>`
//!   deserialization wholesale, so resolution failed closed; after it, the
//!   invalid entry was dropped and a later entry re-using the same `id`
//!   silently became the match — inheriting the victim id's clean,
//!   non-quarantined status, because the quarantine gate is keyed on `id`,
//!   not on the resolved package. Reproduced end to end against round 3's
//!   committed code, with a non-empty quarantine cached and `claude-code` not
//!   quarantined: `resolve_launch("claude-code")` returned
//!   `Ok(LaunchConfig(Npx { package: "attacker-controlled-pkg@9.9.9", .. }))`
//!   after the legitimate `@agentclientprotocol/claude-agent-acp@0.73.0`
//!   entry was dropped for carrying an unrecognized `env` flag — the exact
//!   scenario per-entry tolerance was introduced to handle.
//!   [`partition_registry_agents`] now dedupes through a
//!   `BTreeMap<String, RegistryAgent>` and, on a collision, keeps **neither**
//!   entry — failing closed rather than letting drop order decide.
//! - **Item 2 — no `eprintln!`/`println!` anywhere in this crate's `src/`.**
//!   Round 3 printed one line per dropped entry from inside [`Registry`]'s
//!   `Deserialize` impl and [`fetch_registry`]. Measured by the coordinator
//!   against a body sized to sit *inside* [`MAX_RESPONSE_BYTES`] (1,048,570
//!   bytes): 349,521 warnings, 41,243,478 bytes written to stderr, the whole
//!   ~41 MB `Vec<String>` materialized on the heap before a single line was
//!   printed (89.5 ms to parse, 213.7 ms to emit) — ~39x amplification of a
//!   response the size cap deliberately permits, re-emitted on *every*
//!   `resolve_launch`, because that path re-parses the cache file on each
//!   call. `eprintln!` also panics if the write fails (verified: stderr on a
//!   closed pipe exits 101), which in the `Deserialize` position is a panic
//!   inside a pure operation with no `Result` path for it; and a library
//!   embedded in-process by `roundhouse-daemon` must not write to a stream
//!   the daemon owns and shares with the `round` TUI. [`Registry`]'s
//!   `Deserialize` is now silent; [`fetch_registry`] and
//!   [`RegistryCache::refresh_registry`] **return** the warnings as
//!   [`RegistryRefresh`]'s `warnings` field, bounded by
//!   [`MAX_REPORTED_DROP_WARNINGS`] plus one remainder line.
//! - **Item 3 — the package grammar was one npm syntax short.**
//!   `npm-package-arg`, npm's own classifier, types any spec matching
//!   `/[.](?:tgz|tar.gz|tar)$/i` as a `file` spec — needing no `/`, `:`, `#`,
//!   or leading `.`/`/`/`~`, so nothing in round 3's grammar saw `evil.tgz`,
//!   `pkg@evil.tgz`, or `@scope/name@evil.tgz` (that last one carried in by
//!   round 3's own `@scope/name` allowance). [`is_archive_file_spec`] rejects
//!   that suffix. The brief asked for the check to run per `@`-separated
//!   part; it runs once over the whole string instead, which catches exactly
//!   the same set — `npa` anchors its own file test at the end of the
//!   trailing part, always a suffix of the whole — and a per-part loop was
//!   written, measured as dead (mutating it away left the suite green), and
//!   removed. See [`is_archive_file_spec`]'s doc.
//!   [`is_plausible_package_name`]'s `@scope/name` rule now also requires
//!   both sides non-empty, so `"@scope/"` and `"@/"` no longer pass as
//!   "plausible" — the doc claimed npm's scoped grammar and the code only
//!   counted the `/`.
//! - **Item 4 — two false claims on security assertions, corrected.**
//!   (a) [`ensure_success_status`]'s doc and `RegistryError::BadStatus`'s
//!   claimed that removing the call site "now kills this function's own
//!   dedicated tests"; it did not — the suite passed, and only
//!   `clippy -D warnings`' dead-code lint caught it, a catch that evaporates
//!   as soon as a second caller exists. [`begin_capped_read`] is now the
//!   directly-tested seam performing the check, and its call site in
//!   [`fetch_capped_bytes`] is load-bearing (it returns the running byte
//!   total the read loop counts from, so deleting it does not compile); what
//!   remains inspection-only is disclosed rather than claimed. The status
//!   logic itself is unchanged and correct. (b)
//!   [`partition_registry_agents`]'s doc said
//!   "`RegistryAgent`/`Distribution`'s `deny_unknown_fields` structs are
//!   unchanged by this round". [`RegistryAgent`] has no `deny_unknown_fields`
//!   at all — deliberately, so that the live fields this crate does not model
//!   do not fail every real entry — so unknown *entry-level* keys are in fact
//!   tolerated, and the strictness comes from elsewhere. Reworded to name
//!   what actually enforces it.

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

/// Item 3 (fix round 2): the closed set of environment variable names a
/// registry entry's `env` map is allowed to set — an **allowlist**,
/// replacing fix round 1's `FORBIDDEN_ENV_KEYS` denylist entirely.
///
/// A coordinator probe of 42 keys against round 1's ten-entry denylist found
/// it both arbitrary and unboundedly incomplete: `GCONV_PATH`, `BASH_ENV`,
/// `ENV`, `SHELLOPTS`, `NODE_PATH`, `ELECTRON_RUN_AS_NODE`, `PERL5OPT`,
/// `RUBYOPT`, `RUBYLIB`, `PYTHONSTARTUP`, `PYTHONHOME`,
/// `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `CLASSPATH`, `GIT_SSH_COMMAND`,
/// `GIT_EXTERNAL_DIFF`, `HTTPS_PROXY`/`https_proxy`, `SSL_CERT_FILE`, and
/// `HOME` were all accepted, despite every one of them controlling what
/// code loads into, or where, a spawned process looks for its own
/// libraries or interpreter, or where its egress or credential lookups are
/// redirected — the same hazard class the standing `AcpAgent::spawn`
/// prohibition on this crate exists to prevent, arriving here from the
/// registry side instead of the spawn side. Exact-match evasion also
/// worked (`"LD_PRELOAD "` with a trailing space). A denylist for this
/// class is unbounded by construction: every shell, loader, and language
/// runtime this crate has never heard of adds another name that would have
/// to be chased down and added.
///
/// Real registry `env` maps, by contrast, are tiny and agent-specific: the
/// live index (`https://cdn.agentclientprotocol.com/registry/v1/latest/registry.json`,
/// re-verified 2026-09-02) uses exactly these six keys across all 39
/// agents' `npx`, `uvx`, and `binary` distributions, and none of them is a
/// loader, interpreter, shell, proxy, or credential control — each is an
/// agent-authored feature flag:
const ALLOWED_ENV_KEYS: &[&str] = &[
    "AUGMENT_DISABLE_AUTO_UPDATE",
    "DROID_DISABLE_AUTO_UPDATE",
    "FACTORY_DROID_AUTO_UPDATE_ENABLED",
    "FAST_AGENT_MODEL",
    "VT_ACP_ENABLED",
    "VT_ACP_ZED_ENABLED",
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
            "{kind} package name is not accepted (must not be empty; must not start with `-`, \
             `.`, `/`, or `~`; must not contain `..`, `:`, or `#`; must not contain a control or \
             whitespace character; must not end with `.tgz`, `.tar.gz`, or `.tar`; a `/` is only \
             accepted as the single separator of a leading `@scope/name` with both sides \
             non-empty): {}",
            escape_and_cap_peer_str(&dist.package)
        ));
    }
    if let Some(key) = disallowed_env_key(&dist.env) {
        return Err(format!(
            "{kind} env sets a variable not on the allowlist: {}",
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
            "binary target {}'s cmd is not a safe relative path (must not start with `/`, `\\`, \
             or `~`, must not have a drive-letter prefix, must not contain a `..` segment, and \
             must not contain a control or whitespace character): {}",
            escape_and_cap_peer_str(target),
            escape_and_cap_peer_str(&binary.cmd)
        ));
    }
    if let Some(key) = disallowed_env_key(&binary.env) {
        return Err(format!(
            "binary target {}'s env sets a variable not on the allowlist: {}",
            escape_and_cap_peer_str(target),
            escape_and_cap_peer_str(key)
        ));
    }
    if let Some(sha256) = &binary.sha256 {
        if !is_valid_sha256_hex(sha256) {
            return Err(format!(
                "binary target {}'s sha256 is not a 64-character hex digest: {}",
                escape_and_cap_peer_str(target),
                escape_and_cap_peer_str(sha256)
            ));
        }
    }
    Ok(())
}

/// Item 4 (fix round 1), tightened in fix round 2, tightened again in fix
/// round 3 (Item 1). Plausibility check for an `npx`/`uvx` `package` field:
/// `npx`/`uvx` invoke the string as `npx <package> [args]` / `uvx <package>
/// [args]`, and — per Item 4's live-data probe — **also accept it as an
/// installable spec pointing anywhere**, not only a registry name: a URL
/// (`https://attacker.example/x.tgz`, `git+ssh://attacker/x`,
/// `file:/tmp/evil`) or a filesystem path (`/tmp/evil`, `../../../tmp/evil`)
/// is fetched and executed exactly like a real npm/PyPI package name would
/// be, entirely outside the npm/PyPI registry. This is deliberately **not**
/// a full npm/PyPI name validator — it does not confirm the string is a
/// real, publishable identifier — only the part that is load-bearing for
/// safety:
/// - a leading `-` is consumed by `npx`/`uvx` as a flag rather than a
///   package name (the brief's own concrete example:
///   `--node-options=--require=/tmp/x.js`);
/// - a leading `.`, `/`, or `~`, or a `..` segment anywhere, makes the spec
///   filesystem-path-shaped rather than registry-name-shaped;
/// - a `:` makes the spec scheme-qualified (`file:`, `git+ssh:`, `https:`,
///   ...) — no real npm or PyPI package name published to either public
///   registry contains one, verified against all 23 live `npx`/`uvx`
///   package values (2026-09-02: none contain `:`, `..`, or start with `.`,
///   `/`, or `~`);
/// - a `#` fragment — `npx`/`npm install` accepts `#commit-ish` on a
///   GitHub-shorthand spec to pin an arbitrary commit; no real registry
///   package name contains one;
/// - embedded control characters or whitespace have no legitimate place in
///   a real package identifier either.
///
/// **Fix round 3 (Item 1):** round 2 closed scheme-qualified specs (a `:`)
/// and path-shaped specs (a leading `.`/`/`/`~`, or a `..` segment), but not
/// `npx`/`npm install`'s *schemeless* GitHub shorthand: a bare `user/repo`
/// (optionally `#commit-ish`) resolves as a GitHub tarball, entirely outside
/// the npm registry, with the same "fetch and run attacker-controlled code"
/// capability as the `git+ssh://` shape round 2 already rejected — one
/// syntax removed. A `/` is now legal **only** as the single separator of a
/// leading `@scope/name` (npm's real scoped-package grammar); every other
/// `/` is rejected outright. Verified this rejects no real data: every live
/// `package` value in `ACP-REGISTRY-FORMAT.md` containing a `/` starts with
/// `@` and has exactly one `/` (`@openai/codex-acp`,
/// `@agentclientprotocol/claude-agent-acp@0.73.0`, `@google/gemini-cli@0.58.0`).
///
/// **Fix round 4 (Item 3): npm's *file* spec syntax, the one shape still
/// missing.** `npm-package-arg` — npm's own spec classifier — types any spec
/// matching `/[.](?:tgz|tar.gz|tar)$/i` as a `file`, with no `/`, `:`, `#`,
/// or leading `.`/`/`/`~` required, so nothing above saw it: `evil.tgz`,
/// `evil.tar.gz`, `evil.tar`, `EVIL.TGZ`, `pkg@evil.tgz`, and
/// `@scope/name@evil.tgz` all passed, the last of them carried in by round
/// 3's own `@scope/name` allowance. [`is_archive_file_spec`] now rejects that
/// suffix — see its doc for why one whole-string check, not a per-part loop,
/// is exactly what `npa` does. Verified this rejects no real data: every live
/// `package` value
/// (`ACP-REGISTRY-FORMAT.md`) still validate — see
/// `is_plausible_package_name_accepts_real_live_scoped_and_versioned_specs`.
///
/// Also fixed in round 4: `"@scope/"` (empty name) and `"@/"` (empty scope)
/// used to pass, because the `@scope/name` rule only counted the `/`. Neither
/// is a security issue — neither is an installable spec at all — but the doc
/// above claims npm's scoped-package grammar, so the code now checks that
/// much of it.
///
/// A permissive check remains (this does not implement the full npm/PyPI
/// name grammar), so the error message in [`validate_package_distribution`]
/// deliberately does not claim this validated "a plausible npm/PyPI package
/// identifier" — only that the specific rejected shapes above are refused.
fn is_plausible_package_name(package: &str) -> bool {
    if package.is_empty()
        || package.starts_with('-')
        || package.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return false;
    }
    if package.starts_with('.') || package.starts_with('/') || package.starts_with('~') {
        return false;
    }
    if package.contains("..") || package.contains(':') || package.contains('#') {
        return false;
    }
    // Item 3 (fix round 4): npm's own `npm-package-arg` classifies any spec
    // ending in `.tgz`/`.tar.gz`/`.tar` (case-insensitively) as a `file`
    // spec, needing none of the markers rejected above. `npa` anchors that
    // test at the end of the trailing `@`-separated part, which is always a
    // suffix of the whole string, so one suffix check over the whole string
    // catches `evil.tgz`, `pkg@evil.tgz`, and `@scope/name@evil.tgz` alike --
    // see is_archive_file_spec's doc for why the per-part loop this replaced
    // was dead code.
    if is_archive_file_spec(package) {
        return false;
    }
    if package.contains('/') {
        // Item 1 (fix round 3): a `/` is legal only as the single separator
        // of a leading `@scope/name` — every other shape (npm/npx's bare
        // `user/repo` GitHub shorthand included) is rejected. Item 3 (fix
        // round 4): and neither side of that separator may be empty, so
        // `@scope/` and `@/` no longer pass as "plausible".
        let Some(after_at) = package.strip_prefix('@') else {
            return false;
        };
        let mut parts = after_at.splitn(3, '/');
        let scope = parts.next().unwrap_or("");
        let name = parts.next().unwrap_or("");
        if scope.is_empty() || name.is_empty() || parts.next().is_some() {
            return false;
        }
    }
    true
}

/// Item 3 (fix round 4): whether `spec` is an npm *file* spec — a string
/// ending in `.tgz`, `.tar.gz`, or `.tar`, case-insensitively, matching npm's
/// own `npm-package-arg` classifier (`/[.](?:tgz|tar.gz|tar)$/i`). Such a
/// spec resolves to a local tarball relative to the working directory rather
/// than to anything in the npm registry, and needs none of the markers
/// [`is_plausible_package_name`]'s other rules look for — no `/`, `:`, `#`,
/// or leading `.`/`/`/`~` — so nothing else in that grammar saw it.
///
/// The blast radius is narrower than the GitHub shorthand round 3 closed (a
/// `file` spec is cwd-relative, and `/` and `..` are already rejected, so
/// exploiting it needs an attacker-controlled file already sitting at
/// `<cwd>/<name>.tgz`), but it is the same "resolves outside the registry"
/// class, so it is refused rather than reasoned about.
///
/// **Checked against the whole spec, not each `@`-separated part.** The round
/// 4 brief asked for the latter so that `pkg@evil.tgz` and
/// `@scope/name@evil.tgz` would be caught. They are — but by the whole-string
/// check alone, because `npa` anchors its own file test at the end of the
/// *trailing* `@`-separated part, which is by construction a suffix of the
/// whole string. A per-part loop was written first and then removed: mutating
/// it away left the entire suite passing (every case it could fire on, the
/// whole-string check had already rejected), which is the definition of dead
/// code. Matching `npa` exactly also avoids over-rejecting: `evil.tgz@1.0.0`
/// is *not* a file spec to npm — it is the registry package named `evil.tgz`
/// at version `1.0.0`, resolved inside the registry like any other — and the
/// per-part version refused it for no safety gain.
fn is_archive_file_spec(spec: &str) -> bool {
    let lowered = spec.to_ascii_lowercase();
    [".tgz", ".tar.gz", ".tar"]
        .iter()
        .any(|suffix| lowered.ends_with(suffix))
}

/// Item 4 (fix round 1), corrected in fix round 2. Whether a binary target's
/// `cmd` is safe to treat as "the extracted archive's own relative
/// executable path."
///
/// **Fix round 2:** round 1's check used `Path::new(cmd).is_absolute()`,
/// which is `std::path::Path`'s *host* semantics — POSIX on every platform
/// this crate is actually built for, regardless of which platform the
/// entry's own `target` key (e.g. `"windows-x86_64"`) names. On a Linux
/// build/daemon host, `\Windows\System32\cmd.exe`, `C:evil.exe`,
/// `\\server\share\evil.exe`, and `\\?\C:\...` are all *not* absolute by
/// `Path::is_absolute`'s POSIX rules, so all four passed straight through —
/// each one escapes the extraction directory on Windows, the platform the
/// key names. Rather than branch on `target`'s platform family and
/// reimplement two different absolute-path grammars, this now rejects the
/// dangerous shapes explicitly and unconditionally, without delegating to
/// `Path` at all: a leading `/` or `\` (absolute, or the UNC/`\\?\` prefix,
/// on either family), a leading `~` (shell/home-relative expansion some
/// launchers perform), a `<letter>:` prefix (`C:evil.exe`, `C:\...` — a
/// Windows drive-letter path, whether or not a legitimate archive-relative
/// `cmd` on *any* family ever needs a `:` this early), and any `..` path
/// segment on either separator. This is strictly stronger than a
/// family-specific check (it refuses these shapes even for a `linux-*` or
/// `darwin-*` target, where they happen to be harmless-but-never-legitimate
/// relative filenames) and does not depend on which platform is compiling
/// or running this validation.
///
/// Also closes the asymmetry Item 4's own review found: a `cmd` containing
/// a newline or other control character, or whitespace (`./x\nevil`, `./a
/// b; rm -rf /`), passed round 1's check even though
/// [`is_plausible_package_name`] rejected the same class of character one
/// field over. Live values are all relative with no such characters
/// (`./kilo`, `./bin\devin.exe`), so this is a real grammar the live data
/// actually follows, not a hypothetical one.
fn is_safe_relative_cmd(cmd: &str) -> bool {
    if cmd.is_empty() {
        return false;
    }
    if cmd.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    if cmd.starts_with('/') || cmd.starts_with('\\') || cmd.starts_with('~') {
        return false;
    }
    let mut chars = cmd.chars();
    if let (Some(first), Some(':')) = (chars.next(), chars.next()) {
        if first.is_ascii_alphabetic() {
            return false;
        }
    }
    !cmd.split(['/', '\\']).any(|segment| segment == "..")
}

/// Item 5 (fix round 2): whether `value` is a well-formed SHA-256 digest —
/// exactly 64 ASCII hex characters, matching the upstream schema's own
/// `^[a-fA-F0-9]{64}$` pattern (`ACP-REGISTRY-FORMAT.md`). Without this,
/// `sha256: Some("")` passed `Option::is_some()` in
/// [`resolve_distribution`], so an entry could look checksum-pinned (taking
/// the preferred, Item 3, code path) while carrying a value no verifier
/// downstream could actually use.
fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Item 3 (fix round 2): the first (if any) of an `env` map's keys that is
/// **not** on [`ALLOWED_ENV_KEYS`] — see that constant's doc for why this is
/// an allowlist rather than the denylist ([`FORBIDDEN_ENV_KEYS`] no longer
/// exists) fix round 1 shipped. Exact byte comparison, deliberately not
/// case-insensitive: the allowlist is a small, closed set of real,
/// already-observed exact names, so there is no legitimate case variant to
/// accommodate, and exact matching also closes the round-1 evasion the
/// coordinator's probe found (a trailing space, e.g. `"LD_PRELOAD "`, no
/// longer has any name to accidentally case-fold onto).
fn disallowed_env_key(env: &BTreeMap<String, String>) -> Option<&str> {
    env.keys()
        .map(String::as_str)
        .find(|key| !ALLOWED_ENV_KEYS.contains(key))
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
///
/// **Fix round 3 (Item 3): `Deserialize` is now hand-written, not derived —
/// see the impl below — so that one invalid `agents` element is dropped
/// individually rather than failing the whole array.** Before this round,
/// `agents: Vec<RegistryAgent>` derived `Deserialize` in the ordinary way:
/// `serde`'s `Vec<T>` deserialization aborts the entire sequence on the
/// first element that fails, so one agent using a single `env` key not yet
/// on [`ALLOWED_ENV_KEYS`] took every other agent in the same fetch down
/// with it — measured against a synthetic 3-agent registry with one bad
/// entry: zero of the three survived, not two. Because
/// [`RegistryCache::finish_registry_refresh`] falls back to the stale cache
/// on any parse error, this was a silent, cumulative failure mode: every
/// refresh after the first upstream `env` addition not yet allowlisted would
/// keep serving an ever-staler cache with no operator-visible signal.
///
/// **Fix round 4 (Item 2): this `Deserialize` impl is silent.** Round 3 had
/// it `eprintln!` one line per dropped entry. A library must not write to a
/// stream it does not own (this crate is embedded in-process by
/// `roundhouse-daemon`, which shares stderr with the `round` TUI and owns the
/// logging), `eprintln!` *panics* if the write fails — a panic reachable from
/// inside a `Deserialize` impl, which has no `Result` path for it — and,
/// because [`RegistryCache::resolve_launch`] re-reads and re-parses the cache
/// file on every single call, the output repeated on every resolve.
/// Per-entry *tolerance* is unchanged; only the printing is gone. The one
/// call site that can usefully surface warnings — [`fetch_registry`], reached
/// through [`RegistryCache::refresh_registry`] — now **returns** them
/// (bounded, see [`MAX_REPORTED_DROP_WARNINGS`]) as part of
/// [`RegistryRefresh`], so the decision to log belongs to the daemon that
/// owns the logging.
///
/// **Fix round 4 (Item 1): `agents` is deduplicated by `id`, dropping *every*
/// entry that shares a colliding id.** See [`partition_registry_agents`].
/// Note that `agents` stays a `pub Vec`, so a `Registry` built directly by
/// struct literal (as this module's and `tests/registry.rs`'s own tests
/// legitimately do) can still contain duplicate ids — the deduplication is
/// enforced on the deserialize path, which is the only way registry-supplied
/// bytes become a `Registry`, not in the type system. Same disclosure shape,
/// and same reason, as [`Distribution`]'s.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct Registry {
    pub agents: Vec<RegistryAgent>,
}

/// The `agents` field's raw shape for [`Registry`]'s tolerant `Deserialize`
/// impl — each element stays an unparsed [`serde_json::Value`] until
/// [`partition_registry_agents`] tries it individually against
/// [`RegistryAgent`]'s own validation.
#[derive(Deserialize)]
struct RawRegistryTolerant {
    agents: Vec<serde_json::Value>,
}

impl<'de> Deserialize<'de> for Registry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawRegistryTolerant::deserialize(deserializer)?;
        // Item 2 (fix round 4): the warnings are deliberately discarded here
        // rather than printed -- see this type's doc. `fetch_registry` is the
        // path that returns them to a caller that can log them.
        let (agents, _warnings) = partition_registry_agents(raw.agents);
        Ok(Registry { agents })
    }
}

/// Item 2 (fix round 4): the maximum number of individually-named per-entry
/// drop warnings [`partition_registry_agents`] will build, before it stops
/// building them and counts the remainder into a single trailing
/// `"... and N more registry agent entries dropped"` line instead.
///
/// **Why a cap at all.** Round 3 built one warning `String` per dropped
/// entry, unbounded. Measured by the coordinator against a response sized to
/// sit *inside* [`MAX_RESPONSE_BYTES`] (1,048,570 bytes): 349,521 warnings,
/// ~41 MB of `Vec<String>` held on the heap at once — ~39x amplification of a
/// body the size cap deliberately permits.
///
/// **Why 8.** The realistic case this tolerance exists for (round 3, Item 3)
/// is upstream adding a field or `env` flag this crate has not allowlisted
/// yet, which drops a handful of entries out of the 39 the live index carries
/// (measured 2026-09-01/2026-09-02, `ACP-REGISTRY-FORMAT.md`); 8 names every
/// one of them individually in that case, and in the pathological case caps
/// the output at 9 strings regardless of input size. It is deliberately far
/// below the point where a human reads the output as a list rather than a
/// flood. `partition_registry_agents_caps_its_warnings_and_reports_the_remainder`
/// (this module's tests) measures the resulting bound directly.
const MAX_REPORTED_DROP_WARNINGS: usize = 8;

/// Item 3 (fix round 3): the pure, per-entry decision behind [`Registry`]'s
/// `Deserialize` impl above — factored out so it is directly testable
/// without going through a `Deserializer` at all (this module's tests).
///
/// Returns every element of `raw_agents` that validates against
/// [`RegistryAgent`]'s own `TryFrom<RawRegistryAgent>` rules (the id
/// pattern, and — transitively — every `Distribution`-level check: the env
/// allowlist, the `cmd`/`package` grammar, the sha256 shape), plus one
/// human-readable warning message per element that did not, identifying it
/// by its own `id` field when the payload is well-formed enough to read one
/// (falling back to the literal `"<no id>"` for a payload malformed enough
/// that even `id` cannot be read as a string) — an entry is never silently
/// dropped without a warning that says why and, where possible, which —
/// subject to this round's [`MAX_REPORTED_DROP_WARNINGS`] cap, past which
/// entries are counted into a single remainder line instead of named.
///
/// Per-field validation itself is unchanged and stays exactly as strict as it
/// was: an unrecognized key inside an entry's `distribution` object, or
/// inside one of the three per-shape structs that carry
/// `#[serde(deny_unknown_fields)]` (`RawDistribution`,
/// [`PackageDistribution`], [`BinaryTarget`]), still fails that one entry, as
/// do the `id` pattern and every launch-field check. Unrecognized keys at an
/// *entry's own* top level are ignored rather than fatal: [`RegistryAgent`]
/// deliberately has no `deny_unknown_fields`, so that the live fields this
/// crate does not model (`version`, `description`, `repository`, `authors`,
/// `license`, `license_url`, `icon`) do not fail every real entry — see its
/// doc. This function only narrows the *blast radius* of a per-entry failure
/// from "the whole registry" to "this one entry," never widens what counts as
/// valid. (**Fix round 4, Item 4(b):** round 3's version of this paragraph
/// attributed the strictness to `RegistryAgent`/`Distribution`'s
/// `deny_unknown_fields`. `RegistryAgent` has none — `:678` says so
/// explicitly — and unknown *entry-level* keys are in fact tolerated, so both
/// the reason and, for that one position, the claim were wrong.)
///
/// **Fix round 4 (Item 1): entries whose `id` collides are *all* dropped.**
/// [`Registry`] has no duplicate-id rejection and
/// [`RegistryCache::resolve_launch`] is first-match-wins, so round 3's
/// per-entry tolerance opened an id-shadowing hole: before it, one invalid
/// entry failed the whole document and resolution failed closed; after it,
/// the invalid entry was dropped individually and a *later* entry re-using
/// the same `id` silently became the match — inheriting the victim id's
/// clean, non-quarantined status, because the quarantine gate is keyed on
/// `id`, not on the resolved package. Reproduced end to end against round 3's
/// committed code: a document whose legitimate `claude-code` entry carried an
/// unrecognized `env` flag (exactly the scenario per-entry tolerance was
/// introduced to survive) and whose second, attacker-authored `claude-code`
/// entry was valid resolved to `Ok(LaunchConfig(Npx { package:
/// "attacker-controlled-pkg@9.9.9", .. }))`. Keeping the *first* entry
/// instead would only move the hole — drop order would still decide — so on a
/// collision **neither** entry survives and both count as dropped: fail
/// closed, matching this module's posture everywhere else.
///
/// The collision is keyed on the id each element **claims in its raw JSON**,
/// not on the id of an element that validated. That distinction is the whole
/// fix: in the reported attack the victim is precisely the element that
/// *fails* validation, so a duplicate check over survivors alone would never
/// see the collision at all (verified — a survivors-only version of this
/// function still resolved to the attacker's entry, and
/// `partition_registry_agents_drops_both_entries_that_share_an_id` fails
/// against it). An element whose `id` is absent or is not a JSON string
/// cannot claim an id and so cannot poison one; it simply fails validation on
/// its own.
///
/// **Fix round 4 (Item 2): the warning list is bounded** at
/// [`MAX_REPORTED_DROP_WARNINGS`] individually-named entries plus at most one
/// remainder line. Past the cap no per-entry `String` is built at all (not
/// built and then truncated), so neither the returned `Vec` nor the transient
/// allocations behind it can be inflated by a large hostile document.
///
/// The returned agents are ordered by `id` (a consequence of the `BTreeMap`
/// the deduplication uses), not in document order. Nothing depends on the
/// order: the only reader, [`RegistryCache::resolve_launch`], looks entries up
/// by exact `id`, which this function has just made unique.
fn partition_registry_agents(
    raw_agents: Vec<serde_json::Value>,
) -> (Vec<RegistryAgent>, Vec<String>) {
    // Keyed on the id each element *claims* in its raw JSON, not on the id of
    // an element that successfully validated: the reported attack's victim
    // entry is the one that fails validation, so a map of survivors alone
    // would never see the collision at all. `None` marks an id that has been
    // claimed but yields no usable entry -- invalid, or collided.
    let mut by_id: BTreeMap<String, Option<RegistryAgent>> = BTreeMap::new();
    let mut warnings: Vec<String> = Vec::new();
    // Entries dropped, and how many of those an emitted warning accounts for.
    // These differ because one collision warning covers two entries, and
    // because the cap stops warnings being emitted at all.
    let mut dropped = 0usize;
    let mut reported = 0usize;

    for value in raw_agents {
        // Item 2 (fix round 4): only build the (escaped, allocating) warning
        // while there is still room to report one -- past the cap nothing is
        // built at all, rather than built and then truncated.
        let reportable = warnings.len() < MAX_REPORTED_DROP_WARNINGS;
        let claimed_id = value.get("id").and_then(serde_json::Value::as_str);

        if let Some(claimed_id) = claimed_id {
            if let Some(slot) = by_id.get_mut(claimed_id) {
                // Item 1 (fix round 4): a second element claiming an id some
                // earlier element already claimed. Neither survives.
                let displaced = slot.take().is_some();
                dropped += if displaced { 2 } else { 1 };
                if reportable {
                    reported += if displaced { 2 } else { 1 };
                    warnings.push(format!(
                        "dropping registry agent entry {}: duplicate id -- another entry in this \
                         document already claims it, so no entry with it is used (letting drop \
                         order decide would let a later entry shadow an earlier one)",
                        escape_and_cap_peer_str(claimed_id)
                    ));
                }
                continue;
            }
        }

        match RegistryAgent::deserialize(&value) {
            Ok(agent) => {
                by_id.insert(agent.id.clone(), Some(agent));
            }
            Err(err) => {
                dropped += 1;
                if reportable {
                    reported += 1;
                    let id_hint = claimed_id
                        .map(|id| escape_and_cap_peer_str(id).to_string())
                        .unwrap_or_else(|| "<no id>".to_string());
                    warnings.push(format!(
                        "dropping registry agent entry {id_hint}: {}",
                        RegistryError::from_json_error(err)
                    ));
                }
                // Poison the id so a later element cannot claim it (the whole
                // point of Item 1: the victim entry is the invalid one).
                if let Some(claimed_id) = claimed_id {
                    by_id.insert(claimed_id.to_string(), None);
                }
            }
        }
    }

    if dropped > reported {
        let remainder = dropped - reported;
        warnings.push(format!(
            "... and {remainder} more registry agent entries dropped"
        ));
    }
    (by_id.into_values().flatten().collect(), warnings)
}

/// Item 3 (fix round 3): parses `bytes` into a [`Registry`] with the same
/// element-wise tolerance as [`Registry`]'s `Deserialize` impl, but also
/// returns the (bounded — see [`MAX_REPORTED_DROP_WARNINGS`]) drop warnings —
/// used by [`fetch_registry`], the one path that can usefully hand those
/// warnings back to a caller that owns a log to put them in (fix round 4,
/// Item 2: round 3 printed them here with `eprintln!` instead).
/// A malformed top-level document (not valid JSON at all, or
/// missing `agents` entirely) still fails outright — this only narrows the
/// blast radius of a single *element's* failure, never tolerates a
/// structurally broken response.
fn parse_registry_tolerant(bytes: &[u8]) -> Result<(Registry, Vec<String>), RegistryError> {
    let raw: RawRegistryTolerant =
        serde_json::from_slice(bytes).map_err(RegistryError::from_json_error)?;
    let (agents, warnings) = partition_registry_agents(raw.agents);
    Ok((Registry { agents }, warnings))
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
    /// this. Fix round 2 (Item 5): the `#[allow(clippy::too_many_arguments)]`
    /// that used to sit here is gone — this has 6 parameters, one below
    /// clippy's default 7-argument threshold, so the lint never actually
    /// fired; the suppression was inert and clippy stays clean without it
    /// (verified: `cargo clippy -p roundhouse-acp --no-deps --all-targets -- -D warnings`
    /// after removal).
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
    /// Item 4(a) (fix round 3): a 4xx/5xx HTTP status. Before this round,
    /// this was enforced only by `.error_for_status()?` (a `reqwest`-level
    /// call folded straight into `?`, indistinguishable in the diff from any
    /// other fallible line) — removing that call entirely survived the full
    /// suite, because nothing pinned the enforcement itself, only trusted a
    /// citation of `reqwest-0.13.4`'s own source. [`ensure_success_status`]
    /// is a pure, socket-free-testable reimplementation of the same check,
    /// and this variant is now the one it constructs.
    ///
    /// **Fix round 4 (Item 4(a)):** round 3's doc here added that "removing
    /// the real call site (in [`fetch_capped_bytes`]) now kills
    /// `ensure_success_status`'s own dedicated tests." That was false —
    /// removing the call site left the whole suite passing, caught only by
    /// `clippy -D warnings`' dead-code lint. See [`ensure_success_status`]'s
    /// own doc for what round 4 does about it and what stays
    /// inspection-only.
    ///
    /// `url` is the caller-supplied fetch URL, not registry-derived text,
    /// so — like `ResponseTooLarge` — it is not routed through
    /// `EscapedPeerStr`.
    #[error("http {status} response from {url}")]
    BadStatus { url: String, status: u16 },
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

/// Item 2 (fix round 2): the concrete hardening settings
/// [`build_registry_http_client`] applies, pulled out to a plain value type
/// so a test can assert its field values against literals directly
/// (`registry_http_policy_hardened_matches_the_pinned_literals`, this
/// module's tests). Before this round, no test referenced
/// `build_registry_http_client` at all, and five mutations against its
/// inline builder calls (and [`MAX_RESPONSE_BYTES`]) survived the full
/// suite: `https_only(false)`, the redirect limit `2` → `100`, `.timeout()`
/// removed, `MAX_RESPONSE_BYTES` → `usize::MAX` (and → `0`), and
/// `error_for_status()` removed.
///
/// **Fix round 3 (Item 4): what this actually pins, stated precisely — round
/// 2's doc overstated this.** [`RegistryHttpPolicy::hardened`] is this
/// module's *only* declaration of each of these five values (no other
/// literal duplicates any of them: [`build_registry_http_client`] and
/// [`fetch_capped_bytes`] both read every one of these settings from a
/// `RegistryHttpPolicy` value — never from an inline literal or a
/// free-standing constant at the point of use), and
/// `registry_http_policy_hardened_matches_the_pinned_literals` asserts every
/// field of `hardened()` against a literal. That test catches the realistic
/// regression: someone edits `hardened()`'s own field values (the one place
/// the numbers live) to weaken a setting. It does **not** catch a
/// deliberately-obfuscated regression that bypasses `hardened()` entirely —
/// hardcoding a different literal directly at a builder call instead of
/// reading the corresponding field — for `https_only`, `redirect_limit`,
/// `connect_timeout`, and `timeout` specifically: those four flow into
/// `reqwest::Client`, which exposes no getters, so no test in this crate can
/// observe what a built client actually does with them without a live
/// socket (forbidden by this task's standing conventions: "No network calls
/// in tests"). That gap is real and disclosed, not fixed — nothing short of
/// a live-socket test or a build-time source scan (considered and rejected
/// as machinery aimed at a threat that isn't the realistic failure, per this
/// round's brief) can close it fully.
///
/// `max_response_bytes` is different: it is **genuinely wired end to end**.
/// [`fetch_capped_bytes`] reads it from `RegistryHttpPolicy::hardened()` (not
/// from the free-standing [`MAX_RESPONSE_BYTES`] constant directly — round 2
/// left that direct reference in place, so `max_response_bytes` was pinned
/// as a struct field but not actually consulted by the real fetch path) and
/// passes it straight into [`accumulate_capped`], which this module's own
/// boundary tests exercise directly and thoroughly. So for this one setting,
/// editing `hardened()`'s field *is* editing the value the real enforcement
/// uses, with no opaque `reqwest::Client` in between — this is the one
/// setting this pin genuinely covers past the struct-literal level, not
/// merely at it.
///
/// The reviewer has already verified `reqwest-0.13.4` honours each of the
/// four client-side settings (`https_only` rejects an `http://` *redirect
/// target* via a separate check at `redirect.rs:324`; `.timeout()` is a true
/// overall deadline wrapping the body) — this type exists to pin the *input*
/// side of that already-verified claim for those four, and both the input
/// and the real enforcement for `max_response_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RegistryHttpPolicy {
    connect_timeout: Duration,
    timeout: Duration,
    redirect_limit: usize,
    https_only: bool,
    max_response_bytes: usize,
}

impl RegistryHttpPolicy {
    /// The one hardened policy this module uses — see
    /// [`build_registry_http_client`] for the reqwest-side rationale behind
    /// each field's value.
    const fn hardened() -> Self {
        RegistryHttpPolicy {
            connect_timeout: CONNECT_TIMEOUT,
            timeout: FETCH_TIMEOUT,
            redirect_limit: 2,
            https_only: true,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
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
/// **Fix round 2 (Item 2):** constructs from [`RegistryHttpPolicy::hardened`]
/// rather than inline literals, so the values themselves are pinned by a
/// direct, socket-free test.
///
/// - `.https_only(policy.https_only)`: registry content carries no signature
///   of its own — HTTPS is the sole integrity control, so a downgrade to
///   `http://` (via a misconfigured URL or a redirect) must fail outright
///   rather than silently serve attacker-interceptable content.
/// - `.redirect(redirect::Policy::limited(policy.redirect_limit))`: some
///   redirection is legitimate (the registry is CDN-fronted), but
///   `reqwest`'s own default of 10 is far more hops than any legitimate
///   single-CDN redirect chain needs; combined with `https_only` above, a
///   redirect can no longer be used to downgrade the scheme.
/// - `.connect_timeout(policy.connect_timeout)` / `.timeout(policy.timeout)`:
///   see [`CONNECT_TIMEOUT`]/[`FETCH_TIMEOUT`]'s docs.
///
/// Panics only if the TLS backend cannot initialize at all — a
/// process-startup environment failure, not something request or response
/// data can trigger — matching the same `.expect(...)` convention
/// `roundhouse-provider`'s `reqwest_transport.rs` and `roundhouse-tools`'s
/// `http.rs` already use for their own `reqwest::Client` construction.
pub fn build_registry_http_client() -> reqwest::Client {
    let policy = RegistryHttpPolicy::hardened();
    reqwest::Client::builder()
        .https_only(policy.https_only)
        .redirect(reqwest::redirect::Policy::limited(policy.redirect_limit))
        .connect_timeout(policy.connect_timeout)
        .timeout(policy.timeout)
        .build()
        .expect("TLS backend initialization")
}

/// Item 2 (fix round 2), corrected in fix round 3. The pure byte-cap
/// enforcement algorithm [`fetch_capped_bytes`] applies while streaming a
/// response body — extracted so it is directly testable without a socket
/// (over cap, exactly at cap, under cap, a lying/absent declared length, and
/// — fix round 3 — the `running` seed itself — see this module's tests).
/// Before fix round 2, nothing tested this arithmetic at all.
///
/// `declared` is an optional declared total (`Content-Length`, if the
/// response header conveys one), checked once against `limit` before any
/// chunk is considered. `running` is the running total *already* folded in
/// by earlier calls for this same fetch — 0 for the first call. `chunks` is
/// the sequence of *new* chunk byte-lengths this call is responsible for
/// folding in, added on top of `running` and short-circuiting with `Err` the
/// instant the total exceeds `limit` — a `Content-Length` can be absent or
/// lie low, so the running check must still catch what the declared-length
/// check alone would miss.
///
/// **Fix round 3: this function used to have no `running` parameter, and its
/// only real caller re-summed the entire prefix of chunks on every single
/// call** (`chunk_lens.iter().copied()` over a `Vec` that grew by one
/// element per chunk) — O(n²) in the number of chunks for what round 1's
/// original inline counter was O(n) for, measured (see [`fetch_capped_bytes`]'s
/// doc for the numbers) to burn a tokio worker at ~100% for the full
/// [`FETCH_TIMEOUT`] on a response framed in small enough chunks, entirely
/// within the byte cap this function itself still enforced. `running` lets
/// [`fetch_capped_bytes`] carry its total forward and call this once per
/// *newly received* chunk (`chunks: std::iter::once(chunk.len())`) rather
/// than re-folding everything seen so far — restoring O(n) while keeping the
/// same pure, socket-free-testable shape.
fn accumulate_capped(
    url: &str,
    limit: usize,
    declared: Option<usize>,
    running: usize,
    chunks: impl Iterator<Item = usize>,
) -> Result<usize, RegistryError> {
    if let Some(len) = declared {
        if len > limit {
            return Err(RegistryError::ResponseTooLarge {
                url: url.to_string(),
                limit,
                received: len,
            });
        }
    }
    let mut total = running;
    for len in chunks {
        total += len;
        if total > limit {
            return Err(RegistryError::ResponseTooLarge {
                url: url.to_string(),
                limit,
                received: total,
            });
        }
    }
    Ok(total)
}

/// Item 4(a) (fix round 3): a pure, socket-free-testable reimplementation of
/// `reqwest::Response::error_for_status()`'s status check — whether `status`
/// is at or above 400. `.error_for_status()?` folded straight into a single
/// line's `?` operator is indistinguishable, in a diff, from any of the other
/// fallible calls on that line; removing it survived the full test suite
/// before round 3, with the only evidence it was still enforced being a
/// citation of the vendored `reqwest-0.13.4` source. This is very slightly
/// stricter than what it replaced: `error_for_status` rejects 4xx and 5xx,
/// while `>= 400` also rejects the nonsense 600..=999 range a peer could
/// still put on the wire.
///
/// **Fix round 4 (Item 4(a)): round 3's doc here claimed "removing that call
/// site now kills this function's own dedicated tests." It did not** —
/// removing the call site left the whole suite passing, and the only thing
/// that caught it was `clippy -D warnings`' dead-code lint, which stops
/// catching it the moment a second caller exists. What is true now:
/// [`begin_capped_read`] is the (socket-free, directly tested) seam that
/// performs this check, so removing the check *from that function* does kill
/// `begin_capped_read_rejects_a_4xx_or_5xx_status_before_reading_a_body`; and
/// removing [`begin_capped_read`]'s own call site in [`fetch_capped_bytes`]
/// does not compile, because the running byte total it returns is what the
/// body-read loop counts from. What no test in this crate can observe,
/// because it would need a live socket (forbidden by this task's standing
/// conventions), is that the `status` handed to [`begin_capped_read`] is the
/// real awaited response's — that one link is inspection-only, and is
/// disclosed here rather than claimed as tested.
fn ensure_success_status(url: &str, status: u16) -> Result<(), RegistryError> {
    if status >= 400 {
        Err(RegistryError::BadStatus {
            url: url.to_string(),
            status,
        })
    } else {
        Ok(())
    }
}

/// Item 4(a) (fix round 4): the pure, socket-free prelude to a capped body
/// read — everything [`fetch_capped_bytes`] can decide from a response's
/// status line and headers alone, before a single body byte is read.
///
/// Rejects a >= 400 status ([`ensure_success_status`]) and then a declared
/// `Content-Length` over the cap ([`accumulate_capped`]), in that order: a
/// 404 error page is not worth measuring. Returns the running byte total the
/// caller's read loop continues from (always 0 today — no body bytes have
/// been seen yet — but returned rather than assumed so the call site is
/// load-bearing and cannot be deleted without a compile error).
fn begin_capped_read(
    url: &str,
    status: u16,
    declared: Option<usize>,
    limit: usize,
) -> Result<usize, RegistryError> {
    ensure_success_status(url, status)?;
    accumulate_capped(url, limit, declared, 0, std::iter::empty())
}

/// Item 1: fetches `url` through `client`, enforcing the size cap (via
/// [`accumulate_capped`]) and treating a 4xx/5xx status as an error (via
/// [`ensure_success_status`], fix round 3 — the original implementation had
/// neither, so a 404/500 error page's body went straight to `serde_json`),
/// returning the capped raw body. Shared by [`fetch_registry`] (which then
/// parses the body element-wise — see [`parse_registry_tolerant`]) and
/// [`fetch_json_capped`] (a plain whole-document parse, used by
/// [`fetch_quarantine`]).
///
/// **Fix round 3 (Item 4(b)): reads its cap from
/// [`RegistryHttpPolicy::hardened`], not the free-standing
/// [`MAX_RESPONSE_BYTES`] constant directly** — see that type's doc for why
/// this is the one setting this module's pin genuinely covers end to end,
/// not merely at the struct-literal level.
///
/// **Fix round 3 (Item 2): this function's predecessor re-summed the entire
/// prefix of chunks on every single chunk — O(n²).** Measured by the
/// coordinator's own reproduction against that shape (10,000/20,000/40,000/
/// 80,000 one-byte chunks: 11.6ms/45.9ms/182.6ms/729.9ms, ×4 per doubling,
/// extrapolating to ≈125s for a 1 MiB body delivered one byte at a time).
/// Independently reproduced against an equivalent isolated model of the
/// old-vs-new shapes (same chunk counts, `usize::MAX` cap so no early exit
/// masks the difference, release build): old
/// 4.91ms/19.21ms/79.13ms/317.56ms (×~4 per doubling, ~50M/200M/800M/3.2B
/// inner iterations); new (this fix) 6.36µs/12.67µs/25.28µs/50.54µs (×~2 per
/// doubling — linear — exactly `n` inner iterations at each size). This
/// function now carries the running total forward itself and calls
/// [`accumulate_capped`] once per newly-received chunk — see that
/// function's doc for the corrected O(n) shape — and no longer keeps a
/// `Vec` of every chunk length seen (round 2's `chunk_lens`, which itself
/// grew to several megabytes for a 1 MiB body).
async fn fetch_capped_bytes(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, RegistryError> {
    let max_response_bytes = RegistryHttpPolicy::hardened().max_response_bytes;
    let mut response = client.get(url).send().await?;

    let mut total = begin_capped_read(
        url,
        response.status().as_u16(),
        response.content_length().map(|len| len as usize),
        max_response_bytes,
    )?;

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        total = accumulate_capped(
            url,
            max_response_bytes,
            None,
            total,
            std::iter::once(chunk.len()),
        )?;
        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

/// Fetches and capped-reads `url` through `client` (see
/// [`fetch_capped_bytes`]), then deserializes the whole body as `T` in one
/// shot. Used by [`fetch_quarantine`] — [`fetch_registry`] does not use this,
/// since [`Registry`]'s element-wise tolerance (Item 3, fix round 3) needs
/// the raw bytes, not a type parameter's blanket `Deserialize`.
async fn fetch_json_capped<T: DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
) -> Result<T, RegistryError> {
    let body = fetch_capped_bytes(client, url).await?;
    serde_json::from_slice(&body).map_err(RegistryError::from_json_error)
}

/// Item 2 (fix round 4): what a registry refresh yields — the registry
/// itself, plus the bounded list of warnings for the entries that were
/// dropped on the way ([`partition_registry_agents`]).
///
/// Round 3 wrote those warnings straight to stderr with `eprintln!` from
/// inside [`fetch_registry`] and [`Registry`]'s `Deserialize` impl. Returning
/// them instead removes three problems at once: this crate is embedded
/// in-process by `roundhouse-daemon`, which shares stderr with the `round`
/// TUI and owns the logging (a library must not write to a stream it does not
/// own, and `eprintln!` output is unfilterable, unstructured, and unrateable
/// by the daemon that does); `eprintln!` *panics* if the write fails
/// (verified: a binary whose stderr is a closed pipe exits 101), which in the
/// `Deserialize` position was a panic inside a pure operation with no
/// `Result` path for it; and the print was unbounded in count. The caller —
/// `roundhouse-daemon`, at the point it calls
/// [`RegistryCache::refresh_registry`] — decides where these go.
///
/// Every warning string is already peer-text-escaped at construction
/// ([`escape_and_cap_peer_str`] over both the `id` and the parser detail), so
/// it carries no raw control characters, ANSI escapes, or unbounded length
/// into whatever sink the caller picks.
#[derive(Debug, Clone, PartialEq)]
pub struct RegistryRefresh {
    pub registry: Registry,
    /// At most [`MAX_REPORTED_DROP_WARNINGS`] individually-named entries plus
    /// one `"... and N more registry agent entries dropped"` remainder line.
    pub warnings: Vec<String>,
}

/// §10.3: "Consume it rather than hardcoding agent launch configs." Fetches
/// the real registry over HTTP through `client` — see
/// [`build_registry_http_client`] for the hardening this requires, and
/// [`fetch_capped_bytes`] for the size cap and status/error handling.
///
/// **Fix round 3 (Item 3): parses the body element-wise via
/// [`parse_registry_tolerant`]**, so one invalid agent entry in a live fetch
/// no longer drops every other agent — see that function's doc, and
/// [`Registry`]'s own `Deserialize` impl (which applies the identical
/// tolerance to a cache read, not just a fresh fetch).
///
/// **Fix round 4 (Item 2): returns [`RegistryRefresh`], not a bare
/// [`Registry`]** — round 3 printed the per-entry drop warnings here with
/// `eprintln!`; they are now handed back to the caller. See
/// [`RegistryRefresh`]'s doc.
///
/// Ruling C-P11: `async`, using reqwest's default async client — never
/// `reqwest::blocking` (this crate has no `blocking` feature enabled; see
/// `Cargo.toml`). The stated consumer, `roundhouse-daemon`, is tokio-based,
/// and `reqwest::blocking` panics when called from inside a tokio runtime.
///
/// **Fix round 3 (Item 6): narrowed from `pub` to `pub(crate)`.**
/// [`RegistryCache`] is the sole intended entry point and already always
/// uses [`build_registry_http_client`]'s hardened client; a `pub` caller
/// could otherwise pass an unhardened `reqwest::Client::new()` and silently
/// lose `https_only`, the redirect limit, and both timeouts.
pub(crate) async fn fetch_registry(
    client: &reqwest::Client,
    url: &str,
) -> Result<RegistryRefresh, RegistryError> {
    let body = fetch_capped_bytes(client, url).await?;
    let (registry, warnings) = parse_registry_tolerant(&body)?;
    Ok(RegistryRefresh { registry, warnings })
}

/// Fetches the quarantine list over HTTP through `client`. Same rationale as
/// [`fetch_registry`], including the fix round 3 (Item 6) `pub` → `pub(crate)`
/// narrowing.
pub(crate) async fn fetch_quarantine(
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

/// Item 5 (fix round 2): computes a temp path for [`write_json`] that is
/// unique per call, not just per `path` — see [`write_json`]'s doc for why
/// round 1's fixed `<path>.tmp` suffix was false advertising. Combines the
/// current process id with a per-process monotonic counter, so two
/// concurrent `write_json` calls targeting the same `path` (within one
/// process, and, via the pid, across processes too) always compute two
/// distinct paths and therefore can never share one temp file to interleave
/// into — pinned directly by
/// `unique_tmp_path_never_repeats_for_the_same_target_path` (this module's
/// tests), which calls this twice for the same `path` and asserts the two
/// results differ, rather than relying on a timing-dependent, potentially
/// flaky real concurrent-write race to demonstrate the same property.
fn unique_tmp_path(path: &Path) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut tmp_path = path.as_os_str().to_os_string();
    tmp_path.push(format!(".{}.{}.tmp", std::process::id(), counter));
    PathBuf::from(tmp_path)
}

/// Item 7 (fix round 1), corrected in fix round 2 (Item 5). Writes a
/// [`unique_tmp_path`] then `std::fs::rename`s it over `path`, so a crash or
/// a concurrent writer can never leave a truncated file readable as the real
/// cache — the failure direction was already safe (a truncated
/// pretty-printed JSON object never re-parses, so the cache degrades to
/// "nothing cached" rather than corrupting silently), but a bare `fs::write`
/// left a window where a reader could observe a partially-written file.
///
/// **Fix round 2: round 1's doc claimed this closed the concurrent-writer
/// half too — it did not.** Both writers wrote to the exact same fixed
/// `<path>.tmp`, so two concurrent `store()` calls could interleave their
/// writes inside that one shared temp file before either renamed it into
/// place, producing a torn result that the atomic rename would then publish
/// as if it were whole. [`unique_tmp_path`] closes this: two concurrent
/// writers now always compute two distinct temp paths, so there is no
/// shared file left for their writes to interleave into — one of the two
/// renames simply wins, atomically, over the other's already-complete
/// write. Also now calls `File::sync_all` before the rename, so the
/// renamed-into-place file's contents are durable on disk before the
/// directory entry that makes it visible as the real cache is updated, not
/// only ordered correctly in the page cache.
///
/// The rename is atomic within the same filesystem, which [`unique_tmp_path`]'s
/// result always is by construction (same directory as `path`).
fn write_json<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(value).map_err(std::io::Error::other)?;
    let tmp_path = unique_tmp_path(path);
    let mut file = std::fs::File::create(&tmp_path)?;
    file.write_all(body.as_bytes())?;
    file.sync_all()?;
    drop(file);
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
    ///
    /// **Fix round 4 (Item 2):** returns a [`RegistryRefresh`], whose
    /// `warnings` field carries the bounded per-entry drop warnings for the
    /// caller to log. Round 3 printed them from inside this crate with
    /// `eprintln!`; see [`RegistryRefresh`]'s doc for why that had to go. The
    /// stale-cache fallback path returns no warnings: the cache read goes
    /// through [`Registry`]'s own (silent) `Deserialize`, and re-reporting
    /// drops from a document fetched on some earlier run would attribute them
    /// to this refresh.
    pub async fn refresh_registry(&self, url: &str) -> Result<RegistryRefresh, RegistryError> {
        self.finish_registry_refresh(fetch_registry(&self.client, url).await)
    }

    /// The sync half of [`Self::refresh_registry`], split out so it can be
    /// unit-tested without a network call (see this module's tests) — it
    /// takes an already-obtained fetch result rather than performing the
    /// fetch itself.
    fn finish_registry_refresh(
        &self,
        fetched: Result<RegistryRefresh, RegistryError>,
    ) -> Result<RegistryRefresh, RegistryError> {
        match fetched {
            Ok(refresh) => {
                self.store(&refresh.registry)?;
                Ok(refresh)
            }
            Err(err) => self
                .load_cached_allow_stale()
                .map(|registry| RegistryRefresh {
                    registry,
                    warnings: Vec::new(),
                })
                .ok_or(err),
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
/// platform is preferred over `Npx`/`Uvx`; package managers are the
/// fallback, used only when no verifiable binary exists for this platform.**
/// The previous order (`npx` > `uvx` > `binary`) inverted the actual
/// integrity argument: `Npx`/`Uvx` carry no digest at all *and* `npx`
/// executes install scripts — the live quarantine list's
/// `"agoragentic-acp": "Postinstall script"` entry is exactly this hazard
/// already having been exercised. Verified against live data: the only two
/// agents that reach this function with more than one distribution method
/// (`kilo`, `sigit`) each publish a full `binary` map with `sha256` on every
/// platform target, so the old order discarded the checksum-pinned channel
/// in both real cases that exist.
///
/// **Fix round 2 (Item 1): the `UnverifiableBinary` check for a `Binary`
/// present for this platform but missing `sha256` is now checked
/// immediately — before, not after, the `npx`/`uvx` arms below.** Round 1's
/// version left this check in its original position, *after* the `npx`
/// (then `uvx`) early returns: for any agent publishing a binary with no
/// `sha256` *and* an `npx`/`uvx` fallback, resolution never reached the
/// `UnverifiableBinary` branch at all — it fell through and returned the
/// unverified `npx`/`uvx` channel instead, silently defeating the very
/// checksum preference this round's own doc paragraph above claims to
/// enforce. Reproduced with a `kilo`-shaped entry minus `sha256`:
/// `resolve_launch` returned `Ok(LaunchConfig(Npx { package: "@evil/pkg",
/// .. }))` instead of `Err(UnverifiableBinary)`. A `Binary` present for the
/// current platform but missing `sha256` is now surfaced as
/// [`ResolveError::UnverifiableBinary`] the moment that's known — refusing
/// outright, not falling through to a channel with no digest at all, which
/// is the same hazard one branch later. (A `sha256` that is present but
/// malformed, e.g. `Some("")`, never reaches this function at all as of
/// Item 5's [`is_valid_sha256_hex`] check — it is rejected at deserialize
/// time, in [`validate_binary_target`].)
fn resolve_distribution(agent: &RegistryAgent) -> Result<LaunchConfig, ResolveError> {
    let target = current_platform_target();

    if let Some(binary) = agent.distribution.binary.get(target) {
        return match &binary.sha256 {
            Some(sha256) => Ok(LaunchConfig::binary(
                target.to_string(),
                binary.archive.clone(),
                Some(sha256.clone()),
                binary.cmd.clone(),
                binary.args.clone(),
                binary.env.clone(),
            )),
            None => Err(ResolveError::UnverifiableBinary {
                agent_id: escape_and_cap_peer_str(&agent.id),
                target: escape_and_cap_peer_str(target),
            }),
        };
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
        let refresh = result.expect("must fall back to the stale cache");
        assert_eq!(refresh.registry.agents.len(), 1);
        assert!(
            refresh.warnings.is_empty(),
            "the stale-cache path reports no warnings of its own: {:?}",
            refresh.warnings
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
        let result = cache.finish_registry_refresh(Ok(RegistryRefresh {
            registry: sample_registry(),
            warnings: vec!["dropping registry agent entry x: synthetic".to_string()],
        }));
        let refresh = result.expect("a successful fetch must be stored and returned");
        assert_eq!(cache.load_cached().unwrap().agents.len(), 1);
        assert_eq!(
            refresh.warnings,
            vec!["dropping registry agent entry x: synthetic".to_string()],
            "Item 2 (fix round 4): the fetch's warnings must reach the caller, not stderr"
        );
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
        // Fix round 2 (Item 5): the sibling id test below already asserted
        // both halves (absence of the raw form, presence of the escaped
        // form) — this test asserted only the absence half, so replacing
        // the whole `detail` with `""` (or any other value containing
        // neither a raw newline nor a raw ANSI escape) would have survived
        // it undetected.
        assert!(
            rendered.contains("\\n"),
            "the escaped form of the newline must appear instead: {rendered:?}"
        );
        assert!(
            rendered.contains("\\u{1b}"),
            "the escaped form of the ANSI escape must appear instead: {rendered:?}"
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

    // ---- Item 1: a binary present but missing sha256 must not fall through
    // to npx/uvx when both are published ----

    #[test]
    fn resolve_distribution_refuses_a_no_sha256_binary_even_when_npx_is_also_published() {
        // The exact shape the coordinator's reviewer reproduced against:
        // a kilo-shaped entry (binary + npx both present) minus `sha256`.
        // Before this round, resolve_distribution's UnverifiableBinary check
        // sat after the npx/uvx early returns, so this silently resolved to
        // Ok(LaunchConfig(Npx { package: "@evil/pkg", .. })) instead.
        let mut binary = BTreeMap::new();
        binary.insert(
            current_platform_target().to_string(),
            BinaryTarget {
                archive: "https://example.invalid/evil.tar.gz".to_string(),
                sha256: None,
                cmd: "./evil".to_string(),
                args: vec![],
                env: BTreeMap::new(),
            },
        );
        let agent = RegistryAgent {
            id: "mixed-no-sha256".to_string(),
            name: "Mixed No Sha256".to_string(),
            distribution: Distribution {
                npx: Some(PackageDistribution {
                    package: "@evil/pkg".to_string(),
                    args: vec![],
                    env: BTreeMap::new(),
                }),
                uvx: None,
                binary,
            },
        };
        let err = resolve_distribution(&agent)
            .expect_err("a binary with no sha256 must never fall through to npx");
        assert!(
            matches!(err, ResolveError::UnverifiableBinary { .. }),
            "expected UnverifiableBinary, got {err:?}"
        );
    }

    // ---- Item 2: the pure byte-cap algorithm, tested without a socket ----

    #[test]
    fn accumulate_capped_rejects_a_declared_length_over_the_cap_before_reading_any_chunk() {
        let err = accumulate_capped("https://x.invalid", 100, Some(101), 0, std::iter::empty())
            .expect_err("a declared length over the cap must be rejected immediately");
        assert!(matches!(
            err,
            RegistryError::ResponseTooLarge {
                limit: 100,
                received: 101,
                ..
            }
        ));
    }

    #[test]
    fn accumulate_capped_accepts_a_declared_length_exactly_at_the_cap() {
        let result = accumulate_capped("https://x.invalid", 100, Some(100), 0, std::iter::empty());
        assert!(
            result.is_ok(),
            "exactly at the cap must be accepted: {result:?}"
        );
    }

    #[test]
    fn accumulate_capped_rejects_chunks_whose_running_total_exceeds_the_cap() {
        // No declared length at all (the common real case: a lying or
        // absent Content-Length) -- the running total over the chunk
        // sequence must still catch it.
        let err = accumulate_capped("https://x.invalid", 100, None, 0, [40, 40, 40].into_iter())
            .expect_err("40+40+40 = 120 > 100 must be rejected");
        assert!(matches!(
            err,
            RegistryError::ResponseTooLarge {
                limit: 100,
                received: 120,
                ..
            }
        ));
    }

    #[test]
    fn accumulate_capped_accepts_chunks_exactly_at_the_cap() {
        let result = accumulate_capped("https://x.invalid", 100, None, 0, [40, 40, 20].into_iter());
        assert_eq!(result.unwrap(), 100);
    }

    #[test]
    fn accumulate_capped_accepts_chunks_under_the_cap() {
        let result = accumulate_capped("https://x.invalid", 100, None, 0, [10, 20, 30].into_iter());
        assert_eq!(result.unwrap(), 60);
    }

    #[test]
    fn accumulate_capped_is_not_fooled_by_a_declared_length_that_understates_the_real_total() {
        // A lying Content-Length well under the cap must not exempt the
        // response from the running-total check once its real chunks
        // exceed the cap.
        let err = accumulate_capped("https://x.invalid", 100, Some(5), 0, [60, 60].into_iter())
            .expect_err("the declared length lied; the real chunk total must still be enforced");
        assert!(matches!(
            err,
            RegistryError::ResponseTooLarge { limit: 100, .. }
        ));
    }

    // ---- Item 2 (fix round 3): the running-total seed is genuinely carried
    // forward, not re-derived from a re-summed prefix ----

    #[test]
    fn accumulate_capped_folds_a_nonzero_running_seed_forward() {
        // Simulates fetch_capped_bytes's real call pattern: an earlier call
        // already folded 90 bytes in; this call, given only the *new* 5-byte
        // chunk, must return 95 -- not 5 (which a version that ignored
        // `running` would produce) and not re-derive 90 by re-summing a
        // prefix it was never given.
        let result = accumulate_capped("https://x.invalid", 100, None, 90, [5].into_iter());
        assert_eq!(
            result.unwrap(),
            95,
            "the running seed must be carried forward and added to, not ignored or re-derived"
        );
    }

    #[test]
    fn accumulate_capped_rejects_when_a_running_seed_plus_one_new_chunk_exceeds_the_cap() {
        // 95 already folded in (from a previous call) + a new 10-byte chunk
        // = 105 > 100 -- must be rejected even though the single new chunk
        // passed to *this* call (10 bytes) is nowhere near the cap on its
        // own.
        let err = accumulate_capped("https://x.invalid", 100, None, 95, [10].into_iter())
            .expect_err("running seed (95) + new chunk (10) = 105 > 100 must be rejected");
        assert!(matches!(
            err,
            RegistryError::ResponseTooLarge {
                limit: 100,
                received: 105,
                ..
            }
        ));
    }

    // ---- Item 2: the hardened client's settings are pinned against literals ----

    #[test]
    fn registry_http_policy_hardened_matches_the_pinned_literals() {
        let policy = RegistryHttpPolicy::hardened();
        assert_eq!(policy.connect_timeout, Duration::from_secs(10));
        assert_eq!(policy.timeout, Duration::from_secs(30));
        assert_eq!(policy.redirect_limit, 2);
        assert!(policy.https_only, "https_only must be true");
        assert_eq!(policy.max_response_bytes, 1_048_576);
    }

    // ---- Item 4(a) (fix round 3): status handling reimplemented as a pure,
    // dedicated, testable function -- removing the real `.error_for_status()`
    // call used to survive the full suite ----

    #[test]
    fn ensure_success_status_accepts_2xx_and_3xx() {
        for status in [200, 201, 204, 299, 302] {
            assert!(
                ensure_success_status("https://x.invalid", status).is_ok(),
                "status {status} must be accepted"
            );
        }
    }

    #[test]
    fn ensure_success_status_rejects_4xx_and_5xx() {
        for status in [400, 404, 429, 500, 503] {
            let err = ensure_success_status("https://x.invalid", status)
                .expect_err(&format!("status {status} must be rejected"));
            assert!(matches!(
                err,
                RegistryError::BadStatus { status: s, .. } if s == status
            ));
        }
    }

    // ---- Item 3: env allowlist, not denylist ----

    #[test]
    fn disallowed_env_key_accepts_a_real_live_allowlisted_key() {
        let mut env = BTreeMap::new();
        env.insert("FAST_AGENT_MODEL".to_string(), "codexplan".to_string());
        assert_eq!(disallowed_env_key(&env), None);
    }

    #[test]
    fn disallowed_env_key_rejects_loader_and_interpreter_hijack_variables_the_denylist_missed() {
        // Every one of these was accepted by fix round 1's FORBIDDEN_ENV_KEYS
        // denylist (the coordinator's probe of 42 keys found them all).
        for key in [
            "GCONV_PATH",
            "BASH_ENV",
            "ENV",
            "SHELLOPTS",
            "NODE_PATH",
            "PERL5OPT",
            "RUBYOPT",
            "HTTPS_PROXY",
            "SSL_CERT_FILE",
            "HOME",
            "LD_PRELOAD ", // trailing-space exact-match evasion
        ] {
            let mut env = BTreeMap::new();
            env.insert(key.to_string(), "x".to_string());
            assert_eq!(
                disallowed_env_key(&env),
                Some(key),
                "{key:?} must be rejected by the allowlist"
            );
        }
    }

    #[test]
    fn disallowed_env_key_rejects_case_or_whitespace_varied_forms_of_an_allowed_key() {
        // Item 5 (fix round 3): mutating disallowed_env_key's comparison to
        // `key.trim().eq_ignore_ascii_case(allowed)` survived the full
        // suite -- every existing negative test above uses a name nowhere
        // near the six allowed ones, so trimming/case-folding never changed
        // any of their outcomes. A variant of a *real allowed* key is the
        // only shape that distinguishes exact matching from the round-1
        // evasion (trailing space, case-folding) this module's own doc
        // claims is closed: under exact matching, neither variant equals
        // the literal "FAST_AGENT_MODEL", so both must still be rejected.
        for key in ["fast_agent_model", "FAST_AGENT_MODEL "] {
            let mut env = BTreeMap::new();
            env.insert(key.to_string(), "x".to_string());
            assert_eq!(
                disallowed_env_key(&env),
                Some(key),
                "{key:?} (a case/whitespace-varied form of an allowed key) must still be rejected"
            );
        }
    }

    // ---- Item 4: cmd validated against explicit shapes, not host Path ----

    #[test]
    fn is_safe_relative_cmd_rejects_windows_absolute_and_unc_shapes_on_this_posix_build() {
        // Fix round 2: round 1's `Path::new(cmd).is_absolute()` is POSIX-only
        // semantics on this build, so all four of these -- each escaping the
        // extraction directory on a real Windows target -- previously passed.
        for cmd in [
            "\\Windows\\System32\\cmd.exe",
            "C:evil.exe",
            "\\\\server\\share\\evil.exe",
            "\\\\?\\C:\\evil.exe",
        ] {
            assert!(
                !is_safe_relative_cmd(cmd),
                "{cmd:?} must be rejected as unsafe"
            );
        }
    }

    #[test]
    fn is_safe_relative_cmd_rejects_control_characters_and_whitespace() {
        for cmd in ["./x\nevil", "./a b; rm -rf /"] {
            assert!(
                !is_safe_relative_cmd(cmd),
                "{cmd:?} must be rejected: closes the asymmetry with is_plausible_package_name"
            );
        }
    }

    #[test]
    fn is_safe_relative_cmd_accepts_the_real_live_relative_shapes() {
        for cmd in ["./kilo", "./bin\\devin.exe", "amp-acp.exe"] {
            assert!(is_safe_relative_cmd(cmd), "{cmd:?} must remain accepted");
        }
    }

    #[test]
    fn is_plausible_package_name_rejects_url_and_path_shaped_specs() {
        // Item 4: npx accepts every one of these as an installable spec and
        // fetches/executes code from outside the npm registry entirely.
        for package in [
            "../../../tmp/evil",
            "/tmp/evil",
            "file:/tmp/evil",
            "git+ssh://attacker/x",
            "https://attacker.example/x.tgz",
            "~/evil",
        ] {
            assert!(
                !is_plausible_package_name(package),
                "{package:?} must be rejected"
            );
        }
    }

    // ---- Item 1 (fix round 3): npm/npx's schemeless GitHub shorthand ----

    #[test]
    fn is_plausible_package_name_rejects_npm_github_shorthand_specs() {
        // Round 2 closed scheme-qualified (`git+ssh://...`) and path-shaped
        // (`/`, `.`, `~`-leading) specs, but not npm/npx's *schemeless*
        // `user/repo` GitHub shorthand -- npx resolves a bare `user/repo` as
        // a GitHub tarball, and `#commit-ish` pins an arbitrary commit,
        // giving `attacker/evil-repo` the same "fetch and run
        // attacker-controlled code" capability as `git+ssh://attacker/x`,
        // one syntax removed.
        for package in ["attacker/evil-repo", "attacker/evil-repo#branch", "a/b/c"] {
            assert!(
                !is_plausible_package_name(package),
                "{package:?} must be rejected"
            );
        }
    }

    #[test]
    fn is_plausible_package_name_accepts_real_live_scoped_and_versioned_specs() {
        // Every `package` string in ACP-REGISTRY-FORMAT.md: the five concrete
        // live values, plus the two FORMAT.md schema examples. Fix round 4
        // (Item 3) must not have cost any of them.
        for package in [
            "@openai/codex-acp",
            "@agentclientprotocol/claude-agent-acp@0.73.0",
            "@google/gemini-cli@0.58.0",
            "fast-agent-acp==0.10.1",
            "agoragentic-mcp@1.3.0",
            "@scope/package",
            "package-name",
        ] {
            assert!(
                is_plausible_package_name(package),
                "{package:?} must remain accepted"
            );
        }
    }

    // ---- Item 5: sha256 must be a real 64-hex-character digest ----

    #[test]
    fn is_valid_sha256_hex_rejects_an_empty_string() {
        assert!(!is_valid_sha256_hex(""));
    }

    #[test]
    fn is_valid_sha256_hex_rejects_the_wrong_length() {
        assert!(!is_valid_sha256_hex(&"a".repeat(63)));
        assert!(!is_valid_sha256_hex(&"a".repeat(65)));
    }

    #[test]
    fn is_valid_sha256_hex_rejects_a_64_character_non_hex_string() {
        // Item 5 (fix round 3): mutating this function to `value.len() ==
        // 64` (dropping the is_ascii_hexdigit predicate) survived the full
        // suite -- every existing test exercised length only. A 64-character
        // string with a non-hex character must still be rejected even
        // though its length alone is correct.
        assert!(!is_valid_sha256_hex(&"z".repeat(64)));
        // A real live digest (amp-acp, darwin-aarch64 target,
        // ACP-REGISTRY-FORMAT.md) with its last character swapped to a
        // non-hex character.
        assert!(!is_valid_sha256_hex(
            "240a1a464f2a400ae51e9613b7f52b2abb6e7a29759001e9185291325671ccfz"
        ));
    }

    #[test]
    fn is_valid_sha256_hex_accepts_a_real_shaped_digest() {
        assert!(is_valid_sha256_hex(&"a".repeat(64)));
        // A real live sha256 value (amp-acp, darwin-aarch64 target,
        // ACP-REGISTRY-FORMAT.md).
        assert!(is_valid_sha256_hex(
            "240a1a464f2a400ae51e9613b7f52b2abb6e7a29759001e9185291325671ccf1"
        ));
    }

    #[test]
    fn validate_binary_target_rejects_an_empty_sha256() {
        // sha256: Some("") used to pass Option::is_some() in
        // resolve_distribution and look checksum-pinned with a value no
        // verifier could use.
        let binary = BinaryTarget {
            archive: "https://x".to_string(),
            sha256: Some(String::new()),
            cmd: "./x".to_string(),
            args: vec![],
            env: BTreeMap::new(),
        };
        assert!(validate_binary_target("linux-x86_64", &binary).is_err());
    }

    // ---- Item 5: unique temp paths, tested deterministically ----

    #[test]
    fn unique_tmp_path_never_repeats_for_the_same_target_path() {
        let path = Path::new("/does/not/need/to/exist/registry.json");
        let a = unique_tmp_path(path);
        let b = unique_tmp_path(path);
        assert_ne!(
            a, b,
            "two concurrent writers must never compute the same temp file path"
        );
    }

    #[test]
    fn write_json_produces_a_file_readable_back_as_the_same_value() {
        // write_json's own round trip, now going through unique_tmp_path and
        // an explicit File::create/write_all/sync_all instead of
        // std::fs::write -- must still behave like a normal write.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        write_json(&path, &sample_registry()).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        let parsed: Registry = serde_json::from_str(&contents).unwrap();
        assert_eq!(parsed.agents.len(), 1);
    }

    // ---- Item 3 (fix round 3): one invalid agent entry must not take down
    // its valid siblings ----

    #[test]
    fn partition_registry_agents_drops_only_the_invalid_entry_and_names_it() {
        let raw_agents = vec![
            serde_json::json!({
                "id": "good-agent",
                "name": "Good",
                "distribution": {"npx": {"package": "g"}}
            }),
            serde_json::json!({
                "id": "bad-agent",
                "name": "Bad",
                // A single env key not on ALLOWED_ENV_KEYS -- exactly the
                // coordinator's reproduction (a hypothetical future
                // upstream flag).
                "distribution": {
                    "npx": {"package": "b", "env": {"NEW_UPSTREAM_FEATURE_FLAG": "1"}}
                }
            }),
        ];
        let (agents, warnings) = partition_registry_agents(raw_agents);
        assert_eq!(
            agents.len(),
            1,
            "the valid sibling must survive the invalid entry's failure"
        );
        assert_eq!(agents[0].id, "good-agent");
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0].contains("bad-agent"),
            "the warning must name the id of the dropped entry: {warnings:?}"
        );
    }

    #[test]
    fn partition_registry_agents_names_an_entry_no_id_when_id_itself_is_unreadable() {
        let raw_agents = vec![serde_json::json!({
            "name": "no id field at all",
            "distribution": {"npx": {"package": "x"}}
        })];
        let (agents, warnings) = partition_registry_agents(raw_agents);
        assert!(agents.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0].contains("<no id>"),
            "must fall back to a literal placeholder rather than panicking or omitting the \
             identification entirely: {warnings:?}"
        );
    }

    #[test]
    fn registry_deserialize_drops_an_invalid_entry_without_failing_its_valid_siblings() {
        // Registry's own (hand-written) Deserialize impl, not just the pure
        // partition_registry_agents helper -- pins that the tolerance is
        // actually wired into the type ordinary `serde_json::from_str`
        // callers (including a plain cache-file read) go through, not only
        // the dedicated fetch path.
        let json = r#"{
            "agents": [
                {"id": "bad", "name": "B", "distribution": {}},
                {"id": "good", "name": "G", "distribution": {"npx": {"package": "g"}}}
            ]
        }"#;
        let registry: Registry = serde_json::from_str(json)
            .expect("a single invalid entry must not fail the whole registry's deserialize");
        assert_eq!(registry.agents.len(), 1);
        assert_eq!(registry.agents[0].id, "good");
    }

    // ---- Item 1 (fix round 4): a colliding id drops *every* entry with it ----

    #[test]
    fn partition_registry_agents_drops_both_entries_that_share_an_id() {
        // The round-3 hole, at the unit level: entry 1 is the legitimate
        // `claude-code`, dropped for an env flag this crate has not
        // allowlisted (the exact scenario per-entry tolerance exists for);
        // entry 2 is a valid, attacker-authored entry re-using the same id.
        // Round 3 kept entry 2. Neither may survive.
        let raw_agents = vec![
            serde_json::json!({
                "id": "claude-code",
                "name": "Claude Agent",
                "distribution": {"npx": {
                    "package": "@agentclientprotocol/claude-agent-acp@0.73.0",
                    "env": {"NEW_UPSTREAM_FEATURE_FLAG": "1"}
                }}
            }),
            serde_json::json!({
                "id": "claude-code",
                "name": "Claude Agent",
                "distribution": {"npx": {"package": "attacker-controlled-pkg@9.9.9"}}
            }),
        ];
        let (agents, warnings) = partition_registry_agents(raw_agents);
        assert!(
            agents.is_empty(),
            "a shadowing entry must not inherit the victim id: {agents:?}"
        );
        assert_eq!(warnings.len(), 2, "one drop per entry: {warnings:?}");
        assert!(
            warnings.iter().any(|w| w.contains("duplicate id")),
            "the collision must be reported as such: {warnings:?}"
        );
    }

    #[test]
    fn partition_registry_agents_drops_all_three_entries_that_share_an_id() {
        // The two-entry case removes the stored entry; a third must not then
        // slip into the vacated slot.
        let entry = |package: &str| {
            serde_json::json!({
                "id": "shadowed",
                "name": "N",
                "distribution": {"npx": {"package": package}}
            })
        };
        let (agents, warnings) =
            partition_registry_agents(vec![entry("a"), entry("b"), entry("c")]);
        assert!(agents.is_empty(), "{agents:?}");
        assert_eq!(warnings.len(), 2, "{warnings:?}");
    }

    #[test]
    fn partition_registry_agents_keeps_distinct_ids_when_another_pair_collides() {
        // The collision must not take out unrelated entries -- dropping
        // everything would be fail-closed but useless.
        let raw_agents = vec![
            serde_json::json!({
                "id": "alpha", "name": "A", "distribution": {"npx": {"package": "a"}}
            }),
            serde_json::json!({
                "id": "dup", "name": "D", "distribution": {"npx": {"package": "d1"}}
            }),
            serde_json::json!({
                "id": "dup", "name": "D", "distribution": {"npx": {"package": "d2"}}
            }),
            serde_json::json!({
                "id": "beta", "name": "B", "distribution": {"npx": {"package": "b"}}
            }),
        ];
        let (agents, warnings) = partition_registry_agents(raw_agents);
        let ids: Vec<&str> = agents.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, vec!["alpha", "beta"]);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
    }

    #[test]
    fn registry_deserialize_drops_both_entries_that_share_an_id() {
        // The type's own Deserialize, i.e. what an ordinary cache-file read
        // goes through -- not only the pure helper.
        let json = r#"{
            "agents": [
                {"id": "claude-code", "name": "C", "distribution": {"npx": {
                    "package": "@agentclientprotocol/claude-agent-acp@0.73.0",
                    "env": {"NEW_UPSTREAM_FEATURE_FLAG": "1"}
                }}},
                {"id": "claude-code", "name": "C", "distribution": {"npx": {
                    "package": "attacker-controlled-pkg@9.9.9"
                }}}
            ]
        }"#;
        let registry: Registry = serde_json::from_str(json).unwrap();
        assert!(registry.agents.is_empty(), "{:?}", registry.agents);
    }

    // ---- Item 2 (fix round 4): the warning list is bounded ----

    #[test]
    fn partition_registry_agents_caps_its_warnings_and_reports_the_remainder() {
        // Round 3 built one String per dropped entry, unbounded: the
        // coordinator measured 349,521 warnings / ~41 MB of Vec<String> from
        // a body sized to fit inside MAX_RESPONSE_BYTES. This measures the
        // replacement's bound directly. 20,000 entries is well past the cap
        // and fast enough for a debug-profile test; the id is 1,000
        // characters so per-warning length is exercised too (escape_and_cap
        // caps it at PEER_STR_MAX_LEN).
        const ENTRIES: usize = 20_000;
        let long_bad_id = "A".repeat(1_000); // uppercase => fails ^[a-z][a-z0-9-]*$
        let raw_agents: Vec<serde_json::Value> = (0..ENTRIES)
            .map(|_| {
                serde_json::json!({
                    "id": long_bad_id,
                    "name": "N",
                    "distribution": {"npx": {"package": "p"}}
                })
            })
            .collect();

        let (agents, warnings) = partition_registry_agents(raw_agents);

        assert!(agents.is_empty());
        // MAX_REPORTED_DROP_WARNINGS (8) named entries + 1 remainder line.
        // Stated as an independent literal, not recomputed from the constant.
        assert_eq!(
            warnings.len(),
            9,
            "the warning list must not grow with the input: {} entries produced {} warnings",
            ENTRIES,
            warnings.len()
        );
        assert!(
            warnings[8].contains("and 19992 more registry agent entries dropped"),
            "the remainder line must account for every unnamed drop: {:?}",
            warnings[8]
        );
        // Measured bound (the quantitative-claim rule): each named warning
        // carries at most two PEER_STR_MAX_LEN-capped (128-byte) escaped
        // fragments plus fixed prose. Measured on exactly this input:
        // 2,668 bytes total across the 9 strings, from 20,000 dropped entries
        // whose ids are 1,000 characters each. The same input through round
        // 3's uncapped shape (`reportable = true`) produced 20,000 warnings.
        let total_bytes: usize = warnings.iter().map(String::len).sum();
        assert!(
            total_bytes < 4096,
            "the whole warning list must stay small: {total_bytes} bytes"
        );
    }

    #[test]
    fn registry_deserialize_is_silent_while_the_fetch_path_still_reports_drops() {
        // Item 2 (fix round 4): tolerance and reporting are now separate.
        // The same document must deserialize (silently, discarding warnings)
        // through Registry's Deserialize and *also* yield warnings through
        // the path fetch_registry uses -- so removing the reporting from
        // parse_registry_tolerant does not merely look like the intended
        // silence.
        let body = br#"{
            "agents": [
                {"id": "good", "name": "G", "distribution": {"npx": {"package": "g"}}},
                {"id": "bad", "name": "B", "distribution": {}}
            ]
        }"#;
        let registry: Registry = serde_json::from_slice(body).unwrap();
        assert_eq!(registry.agents.len(), 1);

        let (also_registry, warnings) = parse_registry_tolerant(body).unwrap();
        assert_eq!(also_registry, registry, "same tolerance, both ways in");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("bad"), "{warnings:?}");
    }

    // ---- Item 3 (fix round 4): npm's `file` spec syntax ----

    #[test]
    fn is_plausible_package_name_rejects_npm_archive_file_specs() {
        // npm-package-arg classifies each of these as a `file` spec via
        // /[.](?:tgz|tar.gz|tar)$/i -- no `/`, `:`, `#`, or leading
        // `.`/`/`/`~` needed, so none of the earlier rules saw them. The
        // last two show the check must run against each `@`-separated part,
        // and that round 3's `@scope/name` allowance was itself a carrier.
        for package in [
            "evil.tgz",
            "evil.tar.gz",
            "evil.tar",
            "EVIL.TGZ",
            "Evil.Tar.Gz",
            "pkg@evil.tgz",
            "@scope/name@evil.tgz",
        ] {
            assert!(
                !is_plausible_package_name(package),
                "{package:?} must be rejected"
            );
        }
    }

    #[test]
    fn is_plausible_package_name_rejects_an_empty_scope_or_name() {
        // Not a security hole -- neither is an installable spec -- but the
        // doc claims npm's scoped-package grammar, and round 3's code only
        // counted the `/`.
        for package in ["@scope/", "@/", "@/name"] {
            assert!(
                !is_plausible_package_name(package),
                "{package:?} must be rejected"
            );
        }
    }

    // ---- Item 4(a) (fix round 4): the status check has a real seam ----

    #[test]
    fn begin_capped_read_rejects_a_4xx_or_5xx_status_before_reading_a_body() {
        for status in [400u16, 404, 418, 500, 503, 599] {
            let err = begin_capped_read("https://x.invalid", status, Some(10), 1_000)
                .expect_err("a >= 400 status must not begin a body read");
            assert!(
                matches!(err, RegistryError::BadStatus { status: s, .. } if s == status),
                "{status} produced {err:?}"
            );
        }
    }

    #[test]
    fn begin_capped_read_accepts_a_success_status_and_starts_the_total_at_zero() {
        let total = begin_capped_read("https://x.invalid", 200, Some(10), 1_000)
            .expect("a 200 with a small declared length must begin the read");
        assert_eq!(total, 0, "no body bytes have been counted yet");
    }

    #[test]
    fn begin_capped_read_rejects_an_oversized_declared_length_on_a_success_status() {
        // The status check must not have displaced the declared-length check.
        let err = begin_capped_read("https://x.invalid", 200, Some(1_001), 1_000)
            .expect_err("a declared length over the cap must fail before any body is read");
        assert!(
            matches!(
                err,
                RegistryError::ResponseTooLarge {
                    limit: 1_000,
                    received: 1_001,
                    ..
                }
            ),
            "{err:?}"
        );
    }
}
