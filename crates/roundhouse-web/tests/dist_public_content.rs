//! Task 10 slice A (Phase 7, lane W2) — the criterion-1 guard for
//! `crates/roundhouse-web/assets/dist/`.
//!
//! `crates/roundhouse-web/src/assets.rs`'s module docs state binding
//! acceptance criterion 1 in full: under a LAN bind, the shared token gate
//! covers `/api` only, so **every byte under `assets/dist/` is served to any
//! unauthenticated peer on the network.** That is safe for exactly one
//! reason — the directory is compile-time-constant public content, identical
//! in every install — which holds only as long as nothing per-install ever
//! lands in it: no LAN token, no session or workspace id, no generated
//! `config.json`, no accidental disclosure of where the build was produced.
//!
//! Nothing in `crates/roundhouse-web/src/` can detect a violation of that —
//! `serve_asset` serves whatever the directory holds, by design. This test is
//! the only thing in the workspace that reads the shipped bytes and asks
//! whether one of the specific shapes that constraint forbids showed up in
//! them.
//!
//! # It tests what *ships*, not what happens to be on disk
//!
//! Every check below goes through `WebAssets::iter()` and `WebAssets::get`,
//! the same `rust-embed`-generated lookup `serve_asset` calls at request
//! time — not `std::fs` over `assets/dist/` directly. A file present on disk
//! but excluded from the embed (there is no `#[exclude]` on `WebAssets`
//! today, but a future one could add one) would be invisible to a
//! filesystem walk's opposite failure mode and is exactly the gap this
//! module means to close: what a reader could find in the repository is not
//! the same question as what a LAN peer can fetch from the running daemon.
//!
//! # No `regex` dependency
//!
//! `crates/roundhouse-web/Cargo.toml` declares none, and this lane may not
//! edit `Cargo.toml`. Every pattern below is matched by hand over `&[u8]`
//! (never a lossy `String` conversion, since embedded content is arbitrary
//! bytes — a JS bundle is UTF-8 today, but nothing here should assume it).
//!
//! # Deliberately not checked: `http://`
//!
//! SolidJS's own runtime legitimately contains `http://www.w3.org/2000/svg`
//! (the SVG namespace URI, used by its DOM-patching code for namespaced
//! element creation). A guard that flagged every `http://` would fail on the
//! framework itself on day one and would be the first thing deleted by
//! whoever hit that — which is worse than not having the guard, because its
//! absence would then be silent.

use roundhouse_web::WebAssets;

/// A LAN token is 64 lowercase hex characters (`lan_auth.rs`'s
/// `TOKEN_BYTES = 32`, hex-encoded). A run this long of hex digits — in
/// either case, since a token could in principle be typed or logged in
/// either — has no other legitimate reason to appear in a client bundle: it
/// is not a plausible identifier, class name, or hash Vite would ever emit
/// as one unbroken run (its own content hashes are 8 base-encoded
/// characters, mixed-case and not hex-only).
const HEX_RUN_LEN_THAT_LOOKS_LIKE_A_TOKEN: usize = 64;

/// Every embedded file's path (the `rust-embed` key) and its raw bytes, read
/// through the exact lookup `serve_asset` uses at request time.
fn embedded_files() -> Vec<(String, Vec<u8>)> {
    WebAssets::iter()
        .map(|path| {
            let path = path.into_owned();
            let file = WebAssets::get(&path)
                .unwrap_or_else(|| panic!("{path} was listed by iter() but get() returned None"));
            (path, file.data.into_owned())
        })
        .collect()
}

/// Every check in this file passes vacuously over an empty set of files, so
/// this is what stands between "the guard is enforcing something" and "the
/// embed is empty and every assertion below never ran." It also pins that
/// the two files this task's build pipeline is required to produce
/// (`.superpowers/sdd/W2/task-10a-brief.md`'s Step 1) are the ones actually
/// being scanned, not a stale or substituted set.
#[test]
fn web_assets_iter_is_non_vacuous_and_includes_the_shell_and_its_stylesheet() {
    let files = embedded_files();

    assert!(
        !files.is_empty(),
        "WebAssets::iter() yielded no files at all; every check in this suite would have passed \
         vacuously"
    );
    assert!(
        files.iter().any(|(path, _)| path == "index.html"),
        "expected an embedded index.html; found: {:?}",
        files.iter().map(|(path, _)| path).collect::<Vec<_>>()
    );
    assert!(
        files.iter().any(|(path, _)| path == "app.css"),
        "expected an embedded app.css; found: {:?}",
        files.iter().map(|(path, _)| path).collect::<Vec<_>>()
    );
}

/// No embedded key may end in `.map`. A source map embeds the absolute
/// filesystem paths of the machine that built it — the build author's
/// username, home directory layout, and full checkout path — into a file
/// this directory serves to any unauthenticated LAN peer. `vite.config.ts`
/// sets `build.sourcemap: false` specifically so none is ever produced; this
/// is the belt to that braces; it also catches one that reached
/// `assets/dist/` some other way (a stray `.map` copied in by hand, say).
#[test]
fn no_embedded_key_ends_in_dot_map() {
    for (path, _) in embedded_files() {
        assert!(
            !path.ends_with(".map"),
            "{path} is an embedded source map; it can embed the absolute filesystem paths of the \
             machine that built it, served to any unauthenticated LAN peer. Rebuild with \
             `sourcemap: false` (already set in vite.config.ts) and remove the stray file"
        );
    }
}

/// No embedded file's *content* references a source map, even one that was
/// not itself embedded. A `//# sourceMappingURL=...` comment left in a `.js`
/// file after its companion `.map` was excluded is not a leak on its own,
/// but it is exactly the trail a future change that re-enables sourcemaps
/// would need this test to catch — the comment is the symptom that would
/// appear first.
#[test]
fn no_embedded_file_references_a_source_map() {
    for (path, bytes) in embedded_files() {
        assert!(
            !contains_bytes(&bytes, b"sourceMappingURL"),
            "{path} contains a `sourceMappingURL` reference; vite.config.ts sets \
             `sourcemap: false` so this should be unreachable — check that setting has not \
             regressed"
        );
    }
}

/// No embedded file's content may contain the browser's persistent
/// key-value store's own name. `token.ts`'s whole design is to hold the LAN
/// token in `sessionStorage` — cleared when the tab closes — specifically so
/// it does not outlive the tab; a reference to the persistent store's own
/// identifier in the shipped bundle is the one piece of client-side evidence
/// that boundary was crossed. (The check is a literal byte match, so a
/// deliberate string-split workaround would defeat it — the point is to
/// catch an ordinary write, not a determined evasion.)
#[test]
fn no_embedded_file_references_the_browsers_persistent_key_value_store() {
    for (path, bytes) in embedded_files() {
        assert!(
            !contains_bytes(&bytes, b"localStorage"),
            "{path} references the browser's persistent key-value store; the LAN token contract \
             (`token.ts`, `src/lan_auth.rs`'s \"client contract\") requires it live only in \
             sessionStorage, cleared when the tab closes"
        );
    }
}

/// No embedded file's content may contain the literal `config.json`. This
/// directory is compile-time-constant and identical in every install
/// (`src/assets.rs`'s module docs); a generated, per-install configuration
/// file is exactly the kind of thing that constraint forbids, and this is
/// the shape such a mistake would most plausibly take — a client fetching
/// its own settings from a file baked into the public bundle instead of
/// from a gated `/api` route at runtime.
#[test]
fn no_embedded_file_references_a_generated_config_json() {
    for (path, bytes) in embedded_files() {
        assert!(
            !contains_bytes(&bytes, b"config.json"),
            "{path} references \"config.json\"; per-install configuration must come from a \
             gated /api route at runtime, never from a file baked into this public directory"
        );
    }
}

/// No embedded file's content may contain 64 or more consecutive hex
/// digits — the shape of a LAN token (`lan_auth.rs`'s `TOKEN_BYTES = 32`,
/// hex-encoded). Scanned case-insensitively over raw bytes, not as text, so
/// this holds regardless of what encoding a future non-JS asset uses.
#[test]
fn no_embedded_file_contains_a_lan_token_shaped_run_of_hex_digits() {
    for (path, bytes) in embedded_files() {
        assert!(
            !contains_hex_run(&bytes, HEX_RUN_LEN_THAT_LOOKS_LIKE_A_TOKEN),
            "{path} contains a run of {HEX_RUN_LEN_THAT_LOOKS_LIKE_A_TOKEN}+ hex characters, the \
             shape of a LAN token (`lan_auth.rs`'s 32-byte token, hex-encoded) — this directory \
             is served to any unauthenticated LAN peer and must never carry a real one"
        );
    }
}

/// No embedded file's content may contain a UUID (`8-4-4-4-12` hex digits,
/// hyphen-separated). `roundhouse-core`'s `SessionId`/`WorkspaceId` are UUIDs
/// on the wire, and this directory must never carry a specific session or
/// workspace's id baked in at build time — every one of those is per-install
/// (or per-session) state that belongs behind a gated `/api` route, not in
/// content identical across every install.
#[test]
fn no_embedded_file_contains_a_uuid_shaped_string() {
    for (path, bytes) in embedded_files() {
        assert!(
            !contains_uuid(&bytes),
            "{path} contains a UUID-shaped string; a session or workspace id must never be baked \
             into this compile-time-constant, per-install-identical directory — it belongs behind \
             a gated /api route at runtime"
        );
    }
}

/// No embedded file's content may name an absolute origin. `api.ts`'s own
/// comment says this client "must never call an absolute origin" — there is
/// no CORS layer anywhere in the crate (`lan_auth.rs`) and `apiFetch` sets
/// `Authorization: Bearer` unconditionally on whatever path it is handed, so
/// a baked-in absolute base URL would send the LAN token to a third-party
/// origin on every request.
///
/// Deliberately narrower than a bare `http://` match (see this file's module
/// docs on why: SolidJS's own runtime legitimately contains
/// `http://www.w3.org/2000/svg`). This flags three shapes instead, any one of
/// which is a plausible absolute-origin reference and none of which the
/// current bundle contains:
///
/// - `http://` or `https://` NOT immediately followed by `www.w3.org/`;
/// - any `://` immediately followed by a digit (an IP-literal host, under any
///   scheme — `ws://`, `wss://`, or `http(s)://` itself, already covered by
///   the point above but caught here too);
/// - a bare "dotted quad": four groups of 1-3 ASCII digits separated by `.`,
///   not itself part of a longer run of digits/dots — an IP address with no
///   scheme prefix at all, e.g. a target host in a JSON config blob.
#[test]
fn no_embedded_file_names_an_absolute_origin() {
    for (path, bytes) in embedded_files() {
        assert!(
            !contains_disallowed_scheme(&bytes, b"http://"),
            "{path} contains an `http://` reference that is not the SVG namespace URI \
             (`http://www.w3.org/2000/svg`, which SolidJS's runtime legitimately embeds) — this \
             looks like a baked-in absolute origin, which would send `Authorization: Bearer` to \
             a third party (`api.ts`'s own contract: relative paths only)"
        );
        assert!(
            !contains_disallowed_scheme(&bytes, b"https://"),
            "{path} contains an `https://` reference; this client must never call an absolute \
             origin (`api.ts`'s own contract)"
        );
        assert!(
            !contains_scheme_with_digit_host(&bytes),
            "{path} contains a `scheme://<digit>` reference — an IP-literal absolute origin \
             under some scheme; this client must never call an absolute origin"
        );
        assert!(
            !contains_dotted_quad(&bytes),
            "{path} contains a bare dotted-quad IP address; this client must never carry a \
             baked-in host to call as an absolute origin"
        );
    }
}

/// No embedded file's content may disclose where the build was produced.
/// `crates/roundhouse-web/src/assets.rs` forbids this directory carrying
/// anything that differs between installs, and a build-machine path is
/// exactly that: it names the developer's home directory layout and
/// username. `vite.config.ts`'s `sourcemap: false` closes the main road
/// (a source map embeds absolute paths); this is the belt to that braces —
/// a plugin banner or a `new URL(…, import.meta.url)` could still leak one.
#[test]
fn no_embedded_file_discloses_a_build_machine_path() {
    for (path, bytes) in embedded_files() {
        for needle in [
            b"/home/".as_slice(),
            b"/Users/".as_slice(),
            b"C:\\".as_slice(),
        ] {
            assert!(
                !contains_bytes(&bytes, needle),
                "{path} contains {:?}, which looks like a build-machine filesystem path — this \
                 directory is compile-time-constant and identical across installs, and must not \
                 disclose where it was built",
                String::from_utf8_lossy(needle)
            );
        }
    }
}

/// No embedded file's content may contain a non-hex secret shaped like an API
/// key. The hex-run check above is well-matched to the LAN token (64 hex
/// characters) and matches nothing else — an `sk-…` provider key or similar
/// credential sails through it untouched.
///
/// Anchored on both sides so this does not fire on an ordinary hyphenated
/// identifier: the byte before `sk-` must not be alphanumeric or `_` (so
/// `task-row"` does not match — the `sk-` inside it is preceded by `a`), and
/// what follows must either be Anthropic's own `ant-` marker or a run of at
/// least 16 further alphanumeric/`_` characters — long enough that no short,
/// legitimate `sk-`-prefixed identifier trips it by accident.
#[test]
fn no_embedded_file_contains_an_sk_prefixed_key_shaped_string() {
    for (path, bytes) in embedded_files() {
        assert!(
            !contains_sk_prefixed_key(&bytes),
            "{path} contains a string shaped like an `sk-`-prefixed API key (an Anthropic \
             `sk-ant-…` key, or `sk-` followed by 16+ alphanumeric characters) — this directory \
             is served to any unauthenticated LAN peer and must never carry a real credential"
        );
    }
}

/// Whether `haystack` contains `needle` as a contiguous run of bytes.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Whether `bytes` contains `run_len` or more consecutive ASCII hex digits.
fn contains_hex_run(bytes: &[u8], run_len: usize) -> bool {
    let mut run = 0usize;
    for &byte in bytes {
        if byte.is_ascii_hexdigit() {
            run += 1;
            if run >= run_len {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// Every start index in `haystack` at which `needle` occurs, allowing
/// overlaps (irrelevant for the fixed literals this file searches for, but
/// cheaper to state than to rule out).
fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    haystack
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window)| *window == needle)
        .map(|(index, _)| index)
        .collect()
}

/// Whether `bytes` contains `scheme` (e.g. `http://`) at a position not
/// immediately followed by `www.w3.org/` — SolidJS's runtime legitimately
/// embeds `http://www.w3.org/2000/svg` (the SVG namespace URI); everything
/// else shaped like this is a plausible absolute origin.
fn contains_disallowed_scheme(bytes: &[u8], scheme: &[u8]) -> bool {
    const ALLOWED_AFTER: &[u8] = b"www.w3.org/";
    find_all(bytes, scheme).into_iter().any(|index| {
        let after = &bytes[index + scheme.len()..];
        !after.starts_with(ALLOWED_AFTER)
    })
}

/// Whether `bytes` contains `://` immediately followed by an ASCII digit —
/// an IP-literal host under any scheme (`ws://`, `wss://`, or `http(s)://`
/// itself).
fn contains_scheme_with_digit_host(bytes: &[u8]) -> bool {
    find_all(bytes, b"://")
        .into_iter()
        .any(|index| bytes.get(index + 3).is_some_and(u8::is_ascii_digit))
}

/// Whether `bytes` contains a bare "dotted quad": four groups of 1-3 ASCII
/// digits separated by `.`, bounded on both sides so this does not match a
/// prefix or suffix of some longer digit/dot run (a hash, a longer version
/// string, and so on).
fn contains_dotted_quad(bytes: &[u8]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        let bounded_before = index == 0 || !is_digit_or_dot(bytes[index - 1]);
        if bytes[index].is_ascii_digit() && bounded_before {
            if let Some(end) = match_dotted_quad_at(bytes, index) {
                let bounded_after = end >= bytes.len() || !is_digit_or_dot(bytes[end]);
                if bounded_after {
                    return true;
                }
            }
        }
        index += 1;
    }
    false
}

fn is_digit_or_dot(byte: u8) -> bool {
    byte.is_ascii_digit() || byte == b'.'
}

/// If a dotted quad starts at `start`, the index just past it; otherwise
/// `None`.
fn match_dotted_quad_at(bytes: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    for group in 0..4 {
        let mut len = 0;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() && len < 3 {
            pos += 1;
            len += 1;
        }
        if len == 0 {
            return None;
        }
        // A 4th digit right after would make this group part of a longer
        // number, not a 1-3 digit quad segment.
        if pos < bytes.len() && bytes[pos].is_ascii_digit() {
            return None;
        }
        if group < 3 {
            if bytes.get(pos) != Some(&b'.') {
                return None;
            }
            pos += 1;
        }
    }
    Some(pos)
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Whether `bytes` contains an `sk-`-prefixed key shape: `sk-` not preceded
/// by an alphanumeric/`_` byte (so it is not the tail of some other
/// hyphenated identifier), followed by either Anthropic's `ant-` marker or a
/// run of 16+ further alphanumeric/`_` characters.
fn contains_sk_prefixed_key(bytes: &[u8]) -> bool {
    const MIN_KEY_TAIL: usize = 16;
    find_all(bytes, b"sk-").into_iter().any(|index| {
        let boundary_ok = index == 0 || !is_word_byte(bytes[index - 1]);
        if !boundary_ok {
            return false;
        }
        let after = &bytes[index + 3..];
        if after.starts_with(b"ant-") {
            return true;
        }
        after.iter().take_while(|&&b| is_word_byte(b)).count() >= MIN_KEY_TAIL
    })
}

/// Whether `bytes` contains a 36-byte window shaped like a UUID: hex digits
/// with hyphens at exactly positions 8, 13, 18 and 23 (`8-4-4-4-12`).
fn contains_uuid(bytes: &[u8]) -> bool {
    if bytes.len() < 36 {
        return false;
    }

    'window: for window in bytes.windows(36) {
        for (index, &byte) in window.iter().enumerate() {
            let must_be_hyphen = matches!(index, 8 | 13 | 18 | 23);
            if must_be_hyphen {
                if byte != b'-' {
                    continue 'window;
                }
            } else if !byte.is_ascii_hexdigit() {
                continue 'window;
            }
        }
        return true;
    }
    false
}

#[cfg(test)]
mod self_tests {
    //! The hand-rolled matchers above are the actual security-relevant logic
    //! in this file — a bug in `contains_uuid` that never matched anything
    //! would make every embedded-content test above pass vacuously, silently.
    //! These pin their behaviour directly, independent of whatever the
    //! current build output happens to contain.
    use super::{
        contains_bytes, contains_disallowed_scheme, contains_dotted_quad, contains_hex_run,
        contains_scheme_with_digit_host, contains_sk_prefixed_key, contains_uuid,
    };

    #[test]
    fn contains_bytes_finds_a_substring_and_rejects_a_near_miss() {
        assert!(contains_bytes(b"xxconfig.jsonxx", b"config.json"));
        assert!(!contains_bytes(b"config-json", b"config.json"));
    }

    #[test]
    fn contains_disallowed_scheme_allows_only_the_w3_svg_namespace() {
        assert!(!contains_disallowed_scheme(
            b"xmlns=http://www.w3.org/2000/svg",
            b"http://"
        ));
        assert!(contains_disallowed_scheme(
            b"fetch(\"http://evil.example.com/\")",
            b"http://"
        ));
        assert!(contains_disallowed_scheme(
            b"fetch(\"https://evil.example.com/\")",
            b"https://"
        ));
    }

    #[test]
    fn contains_scheme_with_digit_host_matches_any_scheme_over_an_ip_literal() {
        assert!(contains_scheme_with_digit_host(b"ws://192.168.1.5:9000"));
        assert!(!contains_scheme_with_digit_host(
            b"http://www.w3.org/2000/svg"
        ));
    }

    #[test]
    fn contains_dotted_quad_matches_a_bare_ip_but_not_a_semver_string() {
        assert!(contains_dotted_quad(b"target host 192.168.1.5 reached"));
        // Three components (a typical semver) is not a dotted quad.
        assert!(!contains_dotted_quad(b"solid-js 1.9.15"));
        // A longer digit/dot run that merely contains four dot-separated
        // groups as an interior slice is not a *bare* dotted quad — the
        // match must be bounded on both sides.
        assert!(!contains_dotted_quad(b"9.192.168.1.5.9"));
    }

    #[test]
    fn contains_sk_prefixed_key_is_anchored_against_ordinary_hyphenated_identifiers() {
        // The exact false-positive shape a naive `contains("sk-")` would hit.
        assert!(!contains_sk_prefixed_key(b"class=\"task-row\""));
        assert!(contains_sk_prefixed_key(b"sk-ant-api03-abcdefghijklmnop"));
        assert!(contains_sk_prefixed_key(b"sk-1234567890abcdef1234567890"));
        // Too short a tail to be a plausible key.
        assert!(!contains_sk_prefixed_key(b"sk-short"));
    }

    #[test]
    fn contains_hex_run_requires_the_run_to_be_contiguous_and_long_enough() {
        let sixty_four_hex = "a".repeat(64);
        assert!(contains_hex_run(sixty_four_hex.as_bytes(), 64));

        let sixty_three_hex = "a".repeat(63);
        assert!(!contains_hex_run(sixty_three_hex.as_bytes(), 64));

        // A non-hex byte in the middle breaks the run rather than being
        // skipped over.
        let broken = format!("{}g{}", "a".repeat(40), "a".repeat(40));
        assert!(!contains_hex_run(broken.as_bytes(), 64));
    }

    #[test]
    fn contains_uuid_matches_the_hyphenated_shape_and_rejects_near_misses() {
        assert!(contains_uuid(b"id=550e8400-e29b-41d4-a716-446655440000;"));
        // 32 hex digits with no hyphens at all is not this shape.
        assert!(!contains_uuid(b"550e8400e29b41d4a716446655440000"));
        // Hyphens in the wrong places are not this shape either.
        assert!(!contains_uuid(b"550e8400-e29b41d4-a716-446655440000"));
    }
}
