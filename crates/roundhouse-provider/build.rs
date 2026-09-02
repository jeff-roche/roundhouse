//! §9.5: "TOML, one file per provider, build.rs-deserialized so a typo is a
//! build error, not a production 400." This walks profiles/*.toml, parses each
//! with the SAME struct the runtime uses, and panics the build on any error —
//! then emits a manifest of (id, raw source) pairs so runtime code can
//! `include_str!` each file by its already-known path without re-globbing the
//! filesystem (which would not work once installed).
//!
//! `#![allow(dead_code)]`: build scripts compile as a binary crate, so the
//! parts of the mirrored `schema`/`reasoning`/`ir`/`errors` modules that
//! `main` below never calls (most of `reasoning.rs`'s `ReasoningControl` API,
//! the `errors` mirror's fields, etc.) would otherwise trip `dead_code` —
//! those modules exist here only so `schema::ProviderProfile` type-checks
//! and deserializes identically to the runtime copy, not to be exercised by
//! this binary.
#![allow(dead_code)]
use std::path::Path;

// `reasoning.rs` references `crate::ir::ReasoningIntent` (it re-exports Phase
// 1's actual reasoning-intent type as `Intent` — see Task 4's design note).
// build.rs mounts `schema`/`reasoning` at ITS OWN crate root, not nested under
// a `profile` module the way the real lib does, so a bare `mod ir { .. }`
// mirroring just the one enum `reasoning.rs` needs (not the whole of `ir.rs`,
// which build.rs has no reason to pull in) is what makes `crate::ir::..`
// resolve inside this separate compilation unit. Kept in sync manually with
// Phase 1's real `ir::ReasoningIntent` (REALITY-CORRECTIONS §7: it has NO
// `Default` derive — the real enum does not derive it either) — if Phase 1
// ever changes its variants, this mirror needs the same change, exactly like
// `schema`/`reasoning` below already need to be the same struct as the
// runtime uses.
mod ir {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ReasoningIntent {
        Off,
        Low,
        Medium,
        High,
        Max,
    }
}

#[path = "src/profile/reasoning.rs"]
mod reasoning;
#[path = "src/profile/schema.rs"]
mod schema;

// `schema.rs` calls `crate::errors::ErrorProfile`/`ProviderErrorKind` inside
// `ProviderProfile::error_profile`/`ErrorEntry::error_kind`. build.rs never
// calls those methods (it only needs `ProviderProfile` to deserialize) and
// has no `regex` build-dependency, but the methods still need to *compile*
// in this separate compilation unit, so mirror just the two items they
// reference, keeping `code_table`'s shape exactly in sync with
// `src/errors.rs` (that's the field schema.rs actually populates) while
// stubbing `message_patterns`' element type — schema.rs never constructs a
// non-empty one, so its exact type is inert here.
mod errors {
    use std::collections::HashMap;

    #[derive(Debug, Clone, Copy, PartialEq)]
    pub enum ProviderErrorKind {
        Overloaded,
        RateLimited,
        QuotaExhausted,
        ModelNotFound,
    }

    pub struct ErrorProfile {
        pub code_table: HashMap<String, ProviderErrorKind>,
        pub message_patterns: Vec<(String, ProviderErrorKind)>,
    }
}

fn main() {
    let profiles_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("profiles");
    println!("cargo:rerun-if-changed={}", profiles_dir.display());

    let mut manifest_entries = Vec::new();
    for entry in std::fs::read_dir(&profiles_dir).expect("profiles/ directory must exist") {
        let entry = entry.expect("readable profiles/ entry");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }

        let contents = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read profile {path:?}: {e}"));
        let parsed: schema::ProviderProfile = toml::from_str(&contents).unwrap_or_else(|e| {
            panic!(
                "profile {path:?} failed to deserialize — this is the §9.5 guarantee that a \
                 typo in a quirk profile is a BUILD error, not a production 400: {e}"
            )
        });
        manifest_entries.push((parsed.id.clone(), path.canonicalize().unwrap()));
    }

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let manifest_path = Path::new(&out_dir).join("profiles_manifest.rs");
    let manifest_src = manifest_entries
        .iter()
        .map(|(id, path)| format!("    ({:?}, include_str!({:?})),\n", id, path))
        .collect::<String>();
    std::fs::write(
        &manifest_path,
        format!("pub static PROFILE_SOURCES: &[(&str, &str)] = &[\n{manifest_src}];\n"),
    )
    .unwrap();
}
