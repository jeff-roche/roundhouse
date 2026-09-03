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
        pub error_pointer: String,
    }
}

// Fix round 3, Q2/Q4: `openai_chat::encode::set_json_pointer` walks a
// matched model's `ReasoningControl.field` as a real RFC 6901 JSON pointer
// and writes the resolved reasoning value there. A `field` whose first path
// segment names one of `encode_openai_chat`'s own top-level wire keys would
// silently CLOBBER that key instead of adding a new one (a code-reviewer
// harness confirmed `/model`, `/stream`, and `/messages/0` all do exactly
// this against the fix-round-2 implementation) — exactly the class of "a
// typo in a quirk profile" §9.5 promises turns into a BUILD error, not a
// production data-corruption bug. Kept dependency-free (only
// `std::path::Path`/`&str`) so it can be `#[path]`-mounted here (a build
// script cannot depend on the crate it builds) while the REAL crate calls
// the identical function through its normal `pub` surface — see the
// module's own doc comment for why this isn't a third hand-mirrored copy
// like `schema.rs`/`reasoning.rs` above.
#[path = "src/codec/openai_chat/reasoning_field_validation.rs"]
mod reasoning_field_validation;

// Round-8 review, M2: validates every profile's `error_pointer` is a
// well-formed RFC 6901 pointer at build time. Dependency-free, mounted the
// same way as `reasoning_field_validation` above (a build script cannot
// depend on the crate it builds), so the real crate calls the identical
// function through `profile::validate_error_pointer`.
#[path = "src/profile/error_pointer_validation.rs"]
mod error_pointer_validation;

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
        error_pointer_validation::validate_error_pointer(&path, &parsed.error_pointer);

        for model in &parsed.model {
            if let Some(control) = &model.reasoning {
                // Fix round 7, K6: `value_type` is part of `ReasoningControl`'s
                // own schema, not an `openai-chat`-specific concept, so this
                // runs for every codec's profile -- a profile declaring
                // `value_type = "bool"` against a non-boolean vocabulary/map
                // entry must fail the build regardless of which codec reads
                // it (§9.5: "a wrong type must be a BUILD error, not a
                // runtime surprise").
                control.validate_value_type().unwrap_or_else(|e| {
                    panic!(
                        "profile {path:?} declares a [[model]].reasoning control whose \
                         value_type is inconsistent with its vocabulary/map — this is the §9.5 \
                         guarantee that a typo in a quirk profile is a BUILD error, not a \
                         production 400: {e}"
                    )
                });
                if parsed.codec == "openai-chat" {
                    reasoning_field_validation::validate_openai_chat_reasoning_field(
                        &path,
                        &control.field,
                    );
                } else if parsed.codec == "google-genai" {
                    // Fix round 3, Fix 2 (inverted from the prior blanket
                    // exemption -- see REALITY-CORRECTIONS §15 and the fix
                    // brief for why a `kind == Budget` gate here, unlike a
                    // gate on the panic below, is accurate): `google_genai`'s
                    // `encode_generate_content` calls `resolve_wire_value`
                    // for whichever `ReasoningControl` matches a model,
                    // regardless of `kind`, so this codec CAN legitimately
                    // declare any `value_type` (that's why the panic below
                    // no longer applies to it at all). But a Budget-kind
                    // control's wire field (`thinkingBudget`) is documented
                    // by the vendor schema as a JSON *number*, not a
                    // string -- that is a fact about THIS field, not about
                    // what the encoder generically consumes. A profile that
                    // declares (or, via `#[serde(default)]`, silently
                    // defaults to) `value_type = "string"` for a
                    // Budget-kind control builds clean today and then
                    // `resolve_wire_value` emits a quoted string
                    // (`"8192"`) where the API expects an integer -- the
                    // exact accept-but-ignore fail-open shape Task 17
                    // existed to remove, reintroduced one profile later
                    // (demonstrated reachable by
                    // `tests/google_genai_thinking_budget_type_test.rs`'s
                    // `a_string_typed_control_genuinely_serializes_the_budget_as_a_quoted_string`).
                    if control.google_genai_budget_kind_has_an_invalid_string_value_type() {
                        panic!(
                            "profile {path:?} declares a [[model]].reasoning control of kind = \
                             \"budget\" but value_type is (or defaults to) \"string\" -- \
                             google-genai's Budget-kind wire field (thinkingBudget) is \
                             documented as a JSON number, and encode_generate_content routes it \
                             through resolve_wire_value, so a String value_type here builds \
                             clean and then silently emits a quoted string instead of a number. \
                             Declare value_type = \"number\" (or \"bool\", if a future \
                             Budget-kind field's wire type is genuinely boolean). This is the \
                             §9.5 guarantee that a typo in a quirk profile is a BUILD error, not \
                             a silent runtime gap"
                        );
                    }
                } else if control.value_type != reasoning::ReasoningValueType::String {
                    // Round-8 review, M3, updated by Task 17 (Ruling P108):
                    // `openai_chat::encode`'s `encode_openai_chat` calls
                    // `resolve_wire_value` (the `WireValue`-typed path).
                    // `cohere_v2` and `openai_responses` still call the
                    // untyped `resolve()`, so a `value_type` other than the
                    // default `String` on either of their profiles would
                    // build clean and then be silently ignored at
                    // request-encode time — exactly the "typo in a quirk
                    // profile" §9.5 promises turns into a BUILD error, not a
                    // silent runtime gap.
                    panic!(
                        "profile {path:?} declares a [[model]].reasoning value_type of \
                         {:?}, but its codec ({:?}) does not consume typed WireValue — only \
                         openai-chat's and google-genai's encoders call resolve_wire_value; \
                         cohere-v2 and openai-responses still call the untyped resolve(), so a \
                         non-String value_type here would build clean and then be silently \
                         ignored. This is the §9.5 guarantee that a typo in a quirk profile is \
                         a BUILD error, not a silent runtime gap",
                        control.value_type, parsed.codec
                    );
                }
            }
        }
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
