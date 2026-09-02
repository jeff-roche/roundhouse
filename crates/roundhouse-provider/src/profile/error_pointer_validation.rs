//! Round-8 review, M2: validates a profile's `error_pointer` (the RFC 6901
//! JSON pointer `crate::errors::classify` walks to find this vendor's
//! machine-readable error code — see `schema.rs`'s `ProviderProfile::
//! error_pointer` doc comment for why this field exists at all) is a
//! well-formed pointer at BUILD time, not a silent no-op at request-error
//! time. The same "typo in a quirk profile is a BUILD error" guarantee
//! `reasoning_field_validation::validate_openai_chat_reasoning_field`
//! already gives `[[model]].reasoning.field`.
//!
//! Deliberately dependency-free (only `std::path::Path` and `&str`) so
//! `build.rs` can `#[path]`-mount this exact file — a build script cannot
//! depend on the crate it builds (see `build.rs`'s own module doc comment)
//! — while the real crate calls the SAME function through its normal `pub`
//! surface. One implementation, not two kept in sync by hand.

use std::path::Path;

/// Panics — a BUILD error when called from `build.rs`'s `main` — if
/// `pointer` is not a syntactically well-formed, non-trivial RFC 6901 JSON
/// pointer: it must start with `/` (the empty string, meaning "the whole
/// document", can never resolve to a `&str` code and is never what a
/// profile author means) and must not contain an empty segment (`//`, or a
/// trailing `/`), which can never address a real JSON object key either.
///
/// This does not — and cannot — verify the pointer actually resolves
/// against any real vendor body; that is what `tests/profile_errors_wiring_*`
/// (feeding a realistic error body through `classify()`) proves per profile.
/// This check only catches the class of typo `deny_unknown_fields` and
/// `value_type` already catch for their own fields: a malformed pointer that
/// would silently never match anything, ever, for any body.
pub fn validate_error_pointer(profile_path: &Path, pointer: &str) {
    let Some(stripped) = pointer.strip_prefix('/') else {
        panic!(
            "profile {profile_path:?} declares error_pointer {pointer:?} that is not a valid \
             JSON pointer (must start with '/') — this is the §9.5 guarantee that a typo in a \
             quirk profile is a BUILD error, not a silently-inert error table"
        );
    };
    if stripped.is_empty() || stripped.split('/').any(|segment| segment.is_empty()) {
        panic!(
            "profile {profile_path:?} declares error_pointer {pointer:?} with an empty path \
             segment (or no segment at all) — this can never address a real JSON object key, \
             so the profile's [errors] table would silently never match any body. This is the \
             §9.5 guarantee that a typo in a quirk profile is a BUILD error, not a \
             silently-inert error table"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::validate_error_pointer;
    use std::path::Path;

    fn p() -> &'static Path {
        Path::new("profiles/test-fixture.toml")
    }

    #[test]
    fn accepts_the_default_openai_shape_pointer() {
        validate_error_pointer(p(), "/error/type");
    }

    #[test]
    fn accepts_a_flat_top_level_pointer() {
        validate_error_pointer(p(), "/type");
    }

    #[test]
    fn accepts_a_nested_code_pointer() {
        validate_error_pointer(p(), "/error/code");
    }

    #[test]
    #[should_panic(expected = "not a valid JSON pointer")]
    fn rejects_a_pointer_missing_the_leading_slash() {
        validate_error_pointer(p(), "error/type");
    }

    #[test]
    #[should_panic(expected = "empty path segment")]
    fn rejects_the_bare_root_pointer() {
        validate_error_pointer(p(), "/");
    }

    #[test]
    #[should_panic(expected = "empty path segment")]
    fn rejects_a_pointer_with_a_double_slash() {
        validate_error_pointer(p(), "/error//type");
    }

    #[test]
    #[should_panic(expected = "empty path segment")]
    fn rejects_a_pointer_with_a_trailing_slash() {
        validate_error_pointer(p(), "/error/");
    }
}
