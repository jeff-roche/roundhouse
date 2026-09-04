//! Fix round 1, E2: `build.rs` cannot depend on its own crate (a build
//! script cannot depend on the crate it builds), so it hand-mirrors two real
//! types — `ir::ReasoningIntent` (as its own `ir::ReasoningIntent`) and
//! `errors::{ErrorProfile, ProviderErrorKind}` (as its own `errors` module)
//! — kept in sync manually. That mirroring is a deliberate, accepted design
//! choice (see `build.rs`'s own doc comments); this file is NOT about
//! restructuring it.
//!
//! What it does not have, on its own, is anything that catches drift: if a
//! future task adds a variant to the REAL `ReasoningIntent` or
//! `ProviderErrorKind` and forgets to add the matching variant to
//! `build.rs`'s mirror, `build.rs` keeps compiling against its now-stale
//! mirror and nothing complains.
//!
//! These two exhaustive `match`es (deliberately no `_` arm) turn that silent
//! drift into a loud one: the moment either real enum gains a variant, this
//! file fails to compile with a "non-exhaustive patterns" error, pointing
//! whoever added the variant here — and from here, to `build.rs`'s mirror,
//! which needs the identical addition.

use roundhouse_provider::errors::ProviderErrorKind;
use roundhouse_provider::profile::Intent;

#[test]
fn provider_error_kind_variant_set_is_exhaustively_enumerated_here() {
    fn assert_exhaustive(kind: ProviderErrorKind) {
        // Adding a variant to the real `ProviderErrorKind` (src/errors.rs)
        // without adding it here — and to build.rs's `mod errors` mirror —
        // is a compile error, not a silent gap.
        match kind {
            ProviderErrorKind::Overloaded => {}
            ProviderErrorKind::RateLimited => {}
            ProviderErrorKind::QuotaExhausted => {}
            ProviderErrorKind::ModelNotFound => {}
        }
    }
    assert_exhaustive(ProviderErrorKind::Overloaded);
    assert_exhaustive(ProviderErrorKind::RateLimited);
    assert_exhaustive(ProviderErrorKind::QuotaExhausted);
    assert_exhaustive(ProviderErrorKind::ModelNotFound);
}

#[test]
fn reasoning_intent_variant_set_is_exhaustively_enumerated_here() {
    fn assert_exhaustive(intent: Intent) {
        // Adding a variant to the real `ir::ReasoningIntent` (src/ir.rs,
        // re-exported here as `profile::Intent`) without adding it here —
        // and to build.rs's `mod ir` mirror — is a compile error, not a
        // silent gap.
        match intent {
            Intent::Off => {}
            Intent::Low => {}
            Intent::Medium => {}
            Intent::High => {}
            Intent::Max => {}
        }
    }
    assert_exhaustive(Intent::Off);
    assert_exhaustive(Intent::Low);
    assert_exhaustive(Intent::Medium);
    assert_exhaustive(Intent::High);
    assert_exhaustive(Intent::Max);
}
