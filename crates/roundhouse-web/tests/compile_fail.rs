//! A `trybuild` compile-fail case proving, at compile time rather than by
//! convention, that [`roundhouse_web::BoundedStore`] really does put the
//! `deadpool` pool out of a handler's reach.
//!
//! # Why this test and not a runtime one
//!
//! The property is "this expression does not exist", and no runtime test and no
//! mutation can observe that: there is no code path to exercise, so the whole
//! sweep would score it `EQUIVALENT` while the guarantee quietly lapsed the day
//! someone added an `fn pool(&self)` accessor "just for the daemon". A
//! compile-fail case is the only thing that fails when the reach reopens.
//!
//! Same driver-file + `tests/ui/` layout as
//! `crates/roundhouse-net/tests/compile_fail.rs` and
//! `crates/roundhouse-secrets/tests/compile_fail.rs`, and for the same reason
//! the first of those states: an owned, freely-constructible capability value
//! does not work as a type-level guarantee.

/// Ruling P96 §C. `AppState::store` is and must stay `pub` — a future
/// `roundhouse-daemon` builds the state by struct literal — so the reach is
/// closed by the field's *type* rather than by its visibility.
#[test]
fn a_handler_cannot_reach_the_pool_around_the_permit() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/bounded_store_pool_is_unreachable.rs");
}
