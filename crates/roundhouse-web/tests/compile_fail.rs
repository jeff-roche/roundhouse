//! A `trybuild` compile-fail case pinning that [`roundhouse_web::BoundedStore`]
//! puts the `deadpool` pool out of reach **of code outside this crate**.
//!
//! # What this case's population actually is, stated because it was overstated
//!
//! `trybuild` compiles each case as its **own crate**, linking `roundhouse-web`
//! as a dependency. So the direction it tests is out-of-crate: a
//! `roundhouse-daemon` (or anything else that builds an `AppState` by struct
//! literal) cannot reach the pool through the `pub` `store` field.
//!
//! That is a real property and worth a test — an earlier `AppState` carried a
//! `pub store: Option<StorePool>` whose `pool` field is `pub`, so this file's
//! case compiled and a connection taken that way was held outside
//! `ApiPoolPermits`, which is ruling P93 §B's writer starvation.
//!
//! **It is not, and cannot be, the intra-crate pin**, which is the population
//! rulings P96 §C and P98 are about: a private field is readable from its
//! defining module *and its descendants*, and no external-crate harness can
//! observe where inside `roundhouse-web` the defining module sits. `tests/
//! bounded_reach.rs` is the test for that direction, and it works differently
//! for exactly this reason.
//!
//! **Nor does this case fail if an `fn pool(&self)` accessor is added.** An
//! earlier version of this file claimed it did. It does not: adding an accessor
//! leaves the `inner` field private, so the case below still fails with the same
//! `E0616` and still passes. Nothing in this crate's suite catches that
//! regression, and saying so is better than a claim that gives a reviewer a
//! reason not to look (ruling P98).
//!
//! Same driver-file + `tests/ui/` layout as
//! `crates/roundhouse-net/tests/compile_fail.rs` and
//! `crates/roundhouse-secrets/tests/compile_fail.rs`, and for the same reason
//! the first of those states: an owned, freely-constructible capability value
//! does not work as a type-level guarantee.

/// Ruling P96 §C. `AppState::store` is and must stay `pub` — a future
/// `roundhouse-daemon` builds the state by struct literal — so the reach is
/// closed for an out-of-crate caller by the field's *type* rather than by its
/// visibility.
#[test]
fn code_outside_this_crate_cannot_reach_the_pool_around_the_permit() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/bounded_store_pool_is_unreachable.rs");
}
