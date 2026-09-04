//! The bound in `ApiPoolPermits` is only worth what a caller *cannot* do around
//! it. Before `BoundedStore`, `AppState::store` was an
//! `Option<roundhouse_store::StorePool>` whose `pool` field is `pub`, so this
//! file compiled — and a connection taken this way is held outside the
//! semaphore, which is the starvation ruling P93 §B exists to prevent.
//!
//! This case is compiled as its own crate, so what it pins is the **out-of-crate**
//! direction. The intra-crate one is `tests/bounded_reach.rs`; see
//! `tests/compile_fail.rs` for why one harness cannot do both.

fn main() {
    let state = roundhouse_web::AppState::default();
    let store = state.store.expect("this never runs; the line below must not compile");

    // The pool is private to `roundhouse-web`'s `bounded` module, so
    // `AppState::store_connection` — which delegates to the one function in that
    // module that unwraps it, and which pairs it with a permit — is the only way
    // to reach a connection.
    let _pool = store.inner;
}
