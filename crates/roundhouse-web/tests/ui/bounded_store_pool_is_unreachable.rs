//! The bound in `ApiPoolPermits` is only worth what a handler *cannot* do
//! around it. Before `BoundedStore`, `AppState::store` was a
//! `Option<roundhouse_store::StorePool>` whose `pool` field is `pub`, so this
//! file compiled — and a connection taken this way is held outside the
//! semaphore, which is the starvation ruling P93 §B exists to prevent.

fn main() {
    let state = roundhouse_web::AppState::default();
    let store = state.store.expect("this never runs; the line below must not compile");

    // The pool is private to `roundhouse-web`'s crate root, so
    // `AppState::store_connection` — which pairs it with a permit — is the only
    // way to reach a connection.
    let _pool = store.inner;
}
