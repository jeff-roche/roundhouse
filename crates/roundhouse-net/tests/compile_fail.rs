//! trybuild compile-fail cases proving, at compile time (not by convention), that
//! `ProxyHandle` is not a freely-constructible value that any crate can forge or
//! mutate to bypass `LoopbackProxy`'s allowlist/metadata-IP enforcement.
//!
//! Security-review finding (fix-round-1): `ProxyHandle`'s fields used to be `pub`,
//! which made the "only constructor is `HttpTaskExecutor::via_proxy`" guarantee
//! fake — reproduced two ways: (1) constructing `ProxyHandle { token, addr }`
//! directly from an external crate, pointed at a rogue address; (2) mutating
//! `.addr` on a legitimately registered handle after the fact. Both cases below
//! are now real compile errors, following the same driver-file + `tests/ui/`
//! layout as `crates/roundhouse-secrets/tests/compile_fail.rs` (the precedent this
//! task cites for why an owned, freely-constructible capability value doesn't work
//! as a type-level guarantee).

#[test]
fn proxy_handle_cannot_be_constructed_directly_from_outside_this_crate() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/proxy_handle_cannot_be_constructed_directly.rs");
}

#[test]
fn proxy_handle_addr_cannot_be_mutated_from_outside_this_crate() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/proxy_handle_addr_cannot_be_mutated.rs");
}
