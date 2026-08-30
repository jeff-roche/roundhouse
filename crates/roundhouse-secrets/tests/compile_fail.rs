//! trybuild compile-fail cases proving, at compile time (not by
//! convention), that:
//! - `Secret` has no `Debug`/`Display`/`Serialize` impl reachable from
//!   outside this crate (§6.7).
//! - `ControlLaneToken` cannot be constructed outside this crate's two
//!   sanctioned bridge modules (audit finding 10).
//!
//! Follows the same driver-file + `tests/ui/` layout as
//! `crates/roundhouse-core/tests/compile_fail.rs`.

#[test]
fn secret_has_no_debug_impl() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/secret_format_debug.rs");
}

#[test]
fn secret_has_no_serialize_impl() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/secret_serde_serialize.rs");
}

#[test]
fn control_lane_token_cannot_be_constructed_via_tuple_literal() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/control_lane_token_tuple_literal.rs");
}

#[test]
fn control_lane_token_cannot_be_constructed_via_direct_mint_call() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/control_lane_token_direct_mint_call.rs");
}
