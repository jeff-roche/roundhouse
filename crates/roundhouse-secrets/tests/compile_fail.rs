//! trybuild compile-fail cases proving, at compile time (not by
//! convention), that:
//! - `Secret` has no `Debug`/`Display`/`Serialize` impl reachable from
//!   outside this crate (§6.7).
//! - `Secret::expose_within_control_lane` cannot be called from outside
//!   this crate — only via `provider_bridge`/`mcp_bridge`'s closure-taking
//!   wrappers (fixes audit finding 10, corrected: see `secret.rs`'s module
//!   doc comment for why the original `ControlLaneToken` capability-object
//!   design was replaced with this closure-scoped shape).
//! - the exposed material handed to a bridge function's closure cannot be
//!   smuggled back out as the bridge function's own return value — this is
//!   a genuine lifetime error, not just a style violation, verified below.
//!
//! Follows the same driver-file + `tests/ui/` layout as
//! `crates/roundhouse-core/tests/compile_fail.rs`.

#[test]
fn secret_has_no_debug_impl() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/secret_format_debug.rs");
}

#[test]
fn secret_has_no_display_impl() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/secret_format_display.rs");
}

#[test]
fn secret_has_no_serialize_impl() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/secret_serde_serialize.rs");
}

#[test]
fn expose_within_control_lane_cannot_be_called_from_outside_this_crate() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/expose_within_control_lane_is_private.rs");
}

#[test]
fn a_bridge_closure_cannot_smuggle_the_exposed_str_out_as_a_return_value() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/bridge_closure_cannot_smuggle_exposed_str.rs");
}
