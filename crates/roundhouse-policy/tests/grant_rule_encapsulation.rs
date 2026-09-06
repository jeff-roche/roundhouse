//! Task 23 (W4): `Grant.rule` was `pub`, so `into_rule_for_installation`'s
//! loud `Once`/`Session`-scope error was trivially bypassed by reading
//! `.rule` directly. Proven at compile time, not by convention, following
//! the same driver-file + `tests/ui/` layout as
//! `crates/roundhouse-net/tests/compile_fail.rs` (which cites
//! `crates/roundhouse-secrets/tests/compile_fail.rs` as its own precedent).

#[test]
fn grant_rule_is_not_publicly_readable() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/grant_rule_direct_read.rs");
}
