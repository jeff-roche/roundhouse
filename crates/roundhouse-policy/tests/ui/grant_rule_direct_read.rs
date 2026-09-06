// Must fail: `Grant.rule` is `pub(crate)`, so it cannot be read from outside
// `roundhouse-policy` — the only sanctioned way to obtain an installable
// `CompiledRule` from a `Grant` is `Grant::into_rule_for_installation`, which
// loudly refuses to hand one back for scopes with no real lifetime
// enforcement (`Once`/`Session`/`ExactArgv`). Reading `.rule` directly
// bypasses that check entirely. This case never runs (the `unimplemented!()`
// is never executed) — trybuild only needs the line below to fail to
// *compile*, following the same style as
// `crates/roundhouse-net/tests/ui/proxy_handle_addr_cannot_be_mutated.rs`.
#[allow(unreachable_code)]
fn main() {
    let grant: roundhouse_policy::approval::Grant = unimplemented!();
    let _ = grant.rule;
}
