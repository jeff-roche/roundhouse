// Audit finding 8: ONE shared `glob_match`, used identically by every codec's
// encode.rs (Tasks 5-17) instead of each reimplementing its own — a
// hand-rolled per-codec prefix-length slice comparison would be a divergent,
// harder-to-audit reimplementation of exactly this function.

/// Supports a single trailing `*` (the only pattern shape §9.5's examples use,
/// e.g. `"kimi-k3*"`, `"gpt-5*"`) or an exact match with no wildcard at all.
pub fn glob_match(pattern: &str, value: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => value.starts_with(prefix),
        None => pattern == value,
    }
}
