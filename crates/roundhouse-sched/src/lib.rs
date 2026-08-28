#![forbid(unsafe_code)]

pub fn schema_version_floor() -> u16 {
    // S-CFG-1 (§12.7): layered config's schema-version floor lives here in
    // Phase 0 only as a named constant downstream crates can already
    // depend on; the real layered-config resolution is Phase 5 work.
    1
}
