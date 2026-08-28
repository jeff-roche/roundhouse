// NOTE: unsafe_code is `deny`, not `forbid`, at the crate level — see Cargo.toml.
// The only module permitted to use it is `enforce::unsafe_ops`, which re-enables
// it locally with `#[allow(unsafe_code)]` on that module alone (Phase 2 work).
#![deny(unsafe_code)]
