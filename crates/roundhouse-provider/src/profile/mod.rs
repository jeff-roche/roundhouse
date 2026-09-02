//! §9.5 — TOML quirk profiles: one file per provider under `profiles/`,
//! deserialized both by `build.rs` (a typo is a build error, not a
//! production 400) and at runtime by `crate::load_profile`. See
//! `schema.rs` for the profile shape, `reasoning.rs` for `ReasoningControl`
//! and §9.4's endpoint-preference resolution, and `glob.rs` for the one
//! shared `(provider, model)` glob matcher every codec uses.
mod glob;
mod reasoning;
mod schema;

pub use glob::glob_match;
pub use reasoning::{
    resolve_endpoint_preference, EndpointKind, EndpointPref, EndpointResolution, Intent,
    NoEndpointAvailable, ReasoningControl, ReasoningKind,
};
pub use schema::*;
