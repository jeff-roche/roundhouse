//! Roundhouse-local helpers built on top of the pinned SDK's `acp-v2`
//! (`unstable_protocol_v2`) surface. Gated behind this crate's `acp-v2`
//! feature at the `lib.rs` level — see [`v2`] for the two load-bearing v2
//! details this module carries (`MaybeUndefined` and open-enum
//! round-tripping).

pub mod v2;
