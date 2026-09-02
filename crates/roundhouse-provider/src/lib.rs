//! The `Provider` trait, its adapters, and the capability registry: the
//! narrow-waist IR (`ChatRequest`/`ContentBlock`/`ToolDef`, §9.3) every
//! model provider is translated into and out of, so the rest of the system
//! never speaks a provider-specific wire format.
//!
//! Phase 0 ships the `Provider` trait signature and the IR types
//! (including `tool_def_from_schema`, S-TOOL-9's one sanctioned way to
//! build a `ToolDef` — its `input_schema` is always `schemars`-generated
//! from a typed Rust struct, never hand-written JSON, and `ToolDef`
//! deliberately doesn't derive `Deserialize` so that guarantee can't be
//! bypassed via `serde_json` either). Phase 1 adds the first real adapter
//! and the first real transport — `AnthropicMessagesProvider` over
//! `ReqwestTransport`, the one sanctioned `reqwest::Client` construction
//! site per §9.10 — and the remaining provider families are Phase 6 work.
//! See `docs/architecture/02-system-architecture.md` §5.2 and
//! `06-provider-abstraction.md`.
#![forbid(unsafe_code)]

mod anthropic_provider;
pub mod audit;
mod cassette;
pub mod codec;
pub mod credential;
pub mod errors;
pub mod fallback;
mod ir;
pub mod pricing;
pub mod profile;
mod provider_trait;
mod reqwest_transport;
pub mod retry;
mod stream_event;
mod transport;

pub use anthropic_provider::AnthropicMessagesProvider;
pub use cassette::{CassetteTransport, ChunkStrategy};
pub use ir::MessageRole as Role; // temporary compat alias: rest of this plan's Track B/C/G task text says Role::User/Role::Assistant; a later phase should update those call sites to MessageRole directly and drop this alias
pub use ir::{
    tool_def_from_schema, CacheBreakpoint, Capabilities, ChatRequest, ChatStream, Citation,
    ContentBlock, IdOrigin, MediaSource, Message, MessageRole, ModelId, ModelInfo, Params, Plan,
    ProviderError, ProviderExt, ProviderId, ReasoningIntent, ReasoningRequest, RequestCtx,
    RequestPolicy, ResponseFormat, ShellToolParams, Signature, SystemBlock, TokenCount, ToolCallId,
    ToolChoice, ToolDef, ToolResultPart,
};
pub use provider_trait::{BoxFut, Provider};
pub use reqwest_transport::ReqwestTransport;
pub use stream_event::{BlockDelta, BlockKind, DeltaKeyer, StreamEvent};
// REALITY-CORRECTIONS §2/§14a: `transport` is a private `mod`, so its public
// submodules aren't externally reachable through it directly — re-export the
// whole submodule here (as `eventstream`'s sibling shim, `azure_deployment_routing`,
// needs to be usable from this crate's external `tests/` crates, unlike
// `eventstream`, which today is only ever reached from `codec::bedrock_converse`,
// a sibling module inside this same crate).
pub use transport::azure_deployment_routing;
pub use transport::{HttpRequest, HttpResponseStream, HttpTransport, TransportError};

// §9.5: build.rs validates every `profiles/*.toml` at compile time and emits
// this manifest of (id, raw source) pairs so `load_profile` can look one up
// by id without re-globbing the filesystem (which would not work once
// installed).
include!(concat!(env!("OUT_DIR"), "/profiles_manifest.rs"));

/// Looks up a build.rs-validated quirk profile by id and parses it. The
/// `.expect` is safe: `build.rs` already proved every file in `profiles/`
/// deserializes, using the same `profile::ProviderProfile` struct.
pub fn load_profile(id: &str) -> Option<profile::ProviderProfile> {
    PROFILE_SOURCES
        .iter()
        .find(|(pid, _)| *pid == id)
        .map(|(_, src)| toml::from_str(src).expect("build.rs already validated this profile"))
}
