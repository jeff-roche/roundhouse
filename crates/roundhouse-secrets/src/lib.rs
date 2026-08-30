//! Secret material handling, split out of `roundhouse-config` (which only
//! ever holds `SecretRef` pointers) per the architecture's crate table
//! (§5.2). Two things live here:
//!
//! - [`secret::Secret`]: wraps secret material with no reachable
//!   `Debug`/`Display`/`Serialize` impl.
//! - [`secret::ControlLaneToken`]: a type-level guarantee that
//!   [`secret::Secret::expose_for_request`] can only be called by code that
//!   holds a token minted by one of this crate's two sanctioned bridge
//!   modules ([`provider_bridge`], [`mcp_bridge`]) — see `secret.rs` for
//!   why that's unconstructable anywhere else (audit finding 10).
//! - [`resolve::resolve_secret`]: keyring-first, 0600-file-fallback
//!   resolution, recording the fallback as a visible startup `Degradation`
//!   event (§6.7).

#![forbid(unsafe_code)]

pub mod resolve;
pub mod secret;

/// The daemon's provider dispatch path calls this immediately before
/// making an outbound request and uses the token once. Stands in for "the
/// daemon's provider module" from §6.7 — this crate physically hosts the
/// mint function for privacy reasons, but this is the module that
/// logically owns the provider call site.
pub mod provider_bridge {
    use crate::secret::ControlLaneToken;

    pub fn issue_for_provider_call() -> ControlLaneToken {
        ControlLaneToken::mint_within_control_lane()
    }
}

/// The daemon's MCP dispatch path calls this immediately before
/// forwarding a tool call that needs a resolved credential (e.g. an MCP
/// server's own API key).
pub mod mcp_bridge {
    use crate::secret::ControlLaneToken;

    pub fn issue_for_mcp_call() -> ControlLaneToken {
        ControlLaneToken::mint_within_control_lane()
    }
}
