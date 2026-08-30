//! Secret material handling, split out of `roundhouse-config` (which only
//! ever holds `SecretRef` pointers) per the architecture's crate table
//! (§5.2). Two things live here:
//!
//! - [`secret::Secret`]: wraps secret material with no reachable
//!   `Debug`/`Display`/`Serialize` impl. The only way to read the material
//!   back out is [`secret::Secret::expose_within_control_lane`] — `pub(crate)`,
//!   reachable only via this module's two bridge modules ([`provider_bridge`],
//!   [`mcp_bridge`]), and only for the duration of a caller-supplied closure,
//!   never as a returned free-standing value. See `secret.rs`'s module doc
//!   comment for the full history of why this replaced an earlier
//!   `ControlLaneToken` capability-object design that a security review
//!   found could be defeated with no `unsafe` code at all (fixes audit
//!   finding 10, corrected).
//! - [`resolve::resolve_secret`]: keyring-first, 0600-file-fallback
//!   resolution, recording the fallback as a visible startup `Degradation`
//!   event (§6.7).

#![forbid(unsafe_code)]

pub mod resolve;
pub mod secret;

/// The daemon's provider dispatch path calls this immediately before
/// making an outbound request, to obtain the exposed secret material for
/// exactly the duration of `f`. Stands in for "the daemon's provider
/// module" from §6.7 — this crate physically hosts the exposure function
/// for privacy reasons, but this is the module that logically owns the
/// provider call site.
pub mod provider_bridge {
    use crate::secret::Secret;

    /// Invokes `f` with the secret's exposed material and returns whatever
    /// `f` computes. `f` typically builds and sends an outbound HTTP
    /// request and returns its result — it must not stash the `&str` it's
    /// given anywhere that outlives the call (e.g. into a struct field or
    /// a wider-scoped variable), since that would defeat the whole point
    /// of the closure-scoped shape just as surely as the exposure
    /// function's visibility being widened would.
    ///
    /// **Do not add a variant of this function that returns the exposed
    /// `&str` (or an owned `String` derived from it) as a free value
    /// instead of threading it through `f`.** That is exactly the
    /// regression this design exists to prevent — see `secret.rs`'s
    /// module doc comment for the full history.
    pub fn expose_secret_for_provider_call<R>(secret: &Secret, f: impl FnOnce(&str) -> R) -> R {
        secret.expose_within_control_lane(f)
    }
}

/// The daemon's MCP dispatch path calls this immediately before
/// forwarding a tool call that needs a resolved credential (e.g. an MCP
/// server's own API key), to obtain the exposed secret material for
/// exactly the duration of `f`.
pub mod mcp_bridge {
    use crate::secret::Secret;

    /// See [`provider_bridge::expose_secret_for_provider_call`] — same
    /// shape and same warning against ever returning the exposed material
    /// as a free value.
    pub fn expose_secret_for_mcp_call<R>(secret: &Secret, f: impl FnOnce(&str) -> R) -> R {
        secret.expose_within_control_lane(f)
    }
}
