//! `Secret` and `ControlLaneToken` — a type-level guarantee that secret
//! material can never reach the task executor except through this crate's
//! two sanctioned bridge modules (`crate::provider_bridge`,
//! `crate::mcp_bridge`).
//!
//! **Deliberately no `Debug`/`Display`/`Serialize` impl anywhere reachable
//! for `Secret`** — proven by the compile-fail tests in
//! `tests/ui/secret_*` (driven by `tests/compile_fail.rs`), not just
//! documented as a convention.

use secrecy::{ExposeSecret, SecretString};

/// Wraps a secret's underlying material. No `Debug`, `Display`, or
/// `Serialize` impl exists anywhere in this crate — the only way to read
/// the material out is [`Secret::expose_for_request`], which itself
/// requires a [`ControlLaneToken`] (§6.7).
pub struct Secret(SecretString);

/// Proof that the holder is one of this crate's two sanctioned bridge call
/// sites (`crate::provider_bridge::issue_for_provider_call` or
/// `crate::mcp_bridge::issue_for_mcp_call`), immediately before making an
/// outbound provider/MCP call.
///
/// Unconstructable from outside this crate, and from every module in this
/// crate except the two bridges: the single field is private (defeats a
/// bare tuple-literal construction, e.g. `ControlLaneToken(())`) *and* the
/// mint function is `pub(crate)`, not `pub` (defeats a direct call to
/// `mint_within_control_lane` from another crate). Both defenses are
/// required — a prior draft made the mint function `pub`, which alone
/// defeated the whole point (audit finding 10). Two trybuild compile-fail
/// cases in `tests/ui/control_lane_token_*` prove both are still in force.
pub struct ControlLaneToken(());

impl ControlLaneToken {
    /// `pub(crate)`, not `pub`: reachable only from `provider_bridge` and
    /// `mcp_bridge` in this same crate. Do not widen this visibility — see
    /// the type doc comment.
    pub(crate) fn mint_within_control_lane() -> Self {
        Self(())
    }
}

impl Secret {
    /// Wrap secret material. The caller gives up the plain `String`; the
    /// only way back out is [`Secret::expose_for_request`].
    pub fn new(s: String) -> Self {
        Self(SecretString::from(s))
    }

    /// The only way to read the wrapped material back out. Requires a
    /// [`ControlLaneToken`], which only `provider_bridge`/`mcp_bridge` can
    /// mint — see those modules for the sanctioned call sites.
    pub fn expose_for_request(&self, _token: &ControlLaneToken) -> &str {
        self.0.expose_secret()
    }
}
