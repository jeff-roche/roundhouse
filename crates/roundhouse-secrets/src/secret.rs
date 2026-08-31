//! `Secret` — a type-level guarantee that secret material can never reach
//! the task executor except through this crate's two sanctioned bridge
//! modules (`crate::provider_bridge`, `crate::mcp_bridge`), and even then
//! only for the duration of a caller-supplied closure — never as a
//! free-standing, storable value.
//!
//! **Deliberately no `Debug`/`Display`/`Serialize` impl anywhere reachable
//! for `Secret`** — proven by the compile-fail tests in
//! `tests/ui/secret_*` (driven by `tests/compile_fail.rs`), not just
//! documented as a convention.
//!
//! ## Design history: why there is no `ControlLaneToken`
//!
//! An earlier draft of this module gated exposure behind a
//! `ControlLaneToken` capability type, minted by a `pub(crate)` constructor
//! reachable only from the two bridge modules, on the theory that an
//! unconstructable token proves exposure only happens from a sanctioned
//! call site. That reasoning had a hole: the bridge modules' own `pub`
//! wrapper functions (e.g. `provider_bridge::issue_for_provider_call`)
//! handed back an *owned* token to any external caller — and an owned
//! value can be stashed in a struct, moved anywhere, and reused
//! indefinitely, exactly like the `&str` it was meant to gate. A
//! standalone external crate could call the sanctioned entry point once,
//! keep the token, and expose the secret's material at an arbitrary later
//! time, arbitrarily many times — the "obtained immediately before use"
//! invariant existed only in prose, not in the type system. It was also a
//! zero-sized type, forgeable via `transmute` by anything permitted
//! `unsafe` (this workspace has exactly one such crate, but the type
//! itself didn't know that or defend against it).
//!
//! The fix: no capability object is ever handed out as a free value at
//! all. [`Secret::expose_within_control_lane`] is `pub(crate)` — callable
//! only from code inside `roundhouse-secrets` itself — and takes a
//! caller-supplied closure, invoking it with the exposed `&str` and
//! returning only whatever the closure computes. The two bridge modules
//! are the only public surface that can reach it. Nothing in this shape
//! can be stashed, cloned, or reused later: the exposed material only
//! exists on the stack for the duration of one function call.

use secrecy::{ExposeSecret, SecretString};

/// Wraps a secret's underlying material. No `Debug`, `Display`, or
/// `Serialize` impl exists anywhere in this crate. The only way to read
/// the material out is [`Secret::expose_within_control_lane`] — `pub(crate)`,
/// so reachable only via this crate's two bridge modules
/// (`crate::provider_bridge`, `crate::mcp_bridge`) — and even then only
/// inside a caller-supplied closure, never as a returned free-standing
/// value. See the module doc comment for why this shape replaced an
/// earlier, defeatable `ControlLaneToken` design.
pub struct Secret(SecretString);

impl Secret {
    /// Wrap secret material. The caller gives up the plain `String`; the
    /// only way back out is through a bridge module's closure-scoped
    /// exposure function.
    pub fn new(s: String) -> Self {
        Self(SecretString::from(s))
    }

    /// The only way to read the wrapped material back out — and only from
    /// within this crate. Invokes `f` with the exposed `&str` and returns
    /// whatever `f` computes; the exposed material itself is never
    /// returned as a free-standing value.
    ///
    /// **Do not widen this function's visibility beyond `pub(crate)`.**
    /// Doing so reopens exactly the hole the module doc comment describes:
    /// any caller that can reach this function directly (rather than
    /// through `provider_bridge`/`mcp_bridge`'s closure-taking wrappers)
    /// could call it with a closure that copies the `&str` into an owned
    /// `String` and returns that — defeating the entire scoping guarantee
    /// as surely as the old `ControlLaneToken` did. The two bridge modules
    /// are the only sanctioned callers, and they must never do that
    /// themselves either (see their doc comments).
    pub(crate) fn expose_within_control_lane<R>(&self, f: impl FnOnce(&str) -> R) -> R {
        f(self.0.expose_secret())
    }
}
