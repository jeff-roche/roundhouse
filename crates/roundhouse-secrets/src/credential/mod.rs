//! The six concrete `CredentialProvider` implementations (§9.9), per the
//! frozen crate table (`docs/architecture/02-system-architecture.md` §5.2)
//! and Phase 6 Task 2's REALITY-CORRECTIONS §6 ruling: `roundhouse-provider`
//! defines the trait vocabulary only (`CredentialProvider`, `CredentialCtx`,
//! `CredentialError`) and holds no secret material; this module holds every
//! implementation that does, each wrapping [`crate::secret::Secret`] and
//! reading it *only* inside an
//! [`crate::provider_bridge::expose_secret_for_provider_call`] closure.
//!
//! `Secret` is not `Clone` and has no `Debug`/`Display`/`Serialize` impl —
//! see its own module doc comment. Every struct here holds it behind an
//! `Arc` (or, for `OAuthRefreshCredential`/`AzureEntraCredential`, behind a
//! `tokio::sync::Mutex`-guarded cache) and never derives `Debug`.
//!
//! ## Call-site accounting
//!
//! `apply_bearer_secret` (below) is the one physical call site that ever
//! turns a bearer-shaped [`Secret`] into an `Authorization: Bearer <token>`
//! header — shared by [`bearer::BearerCredential`],
//! [`oauth_refresh::OAuthRefreshCredential`] (both the cache-hit and the
//! freshly-refreshed-token paths), and [`exec_command::ExecCommandCredential`]
//! (which wraps its freshly-read stdout in a `Secret` specifically so it can
//! go through this same site rather than ever reading the exposed material
//! itself).
//! [`azure_entra::AzureEntraCredential`] adds zero further sites: it holds an
//! `OAuthRefreshCredential` internally and delegates `apply` to it, since the
//! wire shape after resolution is identical to a static bearer token — Entra
//! only differs in which token endpoint and `scope` request the token in the
//! first place.
//!
//! That leaves the physical exposure call sites in this tree (deliberately
//! not spelled out literally in this sentence, so the ratchet test's own
//! grep count in `tests/credential_test.rs` doesn't count this doc comment)
//! at exactly the number that test pins: `apply_bearer_secret` (1),
//! [`header_key::HeaderKeyCredential::apply`] (1, a distinct header name so
//! it can't reuse `apply_bearer_secret`), `OAuthRefreshCredential`'s
//! refresh-body construction (1, exposes `client_secret` to build the token
//! endpoint's POST body), and [`sigv4::sign`] (2: HMAC key derivation from
//! `secret_key`, and the `x-amz-security-token` header from `session_token`).

mod azure_entra;
mod bearer;
mod exec_command;
mod header_key;
mod oauth_refresh;
pub mod sigv4;

pub use azure_entra::AzureEntraCredential;
pub use bearer::BearerCredential;
pub use exec_command::ExecCommandCredential;
pub use header_key::HeaderKeyCredential;
pub use oauth_refresh::OAuthRefreshCredential;
pub use sigv4::SigV4Credential;

use crate::secret::Secret;
use roundhouse_provider::HttpRequest;

/// The one physical exposure call site for the Bearer wire shape. Writes
/// `Authorization: Bearer <token>` directly into `req` from inside the
/// exposure closure — the closure returns `()`, never a `String` copy of the
/// exposed material — and is reused (as a function call, not a new textual
/// occurrence of that call) by every credential mechanism that resolves to a
/// bearer token. See the module doc comment's "Call-site accounting"
/// section.
///
/// Idempotent per `CredentialProvider::apply`'s documented contract: removes
/// any `authorization` header this same function previously set before
/// pushing the new one, so a repeat `apply` on the same request (the natural
/// shape for a retry) never accumulates duplicate headers.
fn apply_bearer_secret(secret: &Secret, req: &mut HttpRequest) {
    req.headers
        .retain(|(k, _)| !k.eq_ignore_ascii_case("authorization"));
    crate::provider_bridge::expose_secret_for_provider_call(secret, |s| {
        req.headers
            .push(("authorization".to_string(), format!("Bearer {s}")));
    });
}
