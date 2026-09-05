//! The `CredentialProvider` trait vocabulary (§9.9).
//!
//! This module defines only the trait and its supporting types — no secret
//! material, no `secrecy` dependency, no `ResolvedCredential` enum carrying
//! tokens across a crate boundary. `apply()` mutates an outbound
//! `HttpRequest` in place and never returns secret material to its caller;
//! that is the entire point of this shape.
//!
//! The six concrete, secret-holding implementations (`BearerCredential`,
//! `HeaderKeyCredential`, `OAuthRefreshCredential`, `AzureEntraCredential`,
//! `ExecCommandCredential`, `SigV4Credential`) live in **`roundhouse-secrets`**
//! (`crates/roundhouse-secrets/src/credential/`), not here — three reasons,
//! all load-bearing:
//!
//! 1. The `secrecy` crate's `Secret<T>` does not exist in the pinned
//!    `secrecy` version 0.10.3;
//!    Phase 2 already shipped the real hardened primitive
//!    (`roundhouse_secrets::secret::Secret`), and it is stronger than
//!    anything this phase would build from scratch (see its module doc
//!    comment).
//! 2. The frozen crate table
//!    (`docs/architecture/02-system-architecture.md` §5.2) assigns
//!    "`CredentialProvider` implementations (§9.9)" to `roundhouse-secrets`.
//! 3. `roundhouse-provider` cannot take `roundhouse-secrets` as a normal
//!    dependency: `roundhouse-secrets -> roundhouse-store -> roundhouse-provider`
//!    already exists, so that edge would be a Cargo cycle.
//!
//! `roundhouse-provider` takes `roundhouse-secrets` back only as a
//! `[dev-dependencies]` entry, so this crate's own tests can construct real
//! credentials — legal in Cargo because dev-dependency edges are excluded
//! from the normal build graph.

mod base_url;
mod host_only;

pub use base_url::resolve_base_url;
pub use host_only::record_base_url_override;

use crate::provider_trait::BoxFut;
use crate::transport::{HttpRequest, HttpTransport, TransportError};

/// Context passed to `CredentialProvider::apply`.
pub struct CredentialCtx<'a> {
    pub provider_id: &'a str,
    pub transport: &'a dyn HttpTransport,
    /// The clock a credential uses for token-expiry decisions (skew checks
    /// against a cached token's `expires_at`). **Strictly per-request**:
    /// build a fresh `CredentialCtx` (and read `Instant::now()` into this
    /// field) immediately before each `apply` call. A `CredentialCtx` built
    /// once and reused across many requests — e.g. one per session instead
    /// of one per request — makes a cached token's expiry check compare
    /// against a clock that never advances, so a credential like
    /// `OAuthRefreshCredential` would treat its cached token as eternally
    /// fresh no matter how much real wall-clock time has actually passed.
    pub now: std::time::Instant,
}

#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error(
        "no credential material found for provider `{0}` (checked keyring, env, profile default)"
    )]
    NotFound(String),
    #[error("oauth refresh failed: {0}")]
    RefreshFailed(String),
    #[error("exec-command credential helper exited non-zero (status {0:?}): {1}")]
    ExecFailed(Option<i32>, String),
    #[error("sigv4 signing precondition failed: {0}")]
    SigningFailed(String),
    #[error("transport error while resolving credential: {0}")]
    Transport(#[from] TransportError),
    #[error("invalid base URL: {0}")]
    InvalidBaseUrl(String),
    /// Phase 7 Task 16, Ruling R9 (scheme allowlist per fix round 1, Ruling
    /// R24): an operator-supplied (explicit override or
    /// `ROUNDHOUSE_<PROVIDER>_BASE_URL` env var) base URL used a scheme
    /// other than `https`, or a non-loopback `http://`, without opting in
    /// via `allow_insecure` or the sibling
    /// `ROUNDHOUSE_<PROVIDER>_ALLOW_INSECURE_BASE_URL` env var (fix round 1,
    /// Ruling R23). See `base_url::resolve_base_url`'s doc comment for the
    /// full policy.
    #[error("insecure base URL: {0}")]
    InsecureBaseUrl(String),
}

/// Applies this credential to an outbound request IN PLACE. Implementations
/// that hold secret material live in `roundhouse-secrets` (see the module
/// doc comment above); this trait never returns secret material to the
/// caller — the whole point of the shape.
///
/// No `Provider` implementation anywhere in this phase matches on which
/// concrete `CredentialProvider` it was given: every provider adapter calls
/// `ctx.credentials.apply(&mut req, &cred_ctx)` exactly once and gets
/// bearer, header-key, OAuth, Entra, exec-command, or SigV4 handling alike.
///
/// **Idempotency contract:** `apply` may be called more than once on the
/// same `HttpRequest` — retrying a request (`crate::retry`) re-applies the
/// same credential to the same request object rather than building a fresh
/// one. Implementations MUST make repeat application safe: at minimum, this
/// means removing any header(s) a previous `apply` call on this credential
/// set before setting them again, so retried requests never accumulate
/// duplicate `Authorization`/custom-header values (and, for SigV4
/// specifically, so a stale `authorization`/`x-amz-*` header from a prior
/// signing pass never folds into the next canonical-request hash).
pub trait CredentialProvider: Send + Sync + 'static {
    fn apply<'a>(
        &'a self,
        req: &'a mut HttpRequest,
        ctx: &'a CredentialCtx<'a>,
    ) -> BoxFut<'a, Result<(), CredentialError>>;
}
