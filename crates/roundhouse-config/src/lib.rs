//! Layered config loading (builtin/user/project/workspace scopes, merged
//! narrower-wins per §6.2's precedence ranking) and `SecretRef` — a pointer
//! to where a secret lives (keyring/env/file), never the secret material
//! itself.
//!
//! Unlike most Phase 0 crates, this one is small enough to build for real
//! now rather than stub-and-defer (S-CFG-1, §12.7, is a Phase 0 contract
//! every later phase assumes frozen): `ConfigLoader` is a fully working
//! layered TOML merge. Note the merge is narrower-*wins*, not
//! narrower-*only* — §6.2's stricter rule for `.roundhouse/policy.toml`/
//! `config.toml` (project scope may narrow, never widen, without a
//! recorded trust decision) needs trust-decision infrastructure that
//! doesn't exist yet; see `ConfigScope`'s doc comment. See
//! `docs/architecture/02-system-architecture.md` §5.2 and §6.2.
#![forbid(unsafe_code)]

mod loader;
mod scope;
mod secret_ref;

pub use loader::{default_layers, ConfigError, ConfigLoader, LoadedConfig};
pub use scope::ConfigScope;
pub use secret_ref::SecretRef;
