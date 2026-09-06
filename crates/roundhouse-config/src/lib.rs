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
pub mod network;
pub mod policy;
mod scope;
mod secret_ref;

pub use loader::{default_layers, ConfigError, ConfigLoader, LoadedConfig};
// Fix round 1, MUST 5 (as corrected by fix round 2, MUST 4):
// `load_network_config_from_layers` (the raw, caller-labeled function
// CF-11(b) exists to keep out of easy reach) is not re-exported here — only
// the safe, project-root-taking `load_network_config` is. Fix round 1 had
// stopped at that plus `#[doc(hidden)]` on the function itself, which the
// fix round 2 review proved does not restrict access at all (documentation
// only — the item stays fully callable via its full path from any crate,
// and `tests/network_policy_config.rs` compiling and calling it was the
// proof). The function is now `pub(crate)` in `network.rs`, so it is no
// longer reachable from outside this crate by ANY path, qualified or not;
// its former external test file was folded into `network.rs`'s own
// `#[cfg(test)]` module and removed.
pub use network::{load_network_config, NetworkConfig, NetworkConfigError};
pub use policy::{
    load_policy_files, load_policy_files_from_layers, PolicyFile, PolicyLayer, PolicyRule,
    PolicyRuleOutcome,
};
pub use scope::ConfigScope;
pub use secret_ref::SecretRef;
