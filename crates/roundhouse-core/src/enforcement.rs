//! §6.6's network-enforcement honesty table, made a real function instead of prose:
//! which mechanism actually achieved isolation determines `Attestation.net_enforced`,
//! never the `Tier` alone — a `Tier::Sandbox` reached via Landlock only (bwrap
//! unavailable) must not report the same `net_enforced` as one reached via a real
//! Bubblewrap netns.
//!
//! Lives in `roundhouse-core` (Task 24 fix-round-1; originally placed in
//! `roundhouse-net`) rather than in `roundhouse-net` or `roundhouse-sandbox`: both of
//! those crates need it (`roundhouse-sandbox`'s `attest()` to compute
//! `net_enforced`, `roundhouse-net` to re-export it for `roundhouse-tools` and other
//! consumers), and both already depend on `roundhouse-core` for the `Tier` type this
//! table maps from. Putting it in `roundhouse-net` instead would have forced
//! `roundhouse-sandbox` — the one crate in this workspace with the smallest,
//! `#![forbid(unsafe_code)]`-audited surface — to pull in `roundhouse-net`'s own
//! `roundhouse-store` dependency (SQLite/`libsqlite3-sys`) just to call a pure,
//! three-branch `matches!`. This module has zero dependencies of its own.

/// Which real isolation mechanism produced a task's current tier. See
/// `docs/architecture/03-security-and-sandboxing.md` §6.6 for the source table this
/// mirrors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMechanism {
    /// Container / Remote tiers: a real network namespace with no default route,
    /// only the proxy reachable.
    Netns,
    /// `--unshare-net` + slirp/pasta, or a bound proxy socket.
    Bubblewrap,
    /// TCP connect restricted by port only — any host on that port is reachable, so
    /// this is not real network enforcement.
    LandlockPortOnly,
    /// Proxy env vars only — a convention a determined process can simply ignore.
    None,
}

/// §6.6's honesty table as one pure, directly-tested function: `Netns` and
/// `Bubblewrap` are real network enforcement; `LandlockPortOnly` and `None` are not.
pub fn net_enforced_for(mechanism: NetworkMechanism) -> bool {
    matches!(
        mechanism,
        NetworkMechanism::Netns | NetworkMechanism::Bubblewrap
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honesty_table_matches_the_architecture_doc_exactly() {
        assert!(net_enforced_for(NetworkMechanism::Netns));
        assert!(net_enforced_for(NetworkMechanism::Bubblewrap));
        assert!(!net_enforced_for(NetworkMechanism::LandlockPortOnly));
        assert!(!net_enforced_for(NetworkMechanism::None));
    }
}
