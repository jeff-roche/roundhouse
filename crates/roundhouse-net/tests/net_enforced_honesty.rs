// Fix-round-1: `NetworkMechanism`/`net_enforced_for` moved to `roundhouse-core`
// (security-review finding: keeping them in `roundhouse-net` forced
// `roundhouse-sandbox` to depend on this crate's `roundhouse-store` edge just to
// call a pure function). `roundhouse-net` still re-exports both at its crate root,
// so this test — still `roundhouse-net`'s own, per the original task's `Test:`
// list — keeps validating them through that public surface.
use roundhouse_net::{net_enforced_for, NetworkMechanism};

#[test]
fn honesty_table_matches_the_architecture_doc_exactly() {
    // §6.6's table, verbatim: Container/Remote (netns) and Bubblewrap are real;
    // Landlock-only and None/Worktree are not.
    assert!(net_enforced_for(NetworkMechanism::Netns));
    assert!(net_enforced_for(NetworkMechanism::Bubblewrap));
    assert!(
        !net_enforced_for(NetworkMechanism::LandlockPortOnly),
        "Landlock-only can still reach any host on the proxy's port — not real enforcement"
    );
    assert!(!net_enforced_for(NetworkMechanism::None));
}
