use roundhouse_net::enforcement::{net_enforced_for, NetworkMechanism};

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
