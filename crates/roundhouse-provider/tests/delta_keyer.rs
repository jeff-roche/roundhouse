use roundhouse_provider::DeltaKeyer;

#[test]
fn same_native_key_maps_to_same_index_first_seen_order() {
    let mut keyer = DeltaKeyer::new();

    assert_eq!(keyer.index_for("1"), 0); // first tool call, OpenAI index "1"
    assert_eq!(keyer.index_for("0"), 1); // second distinct key seen, OpenAI index "0"
    assert_eq!(keyer.index_for("1"), 0); // repeat of first key: same index
}
