#[test]
fn event_cannot_be_constructed_outside_roundhouse_core() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/event_literal_construction_fails.rs");
}

#[test]
fn event_cannot_be_deserialized_outside_roundhouse_core() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/event_deserialize_from_outside_fails.rs");
}
