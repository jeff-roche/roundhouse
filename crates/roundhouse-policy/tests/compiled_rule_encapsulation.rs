//! `CompiledRule` is an installable authority and must be constructible only
//! by the policy crate's compiler/approval paths, never by a downstream crate.

use std::process::Command;

#[test]
fn compiled_rule_is_not_literal_constructible() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/compiled_rule_literal.rs");
}

#[test]
fn production_dependency_cannot_name_test_new() {
    let fixture = tempfile::tempdir().expect("temporary consumer crate");
    let policy = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::write(
        fixture.path().join("Cargo.toml"),
        format!(
            "[package]\nname = \"compiled-rule-production-consumer\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[dependencies]\nroundhouse-policy = {{ path = {:?} }}\n",
            policy
        ),
    )
    .expect("write fixture manifest");
    std::fs::create_dir(fixture.path().join("src")).expect("fixture source directory");
    std::fs::write(
        fixture.path().join("src/main.rs"),
        "fn main() { let _ = roundhouse_policy::CompiledRule::test_new; }\n",
    )
    .expect("write fixture source");

    let output = Command::new("cargo")
        .arg("check")
        .arg("--offline")
        .current_dir(fixture.path())
        .output()
        .expect("cargo must be available");
    assert!(
        !output.status.success(),
        "a normal production dependency must not be able to name CompiledRule::test_new"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("test_new"),
        "failure must be specifically the absent test constructor, got: {stderr}"
    );
}
