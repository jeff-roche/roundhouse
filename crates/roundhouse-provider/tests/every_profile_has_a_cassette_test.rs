//! Audit finding 8 / §9.10's Definition of Done: "CI gates on... 'every
//! profile has ≥1 cassette'" was, until this test, prose only — no task
//! ever wrote a check that actually runs it. This walks both directories
//! and cross-checks by convention (`profiles/{id}.toml` implies a nonempty
//! `testdata/cassettes/{id_with_underscores}/`), so a new profile landing
//! without a cassette in the same PR is caught here rather than at review
//! time.
//!
//! This test is expected to fail until every profile task in this plan
//! (Tasks 4-17) has landed its cassette directory — see
//! `docs/superpowers/plans/2026-08-27-phase6-provider-breadth.md`'s exit
//! criterion. As of Task 3, `crates/roundhouse-provider/profiles/` does not
//! exist yet at all (Task 4 creates it), so this fails loudly for that
//! reason rather than a per-profile mismatch — both are honest signals of
//! the same "not done yet" state.

use std::fs;
use std::path::Path;

#[test]
fn every_profile_toml_has_at_least_one_cassette() {
    let profiles_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("profiles");
    let cassettes_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/cassettes");

    let mut missing = Vec::new();
    for entry in fs::read_dir(&profiles_dir).expect("profiles/ must exist") {
        let entry = entry.expect("readable profiles/ entry");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        let cassette_dir = cassettes_root.join(id.replace('-', "_"));
        let has_cassette = cassette_dir.is_dir()
            && fs::read_dir(&cassette_dir)
                .map(|mut it| it.next().is_some())
                .unwrap_or(false);
        if !has_cassette {
            missing.push(id.to_string());
        }
    }

    assert!(
        missing.is_empty(),
        "the following profiles have zero cassettes under testdata/cassettes/<id>/ — \
         §9.10's Definition of Done requires ≥1 per profile: {missing:?}"
    );
}
