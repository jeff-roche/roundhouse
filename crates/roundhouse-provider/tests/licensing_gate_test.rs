use std::fs;
use std::path::Path;

/// §9.7/§9.11: "a license check runs before Phase 6 starts... if either source
/// turns out unsuitable, the fallback is narrower — vendor only per-provider
/// public pricing pages directly." This test is the gate: Task 9 must not exist
/// until this file states a verdict for both datasets.
#[test]
fn licensing_decision_record_states_a_verdict_for_both_datasets() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/decisions/2026-08-27-dataset-licensing-gate.md");
    let contents = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "licensing gate decision record missing at {path:?}: {e} \
            — Task 1 must produce this before Task 9 (dataset ingestion) may begin"
        )
    });

    let models_dev_line = contents
        .lines()
        .find(|l| l.starts_with("MODELS_DEV_LICENSE:"))
        .expect("decision record must contain a MODELS_DEV_LICENSE: line");
    let litellm_line = contents
        .lines()
        .find(|l| l.starts_with("LITELLM_LICENSE:"))
        .expect("decision record must contain a LITELLM_LICENSE: line");
    let fallback_line = contents
        .lines()
        .find(|l| l.starts_with("FALLBACK_ACTIVE:"))
        .expect("decision record must contain a FALLBACK_ACTIVE: line");

    let models_dev_verdict = models_dev_line
        .trim_start_matches("MODELS_DEV_LICENSE:")
        .trim();
    let litellm_verdict = litellm_line.trim_start_matches("LITELLM_LICENSE:").trim();
    let fallback = fallback_line.trim_start_matches("FALLBACK_ACTIVE:").trim();

    assert!(
        !models_dev_verdict.is_empty() && models_dev_verdict != "TBD",
        "MODELS_DEV_LICENSE must be a real verdict, not a placeholder"
    );
    assert!(
        !litellm_verdict.is_empty() && litellm_verdict != "TBD",
        "LITELLM_LICENSE must be a real verdict, not a placeholder"
    );
    assert!(
        fallback == "true" || fallback == "false",
        "FALLBACK_ACTIVE must be the literal `true` or `false`"
    );

    // The spec's own escalation rule: if fallback is active, Task 9 may not use
    // include_bytes! on either full dataset — only per-provider pricing pages.
    if fallback == "true" {
        assert!(
            contents.contains("## Fallback plan"),
            "fallback_active=true requires a `## Fallback plan` section naming the \
             per-provider pricing pages that replace the vendored datasets"
        );
    }
}
