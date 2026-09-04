//! Task 18 (B10): the mandatory structured `report` task's core+extension
//! schema, its fingerprint diff, and `carry_over: { last_report: true }`
//! seeding (§8.6 of `05-scheduling-and-workflows.md`).

use roundhouse_flow::report::{
    build_carry_over_seed, diff_findings, validate_report, CarryOver, Cost, Finding, FindingStatus,
    Outcome, Report, Severity,
};
use serde_json::json;

fn finding(id: &str) -> Finding {
    Finding {
        id: id.to_string(),
        title: id.to_string(),
        severity: Severity::Med,
        location: "x".to_string(),
        extra: serde_json::Map::new(),
    }
}

#[test]
fn core_fields_are_required_extension_fields_are_open() {
    let raw = json!({
        "outcome": "changed",
        "severity": "low",
        "headline": "3 flaky tests quarantined",
        "needs_human": false,
        "findings": [
            { "id": "sha256:abc", "title": "flaky test", "severity": "med", "location": "tests/x.rs",
              "pr_number": 4471 }
        ],
        "artifacts": [ { "kind": "diff", "ref": "worktree:abc", "summary": "quarantine 3 tests" } ],
        "next_actions": [ "review quarantine list" ],
        "cost": { "usd": 0.42, "tokens": 118204 },
        "custom_top_level_field": "job-specific, must not error"
    });
    let report = validate_report(&raw).expect("core-valid report parses");
    assert_eq!(report.outcome, Outcome::Changed);
    assert_eq!(report.severity, Severity::Low);
    assert_eq!(report.headline, "3 flaky tests quarantined");
    assert!(!report.needs_human);
    assert_eq!(report.cost.usd, 0.42);
    assert_eq!(report.cost.tokens, 118204);
    assert_eq!(report.findings[0].id, "sha256:abc");
    assert_eq!(report.findings[0].severity, Severity::Med);
    assert_eq!(
        report.findings[0].extra["pr_number"],
        json!(4471),
        "extension field preserved, not dropped"
    );
    assert_eq!(
        report.findings[0].extra.get("title"),
        None,
        "a core finding field is not also duplicated into `extra`"
    );
    assert_eq!(
        report.extra["custom_top_level_field"],
        json!("job-specific, must not error")
    );
    assert_eq!(
        report.extra.get("outcome"),
        None,
        "a core top-level field is not also duplicated into `extra`"
    );
    assert_eq!(report.artifacts[0]["kind"], json!("diff"));
    assert_eq!(report.next_actions, vec!["review quarantine list"]);
}

#[test]
fn missing_a_core_field_is_rejected() {
    let raw = json!({
        "severity": "low", "headline": "x", "needs_human": false,
        "cost": { "usd": 0.0, "tokens": 0 }
    });
    let err = validate_report(&raw).expect_err("outcome is core and required");
    assert_eq!(err.to_string(), "missing required core field: `outcome`");
}

#[test]
fn an_outcome_outside_the_frozen_vocabulary_is_rejected() {
    // §8.6 freezes the set: nothing | changed | findings | failed |
    // needs_human. "ok" is the plausible-looking value a job author reaches
    // for; the inbox's generic sort has no bucket for it.
    let raw = json!({
        "outcome": "ok", "severity": "low", "headline": "x", "needs_human": false,
        "cost": { "usd": 0.0, "tokens": 0 }
    });
    let err = validate_report(&raw).expect_err("`ok` is not one of the five outcomes");
    assert_eq!(err.to_string(), "invalid value for field `outcome`: \"ok\"");

    for good in ["nothing", "changed", "findings", "failed", "needs_human"] {
        let raw = json!({
            "outcome": good, "severity": "high", "headline": "x", "needs_human": true,
            "cost": { "usd": 0.0, "tokens": 0 }
        });
        assert!(
            validate_report(&raw).is_ok(),
            "`{good}` is one of §8.6's five outcomes"
        );
    }
}

#[test]
fn a_finding_missing_a_core_field_is_rejected_and_the_message_names_the_index() {
    let raw = json!({
        "outcome": "findings", "severity": "med", "headline": "x", "needs_human": false,
        "cost": { "usd": 0.0, "tokens": 0 },
        "findings": [
            { "id": "a", "title": "t", "severity": "low", "location": "l" },
            { "id": "b", "title": "t", "severity": "low" }
        ]
    });
    let err = validate_report(&raw).expect_err("`location` is core per finding");
    assert_eq!(
        err.to_string(),
        "findings[1]: missing required core field: `location`"
    );
}

#[test]
fn a_present_but_wrong_typed_collection_is_rejected_rather_than_silently_dropped() {
    // `findings` drives the inbox's whole diff. Treating a non-array as
    // "no findings" would report a run as clean because its report was
    // malformed — the exact failure mode validation exists to prevent.
    let raw = json!({
        "outcome": "findings", "severity": "med", "headline": "x", "needs_human": false,
        "cost": { "usd": 0.0, "tokens": 0 },
        "findings": "three of them"
    });
    let err = validate_report(&raw).expect_err("`findings` must be an array when present");
    assert_eq!(
        err.to_string(),
        "invalid value for field `findings`: \"three of them\""
    );

    let absent = json!({
        "outcome": "nothing", "severity": "low", "headline": "x", "needs_human": false,
        "cost": { "usd": 0.0, "tokens": 0 }
    });
    let report = validate_report(&absent).expect("absent collections are fine");
    assert!(report.findings.is_empty());
    assert!(report.artifacts.is_empty());
    assert!(report.next_actions.is_empty());
}

#[test]
fn a_non_object_report_or_finding_is_rejected_rather_than_panicking() {
    // A `report:` step body is an arbitrary YAML value, so a scalar or a
    // list reaches the validator as readily as an object does.
    assert_eq!(
        validate_report(&json!("just a string"))
            .expect_err("a report is an object")
            .to_string(),
        "report must be a JSON object, got \"just a string\""
    );
    assert_eq!(
        validate_report(&json!([1, 2, 3]))
            .expect_err("a report is an object")
            .to_string(),
        "report must be a JSON object, got [1,2,3]"
    );

    let raw = json!({
        "outcome": "findings", "severity": "med", "headline": "x", "needs_human": false,
        "cost": { "usd": 0.0, "tokens": 0 },
        "findings": [ "a bare string, not a finding" ]
    });
    assert_eq!(
        validate_report(&raw)
            .expect_err("a finding is an object")
            .to_string(),
        "findings[0] must be a JSON object, got \"a bare string, not a finding\""
    );
}

#[test]
fn a_rejection_message_never_dumps_an_unbounded_payload() {
    // The rejection message reaches a step-failure string that is itself
    // persisted; a report step whose `severity` is a megabyte of prose must
    // not put a megabyte of prose in the run's failure record.
    let long = "z".repeat(10_000);
    let raw = json!({
        "outcome": "nothing", "severity": long, "headline": "x", "needs_human": false,
        "cost": { "usd": 0.0, "tokens": 0 }
    });
    let rendered = validate_report(&raw)
        .expect_err("a 10,000-character severity is not one of low/med/high")
        .to_string();
    assert!(
        rendered.len() < 200,
        "measured rendered length was {}: {rendered}",
        rendered.len()
    );
    assert!(rendered.ends_with('…'), "truncation is marked: {rendered}");
}

#[test]
fn findings_are_tagged_new_persisting_or_resolved_against_the_previous_run() {
    let previous = vec![finding("a"), finding("b")];
    let current = vec![finding("b"), finding("c")];
    let diffed = diff_findings(&previous, &current);

    let status_of = |id: &str| diffed.iter().find(|(f, _)| f.id == id).map(|(_, s)| *s);
    assert_eq!(
        status_of("c"),
        Some(FindingStatus::New),
        "c is only in the current run"
    );
    assert_eq!(
        status_of("b"),
        Some(FindingStatus::Persisting),
        "b is in both runs"
    );
    assert_eq!(
        status_of("a"),
        Some(FindingStatus::Resolved),
        "a was in the previous run but is absent now"
    );
    assert_eq!(
        diffed.len(),
        3,
        "every finding from either run gets exactly one tagged entry"
    );
}

#[test]
fn a_persisting_finding_is_carried_at_its_current_values_not_its_previous_ones() {
    // "Persisting" means the same fingerprint, not the same detail: the
    // detail view must show what this run found, not last night's copy.
    let mut previous_b = finding("b");
    previous_b.title = "3 occurrences".to_string();
    let mut current_b = finding("b");
    current_b.title = "17 occurrences".to_string();

    let diffed = diff_findings(&[previous_b], &[current_b]);
    assert_eq!(diffed.len(), 1);
    assert_eq!(diffed[0].1, FindingStatus::Persisting);
    assert_eq!(diffed[0].0.title, "17 occurrences");
}

#[test]
fn carry_over_seeds_from_the_previous_reports_headline_and_findings() {
    let carry_over = CarryOver { last_report: true };
    let previous = Report {
        outcome: Outcome::Findings,
        severity: Severity::Med,
        headline: "2 flaky tests".into(),
        needs_human: false,
        cost: Cost {
            usd: 0.1,
            tokens: 500,
        },
        findings: vec![finding("a")],
        artifacts: vec![],
        next_actions: vec![],
        extra: serde_json::Map::new(),
    };
    let seed = build_carry_over_seed(&carry_over, Some(&previous))
        .expect("carry_over.last_report is set and a previous report exists");
    assert_eq!(seed["kind"], json!("carry_over_seed"));
    assert_eq!(seed["previous_report"]["outcome"], json!("findings"));
    assert_eq!(seed["previous_report"]["headline"], json!("2 flaky tests"));
    assert_eq!(seed["previous_report"]["findings"][0]["id"], json!("a"));
    assert_eq!(seed["previous_report"]["findings"][0]["title"], json!("a"));
}

#[test]
fn carry_over_off_or_no_history_yields_no_seed_and_never_fails_the_run() {
    assert!(build_carry_over_seed(&CarryOver { last_report: false }, None).is_none());
    assert!(
        build_carry_over_seed(&CarryOver { last_report: true }, None).is_none(),
        "a binding's first-ever run has no prior report — must not fail merely for lacking history"
    );
    let report = Report {
        outcome: Outcome::Nothing,
        severity: Severity::Low,
        headline: "clean".into(),
        needs_human: false,
        cost: Cost {
            usd: 0.0,
            tokens: 0,
        },
        findings: vec![],
        artifacts: vec![],
        next_actions: vec![],
        extra: serde_json::Map::new(),
    };
    assert!(
        build_carry_over_seed(&CarryOver { last_report: false }, Some(&report)).is_none(),
        "carry_over off wins over an available prior report"
    );
}

#[test]
fn a_validated_report_and_its_carry_over_seed_encode_canonically() {
    // `serde_json/preserve_order` is live workspace-wide (ruling P29), so
    // object key order follows insertion order. Two reports that differ only
    // in the order their JSON was written must still encode identically, or
    // anything downstream that hashes, ETags, or compares a report is
    // non-deterministic. Note this compares the two encodings against *each
    // other*, never against a golden literal — P29 forbids the latter.
    let a: serde_json::Value = serde_json::from_str(
        r#"{ "outcome": "changed", "severity": "low", "headline": "h", "needs_human": false,
             "cost": { "usd": 0.0, "tokens": 0 },
             "findings": [ { "id": "i", "title": "t", "severity": "low", "location": "l",
                             "zebra": 1, "apple": 2 } ],
             "artifacts": [ { "zebra": 1, "apple": 2 } ],
             "zebra_top": 1, "apple_top": 2 }"#,
    )
    .unwrap();
    let b: serde_json::Value = serde_json::from_str(
        r#"{ "outcome": "changed", "severity": "low", "headline": "h", "needs_human": false,
             "cost": { "tokens": 0, "usd": 0.0 },
             "findings": [ { "location": "l", "severity": "low", "title": "t", "id": "i",
                             "apple": 2, "zebra": 1 } ],
             "artifacts": [ { "apple": 2, "zebra": 1 } ],
             "apple_top": 2, "zebra_top": 1 }"#,
    )
    .unwrap();

    let ra = validate_report(&a).expect("valid");
    let rb = validate_report(&b).expect("valid");
    assert_eq!(
        serde_json::to_string(&ra).unwrap(),
        serde_json::to_string(&rb).unwrap(),
        "a validated report's encoding depends on structure, not on key insertion order"
    );

    let carry_over = CarryOver { last_report: true };
    assert_eq!(
        serde_json::to_string(&build_carry_over_seed(&carry_over, Some(&ra)).unwrap()).unwrap(),
        serde_json::to_string(&build_carry_over_seed(&carry_over, Some(&rb)).unwrap()).unwrap(),
        "so does the seed built from it"
    );
}

#[test]
fn a_validated_reports_encoding_reproduces_section_8_6s_literal_example() {
    // §8.6's own wire-shape example (`docs/architecture/05-scheduling-and-
    // workflows.md:157-163`), jsonc comments stripped — its `// nothing |
    // changed | ...` and `// extension field, job-defined` annotations carry
    // no meaning to the validator — and its `…` placeholders kept as
    // ordinary string content.
    //
    // Task 18 fix round 1 (ruling P74): a `Report -> Value -> Report` round
    // trip only proves the type's own encoding is self-consistent; it can
    // never prove conformance to a *foreign* wire shape. This test starts
    // from that foreign shape instead: §8.6's document is flat (`pr_number`
    // sits directly on the finding object, not nested under an `extra`
    // key), which is exactly what `#[serde(flatten)]` on `Report::extra` /
    // `Finding::extra` produces and the pre-fix plain named `extra` field
    // never did (`to_value` used to emit `{"outcome": …, "extra": {…}}`).
    let example = json!({
        "outcome": "changed",
        "severity": "low", "headline": "3 flaky tests quarantined", "needs_human": false,
        "findings": [ { "id": "sha256:…", "title": "…", "severity": "med", "location": "…",
                        "pr_number": 4471 } ],
        "artifacts": [ { "kind": "diff", "ref": "worktree:…", "summary": "…" } ],
        "next_actions": [ "…" ], "cost": { "usd": 0.42, "tokens": 118204 }
    });

    let report = validate_report(&example).expect("§8.6's own example is a valid report");
    let encoded = serde_json::to_value(&report).expect("serializes");
    assert_eq!(
        encoded, example,
        "a validated report's encoding must reproduce §8.6's flat document exactly, \
         with no `extra` wrapper anywhere"
    );

    // Validating a validated report's own encoding a second time must be a
    // no-op: nothing migrates into (or out of) an extension bucket on repeat
    // passes.
    let revalidated = validate_report(&encoded).expect("a report's own encoding is itself valid");
    let reencoded = serde_json::to_value(&revalidated).expect("serializes");
    assert_eq!(
        reencoded, encoded,
        "re-validating an already-validated report's encoding must be idempotent"
    );
}

#[test]
fn costs_missing_or_mistyped_subfield_names_the_subfield() {
    let missing_tokens = json!({
        "outcome": "nothing", "severity": "low", "headline": "x", "needs_human": false,
        "cost": { "usd": 0.42 }
    });
    assert_eq!(
        validate_report(&missing_tokens)
            .expect_err("cost.tokens is required")
            .to_string(),
        "missing required core field: `cost.tokens`"
    );

    let bad_usd = json!({
        "outcome": "nothing", "severity": "low", "headline": "x", "needs_human": false,
        "cost": { "usd": "free", "tokens": 0 }
    });
    assert_eq!(
        validate_report(&bad_usd)
            .expect_err("cost.usd must be a number")
            .to_string(),
        "invalid value for field `cost.usd`: \"free\""
    );
}

#[test]
fn a_next_action_element_error_names_its_index() {
    let raw = json!({
        "outcome": "nothing", "severity": "low", "headline": "x", "needs_human": false,
        "cost": { "usd": 0.0, "tokens": 0 },
        "next_actions": [ "fine", 42 ]
    });
    let err = validate_report(&raw).expect_err("next_actions[1] is not a string");
    assert_eq!(err.to_string(), "next_actions[1]: invalid value: 42");
}

#[test]
fn an_explicitly_null_collection_is_treated_as_absent() {
    // Ordinary hand-written YAML for `findings:` followed by nothing parses
    // to `Value::Null`, not to an absent key — that must not be rejected
    // when an absent key is accepted.
    let raw = json!({
        "outcome": "nothing", "severity": "low", "headline": "x", "needs_human": false,
        "cost": { "usd": 0.0, "tokens": 0 },
        "findings": null, "artifacts": null, "next_actions": null
    });
    let report = validate_report(&raw).expect("an explicit null collection is treated as absent");
    assert!(report.findings.is_empty());
    assert!(report.artifacts.is_empty());
    assert!(report.next_actions.is_empty());
}
