//! Task 34 (Phase 5, Subsystem D5) — the presentation half of §8.6's Runs
//! inbox and §11.4's batch-approval collapsing.
//!
//! The query itself is `roundhouse-flow`'s and is tested there, against the real
//! store migrations (ruling P86). What is exercised here is what this crate
//! actually decides: the triage order, the grouping, the JSON the client reads,
//! and that the route is mounted where `build_router` gates it.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use roundhouse_core::BindingId;
use roundhouse_flow::exec::RunId;
use roundhouse_flow::report::{Cost, Finding, FindingStatus, Outcome, Report, Severity};
use roundhouse_flow::runs::RunSummary;
use roundhouse_web::lan_auth::BindConfig;
use roundhouse_web::runs::{
    collapse_by_signature, compute_signature, sort_for_triage, RunSummaryJson,
};
use roundhouse_web::{build_router, AppState};
use tower::ServiceExt;

fn report(outcome: Outcome, severity: Severity, needs_human: bool) -> Report {
    Report {
        outcome,
        severity,
        headline: "x".into(),
        needs_human,
        cost: Cost {
            usd: 0.0,
            tokens: 0,
        },
        findings: Vec::new(),
        artifacts: Vec::new(),
        next_actions: Vec::new(),
        extra: serde_json::Map::new(),
    }
}

/// A summary carrying `headline` as its only identity, so the sort assertions
/// can name what they expect without stringifying a UUID.
fn run(headline: &str, outcome: Outcome, severity: Severity, needs_human: bool) -> RunSummary {
    let mut report = report(outcome, severity, needs_human);
    report.headline = headline.to_string();
    RunSummary {
        run_id: RunId::new(),
        binding_id: None,
        report,
        diffed_findings: Vec::new(),
    }
}

fn headlines(runs: &[RunSummary]) -> Vec<&str> {
    runs.iter()
        .map(|run| run.report.headline.as_str())
        .collect()
}

/// §8.6's `(needs_human, severity, outcome != nothing)`, all three keys in one
/// fixture: the `needs_human` run is `Changed`/`High`, so if the sort read
/// severity or outcome first it would still lead — it leads because
/// `needs_human` outranks both, which the *middle* run is what proves. The
/// no-op run sorts last on the third key alone.
#[test]
fn needs_human_sorts_first_then_severity_then_a_non_trivial_outcome() {
    let sorted = sort_for_triage(vec![
        run("nothing", Outcome::Nothing, Severity::Low, false),
        run("wants a human", Outcome::Changed, Severity::High, true),
        run("findings", Outcome::Findings, Severity::Med, false),
    ]);

    assert_eq!(
        headlines(&sorted),
        vec!["wants a human", "findings", "nothing"]
    );
}

/// The severity key runs High before Low, which is the *reverse* of
/// `Severity`'s derived `Ord` (`Low < Med < High`). Its own doc comment says
/// that variant order is the sort contract, so this pins that the inbox
/// reverses that single ordering rather than carrying a second one beside it —
/// a `sort_by_key` that forgot the `Reverse` would order these Low first.
#[test]
fn a_higher_severity_triages_before_a_lower_one() {
    let sorted = sort_for_triage(vec![
        run("low", Outcome::Findings, Severity::Low, false),
        run("high", Outcome::Findings, Severity::High, false),
        run("med", Outcome::Findings, Severity::Med, false),
    ]);

    assert_eq!(headlines(&sorted), vec!["high", "med", "low"]);
}

/// `needs_human` outranks severity, and this is the case that separates them: a
/// `Low` run wanting a human beats a `High` run that does not. A sort keyed on
/// severity first would put "high" on top.
#[test]
fn a_low_severity_run_wanting_a_human_beats_a_high_severity_run_that_does_not() {
    let sorted = sort_for_triage(vec![
        run("high", Outcome::Findings, Severity::High, false),
        run("low but blocked", Outcome::Findings, Severity::Low, true),
    ]);

    assert_eq!(headlines(&sorted), vec!["low but blocked", "high"]);
}

/// The third key on its own: same `needs_human`, same severity, and only the
/// outcome separating them. Nothing else in this file isolates it — in
/// [`needs_human_sorts_first_then_severity_then_a_non_trivial_outcome`] the
/// no-op run is also the lowest severity, so severity already puts it last and
/// an inverted outcome key would go unnoticed there.
#[test]
fn a_no_op_run_sorts_below_one_that_found_something() {
    let sorted = sort_for_triage(vec![
        run("nothing", Outcome::Nothing, Severity::Med, false),
        run("changed", Outcome::Changed, Severity::Med, false),
    ]);

    assert_eq!(headlines(&sorted), vec!["changed", "nothing"]);
}

/// Runs whose three sort keys are identical keep the order they arrived in —
/// which is `load_run_summaries`' newest-first order. An unstable sort would be
/// free to shuffle them, and the inbox would reorder on refresh with nothing
/// having changed.
///
/// **The fixture is long and its keys are mixed, and both are deliberate.**
/// Rust's `sort_unstable_by_key` uses an insertion sort on short slices and
/// short-circuits an all-equal slice without moving anything, so neither a
/// three-element list nor a long list of *identical* keys can tell the two
/// sorts apart — this test would then be one of the vacuous ones ruling P79 is
/// about. Interleaving three severities over sixty runs makes the sort actually
/// partition, and swapping in `sort_unstable_by_key` fails here.
#[test]
fn runs_with_equal_keys_keep_the_order_they_arrived_in() {
    let severities = [Severity::High, Severity::Med, Severity::Low];
    let runs: Vec<RunSummary> = (0..60)
        .map(|index| {
            run(
                &format!("run-{index:02}"),
                Outcome::Findings,
                severities[index % severities.len()],
                false,
            )
        })
        .collect();

    let sorted = sort_for_triage(runs);

    // Severity groups first, and inside each group the arrival order — which is
    // `load_run_summaries`' newest-first order — untouched.
    let expected: Vec<String> = (0..severities.len())
        .flat_map(|group| {
            (0..60)
                .filter(move |index| index % severities.len() == group)
                .map(|index| format!("run-{index:02}"))
        })
        .collect();

    assert_eq!(headlines(&sorted), expected);
}

/// §11.4's *"×3"*: three tasks waiting on the same decision are one row.
#[test]
fn identical_decision_signatures_collapse_into_one_pending_approval_row() {
    let signature = compute_signature(
        "shell",
        &["gh".into(), "pr".into(), "comment".into()],
        "medium",
        "github.com",
    );
    let collapsed = collapse_by_signature(vec![
        (signature.clone(), "task-1".to_string()),
        (signature.clone(), "task-2".to_string()),
        (signature, "task-3".to_string()),
    ]);

    assert_eq!(collapsed.len(), 1);
    assert_eq!(collapsed[0].task_ids, vec!["task-1", "task-2", "task-3"]);
}

/// The safety property in the signature: an identical call at a higher risk
/// class is a *different* row, so approving the medium-risk one can never carry
/// the high-risk one along with it.
#[test]
fn a_risk_escalation_never_collapses_with_the_otherwise_identical_call() {
    let medium = compute_signature("shell", &["rm".into()], "medium", "local");
    let high = compute_signature("shell", &["rm".into()], "high", "local");

    assert_ne!(medium, high);
    let collapsed = collapse_by_signature(vec![
        (medium, "task-1".to_string()),
        (high, "task-2".to_string()),
    ]);
    assert_eq!(collapsed.len(), 2, "risk class always breaks a collapse");
}

/// Each of the four parts is part of the key, so a change in any one of them
/// splits the row. Without this, a signature that ignored (say) `target_class`
/// would collapse `curl example.com` with `curl internal.corp`.
#[test]
fn every_part_of_the_signature_is_part_of_the_key() {
    let base = compute_signature("shell", &["curl".into()], "medium", "example.com");

    for (label, other) in [
        (
            "tool",
            compute_signature("http", &["curl".into()], "medium", "example.com"),
        ),
        (
            "argv",
            compute_signature("shell", &["wget".into()], "medium", "example.com"),
        ),
        (
            "risk_class",
            compute_signature("shell", &["curl".into()], "low", "example.com"),
        ),
        (
            "target_class",
            compute_signature("shell", &["curl".into()], "medium", "internal.corp"),
        ),
    ] {
        assert_ne!(base, other, "{label} must be part of the signature");
    }
}

/// Rows come back in first-seen order, not in whatever order the `HashMap`
/// iterates. The rows are a list a human reads top to bottom, and `RandomState`
/// gives a different iteration order in every process, so grouping alone would
/// reorder the inbox on every restart with no input having changed.
///
/// **Twelve signatures, not three.** With three, `HashMap` order coincides with
/// insertion order about one process in six, so a three-row fixture would pass
/// under a mutation that dropped the ordering — and would do it *sometimes*,
/// which is worse than always. At twelve the coincidence is one in `12!`.
///
/// The repeat of the first signature at the end is the other half: first-seen,
/// not last-seen, and not "sorted by how many tasks are behind it".
#[test]
fn collapsed_rows_come_back_in_first_seen_order() {
    let signatures: Vec<_> = (0..12)
        .map(|index| compute_signature("shell", &[format!("cmd-{index}")], "low", "local"))
        .collect();

    let mut approvals: Vec<_> = signatures
        .iter()
        .enumerate()
        .map(|(index, signature)| (signature.clone(), format!("task-{index}")))
        .collect();
    approvals.push((signatures[0].clone(), "task-again".to_string()));

    let collapsed = collapse_by_signature(approvals);

    assert_eq!(
        collapsed
            .iter()
            .map(|row| row.signature.clone())
            .collect::<Vec<_>>(),
        signatures,
        "the row that appeared first stays first, even though it also appears last"
    );
    assert_eq!(
        collapsed[0].task_ids,
        vec!["task-0", "task-again"],
        "a repeat joins the row it first opened rather than starting a new one"
    );
}

/// The wire shape, and specifically that a finding's job-defined extension
/// fields cannot shadow the diff verdict.
///
/// §8.6 lets a job put arbitrary keys on a finding, and `Finding` renders them
/// with `#[serde(flatten)]` — directly on the finding object. A finding with its
/// own `status` field is therefore entirely legal, and flattening the finding
/// alongside `status` here would let it overwrite `new`/`persisting`/`resolved`
/// with whatever the job wrote. This asserts both keys are present and that the
/// verdict is the one the diff produced.
#[test]
fn a_findings_own_status_field_cannot_shadow_the_diff_verdict() {
    let mut extra = serde_json::Map::new();
    extra.insert("status".into(), serde_json::json!("wontfix"));
    extra.insert("pr_number".into(), serde_json::json!(4471));

    let binding_id = BindingId::new();
    let run_id = RunId::new();
    let json = serde_json::to_value(RunSummaryJson::from(RunSummary {
        run_id,
        binding_id: Some(binding_id),
        report: report(Outcome::Findings, Severity::Med, false),
        diffed_findings: vec![(
            Finding {
                id: "f1".into(),
                title: "a finding".into(),
                severity: Severity::Med,
                location: "src/lib.rs:1".into(),
                extra,
            },
            FindingStatus::Persisting,
        )],
    }))
    .expect("the wire shape serialises");

    assert_eq!(json["run_id"], serde_json::json!(run_id.to_string()));
    assert_eq!(
        json["binding_id"],
        serde_json::json!(binding_id.to_string())
    );

    let diffed = &json["diffed_findings"][0];
    assert_eq!(
        diffed["status"],
        serde_json::json!("persisting"),
        "the diff verdict is the one the diff produced"
    );
    assert_eq!(
        diffed["finding"]["status"],
        serde_json::json!("wontfix"),
        "the job's own field survives, in the finding's namespace"
    );
    assert_eq!(diffed["finding"]["pr_number"], serde_json::json!(4471));
    assert_eq!(diffed["finding"]["id"], serde_json::json!("f1"));
}

/// A manually-invoked run has no binding, and `null` is what that is on the
/// wire — not an empty string, which the plan's version of `RunSummary` would
/// have produced and which reads as "a binding whose id is blank".
#[test]
fn a_run_with_no_binding_serialises_its_binding_id_as_null() {
    let json = serde_json::to_value(RunSummaryJson::from(RunSummary {
        run_id: RunId::new(),
        binding_id: None,
        report: report(Outcome::Nothing, Severity::Low, false),
        diffed_findings: Vec::new(),
    }))
    .expect("the wire shape serialises");

    assert_eq!(json["binding_id"], serde_json::Value::Null);
}

/// Every router here is loopback-bound, so `127.0.0.1` is the name it answers
/// to. The `Host` is not optional: ruling P93 §A's rebinding check refuses an
/// `/api` request that does not address the bind, and an in-process `oneshot`
/// sets no `Host` of its own. `tests/host_guard.rs` is where that refusal is
/// the assertion rather than the background.
async fn get(router: axum::Router, uri: &str) -> axum::http::Response<Body> {
    router
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("Host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("the router is infallible")
}

/// The route is mounted at `/api/runs`, and a router with no store says so
/// rather than answering `[]`.
///
/// An empty inbox is a real and reassuring answer — "nothing needs you" — so it
/// must never be what "there is no database attached" looks like. A `200 []`
/// here would be indistinguishable from a healthy quiet day.
#[tokio::test]
async fn the_runs_route_reports_a_missing_store_rather_than_an_empty_inbox() {
    let router = build_router(AppState::default(), &BindConfig::loopback());

    let response = get(router, "/api/runs").await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("the body fits");
    assert!(
        String::from_utf8_lossy(&body).contains("no store"),
        "the body names the reason, since a 503 alone does not distinguish it from a restart"
    );
}

/// The route is registered, not merely reachable through the SPA fallback. A
/// `runs::router()` that was never merged into `api_router` would land here on
/// `api_not_found`'s 404 instead, and `/api/runs` would 404 forever with no
/// other symptom.
#[tokio::test]
async fn the_runs_route_is_registered_rather_than_falling_through() {
    let router = build_router(AppState::default(), &BindConfig::loopback());
    assert_eq!(
        get(router, "/api/runs").await.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "an unregistered /api path would be a 404 from the API fallback"
    );

    let router = build_router(AppState::default(), &BindConfig::loopback());
    assert_eq!(
        get(router, "/api/runs/extra").await.status(),
        StatusCode::NOT_FOUND,
        "the route is `/api/runs` exactly, not a prefix"
    );
}
