//! §8.6's Runs inbox and §11.4's batch-approval collapsing: the presentation
//! half of both.
//!
//! **There is no SQL in this crate** (ruling P86). The query, and the
//! fingerprint diff it applies, live in [`roundhouse_flow::runs`], which already
//! owns `WorkflowRun`, `Report` and `diff_findings` and already has the
//! `roundhouse-store` edge the tables belong to. What is here is what is
//! genuinely presentation: the triage order, decision-signature grouping, the
//! JSON wire shape, and the route.
//!
//! # Nothing feeds either half yet
//!
//! Two residuals, both with owners, so neither reads as wired when it is not:
//!
//! - **No run reaches a terminal state with a `Report` task** — B12c owns the
//!   run loop. `GET /api/runs` against a live store therefore answers `[]`
//!   truthfully rather than incorrectly, and this route has no end-to-end
//!   exercise until B12c lands.
//! - **Nothing produces a [`DecisionSignature`]**. §11.4 says *"the daemon
//!   computes a decision signature […]; identical signatures collapse into one
//!   inbox row"*, and the daemon-side half — the approval queue that would hand
//!   [`collapse_by_signature`] its input — does not exist in this workspace.
//!   [`compute_signature`] is the shape that half must produce; it has no
//!   caller today.

use std::cmp::Reverse;
use std::collections::HashMap;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

use roundhouse_flow::report::{Finding, FindingStatus, Outcome, Report};
use roundhouse_flow::runs::{load_run_summaries, RunSummary, MAX_INBOX_RUNS};

/// §8.6: *"a Runs inbox sorted by `(needs_human, severity, outcome != nothing)`,
/// with `nothing` runs collapsed to one line."*
///
/// The collapsing is a client rendering concern — this establishes only the
/// order the client renders in. The sort is **stable**, so runs with equal keys
/// keep the order [`load_run_summaries`] returned them in, which is newest
/// first.
///
/// # The severity key is `Reverse`, not a rank table
///
/// [`roundhouse_flow::report::Severity`] derives `Ord` over `Low, Med, High`,
/// and its own doc comment says that order exists for *"the direction the
/// inbox's sort needs; reordering these variants silently reorders the inbox"*.
/// The variant order **is** the sort contract, so this reverses that one
/// ordering rather than hand-rolling `High = 0 / Med = 1 / Low = 2` beside it. A
/// parallel rank function is an inverted duplicate of a contract that already
/// exists, and it is what goes stale on the day a fourth severity is added — the
/// `match` would still compile if the new variant were mapped to any number at
/// all.
///
/// The two `bool` keys read backwards on purpose and are inverted for the same
/// reason: `false < true`, so `!needs_human` puts the runs wanting a human
/// first, and `outcome == Nothing` puts the no-op runs last.
pub fn sort_for_triage(mut runs: Vec<RunSummary>) -> Vec<RunSummary> {
    runs.sort_by_key(|run| {
        (
            !run.report.needs_human,
            Reverse(run.report.severity),
            run.report.outcome == Outcome::Nothing,
        )
    });
    runs
}

/// §11.4's decision signature: *"the daemon computes a decision signature
/// (tool + normalized argv + risk class + target host/path class); identical
/// signatures collapse into one inbox row."*
///
/// `Eq + Hash` is the whole type: it exists to be a grouping key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DecisionSignature {
    pub tool: String,
    pub normalized_argv: String,
    pub risk_class: String,
    pub target_class: String,
}

/// Builds a [`DecisionSignature`] from §11.4's four parts.
///
/// **`risk_class` is part of the key, and that is a safety property rather than
/// a completeness one.** Two otherwise-identical calls at different risk levels
/// must not collapse into one row, because approving the row would then approve
/// the riskier one on the strength of having read the safer one. §11.4 puts
/// HIGH-risk items through the full modal regardless; keeping the class in the
/// key means a risk escalation breaks the collapse even before that.
///
/// `normalized_argv` is the argv joined on a single space. That is a *display*
/// normalisation, and it is deliberately not a security boundary: `["a b"]` and
/// `["a", "b"]` produce the same string. The caller that will eventually feed
/// this — the daemon-side approval queue, which does not exist yet — is the
/// layer that knows what a real normalisation means for its tool, and it should
/// pass an already-normalised argv rather than expect this to invent one.
pub fn compute_signature(
    tool: &str,
    argv: &[String],
    risk_class: &str,
    target: &str,
) -> DecisionSignature {
    DecisionSignature {
        tool: tool.to_string(),
        normalized_argv: argv.join(" "),
        risk_class: risk_class.to_string(),
        target_class: target.to_string(),
    }
}

/// One inbox row: a signature, and every task waiting on that same decision.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingApproval {
    pub signature: DecisionSignature,
    pub task_ids: Vec<String>,
}

/// Groups pending approvals by signature — §11.4's *"×3"* row.
///
/// **First-seen order, not hash order.** The rows are what a human reads top to
/// bottom, and a `HashMap`'s iteration order changes between runs of the same
/// process, so grouping alone would reorder the inbox on every refresh with no
/// input having changed. The `order` vector is what makes the output a function
/// of the input.
pub fn collapse_by_signature(approvals: Vec<(DecisionSignature, String)>) -> Vec<PendingApproval> {
    let mut grouped: HashMap<DecisionSignature, Vec<String>> = HashMap::new();
    let mut order: Vec<DecisionSignature> = Vec::new();

    for (signature, task_id) in approvals {
        if !grouped.contains_key(&signature) {
            order.push(signature.clone());
        }
        grouped.entry(signature).or_default().push(task_id);
    }

    order
        .into_iter()
        .map(|signature| {
            let task_ids = grouped.remove(&signature).unwrap_or_default();
            PendingApproval {
                signature,
                task_ids,
            }
        })
        .collect()
}

/// One run on the wire.
///
/// [`RunSummary`] stays a plain Rust struct carrying typed ids; this is the one
/// place it becomes JSON. The ids are rendered as strings because that is what a
/// browser can hold without losing anything, and `run_id`'s type is
/// `roundhouse_flow`'s own newtype, not a `roundhouse-proto` wire type.
#[derive(Debug, serde::Serialize)]
pub struct RunSummaryJson {
    pub run_id: String,
    /// `null` for a manually-invoked run, which has no binding — and therefore
    /// nothing to have diffed against.
    pub binding_id: Option<String>,
    pub report: Report,
    pub diffed_findings: Vec<DiffedFindingJson>,
}

/// A finding and its standing relative to the previous run.
///
/// **The finding is nested under `finding`, not flattened alongside `status`.**
/// [`Finding`] carries §8.6's open `extra` map with `#[serde(flatten)]` on it —
/// job-defined keys, sitting directly on the finding object on the wire. A
/// second flatten here would put `status` in the same namespace, so a job whose
/// findings carry a `status` field of their own would silently overwrite the
/// diff verdict with its own value. Nesting costs the client one level of
/// indirection and makes that collision unrepresentable.
#[derive(Debug, serde::Serialize)]
pub struct DiffedFindingJson {
    pub finding: Finding,
    pub status: FindingStatus,
}

impl From<RunSummary> for RunSummaryJson {
    fn from(summary: RunSummary) -> Self {
        RunSummaryJson {
            run_id: summary.run_id.to_string(),
            binding_id: summary.binding_id.map(|id| id.to_string()),
            report: summary.report,
            diffed_findings: summary
                .diffed_findings
                .into_iter()
                .map(|(finding, status)| DiffedFindingJson { finding, status })
                .collect(),
        }
    }
}

/// `GET /api/runs` — the Runs inbox, in triage order.
///
/// # Why a missing store is a `503` and not an empty list
///
/// [`crate::AppState::store`] is an `Option` because [`crate::AppState`] must
/// keep a `Default` (see its docs) and because a router can legitimately be
/// built without a database — every router in this crate's own test suite is.
/// Answering `[]` in that case would be a **lie in the one direction that
/// matters**: an empty inbox is a real, common and reassuring answer ("nothing
/// needs you"), and it must never be what "this daemon has no database attached"
/// looks like. `503` says the surface is not ready, which is what is true.
///
/// # The permit, and why it is taken *after* the store check
///
/// This handler is the first request-triggered consumer of the pool
/// `roundhouse_store::writer` appends events through, and it holds one
/// connection for up to `1 + 3 × MAX_INBOX_RUNS` queries. Enough concurrent
/// requests would hold every connection and block event appends indefinitely —
/// see [`crate::ApiPoolPermits`], which is the bound and carries the whole
/// argument (ruling P93 §B).
///
/// The order matters and is not arbitrary: a router with no store never touches
/// the pool, so taking a permit before finding that out would let a
/// store-less server shed requests it was never going to run a query for. Both
/// answers are `503`, and their bodies are what distinguish them.
async fn list_runs(State(state): State<crate::AppState>) -> Response {
    let Some(store) = state.store else {
        return unavailable("no store is attached to this server");
    };

    // Held until this function returns, which is exactly as long as the
    // connection below is held. `_permit` and not `_`: the latter drops it
    // immediately and the bound would count nothing.
    let Some(_permit) = state.api_pool_permits.try_acquire() else {
        return unavailable(
            "the runs inbox is at its concurrency bound; retry shortly (the store's connections \
             are shared with the event log's writer)",
        );
    };

    let connection = match store.pool.get().await {
        Ok(connection) => connection,
        Err(error) => return internal_error("acquiring a store connection", &error),
    };

    // The query is synchronous and lives in `roundhouse-flow`; `interact` is
    // what runs it on the pool's blocking thread. Note the closure never names
    // `rusqlite` — that is what keeps this crate free of the edge P86 removed.
    let loaded = connection
        .interact(|conn| load_run_summaries(conn, MAX_INBOX_RUNS))
        .await;

    let summaries = match loaded {
        Err(error) => return internal_error("running the runs query", &error),
        Ok(Err(error)) => return internal_error("loading the runs inbox", &error),
        Ok(Ok(summaries)) => summaries,
    };

    Json(
        sort_for_triage(summaries)
            .into_iter()
            .map(RunSummaryJson::from)
            .collect::<Vec<_>>(),
    )
    .into_response()
}

/// A `503` — this surface is not ready — with `reason` in the JSON body.
fn unavailable(reason: &str) -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, error_body(reason)).into_response()
}

/// A `500` whose body names the stage but **not** the underlying error.
///
/// The error text can carry a database path, a SQL fragment, or — through
/// `RunsError::InvalidReport` — part of a report's contents, and this response
/// goes to whoever asked, who on a LAN bind is authenticated as a device and not
/// as a person. `_error` is taken so that the day this crate has a logger, the
/// detail is in view of the one function that should write it.
fn internal_error(stage: &str, _error: &dyn std::fmt::Display) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        error_body(&format!("the runs inbox failed while {stage}")),
    )
        .into_response()
}

/// Every error body under `/api` is `{"error": "…"}`.
///
/// **The convention is set here because it is cheapest here.** `GET /api/runs`
/// answers `application/json` on success, so a client doing `res.json()` on a
/// failure used to get a parse error instead of a reason — and D6 adds four
/// more endpoints to this namespace next. One shape, decided once.
///
/// The text is for a person reading a console, so it stays a sentence rather
/// than a machine-readable code; the **status** is what a client branches on.
/// Nothing derived from an error's `Display` reaches it — see
/// [`internal_error`].
pub(crate) fn error_body(reason: &str) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "error": reason }))
}

/// The Runs routes, merged into [`crate::build_router`]'s single API router.
pub fn router() -> Router<crate::AppState> {
    Router::new().route("/runs", get(list_runs))
}
