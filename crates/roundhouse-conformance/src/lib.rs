//! `roundhouse-conformance` — the shared provider-adapter conformance suite
//! (§9.10).
//!
//! Per §13.3, this harness IS the review artifact for a provider adapter: a
//! human reviewer's whole job per adapter is "read the golden snapshots, skim
//! the cassette list, confirm `conformance().assert_green()`, done." That
//! only works if the checks this crate runs actually catch real violations,
//! which is why [`fixtures`] and `tests/self_test.rs` exist — they prove the
//! harness fails a broken adapter before it is ever pointed at a real one.
//!
//! An adapter under test (a [`ConformanceSubject`]) supplies its `Provider`
//! impl, a list of [`ConformanceCase`]s (each a request + a recorded
//! `.cassette` file — see `roundhouse_provider::CassetteTransport`'s module
//! docs for that file format), and its own `wire_body` encoder. [`run`]
//! then, per case:
//!
//! 1. Checks the encoded wire body against the case's [`SerializeOnlyMask`]
//!    (the "no field outside the resolved mask" property test, §9.10).
//! 2. Replays the cassette at four different chunk boundaries and asserts
//!    the folded result is identical across all of them (fold determinism;
//!    the whole-body replay also stands in for stream/non-stream
//!    equivalence).
//! 3. Checks round-trip fidelity: every content-block kind present in the
//!    request must either survive into the decoded result or have a
//!    declared `LossEvent`.
//! 4. Checks usage invariants (`input_tokens >= cache_read_tokens`, §9.3).
#![forbid(unsafe_code)]

pub mod checks;
pub mod fixtures;
pub mod mask;

pub use checks::FoldedResult;
pub use mask::SerializeOnlyMask;

use roundhouse_provider::{ChatRequest, ContentBlock, Provider};

/// One conformance case: a request, the recorded cassette to replay it
/// against, the mask its encoded wire body must stay inside, and any
/// content-block losses the adapter has deliberately declared for this case.
pub struct ConformanceCase {
    pub name: &'static str,
    pub request: ChatRequest,
    pub cassette_path: std::path::PathBuf,
    pub mask: SerializeOnlyMask,
    pub declared_loss_events: Vec<String>,
}

/// The thing under test: one provider adapter, plus everything the harness
/// needs to exercise it without ever making a live network call.
pub trait ConformanceSubject {
    type Provider: Provider;

    fn provider() -> Self::Provider;

    fn cases() -> Vec<ConformanceCase>;

    /// The encoded wire body for `req`, exactly as this codec's `encode`
    /// produces it. This is what the [`SerializeOnlyMask`] check runs
    /// against — see REALITY-CORRECTIONS §5: `Plan` carries no wire-body
    /// preview, so the harness asks the subject directly instead.
    fn wire_body(req: &ChatRequest) -> serde_json::Value;
}

/// The result of running every case for one [`ConformanceSubject`].
#[derive(Debug, Default)]
pub struct ConformanceReport {
    pub failures: Vec<String>,
}

impl ConformanceReport {
    /// Panics with every accumulated failure if the report is not clean.
    pub fn assert_green(&self) {
        assert!(
            self.failures.is_empty(),
            "conformance suite failures:\n{}",
            self.failures.join("\n")
        );
    }
}

/// Runs every case `S` declares and collects every failure found.
pub async fn run<S: ConformanceSubject>() -> ConformanceReport {
    let provider = S::provider();
    let mut failures = Vec::new();

    for case in S::cases() {
        let wire_body = S::wire_body(&case.request);
        failures.extend(checks::check_mask(&wire_body, &case.mask));

        let (determinism_failures, folded) =
            checks::check_fold_determinism(&provider, &case.request, &case.cassette_path).await;
        failures.extend(determinism_failures);

        if let Some(result) = folded {
            failures.extend(checks::check_round_trip_fidelity(
                &extract_request_blocks(&case.request),
                &result.blocks,
                &case.declared_loss_events,
            ));
            failures.extend(checks::check_usage_invariants(&result.usage));
        }
    }

    ConformanceReport { failures }
}

fn extract_request_blocks(req: &ChatRequest) -> Vec<ContentBlock> {
    req.messages
        .iter()
        .flat_map(|m| m.content.clone())
        .collect()
}
