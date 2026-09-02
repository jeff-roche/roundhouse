//! The meta-test proving the harness itself catches real violations before
//! it is ever pointed at a real provider: a deliberately broken fake
//! adapter must fail `assert_green()`, and a correct one must pass.
//!
//! Per the task brief for `roundhouse-conformance`, this is the harness's
//! own review artifact — if this test passed vacuously (e.g. because the
//! block fold never actually accumulated anything, or `check_fold_determinism`
//! called a nonexistent method), every downstream provider-adapter task's
//! "conformance is green" claim would be worthless. See this crate's
//! `checks.rs` and `fixtures.rs` module docs for how each check is wired to
//! avoid that.

use roundhouse_conformance::{
    fixtures, run, ConformanceCase, ConformanceSubject, SerializeOnlyMask,
};
use roundhouse_provider::{
    BoxFut, Capabilities, ChatRequest, ChatStream, ModelId, Plan, Provider, ProviderError,
    RequestCtx, TokenCount,
};

/// A minimal, deliberately CORRECT fake provider: always emits the same
/// well-formed text block regardless of chunk boundary (it ignores
/// `ctx.transport` entirely), never puts a field outside its declared mask
/// on the wire, and reports usage that satisfies `input_tokens >=
/// cache_read_tokens`.
struct GoodFakeProvider;

impl Provider for GoodFakeProvider {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        Capabilities::default()
    }

    fn resolve(&self, _req: &ChatRequest) -> Result<Plan, ProviderError> {
        Ok(Plan {
            endpoint: "https://fake.invalid/good".into(),
        })
    }

    fn stream_chat<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<ChatStream, ProviderError>> {
        Box::pin(async { Ok(fixtures::good_stream()) })
    }

    fn count_tokens<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<TokenCount, ProviderError>> {
        Box::pin(async { Ok(TokenCount::default()) })
    }
}

/// A deliberately BROKEN fake: its wire body carries an out-of-mask
/// "frobnicate" field, and its stream reports `input_tokens <
/// cache_read_tokens`.
struct BrokenFakeProvider;

impl Provider for BrokenFakeProvider {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        Capabilities::default()
    }

    fn resolve(&self, _req: &ChatRequest) -> Result<Plan, ProviderError> {
        Ok(Plan {
            endpoint: "https://fake.invalid/broken".into(),
        })
    }

    fn stream_chat<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<ChatStream, ProviderError>> {
        Box::pin(async { Ok(fixtures::broken_usage_stream()) })
    }

    fn count_tokens<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<TokenCount, ProviderError>> {
        Box::pin(async { Ok(TokenCount::default()) })
    }
}

/// A fake that always fails `stream_chat` with `RateLimited` -- proves
/// `ConformanceCase::expected_error` (fix-round-1 C7 on Task 5 of
/// `2026-08-27-phase6-provider-breadth`) actually changes what
/// `check_fold_determinism` accepts, rather than being a dead field.
struct ErroringFakeProvider;

impl Provider for ErroringFakeProvider {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        Capabilities::default()
    }

    fn resolve(&self, _req: &ChatRequest) -> Result<Plan, ProviderError> {
        Ok(Plan {
            endpoint: "https://fake.invalid/erroring".into(),
        })
    }

    fn stream_chat<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<ChatStream, ProviderError>> {
        Box::pin(async { Err(ProviderError::RateLimited { retry_after: None }) })
    }

    fn count_tokens<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<TokenCount, ProviderError>> {
        Box::pin(async { Ok(TokenCount::default()) })
    }
}

struct GoodSubject;

impl ConformanceSubject for GoodSubject {
    type Provider = GoodFakeProvider;

    fn provider() -> Self::Provider {
        GoodFakeProvider
    }

    fn cases() -> Vec<ConformanceCase> {
        vec![fixtures::simple_case(SerializeOnlyMask {
            mandatory: vec!["model".into()],
            allowed: vec![],
        })]
    }

    fn wire_body(req: &ChatRequest) -> serde_json::Value {
        serde_json::json!({ "model": req.model.0 })
    }
}

struct BrokenSubject;

impl ConformanceSubject for BrokenSubject {
    type Provider = BrokenFakeProvider;

    fn provider() -> Self::Provider {
        BrokenFakeProvider
    }

    fn cases() -> Vec<ConformanceCase> {
        vec![fixtures::simple_case(SerializeOnlyMask {
            mandatory: vec!["model".into()],
            allowed: vec![], // "frobnicate" is deliberately NOT in the mask
        })]
    }

    fn wire_body(req: &ChatRequest) -> serde_json::Value {
        serde_json::json!({ "model": req.model.0, "frobnicate": true })
    }
}

#[tokio::test]
async fn good_adapter_is_green() {
    let report = run::<GoodSubject>().await;
    report.assert_green(); // must not panic
}

#[tokio::test]
async fn broken_adapter_is_caught() {
    let report = run::<BrokenSubject>().await;
    assert!(
        !report.failures.is_empty(),
        "the mask violation and usage-invariant violation must be caught"
    );
    assert!(
        report.failures.iter().any(|f| f.contains("frobnicate")),
        "expected a failure naming the out-of-mask field, got: {:#?}",
        report.failures
    );
    assert!(
        report.failures.iter().any(|f| f.contains("input_tokens")),
        "expected a usage-invariant failure, got: {:#?}",
        report.failures
    );
}

/// `ConformanceCase::expected_error` set, and the provider's actual error
/// matches the declared predicate -- must be green.
struct ExpectedErrorMatchesSubject;

impl ConformanceSubject for ExpectedErrorMatchesSubject {
    type Provider = ErroringFakeProvider;

    fn provider() -> Self::Provider {
        ErroringFakeProvider
    }

    fn cases() -> Vec<ConformanceCase> {
        vec![fixtures::simple_case_expecting_error(
            SerializeOnlyMask {
                mandatory: vec!["model".into()],
                allowed: vec![],
            },
            |e| matches!(e, ProviderError::RateLimited { .. }),
        )]
    }

    fn wire_body(req: &ChatRequest) -> serde_json::Value {
        serde_json::json!({ "model": req.model.0 })
    }
}

/// `expected_error` set, but the predicate names the WRONG `ProviderError`
/// variant -- the provider really does error, but not with the disposition
/// the case declares, so this must still be caught.
struct ExpectedErrorWrongKindSubject;

impl ConformanceSubject for ExpectedErrorWrongKindSubject {
    type Provider = ErroringFakeProvider;

    fn provider() -> Self::Provider {
        ErroringFakeProvider
    }

    fn cases() -> Vec<ConformanceCase> {
        vec![fixtures::simple_case_expecting_error(
            SerializeOnlyMask {
                mandatory: vec!["model".into()],
                allowed: vec![],
            },
            |e| matches!(e, ProviderError::QuotaExhausted),
        )]
    }

    fn wire_body(req: &ChatRequest) -> serde_json::Value {
        serde_json::json!({ "model": req.model.0 })
    }
}

/// `expected_error` set, but the provider actually SUCCEEDS -- an
/// unexpectedly successful stream must be caught too, not just a mismatched
/// error.
struct ExpectedErrorButSucceedsSubject;

impl ConformanceSubject for ExpectedErrorButSucceedsSubject {
    type Provider = GoodFakeProvider;

    fn provider() -> Self::Provider {
        GoodFakeProvider
    }

    fn cases() -> Vec<ConformanceCase> {
        vec![fixtures::simple_case_expecting_error(
            SerializeOnlyMask {
                mandatory: vec!["model".into()],
                allowed: vec![],
            },
            |e| matches!(e, ProviderError::RateLimited { .. }),
        )]
    }

    fn wire_body(req: &ChatRequest) -> serde_json::Value {
        serde_json::json!({ "model": req.model.0 })
    }
}

#[tokio::test]
async fn expected_error_matching_the_predicate_is_green() {
    let report = run::<ExpectedErrorMatchesSubject>().await;
    report.assert_green();
}

#[tokio::test]
async fn expected_error_with_the_wrong_predicate_is_caught() {
    let report = run::<ExpectedErrorWrongKindSubject>().await;
    assert!(
        !report.failures.is_empty(),
        "a real error that doesn't match the declared expected_error predicate must be caught"
    );
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.contains("didn't match the declared expected_error predicate")),
        "got: {:#?}",
        report.failures
    );
}

#[tokio::test]
async fn expected_error_but_stream_chat_succeeds_is_caught() {
    let report = run::<ExpectedErrorButSucceedsSubject>().await;
    assert!(
        !report.failures.is_empty(),
        "an expected-error case whose provider actually succeeds must be caught"
    );
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.contains("returned a successful stream")),
        "got: {:#?}",
        report.failures
    );
}
