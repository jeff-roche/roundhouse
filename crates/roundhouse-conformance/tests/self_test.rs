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
