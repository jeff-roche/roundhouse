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
use roundhouse_provider::credential::{CredentialCtx, CredentialError, CredentialProvider};
use roundhouse_provider::{
    BoxFut, Capabilities, ChatRequest, ChatStream, HttpRequest, ModelId, Plan, Provider,
    ProviderError, RequestCtx, TokenCount,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

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

/// Fix-round-2 J2: proves `ConformanceSubject::credentials()`'s return value
/// actually reaches the `RequestCtx` passed to `Provider::stream_chat`, and
/// is a real, usable `CredentialProvider` (not just an opaque `Some`) --
/// inside this crate itself, not only by a downstream consumer like
/// `bedrock-converse`'s conformance test, which could be deleted or changed
/// without this capability ever being exercised again in its own crate.
///
/// `FakeCredential::apply` flips a shared flag; the fake provider calls
/// `apply` on whatever `ctx.credentials` holds (mirroring exactly what a
/// real SigV4-style provider does), so the flag can only be `true` after
/// `run::<S>()` if `S::credentials()`'s value genuinely arrived in the
/// `RequestCtx` `check_fold_determinism` built and was a real,
/// callable `CredentialProvider`.
struct FakeCredential {
    applied: Arc<AtomicBool>,
}

impl CredentialProvider for FakeCredential {
    fn apply<'a>(
        &'a self,
        _req: &'a mut HttpRequest,
        _ctx: &'a CredentialCtx<'a>,
    ) -> BoxFut<'a, Result<(), CredentialError>> {
        Box::pin(async move {
            self.applied.store(true, Ordering::SeqCst);
            Ok(())
        })
    }
}

struct CredentialAwareFakeProvider;

impl Provider for CredentialAwareFakeProvider {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        Capabilities::default()
    }

    fn resolve(&self, _req: &ChatRequest) -> Result<Plan, ProviderError> {
        Ok(Plan {
            endpoint: "https://fake.invalid/credential-aware".into(),
        })
    }

    fn stream_chat<'a>(
        &'a self,
        _req: &'a ChatRequest,
        ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<ChatStream, ProviderError>> {
        Box::pin(async move {
            // Exactly the shape every real credential-required provider
            // (e.g. `bedrock-converse`) uses: call `apply` on whatever
            // `ctx.credentials` holds, never matching on its concrete kind.
            if let Some(credentials) = &ctx.credentials {
                let mut dummy_req = HttpRequest {
                    method: "POST".into(),
                    url: "https://fake.invalid".into(),
                    headers: vec![],
                    body: vec![],
                };
                let cred_ctx = CredentialCtx {
                    provider_id: "fake",
                    transport: ctx.transport.as_ref(),
                    now: std::time::Instant::now(),
                };
                credentials
                    .apply(&mut dummy_req, &cred_ctx)
                    .await
                    .expect("FakeCredential::apply never fails");
            } else {
                panic!(
                    "expected ctx.credentials to be Some -- ConformanceSubject::credentials() \
                     did not reach the RequestCtx built for this case"
                );
            }
            Ok(fixtures::good_stream())
        })
    }

    fn count_tokens<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<TokenCount, ProviderError>> {
        Box::pin(async { Ok(TokenCount::default()) })
    }
}

struct CredentialAwareSubject;

impl ConformanceSubject for CredentialAwareSubject {
    type Provider = CredentialAwareFakeProvider;

    fn provider() -> Self::Provider {
        CredentialAwareFakeProvider
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

    fn credentials() -> Option<Arc<dyn CredentialProvider>> {
        Some(Arc::new(FakeCredential {
            applied: shared_flag().clone(),
        }))
    }
}

/// One process-wide flag `CredentialAwareSubject`'s `provider()` and
/// `credentials()` both read -- neither is a method that can carry its own
/// state (`ConformanceSubject`'s methods take no `&self`), so this is the
/// simplest way for the fake credential and the fake provider built from two
/// separate trait methods to share one observable flag.
fn shared_flag() -> &'static Arc<AtomicBool> {
    static FLAG: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();
    FLAG.get_or_init(|| Arc::new(AtomicBool::new(false)))
}

#[tokio::test]
async fn conformance_subjects_credentials_reach_the_request_ctx_stream_chat_receives() {
    shared_flag().store(false, Ordering::SeqCst);
    let report = run::<CredentialAwareSubject>().await;
    report.assert_green();
    assert!(
        shared_flag().load(Ordering::SeqCst),
        "FakeCredential::apply was never called -- ConformanceSubject::credentials()'s value \
         did not reach the RequestCtx passed to stream_chat"
    );
}
