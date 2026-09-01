//! Phase 6 Task 2: the six concrete `CredentialProvider` implementations
//! (§9.9), adapted from the task brief's `resolve()`-shaped tests to the
//! real `apply(&mut HttpRequest, &CredentialCtx) -> Result<(), _>` shape
//! (REALITY-CORRECTIONS §6 — `CredentialProvider::apply` mutates a request
//! in place and never returns secret material).

use bytes::Bytes;
use futures::future::BoxFuture;
use roundhouse_provider::credential::{CredentialCtx, CredentialProvider};
use roundhouse_provider::{HttpRequest, HttpResponseStream, HttpTransport, TransportError};
use roundhouse_secrets::credential::{
    AzureEntraCredential, BearerCredential, ExecCommandCredential, HeaderKeyCredential,
    OAuthRefreshCredential, SigV4Credential,
};
use roundhouse_secrets::secret::Secret;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

struct NullTransport;
impl HttpTransport for NullTransport {
    fn send<'a>(
        &'a self,
        _req: HttpRequest,
    ) -> BoxFuture<'a, Result<HttpResponseStream, TransportError>> {
        Box::pin(async { panic!("this test's credential mechanism should not need HTTP") })
    }
}

fn ctx(transport: &dyn HttpTransport) -> CredentialCtx<'_> {
    CredentialCtx {
        provider_id: "test",
        transport,
        now: Instant::now(),
    }
}

fn empty_request() -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        url: "https://api.example.com/v1/thing".into(),
        headers: vec![],
        body: vec![],
    }
}

fn header<'a>(req: &'a HttpRequest, name: &str) -> Option<&'a str> {
    req.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

#[tokio::test]
async fn bearer_applies_static_token_as_authorization_header() {
    let cred = BearerCredential::new(Secret::new("sk-test-123".to_string()));
    let t = NullTransport;
    let mut req = empty_request();
    cred.apply(&mut req, &ctx(&t)).await.unwrap();
    assert_eq!(header(&req, "authorization"), Some("Bearer sk-test-123"));
}

#[tokio::test]
async fn header_key_applies_value_under_configured_header_name() {
    let cred = HeaderKeyCredential::new("x-api-key".to_string(), Secret::new("k-abc".to_string()));
    let t = NullTransport;
    let mut req = empty_request();
    cred.apply(&mut req, &ctx(&t)).await.unwrap();
    assert_eq!(header(&req, "x-api-key"), Some("k-abc"));
    assert!(
        header(&req, "authorization").is_none(),
        "header-key credential must not also set Authorization"
    );
}

/// Tracks call count and adds artificial latency so a real single-flight bug
/// (racing callers each firing their own refresh) is actually reachable and
/// catchable by `oauth_refresh_single_flights_concurrent_callers_through_one_network_call`
/// below — a fake that just returned the same body unconditionally with no
/// way to observe call count would let that test pass even against a
/// completely non-single-flighted implementation.
struct FakeOAuthTransport {
    call_count: AtomicUsize,
}
impl FakeOAuthTransport {
    fn new() -> Self {
        Self {
            call_count: AtomicUsize::new(0),
        }
    }
}
impl HttpTransport for FakeOAuthTransport {
    fn send<'a>(
        &'a self,
        _req: HttpRequest,
    ) -> BoxFuture<'a, Result<HttpResponseStream, TransportError>> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let body: Vec<u8> = br#"{"access_token":"fresh-token","expires_in":3600}"#.to_vec();
            Ok(HttpResponseStream {
                status: 200,
                headers: vec![],
                body: Box::pin(futures::stream::iter(vec![Ok(Bytes::from(body))])),
            })
        })
    }
}

#[tokio::test]
async fn oauth_refresh_caches_across_sequential_calls() {
    let cred = Arc::new(OAuthRefreshCredential::new(
        "https://auth.example.com/token",
        "client-1",
        Secret::new("secret".to_string()),
    ));
    let t = FakeOAuthTransport::new();

    let mut req_a = empty_request();
    cred.apply(&mut req_a, &ctx(&t)).await.unwrap();
    let mut req_b = empty_request();
    cred.apply(&mut req_b, &ctx(&t)).await.unwrap(); // must hit the cache, not refresh again

    assert_eq!(header(&req_a, "authorization"), Some("Bearer fresh-token"));
    assert_eq!(header(&req_b, "authorization"), Some("Bearer fresh-token"));
    assert_eq!(
        t.call_count.load(Ordering::SeqCst),
        1,
        "second sequential call must be served from cache, not a second network call"
    );
}

#[tokio::test]
async fn oauth_refresh_single_flights_concurrent_callers_through_one_network_call() {
    // §9.9: "single-flight, 60s skew." Ten callers race against an EMPTY
    // cache concurrently. `OAuthRefreshCredential::apply` holds its cache
    // mutex across the whole refresh await, so every concurrent caller
    // either does the one real refresh or blocks until it lands and then
    // reads the now-populated cache — never firing its own.
    let cred = Arc::new(OAuthRefreshCredential::new(
        "https://auth.example.com/token",
        "client-1",
        Secret::new("secret".to_string()),
    ));
    let t = Arc::new(FakeOAuthTransport::new());
    let mut handles = Vec::new();
    for _ in 0..10 {
        let cred = Arc::clone(&cred);
        let transport = Arc::clone(&t);
        handles.push(tokio::spawn(async move {
            let mut req = empty_request();
            let cred_ctx = CredentialCtx {
                provider_id: "test",
                transport: transport.as_ref(),
                now: Instant::now(),
            };
            cred.apply(&mut req, &cred_ctx).await.unwrap();
            req
        }));
    }
    for h in handles {
        let req = h.await.unwrap();
        assert_eq!(header(&req, "authorization"), Some("Bearer fresh-token"));
    }
    let calls = t.call_count.load(Ordering::SeqCst);
    assert_eq!(
        calls, 1,
        "single-flight must collapse 10 concurrent callers into exactly 1 network call, got {calls}"
    );
}

#[tokio::test]
async fn azure_entra_applies_bearer_shape_identical_to_a_static_token() {
    let cred = AzureEntraCredential::new(
        "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
        "client-2",
        Secret::new("secret2".to_string()),
        "https://cognitiveservices.azure.com/.default",
    );
    let t = FakeOAuthTransport::new();
    let mut req = empty_request();
    cred.apply(&mut req, &ctx(&t)).await.unwrap();
    assert_eq!(
        header(&req, "authorization"),
        Some("Bearer fresh-token"),
        "Azure Entra must resolve to the same Bearer wire shape as a static token"
    );
}

#[tokio::test]
async fn exec_command_runs_helper_and_applies_stdout_as_bearer() {
    let cred = ExecCommandCredential::new("printf".into(), vec!["exec-token-xyz".into()]);
    let t = NullTransport;
    let mut req = empty_request();
    cred.apply(&mut req, &ctx(&t)).await.unwrap();
    assert_eq!(header(&req, "authorization"), Some("Bearer exec-token-xyz"));
}

#[tokio::test]
async fn sigv4_applies_signature_with_identifier_kept_out_of_secret_wrapper() {
    let cred = SigV4Credential::new(
        "AKIAEXAMPLE",
        Secret::new("wJalrXUtnFEMI".to_string()),
        None,
        "us-east-1",
        "execute-api",
    );
    let t = NullTransport;
    let mut req = empty_request();
    cred.apply(&mut req, &ctx(&t)).await.unwrap();
    let auth = header(&req, "authorization").expect("SigV4 must set an Authorization header");
    assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/"));
    assert!(header(&req, "x-amz-date").is_some());
    assert!(header(&req, "x-amz-security-token").is_none());
}

#[tokio::test]
async fn sigv4_carries_session_token_header_when_present() {
    let cred = SigV4Credential::new(
        "AKIAEXAMPLE",
        Secret::new("wJalrXUtnFEMI".to_string()),
        Some(Secret::new("session-tok-abc".to_string())),
        "us-east-1",
        "bedrock",
    );
    let t = NullTransport;
    let mut req = empty_request();
    cred.apply(&mut req, &ctx(&t)).await.unwrap();
    assert_eq!(
        header(&req, "x-amz-security-token"),
        Some("session-tok-abc")
    );
}

/// Known-answer test against AWS's own published SigV4 worked example (the
/// "get-vanilla" case from AWS's `aws-sig-v4-test-suite`): access key
/// `AKIDEXAMPLE`, secret key `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`, a
/// `GET /` to `https://example.amazonaws.com/` with no extra headers or
/// body, region `us-east-1`, service `service`, timestamp
/// `20150830T123600Z`, must sign to exactly the documented signature. This
/// pins the crypto math itself, not just "a header got set."
#[test]
fn sigv4_signs_the_aws_published_get_vanilla_test_vector() {
    let secret_key = Secret::new("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string());
    let url = url::Url::parse("https://example.amazonaws.com/").unwrap();
    let now = chrono::DateTime::parse_from_rfc3339("2015-08-30T12:36:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let mut headers = Vec::new();
    roundhouse_secrets::credential::sigv4::sign(
        "AKIDEXAMPLE",
        &secret_key,
        None,
        "us-east-1",
        "service",
        "GET",
        &url,
        &mut headers,
        b"",
        now,
    )
    .unwrap();
    let auth = headers
        .iter()
        .find(|(k, _)| k == "authorization")
        .map(|(_, v)| v.as_str())
        .expect("sign() must set an authorization header");
    // Signature independently cross-checked with a from-scratch Python
    // `hmac`/`hashlib` implementation of the same documented algorithm
    // steps (canonical request -> string-to-sign -> derived signing key ->
    // final HMAC) against this exact input, not copied from memory.
    assert_eq!(
        auth,
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
         SignedHeaders=host;x-amz-date, \
         Signature=ea21d6f05e96a897f6000a1a293f0a5bf0f92a00343409e820dce329ca6365ea"
    );
}

#[test]
fn credential_module_never_reads_secret_material_outside_the_bridge() {
    // §9.9 / REALITY-CORRECTIONS §6: replacement ratchet for the plan's
    // "exactly four expose() call sites" — every read of secret material in
    // this tree goes through `provider_bridge::expose_secret_for_provider_call`,
    // never `Secret`'s own `pub(crate)` exposure method directly, and this
    // tree never touches `SecretString` (the underlying `secrecy` type)
    // itself.
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/credential");
    let mut expose_call_sites = 0usize;
    let mut forbidden_hits = Vec::new();
    for entry in walkdir::WalkDir::new(&src_dir)
        .into_iter()
        .filter_map(Result::ok)
    {
        if entry.path().extension().is_some_and(|e| e == "rs") {
            let contents = std::fs::read_to_string(entry.path()).unwrap();
            expose_call_sites += contents.matches("expose_secret_for_provider_call(").count();
            for forbidden in [
                ".expose_secret(",
                "expose_within_control_lane",
                "SecretString",
            ] {
                if contents.contains(forbidden) {
                    forbidden_hits.push(format!("{}: {forbidden}", entry.path().display()));
                }
            }
        }
    }
    assert!(
        forbidden_hits.is_empty(),
        "src/credential must never touch these directly: {forbidden_hits:?}"
    );
    assert_eq!(
        expose_call_sites, 5,
        "expose_secret_for_provider_call( call-site count is {expose_call_sites}, expected 5 \
         — see mod.rs's module doc comment's \"Call-site accounting\" section before changing \
         this ratchet"
    );
}
