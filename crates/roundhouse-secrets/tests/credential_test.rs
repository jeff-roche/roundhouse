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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
async fn bearer_apply_is_idempotent_across_a_retry() {
    // A7: `apply` may run more than once on the same request (a retry
    // re-applies the same credential to the same request object). A second
    // `apply` must not accumulate a second `authorization` header.
    let cred = BearerCredential::new(Secret::new("sk-test-123".to_string()));
    let t = NullTransport;
    let mut req = empty_request();
    cred.apply(&mut req, &ctx(&t)).await.unwrap();
    cred.apply(&mut req, &ctx(&t)).await.unwrap();
    let count = req
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .count();
    assert_eq!(count, 1, "repeat apply must not duplicate the header");
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

#[tokio::test]
async fn header_key_apply_is_idempotent_across_a_retry() {
    let cred = HeaderKeyCredential::new("x-api-key".to_string(), Secret::new("k-abc".to_string()));
    let t = NullTransport;
    let mut req = empty_request();
    cred.apply(&mut req, &ctx(&t)).await.unwrap();
    cred.apply(&mut req, &ctx(&t)).await.unwrap();
    let count = req
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("x-api-key"))
        .count();
    assert_eq!(count, 1, "repeat apply must not duplicate the header");
}

/// A record of one request `FakeOAuthTransport` received, so tests can
/// assert body/header fidelity rather than only "the fake returned a fixed
/// token" — the earlier version of this fake discarded the request
/// entirely, which is precisely why a JSON-encoded (RFC 6749-violating)
/// token request and a dropped Entra `scope` were both invisible to a green
/// test suite.
#[derive(Clone)]
struct CapturedRequest {
    #[allow(dead_code)]
    method: String,
    #[allow(dead_code)]
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Tracks call count, captures every request it receives, and adds
/// artificial latency so a real single-flight bug (racing callers each
/// firing their own refresh) is actually reachable and catchable by
/// `oauth_refresh_single_flights_concurrent_callers_through_one_network_call`
/// below.
struct FakeOAuthTransport {
    call_count: AtomicUsize,
    captured: Mutex<Vec<CapturedRequest>>,
    respond_status: u16,
}
impl FakeOAuthTransport {
    fn new() -> Self {
        Self {
            call_count: AtomicUsize::new(0),
            captured: Mutex::new(Vec::new()),
            respond_status: 200,
        }
    }

    fn with_status(status: u16) -> Self {
        Self {
            respond_status: status,
            ..Self::new()
        }
    }

    fn last_request(&self) -> CapturedRequest {
        self.captured
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("no request captured yet")
    }
}
impl HttpTransport for FakeOAuthTransport {
    fn send<'a>(
        &'a self,
        req: HttpRequest,
    ) -> BoxFuture<'a, Result<HttpResponseStream, TransportError>> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        self.captured.lock().unwrap().push(CapturedRequest {
            method: req.method.clone(),
            url: req.url.clone(),
            headers: req.headers.clone(),
            body: req.body.clone(),
        });
        let status = self.respond_status;
        Box::pin(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let body: Vec<u8> = if (200..300).contains(&status) {
                br#"{"access_token":"fresh-token","expires_in":3600}"#.to_vec()
            } else {
                br#"{"error":"invalid_client"}"#.to_vec()
            };
            Ok(HttpResponseStream {
                status,
                headers: vec![],
                body: Box::pin(futures::stream::iter(vec![Ok(Bytes::from(body))])),
            })
        })
    }
}

#[tokio::test]
async fn oauth_refresh_caches_across_sequential_calls() {
    let cred = Arc::new(
        OAuthRefreshCredential::new(
            "https://auth.example.com/token",
            "client-1",
            Secret::new("secret".to_string()),
        )
        .unwrap(),
    );
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
    let cred = Arc::new(
        OAuthRefreshCredential::new(
            "https://auth.example.com/token",
            "client-1",
            Secret::new("secret".to_string()),
        )
        .unwrap(),
    );
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
async fn oauth_refresh_sends_a_form_urlencoded_body_not_json() {
    // A2: RFC 6749 §4.4.2 and both Entra endpoints require
    // `application/x-www-form-urlencoded`, not JSON. The earlier version of
    // this credential sent JSON, and the earlier version of this fake
    // transport discarded the request entirely, which is why that defect
    // was invisible to a green test suite.
    let cred = OAuthRefreshCredential::new(
        "https://auth.example.com/token",
        "client-1",
        Secret::new("shh".to_string()),
    )
    .unwrap();
    let t = FakeOAuthTransport::new();
    let mut req = empty_request();
    cred.apply(&mut req, &ctx(&t)).await.unwrap();

    let sent = t.last_request();
    assert_eq!(
        sent.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str()),
        Some("application/x-www-form-urlencoded"),
    );
    let fields: std::collections::HashMap<String, String> = url::form_urlencoded::parse(&sent.body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert_eq!(
        fields.get("grant_type").map(String::as_str),
        Some("client_credentials")
    );
    assert_eq!(
        fields.get("client_id").map(String::as_str),
        Some("client-1")
    );
    assert_eq!(fields.get("client_secret").map(String::as_str), Some("shh"));
    assert!(
        !fields.contains_key("scope"),
        "plain OAuthRefreshCredential::new must not send a scope field"
    );
}

#[tokio::test]
async fn oauth_refresh_does_not_cache_a_non_200_token_response() {
    // Minor 7: a non-200 response body that happens to parse must not be
    // cached (and must not be treated as a fresh token).
    let cred = OAuthRefreshCredential::new(
        "https://auth.example.com/token",
        "client-1",
        Secret::new("secret".to_string()),
    )
    .unwrap();
    let t = FakeOAuthTransport::with_status(400);
    let mut req = empty_request();
    let err = cred.apply(&mut req, &ctx(&t)).await.unwrap_err();
    assert!(err.to_string().contains("400"));
    assert_eq!(
        t.call_count.load(Ordering::SeqCst),
        1,
        "first call reaches the network"
    );

    // A second call must hit the network again — nothing was cached.
    let mut req2 = empty_request();
    let _ = cred.apply(&mut req2, &ctx(&t)).await;
    assert_eq!(
        t.call_count.load(Ordering::SeqCst),
        2,
        "a failed refresh must not be cached, so a second call refreshes again"
    );
}

#[tokio::test]
async fn oauth_refresh_reports_transport_failure_as_host_only() {
    // A5: never surface a transport error's full `Display` (which, for a
    // real reqwest-backed transport, can include the URL's userinfo
    // component) — report the host only.
    struct FailingTransport;
    impl HttpTransport for FailingTransport {
        fn send<'a>(
            &'a self,
            _req: HttpRequest,
        ) -> BoxFuture<'a, Result<HttpResponseStream, TransportError>> {
            Box::pin(async {
                Err(TransportError::Io(
                    "connection refused for url (https://evil:leaked-password@auth.example.com/token)"
                        .to_string(),
                ))
            })
        }
    }
    let cred = OAuthRefreshCredential::new(
        "https://auth.example.com/token",
        "client-1",
        Secret::new("secret".to_string()),
    )
    .unwrap();
    let mut req = empty_request();
    let err = cred
        .apply(&mut req, &ctx(&FailingTransport))
        .await
        .unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("auth.example.com"),
        "error should still name the host: {message}"
    );
    assert!(
        !message.contains("leaked-password"),
        "error must never carry the transport error's raw Display: {message}"
    );
}

#[tokio::test]
async fn oauth_refresh_rejects_a_non_https_refresh_url_at_construction() {
    let err = OAuthRefreshCredential::new(
        "http://auth.example.com/token",
        "client-1",
        Secret::new("secret".to_string()),
    )
    .err()
    .unwrap();
    assert!(err.to_string().contains("https"));
}

#[tokio::test]
async fn oauth_refresh_rejects_a_refresh_url_with_embedded_userinfo() {
    let err = OAuthRefreshCredential::new(
        "https://user:pass@auth.example.com/token",
        "client-1",
        Secret::new("secret".to_string()),
    )
    .err()
    .unwrap();
    assert!(err.to_string().contains("userinfo"));
}

#[tokio::test]
async fn azure_entra_applies_bearer_shape_identical_to_a_static_token() {
    let cred = AzureEntraCredential::new(
        "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
        "client-2",
        Secret::new("secret2".to_string()),
        "https://cognitiveservices.azure.com/.default",
    )
    .unwrap();
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
async fn azure_entra_threads_scope_into_the_token_request_body() {
    // A2: Entra's v2.0 endpoint makes `scope` REQUIRED for
    // `grant_type=client_credentials` and returns `AADSTS900144` without
    // it. An earlier draft accepted `scope` and silently dropped it.
    let cred = AzureEntraCredential::new(
        "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
        "client-2",
        Secret::new("secret2".to_string()),
        "https://cognitiveservices.azure.com/.default",
    )
    .unwrap();
    let t = FakeOAuthTransport::new();
    let mut req = empty_request();
    cred.apply(&mut req, &ctx(&t)).await.unwrap();

    let sent = t.last_request();
    let fields: std::collections::HashMap<String, String> = url::form_urlencoded::parse(&sent.body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert_eq!(
        fields.get("scope").map(String::as_str),
        Some("https://cognitiveservices.azure.com/.default"),
    );
    assert_eq!(
        fields.get("grant_type").map(String::as_str),
        Some("client_credentials")
    );
    assert_eq!(
        fields.get("client_id").map(String::as_str),
        Some("client-2")
    );
}

#[tokio::test]
async fn exec_command_runs_helper_and_applies_stdout_as_bearer() {
    let cred = ExecCommandCredential::new(
        "/usr/bin/printf".into(),
        vec!["exec-token-xyz".into()],
        vec![],
    )
    .unwrap();
    let t = NullTransport;
    let mut req = empty_request();
    cred.apply(&mut req, &ctx(&t)).await.unwrap();
    assert_eq!(header(&req, "authorization"), Some("Bearer exec-token-xyz"));
}

#[test]
fn exec_command_rejects_a_relative_command_path() {
    // A3: no `PATH` search — a bare/relative command name is rejected at
    // construction, so a hostile or hijacked `PATH` entry can never be
    // substituted for the configured helper.
    let err = ExecCommandCredential::new("printf".into(), vec![], vec![])
        .err()
        .unwrap();
    assert!(err.to_string().contains("absolute path"));
}

#[tokio::test]
async fn exec_command_rejects_empty_stdout() {
    let cred = ExecCommandCredential::new("/usr/bin/true".into(), vec![], vec![]).unwrap();
    let t = NullTransport;
    let mut req = empty_request();
    let err = cred.apply(&mut req, &ctx(&t)).await.unwrap_err();
    assert!(err.to_string().contains("empty"));
}

#[tokio::test]
async fn exec_command_rejects_stdout_over_the_size_cap() {
    // `head -c 20000 /dev/zero` terminates immediately (unlike an infinite
    // producer, which would only ever be caught by the timeout below), so
    // this exercises the length check itself.
    let cred = ExecCommandCredential::new(
        "/usr/bin/head".into(),
        vec!["-c".into(), "20000".into(), "/dev/zero".into()],
        vec![],
    )
    .unwrap();
    let t = NullTransport;
    let mut req = empty_request();
    let err = cred.apply(&mut req, &ctx(&t)).await.unwrap_err();
    assert!(err.to_string().contains("exceeded"));
}

#[tokio::test]
async fn exec_command_kills_a_hung_helper_after_its_timeout() {
    let cred = ExecCommandCredential::new("/usr/bin/sleep".into(), vec!["5".into()], vec![])
        .unwrap()
        .with_timeout(Duration::from_millis(50));
    let t = NullTransport;
    let mut req = empty_request();
    let started = Instant::now();
    let err = cred.apply(&mut req, &ctx(&t)).await.unwrap_err();
    assert!(err.to_string().contains("timed out"));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "a hung helper must not wedge the request until its real 5s sleep finishes"
    );
}

#[tokio::test]
async fn exec_command_does_not_inherit_the_calling_processs_environment() {
    // A3: the helper must never receive the daemon's ambient environment.
    // `/usr/bin/env` with no arguments prints every env var it can see; with
    // an empty allow-list and a cleared environment, it must see none.
    std::env::set_var("ROUNDHOUSE_TEST_AMBIENT_PROBE", "leaked-value");
    let cred = ExecCommandCredential::new("/usr/bin/env".into(), vec![], vec![]).unwrap();
    let t = NullTransport;
    let mut req = empty_request();
    let err = cred.apply(&mut req, &ctx(&t)).await.unwrap_err();
    // Empty environment -> `env` prints nothing -> rejected as empty stdout,
    // which is itself the proof nothing ambient leaked through.
    assert!(err.to_string().contains("empty"));
    std::env::remove_var("ROUNDHOUSE_TEST_AMBIENT_PROBE");
}

#[tokio::test]
async fn exec_command_passes_only_the_explicit_env_allowlist() {
    let cred = ExecCommandCredential::new(
        "/usr/bin/env".into(),
        vec![],
        vec![(
            "ROUNDHOUSE_TEST_ALLOWED_VAR".to_string(),
            "hello".to_string(),
        )],
    )
    .unwrap();
    let t = NullTransport;
    let mut req = empty_request();
    cred.apply(&mut req, &ctx(&t)).await.unwrap();
    assert_eq!(
        header(&req, "authorization"),
        Some("Bearer ROUNDHOUSE_TEST_ALLOWED_VAR=hello")
    );
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

#[tokio::test]
async fn sigv4_apply_is_idempotent_across_a_retry() {
    // A7: a stale `authorization`/`x-amz-*` header from a prior signing pass
    // must not fold into the next canonical-request hash — re-signing the
    // same request twice must produce identical headers, not duplicates or
    // a corrupted signature.
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
    let first_auth = header(&req, "authorization").unwrap().to_string();
    cred.apply(&mut req, &ctx(&t)).await.unwrap();
    let second_auth = header(&req, "authorization").unwrap().to_string();
    assert_eq!(first_auth, second_auth);
    for name in ["authorization", "x-amz-date", "host"] {
        let count = req
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .count();
        assert_eq!(
            count, 1,
            "`{name}` must not be duplicated by a repeat apply"
        );
    }
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

/// A8: extends the known-answer coverage to a multi-parameter,
/// non-lexicographically-ordered query string (`z=1&a=2&m=3`) — the
/// original KAT above has no query string at all, so it could not have
/// caught a canonicalization bug in query-parameter sorting/encoding.
/// Expected canonical request/signature independently computed with the
/// same from-scratch Python `hmac`/`hashlib` implementation used for the
/// vanilla case above, over this input.
#[test]
fn sigv4_signs_a_multi_parameter_out_of_order_query_string() {
    let secret_key = Secret::new("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string());
    let url = url::Url::parse("https://example.amazonaws.com/?z=1&a=2&m=3").unwrap();
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
    assert_eq!(
        auth,
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
         SignedHeaders=host;x-amz-date, \
         Signature=ccbc54434cc9e22adb2e74b578bd557d8a5d35d9e9c46c352ddaf22c4e37053e"
    );
}

/// Whitespace-tolerant occurrence count: a literal-substring scan of
/// `expose_secret_for_provider_call(` would silently undercount a call site
/// written as `expose_secret_for_provider_call (` (a space before the
/// paren) — this walks the identifier and then skips whitespace before
/// checking for the opening paren, so reformatting can't hide a site from
/// the ratchet.
fn count_expose_call_sites(haystack: &str) -> usize {
    const NEEDLE: &str = "expose_secret_for_provider_call";
    let mut count = 0;
    let mut idx = 0;
    while let Some(pos) = haystack[idx..].find(NEEDLE) {
        let after = idx + pos + NEEDLE.len();
        if haystack[after..].trim_start().starts_with('(') {
            count += 1;
        }
        idx = after;
    }
    count
}

/// The only two files in this crate where `.expose_secret(`,
/// `expose_within_control_lane`, and `SecretString` are SUPPOSED to appear:
/// `secret.rs` defines `Secret` and its `pub(crate)` exposure method (Phase
/// 2, already proven by that phase's own `trybuild` compile-fail tests —
/// re-litigating it here is out of this ratchet's scope), and `lib.rs`
/// defines the two bridge functions (`provider_bridge`/`mcp_bridge`) that
/// are the sanctioned callers of that method. Everything else in `src/` —
/// this crate's `credential/` tree included — must go through
/// `provider_bridge::expose_secret_for_provider_call` only.
const SANCTIONED_EXPOSURE_FILES: &[&str] = &["secret.rs", "lib.rs"];

#[test]
fn credential_module_never_reads_secret_material_outside_the_bridge() {
    // §9.9 / REALITY-CORRECTIONS §6: replacement ratchet for the plan's
    // "exactly four expose() call sites" — every read of secret material in
    // this crate goes through `provider_bridge::expose_secret_for_provider_call`,
    // never `Secret`'s own `pub(crate)` exposure method directly, and this
    // crate never touches `SecretString` (the underlying `secrecy` type)
    // itself. Scans the WHOLE crate (`src/`), not just `src/credential/`, so
    // a new exposure site added elsewhere in the crate can't hide from it —
    // the two files where the primitive and its bridge are legitimately
    // defined are the sole, explicit exception (see
    // `SANCTIONED_EXPOSURE_FILES`).
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut expose_call_sites = 0usize;
    let mut forbidden_hits = Vec::new();
    for entry in walkdir::WalkDir::new(&src_dir)
        .into_iter()
        .filter_map(Result::ok)
    {
        if entry.path().extension().is_some_and(|e| e == "rs") {
            let contents = std::fs::read_to_string(entry.path()).unwrap();
            expose_call_sites += count_expose_call_sites(&contents);
            let is_sanctioned = entry
                .path()
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| SANCTIONED_EXPOSURE_FILES.contains(&n));
            if is_sanctioned {
                continue;
            }
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
        "src/ must never touch these directly outside secret.rs/lib.rs: {forbidden_hits:?}"
    );
    assert_eq!(
        expose_call_sites, 5,
        "expose_secret_for_provider_call( call-site count is {expose_call_sites}, expected 5 \
         — see credential/mod.rs's module doc comment's \"Call-site accounting\" section before \
         changing this ratchet"
    );
}
