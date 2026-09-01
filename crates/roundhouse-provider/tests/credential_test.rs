//! Phase 6 Task 2: `CredentialProvider` trait vocabulary, defined in
//! `roundhouse-provider` (see REALITY-CORRECTIONS §6 for why the six
//! concrete implementations live in `roundhouse-secrets` instead and are
//! tested there, not here).

use roundhouse_provider::credential::{CredentialCtx, CredentialProvider};
use roundhouse_provider::{BoxFut, HttpRequest, RequestCtx};
use std::sync::Arc;

/// A minimal fake `CredentialProvider` — enough to prove the trait's shape
/// is usable end to end via `RequestCtx.credentials` without needing any of
/// the real (secret-holding) implementations from `roundhouse-secrets`.
struct FixedHeaderCredential;

impl CredentialProvider for FixedHeaderCredential {
    fn apply<'a>(
        &'a self,
        req: &'a mut HttpRequest,
        _ctx: &'a CredentialCtx<'a>,
    ) -> BoxFut<'a, Result<(), roundhouse_provider::credential::CredentialError>> {
        Box::pin(async move {
            req.headers
                .push(("x-fixed".to_string(), "fixed-value".to_string()));
            Ok(())
        })
    }
}

struct NullTransport;
impl roundhouse_provider::HttpTransport for NullTransport {
    fn send<'a>(
        &'a self,
        _req: HttpRequest,
    ) -> futures::future::BoxFuture<
        'a,
        Result<roundhouse_provider::HttpResponseStream, roundhouse_provider::TransportError>,
    > {
        Box::pin(async { panic!("this test never sends a real request") })
    }
}

#[tokio::test]
async fn request_ctx_credentials_field_applies_to_a_request() {
    let cred: Arc<dyn CredentialProvider> = Arc::new(FixedHeaderCredential);
    let _ctx = RequestCtx {
        trace_id: None,
        transport: Arc::new(NullTransport),
        api_key: String::new(),
        credentials: Some(Arc::clone(&cred)),
    };

    let mut req = HttpRequest {
        method: "POST".into(),
        url: "https://example.com".into(),
        headers: vec![],
        body: vec![],
    };
    let cred_ctx = CredentialCtx {
        provider_id: "test",
        transport: &NullTransport,
        now: std::time::Instant::now(),
    };
    cred.apply(&mut req, &cred_ctx).await.unwrap();
    assert!(req
        .headers
        .iter()
        .any(|(k, v)| k == "x-fixed" && v == "fixed-value"));
}

#[tokio::test]
async fn request_ctx_credentials_field_carries_a_real_secrets_crate_implementation() {
    // Exercises the actual cross-crate wiring end to end: a real,
    // secret-holding `CredentialProvider` from `roundhouse-secrets` (taken
    // here only as a dev-dependency — see that crate's Cargo.toml comment on
    // the edge) plugged into `RequestCtx.credentials` and applied through
    // the trait object this crate defines.
    use roundhouse_secrets::credential::BearerCredential;
    use roundhouse_secrets::secret::Secret;

    let cred: Arc<dyn CredentialProvider> = Arc::new(BearerCredential::new(Secret::new(
        "sk-real-123".to_string(),
    )));
    let _ctx = RequestCtx {
        trace_id: None,
        transport: Arc::new(NullTransport),
        api_key: String::new(),
        credentials: Some(Arc::clone(&cred)),
    };

    let mut req = HttpRequest {
        method: "POST".into(),
        url: "https://example.com".into(),
        headers: vec![],
        body: vec![],
    };
    let cred_ctx = CredentialCtx {
        provider_id: "test",
        transport: &NullTransport,
        now: std::time::Instant::now(),
    };
    cred.apply(&mut req, &cred_ctx).await.unwrap();
    assert!(req
        .headers
        .iter()
        .any(|(k, v)| k == "authorization" && v == "Bearer sk-real-123"));
}

#[test]
fn request_ctx_credentials_field_defaults_to_none_for_existing_call_sites() {
    // Existing (Phase 1) construction sites keep working untouched with
    // `credentials: None` and the `api_key` path unaffected.
    let ctx = RequestCtx {
        trace_id: None,
        transport: Arc::new(NullTransport),
        api_key: "sk-test".into(),
        credentials: None,
    };
    assert!(ctx.credentials.is_none());
    assert_eq!(ctx.api_key, "sk-test");
}

#[test]
fn base_url_resolution_order_is_override_then_env_then_profile_default() {
    // §9.9: explicit override -> ROUNDHOUSE_<PROVIDER>_BASE_URL env -> profile default.
    std::env::remove_var("ROUNDHOUSE_TESTPROV_BASE_URL");
    let (url, _recorded) = roundhouse_provider::credential::resolve_base_url(
        "testprov",
        "https://default.example.com",
        None,
    )
    .unwrap();
    assert_eq!(url.as_str(), "https://default.example.com/");

    std::env::set_var("ROUNDHOUSE_TESTPROV_BASE_URL", "https://env.example.com");
    let (url, _recorded) = roundhouse_provider::credential::resolve_base_url(
        "testprov",
        "https://default.example.com",
        None,
    )
    .unwrap();
    assert_eq!(url.as_str(), "https://env.example.com/");

    let (url, recorded) = roundhouse_provider::credential::resolve_base_url(
        "testprov",
        "https://default.example.com",
        Some("https://override.example.com/v1?api_key=sk-should-never-appear"),
    )
    .unwrap();
    assert_eq!(
        url.as_str(),
        "https://override.example.com/v1?api_key=sk-should-never-appear",
    );
    // A6: `resolve_base_url` and the host-only recording are structurally
    // inseparable — a caller cannot get the full URL (query string and all)
    // without also getting the safe-to-persist host-only form.
    assert_eq!(recorded, "override.example.com");

    std::env::remove_var("ROUNDHOUSE_TESTPROV_BASE_URL");
}

#[test]
fn provider_src_never_touches_secret_material_directly() {
    // §9.9 / REALITY-CORRECTIONS §6: `roundhouse-provider` defines the
    // `CredentialProvider` trait vocabulary only. It must never gain a
    // `secrecy` dependency or any raw exposure of secret bytes — those live
    // exclusively in `roundhouse-secrets`.
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut secrecy_hits = Vec::new();
    let mut expose_hits = Vec::new();
    for entry in walkdir::WalkDir::new(&src_dir)
        .into_iter()
        .filter_map(Result::ok)
    {
        if entry.path().extension().is_some_and(|e| e == "rs") {
            let contents = std::fs::read_to_string(entry.path()).unwrap();
            if contents.contains("secrecy::") {
                secrecy_hits.push(entry.path().display().to_string());
            }
            if contents.contains("expose") {
                expose_hits.push(entry.path().display().to_string());
            }
        }
    }
    assert!(
        secrecy_hits.is_empty(),
        "roundhouse-provider/src must never reference secrecy::, found in: {secrecy_hits:?}"
    );
    assert!(
        expose_hits.is_empty(),
        "roundhouse-provider/src must never reference secret exposure, found in: {expose_hits:?}"
    );
}

#[test]
fn provider_manifest_never_depends_on_secrecy() {
    // A10: a source-text scan for `secrecy::` is defeated by `use secrecy as
    // s;` — an aliased import never spells that substring anywhere. The
    // manifest check above's text scan can't be renamed around: if
    // `secrecy` isn't a declared dependency at all, no code in this crate
    // can reference it under any alias.
    let manifest_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let manifest = std::fs::read_to_string(&manifest_path).unwrap();
    let declares_secrecy = manifest.lines().any(|line| {
        let key = line
            .trim_start()
            .split(|c: char| c == '=' || c.is_whitespace())
            .next()
            .unwrap_or("");
        key == "secrecy"
    });
    assert!(
        !declares_secrecy,
        "roundhouse-provider's Cargo.toml must never declare a `secrecy` dependency"
    );
}
