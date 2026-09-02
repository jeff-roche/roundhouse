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
fn base_url_parse_failure_never_echoes_the_malformed_override_verbatim() {
    // B1 (fix-round-2): `resolve_base_url`'s own A6 test above proves the
    // host-only pairing works on the SUCCESS path (a well-formed override
    // carrying `?api_key=...`). An earlier version of the parse-FAILURE
    // path (`InvalidBaseUrl(format!("{raw}: {e}"))`) still interpolated the
    // raw string verbatim — so a malformed override carrying the same
    // sensitive query string would land in the error this project persists
    // onto immutable Event rows, even though the well-formed case was
    // already fixed.
    let malformed = "not-a-valid-url-at-all?api_key=sk-should-never-appear";
    let err = roundhouse_provider::credential::resolve_base_url(
        "testprov",
        "https://default.example.com",
        Some(malformed),
    )
    .err()
    .unwrap();
    let message = err.to_string();
    assert!(
        !message.contains("api_key"),
        "parse-failure error must never carry the malformed override's query string: {message}"
    );
    assert!(
        !message.contains("sk-should-never-appear"),
        "parse-failure error must never carry the malformed override's secret-shaped value: {message}"
    );
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
    // s;` — an aliased import never spells that substring anywhere. A
    // dependency can't be renamed away from the manifest the same way, so
    // this parses `Cargo.toml` as TOML rather than scanning its text.
    //
    // B2 (fix-round-2): the previous version of this check DID scan text —
    // splitting each line on `=`/whitespace to get a "key" — which caught
    // `secrecy = "0.10"` but missed two forms a real TOML document allows:
    // dotted-key syntax (`secrecy.workspace = true`, which a genuine TOML
    // parser normalizes into the identical table structure as
    // `secrecy = { workspace = true }`, so parsing catches it automatically)
    // and a rename (`s = { package = "secrecy" }`, checked explicitly below
    // via each entry's own `package` field). The old comment claimed this
    // "cannot be aliased around" — true of a source-text scan, but the
    // manifest-level check itself had the same class of gap; parsing
    // properly closes it instead of just re-claiming it does.
    let manifest_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let manifest = std::fs::read_to_string(&manifest_path).unwrap();
    let parsed: toml::Value = manifest.parse().expect("parse Cargo.toml");
    let mut hits = Vec::new();
    for table_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(table) = parsed.get(table_name).and_then(|t| t.as_table()) {
            scan_dependency_table_for_secrecy(table_name, table, &mut hits);
        }
    }
    // C5 (fix-round-3): platform-scoped dependency tables
    // (`[target.'cfg(unix)'.dependencies]`) are a real, valid place to
    // declare a dependency that the top-level-only scan above would
    // silently miss — B2's whole point was that a ratchet must not
    // overstate its own strength, so this walks them too rather than
    // leaving an unstated gap.
    if let Some(targets) = parsed.get("target").and_then(|t| t.as_table()) {
        for (cfg, target_table) in targets {
            let Some(target_table) = target_table.as_table() else {
                continue;
            };
            for table_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
                if let Some(table) = target_table.get(table_name).and_then(|t| t.as_table()) {
                    scan_dependency_table_for_secrecy(
                        &format!("target.'{cfg}'.{table_name}"),
                        table,
                        &mut hits,
                    );
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "roundhouse-provider's Cargo.toml must never declare a `secrecy` dependency, found: {hits:?}"
    );
}

/// Checks one `[dependencies]`-shaped TOML table (top-level or under a
/// `[target.'cfg(...)'.*]` section) for a `secrecy` dependency, by key name
/// or by an explicit `package = "secrecy"` rename, appending a description
/// of each hit found to `hits`.
fn scan_dependency_table_for_secrecy(
    table_name: &str,
    table: &toml::value::Table,
    hits: &mut Vec<String>,
) {
    for (key, value) in table {
        if key == "secrecy" {
            hits.push(format!("[{table_name}] key `{key}`"));
            continue;
        }
        let renamed_from_secrecy = value
            .get("package")
            .and_then(|p| p.as_str())
            .is_some_and(|p| p == "secrecy");
        if renamed_from_secrecy {
            hits.push(format!(
                "[{table_name}] `{key}` renamed from package = \"secrecy\""
            ));
        }
    }
}
