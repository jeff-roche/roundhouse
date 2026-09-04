//! Task 30 (Phase 5, Subsystem D1): the embedded-asset router.
//!
//! Every test here asserts on a *payload* — the exact bytes of the embedded
//! file, or the exact header value — rather than on status alone. A router
//! that returned `index.html` for every path would pass a status-only suite;
//! `an_unknown_asset_path_is_a_404_rather_than_a_silent_index_html_fallback`
//! is the one that rules that router out.

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use roundhouse_web::WebAssets;
use tower::ServiceExt;

/// The bytes `rust-embed` compiled into this test binary for `index.html`.
fn embedded_index_html() -> Vec<u8> {
    WebAssets::get("index.html")
        .expect("crates/roundhouse-web/assets/dist/index.html must be embedded")
        .data
        .into_owned()
}

async fn get(uri: &str) -> Response {
    roundhouse_web::asset_router()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .expect("asset router is infallible")
}

async fn body_bytes(response: Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body fits in 64 KiB")
        .to_vec()
}

#[tokio::test]
async fn an_embedded_asset_is_served_with_the_content_type_rust_embed_recorded_for_it() {
    let response = get("/index.html").await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .expect("an embedded asset response declares its content type"),
        "text/html",
    );
    assert_eq!(body_bytes(response).await, embedded_index_html());
}

#[tokio::test]
async fn the_site_root_serves_the_embedded_index_html() {
    let response = get("/").await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_bytes(response).await, embedded_index_html());
}

/// §11.1's shared route table (`docs/architecture/08-ui-design.md`): these are
/// client-side routes owned by the browser router, so the server's whole job
/// is to hand back the app shell.
#[tokio::test]
async fn every_client_route_in_the_shared_route_table_serves_the_index_html_shell() {
    let index = embedded_index_html();
    let client_routes = [
        "/w/default",
        "/w/default/inbox",
        "/w/default/tree",
        "/w/default/messages",
        "/w/default/runs",
        "/w/default/search",
        "/w/default/cost",
        "/w/default/s/sess-1",
        "/w/default/s/sess-1/t/task-1",
        "/w/default/s/sess-1/t/task-1/diff",
        "/settings",
        "/settings/providers",
    ];

    for route in client_routes {
        let response = get(route).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "{route} is a §11.1 client route and must serve the shell"
        );
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .unwrap_or_else(|| panic!("{route} response declares a content type")),
            "text/html",
            "{route} must serve the HTML shell, not an octet-stream blob"
        );
        assert_eq!(
            body_bytes(response).await,
            index,
            "{route} must serve the exact embedded index.html bytes"
        );
    }
}

/// The SPA fallback must not swallow real 404s: an asset the client asked for
/// by name and that is not embedded has to fail loudly, or a missing bundle
/// reaches the browser as HTML with a 200 and fails as a MIME-type error
/// nobody can trace back to the build.
#[tokio::test]
async fn an_unknown_asset_path_is_a_404_rather_than_a_silent_index_html_fallback() {
    let index = embedded_index_html();
    let unknown_assets = [
        "/app.js",
        "/assets/main-deadbeef.js",
        "/static/style.css",
        "/favicon.ico",
        "/w/default/../../etc/passwd",
        "/not-a-route/at-all",
    ];

    for path in unknown_assets {
        let response = get(path).await;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{path} is neither an embedded asset nor a §11.1 client route"
        );
        assert_ne!(
            body_bytes(response).await,
            index,
            "{path} must not be answered with the index.html shell"
        );
    }
}

/// A path that *looks* like a `/w/...` route but does not match any §11.1
/// pattern is a 404, not a shell — otherwise the fallback is "anything under
/// `/w/`" rather than the route table it claims to implement.
#[tokio::test]
async fn a_malformed_w_route_is_not_treated_as_a_client_route() {
    for path in [
        "/w",
        "/w/default/not-a-view",
        "/w/default/s",
        "/w/default/s/sess-1/t",
        "/w/default/s/sess-1/t/task-1/blame",
    ] {
        let response = get(path).await;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{path} matches no §11.1 route pattern"
        );
    }
}

#[tokio::test]
async fn build_router_serves_the_same_assets_as_the_bare_asset_router() {
    let response = roundhouse_web::build_router(roundhouse_web::AppState::default())
        .oneshot(
            Request::builder()
                .uri("/w/default/inbox")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router is infallible");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_bytes(response).await, embedded_index_html());
}
