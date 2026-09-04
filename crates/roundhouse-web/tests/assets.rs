//! Task 30 (Phase 5, Subsystem D1): the embedded-asset router.
//!
//! Every test here asserts on a *payload* — the exact bytes of the embedded
//! file, or the exact header value — rather than on status alone. A router
//! that returned `index.html` for every path would pass a status-only suite;
//! `an_unknown_asset_path_is_a_404_rather_than_a_silent_index_html_fallback`
//! is the one that rules that router out, and
//! `a_css_asset_is_served_as_css_not_as_the_html_shells_content_type` is the
//! one that rules out a handler ignoring `rust-embed`'s recorded type and
//! hardcoding `"text/html"`. No assertion here could rule that out while
//! `assets/dist/` held a single HTML file, because `"text/html"` was then the
//! only value any response could carry; the CSS asset is what gives the
//! header two possible values.

use std::borrow::Cow;
use std::fs;
use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::extract::State;
use axum::http::header::{CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS};
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::routing::get as get_route;
use axum::Router;
use roundhouse_web::{asset_router, AppState, WebAssets};
use tower::ServiceExt;

/// The bytes `rust-embed` compiled into this test binary for `index.html`.
fn embedded_index_html() -> Vec<u8> {
    embedded("index.html")
}

fn embedded(path: &str) -> Vec<u8> {
    WebAssets::get(path)
        .unwrap_or_else(|| panic!("crates/roundhouse-web/assets/dist/{path} must be embedded"))
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

/// The content type must come from what `rust-embed` recorded for the file,
/// not from a constant. `assets/dist/` therefore holds a second asset with a
/// different recorded type: with only `index.html` embedded, `"text/html"` was
/// the only value any response could carry and every content-type assertion in
/// this file passed against a hardcoded one.
#[tokio::test]
async fn a_css_asset_is_served_as_css_not_as_the_html_shells_content_type() {
    let response = get("/app.css").await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .expect("an embedded asset response declares its content type"),
        "text/css",
        "the content type must be the one rust-embed recorded for this file"
    );
    assert_eq!(body_bytes(response).await, embedded("app.css"));
}

/// Every asset response refuses content sniffing. This router answers
/// `/settings/<name>.js` with the HTML shell by design (§11.1 writes the
/// settings subtree as an unenumerated `...`), and `nosniff` is what turns
/// that from a silently mis-executed script into a console error naming the
/// type mismatch.
#[tokio::test]
async fn every_asset_response_refuses_content_type_sniffing() {
    for path in ["/index.html", "/app.css", "/w/default/inbox"] {
        let response = get(path).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(X_CONTENT_TYPE_OPTIONS)
                .unwrap_or_else(|| panic!("{path} response must forbid content sniffing")),
            "nosniff",
        );
    }
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
        // The `/settings` subtree is the arm that used to be an unbounded
        // prefix match, so every one of these answered 200 with the shell.
        // None of the cases above reach it: they all sit at the root or under
        // `/w/`.
        "/settings/../../../etc/passwd",
        "/settings/providers/anthropic/keys",
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

/// Repeated and trailing slashes are not collapsed. `matchit`, the matcher
/// `axum` routes with, treats `//index.html` and `/index.html` as different
/// paths; if this layer collapsed them it would answer requests that a
/// path-prefix policy or middleware in front of it had judged on a different
/// string.
#[tokio::test]
async fn a_path_with_empty_segments_is_not_an_alias_for_the_path_without_them() {
    for path in [
        "//index.html",
        "///////index.html",
        "/w/default//inbox",
        "//w/default/inbox",
        "/settings/",
        "/w/default/inbox/",
    ] {
        let response = get(path).await;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{path} has an empty segment and is not the path it resembles"
        );
    }
}

/// Asset lookup is on the raw request target: `axum` does not percent-decode
/// `Uri::path()` and `serve_asset` does not either, so `%2E` is two characters
/// in a key, not a `.`. That is why a client shipping a filename with a space
/// or a non-ASCII character 404s on it — a functional limit that
/// `serve_asset`'s doc comment records, asserted here so the doc is checked
/// rather than believed.
#[tokio::test]
async fn a_percent_encoded_asset_path_is_not_decoded_before_lookup() {
    for path in ["/index%2Ehtml", "/app%2Ecss", "/%69ndex.html"] {
        let response = get(path).await;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{path} is not decoded, so it matches no embedded key"
        );
    }
}

/// `assets/dist/` must hold only regular files and directories.
///
/// `rust-embed` walks the folder with `follow_links(true)`, so a symlink there
/// has its *target's* contents read at compile time and baked into every
/// binary that links this crate — including targets outside the repository.
/// In a diff a symlink renders as an ordinary added file. The likely trigger
/// is not malice: ruling P12 says a future change replaces this directory
/// wholesale with a JS build output, and several bundlers preserve symlinks.
/// `#[exclude]` cannot express this — it globs paths, not file types.
#[test]
fn every_entry_under_assets_dist_is_a_regular_file() {
    fn walk(dir: &Path) {
        for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
            let entry = entry.expect("directory entry");
            let path = entry.path();
            // `symlink_metadata` does not follow the link, which is the whole
            // point: `metadata` would report the target's type.
            let meta = fs::symlink_metadata(&path)
                .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()));

            assert!(
                !meta.is_symlink(),
                "{} is a symlink; rust-embed follows links, so its target's \
                 contents would be compiled into the daemon binary and served \
                 publicly. Copy the file in instead.",
                path.display()
            );

            if meta.is_dir() {
                walk(&path);
            } else {
                assert!(
                    meta.is_file(),
                    "{} is neither a regular file nor a directory",
                    path.display()
                );
            }
        }
    }

    walk(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets/dist"));
}

/// The behavioural half of the `debug-embed` check below, and the measurement
/// behind `embedded_response`'s zero-copy claim: an embedded file's bytes are
/// borrowed from the binary's own static data, not owned. The filesystem-
/// reading implementation has just read them and hands back `Cow::Owned`
/// (verified by building this crate with the feature removed), so this is the
/// one *behavioural* assertion here that discriminates between the two code
/// paths. The CWD-shifting test one would reach for does not: that
/// implementation bakes in an absolute path from `CARGO_MANIFEST_DIR`, so it
/// serves the same bytes from any working directory.
#[test]
fn an_embedded_files_bytes_are_borrowed_from_the_binary() {
    let file = WebAssets::get("index.html").expect("index.html is embedded");

    assert!(
        matches!(file.data, Cow::Borrowed(_)),
        "embedded bytes must be borrowed from the binary's static data; \
         `Cow::Owned` means rust-embed read them from the filesystem"
    );
}

/// The `debug-embed` feature is what makes `WebAssets::get` a lookup over
/// compile-time literals with no filesystem access, so a request path can only
/// hit or miss a fixed key set. Without it `rust-embed` generates its
/// filesystem-reading implementation, whose own source carries a `TODO`
/// conceding that a symlink escaping the embedded folder is still served.
/// Every *routing* test in this file stays green either way — the dynamic
/// implementation bakes in an absolute path from `CARGO_MANIFEST_DIR` and so
/// serves the same bytes from the same place — so the feature is asserted on
/// directly here, and behaviourally by
/// `an_embedded_files_bytes_are_borrowed_from_the_binary`.
#[test]
fn the_manifest_enables_rust_embeds_debug_embed_feature() {
    // The dependency's own line, not the whole manifest: the comment above it
    // explains `debug-embed` at length, so a substring search over the file
    // would still pass with the feature deleted.
    let declaration = include_str!("../Cargo.toml")
        .lines()
        .find(|line| line.starts_with("rust-embed = "))
        .expect("roundhouse-web declares rust-embed as a direct dependency");

    assert!(
        declaration.contains("\"debug-embed\""),
        "roundhouse-web must enable rust-embed's `debug-embed` feature: without \
         it the generated asset lookup reads the filesystem and follows \
         symlinks out of `assets/dist/`, and no routing test in this file can \
         tell the difference. Found: {declaration}"
    );
}

/// The seam `AppState` and `build_router` claim to be: a later Subsystem D
/// task nests a router whose handlers take `State<AppState>`, *ahead of* the
/// asset fallback and *before* `with_state`. This test performs exactly that
/// composition, so the claim is compiled rather than asserted in a doc
/// comment. It fails to build — not merely fails — if the asset router is not
/// generic over the state type, which is what makes it the guard.
#[tokio::test]
async fn a_handler_taking_app_state_composes_with_the_asset_router() {
    async fn probe(State(state): State<AppState>) -> String {
        format!("{state:?}")
    }

    let router: Router = asset_router()
        .route("/probe", get_route(probe))
        .with_state(AppState::default());

    let response = router
        .oneshot(
            Request::builder()
                .uri("/probe")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router is infallible");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_bytes(response).await,
        format!("{:?}", AppState::default()).into_bytes(),
        "the state the router was built with must reach the handler"
    );
}

#[tokio::test]
async fn build_router_serves_the_same_assets_as_the_bare_asset_router() {
    // Task 33 added the bind argument. Loopback here because this test is about
    // asset routing, and the loopback bind is the one with no gate in front of
    // it — `tests/lan_auth.rs` is where the gated variant is exercised.
    let response = roundhouse_web::build_router(
        roundhouse_web::AppState::default(),
        &roundhouse_web::lan_auth::BindConfig::loopback(),
    )
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
