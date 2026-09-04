//! The embedded web client and the router that serves it.
//!
//! `assets/dist/` is compiled into this library by `rust-embed`, so the web
//! client travels inside whatever binary links `roundhouse-web` — per ruling
//! P10 that is `roundhouse-daemon`, not the `round` CLI binary, which spawns
//! `round-daemon-internal` as a child process rather than linking the daemon
//! in. Nothing in this module binds a listener or starts a server; it builds
//! a router and stops there.

use axum::body::Body;
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use rust_embed::{EmbeddedFile, RustEmbed};

/// The web client's build output, embedded at compile time.
///
/// The directory is hand-committed placeholder HTML today (ruling P12); no
/// task in this plan builds the real SolidJS client. The embedding mechanism
/// is what this task delivers, and it does not care what the directory holds.
#[derive(RustEmbed)]
#[folder = "assets/dist"]
pub struct WebAssets;

/// Serves an embedded asset by exact path, falling back to the `index.html`
/// app shell for the client-side routes in §11.1's shared route table
/// (`docs/architecture/08-ui-design.md`) and 404ing everything else.
///
/// The fallback is deliberately restricted to routes the table actually
/// names. A blanket "anything that is not a file gets `index.html`" fallback
/// — which is what the SPA idiom usually means — would answer a request for a
/// missing JavaScript bundle with a 200 and a page of HTML, and the browser
/// would report that as an opaque MIME-type failure with no trail back to the
/// build that dropped the file.
pub async fn serve_asset(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    if let Some(file) = WebAssets::get(if path.is_empty() { "index.html" } else { path }) {
        return embedded_response(file);
    }

    if is_client_route(uri.path()) {
        return match WebAssets::get("index.html") {
            Some(shell) => embedded_response(shell),
            // Only reachable if `assets/dist/` was emptied of its shell; the
            // committed placeholder means the checked-in tree cannot hit it.
            None => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "roundhouse-web has no embedded index.html to serve",
            )
                .into_response(),
        };
    }

    (StatusCode::NOT_FOUND, "not found").into_response()
}

/// The router serving the embedded client: every path is handled by
/// [`serve_asset`], which is why this is a `fallback` rather than a set of
/// routes. Later Subsystem D tasks nest their own API routers *ahead* of this
/// one in [`crate::build_router`], so `/api/...` never reaches the shell.
pub fn asset_router() -> axum::Router {
    axum::Router::new().fallback(serve_asset)
}

/// Wraps an embedded file in a response carrying the content type `rust-embed`
/// recorded for it at embed time (the `mime-guess` feature), rather than
/// re-deriving one from the request path.
fn embedded_response(file: EmbeddedFile) -> Response {
    let mime = file.metadata.mimetype().to_owned();
    (
        [(header::CONTENT_TYPE, mime)],
        Body::from(file.data.into_owned()),
    )
        .into_response()
}

/// Whether `path` is one of §11.1's client-side routes — a view the browser
/// router resolves, for which the server's whole job is to hand back the app
/// shell.
///
/// The table (`docs/architecture/08-ui-design.md` §11.1) is:
/// `/w/:ws`, `/w/:ws/inbox`, `/w/:ws/s/:session[/t/:task[/diff]]`,
/// `/w/:ws/tree`, `/w/:ws/messages`, `/w/:ws/runs`, `/w/:ws/search`,
/// `/w/:ws/cost`, `/settings/...`.
///
/// `/settings` itself is accepted alongside its subtree: the table writes the
/// subtree as an unenumerated `...`, and the bare prefix is its natural root.
fn is_client_route(path: &str) -> bool {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    match segments.as_slice() {
        // `/settings/...`
        ["settings", ..] => true,
        // `/w/:ws`
        ["w", _ws] => true,
        // `/w/:ws/{inbox,tree,messages,runs,search,cost}`
        ["w", _ws, view] => {
            matches!(
                *view,
                "inbox" | "tree" | "messages" | "runs" | "search" | "cost"
            )
        }
        // `/w/:ws/s/:session[/t/:task[/diff]]`
        ["w", _ws, "s", _session] => true,
        ["w", _ws, "s", _session, "t", _task] => true,
        ["w", _ws, "s", _session, "t", _task, "diff"] => true,
        _ => false,
    }
}
