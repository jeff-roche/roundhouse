//! The embedded web client and the router that serves it.
//!
//! `assets/dist/` is compiled into this library by `rust-embed`, so the web
//! client travels inside whatever binary links `roundhouse-web` — per ruling
//! P10 that is `roundhouse-daemon`, not the `round` CLI binary, which spawns
//! `round-daemon-internal` as a child process rather than linking the daemon
//! in. Nothing in this module binds a listener or starts a server; it builds
//! a router and stops there.
//!
//! # `assets/dist/` is PUBLIC CONTENT — a standing constraint, not a note
//!
//! Since ruling P85 the LAN token gate is mounted on the `/api` nest and this
//! router is served **ungated**, so under `BindConfig::lan(...)` every byte in
//! `assets/dist/` is readable by any unauthenticated peer on the LAN. That is
//! safe for exactly one reason: the directory is **compile-time-constant public
//! content** — the same bytes in every install, embedded from the repo at build
//! time. The reason the gate had to move is mechanical and is argued in full on
//! [`crate::build_router`]: a browser can present the token on a *document*
//! request (`/?access_token=…`), but a **subresource** URL is written by the
//! client build rather than by the client code, so `/app.css` — and the real
//! client's hashed `/assets/*.js` — can carry no credential at all. With the
//! gate over the whole surface they 401 and the page never boots.
//!
//! So, for whoever replaces the placeholder with a real client build (ruling
//! P12 — that person "touches no Rust", which is why this is also restated in
//! `assets/dist/index.html` itself):
//!
//! **`assets/dist/` must never carry session data, secrets, or per-install
//! configuration.** No baked-in token, no workspace or session identifiers, no
//! host names, no generated `config.json` — nothing whose value differs between
//! two installs or between two users of one install. Per-install values reach
//! the client at runtime, from a gated `/api` route. Breaking this puts the
//! value on an unauthenticated LAN endpoint, and nothing in this crate can
//! detect it: `serve_asset` serves whatever the directory holds.
//!
//! # The client contract for the LAN token
//!
//! Recorded here and in `assets/dist/index.html` because it is the client's
//! half of `lan_auth`'s design, and its author will not read `lan_auth.rs`. On
//! boot the client must:
//!
//! 1. read `access_token` from `location.search` — pairing a device is opening
//!    `http://host:port/?access_token=<64 hex>`, which is the only way a
//!    top-level navigation can carry a credential;
//! 2. keep it in `sessionStorage`, not `localStorage`: it should not outlive
//!    the tab;
//! 3. `history.replaceState` it out of the URL immediately. This is the
//!    **mitigation for a residual no server-side code can close** — a URL a
//!    browser navigated to lands in history, in browser account sync, and in
//!    URL-bar autocomplete (see `lan_auth`'s residuals);
//! 4. send it as an `Authorization: Bearer` header on every `fetch`, and as an
//!    `?access_token=` query parameter on `EventSource`, which cannot set
//!    request headers at all.
//!
//! **The `debug-embed` feature is load-bearing for more than test fidelity.**
//! With it, `WebAssets::get` is generated as a lookup over a `static` array of
//! compile-time literals — no filesystem access at all, so a request path can
//! only hit or miss a fixed key set. Without it, `rust-embed` generates its
//! filesystem-reading implementation instead, whose own source carries a
//! `TODO` conceding that a symlink pointing outside the embedded folder is
//! still served. That property therefore rests on one line of `Cargo.toml`,
//! which `tests/assets.rs` asserts on directly.

use std::borrow::Cow;

use axum::body::{Body, Bytes};
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use rust_embed::{EmbeddedFile, RustEmbed};

/// The web client's build output, embedded at compile time.
///
/// The directory is hand-committed placeholder HTML and CSS today (ruling
/// P12); no task in this plan builds the real SolidJS client. The embedding
/// mechanism is what this task delivers, and it does not care what the
/// directory holds.
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
///
/// **Lookup is on the raw request path.** `uri.path()` is the target as the
/// client sent it; axum does not percent-decode it, and this function does not
/// either — the string is used as an exact key against the embedded set. So a
/// client that ships a file whose name contains a space, a `%`, or any
/// non-ASCII character will 404 on it, because the browser requests
/// `/my%20app.css` while the embedded key is `my app.css`. That is a
/// functional limit on filenames, not a security boundary: decoding here would
/// be the thing that *introduced* one. Whoever hits it should rename the asset
/// rather than add a decode step.
pub async fn serve_asset(uri: Uri) -> Response {
    let Some((key, segments)) = split_request_path(uri.path()) else {
        return not_found();
    };

    if let Some(file) = WebAssets::get(key) {
        return embedded_response(file);
    }

    if is_client_route(&segments) {
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

    not_found()
}

/// The router serving the embedded client: every path is handled by
/// [`serve_asset`], which is why this is a `fallback` rather than a set of
/// routes.
///
/// Generic over the state type on purpose. [`serve_asset`] takes no `State`
/// extractor, so this router is compatible with any state — which is what lets
/// [`crate::build_router`] add it to a `Router<AppState>` pipeline and apply
/// the state once, at the end. Called on its own (as the tests do) `S` infers
/// to `()`, because that is the only state type for which `Router` is itself a
/// `Service`.
pub fn asset_router<S>() -> axum::Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    axum::Router::new().fallback(serve_asset)
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
}

/// Splits a request path into the embedded-asset lookup key and its segments,
/// or `None` if the path is not one this router will answer. The site root
/// (`/`) is the one path whose key is not its own text: it maps to
/// `index.html` with no segments.
///
/// Empty segments are rejected rather than skipped, so `//index.html` and
/// `/w/default//inbox` are 404s. Collapsing them would make this layer *more*
/// permissive than `axum`'s own matcher — `matchit` does not collapse repeated
/// slashes — and any future path-prefix policy or middleware in front of this
/// router would then be reasoning about a different path than the one served.
/// The same rule makes a trailing slash (`/settings/`) a 404, matching how
/// `matchit` treats it.
fn split_request_path(path: &str) -> Option<(&str, Vec<&str>)> {
    let rest = path.strip_prefix('/')?;
    if rest.is_empty() {
        return Some(("index.html", Vec::new()));
    }

    let segments: Vec<&str> = rest.split('/').collect();
    if segments.iter().any(|segment| segment.is_empty()) {
        return None;
    }

    Some((rest, segments))
}

/// Wraps an embedded file in a response carrying the content type `rust-embed`
/// recorded for it at embed time (the `mime-guess` feature), rather than
/// re-deriving one from the request path.
///
/// **The recorded type is sent verbatim, with no `charset` parameter.** That is
/// a decision, not an oversight: this crate does not produce the bytes it
/// serves — ruling P12 says `assets/dist/` is replaced wholesale by a future
/// client build — so it is in no position to assert their encoding. The one
/// file it does own declares its own charset in-document. Whoever ships a real
/// client whose text assets need a declared encoding should add it here
/// deliberately, knowing what that build emits.
///
/// `X-Content-Type-Options: nosniff` is sent on every asset. Two reasons, both
/// specific to this router: it already answers `.js`-suffixed URLs under
/// `/settings/<one segment>` with HTML (the app shell), and `nosniff` turns
/// that silent misfire into a console error naming the type mismatch; and any
/// extension `mime-guess` does not recognise is recorded as
/// `application/octet-stream`, which is exactly where content sniffing is
/// worth refusing.
fn embedded_response(file: EmbeddedFile) -> Response {
    let mime = file.metadata.mimetype().to_owned();
    // `debug-embed` gives every file a `Cow::Borrowed(&'static [u8])`, so the
    // borrowed arm hands `Bytes` a pointer to the binary's own read-only data
    // and copies nothing. The owned arm exists for the filesystem-reading
    // build, where the bytes were just read and are already owned. Copying
    // unconditionally (`into_owned()`) would memcpy the whole asset per
    // request; unmeasured here, where the largest asset is under a kilobyte,
    // but the shape is per-request-per-byte either way.
    let body = match file.data {
        Cow::Borrowed(bytes) => Body::from(Bytes::from_static(bytes)),
        Cow::Owned(bytes) => Body::from(bytes),
    };

    (
        [
            (header::CONTENT_TYPE, mime),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_owned()),
        ],
        body,
    )
        .into_response()
}

/// Whether `segments` are one of §11.1's client-side routes — a view the
/// browser router resolves, for which the server's whole job is to hand back
/// the app shell.
///
/// The table (`docs/architecture/08-ui-design.md` §11.1) is:
/// `/w/:ws`, `/w/:ws/inbox`, `/w/:ws/s/:session[/t/:task[/diff]]`,
/// `/w/:ws/tree`, `/w/:ws/messages`, `/w/:ws/runs`, `/w/:ws/search`,
/// `/w/:ws/cost`, `/settings/...`.
///
/// `/settings` itself is accepted alongside its subtree: the table writes the
/// subtree as an unenumerated `...`, and the bare prefix is its natural root.
/// The subtree is bounded to **one** segment below `/settings` rather than
/// matched as a prefix. An unbounded `["settings", ..]` arm was the one arm of
/// this set that never closed: it answered `/settings/../../../etc/passwd`
/// with a 200 and the app shell. Nothing was disclosed by that — the lookup
/// above cannot leave the embedded key set — but it contradicted this module's
/// stated rule that an unknown path is a 404. A `/settings/<name>` that the
/// client does not route still serves the shell, which is what an unenumerated
/// `...` in the table means; depth is what is now bounded.
fn is_client_route(segments: &[&str]) -> bool {
    match segments {
        // `/settings` and `/settings/:view`
        ["settings"] | ["settings", _] => true,
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
