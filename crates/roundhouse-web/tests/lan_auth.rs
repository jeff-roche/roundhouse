//! §11.3's LAN bind and shared token, exercised through the two surfaces that
//! can actually be wrong: a real token file on a real directory, and a real
//! `axum::Router` driven end-to-end with `ServiceExt::oneshot`.
//!
//! Nothing here mocks the filesystem. The whole control *is* filesystem
//! behaviour — `O_EXCL`, `fchmod` after the write, an `fstat` on the descriptor
//! that was read — and a mock would assert only that this file agrees with
//! itself. Every temp directory here has its mode set explicitly rather than
//! left to the umask, because a `tempdir()` inherits the ambient `0022` as
//! `0755` — which
//! [`a_state_dir_others_can_reach_is_refused_with_the_chmod_that_fixes_it`]
//! shows the implementation correctly rejects, and which
//! [`the_token_file_is_owner_read_write_even_under_a_umask_that_would_strip_the_write_bit`]
//! and
//! [`the_state_dir_is_reusable_after_a_first_start_under_a_hostile_umask`]
//! deliberately make hostile for the duration of one test each.
//!
//! The router tests go through [`roundhouse_web::build_router`] rather than
//! calling the middleware directly, because "is the gate actually mounted, and
//! over which routes" is the failure P84 §E was written against — a gate that
//! exists and is never layered passes every unit test of the gate itself.
//!
//! **Which URI a gate test uses is load-bearing since ruling P85.** The gate is
//! mounted on the `/api` nest, so `/` and every other asset path answers `200`
//! with or without a token; a gate test written against `/` could not fail.
//! Every test about the gate therefore uses [`api_events`], and the asset paths
//! appear in exactly one test —
//! [`the_gate_is_on_api_and_the_asset_surface_is_ungated`] — where their being
//! ungated is the assertion.
//!
//! Per rulings P79/P81, every test here (and every `lan_auth` unit test in
//! `src/`) is killed by at least one stated mutation of the implementation, and
//! each of those mutations kills a **proper** subset. The mutation table, and
//! which tests each mutation killed, is in this task's report, measured against
//! this file as it ships rather than an earlier revision of it. One candidate test
//! was cut for failing that bar: an oversized token file is refused with or
//! without a size check, so the surviving test asserts on the *message*, which
//! is the only thing that actually differs.

use std::fs::Permissions;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use roundhouse_web::lan_auth::{token_path, BindConfig, LanToken};
use roundhouse_web::{build_router, AppState};
use tempfile::TempDir;
use tower::ServiceExt;

/// A session id shaped like the ones `sse.rs` parses, so the `/api` requests
/// below reach the SSE handler rather than being rejected as un-parseable
/// before the gate's verdict is even interesting.
const SESSION_ID: &str = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";

/// The one gated path in this crate's router, and therefore the path every
/// test about the *gate* has to use.
///
/// Since ruling P85 the gate is mounted on the `/api` nest and the embedded
/// shell is served ungated, so a gate test written against `/` would pass
/// whatever the token was — it would be `200` for a correct token, a wrong
/// token, and no token alike. That is exactly the "test that cannot fail"
/// shape P79 is about, so the asset paths appear in precisely one test
/// ([`the_gate_is_on_api_and_the_asset_surface_is_ungated`]), where being
/// ungated is the assertion rather than the accident.
fn api_events() -> String {
    format!("/api/sessions/{SESSION_ID}/events")
}

/// The umask is process-global, and this binary runs its tests in threads. Any
/// test that creates a token file and then asserts on its mode has to hold this
/// while it does so, or a concurrent umask change lands on its file instead.
static UMASK: Mutex<()> = Mutex::new(());

fn umask_guard() -> MutexGuard<'static, ()> {
    UMASK.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A `0700` directory, which is what the implementation demands of a state dir.
///
/// The mode is set after the create rather than through
/// `tempfile::Builder::permissions`, and the difference was an observed flake
/// rather than a theoretical one: `Builder::permissions` reaches
/// `DirBuilder::mode`, which the umask masks, so while
/// [`the_token_file_is_owner_read_write_even_under_a_umask_that_would_strip_the_write_bit`]
/// holds `0o277` this directory came out `0o500` and whichever test happened to
/// call this at that moment failed on the state dir's mode check, in a test
/// about something else entirely. Setting the mode explicitly makes this helper
/// umask-immune, so it needs no lock and can be called freely.
fn state_dir() -> TempDir {
    let dir = tempfile::tempdir().expect("a temp dir is creatable");
    std::fs::set_permissions(dir.path(), Permissions::from_mode(0o700))
        .expect("the mode is settable");
    dir
}

/// Reads the token file's text directly, rather than asking [`LanToken`] for
/// it. Deliberate: the file is what an operator types into their phone, so the
/// tests below authenticate with the bytes on disk. If [`LanToken`] ever
/// verified against something other than what it wrote, this is what catches
/// it.
fn token_text(dir: &Path) -> String {
    std::fs::read_to_string(token_path(dir))
        .expect("the token file exists once the token has been loaded")
        .trim()
        .to_string()
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path)
        .expect("the file exists")
        .permissions()
        .mode()
        & 0o777
}

/// Builds the LAN-gated router for `dir`'s token, plus the token's text.
fn lan_router(dir: &Path) -> (axum::Router, String) {
    let _umask = umask_guard();
    let token = LanToken::load_or_create(dir).expect("a fresh 0700 dir yields a token");
    let text = token_text(dir);
    let bind = BindConfig::lan(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 40)), token);
    (build_router(AppState::default(), &bind), text)
}

async fn status_of(router: axum::Router, request: Request<Body>) -> StatusCode {
    router
        .oneshot(request)
        .await
        .expect("the router is infallible")
        .status()
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("the request builds")
}

fn get_with_auth(uri: &str, authorization: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("Authorization", authorization)
        .body(Body::empty())
        .expect("the request builds")
}

// ---------------------------------------------------------------------------
// BindConfig — the type property
// ---------------------------------------------------------------------------

#[test]
fn loopback_is_what_you_get_with_no_configuration() {
    assert_eq!(
        BindConfig::default().bind_addr(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        "§11.3: loopback-only remains what you get with no configuration"
    );
    assert_eq!(
        BindConfig::loopback().bind_addr(),
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    );
}

#[test]
fn a_lan_bind_keeps_the_address_it_was_given() {
    let dir = state_dir();
    let _umask = umask_guard();
    let token = LanToken::load_or_create(dir.path()).expect("a fresh 0700 dir yields a token");
    let addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

    assert_eq!(BindConfig::lan(addr, token).bind_addr(), addr);
}

/// The redaction is the assertion, not the formatting. A derived `Debug` on
/// `LanToken` would put the token itself into every `{:?}` of a `BindConfig` —
/// and a startup log line is the single most likely place a `BindConfig` gets
/// formatted.
#[test]
fn debug_formatting_never_carries_the_token() {
    let dir = state_dir();
    let _umask = umask_guard();
    let token = LanToken::load_or_create(dir.path()).expect("a fresh 0700 dir yields a token");
    let text = token_text(dir.path());
    let bind = BindConfig::lan(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), token);

    let rendered = format!("{bind:?}");
    assert!(
        !rendered.contains(&text),
        "a BindConfig's Debug must not contain the token; got {rendered}"
    );
}

// ---------------------------------------------------------------------------
// The token file
// ---------------------------------------------------------------------------

/// §11.3's token is "entered once per device". A restart that minted a new one
/// would silently unpair every device already paired, which is the failure the
/// idempotence exists to prevent.
#[test]
fn the_token_survives_a_restart_so_paired_devices_stay_paired() {
    let dir = state_dir();
    let _umask = umask_guard();

    let first = LanToken::load_or_create(dir.path()).expect("first load creates");
    let text = token_text(dir.path());
    let second = LanToken::load_or_create(dir.path()).expect("second load reads");

    assert_eq!(
        text,
        token_text(dir.path()),
        "the second load must not rewrite the file"
    );
    // Verified through the public surface: both handles must accept the one
    // token on disk. `LanToken` deliberately has no accessor to compare.
    let bind_first = BindConfig::lan(IpAddr::V4(Ipv4Addr::LOCALHOST), first);
    let bind_second = BindConfig::lan(IpAddr::V4(Ipv4Addr::LOCALHOST), second);
    for bind in [bind_first, bind_second] {
        let router = build_router(AppState::default(), &bind);
        let request = get_with_auth(&api_events(), &format!("Bearer {text}"));
        assert_eq!(block_on(status_of(router, request)), StatusCode::OK);
    }
}

/// A fresh token is 32 bytes of entropy rendered as 64 lowercase hex
/// characters. Asserted because the read path rejects anything else, so a
/// generator that drifted from the validator would fail only on the *second*
/// start of a daemon — the worst possible place to find out.
#[test]
fn a_generated_token_is_sixty_four_hex_characters() {
    let dir = state_dir();
    let _umask = umask_guard();
    LanToken::load_or_create(dir.path()).expect("a fresh 0700 dir yields a token");

    let text = token_text(dir.path());
    assert_eq!(text.len(), 64, "32 bytes hex-encoded");
    assert!(
        text.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "lowercase hex only; got {text}"
    );
}

/// Two tokens generated in two different state dirs must differ. Guards the
/// case where the entropy source is replaced by something deterministic — a
/// constant token passes every other test in this file.
#[test]
fn two_state_dirs_get_two_different_tokens() {
    let one = state_dir();
    let two = state_dir();
    let _umask = umask_guard();

    LanToken::load_or_create(one.path()).expect("token one");
    LanToken::load_or_create(two.path()).expect("token two");

    assert_ne!(token_text(one.path()), token_text(two.path()));
}

/// `OpenOptions::mode` is masked by the umask, and the umask can only *clear*
/// bits — so `0o277` turns a `0600` request into a read-only `0400` file. That
/// is why the implementation `fchmod`s after the write instead of trusting the
/// open. Under a benign umask this test cannot fail, which is exactly why it
/// sets a hostile one.
#[test]
fn the_token_file_is_owner_read_write_even_under_a_umask_that_would_strip_the_write_bit() {
    let dir = state_dir();
    let _umask = umask_guard();

    let previous = rustix::process::umask(rustix::fs::Mode::from_bits_truncate(0o277));
    let created = LanToken::load_or_create(dir.path());
    rustix::process::umask(previous);

    created.expect("a fresh 0700 dir yields a token whatever the umask");
    assert_eq!(
        mode_of(&token_path(dir.path())),
        0o600,
        "the mode must come from this code, not from the ambient umask"
    );
}

/// The state dir holds the token, so a directory anyone can write to is a
/// place anyone can plant a symlink for the token open to follow. `tempdir()`
/// without explicit permissions produces exactly that under a typical `0022`
/// umask, which is what this uses.
///
/// The refusal must also carry its remedy. `0755` is what a plain
/// `create_dir_all` from any other component produces under a normal umask, so
/// this is a state a user reaches without doing anything wrong — and without
/// the `chmod` in the message, LAN opt-in fails permanently with nothing
/// saying how to unstick it.
#[test]
fn a_state_dir_others_can_reach_is_refused_with_the_chmod_that_fixes_it() {
    let dir = tempfile::tempdir().expect("a temp dir is creatable");
    std::fs::set_permissions(dir.path(), Permissions::from_mode(0o755))
        .expect("the mode is settable");

    let error = LanToken::load_or_create(dir.path()).expect_err("a 0755 state dir is refused");
    assert!(
        error.to_string().contains("0755"),
        "the error must name the mode it found; got {error}"
    );
    assert!(
        error
            .to_string()
            .contains(&format!("chmod 700 {}", dir.path().display())),
        "the error must name the command that fixes it, with the path; got {error}"
    );
    assert!(
        !token_path(dir.path()).exists(),
        "refusing must not leave a token file behind in the directory it refused"
    );
}

/// `DirBuilder::mode(0o700)` is masked by the umask exactly as `OpenOptions::
/// mode` is, so under `0o277` the state dir is created `0o500` — and then
/// `ensure_state_dir`'s own `mode != 0o700` check refuses it on **every
/// subsequent start**, for a directory this code created, with no umask the
/// operator can set to undo it. The failure is permanent rather than transient,
/// which is why the `fchmod` after the create is worth its lines.
///
/// The second load is the assertion that matters: the first one could pass with
/// no fix at all, since a freshly created dir takes the `Ok(())` arm without
/// being re-checked.
#[test]
fn the_state_dir_is_reusable_after_a_first_start_under_a_hostile_umask() {
    let dir = tempfile::tempdir().expect("a temp dir is creatable");
    let state = dir.path().join("roundhouse");
    let _umask = umask_guard();

    let previous = rustix::process::umask(rustix::fs::Mode::from_bits_truncate(0o277));
    let first = LanToken::load_or_create(&state);
    rustix::process::umask(previous);

    first.expect("a fresh state dir yields a token whatever the umask");
    assert_eq!(
        mode_of(&state),
        0o700,
        "the mode must come from this code, not from the ambient umask"
    );
    LanToken::load_or_create(&state)
        .expect("a restart must not be refused by the mode this code itself created");
}

#[test]
fn a_token_file_others_can_reach_is_refused() {
    let dir = state_dir();
    let _umask = umask_guard();
    LanToken::load_or_create(dir.path()).expect("first load creates");

    std::fs::set_permissions(token_path(dir.path()), Permissions::from_mode(0o640))
        .expect("the mode is settable");

    let error = LanToken::load_or_create(dir.path()).expect_err("a 0640 token file is refused");
    assert!(
        error.to_string().contains("permissions too open"),
        "got {error}"
    );
    // The reason comes from `check_token_metadata`, which is a predicate over
    // three integers and cannot know *which* file; the path is prefixed by
    // `read_token_file`, the only frame that does. Asserted because a refusal
    // naming no file is one an operator cannot act on, and because the split
    // into a predicate is what put those two halves in different functions.
    assert!(
        error
            .to_string()
            .contains(&token_path(dir.path()).display().to_string()),
        "the refusal must name the file it refused; got {error}"
    );
}

/// Two daemons starting together: one wins the `O_EXCL` create, the other opens
/// the file before the write lands and reads nothing. Treating `""` as the
/// token would authenticate every request presenting an empty string, so an
/// unusable file has to be an error.
#[test]
fn a_truncated_token_file_is_refused_rather_than_treated_as_the_token() {
    let dir = state_dir();
    let _umask = umask_guard();
    LanToken::load_or_create(dir.path()).expect("first load creates");
    std::fs::write(token_path(dir.path()), b"").expect("the file is writable");

    let error = LanToken::load_or_create(dir.path()).expect_err("an empty token file is refused");
    assert!(error.to_string().contains("hex"), "got {error}");
}

/// The size refusal comes from the `fstat`, *before* the read, so it carries
/// its own message rather than arriving as "not hex". That distinction is the
/// whole assertion: without the size check this file is still refused, just
/// after being read into memory whole, and only the message tells the two
/// apart.
#[test]
fn an_oversized_token_file_is_refused_before_it_is_read() {
    let dir = state_dir();
    let _umask = umask_guard();
    LanToken::load_or_create(dir.path()).expect("first load creates");
    // Valid hex all the way down, and far past any real token — so "not hex"
    // cannot be the reason this is rejected.
    std::fs::write(token_path(dir.path()), "a".repeat(1024 * 1024)).expect("the file is writable");

    let error = LanToken::load_or_create(dir.path()).expect_err("a megabyte of hex is not a token");
    assert!(
        error.to_string().contains("past the"),
        "the refusal must name the size limit, not the format; got {error}"
    );
}

#[test]
fn a_token_file_of_the_wrong_length_is_refused() {
    let dir = state_dir();
    let _umask = umask_guard();
    LanToken::load_or_create(dir.path()).expect("first load creates");
    // Valid hex, half the required entropy.
    std::fs::write(token_path(dir.path()), "a".repeat(32)).expect("the file is writable");

    let error = LanToken::load_or_create(dir.path()).expect_err("16 bytes of hex is refused");
    assert!(error.to_string().contains("hex"), "got {error}");
}

/// `create_new` refuses to *write* through a symlink; `O_NOFOLLOW` is what
/// stops the fallback *read* following one to a file with attacker-chosen
/// contents that passes the uid and mode checks.
#[test]
fn a_symlink_in_place_of_the_token_file_is_not_followed() {
    let dir = state_dir();
    let elsewhere = state_dir();
    let _umask = umask_guard();

    // A perfectly well-formed token, owned by us, mode 0600 — everything the
    // uid, mode and content checks look for. Only the symlink is wrong.
    let planted = elsewhere.path().join("planted");
    std::fs::write(&planted, "b".repeat(64)).expect("the file is writable");
    std::fs::set_permissions(&planted, Permissions::from_mode(0o600)).expect("mode is settable");
    std::os::unix::fs::symlink(&planted, token_path(dir.path())).expect("the symlink is creatable");

    LanToken::load_or_create(dir.path()).expect_err("a symlinked token file is refused");
}

// ---------------------------------------------------------------------------
// The gate, through the real router
// ---------------------------------------------------------------------------

/// P84 §B, and the reason this test exists rather than being assumed: with no
/// configuration there is no gate at all, over `/api` or over the assets. The
/// cost is stated in `lan_auth`'s module docs — an unauthenticated local reader
/// gets the SSE ring's retained history.
#[tokio::test]
async fn a_loopback_router_serves_both_surfaces_with_no_token() {
    let bind = BindConfig::loopback();

    assert_eq!(
        status_of(build_router(AppState::default(), &bind), get("/")).await,
        StatusCode::OK,
        "the client shell is unauthenticated on loopback"
    );
    assert_eq!(
        status_of(build_router(AppState::default(), &bind), get(&api_events())).await,
        StatusCode::OK,
        "the SSE stream is unauthenticated on loopback"
    );
}

#[tokio::test]
async fn a_lan_router_rejects_a_request_with_no_token() {
    let dir = state_dir();
    let (router, _) = lan_router(dir.path());

    assert_eq!(
        status_of(router, get(&api_events())).await,
        StatusCode::UNAUTHORIZED
    );
}

/// Ruling P85's boundary, pinned from **both** sides in one test because it is
/// one decision: the gate is on the `/api` nest, so every asset path is served
/// ungated and every `/api` path is refused without the token.
///
/// The asset list is not arbitrary. `/` and `/index.html` are the document a
/// browser navigates to; `/w/default/inbox` is a §11.1 client route served the
/// shell; and **`/does-not-exist.js` is the load-bearing one** — it reaches
/// nothing but `asset_router`'s fallback, so its 404 is what proves the
/// *fallback* is on the ungated side rather than only the named routes. A gate
/// re-applied over the finished router would turn every one of these into a
/// 401, which is precisely the state that left the LAN bind with no working
/// browser: `index.html`'s `<link href="/app.css">` is a subresource and can
/// carry no credential.
///
/// The `/api` half is what stops "ungate the assets" from drifting into
/// "ungate everything". Both halves use the same router construction, so
/// neither can pass by accident of how it was built.
#[tokio::test]
async fn the_gate_is_on_api_and_the_asset_surface_is_ungated() {
    let dir = state_dir();

    // The expected status is asserted, not merely "not 401": the shell has to
    // *serve*, and `/does-not-exist.js` has to reach the fallback's own 404
    // rather than any other refusal.
    for (uri, expected) in [
        ("/", StatusCode::OK),
        ("/index.html", StatusCode::OK),
        ("/app.css", StatusCode::OK),
        ("/w/default/inbox", StatusCode::OK),
        ("/does-not-exist.js", StatusCode::NOT_FOUND),
    ] {
        let (router, _) = lan_router(dir.path());
        assert_eq!(
            status_of(router, get(uri)).await,
            expected,
            "{uri} is compile-time-constant public content and must be served ungated, or the \
             LAN bind has no working browser"
        );
    }

    // Every `/api` path, not just the ones that exist. The unrouted path is the
    // load-bearing one on this side (ruling P88 §A): a gate that covered only
    // the routes `sse::router` happens to register would answer `404` there,
    // and the next API route added outside `roundhouse_web::api_router` would
    // be served ungated with this test still green. A `401` for a path that
    // matches nothing is what says the gate is on the **nest**.
    for uri in [
        format!("/api/sessions/{SESSION_ID}/events"),
        "/api/no-such-route".to_string(),
    ] {
        let (router, _) = lan_router(dir.path());
        assert_eq!(
            status_of(router, get(&uri)).await,
            StatusCode::UNAUTHORIZED,
            "{uri} is under the gated nest and must be refused without the token"
        );
    }
}

#[tokio::test]
async fn a_lan_router_rejects_a_wrong_token() {
    let dir = state_dir();
    let (router, text) = lan_router(dir.path());

    // Same length and alphabet as the real one, differing in the last
    // character: a comparison that stopped early would still reject it, but a
    // comparison keyed on length alone would not.
    let mut wrong = text[..text.len() - 1].to_string();
    wrong.push(if text.ends_with('0') { '1' } else { '0' });

    assert_eq!(
        status_of(
            router,
            get_with_auth(&api_events(), &format!("Bearer {wrong}"))
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_lan_router_rejects_a_token_of_the_wrong_length() {
    let dir = state_dir();
    let (router, text) = lan_router(dir.path());
    let truncated = &text[..text.len() - 1];

    assert_eq!(
        status_of(
            router,
            get_with_auth(&api_events(), &format!("Bearer {truncated}"))
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "a prefix of the real token must not authenticate"
    );
}

#[tokio::test]
async fn a_lan_router_accepts_the_token_in_an_authorization_bearer_header() {
    let dir = state_dir();
    let (router, text) = lan_router(dir.path());

    assert_eq!(
        status_of(
            router,
            get_with_auth(&api_events(), &format!("Bearer {text}"))
        )
        .await,
        StatusCode::OK,
        "the gated nest must be reachable with the token"
    );
}

/// RFC 7235: the scheme name is case-insensitive. Asserted because rejecting
/// `bearer` would surface as an unexplainable 401 against a conformant client.
#[tokio::test]
async fn the_bearer_scheme_name_is_matched_case_insensitively() {
    let dir = state_dir();
    let (router, text) = lan_router(dir.path());

    assert_eq!(
        status_of(
            router,
            get_with_auth(&api_events(), &format!("bEaReR {text}"))
        )
        .await,
        StatusCode::OK
    );
}

/// P84 §A, the whole reason a query parameter is accepted at all: the browser's
/// native `EventSource` sets `Last-Event-ID` for us and **cannot set any
/// request header**, so the SSE endpoint this crate exists to serve is
/// unreachable with a header-only token.
#[tokio::test]
async fn a_lan_router_accepts_the_token_in_the_query_parameter_for_event_source() {
    let dir = state_dir();
    let (router, text) = lan_router(dir.path());

    assert_eq!(
        status_of(
            router,
            get(&format!("{}?access_token={text}", api_events()))
        )
        .await,
        StatusCode::OK
    );
}

/// The query parameter must be found when it is not the first one, since
/// `EventSource` clients will have other parameters of their own.
#[tokio::test]
async fn the_query_parameter_is_found_among_others() {
    let dir = state_dir();
    let (router, text) = lan_router(dir.path());

    assert_eq!(
        status_of(
            router,
            get(&format!(
                "{}?foo=bar&access_token={text}&baz=1",
                api_events()
            ))
        )
        .await,
        StatusCode::OK
    );
}

/// A parameter whose name merely *ends* with the real one must not be read as
/// it — `?not_access_token=<token>` is a different parameter.
#[tokio::test]
async fn a_parameter_whose_name_only_ends_with_the_real_one_is_not_the_token() {
    let dir = state_dir();
    let (router, text) = lan_router(dir.path());

    assert_eq!(
        status_of(
            router,
            get(&format!("{}?not_access_token={text}", api_events()))
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
}

/// A non-`Bearer` `Authorization` header is not a token in some other
/// encoding; it must not authenticate, and it must not be mistaken for the
/// whole credential.
#[tokio::test]
async fn a_non_bearer_authorization_header_does_not_authenticate() {
    let dir = state_dir();
    let (router, text) = lan_router(dir.path());

    assert_eq!(
        status_of(
            router,
            get_with_auth(&api_events(), &format!("Basic {text}"))
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
}

/// RFC 7235 §3.1 requires a `401` to carry a challenge, and `Bearer` is the one
/// browsers do not implement — which is what keeps the native credential dialog
/// from appearing and turning this into the "login system" §11.3 forbids.
#[tokio::test]
async fn the_rejection_carries_a_bearer_challenge() {
    let dir = state_dir();
    let (router, _) = lan_router(dir.path());

    let response = router
        .oneshot(get(&api_events()))
        .await
        .expect("the router is infallible");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok()),
        Some("Bearer")
    );
}

/// Blocks on a future from a non-`async` test. The one place a synchronous test needs to drive the router
/// is [`the_token_survives_a_restart_so_paired_devices_stay_paired`], which is
/// synchronous because it holds the umask lock across two file operations.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime is buildable")
        .block_on(future)
}
