//! Task 35 (Phase 5, Subsystem D6) — §11.4's four distinct interaction inputs.
//!
//! # Half of this file exists because the plan's tests could not fail
//!
//! Worth stating, because it is the lesson rather than the ceremony. All three
//! of this task's planned tests called `parse_interaction` directly and **none
//! built a router**. The planned `router()` used `axum` 0.7's `/:session_id`,
//! which `axum` 0.8 — pinned here at `=0.8.4` — rejects by **panicking inside
//! `Router::route`**. So the suite would have been green over a crate that
//! panicked the first time anything mounted the route, and no amount of
//! strengthening the parse assertions would have found it.
//!
//! So the router tests below are not "integration coverage for completeness":
//! `the_route_is_mounted_under_the_api_namespace` is the only test in this file
//! that can observe an entire category of defect, and it observes it by
//! **constructing** `build_router` at all.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use roundhouse_web::interaction::{parse_interaction, InteractionError, InteractionInput};
use roundhouse_web::lan_auth::BindConfig;
use roundhouse_web::{build_router, AppState};
use serde_json::json;
use tower::ServiceExt;

/// §11.4: *"interrupt vs queue vs steer are four distinct, unambiguous
/// inputs."* Distinct is the assertion — four bodies, four different values,
/// no two of them collapsing onto one variant.
#[test]
fn the_four_inputs_are_distinct_and_unambiguous() {
    assert_eq!(
        parse_interaction(&json!({"kind": "soft_interrupt"})).unwrap(),
        InteractionInput::SoftInterrupt
    );
    assert_eq!(
        parse_interaction(&json!({"kind": "hard_cancel"})).unwrap(),
        InteractionInput::HardCancel
    );
    assert_eq!(
        parse_interaction(&json!({"kind": "queue", "text": "also check the changelog"})).unwrap(),
        InteractionInput::Queue {
            text: "also check the changelog".to_string()
        }
    );
    assert_eq!(
        parse_interaction(&json!({"kind": "steer", "text": "stop, use the other branch"})).unwrap(),
        InteractionInput::Steer {
            text: "stop, use the other branch".to_string()
        }
    );
}

/// The asymmetry `InteractionInput`'s shape encodes: a message needs something
/// to say, a stop signal does not.
#[test]
fn queue_and_steer_require_text_soft_and_hard_do_not() {
    assert_eq!(
        parse_interaction(&json!({"kind": "queue"})),
        Err(InteractionError::MissingText("queue")),
        "queue without text is meaningless"
    );
    assert_eq!(
        parse_interaction(&json!({"kind": "steer"})),
        Err(InteractionError::MissingText("steer"))
    );
    assert!(parse_interaction(&json!({"kind": "soft_interrupt", "text": "ignored"})).is_ok());
    assert!(parse_interaction(&json!({"kind": "hard_cancel", "text": "ignored"})).is_ok());
}

/// An empty string is not text. `{"kind": "steer", "text": ""}` is a steer
/// toward nothing, and accepting it would put an instruction with no content
/// into whatever queue eventually exists — the one case where the `Option`
/// shape of the parse could quietly produce a `Steer` nobody can act on.
#[test]
fn empty_text_is_not_text() {
    assert_eq!(
        parse_interaction(&json!({"kind": "steer", "text": ""})),
        Err(InteractionError::MissingText("steer"))
    );
    assert_eq!(
        parse_interaction(&json!({"kind": "queue", "text": ""})),
        Err(InteractionError::MissingText("queue"))
    );
}

/// A `kind` outside the four is refused rather than mapped onto the nearest
/// one. Mapping is the failure worth naming: silently treating an unrecognised
/// input as a soft interrupt would be a *stop* the caller never asked for.
#[test]
fn unknown_kind_is_rejected_rather_than_silently_mapped_to_something() {
    assert_eq!(
        parse_interaction(&json!({"kind": "pause_forever"})),
        Err(InteractionError::UnknownKind("pause_forever".into()))
    );
    // Absent and non-string `kind`s land in the same arm rather than panicking
    // or defaulting.
    assert!(parse_interaction(&json!({})).is_err());
    assert!(parse_interaction(&json!({"kind": 4})).is_err());
}

/// The case that decided the deny-unknown-fields question, and the reason the
/// answer is visible to a caller: a misspelled *field* used to be reported as a
/// missing one, so `{"kind": "queue", "txt": "…"}` answered *"queue requires
/// non-empty text"* to a caller who had supplied text.
///
/// # Both ends of the object, and why the second fixture is not redundant
///
/// P92's amended rule 2 applied to the side of the search that was missed
/// (ruling P99's fourth rule): a search has **two** collections — the keys being
/// iterated and the known-field list they are matched against — and the
/// cardinality set applies to both. The sweep enumerated mutations of
/// `[KIND, TEXT]` and none of `object.keys()`, so
/// `object.keys().skip(1).find(…)` survived: `txt` is the *last* key under
/// either ordering, so skipping the first still finds it, still returns
/// `UnknownField`, and every assertion above still passes. That mutant accepts
/// `{"aaa": …, "kind": …}` with `aaa` silently ignored — reopening the exact
/// failure this module spends twenty lines justifying.
///
/// `aim` is the second fixture's unknown key because it is index **0 under
/// either `serde_json` map ordering**: it sorts before `kind` (the `BTreeMap`
/// default) *and* is written first (with `preserve_order`). A fixture whose
/// correctness depends on which of the two is compiled in is a live hazard here,
/// not a theoretical one — the feature is reachable in this lock.
///
/// It also carries a valid `text`, so the mutant cannot be killed by the wrong
/// thing: skipping `aim` yields a perfectly well-formed `queue`, and the only
/// way to fail is to have not looked at the first key.
#[test]
fn a_misspelled_field_names_the_typo_wherever_in_the_object_it_sits() {
    assert_eq!(
        parse_interaction(&json!({"kind": "queue", "txt": "also check the changelog"})),
        Err(InteractionError::UnknownField("txt".into())),
        "an unknown key last in the object"
    );
    assert_eq!(
        parse_interaction(&json!({"aim": "left", "kind": "queue", "text": "x"})),
        Err(InteractionError::UnknownField("aim".into())),
        "an unknown key first in the object, beside a kind and a text that are both valid"
    );
}

/// A body that is not an object says so, rather than reporting an empty `kind`
/// and sending the caller to look at a field they did not send.
#[test]
fn a_non_object_body_names_its_own_shape() {
    assert_eq!(
        parse_interaction(&json!([{"kind": "soft_interrupt"}])),
        Err(InteractionError::NotAnObject("an array"))
    );
    assert_eq!(
        parse_interaction(&json!(null)),
        Err(InteractionError::NotAnObject("null"))
    );
    assert_eq!(
        parse_interaction(&json!("soft_interrupt")),
        Err(InteractionError::NotAnObject("a string"))
    );
}

/// The offending value in an error message is the caller's own, so quoting it
/// discloses nothing — but quoting it *unbounded* would let a request choose
/// the size of its own error response.
///
/// The assertion is that the message **does not scale with the input**, stated
/// as an equality between two inputs three orders of magnitude apart rather
/// than as a byte-count threshold. A threshold would have to be re-tuned every
/// time the wording changed, and would pass for a bound that was merely large.
///
/// # The filler character is `€` for a reason, and the reason is a caught bug
///
/// This test first used `é`, which is **two** bytes — and 64 is even, so
/// `&value[..64]` lands exactly on a char boundary and does not panic. The
/// byte-truncation mutation survived the sweep against a test whose whole
/// second half is about char boundaries.
///
/// `€` is three bytes and `64 % 3 == 1`, so a byte slice at the bound splits a
/// character and panics. Picking a multi-byte character is not enough; it has to
/// be one whose width does not divide the bound.
///
/// # Three assertions about the cut itself, one per way of getting it wrong
///
/// The `MAX_ECHOED` mutations cannot reach any of them: the constant appears in
/// *both* the `chars().count() <= MAX_ECHOED` guard and the `take`, so changing
/// it moves them together and everything above holds at any value. Each of these
/// pins a different property of the cut, and each was found by asking P99's
/// fourth-rule question of the *iterated* side of `value.chars()`:
///
/// - **how much** survives — `chars().take(1)` keeps the shape of a bounded
///   echo while quoting a token prefix;
/// - **where it starts** — `chars().skip(1).take(…)` keeps the length and drops
///   the first character of the typo the echo exists to show, which a filler of
///   one repeated character cannot see;
/// - **what the bound counts** — a guard reading `value.len()` calls thirty `€`
///   (ninety bytes, thirty characters) over the bound and marks it truncated
///   when nothing was cut, which is a lie about the caller's own input in a
///   message whose entire job is to show it back.
#[test]
fn a_rejected_value_is_echoed_back_bounded_and_on_a_char_boundary() {
    let render = |repeats: usize| {
        parse_interaction(&json!({ "kind": "€".repeat(repeats) }))
            .expect_err("a run of '€' is not one of the four")
            .to_string()
    };

    let long = render(1_000);
    assert_eq!(
        long,
        render(1_000_000),
        "an error message must not grow with the value that provoked it"
    );
    assert!(
        long.contains('…'),
        "a truncated value must say it was truncated; got {long}"
    );
    // The same value under the bound is quoted whole, so the truncation is a
    // bound and not an unconditional shortening.
    assert!(render(3).contains("€€€"), "got {}", render(3));
    // And what survives the cut is a bound's worth, not a token prefix. Stated
    // as "more than ten" rather than as the exact bound because `MAX_ECHOED` is
    // private, and a test that had to be re-tuned alongside it would be pinning
    // the constant rather than the behaviour.
    assert!(
        long.matches('€').count() > 10,
        "a truncated value keeps the bound's worth of the caller's text, not a token prefix; \
         got {long}"
    );

    // What survives is a *prefix*: it starts where the caller's value starts.
    // A filler of one repeated character cannot see this, which is why the
    // value is marked at its head.
    let marked = parse_interaction(&json!({ "kind": format!("Zebra{}", "€".repeat(1_000)) }))
        .expect_err("a run of '€' behind a word is not one of the four")
        .to_string();
    assert!(
        marked.contains("'Zebra€"),
        "the echo starts where the caller's value starts; got {marked}"
    );

    // The bound counts characters, not bytes. Thirty '€' is ninety bytes and
    // thirty characters, so a byte-counting guard marks it truncated when
    // nothing was cut.
    let under = render(30);
    assert!(
        !under.contains('…'),
        "a value inside the bound must not be marked as truncated; got {under}"
    );
}

async fn post(router: axum::Router, uri: &str, body: serde_json::Value) -> (StatusCode, String) {
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("a POST request builds"),
        )
        .await
        .expect("the router answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("the body fits");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn router() -> axum::Router {
    build_router(AppState::default(), &BindConfig::loopback())
}

const SESSION: &str = "/api/sessions/9d1ad699-0000-4000-8000-000000000001/interactions";

/// **The test the plan had no equivalent of, and the one that matters most.**
///
/// `build_router` is *constructed* here, which is the whole assertion: `axum`
/// 0.8 panics inside `Router::route` on the 0.7 `/:param` form the plan
/// specified, so a crate carrying that form fails this test by panicking before
/// a single status is compared. Three unit tests on `parse_interaction` cannot
/// see that at all.
///
/// The status assertions on top of it pin that the route is reached through the
/// `/api` nest rather than falling through to the asset router's SPA fallback —
/// `200` with an `index.html` body is what "not mounted" looks like here, and it
/// is not obviously wrong from the outside.
#[tokio::test]
async fn the_route_is_mounted_under_the_api_namespace() {
    let (status, body) = post(router(), SESSION, json!({"kind": "soft_interrupt"})).await;

    assert_eq!(
        status,
        StatusCode::NOT_IMPLEMENTED,
        "a well-formed interaction reaches the handler; body was {body}"
    );
}

/// **`501` and not `202`.** The plan returned `202 Accepted` after parsing the
/// body and dropping the result. Nothing in this workspace can deliver an
/// interaction anywhere — `roundhouse-web` holds no session-actor handle — so
/// `202` would tell a client that pressed `Esc` that the interrupt landed while
/// nothing received it.
///
/// The body is asserted, not just the status: a client that shows the reason to
/// a human is the difference between "the agent ignored me" and "this daemon
/// cannot do that yet", and it is what makes the residual visible from outside
/// the source tree.
#[tokio::test]
async fn a_parsed_interaction_is_refused_honestly_rather_than_accepted_falsely() {
    for kind in [
        json!({"kind": "soft_interrupt"}),
        json!({"kind": "hard_cancel"}),
        json!({"kind": "queue", "text": "also check the changelog"}),
        json!({"kind": "steer", "text": "stop, use the other branch"}),
    ] {
        let (status, body) = post(router(), SESSION, kind.clone()).await;
        assert_eq!(
            status,
            StatusCode::NOT_IMPLEMENTED,
            "{kind} must not report success while nothing receives it"
        );
        let body: serde_json::Value = serde_json::from_str(&body).expect("an /api error is JSON");
        assert!(
            body["error"]
                .as_str()
                .expect("the error is a string")
                .contains("nothing received it"),
            "the refusal must say what is missing; got {body}"
        );
    }
}

/// Request-shape validation is live through the route, not only through
/// `parse_interaction` — which is what lets a client build against the four
/// inputs before dispatch exists.
#[tokio::test]
async fn a_malformed_interaction_is_a_400_through_the_route() {
    let (status, body) = post(router(), SESSION, json!({"kind": "queue"})).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let body: serde_json::Value = serde_json::from_str(&body).expect("an /api error is JSON");
    assert!(
        body["error"]
            .as_str()
            .expect("the error is a string")
            .contains("requires non-empty text"),
        "got {body}"
    );
}

/// A path segment that is not a session id is a `400`, not a `501`: `501` would
/// say the request was fine and the server was not.
#[tokio::test]
async fn a_session_id_that_is_not_a_uuid_is_rejected_before_the_501() {
    let (status, body) = post(
        router(),
        "/api/sessions/not-a-uuid/interactions",
        json!({"kind": "soft_interrupt"}),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("session id is not a UUID"), "got {body}");
}

/// **Every error body under `/api` is `{"error": …}`** (`crate::api_error`),
/// and an `axum` extractor rejection is the one path that would silently answer
/// plain text instead — which is why the handler takes
/// `Result<Json<_>, JsonRejection>` rather than `Json<_>`.
///
/// Both rejection shapes are exercised: a wrong content type, and a body that
/// is not JSON at all. A client doing `res.json()` must not get a parse error
/// where a reason belongs, on any path.
///
/// # The two statuses are asserted, not merely their class
///
/// The handler keeps `rejection.status()` rather than hardcoding one status, and
/// the stated reason is that it distinguishes an unsupported content type from
/// unparseable JSON. `is_client_error()` does not check that — hardcoding
/// `BAD_REQUEST` passes it — so the distinction the code is written for is
/// pinned here as the two statuses `axum` 0.8.4 actually chooses: `415` for the
/// content type, `400` for the syntax.
#[tokio::test]
async fn an_extractor_rejection_is_json_like_every_other_api_error() {
    for (content_type, body, expected) in [
        (
            "text/plain",
            "{\"kind\": \"soft_interrupt\"}",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            "application/json",
            "this is not json",
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let response = router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(SESSION)
                    .header("host", "127.0.0.1")
                    .header("content-type", content_type)
                    .body(Body::from(body))
                    .expect("a POST request builds"),
            )
            .await
            .expect("the router answers");

        let status = response.status();
        assert!(
            status.is_client_error(),
            "a rejected body is the caller's error; got {status}"
        );
        assert_eq!(
            status, expected,
            "the handler keeps axum's own status so that {content_type} is distinguishable from \
             unparseable JSON; got {status}"
        );

        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("the body fits");
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            panic!(
                "an /api rejection must be JSON, not axum's plain text; got {}",
                String::from_utf8_lossy(&bytes)
            )
        });
        assert!(
            parsed["error"].is_string(),
            "the namespace's error shape is {{\"error\": …}}; got {parsed}"
        );
    }
}

/// **The route exists under `/api` and nowhere else** — ruling P88 §A's gate is
/// worth exactly what this pins.
///
/// `the_route_is_mounted_under_the_api_namespace` proves the route *is* inside
/// the nest that `build_router` gates. It cannot prove there is no **second,
/// ungated** copy: merging `interaction::router()` onto `build_router`'s outer
/// chain as well as inside `api_router` leaves the `/api` path working, every
/// other test in this file passing, and `POST /sessions/{id}/interactions`
/// answering the handler with no token and no `Host` check in front of it. That
/// is not a hypothetical shape — it is the one P88 §A was written about, and it
/// survived the sweep until this test existed.
///
/// The un-prefixed path must therefore reach the **asset** surface, which is
/// what ruling P85 accepts as ungated, and not the handler.
#[tokio::test]
async fn the_route_is_not_also_served_outside_the_api_namespace() {
    let (status, body) = post(
        router(),
        "/sessions/9d1ad699-0000-4000-8000-000000000001/interactions",
        json!({"kind": "soft_interrupt"}),
    )
    .await;

    assert_ne!(
        status,
        StatusCode::NOT_IMPLEMENTED,
        "an interaction route outside /api is outside the LAN gate and the Host check; got {body}"
    );
    assert_ne!(
        status,
        StatusCode::BAD_REQUEST,
        "reaching the handler's own validation means the handler is mounted here; got {body}"
    );
}

/// The `/api` namespace fallback still answers, which is what ruling P88 §A's
/// gate rests on.
///
/// This is the assertion the plan's `/{session_id}` path would have broken: a
/// parameter at the root of the namespace matches `/api/no-such-route`, so a
/// `GET` there would answer `405 Method Not Allowed` from the interaction route
/// instead of reaching `api_not_found`'s `404`. The gate test one file over
/// probes exactly that path.
#[tokio::test]
async fn the_namespace_fallback_is_not_swallowed_by_the_session_parameter() {
    let response = router()
        .oneshot(
            Request::builder()
                .uri("/api/no-such-route")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .expect("a GET request builds"),
        )
        .await
        .expect("the router answers");

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "an unmatched /api path must reach api_not_found, not a session route"
    );
}
