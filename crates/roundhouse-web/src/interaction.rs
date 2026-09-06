//! §11.4's four distinct interaction inputs — soft interrupt, hard cancel,
//! queue, steer — as a request shape and a URL.
//!
//! §11.4: *"interrupt vs queue vs steer are four distinct, unambiguous
//! inputs"*, and §11.2 gives the TUI's spelling of the same four: `Esc` (soft
//! interrupt), `Esc Esc` (hard cancel), type + `Enter` (queue, delivered as the
//! next turn), type + `Ctrl-Enter` (steer now, injected at the next tool
//! boundary without killing in-flight work). The web client's four affordances
//! and the TUI's four bindings are **the same four inputs**; this is the wire
//! shape both post.
//!
//! # This is the first spelling of that vocabulary, not a fourth
//!
//! Checked before writing it, because adding a parallel vocabulary in a leaf
//! crate is the expensive mistake here. `grep` over `crates/` for `SoftInterrupt`,
//! `HardCancel`, `Steer`, `Queue`, `Interrupt`-as-a-user-action and
//! `InteractionInput` returns nothing outside this file. Nothing in the
//! workspace models more than one user-facing interruption input, and nothing
//! at all models queue or steer:
//!
//! - **`roundhouse-tui` has no input loop.** It is render + coalesce + socket
//!   client; `crossterm` is a dependency for its backend only, and there is no
//!   `KeyEvent` anywhere in it. §11.2's bindings exist as prose in
//!   `docs/architecture/08-ui-design.md` and nowhere else.
//! - **`roundhouse_proto::ClientRequest` has no cancel variant yet**, though its
//!   own doc comment reserves one: *"later phases add variants (attach,
//!   approve, cancel, …)"*. That is where a shared client→daemon vocabulary
//!   belongs, and this module is deliberately not putting one there — see below.
//!
//! What *does* exist is **downstream mechanism at three different layers**,
//! none of it a competitor and all of it a plausible dispatch target:
//! `roundhouse_core::CancelReason` (why a cancel was recorded in the event log),
//! `roundhouse_flow::control::cancel` (a durable `workflow_run` state
//! transition), and `roundhouse_engine::SessionActor::cancel` /
//! `roundhouse_tools::shell::cancel_running_shell` (actor teardown and
//! process-group kill). Each is one binary "stop"; none distinguishes soft from
//! hard, and none carries text.
//!
//! **So the TUI should converge on [`InteractionInput`] rather than invent a
//! second set of names**, and whoever wires dispatch should consider promoting
//! it to `roundhouse-proto` next to `ClientRequest` at that point. It is not
//! promoted here because nothing consumes it yet, and a wire type with no
//! consumer is a contract frozen before anyone has had to satisfy it.
//!
//! ## One name to avoid
//!
//! `roundhouse_core::TaskState::Interrupted` already exists and means
//! **daemon-restart crash recovery** (S-SESS-4), explicitly *not* a user
//! interrupt. If [`InteractionInput::SoftInterrupt`] ever folds into a task
//! state it must not land on that variant.
//!
//! # Nothing receives an interaction
//!
//! [`router`]'s handler answers `501 Not Implemented`. This crate holds no
//! session-actor handle and there is no sink anywhere in Subsystem D to hand a
//! parsed input to. The URL and the request shape are real deliverables and are
//! worth claiming now; reporting success for a request nothing acted on is not.
//! See [`post_interaction`] for the whole argument.
//!
//! **Still true after Task 9 (Phase 7), for a stronger reason than plumbing.**
//! A real session actor now exists (`roundhouse_engine::SessionActor`), so the
//! *sink* half of the argument above is no longer the whole story — but
//! `roundhouse-daemon`'s `socket_server::drive_session` only ever honors a
//! post-handshake request from **the connection that created the session**
//! (rulings W1-R37/W1-R52, the fail-closed answer to an unauthenticated
//! `Attach` — see that function's own doc comment). An HTTP `POST` carries no
//! connection identity that could ever be that creating connection: every
//! request is its own, brand-new TCP connection, gated only by the LAN token
//! (or nothing, on loopback) and the `Host` check, neither of which identifies
//! *which* browser tab, let alone which one issued the original
//! `CreateSession`. So wiring this endpoint to the real actor regardless of
//! plumbing would have to default the send side open — honoring an attached,
//! not-the-creator caller's request — which is exactly the approval-hijack
//! primitive those rulings forbid. `501` stays the honest answer until the web
//! layer has its own notion of "the connection that created this session," not
//! merely until the actor exists to receive one.

use axum::extract::rejection::JsonRejection;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use thiserror::Error;
use uuid::Uuid;

/// One of §11.4's four inputs, parsed from a request body.
///
/// # Why `Queue` and `Steer` carry text and the other two do not
///
/// The four are two pairs. `SoftInterrupt` and `HardCancel` are *stop* signals
/// with nothing to say: the whole content of the input is which of the two
/// severities the user chose. `Queue` and `Steer` are *messages* with a
/// delivery time — queue means "after this turn", steer means "at the next tool
/// boundary, without killing in-flight work" — so a payload is the entire
/// point, and an empty one would be a no-op dressed as an instruction.
///
/// That asymmetry is why they are one enum rather than a `kind` field beside an
/// `Option<String>`: the type makes "steer with nothing to steer toward"
/// unrepresentable, which is the property §11.4's word *unambiguous* is asking
/// for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InteractionInput {
    /// §11.2's `Esc`: stop what you are doing, keep the session.
    SoftInterrupt,
    /// §11.2's `Esc Esc`: stop, and tear down in-flight work.
    HardCancel,
    /// §11.2's type + `Enter`: deliver this as the next turn.
    Queue { text: String },
    /// §11.2's type + `Ctrl-Enter`: inject this at the next tool boundary,
    /// without killing in-flight work.
    Steer { text: String },
}

/// Why a body is not one of the four inputs.
///
/// Every variant's `Display` is what the `400` body says, so each one is
/// written as a sentence for a person reading a console. **Every value echoed
/// back is bounded** by [`bounded`] — the offending text is the caller's own,
/// so echoing it discloses nothing, but echoing it *unbounded* would let a
/// request choose the size of its own error response.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum InteractionError {
    /// The body is not a JSON object — an array, a string, `null`.
    ///
    /// Distinguished from [`Self::UnknownKind`] because a bare
    /// `"unknown interaction kind: ''"` for a body of `[]` names the wrong
    /// problem and sends the caller looking at their `kind` value.
    #[error("an interaction must be a JSON object, got {0}")]
    NotAnObject(&'static str),
    /// A field that is not `kind` or `text`. See [`parse_interaction`] for why
    /// this is refused rather than ignored.
    #[error("unknown field '{0}': an interaction carries only 'kind' and 'text'")]
    UnknownField(String),
    /// A `kind` that is not one of the four.
    #[error(
        "unknown interaction kind '{0}': expected one of soft_interrupt, hard_cancel, queue, steer"
    )]
    UnknownKind(String),
    /// `queue` or `steer` with no `text`, or with an empty one.
    #[error("'{0}' requires non-empty text: there is nothing to deliver without it")]
    MissingText(&'static str),
}

/// How much of a rejected value an error message may quote.
///
/// Small on purpose: the value is only there to help a human spot their typo,
/// and 64 characters is far more than any of the four kind names or either
/// field name needs.
const MAX_ECHOED: usize = 64;

/// A caller-supplied string, bounded and marked when it was cut.
///
/// `chars().take(…)` and not `&s[..n]`, which panics on a multi-byte boundary —
/// and a JSON field name is arbitrary UTF-8 chosen by whoever sent the request,
/// so that boundary is reachable by anyone who wants to reach it.
fn bounded(value: &str) -> String {
    if value.chars().count() <= MAX_ECHOED {
        return value.to_string();
    }
    let head: String = value.chars().take(MAX_ECHOED).collect();
    format!("{head}…")
}

/// The one thing an interaction body may carry besides `kind`.
const TEXT: &str = "text";
/// Which of the four this is.
const KIND: &str = "kind";

/// Parses §11.4's four inputs out of a request body.
///
/// # An unrecognised field is refused, not ignored
///
/// Deliberate, and the opposite of what a permissive parser would do. The
/// precedent is `roundhouse_policy`'s `PreapprovedBundle`, which carries
/// `#[serde(deny_unknown_fields)]` for the same reason: a misspelled *value*
/// was already rejected here (`"kind": "hard_cancle"` is an
/// [`InteractionError::UnknownKind`]), but a misspelled *field* was not, and
/// the two failures are equally likely and equally invisible.
///
/// The case that decides it is `{"kind": "queue", "txt": "…"}`. Ignoring
/// unknown fields answers *"'queue' requires non-empty text"* — which is wrong
/// in the way that costs a caller the most time, because they did supply text
/// and the message says they did not. Refusing names the typo instead.
///
/// It also fixes the direction that matters later: when a fifth field is added
/// (a steer's tool-boundary policy, say), a client sending it to an older
/// daemon gets a refusal rather than an interaction silently missing half its
/// meaning.
///
/// The unknown-field check runs **before** the `kind` check, because it is a
/// property of the whole document and its answer does not depend on which of
/// the four this is.
///
/// # `text` on `soft_interrupt`/`hard_cancel` is accepted and discarded
///
/// Also deliberate, and it is not in tension with the paragraph above: `text`
/// is a *known* field of this schema, so sending it is not a typo. It is what
/// the client naturally has. All four inputs come from one control — a compose
/// box plus a key — so a user who has typed half a message and then presses
/// `Esc` produces exactly this body. Refusing it would make the client
/// responsible for clearing its own draft before it can interrupt, which is
/// work at precisely the wrong moment; the draft stays in the box, and the
/// interrupt is what the request means.
///
/// [`InteractionInput`] has nowhere to put the text on those two variants, so
/// this is a discard the type makes visible rather than a silent one.
pub fn parse_interaction(body: &serde_json::Value) -> Result<InteractionInput, InteractionError> {
    let Some(object) = body.as_object() else {
        let shape = match body {
            serde_json::Value::Null => "null",
            serde_json::Value::Bool(_) => "a boolean",
            serde_json::Value::Number(_) => "a number",
            serde_json::Value::String(_) => "a string",
            serde_json::Value::Array(_) => "an array",
            serde_json::Value::Object(_) => unreachable!("as_object already returned None"),
        };
        return Err(InteractionError::NotAnObject(shape));
    };

    if let Some(unknown) = object
        .keys()
        .find(|key| ![KIND, TEXT].contains(&key.as_str()))
    {
        return Err(InteractionError::UnknownField(bounded(unknown)));
    }

    // A `kind` that is absent, or present but not a string, is the same
    // failure to the caller as a misspelled one: the request does not say
    // which of the four it is. `""` is not a legal kind, so it falls to the
    // `other` arm and is reported as the empty string it is.
    let kind = object.get(KIND).and_then(|v| v.as_str()).unwrap_or("");

    // Non-empty is the requirement, not merely present: `{"kind": "steer",
    // "text": ""}` is a steer toward nothing. A non-string `text` is treated
    // as absent for the same reason.
    let text = || {
        object
            .get(TEXT)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };

    match kind {
        "soft_interrupt" => Ok(InteractionInput::SoftInterrupt),
        "hard_cancel" => Ok(InteractionInput::HardCancel),
        "queue" => text()
            .map(|text| InteractionInput::Queue { text })
            .ok_or(InteractionError::MissingText("queue")),
        "steer" => text()
            .map(|text| InteractionInput::Steer { text })
            .ok_or(InteractionError::MissingText("steer")),
        other => Err(InteractionError::UnknownKind(bounded(other))),
    }
}

/// `POST /api/sessions/{session_id}/interactions` — **`501`, and that status is
/// the deliverable's honest half.**
///
/// # Why not `202 Accepted`
///
/// This task's plan returned `202` after parsing the body and dropping the
/// result, citing an integration test in "Task 7" against a fake session-actor
/// sink. No such sink exists — D7 is the SSE reconnect test — and nothing
/// anywhere in Subsystem D can dispatch an interaction: `roundhouse-web` holds
/// no session-actor handle, and nothing in the workspace even links this crate.
///
/// `202` means *"accepted for processing"*. Answering it here would tell a
/// client that pressed `Esc` that the interrupt landed, when nothing received
/// it — and "the user pressed Esc and the agent kept going" is the exact class
/// of bug this project's own overview cites as a reason it exists. A wrong
/// success is worse than a refusal, because a refusal is visible.
///
/// `501 Not Implemented` is what is true: the route exists, the request was
/// understood, and the server has no implementation for it. Whoever wires
/// dispatch changes one status and deletes this section.
///
/// # The body is still validated, and that is not busywork
///
/// A malformed body is a `400` before the `501`. The request shape is half of
/// what this task delivers, so it is live and observable now rather than
/// arriving with dispatch later — and it is what lets a client build against
/// the four inputs today. `tests/interaction.rs` reaches every one of those
/// answers through the real router.
///
/// # Rejections are JSON, like every other error under `/api`
///
/// The extractor is `Result<Json<_>, JsonRejection>` rather than `Json<_>`.
/// Taking `Json<_>` directly would let `axum` answer a bad content type or
/// unparseable body itself, with a **plain-text** body — and
/// [`crate::api_error`] states that every error under `/api` is
/// `{"error": …}`, which is what makes `res.json()` safe for a client on every
/// path. Catching the rejection is what keeps that true for the first route in
/// this crate that takes a body at all.
async fn post_interaction(
    Path(session_id): Path<String>,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    // Syntax only — there is no session to look up, and there would be nothing
    // to do with it if there were. It is checked because an id that is not an
    // id makes the whole URL meaningless, and `400` says so where `501` would
    // imply the request was fine and the server was not. Same check and same
    // parse as `sse::stream_session_events`, one route over.
    if Uuid::parse_str(&session_id).is_err() {
        return bad_request("session id is not a UUID");
    }

    let body = match body {
        Ok(Json(body)) => body,
        // The rejection's own `body_text()` is not rendered: it can quote the
        // offending bytes, and this response goes back over a LAN bind to a
        // caller authenticated as a device rather than a person. The status
        // `axum` chose is kept, since it distinguishes an unsupported content
        // type from unparseable JSON.
        Err(rejection) => {
            return (
                rejection.status(),
                crate::api_error("an interaction body must be a JSON object"),
            )
                .into_response()
        }
    };

    // Bound rather than discarded at the `match`, so that the day a sink exists
    // the parsed value is already named and in scope at the point it has to be
    // handed over. The underscore is what says nothing consumes it *yet*.
    let _input = match parse_interaction(&body) {
        Ok(input) => input,
        Err(error) => return bad_request(&error.to_string()),
    };

    (
        StatusCode::NOT_IMPLEMENTED,
        crate::api_error(
            "this daemon parses interactions but cannot yet deliver one: no session-actor sink is \
             wired to this route, so nothing received it",
        ),
    )
        .into_response()
}

/// A `400` in the `/api` namespace's error shape.
fn bad_request(reason: &str) -> Response {
    (StatusCode::BAD_REQUEST, crate::api_error(reason)).into_response()
}

/// The interaction routes, merged into [`crate::build_router`]'s single API
/// router (ruling P88 §A — merging there is what makes them gated and
/// `Host`-checked by the same act that registers them).
///
/// # The path is `/sessions/{session_id}/interactions`, and both halves matter
///
/// **`{session_id}` and not `:session_id`.** This workspace pins `axum` at
/// `=0.8.4`, whose `matchit` takes the braced form and **panics at
/// `Router::route`** on the 0.7 colon form. This task's plan specified the
/// colon form, and none of its tests built a router — so its suite would have
/// been green over a crate that panicked the moment anything mounted the route.
/// `tests/interaction.rs` builds the real router through
/// [`crate::build_router`] for exactly that reason; a unit test on
/// [`parse_interaction`] cannot see this class of defect at all.
///
/// **`/sessions/{session_id}/…` and not `/{session_id}`.** The plan's path
/// registers a parameter at the *root* of the `/api` namespace, where it
/// swallows every single-segment path under it. `/api/runs` would survive on
/// `matchit`'s static-beats-parameter priority, but `/api/no-such-route` would
/// match `{session_id}` and answer `405 Method Not Allowed` instead of reaching
/// [`crate::api_not_found`]'s `404` — quietly turning the namespace fallback
/// that ruling P88 §A depends on into something that answers for only some
/// paths. The prefixed form is also what [`crate::sse::router`] already uses
/// for the same id one route over, so a session's two endpoints sit together.
pub fn router() -> Router<crate::AppState> {
    Router::new().route(
        "/sessions/{session_id}/interactions",
        post(post_interaction),
    )
}
