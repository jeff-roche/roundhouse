//! `session/request_permission` handling for Roundhouse acting on the
//! permission-request path of the Agent Client Protocol.
//!
//! **RULING C-P5 (binding over the original task brief):** the brief's
//! `AcpPermissionResponse { AllowOnce, AllowAlways, Reject }` does not exist
//! on the real ACP wire and cannot be serialized into a real response at
//! all. Verified against `agent-client-protocol-schema` 1.5.0's
//! `v1/client.rs`: every allow or deny is expressed by **selecting one of
//! the options the peer itself offered**, by `option_id`
//! (`RequestPermissionRequest.options: Vec<PermissionOption>`), never by a
//! free-standing verdict enum. This module selects from those offered
//! options instead of fabricating a verdict type.
//!
//! **Role note (SEC-7, round-2 review):** `session/request_permission` is
//! answered by the ACP **client** role — the schema marks it
//! `x-side = "client"` (the agent sends the request; the client decides and
//! replies). This module lives under `src/server/` because the task plan
//! names that path and `crate::decision` (Task 4/C4) imports
//! `crate::server::PolicyOutcome` from here — the directory name does not
//! describe an ACP "server" role. Whichever Roundhouse component eventually
//! calls [`handle_request_permission`] is acting as the ACP **client**
//! responding to a peer **agent**'s request.
//!
//! **`options: &[PermissionOption]` is supplied by that untrusted peer, not
//! by Roundhouse.** It cannot be trusted to be well-formed, non-adversarial,
//! or offered in good faith. Every extra check in this module beyond "look
//! up the required kind" — [`ambiguous_option_ids`], the `Ask`-never-
//! `RejectAlways` restriction, refusing to select an unmatched kind — exists
//! because of that, not out of general caution.
use crate::peer_text::escape_and_cap_peer_str;
use agent_client_protocol::schema::v1::{
    PermissionOption, PermissionOptionId, PermissionOptionKind, RequestPermissionOutcome,
    SelectedPermissionOutcome, ToolCallUpdate, ToolKind,
};
use roundhouse_core::PolicyDecision;
use serde_json::Value;
use std::collections::HashSet;
use thiserror::Error;

/// The one real decision type is Phase 0's payload-free `PolicyDecision`
/// (`{ Allow, Ask, Deny }`) — this struct threads it alongside the extra
/// data this crate's callers need (the matched rule's name, a human-legible
/// hint), never replacing it with a second, incompatible enum.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyOutcome {
    pub decision: PolicyDecision,
    pub rule: Option<String>,
    pub hint: Option<String>,
}

/// Thin seam over Phase 2's real `PolicyEngine` so this crate's server logic
/// is unit-testable without linking roundhouse-policy's full rule evaluator.
pub trait PolicyEngineLike {
    fn decide(&self, tool: &str, args: &Value) -> PolicyOutcome;
}

pub struct AcpServer<'a> {
    pub policy: &'a dyn PolicyEngineLike,
}

/// This must fail closed: nothing anywhere in this module converts any of
/// these variants into a selection. Each carries enough context (tool,
/// decision, and/or the offered kinds) to log what happened without a
/// caller having to re-derive it.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PermissionError {
    #[error(
        "no PermissionOption of a kind required by {decision:?} was offered for tool {tool:?}; offered kinds: {offered_kinds:?}"
    )]
    NoMatchingOption {
        tool: String,
        decision: PolicyDecision,
        offered_kinds: Vec<PermissionOptionKind>,
    },

    /// SEC-4 (round-2 review): `Ask` may select `RejectOnce` but must never
    /// fall back to `RejectAlways` the way `Deny` does — see
    /// [`handle_request_permission`]'s doc for why. This is a distinct
    /// variant from `NoMatchingOption` specifically so the fail-closed
    /// reasoning ("we refused to fall back," not merely "nothing matched")
    /// is legible in the error itself, including when `RejectAlways` *was*
    /// offered.
    #[error(
        "Ask decision for tool {tool:?} has no RejectOnce option to select; RejectAlways cannot be used as a fallback for Ask (unlike for Deny) because that would permanently discard a still-pending human decision — offered kinds: {offered_kinds:?}"
    )]
    AskCannotFallBackToRejectAlways {
        tool: String,
        offered_kinds: Vec<PermissionOptionKind>,
    },

    /// SEC-1 (round-2 review): selection is by `kind`, but the only thing a
    /// wire response can name back is `option_id` — nothing in the protocol
    /// requires ids to be unique or non-empty. Offered options with an
    /// empty or duplicated `option_id` are refused before any selection is
    /// attempted; see [`ambiguous_option_ids`].
    #[error(
        "offered PermissionOptions for tool {tool:?} are ambiguous and cannot be trusted to bind a decision to a single option: {reason}"
    )]
    AmbiguousOptions { tool: String, reason: String },

    /// SEC-2 (round-2 review): [`normalize_tool_call_for_policy`] refuses a
    /// `ToolCallUpdate` with no `rawInput` rather than substituting `{}`,
    /// since that substitution is indistinguishable from a real empty-args
    /// call and would let a peer bypass any policy rule that classifies on
    /// argument content.
    ///
    /// **`tool_call_id` is peer-controlled (fix round 2, Item 4):** an
    /// earlier ruling declined to cap it, judging the generalization from
    /// `&PermissionOptionId` to `&str` that would require "half a fix for a
    /// full round"; fix round 1 performed that generalization (Ruling
    /// C-P54), so the cost that justified deferring is gone. This field
    /// always holds the output of [`escape_and_cap_peer_str`] — already
    /// escaped and capped to at most [`crate::peer_text::PEER_STR_MAX_LEN`] bytes — which is
    /// why the display format above interpolates it with `{tool_call_id}`
    /// (plain `Display`) rather than `{tool_call_id:?}`: re-applying `Debug`
    /// to an already-`Debug`-escaped string would double-escape it.
    #[error(
        "ToolCallUpdate {tool_call_id} has no rawInput; substituting an empty object would be indistinguishable from a real empty-args call and could bypass policy rules that classify on argument content"
    )]
    MissingRawInput { tool_call_id: String },

    /// SEC-2 (round-2 review): [`normalize_tool_call_for_policy`] refuses a
    /// `ToolCallUpdate` whose `kind` is absent or `ToolKind::Other` — see
    /// that function's doc for why `title` is deliberately never used as a
    /// fallback identifier.
    ///
    /// **`tool_call_id` is peer-controlled (fix round 2, Item 4):** same
    /// escape-and-cap discipline as [`MissingRawInput`](Self::MissingRawInput)
    /// above, and the same reason this field is interpolated with
    /// `{tool_call_id}` rather than `{tool_call_id:?}`.
    #[error(
        "ToolCallUpdate {tool_call_id} does not identify a tool: `kind` is missing or ToolKind::Other (the wire default and the deserialization fallback for any kind this SDK version doesn't recognize), and `title` is agent-authored free text, never used as a tool identifier"
    )]
    UnidentifiableTool { tool_call_id: String },
}

fn find_option(
    options: &[PermissionOption],
    kind: PermissionOptionKind,
) -> Option<&PermissionOption> {
    options.iter().find(|opt| opt.kind == kind)
}

/// Returns a human-legible reason `options` cannot be trusted to bind a
/// decision to a unique option (an empty `option_id`, or the same
/// `option_id` reused across more than one offered option), or `None` if
/// every id is present, non-empty, and unique.
///
/// **SEC-1 (round-2 review):** selection elsewhere in this module is done by
/// `kind`, but the wire response we build only ever names an `option_id`
/// (`RequestPermissionResponse { outcome: Selected(SelectedPermissionOutcome
/// { option_id, .. }) } }`). Nothing in the protocol requires `option_id`s to
/// be unique or non-empty, so an untrusted peer offering
/// `[{option_id: "go", kind: RejectOnce}, {option_id: "go", kind: AllowOnce}]`
/// can make our `Selected{option_id: "go"}` response resolve to whichever
/// kind *it* prefers, once *it* reads that id back — we'd have decided
/// "deny" and recorded it as such, while the peer legitimately reads back an
/// allow. Refusing ambiguous input outright, before ever selecting, closes
/// that off.
///
/// **FIX round 4:** the duplicate-id reason embeds a peer-controlled
/// `option_id`, so it goes through `escape_and_cap_peer_str` rather than an
/// ad-hoc `{:?}`. The `{:?}` alone escaped correctly but bounded nothing: a
/// peer sharing one multi-megabyte duplicate id across two offered options
/// inflated every log line that renders the resulting
/// `PermissionError::AmbiguousOptions`, with further amplification from
/// `\u{...}` escape expansion. Same escaping, plus the
/// [`crate::peer_text::PEER_STR_MAX_LEN`] cap this module already applies one
/// function away.
fn ambiguous_option_ids(options: &[PermissionOption]) -> Option<String> {
    let mut seen: HashSet<&PermissionOptionId> = HashSet::new();
    for opt in options {
        if opt.option_id.0.is_empty() {
            return Some("an offered PermissionOption has an empty option_id".to_string());
        }
        if !seen.insert(&opt.option_id) {
            return Some(format!(
                "option_id {} is offered by more than one PermissionOption",
                escape_and_cap_peer_str(opt.option_id.0.as_ref())
            ));
        }
    }
    None
}

/// Selects a wire-level `RequestPermissionOutcome` from the options the peer
/// offered, per our engine's `PolicyDecision` for `tool`/`args`. Security
/// rules, in force regardless of how the peer phrased its options:
///
/// - `options` is validated first (see [`ambiguous_option_ids`]): an empty
///   or duplicated `option_id` anywhere in it fails the whole call with
///   `Err(PermissionError::AmbiguousOptions)` before any selection is
///   attempted. Validate first, select second.
/// - `Allow` selects the offered `AllowOnce` option — **never `AllowAlways`**,
///   since selecting that would persist a grant on the peer's side that our
///   engine never made.
/// - `Deny` selects `RejectOnce`, falling back to `RejectAlways` only if no
///   `RejectOnce` was offered.
/// - `Ask` selects `RejectOnce` **only** — it does **not** fall back to
///   `RejectAlways` the way `Deny` does. `Ask` means a human decision is
///   pending; `RejectAlways` tells a conforming peer to permanently remember
///   the rejection and never ask again, which would make a later human
///   `Allow` unreachable through this protocol (a `session/request_permission`
///   is answered once). `Deny`'s rejection is real and final, so
///   `RejectAlways` is a safe fallback there; `Ask`'s is provisional, so it
///   isn't. If no `RejectOnce` was offered for `Ask`, this returns
///   `Err(PermissionError::AskCannotFallBackToRejectAlways)` rather than ever
///   selecting `RejectAlways`. This function does not block waiting for the
///   human decision either way; the caller is responsible for re-entering it
///   (or the underlying `session/request_permission` exchange) once the real
///   approval flow (Phase 2's persisted `Suspended{AwaitingApproval}`, §6.4)
///   resolves the human's answer into a fresh `Allow`/`Deny` from the policy
///   engine.
/// - If no option of the required kind was offered at all (and the decision
///   isn't the `Ask`-specific case above), this returns
///   `Err(PermissionError::NoMatchingOption)`. **This must fail closed**: no
///   code path turns any `PermissionError` variant into a selection.
///
/// `PermissionOptionKind` and `RequestPermissionOutcome` are both
/// `#[non_exhaustive]` in the SDK; this function never exhaustively matches
/// on `PermissionOptionKind` (it searches by equality instead), so an
/// unknown future kind is simply never selected — it can't be mistaken for
/// an allow.
pub fn handle_request_permission(
    server: &AcpServer,
    tool: &str,
    args: &Value,
    options: &[PermissionOption],
) -> Result<RequestPermissionOutcome, PermissionError> {
    if let Some(reason) = ambiguous_option_ids(options) {
        return Err(PermissionError::AmbiguousOptions {
            tool: tool.to_string(),
            reason,
        });
    }

    let outcome = server.policy.decide(tool, args);
    let selected = match outcome.decision {
        PolicyDecision::Allow => find_option(options, PermissionOptionKind::AllowOnce),
        PolicyDecision::Deny => find_option(options, PermissionOptionKind::RejectOnce)
            .or_else(|| find_option(options, PermissionOptionKind::RejectAlways)),
        PolicyDecision::Ask => find_option(options, PermissionOptionKind::RejectOnce),
    };

    match selected {
        Some(opt) => Ok(RequestPermissionOutcome::Selected(
            SelectedPermissionOutcome::new(opt.option_id.clone()),
        )),
        None if outcome.decision == PolicyDecision::Ask => {
            Err(PermissionError::AskCannotFallBackToRejectAlways {
                tool: tool.to_string(),
                offered_kinds: options.iter().map(|opt| opt.kind).collect(),
            })
        }
        None => Err(PermissionError::NoMatchingOption {
            tool: tool.to_string(),
            decision: outcome.decision,
            offered_kinds: options.iter().map(|opt| opt.kind).collect(),
        }),
    }
}

/// Extracts the selected `PermissionOptionId` from a `RequestPermissionOutcome`
/// this crate did not itself construct — e.g. one read back off the wire, or
/// one built by a caller that already knows a `session/cancel` raced the
/// prompt. Returns `None` for `Cancelled` ("the client sent `session/cancel`
/// before the user responded" — never an allow, never a deny) and for any
/// future, currently-unknown outcome variant the `#[non_exhaustive]` wildcard
/// arm below catches. Consumers of a `RequestPermissionOutcome` should route
/// through this instead of assuming `Selected`.
///
/// **The returned id is untrusted peer input — never log it via `Display`.**
/// `PermissionOptionId` derives derive_more's `Display`, which writes its
/// `Arc<str>` content verbatim, so
/// `format!("selected option id: {id}")` writes attacker-chosen bytes —
/// newlines and ANSI escapes included — straight into an audit trail the
/// event log physically cannot `UPDATE` or `DELETE`; that is the same
/// forged-approval-line hazard `SelectionResolution::UnknownOptionId`
/// removes by carrying an already-escaped `String`. This function
/// deliberately still returns the raw id, because its legitimate use is
/// equality lookup against the offered `options` (see [`resolve_selection`]),
/// where escaping would break id matching. A caller that needs to *log* it
/// must escape and length-cap it first — at most
/// [`crate::peer_text::PEER_STR_MAX_LEN`] bytes, the same discipline this module
/// applies elsewhere.
pub fn selected_option_id(outcome: &RequestPermissionOutcome) -> Option<&PermissionOptionId> {
    match outcome {
        RequestPermissionOutcome::Selected(sel) => Some(&sel.option_id),
        RequestPermissionOutcome::Cancelled => None,
        _ => None,
    }
}

/// What resolving a `RequestPermissionOutcome`'s selected id against a set
/// of offered `options` establishes — see [`resolve_selection`].
///
/// **FIX-B (round-3 review):** `resolve_selection` originally returned
/// `Option<PermissionOptionKind>`, reintroducing exactly the carrier
/// `McpCallDisposition` (SEC-3, round-2 review) was created to move away
/// from — this function's own doc already says the id→kind lookup **is**
/// the authorization decision, so collapsing it back into an `Option` was
/// inconsistent with that lesson. Worse, the collapsed `None` merged three
/// materially different situations an investigation needs to tell apart:
/// the peer legitimately cancelled; the peer named an id that was never
/// offered (a protocol violation worth logging); and the options list
/// itself is ambiguous (an attack signal, see [`ambiguous_option_ids`]).
/// This enum keeps them distinct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionResolution {
    /// The outcome selected exactly this kind, unambiguously.
    Resolved(PermissionOptionKind),
    /// `RequestPermissionOutcome::Cancelled`: the peer sent `session/cancel`
    /// before answering. Not a protocol violation, not an attack signal —
    /// just no selection was made.
    Cancelled,
    /// The outcome's `Selected.option_id` does not appear anywhere in
    /// `options`. Unlike `Cancelled`, this is the peer's response naming
    /// something it was never offered — a protocol violation worth logging
    /// on its own, separately from a legitimate cancellation.
    ///
    /// **Finding 2 (round-3 review):** this carries an already-escaped,
    /// length-capped `String` — produced by `escape_and_cap_peer_str` —
    /// **not** the raw `PermissionOptionId`. `PermissionOptionId` derives
    /// derive_more's `Display`, which writes its `Arc<str>` content
    /// verbatim; this variant's own doc used to describe the id as "worth
    /// logging on its own," and a caller that took that advice literally
    /// with `format!("unknown option id: {id}")` would write attacker-
    /// chosen bytes — newlines included — straight into an audit trail the
    /// event log physically cannot `UPDATE` or `DELETE`. A peer answering
    /// `session/request_permission` with an `option_id` containing
    /// `"\n[audit] resolve_selection: Resolved(AllowOnce)"` could forge an
    /// approval line that way. Carrying the escaped, capped form here makes
    /// that unsafe formatting unreachable rather than merely discouraged.
    ///
    /// **Invariant on this `String` (FIX round 4):** it is a bare `String`
    /// rather than a newtype marking "already escaped and capped," so the
    /// invariant is recorded here instead of in the type. The value is
    /// *always* the output of `escape_and_cap_peer_str` — escaped via
    /// `str`'s `Debug` formatting (so it is quoted, and control characters
    /// appear only in their escaped `\n` / `\u{...}` forms) and truncated to
    /// at most [`crate::peer_text::PEER_STR_MAX_LEN`] bytes. `resolve_selection` is
    /// the single construction site in this crate today, which is why a
    /// newtype would only add unused public surface for a mistake with
    /// nowhere to go. **Any future second construction site must preserve
    /// that invariant** — never place a raw `PermissionOptionId`, or any
    /// other unescaped peer-controlled string, into this variant.
    UnknownOptionId(String),
    /// `options` itself is ambiguous (see [`ambiguous_option_ids`]) and
    /// cannot be trusted to resolve any id to a single kind — the same
    /// fail-closed refusal [`handle_request_permission`] applies before
    /// ever selecting.
    AmbiguousOptions,
    /// `outcome` is some `RequestPermissionOutcome` variant this crate does
    /// not recognize (the type is `#[non_exhaustive]`; as of SDK 1.5.0 the
    /// only variants are `Cancelled`/`Selected`, so this is currently
    /// unreachable in practice). Kept distinct from `Cancelled` rather than
    /// folded into it, since a future variant might mean something entirely
    /// different — labeling the unknown as a cancellation would be a guess.
    UnrecognizedOutcome,
}

/// Resolves the `PermissionOptionKind` a `RequestPermissionOutcome` selected,
/// by looking its `option_id` up against the `options` a peer offered.
///
/// **SEC-1 (round-2 review):** in the direction where *we* sent a
/// `session/request_permission` request (with our own offered options) and
/// are reading back what the peer chose, this id→kind lookup **is** the
/// authorization decision — so it belongs here, audited once, rather than
/// reimplemented ad hoc by every caller that reads an outcome off the wire.
///
/// **Caller responsibility this function does not verify (deliberately, per
/// round-3 review):** `options` must be the same list that was offered in
/// the original `RequestPermissionRequest` this `outcome` answers. Nothing
/// in the plain SDK types lets this function check that binding on its own
/// — passing a mismatched `options` list is a caller error, a
/// daemon-integration convention point, not something detectable from here.
pub fn resolve_selection(
    options: &[PermissionOption],
    outcome: &RequestPermissionOutcome,
) -> SelectionResolution {
    if ambiguous_option_ids(options).is_some() {
        return SelectionResolution::AmbiguousOptions;
    }
    match outcome {
        RequestPermissionOutcome::Selected(sel) => {
            match options.iter().find(|opt| opt.option_id == sel.option_id) {
                Some(opt) => SelectionResolution::Resolved(opt.kind),
                None => SelectionResolution::UnknownOptionId(escape_and_cap_peer_str(
                    sel.option_id.0.as_ref(),
                )),
            }
        }
        RequestPermissionOutcome::Cancelled => SelectionResolution::Cancelled,
        _ => SelectionResolution::UnrecognizedOutcome,
    }
}

/// A `ToolKind` extracted from a peer's `ToolCallUpdate`, wrapped rather
/// than returned bare or as a `String`.
///
/// **FIX-A (round-3 review):** the original version of
/// [`normalize_tool_call_for_policy`] returned `(String, Value)` — the exact
/// shape [`handle_request_permission`]'s `(tool: &str, args: &Value, ..)`
/// consumes — built via `format!("{kind:?}")`. That was a trap, not a
/// guardrail, for two compounding reasons:
///
/// - `ToolKind` is a nine-value coarse *category* (`Read`, `Edit`, `Delete`,
///   `Move`, `Search`, `Execute`, `Think`, `Fetch`, `SwitchMode`), not a
///   Roundhouse tool identifier — `shell` and every other command-running
///   tool alike collapse into `Execute`.
/// - Returning a bare `String` type-checks directly against
///   `handle_request_permission`'s `tool: &str` parameter, with nothing at
///   the type level stopping `let (tool, args) = normalize(..)?;
///   handle_request_permission(&s, &tool, &args, opts)` — feeding a coarse
///   SDK category straight into a rule engine keyed on Roundhouse's own
///   tool namespace, silently.
///
/// This newtype closes that gap the same way `AcpClientTier` does elsewhere
/// in this crate: an opaque wrapper makes "the daemon forgot to map this"
/// a compile error instead of an invisible mistake. There is deliberately
/// no `From`/`Into`/`Display` to `&str`/`String` here — the daemon must
/// perform an explicit `AcpToolKindClaim -> &str` mapping (e.g.
/// `Execute -> "shell"`, informed by whatever else it knows about the call)
/// before it can call `handle_request_permission`.
///
/// The name says "claim" deliberately: per §6.4, such tasks record
/// `enforced_by = RemoteAgentClaim` — this is the peer's self-declared,
/// unverified category, not a validated Roundhouse tool name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcpToolKindClaim(pub ToolKind);

/// Normalizes a peer-supplied `ToolCallUpdate` (the `tool_call` field of an
/// incoming `RequestPermissionRequest` — see the module doc for which role
/// receives it) into the `(tool, args)` pair a daemon-owned namespace
/// mapping step needs before calling [`handle_request_permission`].
///
/// **SEC-2 (round-2 review): this must fail closed, not guess.**
/// `ToolCallUpdate` carries no tool-name field at all — verified against
/// `agent-client-protocol-schema` 1.5.0's `v1/tool_call.rs`
/// (`ToolCallUpdateFields { kind: Option<ToolKind>, title: Option<String>,
/// raw_input: Option<Value>, .. }`, all optional). The only candidates are:
///
/// - `fields.title` — agent-authored free prose, not a namespaced tool
///   identifier. **Deliberately never used here**: a peer could craft a
///   title to fool a string-matching policy rule into classifying the call
///   as something it isn't.
/// - `fields.kind: Option<ToolKind>` — whose `Other` variant is *both* the
///   `#[default]` value *and* the `#[serde(other)]` deserialization fallback
///   for any kind this SDK version doesn't recognize. So `Other`/absent
///   isn't "no kind was given," it's "any kind we can't distinguish," and
///   must not be treated as identifying one specific tool.
/// - `fields.raw_input: Option<Value>` — the closest thing to `args`, but
///   optional; a peer can omit it outright.
///
/// **FIX-A (round-3 review): this returns [`AcpToolKindClaim`], never a
/// `String`.** `format!("{kind:?}")` would also have been unsound as a
/// policy key on its own terms: it's `Debug`-derive output, not stable SDK
/// API, so an upstream variant rename would silently change the string a
/// policy rule matches on. Mapping `kind` onto Roundhouse's own tool
/// namespace (`shell`/`read`/`write`/`edit`/`find`/...) is daemon-owned
/// integration knowledge this crate does not have and, per this
/// subsystem's standing rules (`roundhouse-acp` depends on
/// `{roundhouse-core, roundhouse-proto}` only), must not acquire. **The
/// daemon supplies the namespace mapping; this function's only job is to
/// refuse rather than guess** when the wire data can't support a real
/// decision:
///
/// - `fields.raw_input` absent → `Err(MissingRawInput)`. This is
///   deliberately distinct from a present-but-empty `{}` object: collapsing
///   "the peer sent nothing" into `args = json!({})` would let a peer bypass
///   any policy rule that classifies on argument content (e.g. shell command
///   text) just by omitting `rawInput`.
/// - `fields.kind` absent or `ToolKind::Other` → `Err(UnidentifiableTool)`.
///
/// **`tool_call_id` is peer-controlled and arbitrarily long (fix round 2,
/// Item 4).** Both error variants above route it through
/// [`escape_and_cap_peer_str`] rather than `ToolCallId`'s own `Display`
/// (which writes its `Arc<str>` content verbatim) before embedding it —
/// closing off the same forged-log-line and unbounded-log-inflation hazard
/// [`ambiguous_option_ids`] and [`resolve_selection`] already close for
/// `option_id`s.
pub fn normalize_tool_call_for_policy(
    update: &ToolCallUpdate,
) -> Result<(AcpToolKindClaim, Value), PermissionError> {
    let tool = match update.fields.kind {
        Some(kind) if kind != ToolKind::Other => AcpToolKindClaim(kind),
        _ => {
            return Err(PermissionError::UnidentifiableTool {
                tool_call_id: escape_and_cap_peer_str(update.tool_call_id.0.as_ref()),
            })
        }
    };
    let args = update
        .fields
        .raw_input
        .clone()
        .ok_or_else(|| PermissionError::MissingRawInput {
            tool_call_id: escape_and_cap_peer_str(update.tool_call_id.0.as_ref()),
        })?;
    Ok((tool, args))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_text::PEER_STR_MAX_LEN;
    use agent_client_protocol::schema::v1::ToolCallUpdateFields;

    struct FakePolicy(PolicyOutcome);
    impl PolicyEngineLike for FakePolicy {
        fn decide(&self, _tool: &str, _args: &Value) -> PolicyOutcome {
            self.0.clone()
        }
    }

    fn all_four_options() -> Vec<PermissionOption> {
        vec![
            PermissionOption::new("allow-once", "Allow once", PermissionOptionKind::AllowOnce),
            PermissionOption::new(
                "allow-always",
                "Allow always",
                PermissionOptionKind::AllowAlways,
            ),
            PermissionOption::new(
                "reject-once",
                "Reject once",
                PermissionOptionKind::RejectOnce,
            ),
            PermissionOption::new(
                "reject-always",
                "Reject always",
                PermissionOptionKind::RejectAlways,
            ),
        ]
    }

    #[test]
    fn allow_decision_selects_allow_once_never_allow_always() {
        let policy = FakePolicy(PolicyOutcome {
            decision: PolicyDecision::Allow,
            rule: None,
            hint: None,
        });
        let server = AcpServer { policy: &policy };
        let outcome = handle_request_permission(
            &server,
            "shell",
            &serde_json::json!({"cmd": "ls"}),
            &all_four_options(),
        )
        .expect("AllowOnce was offered");
        assert_eq!(
            selected_option_id(&outcome).map(|id| id.to_string()),
            Some("allow-once".to_string())
        );
    }

    #[test]
    fn deny_decision_selects_reject_once_when_offered() {
        let policy = FakePolicy(PolicyOutcome {
            decision: PolicyDecision::Deny,
            rule: Some("no-network".to_string()),
            hint: None,
        });
        let server = AcpServer { policy: &policy };
        let outcome =
            handle_request_permission(&server, "http", &serde_json::json!({}), &all_four_options())
                .expect("RejectOnce was offered");
        assert_eq!(
            selected_option_id(&outcome).map(|id| id.to_string()),
            Some("reject-once".to_string())
        );
    }

    #[test]
    fn deny_decision_falls_back_to_reject_always_when_reject_once_not_offered() {
        let policy = FakePolicy(PolicyOutcome {
            decision: PolicyDecision::Deny,
            rule: None,
            hint: None,
        });
        let server = AcpServer { policy: &policy };
        let options = vec![
            PermissionOption::new("allow-once", "Allow once", PermissionOptionKind::AllowOnce),
            PermissionOption::new(
                "reject-always",
                "Reject always",
                PermissionOptionKind::RejectAlways,
            ),
        ];
        let outcome = handle_request_permission(&server, "http", &serde_json::json!({}), &options)
            .expect("RejectAlways was offered as a fallback");
        assert_eq!(
            selected_option_id(&outcome).map(|id| id.to_string()),
            Some("reject-always".to_string())
        );
    }

    #[test]
    fn ask_decision_selects_reject_once_when_offered() {
        let policy = FakePolicy(PolicyOutcome {
            decision: PolicyDecision::Ask,
            rule: None,
            hint: None,
        });
        let server = AcpServer { policy: &policy };
        let outcome = handle_request_permission(
            &server,
            "shell",
            &serde_json::json!({"cmd": "rm -rf /"}),
            &all_four_options(),
        )
        .expect("RejectOnce was offered");
        assert_eq!(
            selected_option_id(&outcome).map(|id| id.to_string()),
            Some("reject-once".to_string())
        );
    }

    #[test]
    fn ask_decision_does_not_fall_back_to_reject_always_when_reject_once_not_offered() {
        // SEC-4: unlike Deny, Ask must never fall back to RejectAlways —
        // that would permanently discard a still-pending human decision.
        let policy = FakePolicy(PolicyOutcome {
            decision: PolicyDecision::Ask,
            rule: None,
            hint: None,
        });
        let server = AcpServer { policy: &policy };
        let options = vec![
            PermissionOption::new("allow-once", "Allow once", PermissionOptionKind::AllowOnce),
            PermissionOption::new(
                "reject-always",
                "Reject always",
                PermissionOptionKind::RejectAlways,
            ),
        ];
        let err = handle_request_permission(&server, "shell", &serde_json::json!({}), &options)
            .expect_err("RejectOnce was not offered, and Ask must not settle for RejectAlways");
        assert_eq!(
            err,
            PermissionError::AskCannotFallBackToRejectAlways {
                tool: "shell".to_string(),
                offered_kinds: vec![
                    PermissionOptionKind::AllowOnce,
                    PermissionOptionKind::RejectAlways
                ],
            }
        );
    }

    #[test]
    fn missing_required_kind_fails_closed_with_no_matching_option() {
        let policy = FakePolicy(PolicyOutcome {
            decision: PolicyDecision::Allow,
            rule: None,
            hint: None,
        });
        let server = AcpServer { policy: &policy };
        // Only reject options offered — no AllowOnce for an Allow decision to select.
        let options = vec![
            PermissionOption::new(
                "reject-once",
                "Reject once",
                PermissionOptionKind::RejectOnce,
            ),
            PermissionOption::new(
                "reject-always",
                "Reject always",
                PermissionOptionKind::RejectAlways,
            ),
        ];
        let err = handle_request_permission(&server, "shell", &serde_json::json!({}), &options)
            .expect_err("no AllowOnce option was offered");
        assert_eq!(
            err,
            PermissionError::NoMatchingOption {
                tool: "shell".to_string(),
                decision: PolicyDecision::Allow,
                offered_kinds: vec![
                    PermissionOptionKind::RejectOnce,
                    PermissionOptionKind::RejectAlways
                ],
            }
        );
    }

    #[test]
    fn empty_options_never_produce_an_allow() {
        let policy = FakePolicy(PolicyOutcome {
            decision: PolicyDecision::Allow,
            rule: None,
            hint: None,
        });
        let server = AcpServer { policy: &policy };
        let err = handle_request_permission(&server, "shell", &serde_json::json!({}), &[])
            .expect_err("no options at all were offered");
        assert!(matches!(err, PermissionError::NoMatchingOption { .. }));
    }

    #[test]
    fn cancelled_outcome_is_neither_an_allow_nor_a_deny() {
        // A session/cancel racing the prompt: the peer must respond with
        // Cancelled to a pending request rather than a Selected outcome.
        // `selected_option_id` must not treat this as any kind of selection.
        assert_eq!(
            selected_option_id(&RequestPermissionOutcome::Cancelled),
            None
        );
    }

    // ---- SEC-1: ambiguous option_id handling ----

    #[test]
    fn duplicate_option_id_across_conflicting_kinds_is_rejected_before_selection() {
        // The exact attack from round-2 review: a peer offers the same
        // option_id under two different kinds. If we selected by kind and
        // emitted Selected{option_id: "go"}, a consumer resolving "go" back
        // to a kind by first match could read AllowOnce even though we
        // picked the RejectOnce entry — the peer chooses which. This must
        // be refused outright, not merely selected "correctly" by luck of
        // iteration order.
        let policy = FakePolicy(PolicyOutcome {
            decision: PolicyDecision::Deny,
            rule: None,
            hint: None,
        });
        let server = AcpServer { policy: &policy };
        let options = vec![
            PermissionOption::new("go", "Reject", PermissionOptionKind::RejectOnce),
            PermissionOption::new("go", "Allow", PermissionOptionKind::AllowOnce),
        ];
        let err = handle_request_permission(&server, "shell", &serde_json::json!({}), &options)
            .expect_err("duplicate option_id across conflicting kinds must be refused");
        assert!(matches!(err, PermissionError::AmbiguousOptions { .. }));
    }

    #[test]
    fn empty_option_id_is_rejected_before_selection() {
        let policy = FakePolicy(PolicyOutcome {
            decision: PolicyDecision::Allow,
            rule: None,
            hint: None,
        });
        let server = AcpServer { policy: &policy };
        let options = vec![PermissionOption::new(
            "",
            "Allow",
            PermissionOptionKind::AllowOnce,
        )];
        let err = handle_request_permission(&server, "shell", &serde_json::json!({}), &options)
            .expect_err("an empty option_id must be refused");
        assert!(matches!(err, PermissionError::AmbiguousOptions { .. }));
    }

    #[test]
    fn duplicate_option_id_with_the_same_kind_is_still_rejected() {
        // Same id offered twice under the *same* kind is also ambiguous —
        // a caller resolving the id can't tell which PermissionOption record
        // (e.g. differing `name`) the peer meant.
        let policy = FakePolicy(PolicyOutcome {
            decision: PolicyDecision::Allow,
            rule: None,
            hint: None,
        });
        let server = AcpServer { policy: &policy };
        let options = vec![
            PermissionOption::new("dup", "Allow (first)", PermissionOptionKind::AllowOnce),
            PermissionOption::new("dup", "Allow (second)", PermissionOptionKind::AllowOnce),
        ];
        let err = handle_request_permission(&server, "shell", &serde_json::json!({}), &options)
            .expect_err("duplicate option_id must be refused even under one kind");
        assert!(matches!(err, PermissionError::AmbiguousOptions { .. }));
    }

    #[test]
    fn ambiguous_options_reason_caps_an_over_long_duplicate_option_id() {
        // FIX round 4: the duplicate-id reason embeds a peer-controlled
        // option_id. `{:?}` escaped it but bounded nothing, so a peer could
        // inflate every log line rendering this error by duplicating one
        // very long id. Routing through escape_and_cap_peer_str caps it,
        // matching the discipline SelectionResolution::UnknownOptionId
        // already follows.
        let long_id = "z".repeat(PEER_STR_MAX_LEN * 50);
        let policy = FakePolicy(PolicyOutcome {
            decision: PolicyDecision::Allow,
            rule: None,
            hint: None,
        });
        let server = AcpServer { policy: &policy };
        let options = vec![
            PermissionOption::new(
                long_id.clone(),
                "Allow (first)",
                PermissionOptionKind::AllowOnce,
            ),
            PermissionOption::new(
                long_id.clone(),
                "Allow (second)",
                PermissionOptionKind::AllowOnce,
            ),
        ];
        let err = handle_request_permission(&server, "shell", &serde_json::json!({}), &options)
            .expect_err("duplicate option_id must be refused");
        let PermissionError::AmbiguousOptions { reason, .. } = err else {
            panic!("expected AmbiguousOptions, got {err:?}");
        };
        assert!(
            !reason.contains(&long_id),
            "the full peer-controlled id must not appear verbatim in the reason"
        );
        // The reason is a fixed sentence plus the capped id, so its length
        // is bounded by that sentence plus PEER_STR_MAX_LEN — far
        // below the id's own length.
        assert!(
            reason.len() < PEER_STR_MAX_LEN + 64,
            "reason must be bounded by the cap plus the fixed message, got {} bytes",
            reason.len()
        );
    }

    // ---- resolve_selection ----
    //
    // FIX-B (round-3 review): these four tests exist specifically to prove
    // the four SelectionResolution outcomes are distinguishable, not
    // collapsed into one shape the way the old `Option` return type was.

    #[test]
    fn resolve_selection_returns_the_kind_for_a_valid_unambiguous_selection() {
        let options = all_four_options();
        let outcome =
            RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new("reject-once"));
        assert_eq!(
            resolve_selection(&options, &outcome),
            SelectionResolution::Resolved(PermissionOptionKind::RejectOnce)
        );
    }

    #[test]
    fn resolve_selection_reports_ambiguous_options_distinctly() {
        let options = vec![
            PermissionOption::new("go", "Reject", PermissionOptionKind::RejectOnce),
            PermissionOption::new("go", "Allow", PermissionOptionKind::AllowOnce),
        ];
        let outcome = RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new("go"));
        assert_eq!(
            resolve_selection(&options, &outcome),
            SelectionResolution::AmbiguousOptions
        );
    }

    #[test]
    fn resolve_selection_reports_an_unknown_option_id_distinctly_from_ambiguous_or_cancelled() {
        // A peer naming an id it was never offered is a protocol violation
        // worth logging on its own — not the same thing as a cancellation
        // or an ambiguous options list, even though all three used to
        // collapse into the same `None`.
        let options = all_four_options();
        let outcome =
            RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new("not-an-offered-id"));
        assert_eq!(
            resolve_selection(&options, &outcome),
            SelectionResolution::UnknownOptionId(format!("{:?}", "not-an-offered-id"))
        );
    }

    // Note: the escape_and_cap_peer_str / PEER_STR_MAX_LEN unit tests moved
    // to `crate::peer_text::tests` in fix round 2 (Item 5), alongside the
    // function and constant they exercise.

    #[test]
    fn resolve_selection_reports_cancelled_distinctly() {
        let options = all_four_options();
        assert_eq!(
            resolve_selection(&options, &RequestPermissionOutcome::Cancelled),
            SelectionResolution::Cancelled
        );
    }

    // ---- normalize_tool_call_for_policy ----

    #[test]
    fn normalize_tool_call_extracts_tool_and_args_when_both_are_present() {
        let update = ToolCallUpdate::new(
            "tc-1",
            ToolCallUpdateFields::new()
                .kind(ToolKind::Execute)
                .raw_input(serde_json::json!({"cmd": "ls"})),
        );
        let (tool, args) = normalize_tool_call_for_policy(&update).expect("both fields present");
        assert_eq!(tool, AcpToolKindClaim(ToolKind::Execute));
        assert_eq!(args, serde_json::json!({"cmd": "ls"}));
    }

    #[test]
    fn normalize_tool_call_result_does_not_type_check_directly_against_handle_request_permission() {
        // FIX-A (round-3 review), compile-time proof: this is intentionally
        // NOT a test that asserts behavior — it's here so that if
        // `AcpToolKindClaim` ever grows a `Deref`/`AsRef<str>`/`Display`
        // impl that would let it flow into `handle_request_permission`'s
        // `tool: &str` parameter without an explicit daemon-owned mapping
        // step, a reviewer sees this comment fail to describe reality
        // rather than the code failing to compile silently doing the wrong
        // thing. (`AcpToolKindClaim` has no such impl today — this normalize
        // step's whole point is that the daemon must write that mapping out
        // by hand.)
        let update = ToolCallUpdate::new(
            "tc-1",
            ToolCallUpdateFields::new()
                .kind(ToolKind::Execute)
                .raw_input(serde_json::json!({})),
        );
        let (tool, _args) = normalize_tool_call_for_policy(&update).expect("both fields present");
        // An explicit, daemon-owned mapping step, exactly as documented:
        let mapped_tool_name: &str = match tool {
            AcpToolKindClaim(ToolKind::Execute) => "shell",
            _ => "unknown",
        };
        assert_eq!(mapped_tool_name, "shell");
    }

    #[test]
    fn normalize_tool_call_escapes_and_caps_a_hostile_tool_call_id() {
        // FIX round 2 (Item 4): tool_call_id is peer-controlled and
        // arbitrarily long. This constructs one that is both — a fake audit
        // line plus enough padding to exceed the cap — and asserts both
        // PermissionError variants that embed it come back with no raw
        // newline and a bounded length, instead of the peer's bytes
        // verbatim.
        let hostile_id = format!(
            "x\n[audit] normalize_tool_call_for_policy: ok{}",
            "y".repeat(PEER_STR_MAX_LEN * 10)
        );

        let missing_raw_input = ToolCallUpdate::new(
            hostile_id.clone(),
            ToolCallUpdateFields::new().kind(ToolKind::Execute),
        );
        let err = normalize_tool_call_for_policy(&missing_raw_input)
            .expect_err("rawInput was never supplied");
        let PermissionError::MissingRawInput { tool_call_id } = err else {
            panic!("expected MissingRawInput, got {err:?}");
        };
        assert!(
            !tool_call_id.contains('\n'),
            "escaped tool_call_id must not contain a raw newline: {tool_call_id:?}"
        );
        assert!(
            tool_call_id.len() <= PEER_STR_MAX_LEN,
            "escaped tool_call_id must be capped, got {} bytes",
            tool_call_id.len()
        );

        let unidentifiable = ToolCallUpdate::new(
            hostile_id,
            ToolCallUpdateFields::new().raw_input(serde_json::json!({})),
        );
        let err =
            normalize_tool_call_for_policy(&unidentifiable).expect_err("kind was never supplied");
        let PermissionError::UnidentifiableTool { tool_call_id } = err else {
            panic!("expected UnidentifiableTool, got {err:?}");
        };
        assert!(
            !tool_call_id.contains('\n'),
            "escaped tool_call_id must not contain a raw newline: {tool_call_id:?}"
        );
        assert!(
            tool_call_id.len() <= PEER_STR_MAX_LEN,
            "escaped tool_call_id must be capped, got {} bytes",
            tool_call_id.len()
        );
    }

    #[test]
    fn normalize_tool_call_fails_closed_when_raw_input_is_absent() {
        // Absent rawInput must not be silently treated as `{}` — that would
        // be indistinguishable from a real empty-args call.
        let update =
            ToolCallUpdate::new("tc-2", ToolCallUpdateFields::new().kind(ToolKind::Execute));
        let err = normalize_tool_call_for_policy(&update).expect_err("rawInput was never supplied");
        assert_eq!(
            err,
            // FIX round 2 (Item 4): tool_call_id is now escape-and-capped
            // (same discipline as option_id), so the expected value is the
            // escaped form, not the raw id.
            PermissionError::MissingRawInput {
                tool_call_id: format!("{:?}", "tc-2")
            }
        );
    }

    #[test]
    fn normalize_tool_call_distinguishes_absent_raw_input_from_present_but_empty() {
        // A present-but-empty {} object is a legitimate normalization result,
        // not an error — only *absence* is refused.
        let update = ToolCallUpdate::new(
            "tc-3",
            ToolCallUpdateFields::new()
                .kind(ToolKind::Execute)
                .raw_input(serde_json::json!({})),
        );
        let (_, args) =
            normalize_tool_call_for_policy(&update).expect("rawInput was `{}`, not absent");
        assert_eq!(args, serde_json::json!({}));
    }

    #[test]
    fn normalize_tool_call_fails_closed_when_kind_is_absent() {
        let update = ToolCallUpdate::new(
            "tc-4",
            ToolCallUpdateFields::new().raw_input(serde_json::json!({})),
        );
        let err = normalize_tool_call_for_policy(&update).expect_err("kind was never supplied");
        assert_eq!(
            err,
            PermissionError::UnidentifiableTool {
                tool_call_id: format!("{:?}", "tc-4")
            }
        );
    }

    #[test]
    fn normalize_tool_call_fails_closed_when_kind_is_other() {
        // ToolKind::Other is both the default and the deserialization
        // fallback for any unrecognized kind — it must not be trusted to
        // identify a specific tool, even though a title might be present.
        let update = ToolCallUpdate::new(
            "tc-5",
            ToolCallUpdateFields::new()
                .kind(ToolKind::Other)
                .title("Doing something".to_string())
                .raw_input(serde_json::json!({})),
        );
        let err = normalize_tool_call_for_policy(&update)
            .expect_err("kind was Other, and title is never used as a fallback identifier");
        assert_eq!(
            err,
            PermissionError::UnidentifiableTool {
                tool_call_id: format!("{:?}", "tc-5")
            }
        );
    }
}
