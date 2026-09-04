//! §6.4's run-level approval ceiling: *"**Unattended runs** get
//! `ApprovalPolicy::{Interactive | DenyAll | Preapproved{bundle} |
//! Notify{sink,timeout,on_timeout}}`. Scheduled sessions default to
//! `DenyAll` — but the task **blocks rather than failing**, so a human can
//! attach later and unblock it. There is no "unattended = auto-approve";
//! you write a `Preapproved` bundle and it is a reviewable artifact."*
//!
//! # The coarse knob and the fine knob
//!
//! [`ApprovalPolicy`] governs whether a decision needing a human can be
//! taken *at all* in a run with nobody attached. `crate::hitl`'s `Escalate`
//! (§8.5 point 2) governs what happens to one *rule*'s `Ask` once inside
//! such a decision. The run-level ceiling is consulted first, at run
//! admission, and the per-rule knob operates underneath whatever it lets
//! through — the two compose, and neither replaces the other.
//!
//! **Nothing in this module is built out of `Escalate`, and this module
//! imports nothing from `crate::hitl`,** so the ceiling can never be
//! derived from the knob it sits above. That is a module-dependency
//! convention, not a type-level fact, so it is checked the only way a
//! convention can be — by a source scan
//! (`the_run_level_policy_module_never_imports_the_per_rule_escalate_it_composes_with`
//! in `tests/approval_policy.rs`, the mechanism
//! `xtask/tests/no_raw_event_mutation.rs` already uses for the
//! event-mutation ban, scoped to this one file). The plan this module came
//! from tried to assert the same property with a test whose body was one
//! `let` binding plus a comment reading *"the absence of any such import is
//! the assertion"*: a test cannot observe another file's imports, so that
//! test passed unconditionally and was replaced.
//!
//! # What this module deliberately does *not* do
//!
//! - **No run-admission wiring.** Deciding *which* [`ApprovalPolicy`] a run
//!   gets, and acting on the [`ApprovalOutcome`], belongs to the
//!   run-admission path in `roundhouse-daemon`, alongside the rest of this
//!   subsystem's daemon-owned wiring. This module is pure evaluation.
//! - **No notification delivery.** [`ApprovalPolicy::Notify`]'s `sink` is a
//!   string identifier ("desktop", "slack:#ops"), never a live connection:
//!   sending is I/O and this crate does none.
//! - **No clock — and, in consequence, no serde on [`ApprovalPolicy`]
//!   itself.** [`ApprovalPolicy::Notify`]'s `timeout` is a *relative*
//!   [`Duration`], for the reason `crate::hitl`'s module doc gives for
//!   `AwaitingHuman::timeout_after` (ruling P65 #4): reading a clock is the
//!   ambient I/O this crate's position in the graph exists to avoid.
//!
//!   That choice carries a known trap, decided here rather than inherited
//!   silently. `AwaitingHuman`'s doc records it: a relative window that is
//!   persisted and re-derived on every resume hands a re-driven wait a
//!   fresh full window each time, so `deny`/`fail` never fire and the 7-day
//!   reaper becomes the only bound. An `ApprovalPolicy` persisted per run
//!   and re-read to reconstruct a pending `Notify` would have exactly that
//!   bug. **So this type derives neither `Serialize` nor `Deserialize`**,
//!   and there is nothing here to persist or read back: the policy is
//!   constructed in-process at run admission, and the wait a
//!   [`ApprovalOutcome::PendingNotify`] represents must be recorded the way
//!   every other human wait is — through [`crate::parking`], which converts
//!   a relative window into the absolute `workflow_run.awaiting_until` at
//!   the one point where "now" is genuinely known. A derive would also be
//!   useless for authoring: `Duration`'s serde form is
//!   `{"secs": N, "nanos": N}`, not anything a human writes, which is the
//!   same argument `Escalate`'s doc makes for not deriving `Deserialize`
//!   there.
//!
//!   [`PreapprovedBundle`] is the deliberate exception and *does*
//!   deserialize — it is the one part of this policy §6.4 says a human
//!   writes and a reviewer reads, and it carries no duration. See its doc
//!   comment.

use serde::Deserialize;
use std::time::Duration;

/// §6.4: *"you write a `Preapproved` bundle and it is a reviewable
/// artifact"* — a named, versioned, explicit allowlist of rule identifiers,
/// never an implicit "everything unattended is fine".
///
/// # It loads from a document, because that is what "reviewable artifact" means
///
/// Written by a human, read by a reviewer, so something must load it —
/// hence `Deserialize`, via a `#[serde(deny_unknown_fields)]` wire struct
/// and a validating `TryFrom`, which is how this crate already loads the
/// security-relevant parts of a workflow document (`PermissionRuleDef` in
/// [`crate::parse::types`]). A misspelled key is a load error rather than a
/// silently emptied allowlist.
///
/// **Deliberately not `Serialize`**, and the reason matters more than the
/// derive: the reviewable artifact is *the file the human wrote and the
/// reviewer read*. Re-emitting a parsed bundle would produce a second text
/// for the same grant — one nobody reviewed, and one that could drift from
/// the first (Task 10's fix round 2 hit exactly that class of trap in the
/// other direction, where a type's own `Serialize` output was rejected by
/// its own parser). Nothing in this crate needs to write a bundle, so the
/// second spelling simply does not exist.
///
/// # Validation is on the load path, with one exception at match time
///
/// The fields are `pub`, so a hand-built bundle can carry values the
/// document path rejects — the same caveat `Escalate::Park`'s doc records
/// for `Duration::ZERO`. That is the crate's existing stance and not an
/// oversight: the artifact §6.4 describes arrives as a document, and that
/// path is checked.
///
/// The exception is a **blank** `approved_rule_ids` entry, which
/// [`evaluate_unattended_approval`] refuses at match time as well. It is the
/// only value in this type that a hand-built bundle can carry and have fail
/// *open*: a caller that passes no rule id at all would be approved by it.
/// An untrimmed entry needs no second check — it simply never matches, which
/// is already the fail-closed direction, so the load path stays its only
/// gate.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "PreapprovedBundleWire")]
pub struct PreapprovedBundle {
    /// Identifies the bundle in a run record and in review. Rejected on the
    /// document path when blank, on the same ground as
    /// `HitlError::EmptyGateTitle`: it is the only text saying *which*
    /// reviewed grant a run is executing under.
    pub name: String,
    /// **For human review and audit, not for dispatch.** Nothing in this
    /// module branches on it and nothing should: it exists so a run record
    /// can cite "bundle `nightly-lint` v3" and a reviewer can diff v2
    /// against v3, which is the reviewability §6.4 asks for. It is
    /// deliberately *not* a schema/compatibility version — this crate has
    /// exactly one bundle shape — and it mirrors how the crate already
    /// versions an authored document (`WorkflowDef { name, version }`).
    pub version: u32,
    /// The rule identifiers this bundle approves, matched exactly — see
    /// [`evaluate_unattended_approval`] for why no normalisation happens at
    /// match time and what the load path does instead.
    pub approved_rule_ids: Vec<String>,
}

/// The as-written-in-YAML shape of a [`PreapprovedBundle`], deserialized
/// into a validated one via `#[serde(try_from = ...)]`. Never constructed or
/// read directly otherwise; see [`PreapprovedBundle`]'s doc comment.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreapprovedBundleWire {
    name: String,
    version: u32,
    approved_rule_ids: Vec<String>,
}

impl TryFrom<PreapprovedBundleWire> for PreapprovedBundle {
    /// `String` rather than a typed error, matching `PermissionRuleDef`'s
    /// `TryFrom` in [`crate::parse::types`]: `#[serde(try_from)]` renders
    /// whatever this returns into the serde error's message, so a public
    /// error enum here would be an API no caller could ever match on.
    type Error = String;

    fn try_from(wire: PreapprovedBundleWire) -> Result<Self, Self::Error> {
        if wire.name.trim().is_empty() {
            return Err(format!(
                "a preapproved bundle's `name` must not be empty — it is the only text naming which reviewed grant a run is executing under, got {:?}",
                wire.name
            ));
        }
        for id in &wire.approved_rule_ids {
            if id.trim().is_empty() {
                return Err(format!(
                    "preapproved bundle {:?} lists an empty `approved_rule_ids` entry ({id:?}); an empty rule id approves a caller that passes no rule id at all, which is a broken caller rather than an authored grant",
                    wire.name
                ));
            }
            // Rule ids are matched exactly (see `evaluate_unattended_approval`),
            // so an id written with surrounding whitespace silently never
            // matches: an approval the author believes they granted and the
            // reviewer believes they read, which grants nothing. Rejected here
            // rather than trimmed at match time — trimming would widen what the
            // reviewed strings mean, and this crate has already recorded (in
            // `HitlError::ZeroDeadline`) that it stopped silently normalising
            // validly parsed author statements.
            if id.trim() != id {
                return Err(format!(
                    "preapproved bundle {:?} lists the rule id {id:?} with surrounding whitespace; rule ids are matched exactly, so this entry would never match — write it as {:?}",
                    wire.name,
                    id.trim()
                ));
            }
        }
        // An empty `approved_rule_ids` is allowed on purpose: it approves
        // nothing, which is the fail-closed direction, and a reviewer who
        // strikes every entry out of a bundle should get a bundle that
        // approves nothing rather than a document that no longer loads.
        Ok(PreapprovedBundle {
            name: wire.name,
            version: wire.version,
            approved_rule_ids: wire.approved_rule_ids,
        })
    }
}

/// What an [`ApprovalPolicy::Notify`] resolves to when its window elapses
/// with no human response.
///
/// # Deliberately narrower than [`crate::parse::types::OnTimeout`], not a duplicate of it
///
/// [`OnTimeout`](crate::parse::types::OnTimeout) already exists in this
/// crate with `Deny`, `Fail`, `Approve` and `Default(String)`, and it is the
/// right type for the document-level grammar it parses — a `gate:` step's
/// `on_timeout` and `permissions.unattended.on_timeout`. This enum is a strict
/// subset of it, and that is the point rather than an oversight: at the
/// **run** level the other two variants have no meaning §6.4 permits.
///
/// - `Approve` at run level *is* "unattended = auto-approve", which §6.4
///   says does not exist — the sanctioned way to get unattended approval is
///   a [`PreapprovedBundle`] somebody reviewed, not a window expiring.
/// - `Default(expr)` supplies a value a human would have entered into a
///   gate's form. A run-level approval has no form and no value to
///   substitute; the question is only whether the run may proceed.
///
/// Omitting them makes the answer §6.4 forbids **unrepresentable**, which is
/// this codebase's house pattern for exactly this (`BindConfig`,
/// `StepOutput`, `UncheckedOnTimeout`).
///
/// # Obligation, if anyone ever adds `Approve` here
///
/// `hitl.rs` did not merely write "don't honour `Approve`" in a comment: it
/// wrapped the field in an `UncheckedOnTimeout` newtype whose `resolve()`
/// takes, as an argument, the run-time fact that the run's policy is
/// narrower than the job default — so the obvious
/// `match on_timeout { Approve => grant(), .. }` does not compile. **A
/// parallel enum that merely omits `Approve` inherits none of that
/// protection.** Adding the variant here without equivalent gating would
/// reintroduce, at the coarser level and with no guard at all, precisely
/// the escalation that machinery exists to prevent. The exhaustive `match`
/// in `notify_applies_on_timeout_when_no_response_arrives`
/// (`tests/approval_policy.rs`) makes adding a variant a build break, so
/// this paragraph is reached rather than skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnApprovalTimeout {
    /// The decision is denied. The run continues; the denied action does
    /// not happen.
    Deny,
    /// The run fails outright.
    Fail,
}

/// §6.4's run-level unattended default — the coarser knob. Distinct from
/// (never replacing) the per-rule `Escalate::{Park|DenyAndContinue|Fail}`
/// (§8.5 point 2, `crate::hitl`), which operates *underneath* whatever this
/// policy allows through. See this module's doc comment for why it derives
/// no serde impls.
///
/// # How a run record says what it was admitted under: cite, do not re-emit
///
/// Everything in this system is event-sourced, so a run admitted under a
/// policy should be able to say which one — and the obvious way to get that
/// is `Serialize` on this enum. **Do not add it** (ruling P89 §A). The
/// module doc gives one reason (a persisted-and-re-read `Notify` window
/// hands every resume a fresh full timeout); [`PreapprovedBundle`]'s doc
/// gives the stronger one, and `Serialize` here would drag the bundle along
/// with it: a re-emitted grant is a second text for something a human wrote
/// and a reviewer read, unreviewed and free to drift from the first.
///
/// The record therefore **cites** the grant instead of copying it: the
/// variant name, plus — for `Preapproved` — the pair
/// (`bundle.name`, `bundle.version`), which reads as
/// `preapproved(nightly-lint-bundle, v3)`. That pair is precisely what
/// [`PreapprovedBundle`]'s `version` field exists for; a reviewer given it
/// can diff v2 against v3 in the repository that holds the authored
/// document, which a serialized copy would not let them do any better and
/// might let them do worse.
///
/// This is a note for the run-admission author in `roundhouse-daemon`, since
/// this crate does no I/O and holds no run records: write the citation at
/// the point of admission. There is nothing to hand-roll a record type
/// against here, and nothing here to reach for `Serialize` on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalPolicy {
    /// Ask the human. Correct — and the only correct value — for an
    /// *attended* session, which is why the variant exists at all: this
    /// enum is the run's declared approval mode, and an attended run
    /// declares this one.
    ///
    /// Reaching [`evaluate_unattended_approval`] with it is therefore a
    /// caller-side misconfiguration: an unattended run has no human to
    /// interact with. It **degrades to [`ApprovalOutcome::Blocked`]**
    /// rather than being rejected as an error, for two reasons. Blocking is
    /// fail-closed and is exactly the `DenyAll` behaviour §6.4 already
    /// specifies for this situation — the task blocks, a human attaches
    /// later and unblocks it — so the misconfiguration costs a stalled task
    /// rather than a failed run. And the alternative the plan shipped,
    /// [`ApprovalOutcome::PendingNotify`], is unrecoverable: there is no
    /// sink to answer it and no `on_timeout` to fire, so the run waits
    /// forever.
    Interactive,
    /// §6.4's default for scheduled sessions: no approval is possible, so
    /// the task blocks (**not** fails) until a human attaches and unblocks
    /// it.
    DenyAll,
    /// A reviewable, versioned bundle of pre-approved rule ids — the *only*
    /// sanctioned way to get auto-approve behaviour unattended.
    Preapproved { bundle: PreapprovedBundle },
    /// Sends to a notification sink and awaits a response within `timeout`;
    /// `on_timeout` resolves the decision if none arrives.
    ///
    /// `sink` is an identifier, and `timeout` is a *relative* window — see
    /// this module's doc comment for both.
    Notify {
        sink: String,
        timeout: Duration,
        on_timeout: OnApprovalTimeout,
    },
}

/// What a run's [`ApprovalPolicy`] says about one decision needing a human.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalOutcome {
    /// `DenyAll` (or a `Preapproved` bundle that doesn't cover this rule, or
    /// an unattended `Interactive`): the task blocks, and is **not** marked
    /// failed — §6.4's explicit distinction, and what lets a human attach
    /// later and unblock it.
    Blocked,
    /// The rule was named by a reviewed [`PreapprovedBundle`].
    Approved,
    /// A `Notify` has been sent and is awaiting a response within its
    /// timeout. Resolvable two ways: a human responds (the caller's own
    /// response handling), or the window elapses and
    /// [`resolve_notify_timeout`] applies the policy's `on_timeout`. Only
    /// [`ApprovalPolicy::Notify`] ever produces this, because it is the only
    /// variant carrying both.
    PendingNotify,
    /// A `Notify` window elapsed with `on_timeout: deny`.
    Denied,
    /// A `Notify` window elapsed with `on_timeout: fail`.
    Failed,
}

/// §6.4: *"Scheduled sessions default to `DenyAll`."*
///
/// A named function rather than a `Default` impl, following
/// `parse::types::default_permission_effect`: nothing should be able to
/// reach an approval policy through a generic `T::default()` call, where the
/// permissive answer would be as easy to write as the safe one.
pub fn default_for_unattended() -> ApprovalPolicy {
    ApprovalPolicy::DenyAll
}

/// Evaluates a run's [`ApprovalPolicy`] against one rule needing approval.
///
/// This is the run-level ceiling, consulted *before* any individual rule's
/// per-rule escalate configuration is (see this module's doc comment).
///
/// `rule_id` is matched against a [`PreapprovedBundle`] by **exact string
/// equality, with no normalisation** — no case folding, no prefix matching,
/// no globbing. That is a stated choice: every one of those widens what a
/// bundle approves beyond the literal strings its reviewer read, and a glob
/// in a preapproval list is precisely the "unattended = auto-approve" §6.4
/// rules out. The matching cost is a linear scan, which is right for a
/// human-written list; a set is a drop-in replacement with identical
/// semantics if one ever gets long. Exact matching is safe to rely on
/// because the load path rejects ids that are empty or carry surrounding
/// whitespace (see [`PreapprovedBundle`]).
///
/// A **blank `rule_id` is refused outright**, before the scan runs, and is
/// the one thing here not left to the load path. The fields of a
/// [`PreapprovedBundle`] are `pub`, so a hand-built one can carry a blank
/// entry, and that is the single combination in this module that fails
/// *open*: a broken caller passing `""` — no rule id at all — would meet it
/// and be approved. Closing it costs one condition, so it is closed here
/// rather than left as a documented caveat. The guard applies to the
/// caller's argument only; it does not normalise the comparison, which
/// remains exact equality, so nothing above about "no normalisation" is
/// weakened by it. An untrimmed `rule_id` gets no such guard and needs none:
/// it fails to match, which is already fail-closed.
///
/// The only [`ApprovalOutcome::PendingNotify`] this returns is for
/// [`ApprovalPolicy::Notify`]; resolving that pending state is
/// [`resolve_notify_timeout`] plus the caller's own response handling, which
/// is out of this pure module's scope for the same reason `Notify`'s `sink`
/// is a string here rather than a live connection.
pub fn evaluate_unattended_approval(policy: &ApprovalPolicy, rule_id: &str) -> ApprovalOutcome {
    match policy {
        // Fail closed rather than hang — see `ApprovalPolicy::Interactive`.
        ApprovalPolicy::Interactive => ApprovalOutcome::Blocked,
        ApprovalPolicy::DenyAll => ApprovalOutcome::Blocked,
        ApprovalPolicy::Preapproved { bundle } => {
            // A blank `rule_id` is refused before the scan rather than
            // compared against it — see this function's doc comment. This
            // guards the *caller's argument*; it does not normalise the
            // comparison, which remains exact equality between two non-blank
            // strings.
            if !rule_id.trim().is_empty() && bundle.approved_rule_ids.iter().any(|r| r == rule_id) {
                ApprovalOutcome::Approved
            } else {
                ApprovalOutcome::Blocked
            }
        }
        ApprovalPolicy::Notify { .. } => ApprovalOutcome::PendingNotify,
    }
}

/// Resolves an [`ApprovalPolicy::Notify`]'s pending state once its `timeout`
/// elapses with no response.
///
/// Total over [`OnApprovalTimeout`], and neither answer is
/// [`ApprovalOutcome::Approved`] — see that enum's doc comment for why no
/// run-level timeout disposition may approve.
pub fn resolve_notify_timeout(on_timeout: &OnApprovalTimeout) -> ApprovalOutcome {
    match on_timeout {
        OnApprovalTimeout::Deny => ApprovalOutcome::Denied,
        OnApprovalTimeout::Fail => ApprovalOutcome::Failed,
    }
}
