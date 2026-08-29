use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// §4.4 — who/what caused a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum Origin {
    User,
    Model,
    System,
    Peer,
    Trigger,
    Client,
}

/// §6.2 — `Policy::decide` returns one of these three, matched on typed,
/// parsed parameters, never raw strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum PolicyDecision {
    Allow,
    Ask,
    Deny,
}

/// Deliberately a bare-`pub` tuple struct, unlike `SessionId`/`TaskId`/
/// `WorkspaceId`/`TeamId` (which hide their inner `Uuid` and require
/// `::new()`/`::from_uuid()`). Those four are *identity* types this system
/// mints itself and must guard against malformed or colliding construction
/// — that's what the privacy buys. `RuleId` is not minted; it names a rule
/// already defined elsewhere (the policy engine's rule table, Phase 2), so
/// it is closer to `ServerId`/`ModelId`/`ProviderId`/`ToolCallId`/
/// `Signature` (below and in Tasks 6/7) than to the four identity ids:
/// plain wrappers around an externally-sourced value, constructed and
/// unwrapped freely at call sites throughout later phases. This is an
/// intentional stylistic split, not an oversight — see the definitions of
/// `ServerId`/`ProviderId` (Task 6) and `ModelId`/`ProviderId`/
/// `ToolCallId`/`Signature` (Task 7) for the same rationale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RuleId(pub u64);

/// §6.5 — the *achieved* isolation, written on every task row.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct IsolationAttestation {
    pub tier: crate::tier::Tier,
    pub digest: String,
    pub net_enforced: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Progress {
    pub message: String,
    pub fraction: Option<f32>,
}

/// §4.3 — "non-terminating tasks are modelled as long-running tasks with a
/// handle: `TaskStarted` carries a `handle` (pty/process id)." Deliberately
/// minimal, matching this file's other small enums: just enough for the
/// engine to later `read_output`/`kill` a still-running `shell` task without
/// blocking. Note this is a distinct type from `roundhouse_sandbox::Handle`
/// (an opaque isolation-environment handle returned by `Isolate::prepare`) —
/// the two share a name because they're both "a handle" in their own
/// domains, but callers needing both should refer to them by qualified path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum Handle {
    Pid(u32),
    Pty(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum SuspendReason {
    /// `rule`/`params_digest` let an approval's grant record which rule was
    /// matched and a digest of the exact params it was granted for (§6.2/
    /// §6.4 grant-scope provenance).
    AwaitingApproval {
        rule: Option<RuleId>,
        params_digest: [u8; 32],
    },
    /// `schema` carries the elicit JSON schema (§8).
    AwaitingElicitation {
        schema: serde_json::Value,
    },
    AwaitingReply,
    AwaitingPeer {
        session: crate::ids::SessionId,
    },
    /// §8.8-8.13 — a workflow step paused at a gate, named by `step_ref`.
    WorkflowGate {
        step_ref: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum TaskInput {
    Json(serde_json::Value),
    Text(String),
    /// §4.5 — payload routed to the blob store instead of inlined.
    Blob(crate::blob::BlobRef),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum TaskOutput {
    Json(serde_json::Value),
    Text(String),
    Blob(crate::blob::BlobRef),
}

/// `category` is a free-string tag rather than a closed enum (unlike
/// `TaskKind`/`PolicyDecision`) because later phases' executors add
/// categories this crate has no visibility into — but it is not
/// unconstrained in practice. Expected values, inferred from how errors are
/// produced elsewhere in this plan and later phases: `"policy_denied"`
/// (Task 6's `Policy::decide` returning `Deny`), `"timeout"` (a task's
/// deadline elapsed), `"provider_error"` (a `ProviderError` surfaced from
/// `roundhouse-provider`, Task 7), `"executor_error"` (the tool/executor
/// itself failed, e.g. a non-zero shell exit or a filesystem error),
/// `"isolation_error"` (an `IsolationError` from `roundhouse-sandbox`, Task
/// 8), and `"cancelled"` (a `TaskCancelled` surfaced as a failure on the
/// waiting side of a `message`/`agent` task). New categories are expected
/// as later phases add executors; this list is the Phase 0 baseline, not a
/// closed set.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TaskError {
    pub message: String,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum CancelReason {
    User,
    Timeout,
    SessionClosed,
    PolicyDeny,
    /// Task was interrupted by crash recovery (daemon restart).
    /// Distinct from `User` — allows callers to distinguish daemon-restart
    /// cancellations from user-requested cancellations. Folds to `TaskState::Interrupted`
    /// rather than `TaskState::Cancelled` for observability (S-SESS-4).
    DaemonRestart,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum NoteLevel {
    Debug,
    Info,
    Warn,
    Error,
    /// §6.5/§6.7 — a startup/runtime isolation degradation (e.g. requested
    /// tier unavailable, fell back to a weaker one). Distinct from an
    /// ordinary `Warn`: this is a UI-surfaced concept the frozen spec calls
    /// out by name, not just a log line.
    Degradation,
}

/// §4.4 names `usage` as carrying "tokens, cost, wall time," but only token
/// counts are stored fields here — deliberately. Per §9.7, "cost is a
/// derived view over `(usage, pricing_snapshot_id)`, never a stored
/// column": storing a computed dollar figure alongside its inputs invites
/// drift the moment a pricing snapshot changes retroactively. Wall time is
/// likewise derivable from the owning task's `TaskStarted`/terminal event
/// timestamps rather than duplicated here. This comment exists so the
/// omission reads as a documented decision, not a gap.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
}

/// §7 — inter-agent message envelope. Self-contained and serializable per
/// §7.8's rule (`RemoteBus` frames this as CBOR unchanged).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Envelope {
    pub from: crate::address::Address,
    pub to: crate::address::Address,
    pub body: TaskInput,
    pub expect_reply: bool,
}

impl Envelope {
    #[doc(hidden)]
    pub fn default_for_test() -> Self {
        Envelope {
            from: crate::address::Address::Human {
                session: crate::ids::SessionId::new(),
            },
            to: crate::address::Address::Human {
                session: crate::ids::SessionId::new(),
            },
            body: TaskInput::Text(String::new()),
            expect_reply: false,
        }
    }
}
