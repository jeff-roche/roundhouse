//! Core trigger/binding/event types for Subsystem A (Scheduling).
//!
//! `TriggerSpec` describes *what* starts a job (a cron schedule, a webhook,
//! a file-system watch, another session's message, ...); `Binding` pairs a
//! `TriggerSpec` with the `JobId` it starts plus its overlap policy and
//! scheduling cursor; `TriggerEvent` is the durable record of one firing,
//! persisted by Task 4 for dedupe. See
//! `docs/architecture/05-scheduling-and-workflows.md`.
use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use roundhouse_core::{Address, BindingId, JobId, SessionId};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CatchUp {
    Latest,
    All,
    None,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DstGap {
    FireAtGapEnd,
    Skip,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DstAmbiguous {
    First,
    Second,
    Both,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Glob(pub String);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RefPattern(pub String);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FsEventMask {
    pub create: bool,
    pub modify: bool,
    pub remove: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GitEventMask {
    pub push: bool,
    pub tag: bool,
    pub branch_created: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WebhookAuth {
    None,
    SharedSecret { header: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OutcomeFilter {
    Any,
    /// Matches `report.outcome`; kept as a string rather than
    /// `roundhouse-flow`'s outcome enum to stay decoupled — `roundhouse-flow`
    /// depends on `roundhouse-sched`, not the other way around.
    Outcome(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TriggerSpec {
    Manual,
    Cron {
        expr: String,
        tz: Tz,
        catch_up: CatchUp,
        jitter: Duration,
        dst_gap: DstGap,
        dst_ambiguous: DstAmbiguous,
    },
    Interval {
        every: Duration,
        align: bool,
        anchor: Option<DateTime<Utc>>,
    },
    Fs {
        roots: Vec<PathBuf>,
        include: Vec<Glob>,
        exclude: Vec<Glob>,
        events: FsEventMask,
        debounce: Duration,
        coalesce: bool,
    },
    Git {
        repo: PathBuf,
        on: GitEventMask,
        refs: Vec<RefPattern>,
    },
    Webhook {
        path: String,
        auth: WebhookAuth,
        input_schema: Option<serde_json::Value>,
    },
    RunComplete {
        source_binding: BindingId,
        when: OutcomeFilter,
    },
    /// A4 (§7.3 deliberately cut topic pub/sub — "no subject space, no
    /// wildcard subscriptions"): binds on an `Address` (§7.2), never a topic
    /// string. Binding this variant creates a durable
    /// `Address::Handle { workspace, name }` that the scheduler itself owns
    /// (Task 4's `bind_message_trigger`); a `message_send` to that handle,
    /// resolved daemon-side exactly like any other address, is what fires
    /// the trigger. `filter` narrows on the message's typed payload *after*
    /// that resolution — it is never a topic/subject match. Kept as the
    /// expression-language's source text (`Option<String>`, evaluated by
    /// `roundhouse-flow`'s `${{ }}` engine at fire time) rather than a typed
    /// `Expr` AST, because `roundhouse-flow` depends on `roundhouse-sched`
    /// and not the other way around — this crate cannot name
    /// `roundhouse-flow`'s expression type without an illegal upward
    /// dependency.
    Message {
        address: Address,
        filter: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OverlapPolicy {
    Skip,
    Queue { depth: u32 },
    Concurrent { max: u32 },
    CancelPrevious,
}

impl OverlapPolicy {
    pub fn default_for(spec: &TriggerSpec) -> Self {
        match spec {
            TriggerSpec::Cron { .. } | TriggerSpec::Interval { .. } => OverlapPolicy::Skip,
            TriggerSpec::Webhook { .. } | TriggerSpec::Message { .. } => {
                OverlapPolicy::Queue { depth: 8 }
            }
            TriggerSpec::Fs { .. } => OverlapPolicy::CancelPrevious,
            TriggerSpec::Manual | TriggerSpec::Git { .. } | TriggerSpec::RunComplete { .. } => {
                OverlapPolicy::Skip
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Binding {
    pub id: BindingId,
    pub job_id: JobId,
    pub spec: TriggerSpec,
    pub overlap: OverlapPolicy,
    pub last_fired_for: Option<DateTime<Utc>>,
    pub next_fire_at: Option<DateTime<Utc>>,
    pub enabled: bool,
}

impl Binding {
    pub fn new(job_id: JobId, spec: TriggerSpec) -> Self {
        let overlap = OverlapPolicy::default_for(&spec);
        Binding {
            id: BindingId::new(),
            job_id,
            spec,
            overlap,
            last_fired_for: None,
            next_fire_at: None,
            enabled: true,
        }
    }

    pub fn new_cron(job_id: JobId, expr: String, tz: Tz) -> Self {
        Self::new(
            job_id,
            TriggerSpec::Cron {
                expr,
                tz,
                catch_up: CatchUp::Latest,
                jitter: Duration::from_secs(0),
                dst_gap: DstGap::FireAtGapEnd,
                dst_ambiguous: DstAmbiguous::First,
            },
        )
    }

    /// The `SessionId` this binding registers a bus mailbox under when its
    /// spec is `Message` (Task 4). Deliberately a re-typing of the binding's
    /// own `BindingId`, not a second minted identity — a `Message` binding
    /// *is* the addressable recipient (§8.2: "the binding is the addressable
    /// recipient, the same way any other named session/handle is
    /// addressable"), so there is exactly one stable id per binding across
    /// daemon restarts, with no separate id to persist or reconcile.
    pub fn trigger_session_id(&self) -> SessionId {
        SessionId::from_uuid(self.id.as_uuid())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TriggerEvent {
    pub binding_id: BindingId,
    pub idempotency_key: String,
    pub scheduled_for: DateTime<Utc>,
    pub fired_at: DateTime<Utc>,
    pub is_catch_up: bool,
    pub session_id: Option<SessionId>,
}
