//! Domain types shared by every other crate: `Event`/`EventPayload`/`Delta`,
//! `Task`/`TaskState`, `Session`, id newtypes, `Address`, and the core error
//! type. **No I/O, no async, zero dependencies on other workspace crates** —
//! every other crate in the workspace depends on this one transitively, so
//! it must stay the zero-cost, always-compiles-fast root.
//!
//! Phase 0 gives this crate its real, final shape (not a stub): the
//! `TaskRunner` private-constructor pattern that structurally enforces
//! S-LOG-1 (one `Task` record per action, no bypass — see `task_runner`'s
//! module docs), and content-addressed blob types (`Blake3Hash`, `BlobRef`)
//! for §4.5's retention contract. `TaskRunner` is also the sole minter of
//! session-lifecycle and `Note` events, not just task-lifecycle ones — see
//! `task_runner`'s module docs. See `docs/architecture/01-data-model.md`
//! and `02-system-architecture.md` §5.2.
#![forbid(unsafe_code)]

mod address;
mod blob;
mod delta;
mod error;
mod event;
mod ids;
mod seal;
mod session;
mod task;
mod task_kind;
mod task_meta;
mod task_runner;
mod tier;
mod timestamp;

pub use address::Address;
pub use blob::{Blake3Hash, BlobRef, BLOB_INLINE_THRESHOLD};
pub use delta::Delta;
pub use error::CoreError;
pub use event::{Event, EventFields, EventPayload};
pub use ids::{SessionId, TaskId, TeamId, WorkspaceId};
pub use session::{OnDegrade, SessionOutcome, SessionPatch, SessionSpec, SessionState};
pub use task::{fold_task_state, RedactedSpan, Task, TaskState};
pub use task_kind::TaskKind;
pub use task_meta::{
    CancelReason, Envelope, Handle, IsolationAttestation, NoteLevel, Origin, PolicyDecision,
    Progress, RuleId, SuspendReason, TaskError, TaskInput, TaskOutput, Usage,
};
pub use task_runner::TaskRunner;
pub use tier::Tier;
pub use timestamp::Timestamp;
