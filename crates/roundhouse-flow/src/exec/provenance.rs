//! `RunId`/`Provenance` — a workflow run's own identity and the per-step
//! record that makes a step's tasks findable in the append-only log
//! independent of the workflow interpreter's in-memory state (§8.8).
//!
//! Fix note (audit X5, "Phase 0 assumes a `new_id_type!` macro" — see Task
//! 13's brief): Phase 0's `roundhouse-core` exports no such macro; its own
//! `TaskId`/`SessionId`/`WorkspaceId`/`TeamId`/`JobId`/`BindingId` newtypes
//! are all built from a private, non-exported local macro
//! (`crates/roundhouse-core/src/ids.rs`). `RunId` is this crate's own
//! identity — a workflow run is a Phase 5 concept `roundhouse-core` has no
//! reason to know about — so it is written out by hand here, following the
//! identical private-field-`Uuid` + `::new()`/`::from_uuid()`/`::as_uuid()`
//! pattern `roundhouse-core` uses for its own ids, rather than depending on
//! a macro this crate cannot reach.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// A workflow run's own identity, minted once per `Executor` (one run =
/// one `Executor` instance, per this task's Interfaces).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RunId(Uuid);

impl RunId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for RunId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Every step is a task subtree; `Provenance` is what makes a step's tasks
/// findable in the append-only log independent of the workflow
/// interpreter's in-memory state (§8.8): which run, which step, which
/// attempt (retries — a later task's concern), and which `map.over` item
/// index (also a later task's concern; `None` at top-level scope).
///
/// **Not yet persisted anywhere.** `roundhouse_core::EventPayload::TaskCreated`
/// (Phase 0, frozen) carries only `kind`/`parent`/`origin`/`input` — there is
/// no field on it to carry a `Provenance` value through today. `Executor`
/// (`super::Executor::dispatch_step`) constructs one per step dispatch,
/// matching this task's own Interfaces list, but has nowhere in the frozen
/// event shape to put it; how (or whether) `Provenance` reaches the
/// persisted log for real is Task 8's durability layer's call, not this
/// task's.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Provenance {
    pub run_id: RunId,
    pub step_id: String,
    pub attempt: u32,
    pub item_index: Option<u32>,
}
