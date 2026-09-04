use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

macro_rules! newtype_id {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
        pub struct $name(Uuid);

        impl $name {
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

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

newtype_id!(TaskId);
newtype_id!(SessionId);
newtype_id!(WorkspaceId);
newtype_id!(TeamId);

// Phase 5 (Subsystem A, Task 1 ruling P6): `Job`/`Binding` are Phase 5
// concepts owned by `roundhouse-sched`/`roundhouse-flow`, but their ids are
// minted here rather than in `roundhouse-sched` — `roundhouse-flow` also
// needs `JobId`, and `roundhouse-flow` does not depend on `roundhouse-sched`
// (nor may it, per the frozen dependency table in
// `docs/architecture/02-system-architecture.md` §5.2), so a `JobId` defined
// in `roundhouse-sched` would be unreachable from `roundhouse-flow` without
// an illegal upward edge. Minting both ids here, alongside the other
// core ids, keeps them reachable from every crate that needs them with no
// new dependency edge at all.
newtype_id!(JobId);
newtype_id!(BindingId);
