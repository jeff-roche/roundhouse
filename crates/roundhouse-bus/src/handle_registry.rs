use crate::types::{Address, BusError};
use dashmap::DashMap;
use roundhouse_core::{SessionId, WorkspaceId};

/// §7.2: "(workspace, name) -> SessionId resolved daemon-side at send time."
pub struct HandleRegistry {
    by_workspace: DashMap<WorkspaceId, DashMap<String, SessionId>>,
}

impl HandleRegistry {
    pub fn new() -> Self {
        Self {
            by_workspace: DashMap::new(),
        }
    }

    /// H2: refuses to overwrite a name a *different* session already holds
    /// (a bare `insert` here would be last-writer-wins with no error and no
    /// log — whichever binding registers second would silently steal the
    /// name and start receiving the first binding's payloads). Registering
    /// the *same* `(workspace, name) -> session` mapping again (e.g. daemon
    /// restart re-deriving a `Message`-trigger registration from its
    /// `Binding`) is a no-op, not a conflict.
    pub fn register(
        &self,
        workspace: WorkspaceId,
        name: String,
        session: SessionId,
    ) -> Result<(), BusError> {
        // LOAD-BEARING: `entry(workspace).or_default()` holds the outer
        // `by_workspace` shard's *write* guard for this entire function —
        // that is what makes the check-then-insert below an atomic
        // compare-and-swap rather than a TOCTOU race. Do NOT rewrite this as
        // `self.by_workspace.get(&workspace)` (what `unregister`/`resolve`
        // below use, since they don't need the same guarantee): that reads
        // under a shared guard, drops it, and would silently reintroduce
        // last-writer-wins between the read and the `insert` a few lines
        // down, with no test able to catch the race deterministically.
        let names = self.by_workspace.entry(workspace).or_default();
        if let Some(existing) = names.get(&name).map(|e| *e.value()) {
            if existing != session {
                tracing::warn!(
                    ?workspace,
                    handle = %name,
                    existing_session = ?existing,
                    attempted_session = ?session,
                    "handle registration refused: name already held by a different session"
                );
                return Err(BusError::HandleAlreadyRegistered { workspace, name });
            }
            return Ok(());
        }
        names.insert(name, session);
        Ok(())
    }

    /// H2: a compare-and-remove against `expected_session`, not a bare
    /// remove-by-name — without this, unbinding your own trigger could
    /// delete a mapping a *different* session owns. Removing a name that
    /// isn't registered at all is a no-op (idempotent unbind), matching the
    /// previous unconditional-remove semantics for that case.
    pub fn unregister(
        &self,
        workspace: WorkspaceId,
        name: &str,
        expected_session: SessionId,
    ) -> Result<(), BusError> {
        let Some(names) = self.by_workspace.get(&workspace) else {
            return Ok(());
        };
        match names.get(name).map(|e| *e.value()) {
            None => Ok(()),
            Some(owner) if owner != expected_session => {
                tracing::warn!(
                    ?workspace,
                    handle = %name,
                    owner = ?owner,
                    attempted_by = ?expected_session,
                    "handle unregistration refused: caller does not own this handle"
                );
                Err(BusError::NotAuthorizedForHandle {
                    workspace,
                    name: name.to_string(),
                })
            }
            Some(_) => {
                names.remove_if(name, |_, v| *v == expected_session);
                Ok(())
            }
        }
    }

    pub fn resolve(&self, workspace: WorkspaceId, name: &str) -> Result<SessionId, BusError> {
        self.by_workspace
            .get(&workspace)
            .and_then(|names| names.get(name).map(|e| *e.value()))
            .ok_or_else(|| BusError::UnknownHandle {
                workspace,
                name: name.to_string(),
            })
    }

    /// Resolves any `Address` variant that names a single session directly.
    /// `Team`/`Role` fan-out has no single resolution and is refused here on purpose —
    /// `LocalBus::resolve_recipients` (Task 12) is the real fan-out expansion against
    /// the team roster (§7.2/§7.5); this registry only knows named handles and raw ids,
    /// and has no access to `TeamRegistry` to expand a roster even if it wanted to.
    ///
    /// H1(b): `Address::Handle`'s own `workspace` field is the *sender's claim* about
    /// which workspace it means, not an instruction this registry should ever act on —
    /// resolution always happens against the ambient `workspace` argument (the caller's
    /// real workspace context), and a mismatch is treated as an unknown handle rather
    /// than as license to reach into a different workspace's registry. Resolving
    /// against the embedded field instead (the previous behavior) let a caller in
    /// workspace A reach a handle registered in workspace B just by naming B in the
    /// address it constructed, breaking the workspace isolation `by_workspace`'s
    /// per-workspace `DashMap`s exist to enforce.
    pub fn resolve_address(
        &self,
        workspace: WorkspaceId,
        addr: &Address,
    ) -> Result<SessionId, BusError> {
        match addr {
            Address::Session { id } => Ok(*id),
            Address::Handle {
                workspace: claimed,
                name,
            } => {
                if *claimed != workspace {
                    return Err(BusError::UnknownHandle {
                        workspace,
                        name: name.clone(),
                    });
                }
                self.resolve(workspace, name)
            }
            Address::Human { session } => Ok(*session),
            Address::Team { .. } | Address::Role { .. } => {
                // Fan-out addresses have no single resolution; `Bus::resolve_recipients`
                // (Task 12) is what callers should use for these two variants instead.
                Err(BusError::UnknownHandle {
                    workspace,
                    name: "<fan-out address>".into(),
                })
            }
        }
    }
}

impl Default for HandleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use roundhouse_core::{SessionId, WorkspaceId};

    #[test]
    fn resolves_handle_to_session_id_within_workspace() {
        let reg = HandleRegistry::new();
        let ws = WorkspaceId::new();
        let sid = SessionId::new();
        reg.register(ws, "reviewer".into(), sid).unwrap();

        assert_eq!(reg.resolve(ws, "reviewer").unwrap(), sid);
    }

    #[test]
    fn unknown_handle_is_a_typed_error_not_a_panic() {
        let reg = HandleRegistry::new();
        let ws = WorkspaceId::new();
        let err = reg.resolve(ws, "nobody").unwrap_err();
        assert!(matches!(err, BusError::UnknownHandle { .. }));
    }

    #[test]
    fn handles_do_not_leak_across_workspaces() {
        let reg = HandleRegistry::new();
        let ws_a = WorkspaceId::new();
        let ws_b = WorkspaceId::new();
        let sid = SessionId::new();
        reg.register(ws_a, "reviewer".into(), sid).unwrap();

        assert!(reg.resolve(ws_b, "reviewer").is_err());
    }

    /// H1(b): the previous behavior resolved `Address::Handle` against its
    /// own embedded `workspace` field, letting a caller whose ambient
    /// workspace is A reach a handle registered in workspace B just by
    /// naming B in the address it constructed. `resolve_address` must
    /// resolve against the ambient argument and refuse a mismatch, not
    /// treat the address's own claim as an instruction.
    #[test]
    fn resolve_address_ignores_the_addresses_own_claimed_workspace_and_uses_the_ambient_one() {
        let reg = HandleRegistry::new();
        let caller_workspace = WorkspaceId::new();
        let victim_workspace = WorkspaceId::new();
        let victim_session = SessionId::new();
        reg.register(victim_workspace, "shared-name".into(), victim_session)
            .unwrap();

        // The address claims `victim_workspace`, but the caller's own
        // (ambient) workspace is different — this must be refused, not
        // silently resolved into `victim_workspace`'s registry.
        let addr = Address::Handle {
            workspace: victim_workspace,
            name: "shared-name".into(),
        };
        let err = reg.resolve_address(caller_workspace, &addr).unwrap_err();
        assert!(matches!(err, BusError::UnknownHandle { .. }));
    }

    #[test]
    fn resolve_address_succeeds_when_the_claimed_workspace_matches_the_ambient_one() {
        let reg = HandleRegistry::new();
        let ws = WorkspaceId::new();
        let sid = SessionId::new();
        reg.register(ws, "reviewer".into(), sid).unwrap();

        let addr = Address::Handle {
            workspace: ws,
            name: "reviewer".into(),
        };
        assert_eq!(reg.resolve_address(ws, &addr).unwrap(), sid);
    }

    /// H2: a bare `insert` used to let whichever binding registers second
    /// silently steal the name, with no error and no log.
    #[test]
    fn register_refuses_to_overwrite_a_name_held_by_a_different_session() {
        let reg = HandleRegistry::new();
        let ws = WorkspaceId::new();
        let first = SessionId::new();
        let second = SessionId::new();
        reg.register(ws, "listener".into(), first).unwrap();

        let err = reg.register(ws, "listener".into(), second).unwrap_err();
        assert!(matches!(err, BusError::HandleAlreadyRegistered { .. }));
        // The original registration must be untouched.
        assert_eq!(reg.resolve(ws, "listener").unwrap(), first);
    }

    #[test]
    fn re_registering_the_same_session_under_the_same_name_is_not_a_conflict() {
        let reg = HandleRegistry::new();
        let ws = WorkspaceId::new();
        let sid = SessionId::new();
        reg.register(ws, "listener".into(), sid).unwrap();

        reg.register(ws, "listener".into(), sid).unwrap();
        assert_eq!(reg.resolve(ws, "listener").unwrap(), sid);
    }

    /// H2: `unregister` used to be a bare remove-by-name with no ownership
    /// check — unbinding your own trigger could delete a mapping a
    /// different session owns.
    #[test]
    fn unregister_refuses_to_remove_a_mapping_owned_by_a_different_session() {
        let reg = HandleRegistry::new();
        let ws = WorkspaceId::new();
        let owner = SessionId::new();
        let impostor = SessionId::new();
        reg.register(ws, "listener".into(), owner).unwrap();

        let err = reg.unregister(ws, "listener", impostor).unwrap_err();
        assert!(matches!(err, BusError::NotAuthorizedForHandle { .. }));
        assert_eq!(reg.resolve(ws, "listener").unwrap(), owner);
    }

    #[test]
    fn unregister_removes_a_mapping_the_caller_actually_owns() {
        let reg = HandleRegistry::new();
        let ws = WorkspaceId::new();
        let owner = SessionId::new();
        reg.register(ws, "listener".into(), owner).unwrap();

        reg.unregister(ws, "listener", owner).unwrap();
        assert!(reg.resolve(ws, "listener").is_err());
    }

    #[test]
    fn unregistering_a_name_that_was_never_registered_is_a_no_op() {
        let reg = HandleRegistry::new();
        let ws = WorkspaceId::new();
        reg.unregister(ws, "nobody", SessionId::new()).unwrap();
    }
}
