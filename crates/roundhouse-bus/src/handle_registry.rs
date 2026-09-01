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

    pub fn register(&self, workspace: WorkspaceId, name: String, session: SessionId) {
        self.by_workspace
            .entry(workspace)
            .or_default()
            .insert(name, session);
    }

    pub fn unregister(&self, workspace: WorkspaceId, name: &str) {
        if let Some(names) = self.by_workspace.get(&workspace) {
            names.remove(name);
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
    pub fn resolve_address(
        &self,
        workspace: WorkspaceId,
        addr: &Address,
    ) -> Result<SessionId, BusError> {
        match addr {
            Address::Session { id } => Ok(*id),
            Address::Handle {
                workspace: ws,
                name,
            } => self.resolve(*ws, name),
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
        reg.register(ws, "reviewer".into(), sid);

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
        reg.register(ws_a, "reviewer".into(), sid);

        assert!(reg.resolve(ws_b, "reviewer").is_err());
    }
}
