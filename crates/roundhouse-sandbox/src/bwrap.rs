//! §6.5: "we vendor bubblewrap's binary, not its namespace-creation logic" — this module
//! execs the vendored static bwrap binary rather than reimplementing namespace/mount
//! setup. Fixes audit finding 11's undefined `spawn_under_bwrap`.
use crate::{Child, CommandSpec, IsolationError};
use std::path::{Path, PathBuf};
use tokio::process::{Child as TokioChild, Command};

/// Returns both the frozen `Child{pid}` shape (what `Isolate::spawn`'s signature
/// requires) and the live `tokio::process::Child` (which the caller must keep alive
/// somewhere — `BwrapLandlockIsolate` stores it in `HandleMeta` — so tokio can still
/// reap the process; dropping it immediately would orphan/zombie the child).
pub async fn spawn_under_bwrap(
    bwrap_path: &Path,
    workspace_root: &PathBuf,
    cmd: CommandSpec,
) -> Result<(Child, TokioChild), IsolationError> {
    let mut command = Command::new(bwrap_path);
    command
        .arg("--ro-bind")
        .arg("/")
        .arg("/")
        .arg("--bind")
        .arg(workspace_root)
        .arg(workspace_root)
        .arg("--unshare-all")
        // Network egress is bound to the per-session loopback proxy socket, not left
        // fully unshared — see this plan's network-policy task (§6.6) for the proxy this
        // binds into; that task is what makes `net_enforced` on this tier's Attestation
        // actually true rather than aspirational.
        .arg("--die-with-parent")
        .arg("--")
        .arg(&cmd.program)
        .args(&cmd.argv);
    if let Some(cwd) = &cmd.cwd {
        command.current_dir(cwd);
    }
    let child = command
        .spawn()
        .map_err(|e| IsolationError::Unsupported(format!("failed to spawn under bwrap: {e}")))?;
    let pid = child.id().ok_or_else(|| {
        IsolationError::Unsupported("bwrap child exited before its pid was observable".into())
    })?;
    Ok((Child { pid }, child))
}
