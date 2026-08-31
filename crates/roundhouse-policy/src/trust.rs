//! `Project` scope may narrow, never widen — the `(repo_root, blake3(policy_file))` trust
//! record (audit finding 4).
//!
//! `.roundhouse/policy.toml` is repo-committed, so an agent working in that repo could
//! itself have written it: nothing stops an agent from adding `Allow git push --force` to
//! the project's own policy file and having it take effect on the very next task, unless
//! something outside the repo — something the agent cannot write — gates it. This module
//! is that gate.
//!
//! The precedence rule this implements is stated verbatim in
//! `docs/architecture/03-security-and-sandboxing.md:65-78`: *"Project scope may narrow,
//! never widen, unless the user has recorded a trust decision keyed on
//! `(repo_root, blake3(policy_file))`. `Workspace` scope carries no such restriction — it
//! is never agent-writable in the first place."* The `TrustStore`'s on-disk layout below
//! (`<state_dir>/workspaces/<blake3(repo_root)>/policy_trust.toml`, mode 0600) is this
//! task's own design choice, not a doc-mandated path — chosen to be consistent in spirit
//! with the real `Workspace`-scope config storage convention documented at the same
//! location (`.../workspaces/<blake3(repo_root)>/config.toml`).

use crate::engine::{CompiledRule, Outcome, Scope};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrustRecord {
    pub trusted_policy_hash: String,
    pub trusted_allow_signatures: Vec<String>,
}

/// Storage for per-repo trust records, rooted at a per-machine state directory the agent
/// cannot write (e.g. `~/.local/state/roundhouse`) — never inside the repo itself, which
/// is exactly the property this mechanism depends on: a `Project`-scope file the agent
/// CAN write must be checked against something the agent CANNOT write.
pub struct TrustStore {
    state_dir: PathBuf,
}

impl TrustStore {
    pub fn new(state_dir: PathBuf) -> Self {
        assert!(
            state_dir.is_absolute(),
            "TrustStore::new: state_dir must be a non-empty, absolute path (got {state_dir:?}) \
             — an empty/relative path would silently defeat the never-agent-writable property \
             this store depends on"
        );
        Self { state_dir }
    }

    fn path_for(&self, repo_root: &Path) -> PathBuf {
        let repo_hash = blake3::hash(repo_root.to_string_lossy().as_bytes())
            .to_hex()
            .to_string();
        self.state_dir
            .join("workspaces")
            .join(repo_hash)
            .join("policy_trust.toml")
    }

    pub fn load(&self, repo_root: &Path) -> Option<TrustRecord> {
        let contents = std::fs::read_to_string(self.path_for(repo_root)).ok()?;
        toml::from_str(&contents).ok()
    }

    pub fn save(&self, repo_root: &Path, record: &TrustRecord) -> std::io::Result<()> {
        let path = self.path_for(repo_root);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let contents = toml::to_string(record).expect("TrustRecord always serializes");
        std::fs::write(&path, contents)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}

/// A signature stable enough to detect a genuinely new/changed Allow rule — scope,
/// outcome, and a Debug rendering of the predicate. Not a general rule-equality algebra;
/// good enough to answer "did this specific Allow rule exist in the last-trusted file."
fn allow_signature(rule: &CompiledRule) -> Option<String> {
    if rule.outcome != Outcome::Allow || rule.scope != Scope::Project {
        return None;
    }
    Some(format!("{:?}", rule.predicate))
}

/// The precedence rule, made real: `Project` scope may narrow, never widen, unless a
/// human has recorded a trust decision at this exact `(repo_root, blake3(policy_file))`
/// pair. Returns the rule set that is actually safe to compile into the `PolicyEngine` —
/// which may be strictly narrower than what the (agent-writable) file itself authors.
pub fn apply_project_scope_trust(
    repo_root: &Path,
    policy_file_contents: &str,
    parsed_project_rules: Vec<CompiledRule>,
    trust_store: &TrustStore,
) -> Vec<CompiledRule> {
    let current_hash = blake3::hash(policy_file_contents.as_bytes())
        .to_hex()
        .to_string();
    let current_allow_sigs: HashSet<String> = parsed_project_rules
        .iter()
        .filter_map(allow_signature)
        .collect();

    match trust_store.load(repo_root) {
        None => {
            // First use: narrow default (S-PERM-1's "no matching rule -> Deny" spirit,
            // applied to the whole file). Auto-record trust at THIS hash with an EMPTY
            // trusted-Allow-set, so a later addition of any Allow rule is detected as
            // new and stays refused too, until a human explicitly trusts it.
            let _ = trust_store.save(
                repo_root,
                &TrustRecord {
                    trusted_policy_hash: current_hash,
                    trusted_allow_signatures: vec![],
                },
            );
            parsed_project_rules
                .into_iter()
                .filter(|r| !(r.scope == Scope::Project && r.outcome == Outcome::Allow))
                .collect()
        }
        Some(record) if record.trusted_policy_hash == current_hash => {
            parsed_project_rules // unchanged since last trust — apply exactly as authored
        }
        Some(record) => {
            let trusted: HashSet<&str> = record
                .trusted_allow_signatures
                .iter()
                .map(|s| s.as_str())
                .collect();
            let widened = current_allow_sigs
                .iter()
                .any(|s| !trusted.contains(s.as_str()));
            if widened {
                // Refuse the widened rules: keep only previously-trusted Allow rules,
                // plus every Deny/Ask rule — narrowing is always accepted immediately.
                parsed_project_rules
                    .into_iter()
                    .filter(|r| {
                        if r.scope == Scope::Project && r.outcome == Outcome::Allow {
                            allow_signature(r)
                                .map(|s| trusted.contains(s.as_str()))
                                .unwrap_or(false)
                        } else {
                            true
                        }
                    })
                    .collect()
            } else {
                // Pure narrowing (or an unchanged Allow set with unrelated Deny/Ask
                // edits) — auto-advance the trusted hash, no human action required.
                let _ = trust_store.save(
                    repo_root,
                    &TrustRecord {
                        trusted_policy_hash: current_hash,
                        trusted_allow_signatures: current_allow_sigs.into_iter().collect(),
                    },
                );
                parsed_project_rules
            }
        }
    }
}

/// The human-facing escape hatch (`round policy trust`, or equivalent) — explicitly
/// trusts the CURRENT file's exact content and Allow-rule set, unlocking whatever it
/// widened. Never called automatically except by `apply_project_scope_trust`'s own
/// narrowing-auto-advance path above.
pub fn record_explicit_trust(
    repo_root: &Path,
    policy_file_contents: &str,
    parsed_project_rules: &[CompiledRule],
    trust_store: &TrustStore,
) -> std::io::Result<()> {
    let hash = blake3::hash(policy_file_contents.as_bytes())
        .to_hex()
        .to_string();
    let sigs = parsed_project_rules
        .iter()
        .filter_map(allow_signature)
        .collect();
    trust_store.save(
        repo_root,
        &TrustRecord {
            trusted_policy_hash: hash,
            trusted_allow_signatures: sigs,
        },
    )
}
