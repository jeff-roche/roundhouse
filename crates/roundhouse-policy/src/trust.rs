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
//!
//! The `state_dir` this module is rooted at must not be agent-writable for the mechanism
//! to mean anything — but that property is enforced elsewhere (the sealed floor / sandbox
//! layer, e.g. `sealed.rs`'s `sealed_state_dir_write` rule, and OS-level file permissions
//! for policy-routed writes), not by this module itself. `trust.rs` has no MAC, signing,
//! or ownership check on the record it reads — a same-user process that bypasses the
//! sandbox (or runs outside it entirely) can still forge a trust record on disk. This
//! module's contribution is the narrow-vs-widen decision logic and safe-by-construction
//! storage semantics (fail-closed on corruption, atomic writes); it is not, by itself, a
//! complete trust boundary.

use crate::engine::{CompiledRule, Outcome, Scope};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrustRecord {
    pub trusted_policy_hash: String,
    /// Signatures of every Project-scope rule (Allow *and* Deny/Ask) present in the file
    /// at the time trust was last established or auto-advanced. Tagged so `Allow` and
    /// non-`Allow` signatures can be told apart on load — see `signature_string`.
    pub trusted_rule_signatures: Vec<String>,
}

/// A record exists on disk but could not be read/parsed. Deliberately distinct from
/// "no record exists" (`TrustStore::load` returning `Ok(None)`): a corrupt record must
/// never be treated as first-use, because first-use auto-creates a fresh (permissive by
/// construction, trust-nothing-yet) record — silently doing that over a corrupt file
/// would let a crash-induced torn write, or a hostile same-user actor, reset trust to an
/// attacker-controlled baseline.
#[derive(Debug, thiserror::Error)]
pub enum TrustLoadError {
    #[error("failed to read trust record: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse trust record: {0}")]
    Parse(#[from] toml::de::Error),
}

/// Storage for per-repo trust records, rooted at a per-machine state directory the agent
/// must not be able to write (e.g. `~/.local/state/roundhouse`) — never inside the repo
/// itself, which is exactly the property this mechanism depends on: a `Project`-scope
/// file the agent CAN write must be checked against something the agent CANNOT write.
/// See the module doc comment: enforcing that property is out of scope for this struct.
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

    /// `Ok(None)` means no record exists yet (genuinely first use — safe to auto-create).
    /// `Err(_)` means a record exists but failed to read or parse — callers must treat
    /// this as a hard fail-closed condition, never as first-use.
    pub fn load(&self, repo_root: &Path) -> Result<Option<TrustRecord>, TrustLoadError> {
        let path = self.path_for(repo_root);
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(TrustLoadError::Io(e)),
        };
        let record = toml::from_str(&contents)?;
        Ok(Some(record))
    }

    /// Writes the record atomically: content is written to a fresh, mode-0600,
    /// exclusively-created sibling temp file, `fsync`ed, then renamed into place.
    /// `rename(2)` replaces the destination directory entry without dereferencing a
    /// symlink there, and the destination is never observable in a partially-written or
    /// world-readable state — closing the torn-write and symlink-follow gaps a plain
    /// `write` + `set_permissions` sequence leaves open on a security-boundary file.
    pub fn save(&self, repo_root: &Path, record: &TrustRecord) -> std::io::Result<()> {
        let path = self.path_for(repo_root);
        let dir = path
            .parent()
            .expect("path_for always yields a path with a parent directory");
        std::fs::create_dir_all(dir)?;
        let contents = toml::to_string(record).expect("TrustRecord always serializes");

        let tmp_path = dir.join(format!(
            ".policy_trust.{}.{}.tmp",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));

        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)?;
            f.write_all(contents.as_bytes())?;
            f.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&tmp_path, &contents)?;
        }

        std::fs::rename(&tmp_path, &path)?;
        Ok(())
    }
}

/// A signature stable enough to detect a genuinely new/changed Project-scope rule —
/// tagged with whether it's an `Allow` rule or not, so widening (a new `Allow` appearing,
/// *or* a previously-trusted `Deny`/`Ask` disappearing) can be told apart from narrowing
/// (an `Allow` disappearing, or a new `Deny`/`Ask` appearing) using simple set membership.
/// Not a general rule-equality algebra; good enough to answer "did this specific rule
/// exist in the last-trusted file."
fn signature_string(rule: &CompiledRule) -> Option<String> {
    if rule.scope != Scope::Project {
        return None;
    }
    let tag = if rule.outcome == Outcome::Allow {
        "ALLOW"
    } else {
        "OTHER"
    };
    Some(format!("{tag}:{:?}", rule.predicate))
}

fn is_allow_signature(sig: &str) -> bool {
    sig.starts_with("ALLOW:")
}

/// The precedence rule, made real: `Project` scope may narrow, never widen, unless a
/// human has recorded a trust decision at this exact `(repo_root, blake3(policy_file))`
/// pair. Returns the rule set that is actually safe to compile into the `PolicyEngine` —
/// which may be strictly narrower than what the (agent-writable) file itself authors.
///
/// Widening covers two symmetric cases, both gated identically: a new `Allow` rule
/// appearing that was never previously trusted, or a previously-trusted `Deny`/`Ask` rule
/// disappearing (removing a restriction is exactly as much a widening as adding a new
/// permission). Either one refuses every `Allow` rule that isn't in the last-trusted set
/// and leaves the trusted baseline exactly where it was — repeated calls on the same
/// untrusted-and-widened file keep refusing until a human calls `record_explicit_trust`.
pub fn apply_project_scope_trust(
    repo_root: &Path,
    policy_file_contents: &str,
    parsed_project_rules: Vec<CompiledRule>,
    trust_store: &TrustStore,
) -> Vec<CompiledRule> {
    let current_hash = blake3::hash(policy_file_contents.as_bytes())
        .to_hex()
        .to_string();
    let current_sigs: HashSet<String> = parsed_project_rules
        .iter()
        .filter_map(signature_string)
        .collect();

    match trust_store.load(repo_root) {
        Err(_) => {
            // A trust record exists but failed to read/parse. Fail closed: refuse every
            // Project-scope Allow rule, and — critically — do NOT touch the file. A
            // corrupt record must force a human through `record_explicit_trust`, not
            // silently reset to a fresh, agent-controllable baseline.
            parsed_project_rules
                .into_iter()
                .filter(|r| !(r.scope == Scope::Project && r.outcome == Outcome::Allow))
                .collect()
        }
        Ok(None) => {
            // First use: narrow default (S-PERM-1's "no matching rule -> Deny" spirit,
            // applied to the whole file). Auto-record trust at THIS hash with an EMPTY
            // trusted-signature set, so a later addition of any Allow rule is detected as
            // new and stays refused too, until a human explicitly trusts it. Every later
            // call against this same unchanged hash falls into the `Some(record)` arm
            // below and re-evaluates against that (initially empty) trusted set — it does
            // NOT take a "hash matches, apply verbatim" shortcut, which is what let a
            // first-use Allow rule silently self-grant on the very next call.
            let _ = trust_store.save(
                repo_root,
                &TrustRecord {
                    trusted_policy_hash: current_hash,
                    trusted_rule_signatures: vec![],
                },
            );
            parsed_project_rules
                .into_iter()
                .filter(|r| !(r.scope == Scope::Project && r.outcome == Outcome::Allow))
                .collect()
        }
        Ok(Some(record)) => {
            let trusted: HashSet<&str> = record
                .trusted_rule_signatures
                .iter()
                .map(|s| s.as_str())
                .collect();

            let new_allow_appeared = current_sigs
                .iter()
                .any(|s| is_allow_signature(s) && !trusted.contains(s.as_str()));
            let restriction_disappeared = trusted
                .iter()
                .any(|s| !is_allow_signature(s) && !current_sigs.contains(*s));
            let widened = new_allow_appeared || restriction_disappeared;

            if widened {
                // Refuse anything not already trusted: keep only previously-trusted
                // Allow rules, plus every Deny/Ask rule the current file still has (a
                // *new* Deny/Ask only narrows further and is always safe to keep). Do
                // NOT save — the trusted baseline stays exactly where it was, so this
                // file keeps being flagged as widened on every subsequent call until a
                // human calls `record_explicit_trust`.
                parsed_project_rules
                    .into_iter()
                    .filter(|r| {
                        if r.scope == Scope::Project && r.outcome == Outcome::Allow {
                            signature_string(r)
                                .map(|s| trusted.contains(s.as_str()))
                                .unwrap_or(false)
                        } else {
                            true
                        }
                    })
                    .collect()
            } else {
                // Pure narrowing (or no change at all) — auto-advance the trusted
                // baseline to the current file, no human action required.
                let _ = trust_store.save(
                    repo_root,
                    &TrustRecord {
                        trusted_policy_hash: current_hash,
                        trusted_rule_signatures: current_sigs.into_iter().collect(),
                    },
                );
                parsed_project_rules
            }
        }
    }
}

/// The human-facing escape hatch (`round policy trust`, or equivalent) — explicitly
/// trusts the CURRENT file's exact content and full Project-scope rule set (`Allow` and
/// `Deny`/`Ask` alike), unlocking whatever it widened. Never called automatically except
/// by `apply_project_scope_trust`'s own narrowing-auto-advance path above. Overwrites any
/// existing record unconditionally — including a corrupt one — since this is the human
/// resolving exactly the ambiguity `apply_project_scope_trust` fails closed on.
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
        .filter_map(signature_string)
        .collect();
    trust_store.save(
        repo_root,
        &TrustRecord {
            trusted_policy_hash: hash,
            trusted_rule_signatures: sigs,
        },
    )
}
