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
//!
//! **What "safe narrowing" means here, precisely** (security review round 2 corrected an
//! earlier, too-permissive definition): `PolicyEngine::decide` picks a winning rule by
//! scope, then specificity, then — when those tie — by relative file order (see
//! `engine.rs::decide`'s sort). That means the *set* of rule signatures being unchanged is
//! NOT sufficient evidence of safety: reordering two rules that tie in specificity can
//! flip which one wins with zero signature-level change at all, and a trusted `Deny`/`Ask`
//! rule quietly disappearing (or being rewritten to a less restrictive outcome on the same
//! predicate) removes a constraint on whatever broader `Allow` rule used to be shadowed by
//! it. Rather than special-case each such shape, this module treats anything that isn't
//! *exactly* "the current file's Project-scope rules are the trusted baseline's rules with
//! zero or more `Allow` rules removed and zero or more new non-`Allow` rules added, with
//! every retained rule's relative order preserved" as an undifferentiated widening event,
//! and fails closed on it: every Project-scope `Allow` rule is dropped for that call, the
//! same fail-closed treatment first-use and a corrupt record already get. The only softer
//! case is a brand-new `Allow` rule appearing with nothing else disturbed, where the
//! previously-trusted `Allow` rules can safely keep applying (see `Widening::Additive`
//! below) — everything else nukes every Project-scope `Allow` rule until a human calls
//! `record_explicit_trust` again. There is deliberately no "trusted hash matches current
//! hash, apply verbatim" shortcut anywhere in this module: that exact shortcut was the
//! root cause of a prior Critical finding (a file trusted-at-hash `H` with an empty
//! trusted-signature set self-granted on the very next call, since the shortcut never
//! consulted the signature set at all). `trusted_policy_hash` is retained purely as
//! human-auditable metadata (which exact file content was last trusted) — it plays no
//! role in the authorization decision itself, which is entirely signature-and-order based.
//!
//! "Order," precisely: `PolicyEngine::decide`'s tie-break reads each `CompiledRule`'s
//! `file_order` FIELD, not whatever position a caller's `Vec` happens to iterate rules
//! in — so `signature_sequence` (below) always sorts by `file_order` before building the
//! sequence `classify` compares, regardless of the order `parsed_project_rules` arrives
//! in. Nothing currently in this codebase sets a non-zero `file_order` (the real
//! `.roundhouse/policy.toml` parser/compiler this module isn't wired into yet doesn't
//! exist), so today `Vec` order and `file_order` order coincide by construction; this
//! sort is what keeps that true once a real caller exists that might filter, group, or
//! recollect rules before calling this module.

use crate::engine::{CompiledRule, Outcome, Scope};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrustRecord {
    pub trusted_policy_hash: String,
    /// Every Project-scope rule's signature (`Allow`, `Ask`, *and* `Deny` alike — see
    /// `signature_string`), in the exact order they appeared in the trusted file. Order
    /// is significant and preserved deliberately: see the module doc comment on why a
    /// pure reorder of tied-specificity rules must be detectable from this alone.
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

fn tag_for(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Allow => "ALLOW",
        Outcome::Ask => "ASK",
        Outcome::Deny => "DENY",
    }
}

/// A signature stable enough to detect a genuinely new/changed/reordered Project-scope
/// rule: the real outcome (`Allow`/`Ask`/`Deny`, not collapsed into a generic
/// non-`Allow` bucket — a `Deny` rewritten to an `Ask` on the identical predicate must
/// produce a DIFFERENT signature, not the same one) plus a `Debug` rendering of the
/// predicate. Not a general rule-equality algebra; good enough to answer "did this exact
/// (outcome, predicate) pair exist in the last-trusted file, and where."
fn signature_string(rule: &CompiledRule) -> Option<String> {
    if rule.scope != Scope::Project {
        return None;
    }
    Some(format!("{}:{:?}", tag_for(rule.outcome), rule.predicate))
}

fn is_allow_signature(sig: &str) -> bool {
    sig.starts_with("ALLOW:")
}

/// Builds the ordered Project-scope signature sequence `classify`'s order check relies
/// on — critically, ordered by each rule's `file_order` FIELD, not by the position the
/// caller happened to put it at in the `Vec`. `PolicyEngine::decide` (`engine.rs:520`)
/// breaks specificity ties by `file_order`, never by however a caller iterated/filtered/
/// recollected its rules on the way here — so this function's entire "detect a pure
/// reorder" guarantee is meaningless unless the sequence it builds reflects `file_order`,
/// not incidental `Vec` order. `file_order` is deliberately excluded from the signature
/// *string* itself (only used to sort): baking the numeric value in would treat a
/// legitimate narrowing edit — which renumbers every rule after the deleted one — as a
/// wholesale signature change instead of the safe removal it actually is.
fn signature_sequence(rules: &[CompiledRule]) -> Vec<String> {
    let mut project_rules: Vec<&CompiledRule> =
        rules.iter().filter(|r| r.scope == Scope::Project).collect();
    project_rules.sort_by_key(|r| r.file_order);
    debug_assert!(
        project_rules.windows(2).all(|w| w[0].file_order <= w[1].file_order),
        "trust::signature_sequence: rules must come out sorted by file_order — the exact \
         field PolicyEngine::decide's tie-break reads — after the sort_by_key above; a \
         violation here means the sort was changed or bypassed, silently reintroducing the \
         reorder-widening bug this ordering exists to catch"
    );
    project_rules
        .into_iter()
        .map(|r| signature_string(r).expect("already filtered to Scope::Project above"))
        .collect()
}

/// How the current file's Project-scope rule signatures compare to the trusted baseline.
#[derive(Debug, PartialEq, Eq)]
enum Widening {
    /// Nothing widened: every signature disappearance was an `Allow` (safe to drop), no
    /// trusted `Ask`/`Deny` signature disappeared or got replaced, no new `Allow`
    /// signature appeared, and every retained signature's relative order is unchanged.
    None,
    /// Only new `Allow` signature(s) appeared; nothing else about the trusted baseline
    /// was disturbed. Safe to keep applying every previously-trusted `Allow` rule and
    /// refuse only the new one(s).
    Additive,
    /// Something beyond "a brand-new `Allow` rule appeared" changed: a trusted
    /// `Ask`/`Deny` signature disappeared (whether removed outright or replaced by a
    /// less restrictive outcome on the same predicate), or the relative order of
    /// signatures retained in both the trusted baseline and the current file changed.
    /// Either can flip `PolicyEngine::decide`'s real output for an action nothing here
    /// individually "added" — fails closed exactly like first-use/corrupt-record: every
    /// Project-scope `Allow` *and* `Ask` rule is dropped (only `Deny` survives), not just
    /// the ones that look new. `Ask` has to go too, not just `Allow`: a Deny-to-Ask
    /// rewrite on the same predicate leaves a live, matching `Ask` rule in place, which
    /// would otherwise stop `decide_unattended`'s no-human-to-ask downgrade from ever
    /// reinstating a real `Deny`.
    Structural,
}

fn classify(trusted_seq: &[String], current_seq: &[String]) -> Widening {
    let trusted_set: HashSet<&str> = trusted_seq.iter().map(String::as_str).collect();
    let current_set: HashSet<&str> = current_seq.iter().map(String::as_str).collect();

    // A trusted restriction (Ask/Deny) that is no longer present at all — whether the
    // line was deleted outright, or rewritten to a different (less restrictive)
    // outcome on the same predicate, either way the OLD signature string vanishes from
    // the current set.
    let restriction_disappeared = trusted_seq
        .iter()
        .any(|s| !is_allow_signature(s) && !current_set.contains(s.as_str()));

    // Relative order of every signature retained in BOTH files, compared as a sequence.
    // A pure reorder changes nothing about set membership but changes this.
    let filtered_trusted_order: Vec<&str> = trusted_seq
        .iter()
        .map(String::as_str)
        .filter(|s| current_set.contains(s))
        .collect();
    let filtered_current_order: Vec<&str> = current_seq
        .iter()
        .map(String::as_str)
        .filter(|s| trusted_set.contains(s))
        .collect();
    let reordered = filtered_trusted_order != filtered_current_order;

    if restriction_disappeared || reordered {
        return Widening::Structural;
    }

    let new_allow_appeared = current_seq
        .iter()
        .any(|s| is_allow_signature(s) && !trusted_set.contains(s.as_str()));

    if new_allow_appeared {
        Widening::Additive
    } else {
        Widening::None
    }
}

/// The precedence rule, made real: `Project` scope may narrow, never widen, unless a
/// human has recorded a trust decision at this exact `(repo_root, blake3(policy_file))`
/// pair. Returns the rule set that is actually safe to compile into the `PolicyEngine` —
/// which may be strictly narrower than what the (agent-writable) file itself authors.
/// See the module doc comment for the precise, conservative definition of "safe
/// narrowing" this function fails closed against anything short of.
pub fn apply_project_scope_trust(
    repo_root: &Path,
    policy_file_contents: &str,
    parsed_project_rules: Vec<CompiledRule>,
    trust_store: &TrustStore,
) -> Vec<CompiledRule> {
    let current_hash = blake3::hash(policy_file_contents.as_bytes())
        .to_hex()
        .to_string();

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
            // call re-evaluates against that (initially empty) trusted set via the same
            // `classify` logic below — there is no "hash matches, apply verbatim"
            // shortcut anywhere, which is what let a first-use Allow rule silently
            // self-grant on the very next call in an earlier version of this function.
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
            let trusted_seq = &record.trusted_rule_signatures;
            let current_seq: Vec<String> = signature_sequence(&parsed_project_rules);

            match classify(trusted_seq, &current_seq) {
                Widening::Structural => {
                    // Fails closed exactly like first-use/corrupt-record — and stricter:
                    // drop EVERY Project-scope Allow *and* Ask rule, keeping only Deny.
                    // Allow must go for the usual reason (a disappearing restriction or
                    // reorder can make an already-trusted Allow rule cover ground it
                    // never used to). Ask must go too: when the widening is a Deny
                    // rewritten to an Ask on the same predicate, that Ask rule DOES
                    // match, so leaving it in place would mean even
                    // `decide_unattended`'s no-human-to-ask-so-Deny downgrade never
                    // kicks in (it only downgrades an unmatched Ask, not one produced by
                    // a live rule) — nothing legitimate is lost by dropping it, since a
                    // Structurally-widened file is already fully distrusted. Do NOT
                    // save — the trusted baseline stays exactly where it was, so this
                    // file keeps being flagged as widened on every subsequent call
                    // until a human calls `record_explicit_trust`.
                    parsed_project_rules
                        .into_iter()
                        .filter(|r| !(r.scope == Scope::Project && r.outcome != Outcome::Deny))
                        .collect()
                }
                Widening::Additive => {
                    // Only a brand-new Allow rule appeared; nothing else about the
                    // trusted baseline was disturbed. Safe to keep every
                    // previously-trusted Allow rule (and every current Deny/Ask rule —
                    // new restrictions only narrow further); refuse just the new
                    // Allow(s). Do NOT save, for the same reason as above.
                    let trusted_allow: HashSet<&str> = trusted_seq
                        .iter()
                        .filter(|s| is_allow_signature(s))
                        .map(|s| s.as_str())
                        .collect();
                    parsed_project_rules
                        .into_iter()
                        .filter(|r| {
                            if r.scope == Scope::Project && r.outcome == Outcome::Allow {
                                signature_string(r)
                                    .map(|s| trusted_allow.contains(s.as_str()))
                                    .unwrap_or(false)
                            } else {
                                true
                            }
                        })
                        .collect()
                }
                Widening::None => {
                    // Provably safe narrowing (or literally no change): auto-advance
                    // the trusted baseline to the current file, no human action
                    // required.
                    let _ = trust_store.save(
                        repo_root,
                        &TrustRecord {
                            trusted_policy_hash: current_hash,
                            trusted_rule_signatures: current_seq,
                        },
                    );
                    parsed_project_rules
                }
            }
        }
    }
}

/// The human-facing escape hatch (`round policy trust`, or equivalent) — explicitly
/// trusts the CURRENT file's exact content and full Project-scope rule sequence (`Allow`
/// and `Deny`/`Ask` alike, in file order), unlocking whatever it widened. Never called
/// automatically except by `apply_project_scope_trust`'s own narrowing-auto-advance path
/// above. Overwrites any existing record unconditionally — including a corrupt one —
/// since this is the human resolving exactly the ambiguity `apply_project_scope_trust`
/// fails closed on.
pub fn record_explicit_trust(
    repo_root: &Path,
    policy_file_contents: &str,
    parsed_project_rules: &[CompiledRule],
    trust_store: &TrustStore,
) -> std::io::Result<()> {
    let hash = blake3::hash(policy_file_contents.as_bytes())
        .to_hex()
        .to_string();
    let sigs = signature_sequence(parsed_project_rules);
    trust_store.save(
        repo_root,
        &TrustRecord {
            trusted_policy_hash: hash,
            trusted_rule_signatures: sigs,
        },
    )
}
