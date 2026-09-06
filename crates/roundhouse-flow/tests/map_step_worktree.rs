//! Tests for Task 34 (lane W5, rulings W5-8/W5-22 — Phase 5 ruling P42):
//! `map.isolation: worktree` actually materializes a real git worktree per
//! fan-out item. See `crates/roundhouse-flow/src/exec/map_step.rs`'s own
//! doc comment, "Task 34: `isolation: worktree` materialization", for the
//! mechanism this exercises, and `crates/roundhouse-flow/src/worktree.rs`
//! for the `WorktreeProvider` trait/adapter these tests drive.
//!
//! Tests that spawn real `git` skip cleanly (with an explanatory
//! `eprintln!` and an early `return`) when `git` is not on this host's
//! `PATH` — matching `roundhouse-sandbox`'s existing OS/mechanism-gating
//! convention. CI is `ubuntu-latest`, where `git` exists, so this is not
//! how these tests pass there.

use roundhouse_core::TaskKind;
use roundhouse_flow::exec::{Executor, RunContext, TaskSink};
use roundhouse_flow::expr::EnvAllowlist;
use roundhouse_flow::parse::parse_workflow;
use roundhouse_flow::worktree::{SandboxWorktreeProvider, WorktreeProvider, WorktreeProviderError};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// A fresh `git init`-ed repo, one commit on the default branch. Cleans up
/// its directory on drop.
struct TempRepo {
    path: PathBuf,
}

impl TempRepo {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "roundhouse-flow-worktree-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&path).expect("create temp repo dir");
        let run = |args: &[&str]| {
            let status = Command::new("git")
                .args(args)
                .current_dir(&path)
                .status()
                .expect("spawn git for test fixture setup");
            assert!(status.success(), "git {args:?} failed during test setup");
        };
        run(&["init", "-q"]);
        run(&["config", "user.email", "test@example.com"]);
        run(&["config", "user.name", "test"]);
        std::fs::write(path.join("f.txt"), "hello\n").expect("write fixture file");
        run(&["add", "f.txt"]);
        run(&["commit", "-q", "-m", "init"]);
        TempRepo { path }
    }

    /// Real `git worktree list` output — used to assert against the
    /// ground truth, not just this crate's own bookkeeping.
    fn worktree_list(&self) -> String {
        let output = Command::new("git")
            .args(["worktree", "list"])
            .current_dir(&self.path)
            .output()
            .expect("git worktree list");
        String::from_utf8_lossy(&output.stdout).into_owned()
    }
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Wraps a real [`SandboxWorktreeProvider`] and, on every
/// [`WorktreeProvider::materialize`] call, independently confirms via a
/// real `git worktree list` (not this crate's own bookkeeping) that the
/// path it is about to return is genuinely registered — this is what makes
/// "one real git worktree per item" a claim this test file actually checks
/// against `git`, not merely against `SandboxWorktreeProvider`'s own return
/// value. Also records every `materialize`/`release` call, in order, so a
/// test can assert exactly one of each per fan-out item.
struct ObservingWorktreeProvider {
    inner: SandboxWorktreeProvider,
    repo_root: PathBuf,
    materialized: Mutex<Vec<PathBuf>>,
    released: Mutex<Vec<PathBuf>>,
}

impl ObservingWorktreeProvider {
    fn new(repo_root: PathBuf) -> Self {
        Self {
            inner: SandboxWorktreeProvider::new(repo_root.clone()),
            repo_root,
            materialized: Mutex::new(Vec::new()),
            released: Mutex::new(Vec::new()),
        }
    }

    fn worktree_list(&self) -> String {
        let output = Command::new("git")
            .args(["worktree", "list"])
            .current_dir(&self.repo_root)
            .output()
            .expect("git worktree list");
        String::from_utf8_lossy(&output.stdout).into_owned()
    }
}

impl WorktreeProvider for ObservingWorktreeProvider {
    fn materialize(&self, base_ref: &str) -> Result<PathBuf, WorktreeProviderError> {
        let path = self.inner.materialize(base_ref)?;
        assert!(
            self.worktree_list().contains(path.to_str().unwrap()),
            "real `git worktree list` must show the worktree this call just materialized"
        );
        self.materialized.lock().unwrap().push(path.clone());
        Ok(path)
    }

    fn release(&self, worktree_path: &Path) -> Result<(), WorktreeProviderError> {
        self.inner.release(worktree_path)?;
        self.released
            .lock()
            .unwrap()
            .push(worktree_path.to_path_buf());
        Ok(())
    }
}

/// A provider whose `materialize` always fails — no real repo needed, since
/// nothing ever reaches `git`. Used to pin that a materialize failure (as
/// opposed to a *missing* provider) also fails the item, with a message,
/// rather than panicking or silently continuing unisolated.
struct FailingMaterializeProvider;
impl WorktreeProvider for FailingMaterializeProvider {
    fn materialize(&self, _base_ref: &str) -> Result<PathBuf, WorktreeProviderError> {
        Err(WorktreeProviderError::new(
            "FailingMaterializeProvider refuses every materialize call",
        ))
    }
    fn release(&self, _worktree_path: &Path) -> Result<(), WorktreeProviderError> {
        panic!("release() must never be called when materialize() never succeeded")
    }
}

/// A provider whose `materialize` always succeeds (returning a fake path —
/// no real repo needed) but whose `release` always fails. Used to pin that
/// a release failure is folded into the item's own outcome on the
/// otherwise-successful path, rather than being silently swallowed.
struct FailingReleaseProvider;
impl WorktreeProvider for FailingReleaseProvider {
    fn materialize(&self, _base_ref: &str) -> Result<PathBuf, WorktreeProviderError> {
        Ok(PathBuf::from("/fake/worktree/path"))
    }
    fn release(&self, _worktree_path: &Path) -> Result<(), WorktreeProviderError> {
        Err(WorktreeProviderError::new(
            "FailingReleaseProvider refuses every release call",
        ))
    }
}

/// A provider whose `release` fails with an error embedding whatever text it
/// was constructed with, built through [`WorktreeProviderError::new`] — the
/// constructor the trait's own doc now tells implementors *not* to use for a
/// message carrying outside free text. Deliberately the careless
/// implementation, because the point of the test that uses it is that the
/// declared-secrets needle backstop still catches it.
struct LeakyReleaseProvider(String);
impl WorktreeProvider for LeakyReleaseProvider {
    fn materialize(&self, _base_ref: &str) -> Result<PathBuf, WorktreeProviderError> {
        Ok(PathBuf::from("/fake/worktree/path"))
    }
    fn release(&self, _worktree_path: &Path) -> Result<(), WorktreeProviderError> {
        Err(WorktreeProviderError::new(format!(
            "LeakyReleaseProvider failed while cleaning up after {}",
            self.0
        )))
    }
}

/// A provider whose `release` fails with a two-rendering error built the way
/// the trait doc tells implementors to — full text embedding whatever it was
/// constructed with, safe summary saying nothing beyond this crate's own
/// vocabulary. The counterpart to [`LeakyReleaseProvider`]: it exercises
/// whether the *caller* actually reads `safe_summary()` on the release path.
struct WithheldReleaseProvider(String);
impl WorktreeProvider for WithheldReleaseProvider {
    fn materialize(&self, _base_ref: &str) -> Result<PathBuf, WorktreeProviderError> {
        Ok(PathBuf::from("/fake/worktree/path"))
    }
    fn release(&self, _worktree_path: &Path) -> Result<(), WorktreeProviderError> {
        Err(WorktreeProviderError::with_safe_summary(
            format!("WithheldReleaseProvider failed cleaning up {}", self.0),
            "release failed (its free text is withheld here)",
        ))
    }
}

// ---------------------------------------------------------------------
// Test scaffolding shared with `tests/map_step.rs` (each `tests/*.rs` file
// is its own crate, so this cannot be imported from there).
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
struct RecordedEvent {
    // Only `RecordingSink`'s own length is asserted on in this file today
    // (`sink.0.is_empty()`) — kept for parity with `tests/map_step.rs`'s
    // identical struct and so a future test in this file can inspect a
    // specific event without re-adding these fields.
    #[allow(dead_code)]
    kind: TaskKind,
    #[allow(dead_code)]
    payload_json: serde_json::Value,
}

struct RecordingSink(Vec<RecordedEvent>);
impl TaskSink for RecordingSink {
    fn emit(
        &mut self,
        _task_id: roundhouse_core::TaskId,
        _parent: Option<roundhouse_core::TaskId>,
        kind: TaskKind,
        payload: roundhouse_core::EventPayload,
    ) {
        let payload_json = serde_json::to_value(&payload).unwrap_or(serde_json::Value::Null);
        self.0.push(RecordedEvent { kind, payload_json });
    }
}

fn run_ctx(
    inputs: serde_json::Value,
    worktree_provider: Option<Arc<dyn WorktreeProvider>>,
) -> RunContext {
    RunContext {
        inputs,
        vars: serde_json::json!({}),
        secrets: HashMap::new(),
        run_id: roundhouse_flow::exec::RunId::new(),
        previous_report: None,
        env_allowlist: EnvAllowlist::deny_all(),
        worktree_provider,
    }
}

fn secret_run_ctx(
    inputs: serde_json::Value,
    key: &str,
    value: &str,
    worktree_provider: Option<Arc<dyn WorktreeProvider>>,
) -> RunContext {
    let mut secrets = HashMap::new();
    secrets.insert(key.to_string(), value.to_string());
    RunContext {
        inputs,
        vars: serde_json::json!({}),
        secrets,
        run_id: roundhouse_flow::exec::RunId::new(),
        previous_report: None,
        env_allowlist: EnvAllowlist::deny_all(),
        worktree_provider,
    }
}

const WORKFLOW_PREAMBLE: &str = r#"
name: worktree-fanout
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
"#;

#[test]
fn explicit_worktree_isolation_creates_one_real_git_worktree_per_item_and_removes_it_after() {
    if !git_available() {
        eprintln!("skipping: git not available on this host");
        return;
    }
    let repo = TempRepo::new();
    let provider = Arc::new(ObservingWorktreeProvider::new(repo.path.clone()));

    let yaml = format!(
        "{WORKFLOW_PREAMBLE}steps:\n\
         \x20\x20- id: per_item\n\
         \x20\x20\x20\x20map:\n\
         \x20\x20\x20\x20\x20\x20over: \"${{{{ inputs.items }}}}\"\n\
         \x20\x20\x20\x20\x20\x20as: item\n\
         \x20\x20\x20\x20\x20\x20max_parallel: 1\n\
         \x20\x20\x20\x20\x20\x20on_item_error: continue\n\
         \x20\x20\x20\x20\x20\x20isolation: worktree\n\
         \x20\x20\x20\x20steps:\n\
         \x20\x20\x20\x20\x20\x20- id: emit_path\n\
         \x20\x20\x20\x20\x20\x20\x20\x20emit: {{ path: \"${{{{ worktree.path }}}}\" }}\n"
    );
    let def = parse_workflow(&yaml).expect("workflow must parse");
    let mut sink = RecordingSink(Vec::new());
    let ctx = run_ctx(
        serde_json::json!({"items": [1, 2, 3]}),
        Some(provider.clone()),
    );
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().expect("run must not error");

    let map_outcome = &outcomes[0];
    let items = map_outcome.output["items"].as_array().unwrap();
    assert_eq!(items.len(), 3, "one ItemOutcome per fan-out item");
    for item in items {
        assert_eq!(item["status"], "completed", "item outcome: {item:?}");
    }

    assert_eq!(
        provider.materialized.lock().unwrap().len(),
        3,
        "exactly one materialize() call per fan-out item"
    );
    assert_eq!(
        provider.released.lock().unwrap().len(),
        3,
        "exactly one release() call per fan-out item"
    );
    assert_eq!(
        *provider.materialized.lock().unwrap(),
        *provider.released.lock().unwrap(),
        "the path released must always be the exact path materialized"
    );

    // Cleanup is real, not just this crate's own bookkeeping: after the map
    // step finishes, `git worktree list` must show only the repo's own
    // primary worktree, none of the three items' worktrees.
    let final_listing = repo.worktree_list();
    for path in provider.materialized.lock().unwrap().iter() {
        assert!(
            !final_listing.contains(path.to_str().unwrap()),
            "worktree at {path:?} must be gone from `git worktree list` after the map step \
             finishes, got:\n{final_listing}"
        );
        assert!(
            !path.exists(),
            "worktree directory at {path:?} must not exist on disk after cleanup"
        );
    }

    // The path was genuinely readable from inside the map body: each
    // item's emitted `${{ worktree.path }}` matches the path this test
    // independently observed via `git worktree list` at materialize time.
    let emitted_paths: Vec<String> = items
        .iter()
        .map(|item| item["output"]["path"].as_str().unwrap().to_string())
        .collect();
    let materialized_paths: Vec<String> = provider
        .materialized
        .lock()
        .unwrap()
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    assert_eq!(
        emitted_paths, materialized_paths,
        "`${{ worktree.path }}` inside the map body must equal the real materialized path"
    );
}

#[test]
fn isolation_left_unset_creates_no_worktree_even_though_defaults_isolation_is_worktree() {
    // `defaults: { isolation: worktree }` is present in every workflow this
    // crate parses (a required default), but this map step's own
    // `isolation:` field is absent — see
    // `Executor::dispatch_map_step`'s own doc comment, "Task 34", for why
    // that must never be read as an implicit demand to materialize
    // anything.
    let repo = TempRepo::new();
    let provider = Arc::new(ObservingWorktreeProvider::new(repo.path.clone()));

    let yaml = format!(
        "{WORKFLOW_PREAMBLE}steps:\n\
         \x20\x20- id: per_item\n\
         \x20\x20\x20\x20map:\n\
         \x20\x20\x20\x20\x20\x20over: \"${{{{ inputs.items }}}}\"\n\
         \x20\x20\x20\x20\x20\x20as: item\n\
         \x20\x20\x20\x20\x20\x20max_parallel: 1\n\
         \x20\x20\x20\x20\x20\x20on_item_error: continue\n\
         \x20\x20\x20\x20steps:\n\
         \x20\x20\x20\x20\x20\x20- id: emit_something\n\
         \x20\x20\x20\x20\x20\x20\x20\x20emit: {{ ok: true }}\n"
    );
    let def = parse_workflow(&yaml).expect("workflow must parse");
    let mut sink = RecordingSink(Vec::new());
    let ctx = run_ctx(serde_json::json!({"items": [1, 2]}), Some(provider.clone()));
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().expect("run must not error");

    let items = outcomes[0].output["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    for item in items {
        assert_eq!(item["status"], "completed");
    }
    assert!(
        provider.materialized.lock().unwrap().is_empty(),
        "no worktree may be materialized when the map-level `isolation:` field is absent"
    );
}

#[test]
fn explicit_worktree_isolation_with_no_provider_fails_the_item_naming_the_missing_provider() {
    let yaml = format!(
        "{WORKFLOW_PREAMBLE}steps:\n\
         \x20\x20- id: per_item\n\
         \x20\x20\x20\x20map:\n\
         \x20\x20\x20\x20\x20\x20over: \"${{{{ inputs.items }}}}\"\n\
         \x20\x20\x20\x20\x20\x20as: item\n\
         \x20\x20\x20\x20\x20\x20max_parallel: 1\n\
         \x20\x20\x20\x20\x20\x20on_item_error: continue\n\
         \x20\x20\x20\x20\x20\x20isolation: worktree\n\
         \x20\x20\x20\x20steps:\n\
         \x20\x20\x20\x20\x20\x20- id: emit_something\n\
         \x20\x20\x20\x20\x20\x20\x20\x20emit: {{ ok: true }}\n"
    );
    let def = parse_workflow(&yaml).expect("workflow must parse");
    let mut sink = RecordingSink(Vec::new());
    // No provider configured — the fail-closed case.
    let ctx = run_ctx(serde_json::json!({"items": [1]}), None);
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().expect("run must not error");

    let items = outcomes[0].output["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0]["status"], "failed",
        "an explicit `isolation: worktree` with no provider must fail the item, not silently \
         succeed unisolated — got {:?}",
        items[0]
    );
    let error = items[0]["error"].as_str().unwrap();
    assert!(
        error.contains("WorktreeProvider") || error.to_lowercase().contains("provider"),
        "the failure message must name the missing provider, got: {error:?}"
    );
}

#[test]
fn cleanup_runs_on_the_failure_path_not_only_on_success() {
    if !git_available() {
        eprintln!("skipping: git not available on this host");
        return;
    }
    let repo = TempRepo::new();
    let provider = Arc::new(ObservingWorktreeProvider::new(repo.path.clone()));

    // The inner step fails for its own reason (a `tool:` step body cannot
    // itself fail synchronously today, so a nested `report:` — refused
    // inside a `map` — is used as a reliable, synchronous inner-step
    // failure).
    let yaml = format!(
        "{WORKFLOW_PREAMBLE}steps:\n\
         \x20\x20- id: per_item\n\
         \x20\x20\x20\x20map:\n\
         \x20\x20\x20\x20\x20\x20over: \"${{{{ inputs.items }}}}\"\n\
         \x20\x20\x20\x20\x20\x20as: item\n\
         \x20\x20\x20\x20\x20\x20max_parallel: 1\n\
         \x20\x20\x20\x20\x20\x20on_item_error: continue\n\
         \x20\x20\x20\x20\x20\x20isolation: worktree\n\
         \x20\x20\x20\x20steps:\n\
         \x20\x20\x20\x20\x20\x20- id: doomed_report\n\
         \x20\x20\x20\x20\x20\x20\x20\x20report: {{ outcome: nothing, severity: low, headline: x, needs_human: false, cost: {{ usd: 0, tokens: 0 }} }}\n"
    );
    let def = parse_workflow(&yaml).expect("workflow must parse");
    let mut sink = RecordingSink(Vec::new());
    let ctx = run_ctx(serde_json::json!({"items": [1]}), Some(provider.clone()));
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().expect("run must not error");

    let items = outcomes[0].output["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0]["status"], "failed",
        "the nested `report:` refusal must fail this item — got {:?}",
        items[0]
    );

    assert_eq!(
        provider.materialized.lock().unwrap().len(),
        1,
        "the worktree must still have been materialized before the inner step failed"
    );
    assert_eq!(
        provider.released.lock().unwrap().len(),
        1,
        "the worktree must be released even though the item's inner step failed"
    );

    let final_listing = repo.worktree_list();
    let materialized_path = provider.materialized.lock().unwrap()[0].clone();
    assert!(
        !final_listing.contains(materialized_path.to_str().unwrap()),
        "worktree must be gone from `git worktree list` after a failed item, got:\n{final_listing}"
    );
    assert!(!materialized_path.exists());
}

#[test]
fn a_base_ref_the_parse_time_validator_rejects_never_reaches_the_dispatcher() {
    // Regression pin (brief's Step 1, last bullet): the two layers —
    // `parse/steps.rs::validate_git_ref` and this crate's runtime argv
    // discipline — must stay wired together. A `base_ref` shaped like a
    // git-flag injection is rejected before `Executor::dispatch_map_step`
    // ever sees it — there is nothing to dispatch.
    //
    // `parse_workflow` itself does **not** reach this: `WorkflowDef.steps`
    // stays raw `Vec<serde_yaml::Value>` (`crate::parse::types::WorkflowDef`'s
    // own doc comment — "Task 3 defines `StepDef` and parses these"), so a
    // step's own body, `map.isolation` included, is only parsed by
    // `parse_step`, called per top-level step from
    // `Executor::run_to_completion`/`run_loop::run_workflow`. So the
    // rejection surfaces there, as an `Err` from `run_to_completion` — this
    // pins that it happens *before* any item is ever dispatched, not that
    // `parse_workflow` itself catches it.
    let yaml = format!(
        "{WORKFLOW_PREAMBLE}steps:\n\
         \x20\x20- id: per_item\n\
         \x20\x20\x20\x20map:\n\
         \x20\x20\x20\x20\x20\x20over: \"${{{{ inputs.items }}}}\"\n\
         \x20\x20\x20\x20\x20\x20as: item\n\
         \x20\x20\x20\x20\x20\x20max_parallel: 1\n\
         \x20\x20\x20\x20\x20\x20on_item_error: continue\n\
         \x20\x20\x20\x20\x20\x20isolation: {{ worktree: {{ base_ref: \"--upload-pack=/tmp/evil\" }} }}\n\
         \x20\x20\x20\x20steps:\n\
         \x20\x20\x20\x20\x20\x20- id: emit_something\n\
         \x20\x20\x20\x20\x20\x20\x20\x20emit: {{ ok: true }}\n"
    );
    let def = parse_workflow(&yaml).expect("parse_workflow does not parse step bodies");
    let mut sink = RecordingSink(Vec::new());
    let ctx = run_ctx(serde_json::json!({"items": [1]}), None);
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();

    let result = exec.run_to_completion();
    assert!(
        result.is_err(),
        "a flag-shaped `base_ref` literal must fail step parsing before any item is \
         dispatched, got {result:?}"
    );
    assert!(
        sink.0.is_empty(),
        "no task may be emitted for a map step whose isolation could not even be parsed"
    );
}

#[test]
fn a_materialize_failure_fails_the_item_with_a_message_distinct_from_the_missing_provider_case() {
    let yaml = format!(
        "{WORKFLOW_PREAMBLE}steps:\n\
         \x20\x20- id: per_item\n\
         \x20\x20\x20\x20map:\n\
         \x20\x20\x20\x20\x20\x20over: \"${{{{ inputs.items }}}}\"\n\
         \x20\x20\x20\x20\x20\x20as: item\n\
         \x20\x20\x20\x20\x20\x20max_parallel: 1\n\
         \x20\x20\x20\x20\x20\x20on_item_error: continue\n\
         \x20\x20\x20\x20\x20\x20isolation: worktree\n\
         \x20\x20\x20\x20steps:\n\
         \x20\x20\x20\x20\x20\x20- id: emit_something\n\
         \x20\x20\x20\x20\x20\x20\x20\x20emit: {{ ok: true }}\n"
    );
    let def = parse_workflow(&yaml).expect("workflow must parse");
    let mut sink = RecordingSink(Vec::new());
    let ctx = run_ctx(
        serde_json::json!({"items": [1]}),
        Some(Arc::new(FailingMaterializeProvider) as Arc<dyn WorktreeProvider>),
    );
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().expect("run must not error");

    let items = outcomes[0].output["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["status"], "failed");
    let error = items[0]["error"].as_str().unwrap();
    assert!(
        error.contains("materializing"),
        "a real provider's materialize failure must be distinguishable from the \
         missing-provider case, got: {error:?}"
    );
}

#[test]
fn a_release_failure_is_folded_into_an_otherwise_successful_items_outcome() {
    let yaml = format!(
        "{WORKFLOW_PREAMBLE}steps:\n\
         \x20\x20- id: per_item\n\
         \x20\x20\x20\x20map:\n\
         \x20\x20\x20\x20\x20\x20over: \"${{{{ inputs.items }}}}\"\n\
         \x20\x20\x20\x20\x20\x20as: item\n\
         \x20\x20\x20\x20\x20\x20max_parallel: 1\n\
         \x20\x20\x20\x20\x20\x20on_item_error: continue\n\
         \x20\x20\x20\x20\x20\x20isolation: worktree\n\
         \x20\x20\x20\x20steps:\n\
         \x20\x20\x20\x20\x20\x20- id: emit_something\n\
         \x20\x20\x20\x20\x20\x20\x20\x20emit: {{ ok: true }}\n"
    );
    let def = parse_workflow(&yaml).expect("workflow must parse");
    let mut sink = RecordingSink(Vec::new());
    let ctx = run_ctx(
        serde_json::json!({"items": [1]}),
        Some(Arc::new(FailingReleaseProvider) as Arc<dyn WorktreeProvider>),
    );
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().expect("run must not error");

    let items = outcomes[0].output["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0]["status"], "failed",
        "a release failure must surface as the item's own failure, not be swallowed — got {:?}",
        items[0]
    );
    let error = items[0]["error"].as_str().unwrap();
    assert!(
        error.contains("releasing"),
        "the failure message must name the release failure, got: {error:?}"
    );
}

/// Fix round 1, item 1 (CRITICAL): a secret-derived `base_ref` must never
/// reach the map step's persisted, displayable output as cleartext, and the
/// item's own `output_is_secret_derived` must be `true`. Drives the
/// materialize-*failure* path specifically (git rejects "not-a-real-ref" as
/// an invalid reference and quotes it back in stderr) because that is the
/// path the security lens reproduced the leak through: the secret appeared
/// three times — the direct interpolation-result echo, the argv echo inside
/// `WorktreeError::CommandFailed`'s `Display`, and git's own stderr quoting
/// the rejected ref.
#[test]
fn a_secret_derived_base_ref_never_reaches_the_serialized_outcome_and_taints_the_item() {
    if !git_available() {
        eprintln!("skipping: git not available on this host");
        return;
    }
    const SECRET_VALUE: &str = "not-a-real-git-ref-topsecret123";
    let repo = TempRepo::new();
    let provider = Arc::new(ObservingWorktreeProvider::new(repo.path.clone()));

    let yaml = format!(
        "{WORKFLOW_PREAMBLE}secrets: [T]\nsteps:\n\
         \x20\x20- id: per_item\n\
         \x20\x20\x20\x20map:\n\
         \x20\x20\x20\x20\x20\x20over: \"${{{{ inputs.items }}}}\"\n\
         \x20\x20\x20\x20\x20\x20as: item\n\
         \x20\x20\x20\x20\x20\x20max_parallel: 1\n\
         \x20\x20\x20\x20\x20\x20on_item_error: continue\n\
         \x20\x20\x20\x20\x20\x20isolation: {{ worktree: {{ base_ref: \"${{{{ secrets.T }}}}\" }} }}\n\
         \x20\x20\x20\x20steps:\n\
         \x20\x20\x20\x20\x20\x20- id: emit_something\n\
         \x20\x20\x20\x20\x20\x20\x20\x20emit: {{ ok: true }}\n"
    );
    let def = parse_workflow(&yaml).expect("workflow must parse");
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(
        serde_json::json!({"items": [1]}),
        "T",
        SECRET_VALUE,
        Some(provider.clone() as Arc<dyn WorktreeProvider>),
    );
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().expect("run must not error");

    // Sanity: this must actually exercise the materialize-failure path —
    // otherwise the test proves nothing.
    let items = outcomes[0].output["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0]["status"], "failed",
        "expected git to reject this base_ref as invalid — got {:?}",
        items[0]
    );
    let error = items[0]["error"].as_str().unwrap();
    assert!(
        !error.contains(SECRET_VALUE),
        "the raw secret value must never appear in the item's own error message, got: {error:?}"
    );

    // The whole serialized outcome — not just the one field this test
    // happens to look at — must never contain the secret, matching the
    // brief's "the secret string appears nowhere in the serialized outcome"
    // requirement.
    let serialized = serde_json::to_string(&outcomes[0].output).unwrap();
    assert!(
        !serialized.contains(SECRET_VALUE),
        "the raw secret value must not appear anywhere in the map step's serialized output, \
         got: {serialized}"
    );

    assert!(
        outcomes[0].output_is_secret_derived,
        "output_is_secret_derived must be true once a secret-derived base_ref was read, so \
         durability.rs's value_for_display() redacts this output rather than showing it \
         verbatim"
    );
}

/// Fix round 1, item 6: `isolation: sandbox|container|remote` all parse
/// (`parse/steps.rs` accepts all five tiers), but this crate can only ever
/// materialize `worktree`. Before this fix the other three silently fell
/// through with no worktree, no error, and no warning — exactly the P42
/// shape this whole task exists to close, for three of the four non-`none`
/// tiers. Grepped the fixture suite and every test file first (per the
/// brief's explicit instruction): no fixture or test declares
/// `isolation: sandbox|container|remote` at the map level, so this fix does
/// not need to accommodate one.
#[test]
fn the_other_three_isolation_tiers_fail_closed_rather_than_silently_doing_nothing() {
    for tier in ["sandbox", "container", "remote"] {
        let yaml = format!(
            "{WORKFLOW_PREAMBLE}steps:\n\
             \x20\x20- id: per_item\n\
             \x20\x20\x20\x20map:\n\
             \x20\x20\x20\x20\x20\x20over: \"${{{{ inputs.items }}}}\"\n\
             \x20\x20\x20\x20\x20\x20as: item\n\
             \x20\x20\x20\x20\x20\x20max_parallel: 1\n\
             \x20\x20\x20\x20\x20\x20on_item_error: continue\n\
             \x20\x20\x20\x20\x20\x20isolation: {tier}\n\
             \x20\x20\x20\x20steps:\n\
             \x20\x20\x20\x20\x20\x20- id: emit_something\n\
             \x20\x20\x20\x20\x20\x20\x20\x20emit: {{ ok: true }}\n"
        );
        let def =
            parse_workflow(&yaml).unwrap_or_else(|e| panic!("{tier}: workflow must parse: {e}"));
        let mut sink = RecordingSink(Vec::new());
        let ctx = run_ctx(serde_json::json!({"items": [1]}), None);
        let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
        let outcomes = exec.run_to_completion().expect("run must not error");

        let items = outcomes[0].output["items"].as_array().unwrap();
        assert_eq!(items.len(), 1, "tier {tier}");
        assert_eq!(
            items[0]["status"], "failed",
            "tier {tier}: a declared-but-undeliverable isolation tier must fail the item \
             closed, not silently run it unisolated — got {:?}",
            items[0]
        );
        let error = items[0]["error"].as_str().unwrap();
        assert!(
            error.contains(tier),
            "tier {tier}: the failure message must name the tier it could not deliver, got: \
             {error:?}"
        );
    }
}

/// `isolation: none` — as opposed to the field being absent — is a
/// legitimately deliverable choice (this crate can always deliver "no
/// isolation": doing nothing) and must remain a true no-op, not fail
/// closed like `sandbox`/`container`/`remote`.
#[test]
fn isolation_none_explicitly_set_is_still_a_deliverable_no_op() {
    let yaml = format!(
        "{WORKFLOW_PREAMBLE}steps:\n\
         \x20\x20- id: per_item\n\
         \x20\x20\x20\x20map:\n\
         \x20\x20\x20\x20\x20\x20over: \"${{{{ inputs.items }}}}\"\n\
         \x20\x20\x20\x20\x20\x20as: item\n\
         \x20\x20\x20\x20\x20\x20max_parallel: 1\n\
         \x20\x20\x20\x20\x20\x20on_item_error: continue\n\
         \x20\x20\x20\x20\x20\x20isolation: none\n\
         \x20\x20\x20\x20steps:\n\
         \x20\x20\x20\x20\x20\x20- id: emit_something\n\
         \x20\x20\x20\x20\x20\x20\x20\x20emit: {{ ok: true }}\n"
    );
    let def = parse_workflow(&yaml).expect("workflow must parse");
    let mut sink = RecordingSink(Vec::new());
    let ctx = run_ctx(serde_json::json!({"items": [1]}), None);
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().expect("run must not error");

    let items = outcomes[0].output["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0]["status"], "completed",
        "explicit `isolation: none` must remain a deliverable no-op — got {:?}",
        items[0]
    );
}

/// Fix round 2, item 2 (PROBE D): a secret-*derived* `over:` — as opposed
/// to `base_ref` reading `secrets.*` directly — still let the per-item
/// element reach the persisted output in cleartext, because
/// `self.redaction_needles` only ever contains the *raw* `RunContext.secrets`
/// values, never anything computed from them (`json(secrets.T)`'s decoded
/// elements are exactly that). `redacted_base_ref` alone (fix round 1's
/// fix) is `***` — `Interpolated`'s own provenance tracking already caught
/// this — but the *other* two copies (the argv echo inside
/// `WorktreeError::CommandFailed`'s `Display`, and git's own stderr quoting
/// the rejected ref) live inside `{e}`, which the crate-wide needle list
/// alone cannot see. Reproduces the brief's PROBE D exactly: `over: "${{
/// json(secrets.T) }}"`, secret `["itemvalue-secret1"]`, `base_ref: "${{
/// item }}"`.
#[test]
fn a_secret_derived_over_item_never_reaches_the_serialized_outcome() {
    if !git_available() {
        eprintln!("skipping: git not available on this host");
        return;
    }
    const SECRET_ELEMENT: &str = "itemvalue-secret1";
    let repo = TempRepo::new();
    let provider = Arc::new(ObservingWorktreeProvider::new(repo.path.clone()));

    let yaml = format!(
        "{WORKFLOW_PREAMBLE}secrets: [T]\nsteps:\n\
         \x20\x20- id: per_item\n\
         \x20\x20\x20\x20map:\n\
         \x20\x20\x20\x20\x20\x20over: \"${{{{ json(secrets.T) }}}}\"\n\
         \x20\x20\x20\x20\x20\x20as: item\n\
         \x20\x20\x20\x20\x20\x20max_parallel: 1\n\
         \x20\x20\x20\x20\x20\x20on_item_error: continue\n\
         \x20\x20\x20\x20\x20\x20isolation: {{ worktree: {{ base_ref: \"${{{{ item }}}}\" }} }}\n\
         \x20\x20\x20\x20steps:\n\
         \x20\x20\x20\x20\x20\x20- id: emit_something\n\
         \x20\x20\x20\x20\x20\x20\x20\x20emit: {{ ok: true }}\n"
    );
    let def = parse_workflow(&yaml).expect("workflow must parse");
    let mut sink = RecordingSink(Vec::new());
    // The raw secret value is the JSON-encoded array text itself — never
    // the decoded element. This is precisely what makes the gap real:
    // `self.redaction_needles` will contain `["itemvalue-secret1"]` (the
    // whole blob), not `itemvalue-secret1` (the element that actually
    // reaches argv).
    let ctx = secret_run_ctx(
        serde_json::json!({}),
        "T",
        &format!("[{SECRET_ELEMENT:?}]"),
        Some(provider.clone() as Arc<dyn WorktreeProvider>),
    );
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().expect("run must not error");

    let items = outcomes[0].output["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0]["status"], "failed",
        "expected git to reject this base_ref as invalid — got {:?}",
        items[0]
    );
    let error = items[0]["error"].as_str().unwrap();
    assert!(
        !error.contains(SECRET_ELEMENT),
        "the secret-derived over: element must never appear in the item's own error message, \
         got: {error:?}"
    );

    let serialized = serde_json::to_string(&outcomes[0].output).unwrap();
    assert!(
        !serialized.contains(SECRET_ELEMENT),
        "the secret-derived over: element must not appear anywhere in the map step's \
         serialized output, got: {serialized}"
    );

    assert!(
        outcomes[0].output_is_secret_derived,
        "output_is_secret_derived must be true — over_evaluated.secret_derived() already folds \
         this in independently of the base_ref taint fix"
    );
}

/// Fix round 3, item 1, probe (a): `git` does not always echo a **copy** of
/// a rejected ref — `@{upstream}`-style branch-mark syntax makes it die
/// mid-interpretation and report only the prefix before `@{`. A
/// needle-based scrub keyed on the *whole* secret-derived value (fix round
/// 2's fix) matches nothing against that truncated echo, so the secret
/// still leaked through git's stderr even though the direct
/// `redacted_base_ref` copy was already correctly `***`. This is the
/// regression the withhold-don't-scrub fix (this round) closes.
#[test]
fn a_secret_derived_base_ref_with_an_at_brace_suffix_never_reaches_the_serialized_outcome() {
    if !git_available() {
        eprintln!("skipping: git not available on this host");
        return;
    }
    const SECRET_ELEMENT: &str = "itemvalue-secret1@{upstream}";
    // What must never leak is the *branch name* git reports back
    // (`itemvalue-secret1`) — git's own truncation drops the `@{upstream}`
    // suffix before echoing anything, so that suffix was never the leak
    // vector this probe is pinning.
    const LEAKED_PREFIX: &str = "itemvalue-secret1";
    let repo = TempRepo::new();
    let provider = Arc::new(ObservingWorktreeProvider::new(repo.path.clone()));

    let yaml = format!(
        "{WORKFLOW_PREAMBLE}secrets: [T]\nsteps:\n\
         \x20\x20- id: per_item\n\
         \x20\x20\x20\x20map:\n\
         \x20\x20\x20\x20\x20\x20over: \"${{{{ json(secrets.T) }}}}\"\n\
         \x20\x20\x20\x20\x20\x20as: item\n\
         \x20\x20\x20\x20\x20\x20max_parallel: 1\n\
         \x20\x20\x20\x20\x20\x20on_item_error: continue\n\
         \x20\x20\x20\x20\x20\x20isolation: {{ worktree: {{ base_ref: \"${{{{ item }}}}\" }} }}\n\
         \x20\x20\x20\x20steps:\n\
         \x20\x20\x20\x20\x20\x20- id: emit_something\n\
         \x20\x20\x20\x20\x20\x20\x20\x20emit: {{ ok: true }}\n"
    );
    let def = parse_workflow(&yaml).expect("workflow must parse");
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(
        serde_json::json!({}),
        "T",
        &format!("[{SECRET_ELEMENT:?}]"),
        Some(provider.clone() as Arc<dyn WorktreeProvider>),
    );
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().expect("run must not error");

    let items = outcomes[0].output["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0]["status"], "failed",
        "expected git to reject this base_ref as invalid — got {:?}",
        items[0]
    );
    let error = items[0]["error"].as_str().unwrap();
    assert!(
        !error.contains(LEAKED_PREFIX),
        "git's truncated echo of the secret-derived branch name must never appear in the \
         item's own error message, got: {error:?}"
    );

    // Final round, item C4: assert the *mechanism*, not only the outcome.
    // "no leak" also holds if git happened not to echo anything at all, or
    // if the item failed earlier for an unrelated reason; this pins that
    // the withhold branch is what produced the message.
    assert!(
        error.contains("withheld"),
        "the secret-derived branch must render `WorktreeError::safe_summary()`, whose \
         text says what it withheld — got: {error:?}"
    );

    let serialized = serde_json::to_string(&outcomes[0].output).unwrap();
    assert!(
        !serialized.contains(LEAKED_PREFIX),
        "git's truncated echo of the secret-derived branch name must not appear anywhere in \
         the map step's serialized output, got: {serialized}"
    );
}

/// Fix round 3, item 1, probe (b): `git`'s own `vreportf` stderr buffer
/// silently truncates values past ~4KB (measured on git 2.55.0: 4069 bytes
/// echo whole, 4070 echo a 4069-byte prefix) — a needle-based scrub keyed
/// on the whole secret-derived value cannot match a truncated prefix of
/// it, so a long secret's leading ~4KB survived fix round 2's fix. Uses a
/// 6000-byte element, comfortably past the measured cutover on any git
/// build (the withhold-don't-scrub fix depends on no particular threshold —
/// see this test's assertion, which checks for the *whole* element, not a
/// build-specific truncation point).
#[test]
fn a_secret_derived_base_ref_longer_than_gits_stderr_buffer_never_reaches_the_serialized_outcome() {
    if !git_available() {
        eprintln!("skipping: git not available on this host");
        return;
    }
    let secret_element: String = "x".repeat(6000);
    let repo = TempRepo::new();
    let provider = Arc::new(ObservingWorktreeProvider::new(repo.path.clone()));

    let yaml = format!(
        "{WORKFLOW_PREAMBLE}secrets: [T]\nsteps:\n\
         \x20\x20- id: per_item\n\
         \x20\x20\x20\x20map:\n\
         \x20\x20\x20\x20\x20\x20over: \"${{{{ json(secrets.T) }}}}\"\n\
         \x20\x20\x20\x20\x20\x20as: item\n\
         \x20\x20\x20\x20\x20\x20max_parallel: 1\n\
         \x20\x20\x20\x20\x20\x20on_item_error: continue\n\
         \x20\x20\x20\x20\x20\x20isolation: {{ worktree: {{ base_ref: \"${{{{ item }}}}\" }} }}\n\
         \x20\x20\x20\x20steps:\n\
         \x20\x20\x20\x20\x20\x20- id: emit_something\n\
         \x20\x20\x20\x20\x20\x20\x20\x20emit: {{ ok: true }}\n"
    );
    let def = parse_workflow(&yaml).expect("workflow must parse");
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(
        serde_json::json!({}),
        "T",
        &format!("[{secret_element:?}]"),
        Some(provider.clone() as Arc<dyn WorktreeProvider>),
    );
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().expect("run must not error");

    let items = outcomes[0].output["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0]["status"], "failed",
        "expected git to reject this base_ref as invalid — got {:?}",
        items[0]
    );
    let error = items[0]["error"].as_str().unwrap();
    // Even a partial (truncated) echo of the element must not appear —
    // check for a long prefix, not just the whole 6000-byte string, since
    // the whole point of this probe is that git's own truncation would
    // otherwise let a multi-KB prefix survive a whole-value needle.
    let probe_prefix = &secret_element[..100];
    assert!(
        !error.contains(probe_prefix),
        "no prefix of the secret-derived element (checked: {} bytes) may appear in the item's \
         own error message, got an error of {} bytes",
        probe_prefix.len(),
        error.len()
    );

    // Final round, item C4: assert the *mechanism*, not only the outcome.
    // "no leak" also holds if git happened not to echo anything at all, or
    // if the item failed earlier for an unrelated reason; this pins that
    // the withhold branch is what produced the message.
    assert!(
        error.contains("withheld"),
        "the secret-derived branch must render `WorktreeError::safe_summary()`, whose \
         text says what it withheld — got: {error:?}"
    );

    let serialized = serde_json::to_string(&outcomes[0].output).unwrap();
    assert!(
        !serialized.contains(probe_prefix),
        "no prefix of the secret-derived element may appear anywhere in the map step's \
         serialized output"
    );
}

/// Final whole-branch round, item A1 — the **declared-secrets needle
/// backstop**, which is a different guard from the withhold above and closes
/// a hole the withhold cannot see.
///
/// The withhold fires on provenance: `base_ref` computed from
/// `${{ secrets.T }}` is secret-*derived*, so `WorktreeError::safe_summary()`
/// replaces `git`'s free text. This test drives the case where a **declared**
/// secret's raw value reaches `base_ref` through a channel provenance treats
/// as clean — here the workflow author pasting it literally into the YAML.
/// (The other reachable channel is a placeholder over *public* data, driven
/// by `a_backslash_bearing_secret_is_scrubbed_before_debug_formatting_can_escape_it`
/// below. `env('NAME')` is **not** one: `'`, `(` and `)` are in
/// `FORBIDDEN_GIT_REF_CHARS`, so such a `base_ref` never parses — an earlier
/// version of this comment said otherwise.) Then
/// `base_ref_is_secret_derived` is `false`, no withhold happens, and the only
/// thing standing between the raw value and the append-only `events` table is
/// the needle scan every sibling dispatch arm applies
/// (`exec/mod.rs:958`/`:1007`/`:1065`/`:1122`).
///
/// Task 34's fix round 3 deleted `redact_message` when it replaced scrubbing
/// with withholding, taking that backstop off this branch with it; this pins
/// the restoration. **Verified by removal, not by assertion:** with the
/// `redact_message` call on the `else` branch dropped, the raw value appears
/// in the serialized outcome three times — as the echoed `base_ref`, inside
/// the echoed argv, and inside `git`'s own stderr — and this test fails.
#[test]
fn a_declared_secrets_raw_value_pasted_literally_into_base_ref_is_still_scrubbed() {
    if !git_available() {
        eprintln!("skipping: git not available on this host");
        return;
    }
    // Long enough to clear `MIN_REDACTABLE_SECRET_LEN` (8) — a shorter
    // secret is deliberately never made a needle — and shaped so `git`
    // rejects it as a ref and quotes it back in stderr, which is what makes
    // the leak reachable at all.
    const SECRET_VALUE: &str = "not-a-real-git-ref-topsecret123";
    let repo = TempRepo::new();
    let provider = Arc::new(ObservingWorktreeProvider::new(repo.path.clone()));

    // `base_ref` is the literal value, NOT `${{ secrets.T }}`: that is the
    // whole point — provenance has nothing to mark, so the withhold branch
    // never runs.
    let yaml = format!(
        "{WORKFLOW_PREAMBLE}secrets: [T]\nsteps:\n\
         \x20\x20- id: per_item\n\
         \x20\x20\x20\x20map:\n\
         \x20\x20\x20\x20\x20\x20over: \"${{{{ inputs.items }}}}\"\n\
         \x20\x20\x20\x20\x20\x20as: item\n\
         \x20\x20\x20\x20\x20\x20max_parallel: 1\n\
         \x20\x20\x20\x20\x20\x20on_item_error: continue\n\
         \x20\x20\x20\x20\x20\x20isolation: {{ worktree: {{ base_ref: \"{SECRET_VALUE}\" }} }}\n\
         \x20\x20\x20\x20steps:\n\
         \x20\x20\x20\x20\x20\x20- id: emit_something\n\
         \x20\x20\x20\x20\x20\x20\x20\x20emit: {{ ok: true }}\n"
    );
    let def = parse_workflow(&yaml).expect("workflow must parse");
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(
        serde_json::json!({"items": [1]}),
        "T",
        SECRET_VALUE,
        Some(provider.clone() as Arc<dyn WorktreeProvider>),
    );
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().expect("run must not error");

    // Sanity: this must actually exercise the materialize-failure path, and
    // it must be the *non*-withheld branch — otherwise the test would pass
    // for the wrong reason (the withhold, not the backstop).
    let items = outcomes[0].output["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0]["status"], "failed",
        "expected git to reject this base_ref as invalid — got {:?}",
        items[0]
    );
    let error = items[0]["error"].as_str().unwrap();
    // Part 3 (ruling W5-48) made a declared secret's *presence* in
    // `base_ref` trigger the withhold as well, so this input now exercises
    // **both** guards rather than the scrub alone. (Before part 3 the
    // assertion below was `!contains("withheld")` — accurate then, false
    // now.)
    //
    // **What each of these two assertions actually pins, measured with
    // mutants rather than argued (part 5).** `contains("withheld")` bites:
    // dropping the needle-presence disjunct at the guard fails this test.
    // `contains("***")` pins that *a* needle scrub ran — but **not which
    // one**: an earlier version of this comment claimed only the
    // pre-format scrub could produce it, and that is wrong, because the
    // post-assembly `redact_message` in the same arm produces `***` too.
    // Measured: with the pre-format scrub removed, this test still passes.
    //
    // That is not a gap to close with a better assertion here — it is
    // structural. This test's channel is a **literal YAML paste**, and
    // `"`, `'` and `\` are all in `FORBIDDEN_GIT_REF_CHARS`, so a literal
    // `base_ref` can never carry a `Debug`-escapable character and the two
    // scrub positions are indistinguishable for every input this test can
    // construct. Pre-format specificity is pinned by
    // `a_backslash_bearing_secret_is_scrubbed_before_debug_formatting_can_escape_it`,
    // which reaches the escapable characters through the placeholder
    // channel, and which does fail under that same mutant.
    assert!(
        error.contains("***"),
        "the needle backstop must have replaced the pasted secret with `***`, got: {error:?}"
    );
    assert!(
        error.contains("withheld"),
        "part 3: a declared secret in base_ref must route the provider's own text through \
         safe_summary() too, got: {error:?}"
    );

    let serialized = serde_json::to_string(&outcomes[0].output).unwrap();
    assert!(
        !serialized.contains(SECRET_VALUE),
        "a declared secret's raw value must not survive anywhere in the map step's \
         serialized output just because it arrived through a channel provenance treats as \
         clean, got: {serialized}"
    );
}

/// Final round part 2, item 1 — the **`Debug`-escaping** hole in the
/// backstop item A1 restored, found by the security lens and reproduced end
/// to end.
///
/// A1's fix assembled the message first (embedding the value as
/// `{redacted_base_ref:?}`) and scrubbed the whole thing afterwards.
/// `Debug for str` escapes `"`, `\` and control characters, so a declared
/// secret containing any of them stops matching the plain-substring needle
/// **in that one copy** while the raw copies — the echoed argv and `git`'s
/// stderr — scrub correctly. Two of three occurrences became `***` and the
/// escaped one survived into the append-only `events` table in trivially
/// reversible form.
///
/// **The channel matters, and it is not the one the previous test drives.**
/// A literal paste cannot carry a backslash: `\` is in
/// `FORBIDDEN_GIT_REF_CHARS`, so `parse/steps.rs::validate_git_ref` rejects
/// it at parse time. The reachable channel is a **placeholder over public
/// data** — `base_ref: "${{ item }}"` over a public input list whose
/// element happens to equal a declared secret's raw value. The template
/// text passes validation, the resolved value is never re-validated, and
/// provenance marks nothing because the value came from `inputs`.
///
/// **Asserting on the escaped form is the whole point.** The A1 test
/// asserts `!serialized.contains(SECRET_VALUE)`, which an escaped copy
/// satisfies by construction — that is exactly how it shipped green over
/// this defect. This asserts on `\\` (the escape `Debug` emits for one
/// backslash) and on a distinctive substring that survives escaping.
#[test]
fn a_backslash_bearing_secret_is_scrubbed_before_debug_formatting_can_escape_it() {
    if !git_available() {
        eprintln!("skipping: git not available on this host");
        return;
    }
    // One backslash, so `Debug` renders it as `\\` — the cheap tell below.
    const SECRET_VALUE: &str = "not-a-real-ref-top\\secret123";
    let repo = TempRepo::new();
    let provider = Arc::new(ObservingWorktreeProvider::new(repo.path.clone()));

    let yaml = format!(
        "{WORKFLOW_PREAMBLE}secrets: [T]\nsteps:\n\
         \x20\x20- id: per_item\n\
         \x20\x20\x20\x20map:\n\
         \x20\x20\x20\x20\x20\x20over: \"${{{{ inputs.items }}}}\"\n\
         \x20\x20\x20\x20\x20\x20as: item\n\
         \x20\x20\x20\x20\x20\x20max_parallel: 1\n\
         \x20\x20\x20\x20\x20\x20on_item_error: continue\n\
         \x20\x20\x20\x20\x20\x20isolation: {{ worktree: {{ base_ref: \"${{{{ item }}}}\" }} }}\n\
         \x20\x20\x20\x20steps:\n\
         \x20\x20\x20\x20\x20\x20- id: emit_something\n\
         \x20\x20\x20\x20\x20\x20\x20\x20emit: {{ ok: true }}\n"
    );
    let def = parse_workflow(&yaml).expect("workflow must parse");
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(
        // The value arrives through a **public** input, so nothing about
        // this `base_ref` is secret-derived and the withhold branch never
        // runs — the needle backstop is the only guard in play.
        serde_json::json!({"items": [SECRET_VALUE]}),
        "T",
        SECRET_VALUE,
        Some(provider.clone() as Arc<dyn WorktreeProvider>),
    );
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().expect("run must not error");

    let items = outcomes[0].output["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0]["status"], "failed",
        "expected git to reject this base_ref as invalid — got {:?}",
        items[0]
    );
    let error = items[0]["error"].as_str().unwrap();
    // As in the A1 test above, this input trips the withhold too since part
    // 3, so `***` here pins only that *a* needle scrub ran. What makes this
    // test — and not that one — the pin for the **pre-format** scrub is the
    // `\\` assertion below: measured with a mutant, removing the pre-format
    // scrub fails this test and leaves the A1 test passing.
    assert!(
        error.contains("***"),
        "the pre-format needle scrub must have replaced the echoed base_ref, got: {error:?}"
    );

    // The escaped form is what the raw-contains assertion in the A1 test is
    // structurally blind to. Nothing else in this message contains a
    // backslash, so this is an unambiguous tell.
    assert!(
        !error.contains(r"\\"),
        "a `Debug`-escaped copy of the secret survived the needle scrub — the message must \
         be scrubbed BEFORE `{{:?}}` gets to escape it, got: {error:?}"
    );

    // Escape-agnostic: this substring survives any escaping of the
    // backslash, so it catches a future escaping scheme this test did not
    // anticipate as well as `Debug`'s.
    let serialized = serde_json::to_string(&outcomes[0].output).unwrap();
    assert!(
        !serialized.contains("secret123"),
        "no rendering of the secret — escaped or raw — may survive anywhere in the map \
         step's serialized output, got: {serialized}"
    );
}

/// Final round part 2, M2: A1's "verified by removal" evidence covered the
/// **materialize** site only, while the fix (and its doc comment) claims
/// both. This drives the other one.
///
/// A release failure whose message embeds a declared secret's raw value —
/// built via `WorktreeProviderError::new`, i.e. by an implementor who
/// ignored the obligation the trait doc states — must still be scrubbed on
/// its way into the item's outcome. No `git` involved: `materialize`
/// returns a fake path, so this exercises the release arm and nothing else.
///
/// This is not a hypothetical shape. `WorktreeProvider` is `pub` and meant
/// for downstream implementation, `new` reads like the default constructor,
/// and the needle backstop is what stands behind an implementor who got it
/// wrong.
#[test]
fn a_declared_secret_inside_a_release_failure_is_scrubbed_too() {
    const SECRET_VALUE: &str = "release-path-topsecret456";
    let yaml = format!(
        "{WORKFLOW_PREAMBLE}secrets: [T]\nsteps:\n\
         \x20\x20- id: per_item\n\
         \x20\x20\x20\x20map:\n\
         \x20\x20\x20\x20\x20\x20over: \"${{{{ inputs.items }}}}\"\n\
         \x20\x20\x20\x20\x20\x20as: item\n\
         \x20\x20\x20\x20\x20\x20max_parallel: 1\n\
         \x20\x20\x20\x20\x20\x20on_item_error: continue\n\
         \x20\x20\x20\x20\x20\x20isolation: worktree\n\
         \x20\x20\x20\x20steps:\n\
         \x20\x20\x20\x20\x20\x20- id: emit_something\n\
         \x20\x20\x20\x20\x20\x20\x20\x20emit: {{ ok: true }}\n"
    );
    let def = parse_workflow(&yaml).expect("workflow must parse");
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(
        serde_json::json!({"items": [1]}),
        "T",
        SECRET_VALUE,
        Some(Arc::new(LeakyReleaseProvider(SECRET_VALUE.to_string())) as Arc<dyn WorktreeProvider>),
    );
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().expect("run must not error");

    let items = outcomes[0].output["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0]["status"], "failed",
        "a release failure must surface as the item's own failure — got {:?}",
        items[0]
    );
    let error = items[0]["error"].as_str().unwrap();
    // Sanity: this really is the release arm, not the materialize one.
    assert!(
        error.contains("releasing"),
        "expected the release-failure message, got: {error:?}"
    );
    assert!(
        error.contains("***"),
        "the needle backstop must have replaced the secret on the release path too, \
         got: {error:?}"
    );

    let serialized = serde_json::to_string(&outcomes[0].output).unwrap();
    assert!(
        !serialized.contains(SECRET_VALUE),
        "a declared secret's raw value must not survive a release failure into the map \
         step's serialized output, got: {serialized}"
    );
}

/// The other half of M1: the release arm must read `safe_summary()` when the
/// item's `base_ref` was secret-derived, exactly as the materialize arm
/// does. Before this round it formatted `Display` (i.e. `full`)
/// unconditionally, so `WorktreeProvider`'s doc promised implementors a
/// guarantee the only shipped caller applied on one of its two paths.
///
/// The needle backstop cannot stand in for the withhold here, and that is
/// the point: the declared secret is the JSON list `["..."]`, while what
/// reaches `base_ref` is the *element*. `redaction_needles` holds only raw
/// `RunContext.secrets` values, never anything computed from them, so the
/// element is invisible to it — only provenance knows, and only the withhold
/// acts on what provenance knows.
#[test]
fn a_secret_derived_items_release_failure_is_withheld_not_rendered_in_full() {
    const DERIVED_ELEMENT: &str = "derived-release-leak-marker789";
    let yaml = format!(
        "{WORKFLOW_PREAMBLE}secrets: [T]\nsteps:\n\
         \x20\x20- id: per_item\n\
         \x20\x20\x20\x20map:\n\
         \x20\x20\x20\x20\x20\x20over: \"${{{{ json(secrets.T) }}}}\"\n\
         \x20\x20\x20\x20\x20\x20as: item\n\
         \x20\x20\x20\x20\x20\x20max_parallel: 1\n\
         \x20\x20\x20\x20\x20\x20on_item_error: continue\n\
         \x20\x20\x20\x20\x20\x20isolation: {{ worktree: {{ base_ref: \"${{{{ item }}}}\" }} }}\n\
         \x20\x20\x20\x20steps:\n\
         \x20\x20\x20\x20\x20\x20- id: emit_something\n\
         \x20\x20\x20\x20\x20\x20\x20\x20emit: {{ ok: true }}\n"
    );
    let def = parse_workflow(&yaml).expect("workflow must parse");
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(
        serde_json::json!({}),
        "T",
        &format!("[{DERIVED_ELEMENT:?}]"),
        Some(
            Arc::new(WithheldReleaseProvider(DERIVED_ELEMENT.to_string()))
                as Arc<dyn WorktreeProvider>,
        ),
    );
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().expect("run must not error");

    let items = outcomes[0].output["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0]["status"], "failed",
        "a release failure must surface as the item's own failure — got {:?}",
        items[0]
    );
    let error = items[0]["error"].as_str().unwrap();
    assert!(
        error.contains("releasing") && error.contains("withheld"),
        "the release arm must render the provider's safe summary for a secret-derived \
         base_ref, got: {error:?}"
    );

    let serialized = serde_json::to_string(&outcomes[0].output).unwrap();
    assert!(
        !serialized.contains(DERIVED_ELEMENT),
        "the secret-derived element must not reach the serialized outcome through a \
         release failure, got: {serialized}"
    );
}

/// Final round part 3 (ruling W5-48) — the needle backstop alone cannot
/// survive `git`'s **lossy** stderr echoes, so a declared secret's presence
/// in `base_ref` now triggers the withhold regardless of provenance.
///
/// This is the same pair of transforms ruling W5-36 already solved for the
/// secret-*derived* branch, which the scrub-only branch silently inherited:
///
/// - `@{upstream}`-style syntax makes `git` die mid-interpretation and echo
///   only the **prefix** before it, so a needle keyed on the whole value
///   never matches — measured, 27 of a 38-byte secret survived cleartext;
/// - a value past `git`'s own `vreportf` stderr buffer (~4KB — **`git`'s
///   buffer, not this crate's `OUTPUT_CAP`**; a 3024-byte value scrubs
///   fully, a 5029-byte one does not) comes back as a shorter, still
///   sensitive prefix.
///
/// No scrub of a lossy transform can be made reliable; that was W5-36's
/// whole finding. The fix makes a declared secret's *presence* sufficient
/// to withhold, which does not depend on anything `git` does to the value.
///
/// Drives the `@{upstream}` case, the cheap one, through the channel that
/// makes it reachable: a public input list whose element equals a declared
/// secret, so provenance marks nothing.
///
/// **Asserts the produced form AND the absence of the transformed one.**
/// `***`-present is necessary but not sufficient here: the pre-fix failing
/// message contained `***` twice *and* the leaked prefix, because the two
/// raw copies scrubbed while the lossy echo did not.
#[test]
fn a_declared_secret_in_base_ref_is_withheld_even_when_git_echoes_only_a_prefix() {
    if !git_available() {
        eprintln!("skipping: git not available on this host");
        return;
    }
    // `@{` makes git die mid-interpretation and echo only what precedes it.
    const SECRET_VALUE: &str = "not-a-real-ref-topsecret123@{upstream}";
    const LEAKED_PREFIX: &str = "not-a-real-ref-topsecret123";
    let repo = TempRepo::new();
    let provider = Arc::new(ObservingWorktreeProvider::new(repo.path.clone()));

    let yaml = format!(
        "{WORKFLOW_PREAMBLE}secrets: [T]\nsteps:\n\
         \x20\x20- id: per_item\n\
         \x20\x20\x20\x20map:\n\
         \x20\x20\x20\x20\x20\x20over: \"${{{{ inputs.items }}}}\"\n\
         \x20\x20\x20\x20\x20\x20as: item\n\
         \x20\x20\x20\x20\x20\x20max_parallel: 1\n\
         \x20\x20\x20\x20\x20\x20on_item_error: continue\n\
         \x20\x20\x20\x20\x20\x20isolation: {{ worktree: {{ base_ref: \"${{{{ item }}}}\" }} }}\n\
         \x20\x20\x20\x20steps:\n\
         \x20\x20\x20\x20\x20\x20- id: emit_something\n\
         \x20\x20\x20\x20\x20\x20\x20\x20emit: {{ ok: true }}\n"
    );
    let def = parse_workflow(&yaml).expect("workflow must parse");
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(
        // Public input: provenance marks nothing, so only the declared
        // secret's *presence* can trigger the withhold.
        serde_json::json!({"items": [SECRET_VALUE]}),
        "T",
        SECRET_VALUE,
        Some(provider.clone() as Arc<dyn WorktreeProvider>),
    );
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().expect("run must not error");

    let items = outcomes[0].output["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0]["status"], "failed",
        "expected git to reject this base_ref as invalid — got {:?}",
        items[0]
    );
    let error = items[0]["error"].as_str().unwrap();

    // The produced form: a declared secret in `base_ref` must route to
    // `safe_summary()`, the same way a secret-derived one does.
    assert!(
        error.contains("withheld"),
        "a declared secret's presence in base_ref must trigger the withhold, not merely a \
         scrub — got: {error:?}"
    );
    // The transformed form: this is the assertion `***`-present cannot make
    // for us, and the one that fails without the fix.
    assert!(
        !error.contains(LEAKED_PREFIX),
        "git's truncated echo of a declared secret must not survive into the item's error \
         message, got: {error:?}"
    );

    let serialized = serde_json::to_string(&outcomes[0].output).unwrap();
    assert!(
        !serialized.contains(LEAKED_PREFIX),
        "git's truncated echo must not appear anywhere in the serialized output, got: \
         {serialized}"
    );
}
