//! Phase 8 Task 25.7 Task 9: §8.9's reference workflow
//! (`roundhouse-flow`'s `tests/fixtures/pr_review.yaml`) driven through the
//! real daemon, for the first time.
//!
//! Every earlier task parsed that fixture — `roundhouse-flow`'s
//! `parse_top_level.rs`/`parse_steps.rs`/`bounded_parse_out_of_process.rs`
//! all `include_str!` it — but none ever handed it to
//! [`DeliveryExecutor::drive_run_to_completion`] and watched what a real
//! session, a real policy engine, a real isolate and a real provider make
//! of it. These tests do, and they come in two halves that prove different
//! things:
//!
//! 1. [`the_frozen_reference_workflow_runs_and_stops_at_its_first_unwired_tool`]
//!    and
//!    [`the_frozen_reference_workflows_map_refuses_every_worktree_isolated_item`]
//!    pin what the **frozen fixture itself** does today — unmodified, and
//!    modified in exactly one named place, respectively. Both are
//!    characterization tests: their assertions are a record of real
//!    behaviour, not of intended behaviour.
//! 2. [`a_map_dispatches_nested_agent_shell_and_gate_steps_for_real_concurrently_and_resumably`]
//!    proves the integration those cannot: a `map` fanning out to several
//!    items that each nest a real `agent:` step, a real `tool: shell` step,
//!    a real `gate:` park/resume, and a real follow-up `tool:` step —
//!    concurrently, and across two full park/resume cycles.
//! 3. [`a_map_inner_step_reads_a_siblings_real_output`] and
//!    [`a_failed_map_inner_step_declaring_continue_on_error_does_not_stop_its_item`]
//!    assert *intended* behaviour, which is what makes them the odd ones
//!    out here. Both started life in group 1, pinning a gap this drive
//!    found in the two mechanisms §8.9's own `map` body is built on; Phase
//!    8 Task 25.7 Task 10 closed both gaps and flipped both assertions.
//!
//! # What driving the frozen fixture turned up
//!
//! Five places where §8.9's reference workflow and this workspace's
//! implementation disagree, listed together here because no single test
//! sees all of them and because the list, not any one test, is this task's
//! finding. The first two are asserted by the unmodified-fixture test, the
//! fourth and fifth by their own tests above; the third is unreachable and
//! recorded only.
//!
//! 1. **`tool: http` is not dispatchable.**
//!    `roundhouse_engine::workflow_dispatch::dispatch_tool_for_workflow`
//!    allowlists Read/Write/Edit/Find/Shell; `list_prs` — the reference
//!    workflow's first step — is `tool: http`, so the run stops there.
//! 2. **The `finally:` `report:` step is invalid**, declaring two of §8.6's
//!    five core fields with ellipsis placeholders for values.
//! 3. **`tool: shell` takes `{ program, argv, cwd }`**, not §8.9's
//!    `cmd: [...]`, so both of the fixture's shell steps would be rejected
//!    before admission.
//! 4. **A `map` inner step could not read a sibling's output.** §8.9's map
//!    gates on `${{ len(steps.review.output.findings) > 0 }}` and then on
//!    `${{ steps.gate.output.approve }}`; both evaluated to `null`.
//!    **Closed by Phase 8 Task 25.7 Task 10** — `Loop::advance_map_item`
//!    now binds an item-scoped `steps` object around each item's walk (see
//!    `run_loop`'s `ItemStepsContext`), so an item's later inner step reads
//!    its own earlier ones and nothing else reads either. One reference in
//!    the fixture's `map` body is still `null` and is a different gap:
//!    `post`'s `--body-file ${{ steps.review.artifact }}`, because
//!    `exec::steps_context_entry` records `output`/`status`/`error` for
//!    every step in the run and no `artifact` field for any of them.
//! 5. **`continue_on_error:` was ignored on a `map` inner step**, so §8.9's
//!    `tests` step failed its whole item rather than letting it continue.
//!    **Closed by the same task** — see
//!    `map_step::fold_inner_step_outcome`, the one place both fan-out loops
//!    decide whether an inner step's failure ends its item.
//!
//! Both of those are why the tests that pinned them now assert the
//! opposite; see group 3 above.
//!
//! Separately, and *not* a divergence but the accepted limitation that
//! `run_loop`'s `worktree_cannot_span_a_suspend` documents in full: the
//! fixture's `isolation: worktree` makes every item fail at its first
//! dispatching inner step. That is deliberate and permanent, and the second
//! test above pins it.
//!
//! # Why these live in the library's own test binary rather than `tests/`
//!
//! [`DeliveryExecutor::drive_run_to_completion`] is the only entry point
//! that drives a run through *every* `AwaitingWork` suspension for real
//! while letting the caller supply both the [`RunContext`] (inputs, vars,
//! secrets, worktree provider) and the [`Resume`] that releases a park —
//! and [`DeliveryExecutor`] is `pub(crate)`, so an external `tests/*.rs`
//! binary cannot construct one at all, let alone call that method. Its only
//! route to a driven workflow run is this module's own `run` background
//! service, which builds a fixed `RunContext` with null inputs and has no
//! way to answer a gate — so it could drive neither the fixture's
//! `inputs.repo`/`vars.review_model` nor either half of a park/resume
//! cycle. `tests/common/mod.rs`'s `resources_with_provider_and_rules` is
//! the right shape for a *socket-level* test and the wrong one here for
//! that reason; this module uses `crate::test_support`'s in-crate
//! equivalents instead, the same choice `delivery_tests` made.
//!
//! # Only the model is scripted
//!
//! The provider is the one faked mechanism, exactly as in
//! `delivery_tests`' own `agent:` tests: the store, the session actor, the
//! policy engine, the isolate (a real `bwrap` wherever a step really
//! spawns), the run loop, the `map` fan-out, the gate park and the durable
//! rows are all production code.

use super::*;
use crate::session_registry::SessionRegistry;
use crate::workspace_registry::{WorkspaceRegistration, WorkspaceRegistry};
use roundhouse_core::Tier;
use roundhouse_flow::durability::{
    insert_workflow_run, recover_run, StepRunState, WorkflowStepRun,
};
use roundhouse_flow::exec::run_loop::{GateAnswer, ReportOrigin};
use roundhouse_flow::exec::{StepOutcome, StepStatus};
use roundhouse_flow::job::SessionTemplate;
use roundhouse_flow::job_store::register_workflow_file;
use roundhouse_policy::engine::{CompiledRule, Outcome as PolicyOutcome, Predicate, Scope};
use roundhouse_policy::FsOp;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// §8.9's reference workflow, byte for byte. `include_str!` rather than a
/// copy pasted into this file: a copy would drift the first time the frozen
/// document is edited, and these tests are worth nothing if they are not
/// running the real thing. The relative path is resolved at compile time,
/// so moving the fixture breaks the build rather than silently testing
/// something else.
const PR_REVIEW_YAML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../roundhouse-flow/tests/fixtures/pr_review.yaml"
));

/// A deadlock guard, not a timing assertion: every `await` in these tests
/// is on real work that either completes promptly or is hung, and a hung
/// `cargo test` reports nothing useful. Nothing here asserts against
/// elapsed time — the same idiom `delivery_tests`' own shell tests use for
/// the same reason.
const NEVER_HANGS: Duration = Duration::from_secs(120);

/// The one instant these tests reckon against — a constant, for the reason
/// `delivery_tests`' own `instant` gives.
fn instant() -> DateTime<Utc> {
    DateTime::from_timestamp_nanos(1_700_000_000_000_000_000)
}

fn template() -> SessionTemplate {
    SessionTemplate {
        provider: "test".into(),
        model: "test-model".into(),
        cwd: "/tmp".into(),
        tools: vec![],
        isolation: Tier::Sandbox,
        permission_policy_ref: "default".into(),
    }
}

/// Which isolate a fixture wires — the axis that decides whether a
/// `tool: shell` step can actually spawn. See
/// `crate::test_support::available_isolate`'s own doc comment for why the
/// cheap one cannot.
enum Spawning {
    /// The always-`Tier::Sandbox` probe isolate, which cannot exec anything
    /// in a dev checkout. Enough for a run whose steps never reach a real
    /// process.
    No,
    /// The real `bwrap` on `$PATH`.
    Yes,
}

/// Everything one driven run needs: a registered job, its `workflow_run`
/// row, a live headless session, and the executor that drives them.
struct Fixture {
    _dir: tempfile::TempDir,
    executor: DeliveryExecutor,
    session: HeadlessSession,
    session_id: SessionId,
    spec: SessionSpec,
    workspace_root: PathBuf,
    run_id: RunId,
}

impl Fixture {
    /// One drive of this run, with [`NEVER_HANGS`] applied, already
    /// unwrapped past that guard and the two failure kinds no test here
    /// expects.
    async fn drive(&self, run_ctx: &RunContext, resume: Option<Resume>) -> DrivenRun {
        tokio::time::timeout(
            NEVER_HANGS,
            self.executor.drive_run_to_completion(
                self.run_id,
                self.session_id,
                &self.session,
                self.spec.clone(),
                self.workspace_root.clone(),
                run_ctx.clone(),
                self.executor.now(),
                resume,
            ),
        )
        .await
        .expect("the run must not hang")
        .expect("drive_run_to_completion's own DeliveryError path must not be reached")
        .expect("run_workflow must not return a RunLoopError for these fixtures")
    }

    /// The durable `workflow_run` row's state — what a restart would read
    /// back, rather than the value the drive happened to return.
    async fn run_row_state(&self) -> RunState {
        let conn = self.executor.store.pool.get().await.unwrap();
        let run_id = self.run_id;
        conn.interact(move |connection| recover_run(connection, run_id).unwrap().run.state)
            .await
            .unwrap()
    }

    /// Every per-item `workflow_step_run` row for one inner step id, keyed
    /// by item index.
    ///
    /// These rows are the only place a `map` item's inner-step outcome is
    /// observable **from outside the item**: the `map` step's own output
    /// carries one aggregate entry per item rather than a per-inner-step
    /// breakdown, and the item-scoped `${{ steps.* }}` binding Phase 8 Task
    /// 25.7 Task 10 added is deliberately scoped to the item's own walk (see
    /// `run_loop`'s `ItemStepsContext`), so a test — or a top-level step —
    /// standing outside that walk cannot read one. So a test that wants to
    /// know how one item's `gate:` was answered, or whether one item's
    /// `tool: shell` step really ran, has to read the rows.
    ///
    /// Keyed by item index alone, which the durable key is **not**: that is
    /// `(step_id, attempt, item_index)`, so a step that ran twice has two
    /// rows for one item. Every fixture in this module runs each step once,
    /// so one row per item holds here — but that is a property of these
    /// fixtures, not of the table, and it is reachable to break: the frozen
    /// `pr_review.yaml` itself declares `defaults: retry: { attempts: 3, …
    /// }`, so the first test that combines this helper with a retrying
    /// document would otherwise lose a row and assert against whichever of
    /// the two `collect` happened to keep. Hence the collision check below
    /// rather than a `collect()` — a plain `assert!`, not a
    /// `debug_assert!`, so it holds in a release-profile test run too.
    async fn item_step_rows(&self, step_id: &str) -> HashMap<u32, WorkflowStepRun> {
        let conn = self.executor.store.pool.get().await.unwrap();
        let run_id = self.run_id;
        let step_id = step_id.to_string();
        conn.interact(move |connection| {
            let mut rows: HashMap<u32, WorkflowStepRun> = HashMap::new();
            for row in recover_run(connection, run_id).unwrap().steps {
                if row.step_id != step_id {
                    continue;
                }
                let Some(item_index) = row.item_index else {
                    continue;
                };
                let attempt = row.attempt;
                assert!(
                    rows.insert(item_index, row).is_none(),
                    "step `{step_id}` has more than one row for item {item_index} (this one is \
                     attempt {attempt}) — this helper keys on the item alone and would silently \
                     drop one, so a retrying fixture needs `attempt` in the key"
                );
            }
            rows
        })
        .await
        .unwrap()
    }
}

/// One row's recorded output. `value_unredacted_for_resume` rather than
/// `value_for_display` because these fixtures carry no secrets at all and
/// the display form withholds a secret-derived value entirely — a test that
/// used it would silently assert against `None` the day someone made one of
/// these fixtures secret-derived.
fn row_output(row: &WorkflowStepRun) -> serde_json::Value {
    row.output.as_ref().map_or(serde_json::Value::Null, |o| {
        o.value_unredacted_for_resume().clone()
    })
}

/// Builds a fixture around whatever `prepare` writes.
///
/// `prepare` takes the **canonical** workspace root and returns the
/// workflow document and the policy rules that admit its steps. It is a
/// callback rather than two plain parameters because both of those depend
/// on that root — a `tool: shell` step names an absolute program path, a
/// `tool: write` step names an absolute target, and the matching
/// `CompiledRule`s name the same paths — and the root is not known until
/// the registry has canonicalized it. `prepare` may also create files
/// under that root (the shell script a `tool: shell` step execs).
async fn fixture(
    prepare: impl FnOnce(&Path) -> (String, Vec<CompiledRule>),
    provider: Arc<dyn roundhouse_provider::Provider>,
    spawning: Spawning,
) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let workspace_root = dir.path().join("workspace");
    std::fs::create_dir(&workspace_root).unwrap();

    let store = roundhouse_store::open(&dir.path().join("events.db"))
        .await
        .unwrap();
    let workspaces = Arc::new(
        WorkspaceRegistry::open(
            roundhouse_store::open(&dir.path().join("events.db"))
                .await
                .unwrap(),
        )
        .await
        .unwrap(),
    );
    let workspace = workspaces
        .register(WorkspaceRegistration::new("pr-review", workspace_root))
        .await
        .unwrap();
    // The canonical root the registry resolved, not the raw tempdir path —
    // `register_workflow_file` canonicalizes both sides and would otherwise
    // reject the source as outside the workspace on a platform whose temp
    // directory is a symlink. Same reason `delivery_tests`' own harness
    // does it.
    let workspace_root = workspace.root.clone();
    let (workflow_yaml, rules) = prepare(&workspace_root);
    let source = workspace_root.join("workflow.yaml");
    std::fs::write(&source, &workflow_yaml).unwrap();

    let policy_rules: crate::session_bootstrap::PolicyRuleSource = Arc::new(move || rules.clone());
    let resources = Arc::new(match spawning {
        Spawning::No => {
            crate::test_support::daemon_resources_with_rules_and_provider(
                dir.path(),
                Some(Arc::clone(&workspaces)),
                policy_rules,
                provider,
            )
            .await
        }
        Spawning::Yes => {
            crate::test_support::daemon_resources_with_rules_and_provider_and_real_bwrap(
                dir.path(),
                Some(Arc::clone(&workspaces)),
                policy_rules,
                provider,
            )
            .await
        }
    });
    let sessions = Arc::new(SessionRegistry::new());
    let executor = DeliveryExecutor::new(
        store.clone(),
        Arc::clone(&resources),
        Arc::clone(&sessions),
        Arc::new(InMemoryRunRegistry::new()),
        Arc::clone(&resources.spawn_tree),
        Arc::new(FixedClock(instant())),
    );

    let session_id = SessionId::new();
    let spec = SessionSpec {
        workspace: workspace.id,
        name: None,
        requested_tier: Tier::Sandbox,
        on_degrade: resources.default_on_degrade,
        parent: None,
    };
    let session = create_headless_session(
        &resources,
        &sessions,
        session_id,
        spec.clone(),
        workspace_root.clone(),
        workspace.root_device,
        workspace.root_inode,
    )
    .await
    .expect("headless session construction must succeed against a working fixture");

    let job_id = {
        let conn = store.pool.get().await.unwrap();
        let root = workspace_root.clone();
        let source = source.clone();
        conn.interact(move |connection| {
            register_workflow_file(connection, &root, &source, template())
                .unwrap()
                .job
                .id()
        })
        .await
        .unwrap()
    };

    let run_id = RunId::new();
    // The executor's own `FixedClock` reading, for the reason
    // `delivery_tests`' mid-shell-cancel test records: `finally:`'s
    // wall-timeout admission check compares against `started_at`, so a run
    // "started" at epoch 0 has its cleanup refused before it runs.
    let now = executor.now();
    {
        let conn = store.pool.get().await.unwrap();
        let root = workspace_root.clone();
        conn.interact(move |connection| {
            let resolved = resolve_latest_by_job_id(connection, &root, job_id)
                .unwrap()
                .expect("the job just registered above must resolve");
            let version = resolved.job.latest();
            insert_workflow_run(
                connection,
                &WorkflowRun {
                    id: run_id,
                    job_id,
                    job_version: version.version(),
                    content_hash: content_hash(version),
                    session_id,
                    binding_id: None,
                    trigger_event_id: None,
                    state: RunState::Running,
                    parent_run_id: None,
                    forked_from_run_id: None,
                    awaiting_until: None,
                    checkpoint_ref: None,
                    checkpoint_blob_ref: None,
                    started_at: now,
                    ended_at: None,
                    session_depth: Some(0),
                    caps: Some(ResourceCaps::default()),
                },
            )
            .unwrap();
        })
        .await
        .unwrap();
    }

    Fixture {
        _dir: dir,
        executor,
        session,
        session_id,
        spec,
        workspace_root,
        run_id,
    }
}

/// The `RunContext` §8.9's own `inputs:`/`vars.review_model`/`secrets:`
/// declarations ask for, so that neither characterization test below is
/// measuring a missing input rather than the behaviour it is about.
fn pr_review_run_context(f: &Fixture) -> RunContext {
    RunContext {
        inputs: serde_json::json!({ "repo": "octocat/hello-world" }),
        inputs_secret_derived: false,
        vars: serde_json::json!({ "review_model": "test-model" }),
        secrets: HashMap::from([("GH_TOKEN".to_string(), "not-a-real-token".to_string())]),
        run_id: f.run_id,
        previous_report: None,
        env_allowlist: EnvAllowlist::deny_all(),
        // What production supplies — `run_claimed_delivery` and
        // `rebuild_and_drive_recovered_run` both construct exactly this —
        // so an `isolation: worktree` map is measured against the real
        // provider rather than against the missing-provider refusal.
        worktree_provider: Some(Arc::new(SandboxWorktreeProvider::new(
            f.workspace_root.clone(),
        ))),
    }
}

fn terminal(driven: DrivenRun) -> (RunState, ReportOrigin, Vec<StepOutcome>) {
    match driven {
        DrivenRun::Outcome(RunOutcome::Terminal {
            state,
            report,
            steps,
        }) => (state, report, steps),
        other => panic!("expected a terminal outcome, got {other:?}"),
    }
}

fn step<'a>(steps: &'a [StepOutcome], id: &str) -> &'a StepOutcome {
    steps
        .iter()
        .find(|s| s.step_id == id)
        .unwrap_or_else(|| panic!("no outcome for step `{id}`; got {:?}", ids(steps)))
}

fn ids(steps: &[StepOutcome]) -> Vec<&str> {
    steps.iter().map(|s| s.step_id.as_str()).collect()
}

fn failure_message(outcome: &StepOutcome) -> &str {
    match &outcome.status {
        StepStatus::Failed { message } => message,
        other => panic!("step `{}` did not fail: {other:?}", outcome.step_id),
    }
}

/// Every item entry of a completed `map` step's output, in item order.
fn map_items(outcome: &StepOutcome) -> Vec<serde_json::Value> {
    outcome.output["items"]
        .as_array()
        .unwrap_or_else(|| panic!("§8.9 gives every item an entry: {}", outcome.output))
        .clone()
}

/// Fails the test — loudly and immediately — when an external binary these
/// tests genuinely need is not on `PATH`.
///
/// **Deliberately not a skip** (fix round 1, ruling: fail, don't skip).
/// `roundhouse-flow`'s `map_step_worktree.rs` prints a message and returns
/// early when `git` is missing; this crate's own `delivery_tests` does the
/// opposite, depending on a real `bwrap` unconditionally
/// (`executor_and_session_with_real_bwrap` and its callers have no guard at
/// all), so the daemon suite already fails outright on a runner without it.
/// A skip here would buy nothing against that existing dependency and would
/// cost something real: the one test that actually discharges #44/#64's
/// acceptance criteria
/// ([`a_map_dispatches_nested_agent_shell_and_gate_steps_for_real_concurrently_and_resumably`])
/// would report green having asserted nothing, and nobody reads
/// `eprintln!` from a passing test. A missing tool is a broken environment,
/// and a broken environment should look broken.
fn require_on_path(program: &str, why: &str) {
    let found = std::process::Command::new(program)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    assert!(
        found,
        "this test requires `{program}` on PATH ({why}). These tests fail rather than skip on a \
         missing tool, because a skip would report green having asserted nothing — this crate's \
         `delivery_tests` already depends on a real `bwrap` the same way, through \
         `executor_and_session_with_real_bwrap`"
    );
}

fn git(repo: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .unwrap_or_else(|e| panic!("spawning `git {args:?}`: {e}"));
    assert!(
        output.status.success(),
        "`git {args:?}` failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// A repository with one commit, plus a `refs/pull/<n>/head` for each
/// `pulls` entry — the refs §8.9's own
/// `base_ref: "refs/pull/${{ pr.number }}/head"` names. Without them the
/// per-item worktree could not materialize at all, and the test would be
/// measuring a `git` failure instead of the refusal it is about.
fn git_repo_with_pull_refs(root: &Path, pulls: &[u32]) {
    git(root, &["init", "-q"]);
    git(root, &["config", "user.email", "test@example.com"]);
    git(root, &["config", "user.name", "test"]);
    std::fs::write(root.join("seed.txt"), "seed\n").unwrap();
    git(root, &["add", "seed.txt"]);
    git(root, &["commit", "-q", "-m", "init"]);
    let head = git(root, &["rev-parse", "HEAD"]);
    for n in pulls {
        git(root, &["update-ref", &format!("refs/pull/{n}/head"), &head]);
    }
}

// ───────────────────────── 1. the frozen fixture ─────────────────────────

/// **§8.9's reference workflow, unmodified, driven end to end.** What it
/// actually does today: `list_prs` — its very first step — fails, because
/// `tool: http` is not one of the five kinds
/// `roundhouse_engine::workflow_dispatch::dispatch_tool_for_workflow`
/// dispatches. The `map` is therefore never reached; `catch:` runs, because
/// a main-phase step failed; `finally:` runs; and the run ends `Failed`.
///
/// # Two places §8.9's example and this workspace disagree, pinned here
///
/// Both are recorded rather than repaired: this test's job is to say what
/// the frozen document does today, and neither divergence is this task's to
/// decide.
///
/// - **`tool: http` is unwired.** `dispatch_tool_for_workflow`'s allowlist
///   is Read/Write/Edit/Find/Shell; `Http` (like `Git` and `Mcp`) is
///   refused as `unsupported_workflow_tool`. So the reference workflow
///   cannot run its own first step.
/// - **The fixture's `report:` step is invalid against §8.6's core
///   schema.** `finally: [{ id: report, report: { outcome: "…", headline:
///   "…" } }]` declares two of the five fields `roundhouse_flow::report`
///   requires (`outcome`, `severity`, `headline`, `needs_human`, `cost`),
///   and its values are literal ellipsis placeholders rather than an
///   `Outcome`. The step fails validation, so the run's report is
///   *synthesised* rather than authored.
///
/// Three further divergences are not reachable from here (nothing in this
/// run gets as far as the `map`, let alone a shell step); this module's own
/// doc comment lists all five together, and two of them have tests of their
/// own further down.
#[tokio::test]
async fn the_frozen_reference_workflow_runs_and_stops_at_its_first_unwired_tool() {
    let f = fixture(
        |_root| (PR_REVIEW_YAML.to_string(), vec![]),
        Arc::new(crate::test_support::NoopProvider),
        Spawning::No,
    )
    .await;
    let run_ctx = pr_review_run_context(&f);

    let (state, report, steps) = terminal(f.drive(&run_ctx, None).await);

    assert!(
        failure_message(step(&steps, "list_prs")).contains("`Http` is not wired yet"),
        "the reference workflow's first step is a `tool: http` call, and this daemon dispatches \
         five tool kinds, none of them Http — got {:?}",
        step(&steps, "list_prs").status
    );
    assert!(
        !ids(&steps).contains(&"per_pr"),
        "a failed `list_prs` (it declares no `continue_on_error:`) stops the main phase, so the \
         `map` this fixture is famous for is never reached at all: {:?}",
        ids(&steps)
    );
    assert!(
        matches!(step(&steps, "on_failure").status, StepStatus::Completed),
        "a failed main phase must run `catch:` — got {:?}",
        step(&steps, "on_failure").status
    );
    assert_eq!(
        step(&steps, "on_failure").output,
        serde_json::json!({ "notify": ["desktop"], "severity": "high" }),
        "`catch:`'s `emit:` must carry the document's own payload"
    );
    assert!(
        failure_message(step(&steps, "report")).contains("missing required core field: `severity`"),
        "§8.9's `finally:` report declares only `outcome`/`headline`, and §8.6's core schema \
         requires five fields — got {:?}",
        step(&steps, "report").status
    );
    assert!(
        matches!(report, ReportOrigin::Synthesised),
        "the authored `report:` step failed validation, so ruling P112's exactly-one-report is \
         discharged by the synthesised one — got {report:?}"
    );
    assert_eq!(state, RunState::Failed);
    assert_eq!(
        f.run_row_state().await,
        RunState::Failed,
        "the durable row, not the returned value, is what a restart would read back"
    );
}

/// **§8.9's `per_pr:` map, verbatim, actually reached** — the half the test
/// above cannot get to, with the fixture edited in exactly one named place:
/// `list_prs` becomes an `emit:` producing the array the unwired
/// `tool: http` call would have produced. Everything from `per_pr` onward —
/// `isolation: { worktree: { base_ref: "refs/pull/${{ pr.number }}/head" }
/// }`, `max_parallel: 4`, `on_item_error: continue`, all four inner steps,
/// and both the `catch:` and `finally:` blocks — is the frozen document's
/// own text, spliced out of [`PR_REVIEW_YAML`] rather than retyped.
///
/// What it proves is the accepted limitation rather than a bug: every item
/// fails via `run_loop`'s `worktree_cannot_span_a_suspend`, at the first
/// inner step that would suspend the run (`review`, an `agent:`). That
/// refusal's own doc comment carries the full reasoning and states it is
/// permanent, not a gap slated to close. The item's worktree really was
/// materialized first — the refusal is reachable only from the branch that
/// holds one — and really is released again, which the `git worktree list`
/// assertion below checks against `git`'s own ground truth rather than
/// against this workspace's bookkeeping.
///
/// `on_item_error: continue` then does its job: the `map` step itself
/// **completes**, carrying a `failed` entry per item, so the main phase
/// does not fail — `catch:` does *not* run, and the only reason the run
/// still ends `Failed` is the same invalid `report:` step the test above
/// pins.
#[tokio::test]
async fn the_frozen_reference_workflows_map_refuses_every_worktree_isolated_item() {
    require_on_path("git", "each item materializes a real worktree");
    let f = fixture(
        |_root| (pr_review_with_a_local_pr_list(), vec![]),
        Arc::new(crate::test_support::NoopProvider),
        Spawning::No,
    )
    .await;
    git_repo_with_pull_refs(&f.workspace_root, &[1, 2]);
    let run_ctx = pr_review_run_context(&f);

    let (state, report, steps) = terminal(f.drive(&run_ctx, None).await);

    assert!(
        matches!(step(&steps, "per_pr").status, StepStatus::Completed),
        "`on_item_error: continue` means a fan-out whose every item failed is still a completed \
         `map` step — got {:?}",
        step(&steps, "per_pr").status
    );
    let items = map_items(step(&steps, "per_pr"));
    assert_eq!(items.len(), 2, "one entry per item: {items:?}");
    for (index, item) in items.iter().enumerate() {
        assert_eq!(item["status"], "failed", "item {index}: {item:?}");
        let error = item["error"].as_str().unwrap_or_default();
        assert!(
            error.contains("inner step `review` needs real dispatch, which suspends the run")
                && error.contains("`isolation: worktree`, which cannot span a suspend"),
            "item {index} must fail through `worktree_cannot_span_a_suspend` specifically, not \
             through some other failure that merely looks similar — got {error}"
        );
    }
    assert!(
        !ids(&steps).contains(&"on_failure"),
        "a completed `map` step is not a failed main phase, so `catch:` must not run: {:?}",
        ids(&steps)
    );
    assert!(
        failure_message(step(&steps, "report")).contains("missing required core field: `severity`"),
        "the same invalid `finally:` report as the unmodified fixture"
    );
    assert!(
        matches!(report, ReportOrigin::Synthesised),
        "the authored `report:` step failed validation here too, so the run's one report is the \
         synthesised one — got {report:?}"
    );
    assert_eq!(
        state,
        RunState::Failed,
        "the `report:` step is the only thing that failed on this path"
    );

    let worktrees = git(&f.workspace_root, &["worktree", "list"]);
    assert_eq!(
        worktrees.lines().count(),
        1,
        "each item's worktree must be released on the refusal path too — `git worktree list` \
         must still show only the main checkout, got:\n{worktrees}"
    );
}

/// [`PR_REVIEW_YAML`] with its `list_prs` step — and only that step —
/// replaced, because `tool: http` cannot be dispatched (see
/// [`the_frozen_reference_workflow_runs_and_stops_at_its_first_unwired_tool`]).
/// The `emit:` produces the same `[{ number, title }, …]` shape the GitHub
/// call would, so `per_pr`'s own
/// `over: "${{ slice(steps.list_prs.output, 0, inputs.max_prs) }}"` is used
/// unchanged.
///
/// Built by splitting the frozen text rather than by pasting a copy of it:
/// the point of the test that uses this is the fixture's *own* map body,
/// and a hand-copied one would stop being that the first time §8.9's
/// document is edited.
fn pr_review_with_a_local_pr_list() -> String {
    let (preamble, per_pr_onwards) = PR_REVIEW_YAML
        .split_once("  - id: per_pr\n")
        .expect("the frozen fixture declares a `per_pr` step");
    let (header, _http_step) = preamble
        .split_once("  - id: list_prs\n")
        .expect("the frozen fixture declares a `list_prs` step");
    format!(
        "{header}  - id: list_prs\n    emit: [ {{ number: 1, title: \"first\" }}, {{ number: 2, \
         title: \"second\" }} ]\n  - id: per_pr\n{per_pr_onwards}"
    )
}

// ──────────────── 2. the same shape, actually working ────────────────

/// The PR numbers [`live_map_workflow`] fans out over, and therefore the
/// item order the whole test reads item indices against. Four, so that one
/// fan-out covers all three outcomes §8.9 gives an item — completed,
/// failed, and skipped — rather than only the happy one.
const LIVE_PRS: [u32; 4] = [1, 2, 3, 4];

/// The PR whose scripted answer violates its step's declared
/// `output_schema`, and whose item therefore **fails** at its first inner
/// step. `on_item_error: continue` proves nothing unless something actually
/// goes wrong while the others keep going.
const FAILING_PR: u32 = 3;

/// The PR the fan-out data marks `review_needed: false`, so its `gate:` and
/// `post:` steps' `when:` conditions are false and its item entry reads
/// **skipped**.
///
/// Note *why* it reads that, because it is not "the item was skipped": this
/// item's `review` and `tests` steps genuinely run and complete.
/// `map_step::fold_inner_step_outcome` overwrites the item's running
/// outcome with every inner step's status in turn — every one but a failure
/// the step declared non-fatal, which it leaves alone — so what an item
/// finally reports is simply its last-run inner step's status, here
/// `post`'s. (The walk stops early only on a failure, and only one the
/// step's own `continue_on_error:` did not declare non-fatal.) Append an
/// unconditional step after `post` and this item would report `completed`
/// instead, with nothing else about the run changed.
const SKIPPED_PR: u32 = 4;

/// The PRs that reach a gate, in item order — everything that neither fails
/// nor has its gate's `when:` evaluate false. Each one costs the run a full
/// park/resume cycle.
const GATED_PRS: [u32; 2] = [1, 2];

/// A scripted `Provider` that answers a workflow `agent:` step with one
/// final text block chosen by the PR number in the prompt it was handed —
/// and that answers **none** of them until [`LIVE_PRS`]`.len()` calls are
/// in flight together.
///
/// # The barrier is the concurrency proof
///
/// A wave of `map` items is dispatched by `dispatch_wave`, and
/// `delivery_tests`' own
/// `dispatch_wave_runs_every_item_concurrently_not_sequentially` proves
/// that function polls its items concurrently against a synthetic closure.
/// What that test cannot show is that a *real* `map` of a real workflow,
/// driven through the real daemon, still puts every item's `agent:`
/// dispatch into one wave rather than serializing them somewhere between
/// `run_workflow` and `run_agent_loop`.
///
/// `Barrier::new(LIVE_PRS.len())` shows exactly that, without measuring
/// time: were the dispatches sequential, the first would wait on peers that
/// cannot exist yet and the run would never finish — caught by
/// [`NEVER_HANGS`] rather than by a threshold on elapsed wall-clock. Are
/// they concurrent, it releases as soon as the last one arrives. There is
/// no flaky middle ground, and no clock on either path.
struct RendezvousReviewProvider {
    barrier: tokio::sync::Barrier,
    /// Every prompt this provider was asked to answer, in arrival order —
    /// so a test can assert each item's own `${{ pr.* }}` interpolation
    /// actually reached the model.
    prompts: Mutex<Vec<String>>,
}

impl RendezvousReviewProvider {
    fn new() -> Self {
        RendezvousReviewProvider {
            barrier: tokio::sync::Barrier::new(LIVE_PRS.len()),
            prompts: Mutex::new(Vec::new()),
        }
    }

    fn prompts(&self) -> Vec<String> {
        self.prompts.lock().unwrap().clone()
    }

    /// What this provider answers about PR `n`.
    ///
    /// Every PR but [`FAILING_PR`] gets a JSON object matching the step's
    /// declared `output_schema`, with a finding naming its own PR — so the
    /// downstream `when: "${{ len(steps.review.output.findings) > 0 }}"` is
    /// true, and the finding's text proves *which* item's answer landed in
    /// *which* item's `steps.review.output`.
    ///
    /// [`FAILING_PR`] gets prose. The step declared an `output_schema`, so
    /// `workflow_agent_output_from_blocks` requires the final transcript to
    /// parse as JSON and fails the step when it does not — which is what
    /// makes that item fail for a real, production reason rather than a
    /// synthetic one.
    fn answer_for(pr: u32) -> String {
        if pr == FAILING_PR {
            "I could not review this PR.".to_string()
        } else {
            format!("{{\"findings\":[\"pr-{pr}-defect\"]}}")
        }
    }
}

impl roundhouse_provider::Provider for RendezvousReviewProvider {
    fn capabilities(
        &self,
        _model: &roundhouse_provider::ModelId,
    ) -> roundhouse_provider::Capabilities {
        roundhouse_provider::Capabilities::default()
    }

    fn resolve(
        &self,
        _req: &roundhouse_provider::ChatRequest,
    ) -> Result<roundhouse_provider::Plan, roundhouse_provider::ProviderError> {
        Ok(roundhouse_provider::Plan {
            endpoint: "fake".into(),
        })
    }

    fn stream_chat<'a>(
        &'a self,
        req: &'a roundhouse_provider::ChatRequest,
        _ctx: &'a roundhouse_provider::RequestCtx,
    ) -> roundhouse_provider::BoxFut<
        'a,
        Result<roundhouse_provider::ChatStream, roundhouse_provider::ProviderError>,
    > {
        let prompt = req
            .messages
            .iter()
            .flat_map(|m| m.content.iter())
            .filter_map(|block| match block {
                roundhouse_provider::ContentBlock::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n");
        // Recorded before the rendezvous, so every prompt that arrived is
        // observable even on a run that deadlocks and is cut off by
        // `NEVER_HANGS`.
        self.prompts.lock().unwrap().push(prompt.clone());
        Box::pin(async move {
            self.barrier.wait().await;
            let pr = LIVE_PRS
                .iter()
                .copied()
                .find(|n| prompt.contains(&format!("PR #{n}:")))
                .unwrap_or_else(|| panic!("no PR number in the dispatched prompt: {prompt}"));
            let events = vec![
                roundhouse_provider::StreamEvent::BlockStart {
                    index: 0,
                    kind: roundhouse_provider::BlockKind::Text,
                },
                roundhouse_provider::StreamEvent::BlockDelta {
                    index: 0,
                    delta: roundhouse_provider::BlockDelta::Text(Self::answer_for(pr)),
                },
                roundhouse_provider::StreamEvent::BlockStop { index: 0 },
                roundhouse_provider::StreamEvent::MessageStop,
            ];
            Ok(roundhouse_provider::ChatStream(Box::pin(
                futures::stream::iter(events),
            )))
        })
    }

    fn count_tokens<'a>(
        &'a self,
        _req: &'a roundhouse_provider::ChatRequest,
        _ctx: &'a roundhouse_provider::RequestCtx,
    ) -> roundhouse_provider::BoxFut<
        'a,
        Result<roundhouse_provider::TokenCount, roundhouse_provider::ProviderError>,
    > {
        Box::pin(async { Ok(roundhouse_provider::TokenCount::default()) })
    }

    fn list_models<'a>(
        &'a self,
        _ctx: &'a roundhouse_provider::RequestCtx,
    ) -> roundhouse_provider::BoxFut<
        'a,
        Result<Vec<roundhouse_provider::ModelInfo>, roundhouse_provider::ProviderError>,
    > {
        Box::pin(async { Ok(Vec::new()) })
    }
}

/// The shell script every item's `tests` step execs — the cheapest thing
/// that is still a *real* process under a real `bwrap`, which is what makes
/// the `tool: shell` half of this integration real rather than simulated.
fn write_tests_script(root: &Path) -> PathBuf {
    let path = root.join("run-tests.sh");
    std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
    }
    path
}

/// The **item indices** of the [`LIVE_PRS`] entries matching `predicate`,
/// ascending. Derived rather than written out as `[0, 1]`: an item's index
/// is its position in `LIVE_PRS`, and an assertion that hard-coded the
/// positions would quietly stop testing what it says the day that array
/// changed.
fn item_indices(predicate: impl Fn(&u32) -> bool) -> Vec<u32> {
    LIVE_PRS
        .iter()
        .enumerate()
        .filter(|(_, pr)| predicate(pr))
        .map(|(index, _)| index as u32)
        .collect()
}

/// Where item `pr`'s `post` step writes, and therefore the file whose
/// existence and contents are the proof that the follow-up step really ran
/// with the human's own answer in hand.
fn posted_path(root: &Path, pr: u32) -> PathBuf {
    root.join(format!("posted-{pr}.txt"))
}

/// §8.9's `per_pr:` shape with the things that make it non-functional
/// replaced — each one named, because the substitutions *are* the finding.
///
/// 1. **`isolation: none` instead of `worktree`**, so the inner steps can
///    actually dispatch. See
///    [`the_frozen_reference_workflows_map_refuses_every_worktree_isolated_item`]
///    for what `worktree` does instead, and `run_loop`'s
///    `worktree_cannot_span_a_suspend` for why.
/// 2. **Every `when:` reads the item binding (`${{ pr.* }}`), never a
///    sibling inner step's output.** Not because it could not: §8.9's own
///    `${{ len(steps.review.output.findings) > 0 }}` resolves since Phase 8
///    Task 25.7 Task 10 (see
///    [`a_map_inner_step_reads_a_siblings_real_output`]), and this
///    substitution predates it. It is kept because gating on the item's own
///    data is what gives this one fan-out all three of §8.9's item outcomes
///    — every non-failing item's `review` answer carries a finding, so
///    §8.9's own condition would be true for all of them and no item would
///    reach [`SKIPPED_PR`]'s shape. Which answer reached which item is
///    asserted against the item's own durable `workflow_step_run` row rather
///    than through `${{ steps.gate.output }}`, for the reason
///    [`Fixture::item_step_rows`] gives: that binding is scoped to the item's
///    own walk, and this test stands outside it.
/// 3. **`tests` uses `{ program, argv, cwd }`**, which is what
///    `roundhouse_engine::tool_dispatch::task_params_for_in_workspace`
///    requires, rather than §8.9's `cmd: [...]`.
/// 4. **`post` writes a file** instead of shelling out to `gh`, so "the
///    follow-up step really ran, for exactly the right items" is checkable
///    against the filesystem rather than against a mock.
/// 5. **The `report:` step declares all five of §8.6's core fields**, so
///    `finally:` really produces an *authored* report — the direct contrast
///    with the frozen fixture's two-field placeholder.
///
/// What is *not* substituted is the integration shape the whole test exists
/// for: a `map` fanning out concurrently, each item nesting an `agent:`
/// step with an `output_schema` first, then a `tool: shell` step, then a
/// conditional `gate:` that really parks the run, then a conditional
/// follow-up `tool:` step — plus `catch:` and `finally:` blocks.
///
/// `tests` keeps §8.9's `continue_on_error: true`, which since Phase 8 Task
/// 25.7 Task 10 really does keep an item walking past a failed inner step
/// (see
/// [`a_failed_map_inner_step_declaring_continue_on_error_does_not_stop_its_item`]).
/// The test still asserts that step's durable row is `Completed`, so no
/// assertion below rests on the flag: a shell step that silently stopped
/// spawning would fail this test rather than be waved through as a failure
/// its author declared non-fatal.
///
/// Written as a raw string with `@NAME@` placeholders substituted
/// afterwards, rather than as a `format!` template: every `${{ … }}` in a
/// workflow document would otherwise have to be written `${{{{ … }}}}` to
/// survive `format!`'s own brace escaping, which is unreadable and is
/// exactly the kind of text a reviewer cannot check by eye.
fn live_map_workflow(workspace_root: &Path, tests_script: &Path) -> String {
    const TEMPLATE: &str = r#"name: pr-review-live
version: 3
inputs:
  repo: { type: string, required: true }
permissions:
  default: deny
  unattended: { escalate: fail }
steps:
  - id: list_prs
    emit: [ @PULLS@ ]
  - id: per_pr
    map:
      over: "${{ steps.list_prs.output }}"
      as: pr
      max_parallel: 4
      on_item_error: continue
      isolation: none
    steps:
      - id: review
        agent:
          model: "${{ vars.review_model }}"
          tools: [read, find]
          prompt: "Review PR #${{ pr.number }}: ${{ pr.title }}."
          output_schema: { type: object, properties: { findings: { type: array } } }
      - id: tests
        tool: shell
        with: { program: "@SCRIPT@", argv: [], cwd: "@ROOT@" }
        continue_on_error: true
      - id: gate
        when: "${{ pr.review_needed }}"
        gate:
          title: "Post review on PR #${{ pr.number }}?"
          form: { approve: { type: boolean, default: true }, note: { type: string } }
          timeout: 24h
          on_timeout: deny
      - id: post
        when: "${{ pr.review_needed }}"
        tool: write
        with:
          path: "@ROOT@/posted-${{ pr.number }}.txt"
          contents: "posted review of pr ${{ pr.number }}: ${{ pr.title }}"
catch:   [ { id: on_failure, emit: { notify: [desktop], severity: high } } ]
finally:
  - id: report
    report:
      outcome: findings
      severity: med
      headline: "reviewed the open pull requests"
      needs_human: false
      cost: { usd: 0, tokens: 0 }
"#;
    let pulls = LIVE_PRS
        .iter()
        .map(|n| {
            format!(
                "{{ number: {n}, title: \"pr {n}\", review_needed: {} }}",
                *n != SKIPPED_PR
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    TEMPLATE
        .replace("@PULLS@", &pulls)
        .replace("@SCRIPT@", &tests_script.to_string_lossy())
        .replace("@ROOT@", &workspace_root.to_string_lossy())
}

/// The policy rules that admit [`live_map_workflow`]'s three real
/// dispatches: spawning an `agent:` child, exec'ing the `tests` script, and
/// writing each item's `post` file. `no_policy_rules` (production's
/// default) answers `Ask` to all three, which is the right fail-closed
/// default and leaves a test about what happens *after* admission with
/// nothing to measure — the same reason `daemon_resources_with_rules`
/// exists at all.
fn live_map_rules(workspace_root: &Path, tests_script: &Path) -> Vec<CompiledRule> {
    let mut rules = vec![
        CompiledRule::test_new(
            Scope::Project,
            PolicyOutcome::Allow,
            Predicate::agent(None, None, Tier::None),
        ),
        CompiledRule::test_new(
            Scope::Builtin,
            PolicyOutcome::Allow,
            Predicate::program(&tests_script.to_string_lossy()),
        ),
    ];
    // Exact paths rather than a prefix over the workspace, so that policy
    // admits exactly the files this workflow may write and nothing else: an
    // item whose `${{ pr.number }}` interpolation went wrong would be denied
    // at admission rather than quietly writing a stray file the assertions
    // never look at.
    //
    // A rule for **every** PR, including the two whose `post` step never
    // runs — which is what makes their files' absence evidence that the
    // step was never attempted, rather than evidence that policy stopped it.
    rules.extend(LIVE_PRS.iter().map(|pr| {
        CompiledRule::test_new(
            Scope::Builtin,
            PolicyOutcome::Allow,
            Predicate::FsExact {
                op: FsOp::Write,
                path: posted_path(workspace_root, *pr),
            },
        )
    }));
    rules
}

/// **The integration issue #44/#64 were building toward, proved end to
/// end.** A `map` fanning out to four items, each nesting a real `agent:`
/// step (dispatched through the real `sub_agent_host` and the real
/// `run_agent_loop`), a real `tool: shell` step that really execs under
/// `bwrap`, a conditional `gate:` that really parks the run, and a
/// conditional follow-up `tool: write` step — all driven through
/// `DeliveryExecutor::drive_run_to_completion`, the production segment
/// loop, across two full park/resume cycles.
///
/// It is also the first test anywhere in this workspace to put an `agent:`
/// step **inside a `map` item**: `roundhouse-flow`'s own `run_loop.rs` has
/// dedicated nested-`tool:`, nested-`call:` and nested-`gate:` coverage,
/// and `delivery_tests` dispatches a top-level `agent:` step, but nothing
/// joined the two.
///
/// # What each assertion is load-bearing for
///
/// - **Concurrency**: [`RendezvousReviewProvider`]'s barrier, whose own doc
///   comment carries the argument. Nothing here measures elapsed time.
/// - **Per-item dispatch**: each item's own `${{ pr.* }}` interpolation
///   reaches the model, and each item's `post` step writes its own file
///   with its own interpolated contents. A fan-out that cross-wired items
///   would send one PR's prompt twice or write one PR's text into
///   another's file.
/// - **`on_item_error: continue`**: [`FAILING_PR`]'s `agent:` answer is
///   prose, which violates its declared `output_schema`, so that item fails
///   at its first inner step — and the others still run, and the `map` step
///   itself still completes.
/// - **All three item outcomes in one fan-out**: completed
///   ([`GATED_PRS`]), failed ([`FAILING_PR`]), and skipped
///   ([`SKIPPED_PR`], whose *last* inner step's `when:` is false — see that
///   constant's own doc comment for why that, and not "the item was
///   skipped", is what the status means).
/// - **Park/resume**: the drive returns `Parked` once per gated item, each
///   naming the item it is about via `ParkResult::item_index`, and each
///   answer lands on **that item's own** durable `workflow_step_run` row.
///   The row is where this is checked rather than a downstream `${{
///   steps.gate.output.* }}` reference, because that reference resolves only
///   *inside* the item that owns the gate and this assertion stands outside
///   the fan-out — see [`Fixture::item_step_rows`] for the scope, and
///   [`live_map_workflow`]'s doc comment for why this fixture's `when:`
///   conditions read the item binding instead.
/// - **`finally:`**: a `report:` step carrying §8.6's five core fields
///   validates, so the run's report is authored rather than synthesised.
#[tokio::test]
async fn a_map_dispatches_nested_agent_shell_and_gate_steps_for_real_concurrently_and_resumably() {
    require_on_path("bwrap", "each item's `tool: shell` step really spawns");
    let provider = Arc::new(RendezvousReviewProvider::new());
    let f = fixture(
        |root| {
            let script = write_tests_script(root);
            (
                live_map_workflow(root, &script),
                live_map_rules(root, &script),
            )
        },
        Arc::clone(&provider) as Arc<dyn roundhouse_provider::Provider>,
        Spawning::Yes,
    )
    .await;
    let run_ctx = RunContext {
        inputs: serde_json::json!({ "repo": "octocat/hello-world" }),
        inputs_secret_derived: false,
        vars: serde_json::json!({ "review_model": "test-model" }),
        secrets: HashMap::new(),
        run_id: f.run_id,
        previous_report: None,
        env_allowlist: EnvAllowlist::deny_all(),
        worktree_provider: None,
    };

    // Each park is answered with a `note` naming its own item, so the
    // durable gate rows below prove *which* answer reached *which* item.
    let mut answered: Vec<u32> = Vec::new();
    let mut driven = f.drive(&run_ctx, None).await;
    while let DrivenRun::Outcome(RunOutcome::Parked(park)) = &driven {
        let item_index = park
            .item_index
            .expect("a `map` item's nested gate parks naming the item it is about");
        let pr = LIVE_PRS[item_index as usize];
        answered.push(pr);
        assert!(
            answered.len() <= GATED_PRS.len(),
            "only {} items reach a gate; parked again for item {item_index} after answering \
             {answered:?}",
            GATED_PRS.len()
        );
        driven = f
            .drive(
                &run_ctx,
                Some(Resume::Gate(GateAnswer {
                    step_id: "gate".to_string(),
                    item_index: Some(item_index),
                    output: serde_json::json!({ "approve": true, "note": format!("ship-{pr}") }),
                })),
            )
            .await;
    }

    let (state, report, steps) = terminal(driven);

    assert_eq!(
        provider.prompts().len(),
        LIVE_PRS.len(),
        "one `agent:` dispatch per item, and no re-dispatch across the resumes: {:?}",
        provider.prompts()
    );
    for pr in LIVE_PRS {
        assert!(
            provider
                .prompts()
                .iter()
                .any(|p| p.contains(&format!("PR #{pr}:"))),
            "every item's own `${{ pr.* }}` interpolation must reach the model: {:?}",
            provider.prompts()
        );
    }
    assert_eq!(
        answered,
        GATED_PRS.to_vec(),
        "exactly the items whose `when:` is true must park on their gate, in item order"
    );

    assert!(
        matches!(step(&steps, "per_pr").status, StepStatus::Completed),
        "`on_item_error: continue` keeps a fan-out with one failed item a completed `map` step \
         — got {:?}",
        step(&steps, "per_pr").status
    );
    let items = map_items(step(&steps, "per_pr"));
    assert_eq!(items.len(), LIVE_PRS.len(), "one entry per item: {items:?}");
    // Every item whose `agent:` step succeeded goes on to `tests`, and that
    // step really execs a process under a real `bwrap`. Asserted against
    // the durable rows because `continue_on_error: true` would otherwise
    // hide a shell dispatch that failed outright — which is exactly how
    // this test could claim "real shell dispatch" while proving nothing.
    let test_rows = f.item_step_rows("tests").await;
    let mut shell_items: Vec<u32> = test_rows.keys().copied().collect();
    shell_items.sort_unstable();
    assert_eq!(
        shell_items,
        item_indices(|pr| *pr != FAILING_PR),
        "every item that got past `review` must have dispatched its `tool: shell` step"
    );
    for (item_index, row) in &test_rows {
        assert_eq!(
            row.state,
            StepRunState::Completed,
            "item {item_index}'s `tool: shell` step really execs under a real `bwrap`, and must \
             have succeeded — `continue_on_error: true` would otherwise hide a dispatch that \
             never ran at all: {:?}",
            row.error
        );
    }

    let gate_rows = f.item_step_rows("gate").await;
    for (index, pr) in LIVE_PRS.iter().enumerate() {
        let item = &items[index];
        let posted = posted_path(&f.workspace_root, *pr);
        if *pr == FAILING_PR {
            assert_eq!(item["status"], "failed", "{item:?}");
            assert!(
                item["error"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("output_schema"),
                "the failing item must fail because its answer violated the step's declared \
                 `output_schema`, not for some unrelated reason — got {:?}",
                item["error"]
            );
            assert!(
                !posted.exists(),
                "an item that failed at its first inner step must not reach `post`"
            );
        } else if *pr == SKIPPED_PR {
            assert_eq!(
                item["status"], "skipped",
                "an item reports its LAST-RUN inner step's status, whatever that status is — \
                 `fold_inner_step_outcome` overwrites the running outcome on every inner step \
                 the item walks but a non-fatal failure — and this item's last step (`post`) \
                 is `when:`-false, even though its `review` and `tests` steps completed. If \
                 this ever fails because a step was appended after `post`, the fold is what \
                 changed, not `when:` evaluation: {item:?}"
            );
            assert_eq!(
                gate_rows
                    .get(&(index as u32))
                    .unwrap_or_else(|| panic!("a skipped step still gets a row"))
                    .state,
                StepRunState::Skipped,
                "a `when:`-false gate is recorded as skipped rather than left with no row, and \
                 must not have parked the run"
            );
            assert!(
                !posted.exists(),
                "a skipped `post` step must not have written anything"
            );
        } else {
            assert_eq!(item["status"], "completed", "{item:?}");
            assert_eq!(
                std::fs::read_to_string(&posted)
                    .expect("a gated, approved item must really have written its `post` file"),
                format!("posted review of pr {pr}: pr {pr}"),
                "item {index}'s `post` must carry its OWN item binding, interpolated per item"
            );
            assert_eq!(
                row_output(
                    gate_rows
                        .get(&(index as u32))
                        .unwrap_or_else(|| panic!("item {index} reached a gate, so it has a row"))
                ),
                serde_json::json!({ "approve": true, "note": format!("ship-{pr}") }),
                "item {index}'s gate row must hold the answer given for THAT item — the thing a \
                 fan-out can most easily cross-wire, and the one place it is observable from \
                 outside the item's own walk, which is where `${{ steps.gate.output }}` \
                 resolves and this assertion does not stand"
            );
        }
    }
    let mut answered_items: Vec<u32> = gate_rows
        .iter()
        .filter(|(_, row)| row.state == StepRunState::Completed)
        .map(|(item_index, _)| *item_index)
        .collect();
    answered_items.sort_unstable();
    assert_eq!(
        answered_items,
        item_indices(|pr| GATED_PRS.contains(pr)),
        "only the items whose gate was actually asked and answered may carry an answer — a run \
         that resolved one human's answer against every item's gate would show more"
    );

    assert!(
        !ids(&steps).contains(&"on_failure"),
        "a completed `map` step is not a failed main phase, so `catch:` must not run: {:?}",
        ids(&steps)
    );
    assert!(
        matches!(step(&steps, "report").status, StepStatus::Completed),
        "a `report:` step carrying §8.6's five core fields must validate — got {:?}",
        step(&steps, "report").status
    );
    assert!(
        matches!(report, ReportOrigin::Authored { ref step_id } if step_id == "report"),
        "an authored report, not the synthesised fallback the frozen fixture falls back to — \
         got {report:?}"
    );
    assert_eq!(state, RunState::Completed);
    assert_eq!(
        f.run_row_state().await,
        RunState::Completed,
        "the durable row, not the returned value, is what a restart would read back"
    );
}

// ────────── 3. the inner-step mechanics §8.9's `map` body needs ──────────
//
// Both of these started life in section 1, pinning a gap this module's own
// drive of the frozen fixture found; Phase 8 Task 25.7 Task 10 closed both
// and flipped their assertions. They stay here, driven through the real
// daemon, because that is where the gaps were found and because §8.9's
// reference workflow is built entirely on the two mechanisms they cover.

/// **§8.9's own two inner-step idioms, evaluated for real**: an inner step
/// gating on a sibling's output (`when: "${{ len(steps.review.output.findings)
/// > 0 }}"`) and then reading it.
///
/// Both read `null` until Phase 8 Task 25.7 Task 10, because a `map` item's
/// inner-step outputs are keyed `"<step_id>#<item_index>"` in the loop's
/// `steps` context and nothing bound them under the bare id an expression
/// actually names. `Loop::advance_map_item` now opens an item-scoped `steps`
/// binding around each item's walk, so a sibling that completed a moment
/// earlier — in this segment or an earlier one — is readable by exactly the
/// item that owns it.
///
/// Both inner steps here are `emit:`, so neither leaves the run loop: this
/// is the same-segment case, at its most favourable. The resumed case, where
/// the sibling's output has to come back off its durable row, is
/// `roundhouse-flow`'s own
/// `an_items_later_inner_step_reads_a_sibling_decided_in_an_earlier_segment`.
///
/// It also keeps the half that always worked, in the same item's output: the
/// `as:` binding (`${{ it }}`) resolves, so a regression here would be
/// attributable to `${{ steps.* }}` specifically rather than to expressions
/// inside a `map` generally.
#[tokio::test]
async fn a_map_inner_step_reads_a_siblings_real_output() {
    let yaml = "name: sibling-probe\nversion: 1\npermissions:\n  default: deny\n  \
                unattended: { escalate: fail }\nsteps:\n  - id: m\n    map:\n      \
                over: \"${{ [1] }}\"\n      as: it\n      isolation: none\n    steps:\n      \
                - id: a\n        emit: { findings: [\"x\"] }\n      - id: b\n        \
                when: \"${{ len(steps.a.output.findings) > 0 }}\"\n        \
                emit: { saw: \"${{ steps.a.output.findings[0] }}\", item: \"${{ it }}\" }\n";
    let f = fixture(
        |_root| (yaml.to_string(), vec![]),
        Arc::new(crate::test_support::NoopProvider),
        Spawning::No,
    )
    .await;
    let run_ctx = RunContext {
        inputs: serde_json::Value::Null,
        inputs_secret_derived: false,
        vars: serde_json::Value::Null,
        secrets: HashMap::new(),
        run_id: f.run_id,
        previous_report: None,
        env_allowlist: EnvAllowlist::deny_all(),
        worktree_provider: None,
    };

    let (state, _report, steps) = terminal(f.drive(&run_ctx, None).await);

    assert_eq!(state, RunState::Completed);
    let items = map_items(step(&steps, "m"));
    assert_eq!(
        items[0],
        serde_json::json!({
            "status": "completed",
            "output": { "saw": "x", "item": "1" },
        }),
        "`b` must be reached at all — its `when:` reads its sibling's output, so a `null` \
         there skips it — and must read that sibling's real value alongside the item's own \
         `as:` binding"
    );
}

/// **A failed `map` inner step that declared `continue_on_error: true` does
/// not stop its item** — so §8.9's own `tests` step (`tool: shell` with
/// `continue_on_error: true`, so a red test suite still lets the review be
/// posted) means what it says.
///
/// `map_step::fold_inner_step_outcome` is the whole mechanism an inner
/// step's outcome goes through, and until Phase 8 Task 25.7 Task 10 its
/// `StepStatus::Failed` arm returned "stop this item" unconditionally: it
/// was never handed the step it was folding, so it could not consult the
/// flag at all. It now mirrors the guard `Loop::run_phase` has always
/// applied to a top-level step's failure.
///
/// Two halves, and the second is what keeps this from being a fix that
/// merely swallows failures: the failure is still **recorded** — on the
/// failing inner step's own durable row, with its message — and the item's
/// later inner steps still run.
#[tokio::test]
async fn a_failed_map_inner_step_declaring_continue_on_error_does_not_stop_its_item() {
    let yaml = "name: continue-probe\nversion: 1\npermissions:\n  default: deny\n  \
                unattended: { escalate: fail }\nsteps:\n  - id: m\n    map:\n      \
                over: \"${{ [1] }}\"\n      as: it\n      on_item_error: continue\n      \
                isolation: none\n    steps:\n      - id: boom\n        \
                emit: \"${{ no_such_fn(1) }}\"\n        continue_on_error: true\n      \
                - id: after\n        emit: { reached: true }\n";
    let f = fixture(
        |_root| (yaml.to_string(), vec![]),
        Arc::new(crate::test_support::NoopProvider),
        Spawning::No,
    )
    .await;
    let run_ctx = RunContext {
        inputs: serde_json::Value::Null,
        inputs_secret_derived: false,
        vars: serde_json::Value::Null,
        secrets: HashMap::new(),
        run_id: f.run_id,
        previous_report: None,
        env_allowlist: EnvAllowlist::deny_all(),
        worktree_provider: None,
    };

    let (_state, _report, steps) = terminal(f.drive(&run_ctx, None).await);

    let items = map_items(step(&steps, "m"));
    assert_eq!(
        items[0],
        serde_json::json!({ "status": "completed", "output": { "reached": true } }),
        "the item walks on to `after` and reports that step's outcome, rather than stopping at \
         a failure its author declared non-fatal: {:?}",
        items[0]
    );
    let boom = f.item_step_rows("boom").await;
    let failed = boom
        .get(&0)
        .expect("the failed inner step still gets its own durable row");
    assert_eq!(
        failed.state,
        StepRunState::Failed,
        "`continue_on_error:` decides whether the item stops, never whether the failure is \
         recorded — the row must still say what went wrong"
    );
    assert!(
        failed
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("no_such_fn"),
        "and it must be the step's own failure, not some later step's: {:?}",
        failed.error
    );
    assert_eq!(
        f.item_step_rows("after")
            .await
            .get(&0)
            .expect("the inner step after the failure runs")
            .state,
        StepRunState::Completed,
        "the step after the failure really ran — which is what makes the flag behavioural \
         rather than cosmetic"
    );
}
