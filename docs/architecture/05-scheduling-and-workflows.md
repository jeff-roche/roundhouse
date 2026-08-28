# Roundhouse Architecture — Triggers, Scheduling, Workflows

> Triggers, the Job model, execution semantics, unattended permissions, report
> schema, daemon-vs-OS responsibility split, the workflow step-graph model, the YAML
> definition format, durability, human-in-the-loop, composition, and observability/
> control. See `docs/superpowers/plans/2026-08-27-phase5-acp-triggers-workflows-web.md`
> for the implementation plan (Scheduling and Workflows sections).

## 8. Triggers, scheduling, workflows

### 8.1 The one-sentence story

A **trigger** fires a persisted **event**; overlap policy admits it; it instantiates a
pinned **Job version** as a **workflow run** backed by exactly one **Session**; each
**step** emits **Tasks** into the append-only log; the log is simultaneously the audit
record, the live event stream, the agent's context, and the join target for durability;
every run ends in a structured **report** that feeds the morning inbox.

### 8.2 Triggers

Three entities, not one: `TriggerSpec` (how firings are produced), `Binding` (trigger +
job + execution policy), `TriggerEvent` (a persisted firing). **Persisting the event
before the run starts** is what makes the subsystem at-least-once with dedupe, and gives
the UI somewhere to show "fired but skipped by overlap policy."

```rust
pub enum TriggerSpec {
    Manual,
    Cron  { expr: String, tz: Tz, catch_up: CatchUp, jitter: Duration,
            dst_gap: DstGap, dst_ambiguous: DstAmbiguous },
    Interval { every: Duration, align: bool, anchor: Option<DateTime<Utc>> },
    Fs    { roots: Vec<PathBuf>, include: Vec<Glob>, exclude: Vec<Glob>,
            events: FsEventMask, debounce: Duration, coalesce: bool },
    Git   { repo: PathBuf, on: GitEventMask, refs: Vec<RefPattern> },
    Webhook { path: String, auth: WebhookAuth, input_schema: Option<Schema> },
    RunComplete { source_binding: BindingId, when: OutcomeFilter },
    Message { address: Address, filter: Option<Expr> },  // rides the §7 bus, not a parallel path
}
```

**Timezones and DST are policy, not accident.** A cron expression without a timezone is a
bug; `tz` is a required IANA name (never a fixed offset — offsets don't survive rule
changes). Spring-forward deletes wall-clock times, so `dst_gap` must be answered (default
`FireAtGapEnd`); fall-back duplicates an hour, so `dst_ambiguous` defaults to `First`.
Two cheap fields that delete the entire "my nightly job ran twice in November" bug class.

**The requirement stays explicit in the stored record; the friction is removed at the UX
layer instead.** When a trigger is created via the TUI/web form or a YAML/CLI definition
that omits `tz`, the daemon resolves the host's own system timezone (e.g. via the
`iana-time-zone` crate) **at creation time** and writes the resolved concrete IANA name
into the persisted binding — visible and editable before save, never a hidden
assumption. The stored config is exactly as explicit and DST-safe as before; only the
human's manual-lookup burden for the common case (schedule this on my machine, in my
timezone) is removed.

**Clocks.** Never sleep to a wall-clock deadline. A min-heap of next-fire instants in UTC,
slept on a **monotonic** timer. Each tick compares monotonic elapsed against wall elapsed;
divergence beyond ~2s means NTP step, manual clock change, or resume-from-suspend → drop
the heap, recompute every binding, run catch-up.

**Catch-up.** Bindings store `last_fired_for` (the *scheduled* instant) and `next_fire_at`.
`CatchUp::Latest` is the right default — you want one report this morning, not eight.
Every `TriggerEvent` carries both `scheduled_for` and `fired_at`, and **a backfill run is
told it is late in its prompt context**, not merely in metadata.

Dedupe is a `UNIQUE INDEX ON trigger_event(binding_id, idempotency_key)` — covering
webhook retries, coalesced fs events, and double catch-up after a crash between "compute
occurrence" and "start run."

**`Message` binds on an `Address` (§7.2), not a topic string.** §7.3 deliberately cut
topic pub/sub — "no subject space, no wildcard subscriptions" — so this trigger cannot
subscribe to an arbitrary topic. Instead, binding a `Message` trigger creates a durable
`Address::Handle { workspace, name }` that the scheduler itself owns (the binding *is* the
addressable recipient, the same way any other named session/handle is addressable); a
`message_send` to that handle is what fires the trigger, resolved daemon-side exactly like
any other address (§7.2) — never a subject match. `filter` narrows on the message's typed
payload after that resolution, not on a topic string. This makes the trigger a normal
consumer of the one routing primitive §7 already provides, rather than a second, parallel
delivery mechanism.

### 8.3 The scheduled unit is a `Job`

**You schedule a Job, not a prompt and not a workflow.** A prompt without a provider,
model, cwd, tool set, isolation tier and permission policy is not runnable unattended; a
workflow needs the same envelope.

> **Job = SessionTemplate (the environment) + Body (the work) + InputSchema.**
> A `Body` is `Prompt(template)` or `Workflow(ref)`, and **a prompt job is defined as
> sugar for a single-step workflow.** That collapses scheduling and workflows into one
> execution path and one durability model.

Jobs are **immutable versions**. Editing produces a new version; every run pins
`(job_id, version)` and stores the content hash. Without this, "why did last Tuesday's run
behave differently" is unanswerable and retry-from-step is unsound.

### 8.4 Execution semantics

**Overlap** per binding: `Skip` (cron default), `Queue{depth}` (webhook/message default),
`Concurrent{max}`, `CancelPrevious` (fs-watch default, paired with debounce).
**Retries** are two-tier — step-level inside workflows, run-level for infrastructure
faults — both classified `Retryable` (429/5xx, connection reset, provider timeout) vs
`Terminal` (schema validation, permission denial), with exponential backoff plus full
jitter and a total retry budget so a wedged provider cannot burn the night.

**Caps enforced at task admission** — the everything-is-a-task invariant paying off, since
one chokepoint enforces everything:

```rust
pub struct ResourceCaps {
    run_wall_timeout: Duration,     // includes parked time
    run_active_timeout: Duration,   // excludes AwaitingHuman — the one you actually tune
    step_timeout: Duration,
    max_tokens: u64, max_cost_usd: Decimal, max_tasks: u32,
    max_tool_calls: u32, max_subagents: u32, max_bytes_written: u64, max_escalations: u32,
}
```

Separating wall from active time matters: a run parked three days on an approval gate has
not misbehaved.

### 8.5 Unattended permissions — the crux

1. **Decide at admission, never mid-action.** `decide()` is pure and total; there is no
   interactive fallback in unattended mode.
2. **`Escalate` is configurable per job:** `Park{deadline, on_timeout}`,
   `DenyAndContinue`, or `Fail`.
3. **Denials are legible to the model.** `DenyAndContinue` returns a *structured tool
   error* — `{error: "permission_denied", rule, hint}` — into context. **An agent told it
   may not `git push` will write a patch file instead; an agent that hangs does nothing.**
   This should be the default for most rules.
4. **Isolation is the boundary; policy is depth.** Unattended jobs default to worktree or
   higher; `unattended + shared_fs + write` requires explicit `dangerous: true`.
5. **Capabilities narrow downward only** — a step may shrink the job's policy, never widen
   it.

### 8.6 Where results go

**Each run creates a new Session.** A long-lived session accumulating 300 nightly runs
destroys context management and makes cancellation and cost attribution ambiguous. Runs
relate by `binding_id` (a `workflow_run.binding_id` / `trigger_event_id` column on every
run row — this is how "the previous run of this binding" is queried), not shared
transcript. **Continuity is data, not scrollback**: a job may declare
`carry_over: { last_report: true }` and the daemon injects the previous run's structured
`report` task output as a seed task. This does not need a dedicated memory scope — the
report is already a persisted, queryable task (see below), so seeding is "load the prior
`report` task for this `binding_id` and inject it," not a `MemoryScope` read. (§15.1's
three scopes — User/Project/Team — stay exactly three; job continuity was the one
candidate for a fourth, and it is fully served by report seeding instead.)

**Every run ends in a mandatory structured `report` task** — the single highest-leverage
decision for triage. `report` is a first-class kind in §4.2's frozen `TaskKind` table
(`TaskKind::Report`); a workflow's `report:` step (§8.9) and a scheduled job's implicit
final step both produce one, persisted through the same `TaskRunner` path as every other
task — never assembled in memory and discarded, since the inbox, fingerprint diffing, and
`round workflow replay` all need to load it back later:

```jsonc
{ "outcome": "changed",        // nothing | changed | findings | failed | needs_human
  "severity": "low", "headline": "3 flaky tests quarantined", "needs_human": false,
  "findings": [ { "id": "sha256:…", "title": "…", "severity": "med", "location": "…",
                  "pr_number": 4471 } ],                    // extension field, job-defined
  "artifacts": [ { "kind": "diff", "ref": "worktree:…", "summary": "…" } ],
  "next_actions": [ "…" ], "cost": { "usd": 0.42, "tokens": 118204 } }
```

**Core vs extension is precisely the fields the generic inbox touches, nothing more.**
Core, required, fixed-shape: `outcome`, `severity`, `needs_human`, `headline`, `cost` at
the top level; `id`, `title`, `severity`, `location` per finding. Every job type produces
these, and it's all the inbox's generic sort-and-diff logic ever reads. Everything else —
extra top-level fields, extra per-finding detail (`pr_number` above) — is open and
job-defined; it's still visible when a human drills into a specific finding's detail view
(rendered generically, same as any task detail), just never something the inbox's
cross-job logic needs to understand. **Who computes the fingerprint `id` is job-specific
(a lint job hashes `(file_path, rule_id)`, a PR-review job hashes `(pr_number,
comment_category)` — the job author knows what makes two findings the same issue
semantically), but that a stable fingerprint exists is core and mandatory.**

**Triaging 50 overnight runs:** a Runs inbox sorted by `(needs_human, severity, outcome !=
nothing)`, with `nothing` runs collapsed to one line. Crucially, **findings carry stable
fingerprint ids, so the inbox diffs against the previous run of the same binding and
labels each finding new / persisting / resolved** — you read the twelve nightly lint
complaints once, not thirty times. Notification sinks (desktop, ntfy, webhook, email, or a
`message` task to another agent) support `digest: "daily 08:00"`, so fifty runs produce
one notification.

### 8.7 The daemon owns scheduling; the OS owns liveness

systemd timers give persistence, `OnCalendar`, and cgroup limits free — but cannot express
fs watches, webhooks, git events, run-completion chaining, or overlap policy; launchd and
Windows differ enough that we'd write three schedulers anyway; and decisively, **they
split the source of truth for "what is scheduled" between SQLite and unit files**, making
a TUI that lists and edits schedules unimplementable without a sync layer nobody trusts.

Ship a systemd *user service* (and launchd `LaunchAgent`) with `Restart=always`, ideally
socket-activated. Clean split: **the OS answers "is the daemon running", the daemon answers "what
runs when".** We need catch-up ourselves regardless, so `Persistent=true` buys nothing.

Sleep/wake: subscribe to logind `PrepareForSleep` / `NSWorkspaceDidWake` where available,
falling back to monotonic-vs-wall divergence. On resume, recompute schedules, run
catch-up, and **mark all in-flight provider calls retryable — their sockets are dead.**

### 8.8 What a workflow is

> **The graph is the deterministic skeleton; each agent step is a bounded
> non-deterministic hole. Determinism lives *between* steps, never inside them.**

A **declarative step graph whose interesting step type is an `agent` step** — a bounded
mini-session with its own prompt, tool allowlist, isolation, caps and *typed output
schema*. Deterministic step types (`tool`, `map`, `gate`, `call`, `emit`, `report`) handle
the rest.

Rejected: *pure declarative* cannot express "figure out what to do"; *imperative
interpreted* means building a language and a sandbox for it (revisit via WASM only on real
demand); *pure prompt* has no durability, no fan-out control, no cost caps, no HITL
parking, and re-derives its plan every night — precisely wrong for a job whose value is
being boringly repeatable.

Because every action is already a task, **a step is a task subtree**: `provenance` carries
`{run_id, step_id, attempt, item_index}`. A workflow run *is* a Session with a graph
superimposed on its task log. **No second execution substrate.**

Prior art taken deliberately: Temporal's journal idea (but not its determinism tax);
LangGraph's cycles + checkpointer + `interrupt` as the correct HITL shape; Windmill's
typed step inputs auto-generating a form; n8n's triggers-as-first-class-nodes; Dagster's
typed step IO. GitHub Actions is the cautionary tale — its `${{ }}` expression language
accreted into a small ugly language.

### 8.9 Definition format

YAML, for readable multi-line prompt blocks. **The `inputs:` schema does triple duty:** it
validates webhook payloads, renders the manual-trigger and gate forms, and *becomes the
JSON tool schema when the workflow is exposed as a sub-agent tool*. One definition, three
uses.

```yaml
name: pr-review
version: 3
inputs:
  repo:    { type: string, required: true }
  max_prs: { type: integer, default: 10 }
defaults:
  isolation: worktree
  retry: { attempts: 3, backoff: exponential, base: 10s, max: 5m, on: [retryable] }
secrets: [GH_TOKEN]
permissions:
  default: deny
  rules:
    - { http:  { methods: [GET], hosts: ["api.github.com"] },   effect: allow }
    - { shell: { program: "cargo", args: ["test", "*"] },       effect: allow }
    - { shell: { program: "gh", args: ["pr", "comment", "*"] }, effect: escalate }
  unattended: { escalate: park, deadline: 12h, on_timeout: deny }
steps:
  - id: list_prs
    tool: http
    with: { method: GET, url: "https://api.github.com/repos/${{ inputs.repo }}/pulls?state=open" }
  - id: per_pr
    map:
      over: "${{ slice(steps.list_prs.output, 0, inputs.max_prs) }}"
      as: pr
      max_parallel: 4
      on_item_error: continue                     # continue | fail_fast | collect
      isolation: { worktree: { base_ref: "refs/pull/${{ pr.number }}/head" } }
    steps:
      - id: review
        agent:
          model: "${{ vars.review_model }}"
          tools: [read, find, git]
          prompt: |
            Review PR #${{ pr.number }}: "${{ pr.title }}".
            Report only defects you can point at a line for. No style nits.
          output_schema: { type: object, properties: { findings: { type: array } } }
        caps: { max_cost_usd: 0.50, max_tool_calls: 60 }
      - id: tests
        tool: shell
        with: { cmd: ["cargo", "test", "--all"] }
        continue_on_error: true                   # non-zero exit is data, not failure
      - id: gate
        when: "${{ len(steps.review.output.findings) > 0 }}"
        gate:
          title: "Post review on PR #${{ pr.number }}?"
          form: { approve: { type: boolean, default: true }, note: { type: string } }
          timeout: 24h
          on_timeout: deny
      - id: post
        when: "${{ steps.gate.output.approve }}"
        tool: shell
        idempotency_key: "pr-${{ pr.number }}-review-${{ run.id }}"
        with: { cmd: ["gh","pr","comment","${{ pr.number }}","--body-file","${{ steps.review.artifact }}"] }
        env: { GH_TOKEN: "${{ secrets.GH_TOKEN }}" }
catch:   [ { id: on_failure, emit: { notify: [desktop], severity: high } } ]
finally: [ { id: report, report: { outcome: "…", headline: "…" } } ]
```

Steps run in file order unless `needs:` declares an explicit DAG. **The expression
language is deliberately tiny and frozen** — property access, indexing, ternary, and ~10
functions (`len`, `slice`, `default`, `contains`, `flatten`, `json`, `env`). Anything more
goes in a `tool: shell` step with `jq`, or an agent step. This is the explicit lesson from
GHA, and resisting growth here forever is a standing commitment.

`map` gives each item **its own worktree** — the feature that makes parallel PR review
actually work. `continue_on_error` distinguishes "the command failed" (data) from "the
step failed" (control flow).

**A `map` item's `caps:` block (shown on `review` above) is a transfer out of the run's
remaining budget, not an independent pool** — the same model as §7.7/§8.12, so one
expensive item can never starve the others by draining an undifferentiated shared
budget. Unset defaults to an even split of the run's remaining budget across the item
count at the moment the `map` starts. If the *run-level* ceiling is hit even though
individual items are within their own caps, exhaustion is cooperative — in-flight items
finish their current tool call/`infer` round-trip (§8.13's existing cancel semantics),
no new round-trips or new items start. Items that never got to run are recorded
`Skipped { reason: "run_budget_exhausted" }`, never silently dropped or conflated with a
real failure, and the run's report sets `needs_human: true` so the inbox visibly flags
an incomplete run rather than presenting a partial result as if it were whole.

### 8.10 Durability — checkpoint, not replay

**Can the task log be the durable execution journal, Temporal-style?** Structurally yes.
But Temporal's replay model exists because workflow control flow is *opaque code* — the
only way to recover the program counter is to re-execute feeding recorded results back,
which is why determinism is mandatory and why LLM calls would break it.

**We chose a declarative graph, so we don't need replay.** Interpreter state is small and
explicit — completed step ids with outputs, plus attempt counters — and can be
checkpointed directly. **Checkpoint-and-re-drive beats replay whenever control flow is
data rather than code**, and costs us nothing replay would have bought.

Three tiers:
1. **Workflow — durable state machine.** `workflow_run` + `workflow_step_run` rows; every
   transition one SQLite transaction through the single writer. Recovery = load and
   resume.
2. **Step — at-least-once with declared idempotency.** A step found `Running` after a
   crash is *not known* to have completed. `Pure`/`Idempotent` → re-run. `Effectful`
   (shell, write, push, POST) → mark `Indeterminate` and apply
   `on_crash: rerun | fail | ask` (default `ask`, landing in the gate queue).
3. **Agent step — conversation reload, not replay.** Reload its own tasks from the log,
   continue from the last complete assistant turn. A tool task dispatched with no recorded
   output is re-dispatched if idempotent, else surfaced to the model as
   `{status: "interrupted", outcome: "unknown"}` — models handle that far better than we
   handle guessing.

> **State the promise honestly.** We do not offer deterministic replay and must not
> pretend to. We offer: a complete audit record; durable control flow; at-least-once side
> effects with declared idempotency; reconstructible model context. Exactly-once requires
> idempotent steps — a property of the user's steps, not something we can manufacture.

`workflow_step_run.first_task_seq`/`last_task_seq` join back to the log, so a step's full
evidence is `SELECT * FROM task WHERE session_id = ? AND seq BETWEEN ? AND ?`.

**Keep replay as a debugging tool:** `round workflow replay --dry <run_id>` re-executes the
graph feeding recorded step outputs, so a workflow *logic* change can be tested against a
real historical run without paying for inference. Nearly free once the journal exists.

### 8.11 Human-in-the-loop

**Parking must be stateless.** `AwaitingHuman` releases the worker slot, the provider
connection, and (unless `hold_workspace: true` with a TTL) the worktree. **Before
releasing, it runs an implicit `checkpoint` task (§4.2)** — a plain git ref alone
wouldn't capture untracked or staged-but-uncommitted files, but the checkpoint mechanism
already designed for restore points does, so releasing never loses anything a resume
would need. Deadlines use the **same timer heap as triggers**; there is exactly one
scheduler in the system.

**`hold_workspace`'s TTL defaults to the enclosing gate's own `timeout`** — a workflow
author who already set `timeout: 24h` on a gate has already decided the reasonable
human-response window, so reusing it avoids a second, disconnected config knob. With no
explicit gate timeout, fall back to 72h. Either way, **a system-wide 7-day cap is
enforced by a reaper regardless of what any individual gate specifies** — the same
retention discipline already required for the event log (§1.1's rule #4: unbounded
storage growth is a Phase-0 contract, not a later feature), so forgotten
`hold_workspace: true` runs can't accumulate disk indefinitely.

Three sources of human waits — an explicit `gate` step, an unattended permission
`Escalate`, and mid-step elicitation — resolve to **one mechanism**: an `AwaitingHuman`
task with a JSON-Schema form that TUI and web render from the same schema. Unifying
permission escalation with approval gates is what makes unattended mode tractable rather
than a second policy engine. `on_timeout: deny | fail | default(value) | approve`, where
`approve` is permitted only when the run's policy is narrower than the job default.

### 8.12 Composition

- **`call:` sub-workflow** creates a child `workflow_run` **and a child Session**, so
  isolation, caps and permissions are per-workflow. **Cost rollup is a real transfer, not
  just a display rollup** — following §7.7's sub-agent budget model exactly, since this
  is architecturally the same relationship: the child's `max_cost_usd`/`max_tokens` are
  drawn from the parent's remaining budget, refunded on completion, enforced. A workflow
  subtree can never spend more than its root was given, same invariant as sub-agent
  spawning. The parent's log gets one `agent`-kind task standing for the call — identical
  to sub-agent spawning, which is the point.
- **Workflow-as-tool**: registered as `workflow:<name>`; `inputs` *is* the tool schema,
  `outputs` *is* the result. Recursion depth and fan-out budget enforced at admission.
- **`acp:` step** hands off to an external ACP agent; its activity streams into our task
  log with `provenance: external`, its permission requests route through **our** policy
  engine. ⚠️ The ACP surface is still moving — keep behind `trait ExternalAgent` and treat
  the first implementation as disposable.

### 8.13 Observability and control

**Live progress needs no separate path from history.** `(session_id, seq)` is a cursor;
the daemon publishes appends and workflow transitions on one bus, and a reconnecting
client resumes from its last seq and catches up exactly. A direct dividend of the
append-only invariant, and **a hard constraint on the socket protocol**.

Controls: **cancel** (cooperative — mark `Cancelling`, refuse new task admission,
SIGTERM→SIGKILL running shells, run `finally:`); **pause**; **resume**;
**retry-from-step**, which **forks a new run** inheriting completed step outputs with a
`forked_from_run_id` link — history is append-only, so we never rewrite it; **rerun**.

### 8.14 Open questions

~~Report schema fixed or core+extension?~~ **Decided (§8.6): core+extension, with the
core defined as precisely the fields the generic inbox touches** (top-level
outcome/severity/needs_human/headline/cost; per-finding id/title/severity/location) —
never actually in tension once the core is that precisely scoped.

~~Do parked runs hold worktrees?~~ **Decided (§8.11): release by default via an implicit
`checkpoint` first (so nothing is lost — a plain git ref alone wouldn't capture untracked
files, but a proper checkpoint does); opt-in `hold_workspace` TTL defaults to the
enclosing gate's own timeout, with a hard 7-day system-wide cap regardless.**

~~Cost rollup across the tree.~~ **Decided (§8.12): a real enforced transfer, matching
§7.7's sub-agent budget model exactly** — same relationship, same invariant, not a
separately-decided rule.

~~Remote workers break the single-SQLite-writer assumption.~~ **Resolved (§6.5): the
premise didn't hold.** Remote workers stream results back to the one daemon, which
remains sole writer — no store change needed at any scale. True multi-daemon shared
storage was never proposed and is already out of scope (§12.6).

~~Fan-out budgets per-run or per-item?~~ **Decided (§8.9): per-item, transferred from the
run's budget (same model as §7.7/§8.12); run-level exhaustion is cooperative and
not-yet-run items are recorded `Skipped`, never silently dropped.**

~~Explicit `tz` on cron is friction.~~ **Decided (§8.2): keep the stored requirement,
remove the friction at the UX layer** — auto-fill from the host's detected system
timezone at creation time, resolved into a concrete stored IANA name the human can
still override, never a hidden runtime assumption.

*(All of §8's open questions are now resolved.)*

