# Roundhouse Architecture — User Stories

> Personas, epic-to-crate mapping, the three load-bearing stories that no design
> change may make harder to assert in a test, representative P0 acceptance criteria,
> non-functional budgets, explicit out-of-scope items, and phase traceability. These
> are the acceptance-test source of truth for every implementation phase.

## 12. User stories

Full story set (~100 stories, personas, acceptance criteria, traceability table) is
authored and ready to hand to `writing-plans`; summarized here for the design doc.

### 12.1 Personas

**Dana** — solo developer, agentic coding, one or two sessions from the TUI, cares about
latency and never losing work. **Priya** — power user orchestrating 5–20 parallel
sessions across providers, cares about aggregate attention state and killing runaways.
**Omar** — operator running unattended scheduled/webhook agents, cares about audit trail,
spend caps, and being paged only when it matters. **Lena** — integrator driving Roundhouse
via ACP/MCP and scripting the API, cares about a stable versioned contract.

### 12.2 Epics → crates

SESS(`roundhouse-engine`) · LOG(`roundhouse-store`) · PROV(`roundhouse-provider`) · LOOP(`roundhouse-engine`) ·
TOOL(`roundhouse-tools`) · PERM(`roundhouse-policy`) · ISO(`roundhouse-sandbox`) · MCP(`roundhouse-mcp`) ·
ACPC/ACPS(`roundhouse-acp`) · MSG(`roundhouse-bus`) · TRIG(`roundhouse-sched`) · FLOW(`roundhouse-flow`) ·
TUI(`roundhouse-tui`) · WEB(`roundhouse-web`) · OBS(`roundhouse-store`/search) · CFG(`roundhouse-config`) ·
MEM(memory task kind).

> SESS and LOOP both map to `roundhouse-engine` — session lifecycle and the agent loop
> are one crate (see §5.2's crate table and its naming-reconciliation note in
> `02-system-architecture.md`), not two. CFG maps to `roundhouse-config`, added to §5.2's
> table during phase planning to give S-CFG-1/S-CFG-5 (below) an actual home.

### 12.3 The three load-bearing stories

Everything else is negotiable; these three are not, and a design change that makes any
of them harder to assert in a test is the wrong design change:

> **S-LOG-1** — every action an agent takes produces exactly one Task record, enforced
> *structurally* (a private-constructor `TaskRunner` that no executor can bypass), not by
> convention. **S-LOG-2** — the event log is append-only, enforced by a SQLite trigger
> that aborts on `UPDATE`/`DELETE` plus a source-scanning test. **S-ISO-1/2** — the
> achieved isolation tier is recorded on every task, and a session never silently starts
> at a lower tier than requested.

### 12.4 Representative P0 stories (full acceptance criteria in the story doc)

- **S-SESS-4** (crash → resume): a session killed mid-task shows the interrupted task as
  `Interrupted`, never `Running`, on restart; 500 sessions × 200 tasks recovers and
  serves requests within 5s.
- **S-LOG-4/5** (durable, contention-safe writes): an acknowledged task survives `kill
  -9` in 100/100 trials; `SQLITE_BUSY` retries with backoff and never surfaces to a
  client as session failure.
- **S-PROV-3/4** (retry & fallback): 429 with `Retry-After` honored exactly; a fallback
  chain attributes cost per actual attempt, never invents a `0.0`.
- **S-TOOL-3** (edit is verified and reversible): an edit with an ambiguous or absent
  match fails closed with the file byte-for-byte unchanged; writes are atomic
  (temp+rename).
- **S-PERM-1/6** (deny-by-default, sealed floor): no matching rule → `Deny` in
  unattended mode; the always-deny list survives every profile including `auto`
  (there is no `yolo` mode — §6.2 names the four modes `plan`/`ask`/`accept-edits`/`auto`,
  and §6.5 explains why `auto` is not a "disable the sealed floor" special case) and
  cannot be edited away by a config file the agent itself could have written.
- **S-OBS-4** (blocked-anywhere-discoverable): approvals, `elicit` tasks and workflow
  gates across every session are enumerable in one query in ≤50ms over 10,000 sessions —
  this is the API the attention queue (§3.2) is built on, not a UI convenience.

### 12.5 Non-functional budgets (reference: 8-core/32GB/NVMe/Linux 6.x, the median dev machine)

Cold start ≤300ms empty / ≤5s at 500×200 tasks · idle RSS ≤40MiB + ≤256KiB/idle session ·
64 concurrent running sessions, 10min, zero lost events, p99 API ≤100ms · streaming p99
≤50ms in-daemon / ≤200ms daemon→browser · TUI frame p99 ≤16ms, keypress-to-echo ≤50ms ·
log writes ≥2000 events/s WAL+NORMAL · FTS search p95 ≤300ms over 1M tasks · crash
recovery ≤5s at 100k tasks, zero acknowledged-event loss over 100 kill/restart trials ·
binary ≤40MiB stripped · zero outbound connections before first session creation · panic
in any executor fails only the owning task, never the daemon.

### 12.6 Explicitly out of scope

No hosted/multi-tenant service, no model hosting/fine-tuning, no vector DB/RAG (memory is
lexical FTS over plain text), no IDE plugins beyond the ACP server role, no general-
computation workflow DSL (loops/arithmetic belong in an `agent` or `shell` step), no
marketplace/template registry, no automatic merge-conflict resolution across parallel
worktrees, no default telemetry, no installer/auto-updater, no mobile client, no
cross-machine session migration.

### 12.7 Traceability (P0 excerpt; full table in the story doc)

Phase 0: `S-CFG-5` (API versioning), `S-TOOL-9` (schema-generated tools), `S-LOG-2/3`
(append-only, fold), `S-CFG-1` (layered config) — these are the contracts every later
phase assumes frozen. Phase 1: session lifecycle, task-log invariant, provider trait +
streaming + hermetic tests, agent loop core, core tool executors, TUI attach+render.
Phase 2: crash recovery, cancellation, retry/fallback, compaction, permission engine +
sealed floor, worktree+sandbox isolation, secrets/redaction, cost attribution, blocked-
query. Phase 3: MCP host. Phase 4: sub-agent spawning, messaging/teams (matches
§10-implementation-phasing.md §13.2, the README, and the plan set — this was previously
misstated here as Phase 5). Phase 5: unattended approval timeouts, ACP surfaces,
workflows, web UI.



