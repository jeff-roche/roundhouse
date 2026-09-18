# Roundhouse Architecture — Core Data Model

> The spine of the system. This is the contract every other document and every
> implementation phase is written against — frozen first, changed only by explicit
> amendment. See `docs/superpowers/plans/2026-08-27-phase0-contracts.md` for the
> task-by-task plan that implements it.

## 4. Core data model — the spine

This is the contract everything else is written against. It is frozen first and
changed only by explicit amendment.

### 4.1 Events are truth; Tasks are a fold over events

A naive "table of tasks" cannot express the four things this system does constantly:
streaming partial output, tasks that suspend for hours awaiting a human, tasks
interrupted by a daemon crash, and tasks that nest. Mutating a task row for each of
those loses history and fights the append-only requirement.

So the storage primitive is an **Event**, and a **Task is the materialised fold of
the events bearing its `task_id`**. The `tasks` table is a derived cache maintained
by the single writer; the event log is the source of truth. This buys, for free:
crash recovery (a task with `Started` and no terminal event was interrupted),
deterministic replay, time-travel/checkpoints, and an honest audit trail.

```rust
/// The only thing ever written. Append-only. No UPDATE, no DELETE.
pub struct Event {
    pub session_id: SessionId,
    pub seq:        u64,           // monotonic per session; (session_id, seq) is PK
    pub ts:         Timestamp,     // UTC, monotonic-corrected
    pub task_id:    Option<TaskId>,// None for session-level events
    pub payload:    EventPayload,
    pub schema_v:   u16,           // payload schema version, from day one
}

pub enum EventPayload {
    // ── session lifecycle ─────────────────────────────────────────────
    SessionCreated  { spec: Box<SessionSpec> },
    SessionConfigured { patch: SessionPatch },
    SessionStateChanged { state: SessionState, reason: Option<String> },
    SessionClosed   { outcome: SessionOutcome },

    // ── task lifecycle ────────────────────────────────────────────────
    TaskCreated   { kind: TaskKind, parent: Option<TaskId>,
                    origin: Origin, input: TaskInput },
    TaskDecided   { decision: PolicyDecision, rule: Option<RuleId> },
    TaskStarted   { isolation: IsolationAttestation },
    TaskDelta     { delta: Delta },              // streaming, 0..n
    TaskProgress  { progress: Progress },        // structured, replaces prior
    TaskSuspended { reason: SuspendReason },     // permission / elicit / peer-wait
    TaskResumed   { by: Origin },
    TaskCompleted { output: TaskOutput, usage: Usage },
    TaskFailed    { error: TaskError, retryable: bool },
    TaskCancelled { by: Origin, reason: CancelReason },

    // ── cross-cutting ─────────────────────────────────────────────────
    Message       { envelope: Envelope },        // inter-agent, see §7
    Note          { level: NoteLevel, text: String }, // daemon/system annotation
}
```

`Delta` is deliberately typed rather than `String`, because a `shell` task streams
stdout/stderr bytes, a `chat` task streams text/thinking/tool-call fragments, and an
`agent` task streams child-session progress:

```rust
pub enum Delta {
    Text     { text: String },
    Thinking { text: String, signature: Option<String> }, // must round-trip verbatim
    Stdout   { bytes: Bytes },
    Stderr   { bytes: Bytes },
    ToolArgs { fragment: String },   // partial JSON from a streaming tool call
    Child    { session: SessionId, seq: u64 }, // pointer to a child session's event
}
```

**Redaction coverage (Phase 8 Task 19 lane B).** `Redactor::redact_event_payload`
(`roundhouse-store`) runs on every `TaskDelta` before it is durably appended:
`Delta::Text`, `Delta::Thinking.text`, and `Delta::ToolArgs.fragment` are scanned as
text; `Delta::Stdout`/`Delta::Stderr` are scanned as raw bytes
(`Redactor::redact_bytes`), since shell output is not guaranteed to be valid UTF-8.
`Delta::Child` is a session/seq pointer and `Delta::Blob` is a content hash — neither
carries inline text or bytes for the automaton to scan, so `redact_event_payload`
leaves both untouched. A blob's actual content is therefore **never** redacted by the
store: a caller writing secret-bearing bytes to a blob (`roundhouse_store::blobs::write_blob`)
must redact them itself before that write (see §4.5's shell-output blob routing).

### 4.2 Task kinds

Core kinds are flat identifiers; plugin-provided kinds are namespaced `vendor:verb`
so the enum stays closed for the core and open for extension.

| Kind | Input | Output | Notes |
|---|---|---|---|
| `chat` | user/system prompt, attachments | final assistant content + task-tree summary | One **turn**. Parent of everything the turn caused. |
| `infer` | rendered messages, tools, params, provider+model | content blocks, stop reason, usage | **One provider round-trip.** See below. |
| `shell` | argv or command string, cwd, env, pty? | exit status, captured output ref, duration | |
| `read` `write` `edit` `find` | path/glob/patch | content ref, diff, match list | `edit` output carries a structured diff |
| `http` | method, url, headers, body | status, headers, body ref | REST + GraphQL |
| `web` | query or url | result set / extracted content | search + fetch |
| `mcp` | server, tool, args | MCP `CallToolResult` content blocks | |
| `git` | subcommand + args (structured) | structured result (diff, log, status) | |
| `memory` | scope, op, key, value | value / ack | user/project/team-scoped, see §15 |
| `agent` | child `SessionSpec`, prompt, mode | child `SessionId` + final result | **Creates a child session.** |
| `message` | address, body, mode | ack or peer reply | See §7 |
| `compact` | strategy, target budget | new context state + summary | Context compaction is an *action*, so it is a task |
| `checkpoint` | label | snapshot ref | Restore point over the event log |
| `plan` | plan entries | accepted plan | Maps to ACP `plan_update`. **This is also CONCEPT.md's `todo` kind** — a todo list is a plan whose entries are checked off, so no separate kind is needed (see the note below the table). |
| `elicit` | schema or free-form question | user response | Human-in-the-loop, ACP/MCP elicitation |
| `flow` | workflow step ref | step result | Workflow node, see §8 |
| `report` | none (assembled from the run's tasks) | the structured report object, §8.6 | The mandatory terminal task of every workflow/job run. Persisted like any other task so the Runs inbox, fingerprint diffing, and audit have something to read — it is not an in-memory-only summary. |

**On `todo` and CONCEPT's "open agent plugin protocol."** CONCEPT.md's rough sketch named two
items this frozen model deliberately answers rather than drops silently:
- **`todo`** is not a separate task kind. The `plan` kind already models an ordered list of
  entries with accept/update semantics (and a direct ACP mapping via `plan_update`) — a
  todo list is exactly that, entries with a done/not-done status folded from successive
  `plan` tasks. Giving `todo` its own kind would duplicate `plan`'s shape for no new
  capability.
- **"Open agent plugin protocol"** is intentionally *not* a designed protocol in v1. The
  `vendor:verb` namespacing rule for plugin-provided task kinds (this section, above) is
  the only surface reserved for it — enough that a future plugin protocol has somewhere to
  land without an `Event`/`TaskKind` migration, but no plugin loading, manifest format, or
  capability negotiation is being built now. Tracked as deliberately out of scope, not an
  oversight.
- CONCEPT's "config option to spawn sub-agents into new processes or the same process" is
  subsumed by the isolation tiers (§6.5): `Tier::None`/`Worktree` run in-process (same
  daemon, same OS process); `Tier::Container`/`Remote` spawn a genuinely separate process
  (or host). There is no additional process-vs-thread toggle beyond choosing a tier.

**Why `infer` is a task kind.** A single `chat` turn causes many provider round-trips.
If those are invisible, you cannot cost-account a turn, see which call was retried or
fell back to another provider, debug a malformed tool call, or measure cache hit rate.
Making the model call a task is the difference between a chat log and a record. It is
also what makes cross-provider sub-agents legible: the provider is a field on `infer`,
not a property of the process.

### 4.3 Nesting, streaming, and non-terminating tasks

Three known failure modes of a literal "everything is a task" model, and the answers:

- **Nesting.** `parent: Option<TaskId>` gives a tree inside a session; `agent` tasks
  point at a child *session*. Depth and fan-out are bounded by policy (§6, §7).
  **Amendment (Phase 8 L5, "sub-agent spawn tracking" #2):** `SessionSpec` itself
  carries `parent: Option<SessionId>` (`#[serde(default)]`, so events serialized
  before this field existed still deserialize, defaulting to `None`). Sub-agent
  spawn edges could not survive a daemon restart without it — `SessionCreated` is
  the one place a session's origin is already durably recorded, so a session's
  parent lives there rather than in a separate table. `None` for a root session
  (socket-attached or scheduler-driven); set by whichever code path creates a
  child session — workflow `call:` (`WorkflowSessionTree::persist_child_session`
  in `roundhouse-daemon`) and, since #3 of the same plan, the model-facing
  `agent` tool (`roundhouse_engine::tools::agent_spawn_tool` deciding the spawn,
  `roundhouse-daemon`'s `DaemonSubAgentHost` creating the child and appending its
  `SessionCreated`). Both write the same event with the same field, so one
  recovery pass reads both — `reconcile_spawn_tree` (`roundhouse-daemon`'s
  `workflow_host`), which the daemon runs once at startup via
  `boot::reconcile_spawn_tree_at_boot`, rebuilds the runtime spawn tree from
  these edges after a restart. See that function's own documentation for what
  a restart still cannot know about a sub-agent child.
- **Streaming.** Solved by `TaskDelta`. A task's output is not written until it
  completes; consumers fold deltas for a live view.

  **Coalescing and ordering (Phase 8 Task 19 lane B).** A provider's raw per-token
  deltas are batched before persistence by `roundhouse_engine::delta_sink::DeltaCoalescer`:
  a mid-block flush fires at about 2 KiB of buffered text or after 250ms (4Hz, the
  cadence §11.2's coalesced session summaries already use) — whichever comes first —
  plus on a content-kind change and at block/stream end. `roundhouse_engine::chat::run_chat_turn_with_clock`
  guarantees every infer `TaskDelta` this batching produces commits before that
  task's terminal event, on both the success path and a mid-stream provider-failure
  path. Every chunk boundary the coalescer emits — not only the
  size/time-triggered ones, but every cut inside an oversized final release too — is
  chosen by a redaction-safe split, never picked locally: `Redactor::safe_split_len`,
  through `EventWriter`'s combined holdback-and-split queries
  (`redaction_split_for_coalescer`/`redaction_split_and_redact`), decides every
  boundary. What that buys, stated at the strength `safe_split_len`'s own doc comment
  claims and no higher: **within a single coalesced run**, no live secret survives
  *intact* across the run's delta boundaries. A boundary never lands inside a match
  `AhoCorasick::find_iter` reported, so every reported match sits wholly inside one
  delta and is replaced there; an occurrence that overlaps a reported one is never
  reported at all and a boundary *can* legitimately land inside it, but it loses
  interior bytes to that `[REDACTED]` replacement and so cannot reassemble as its own
  literal byte sequence either. The scope matters: `DeltaCoalescer` closes its pending
  buffer on a content-kind change and at block end, releasing with no holdback, and the
  next delta starts a fresh empty buffer — so the seam between, say, the last delta of
  a text block and the first delta of the following tool-args block carries no straddle
  protection. The identical split-safe-boundary rule, with the identical scope, governs
  a dispatched `shell` task's streamed stdout/stderr (§4.5).
- **Non-terminating tasks.** A `shell` task running `npm run dev` never exits. These
  are modelled as **long-running tasks with a handle**: `TaskStarted` carries a
  `handle` (pty/process id), the task stays `Running`, deltas keep arriving, and it is
  terminated by an explicit `TaskCancelled` or session close. The agent gets a
  `read_output`/`kill` affordance rather than blocking. Sessions cannot close with
  live handles without an explicit disposition. **Amendment (Phase 8 T19a, "session
  close"):** `SessionClosed` is the event log's terminator, not merely another
  lifecycle event — folding a session's state (`fold_session_state`, in
  `roundhouse-core`) treats `Closed` as absorbing: once reached, every later event in
  the slice is folded away and the result stays `Closed`. `roundhouse-store`'s
  `EventWriter::close_session` is the sole writer of it, and it runs as one
  transaction: it first sweeps every task of that session still
  `Created`/`Decided`/`Running`/`Suspended` into `TaskCancelled { by: System, reason:
  CancelReason::SessionClosed }` — this is the explicit disposition every live handle
  gets, so none is left dangling — and only then appends `SessionClosed { outcome }`
  as the transaction's last event. Closing an already-closed session is a no-op read
  (`CloseReceipt::AlreadyClosed`); a genuine close reports `CloseReceipt::Closed
  { swept }`, the count of tasks it cancelled. A tail guard enforces the terminator at
  the store boundary too: any later `append`/`append_batch`/`append_batch_with_blobs`
  for that session is rejected with `StoreError::SessionClosed` rather than silently
  accepted after the log has already ended. That last one is the streaming-delta flush
  path described in the amendment to §4.3's streaming bullet above; it is covered
  because every append path assigns sequence numbers through the same guarded
  `append_event_in_transaction`, not because each one carries a check of its own.

### 4.4 Identity and provenance

Every task carries: `origin` (`User | Model | System | Peer | Trigger | Client`),
`actor` (which session/agent), `policy_decision` + matched rule, `isolation`
(the *achieved* tier, not the requested one), `usage` (tokens, cost, wall time), and
`redactions` (which spans were secrets-scrubbed).

### 4.5 Retention: content-addressed blobs, GC, and quota

*(Added 2026-08-28 — named as a Phase 0 contract in §1.1 bug #4 ("OpenCode's 13GB event
table; Roo's 370GB of checkpoint blobs") but never given a concrete design. This section
is that design, so Phase 0 has something to implement rather than a one-line promise.)*

**The rule: nothing large lives inline in an event row.** "Large" is defined once, in one
place, so every executor applies it identically: any `TaskInput`/`TaskOutput`/`Delta`
payload whose serialized size exceeds `BLOB_INLINE_THRESHOLD` (4096 bytes) is written to
the blob store instead, and the event row carries a `BlobRef` in its place:

```rust
pub struct BlobRef {
    pub hash: Blake3Hash,   // content address; identical bytes always collide to one blob
    pub len:  u64,
    pub mime: Option<String>,
}
```

`shell` stdout/stderr, `read`/`edit` file contents and diffs, `http`/`web`/`mcp` response
bodies, and checkpoint snapshots are the dominant sources of large payloads and always
route through this path regardless of size (avoids a threshold judgment call on the
kinds most likely to be large); anything else is measured and only escalated to a blob if
it crosses the threshold.

**A deliberate exception (Controller ruling R14, Phase 8 Task 19 lane B).**
`roundhouse_engine::delta_sink::DeltaCoalescer` can still emit a single `Delta` whose
serialized size reaches or exceeds `BLOB_INLINE_THRESHOLD` without routing it to the
blob store, in two cases: a thinking signature that alone exceeds the threshold (it
must ride the delta that closes its block and round-trip verbatim — splitting it would
break that contract), and a redaction match wider than the size budget (a registered
secret whose own serialized form exceeds the threshold — splitting it would put a
recoverable secret across two separately redacted payloads, each missing part of the
match). Both cases put content integrity ahead of the size rule above; the resulting
delta stays inline and is **never** written to the blob store. This is a deliberate,
documented deviation from this section's size rule, not an oversight, and closing it
(e.g. giving an oversized-but-safe-to-inline delta somewhere else to go) is tracked as
follow-up work, not something this lane resolved.

**Shell output's mime convention (Phase 8 Task 19 lane B).** A dispatched `shell`
task's streamed stdout/stderr are `Delta::Blob` refs whose `BlobRef.mime` is
`application/vnd.roundhouse.stdout` or `application/vnd.roundhouse.stderr` — a project
convention layered on the `BlobRef` shape above, not a new field. The bytes are
redacted (`Redactor::redact_bytes`, via `EventWriter::redaction_split_and_redact`)
*before* `roundhouse_store::blobs::write_blob` ever sees them, precisely because (§4.1)
the store's persistence-boundary redaction pass never inspects blob content — a
shell-output caller is exactly the kind of caller that must redact before that write.

A streamed shell delta sequence can also contain gaps: `roundhouse_engine::tool_dispatch`'s
pump drops a chunk from the delta stream alone (never from the task's own authoritative
captured output, which is assembled independently) when a shared in-flight byte budget
is exceeded, or truncates once a fixed output cap is reached. Either discontinuity is
marked by a `TaskProgress` event before the stream continues or ends, so a consumer
folding `TaskDelta`s into a live view can tell a genuine gap apart from a contiguous
read. **A consumer must never treat the concatenation of a task's `Delta::Blob`
sequence as that task's complete output** — a gap marker means bytes existed that will
never appear in any blob for this task.

**Storage.** Blobs live under `<state_dir>/blobs/<hash[0..2]>/<hash>` (git-style
sharded-by-prefix layout, avoiding one directory with millions of entries), written via
temp-file-then-rename so a crash mid-write never leaves a partial blob at its final path.
A `blobs` table in SQLite (`hash PRIMARY KEY, len, mime, created_at, last_referenced_at`)
is the index — it is a cache over the filesystem, not the source of truth for content,
matching the same "structured index, plain-file content" split §15.3 already uses for
memory.

**Reference counting, not mark-and-sweep.** Every `BlobRef` written into an event bumps a
`ref_count` on the `blobs` row in the same SQLite transaction as the event append (so a
blob can never be referenced by an event that isn't durably recorded, and vice versa);
closing/GC-ing an event's owning session decrements it. A blob with `ref_count == 0` is
GC-eligible immediately but is not deleted immediately — see the grace period below.
Mark-and-sweep (walk every event, mark reachable blobs) is kept only as `round blob
fsck`, an offline consistency check for after a bug or manual DB surgery, never the
steady-state GC path.

**GC.** A background task, run on daemon startup and then daily: delete blobs with
`ref_count == 0` **and** `last_referenced_at` older than a 7-day grace period (so a blob
freed by, e.g., closing a session isn't yanked out from under a UI tab still rendering
its last view). Deletion is logged as a `Note` session-level event (`level: Info`), never
silent. `round blob gc --dry-run` reports what would be reclaimed without deleting.

**Per-workspace quota.** `WorkspaceConfig.blob_quota_bytes` (default 5GiB) is checked at
write time: if writing a new blob would exceed the workspace's quota, GC-eligible blobs
for that workspace are reclaimed oldest-`last_referenced_at`-first *before* the write is
attempted; if that still isn't enough, the write itself gets a synchronous
`Degradation` event (`kind: "blob_quota_exceeded"`) and the task fails with a structured
error rather than silently truncating the payload — the same "silent degradation becomes
a loud, recorded event" rule as isolation degradation (§6.5) and unknown pricing (§9.7).
`round doctor` surfaces current usage per workspace.

**Why this is Phase 0, not deferred:** `TaskInput`/`TaskOutput`/`Delta` are frozen types
(§4.1); adding a `BlobRef` variant to them later, after adapters and tools already assume
inline payloads, is exactly the "retrofitting a frozen contract" cost §13.3 warns against.
The blob store itself has no dependency on later phases — it is pure `roundhouse-store`
(schema) plus `roundhouse-core` (the `BlobRef` type), same crates already delivering the
event log.

---

