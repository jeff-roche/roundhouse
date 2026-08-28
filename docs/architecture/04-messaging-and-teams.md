# Roundhouse Architecture — Teaming and Inter-Agent Messaging

> Addressing, delivery semantics, teams, deadlock/livelock/cost bounds, and the
> `LocalBus` implementation. See
> `docs/superpowers/plans/2026-08-27-phase4-subagents-messaging.md` for the
> implementation plan.

## 7. Teaming and inter-agent messaging

### 7.1 Four decisions

1. **Messages are Tasks on both sides.** A send appends a `message` task to the
   sender's log; delivery appends one to the recipient's. No message exists outside a
   session log. The `mailbox` table is a *derived* delivery queue, rebuildable by
   scanning outbound `message` tasks with no matching inbound.
2. **One routing primitive: directed send to an `Address`.** Broadcast and pub/sub are
   *address expansion against a roster*, not a separate subsystem. No subject space,
   no wildcard subscriptions, no retained messages.
3. **Request/reply is `send` + `wait`, not blocking RPC.** The sender's task parks in
   `Suspended{AwaitingReply}` — a first-class, inspectable, human-breakable object.
4. **A Team owns addressing only.** The spawn tree remains the sole authority for
   lifecycle, cancellation, and budget. Never let two structures both answer
   "who dies when."

### 7.2 Addressing

```rust
pub enum Address {
    Session { id: SessionId },
    Handle  { workspace: WorkspaceId, name: String }, // "reviewer", "db-migrator"
    Team    { team: TeamId },
    Role    { team: TeamId, role: String },
    Human   { session: SessionId },                    // never blocked by policy
}
```

Ids are truth, handles are UX: `(workspace, name) -> SessionId` resolved **daemon-side
at send time**, never in the model's head, with the resolved id recorded in the
envelope. `WorkspaceId` is the hard boundary — cross-workspace messaging is out of
scope for now (it is where filesystem isolation, secret scope, and budget ownership all
differ at once), but `SessionId` stays globally unique so lifting it needs no migration.

**Ephemeral sub-agents are addressable the moment they exist.** This is the deliberate
departure from Claude Code's model, where a sub-agent is a write-only call returning one
blob. `agent_spawn` returns `{session_id, handle}` and the child joins the parent's team
roster immediately. Ended sessions leave a tombstone, so a late send fails with
`Undeliverable::Ended` rather than "unknown address."

**The human is never a `Team` roster member, and `to: team` never implicitly pages
them.** `Address::Human`'s actual delivery mechanism is UI surfacing/notification, not
"land in a mailbox, inject before the recipient's next `infer` round-trip" — a human has
no "next turn." Folding them into the roster would also directly undermine the
attention-queue design's whole point (§8.6, §11.4: no-op activity must cost zero human
attention) by letting ordinary team coordination chatter reach the human on every
broadcast. Nothing is lost by keeping this split: an agent that wants the human informed
about a broadcast already can, with no new mechanism — it just also sends
`message_send(to: Address::Human, ...)` directly, which is a deliberate, visible choice
about when human attention is warranted rather than an automatic CC.

### 7.3 Primitives — in and out

**In:** directed send (fire-and-forget) · request/reply (`expect_reply`) · fan-out to
`Team`/`Role` · `wait` (park for inbound).

**Cut, with reasons:** *Topic pub/sub with a subject space* — the only topic anyone
publishes to is "my team," and a roster is a small enumerable set; subject matching buys
a subscription table, a retention policy, and unattributable messages for nothing.
*Blackboard/shared KV* — the `memory` task kind plus a `MemoryScope::Team(TeamId)`
already is one; two shared-state mechanisms is two sources of truth. *Agent-to-agent
streaming channels* — LLM turns are discrete. *Contract-net capability auction* — fails
opaquely; a human or orchestrator picking a recipient is legible.

**Fan-out replies: all of them land, none get summarized — this falls out of two rules
already stated, not a separate mechanism.** `expect_reply` carries a `quorum:
Any|All|AtLeast(n)`, and quorum governs only *when the sender's blocking wait resolves*
— it says nothing about delivery. Every reply is still a `message` task on both ends
(§7.1). So under `quorum: any`, the sender's `AwaitingReply` task unblocks the moment
the first reply lands and the session proceeds; replies still in flight at that moment
are not discarded or folded into the one that resolved the wait — they arrive as
ordinary inbound `message` tasks at their own next turn boundary (§7.4). No
daemon-side summarization step exists: that would be an unrequested model call, and team
size is already bounded (≤32 sessions per team, §7.7) so the worst-case reply volume a
sender could face is already small.

### 7.4 Delivery semantics

- **FIFO per (sender, recipient) pair.** Not global, not causal. A daemon-global
  `bus_seq` exists for the *timeline view*, not for ordering guarantees.
- **At-least-once delivery, effectively-once observation.** The mailbox row is written
  in the same SQLite transaction as the sender's task append; the recipient's log has
  `UNIQUE(session_id, inbound_msg_id)`, so redelivery is idempotent.
- **Recipient paused** → queues, badge shown, injected before the next model turn —
  precisely, before the next `infer` round-trip, not before the next whole `chat` task
  (§7.9: never mid-stream, but a busy tool loop still gets frequent injection points
  since each round-trip is its own task, §4.2).
  **Ended** → `Undeliverable::Ended` synchronously, never a silent drop.
  **On a remote worker** → identical; the mailbox lives in the daemon, the worker pulls.
- **Backpressure:** bounded mailbox (default 64). On overflow **reject the send** —
  never drop the oldest. A rejected send is information the model can act on; a dropped
  message is a bug nobody sees. `Human` mailboxes are unbounded.
- **Attachments are refs, never inlined blobs** (`ArtifactRef::{Task,File,Blob}`).
  Dereferencing a peer's `ArtifactRef::Task` is permitted *because the peer attached
  it* — the attachment is the capability grant. Without that rule, messaging is a hole
  straight through session isolation.

### 7.5 Teams

```rust
pub struct Team   { id: TeamId, workspace: WorkspaceId, name: String,
                    charter: String,       // injected into every member's system prompt
                    created_by: SessionId, policy: TeamPolicy, state: TeamState }
pub struct Membership { team: TeamId, session: SessionId, role: String,
                        joined_at: Timestamp, left_at: Option<Timestamp> }
```

First-class and persisted, not a view over the spawn tree, because teams must survive
their creator, must admit peers that never spawned each other, and must reopen after
daemon restart. `agent_spawn` auto-joins the child to the parent's team as `worker`
unless overridden. Teardown is explicit: `Draining` (no new sends, pending replies land)
→ `Closed`; a roster of all-`Ended` members is auto-closed by a reaper.

Rejected: a flat peer set (can't express "the lead decides when we're done"); a pure
orchestrator hierarchy à la AutoGen `GroupChatManager`/CrewAI sequential (forces every
worker-to-worker exchange through the lead's context window — the single largest token
cost in multi-agent systems).

**Team-scoped memory access (see §15) is granted, not inherited wholesale**: every
member of a team gets **read** access to the team's memory scope as a side effect of
membership — no separate grant needed, since the whole point of a shared blackboard is
that teammates can see it. **Write access is a distinct, explicit grant**, scoped
per-session, so a sub-agent cannot silently rewrite shared team state just because it
joined the roster.

### 7.6 Tools exposed to the model

`message_send`, `message_wait`, `peers`, `agent_spawn` (extended with `as`, `role`,
`team`, `isolation`, `provider`, `budget_tokens`, `detached`), `team_create`/`team_close`.

**Discovery is hybrid and that matters.** The system prompt carries a small static block
— team name, charter, your role, your handle, and the roster as
`handle · role · one-line self-description · state` — regenerated on roster change.
`peers` gives the live detailed view (state, mailbox depth, who is blocked on whom).
Prompt-only goes stale and lies; tool-only means models forget teammates exist. The
one-line self-description is borrowed from Google A2A's AgentCard: declarative, never
auto-inferred.

**How an inbound message renders splits on whether it was asked for.** A reply arriving
while the agent is parked in `message_wait` renders as the **`tool_result` of that
pending call** — no special-casing, since that's exactly how every provider's tool-calling
API already correlates a result to a prior call, and it correctly signals "retrieved
data" rather than "an instruction from my principal." An unsolicited message (no pending
`wait`) renders as a **system-level/injected context note — never a synthetic user
turn.** Framing a peer agent as a user-role turn risks real authority miscalibration: the
model could extend the same deference to a peer's claims that it gives the actual human,
which directly undermines taint-gated autonomy (§6.8) — every peer message is
`Trust::Untrusted` regardless of how it's phrased in context. This also matches how other
harnesses inject non-conversational context: Claude Code's `attachment` records push
tool-list and environment updates as system-attributed material, never as fake user
speech (§1.1). **Still needs verification, kept scoped as a provider-adapter detail
(§9), not a policy question:** the exact mechanical encoding of "system note mid-
conversation" differs by provider — some accept a literal mid-conversation system-role
turn, Anthropic takes exactly one top-level system field per request, so the injection
there has to be a clearly-delimited block inside the next user-role turn instead.

### 7.7 Deadlock, livelock, cost

- **Wait-for cycle detection.** `WaitGraph: HashMap<SessionId, SmallVec<[SessionId;4]>>`;
  registering a blocking wait does a DFS back to self and **refuses synchronously**,
  telling the model *"waiting on `reviewer` would deadlock — `reviewer` is waiting on
  you."* Highest-value guard here and roughly 40 lines.
- **Depth limit** 4 (inherited +1 per spawn). **Fan-out** ≤8 direct children per
  session, ≤32 live sessions per team.
- **Budget inheritance is a transfer, not a grant.** `agent_spawn` moves tokens from the
  parent's remaining budget into the child's, refunded on exit. A subtree can never cost
  more than its root was given.
- **Message rate cap** — token bucket per session (default 20/min, burst 10) plus a
  global cap; exceeding returns `Refused`, never silently queues.
- **Repetition damper** — ≥3 sends with identical `(to, subject)` and no state change
  between refuses the 4th. Cheap livelock kill.
- **`ttl_hops`** (default 8) decremented per relay.
- **Human break-glass** on any blocked task: *answer as peer* (injected reply, clearly
  marked in provenance), *release* (unblock as `TimedOut`), *cancel task*, *kill
  subtree*. Plus a global Blocked panel with wait-for edges rendered.

### 7.8 Implementation

A **routed mpsc registry** (`LocalBus` with `DashMap` of mailboxes, handles, teams, plus
the wait graph and the shared DB writer) — not `tokio::sync::broadcast` (lossy under lag,
no per-recipient ack, no way to express "paused" — every property we need is the one it
lacks), and not an embedded broker (right answer for cross-machine, a whole daemon's
worth of ops burden at this stage).

`Bus` is a trait and the only thing session runtimes touch, so a `RemoteBus` framing
`Envelope` as CBOR over a worker's control channel drops in unchanged. Two rules to
honour now so that stays true: `Envelope` must be self-contained and serializable (hence
refs, not in-process handles), and the resolved `to` is always a `SessionId` — address
expansion stays daemon-side, workers never resolve.

**Restart:** re-register mailboxes for live sessions, re-arm deadlines from
`mailbox.deadline`, rebuild the wait graph from suspended tasks. Deadlines already past
resolve to `TimedOut` at boot, so a crashed daemon never leaves an agent parked forever.

### 7.9 Open questions

~~Does an inbound message interrupt a running turn?~~ **Decided (§7.4): never mid-stream
or mid-tool-execution** — true preemption risks orphaned `tool_use`/`tool_result` pairs,
exactly the state-corruption failure mode §1.1 already identified as the top competitor
bug class. Injection happens before the next `infer` round-trip specifically (not the
next whole `chat` task), which stays responsive during an active tool loop. `Control` is
reserved as a documented, unbuilt escape hatch for real preemption later.

~~Team fan-out replies: all N or summarize?~~ **Decided (§7.3): all N, no
summarization** — not a new mechanism, just `quorum` (governs when a wait resolves) and
"every message is a task" (governs delivery) already composing correctly on their own.

~~How an inbound message renders per provider.~~ **Decided (§7.6): `wait`-triggered
replies render as tool results; unsolicited messages render as system-framed injection,
never a synthetic user turn.** Only the per-provider mechanical encoding of "system note
mid-conversation" remains open, and it's scoped to §9 as an adapter detail, not a policy
question.
~~Is the human a roster member with a role?~~ **Decided (§7.2): no.** Different delivery
mechanism entirely (UI surfacing vs. mailbox-and-next-turn), and it would undercut the
attention-queue's noise-reduction goal. An agent that wants the human informed sends to
them directly — no new mechanism needed.

*(All of §7's open questions are now resolved.)*

