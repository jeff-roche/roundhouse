# Roundhouse Architecture — Overview

> Extracted from the frozen design plan. This document covers naming, the problem
> Roundhouse solves and why existing agent harnesses don't, the decisions taken during
> initial clarification, and the core product nouns (Workspace/Session/Task/Team/Trigger).
> See the sibling documents in this directory for the remaining sections, and
> `docs/superpowers/plans/` for the phase-by-phase implementation plans built from this
> design.

## 0. Naming

**The project is `Roundhouse`. The CLI binary is `round`. The daemon is `round daemon` —
the same binary, not a second one.**

A roundhouse is the semicircular engine shed where locomotives rest in individual stalls
radiating from a central **turntable** that can route any engine to any track. That is
§5.1's process topology: N isolated sessions, one hub routing between them.

**Why the placeholder had to go.** `sund-ai` collides directly with **Sundai** —
`sundai.foundation`, a 501(c)(3) in Cambridge MA running `sundai.club`, with MIT /
Harvard / Northeastern affiliation, a Google Cloud partnership, 1,500+ members and 300+
AI products built. Same string modulo a hyphen, same space, same audience, and they were
there first with institutional backing.

**Collision status (checked against crates.io 2026-08-27):**

- `roundhouse` — **total: 0.** The entire `roundhouse-*` namespace is unclaimed.
- `round` — taken as a *library* crate (125k downloads) but ships **no binary**, so the
  `round` command name is free. The CLI crate is `roundhouse-cli` with `[[bin]] name = "round"`.
- `rh` was rejected: an existing `rh` crate (7,918 downloads) ships a binary named `rh`,
  which would collide on `PATH`.
- ⚠️ **Still unverified:** GitHub org, npm, domains, and trademarks — the naming search
  exhausted this session's web-search budget before those could be checked. **Do this
  before the repo is created.**

**Vocabulary the metaphor gives us — use these terms in code and docs:**

| Term | Means |
|---|---|
| **stall** | A session's isolated slot — its worktree, sandbox handle, and task log |
| **turntable** | The routing layer in the daemon that dispatches between sessions (§7.8's `Bus`, §5.1's supervisor) |
| **interlocking** | §7.7's wait-graph cycle refusal. Named for the 1856 railway invention that makes conflicting routes *mechanically impossible to set* — which is exactly what the wait-graph DFS does |

**Prior art found during the naming search — read before Phase 0.** `kedge` on crates.io
is "a high-throughput, deterministic AI agent execution harness and verification engine,"
shipping `kedge-mesh` (bounded Tokio subagent supervision and multi-agent orchestration),
`kedge-skill` (deny-by-default capability manifests: "declare what a skill may touch,
prove it stayed inside"), `kedge-audit`, and `kedge-server` (HITL approvals over HTTP).
That is an uncanny overlap with §6, §7 and §8 of this design and deserves a review pass
regardless of naming. Adjacent finds worth a look: `quipu-server`/`quipu-mcp` (audit-log
daemon exposed to LLM agents), `cordon` (embeddable sandboxing), `interlock-memory`
(fail-closed memory for coding agents), and `bulkhead` (hardened devcontainer CLI for
agent work).

---

## 1. Context

`CONCEPT.md` sketches a Rust agent harness with no LLM-provider lock-in, where a
**Session** is a set of interactions and every individual interaction is a **Task**
with a typed input and output. The concept lists task kinds (`chat`, `mcp`, `shell`,
`http`, `web`, file ops, `agent`, `message`, `git`, `memory`), asks for 15–20 inference
providers, eventual sandboxing, and cross-provider sub-agents.

The repository is empty apart from `CONCEPT.md` — this is a greenfield build.

**What we're actually building, and why it isn't just another coding agent:**

Existing harnesses (Claude Code, OpenCode, Crush, Goose, Codex CLI) are all
*one conversation at a time, in one terminal, against one vendor's loop*. Three
things are consistently missing:

1. **Parallelism is bolted on.** Sub-agents are opaque black boxes; running five
   agents means running five terminals; there is no single place to triage them.
2. **The transcript is a chat log, not a record.** Tool calls are formatted text
   inside messages. You cannot query "every shell command any agent ran in this repo
   last week," cost-account a single tool call, or replay a session deterministically.
3. **Provider choice is per-process.** You cannot have an expensive frontier model
   orchestrate cheap local models inside one coherent run.

Roundhouse's thesis is that **one primitive fixes all three**: make the *task* — not the
*message* — the unit of record. If every interaction and every action is a typed,
addressable, persisted Task, then a session is a queryable log, sub-agents are just
child sessions you can open, parallel sessions are rows in a table, and per-task
provider selection is a field rather than a process boundary.

**Intended outcome:** a local-first Rust daemon supervising many concurrent agent
sessions, driven from a terminal UI and a web UI, speaking to any provider, with
every action recorded as a first-class task.

### 1.1 What actually goes wrong in existing harnesses

A survey of the issue trackers of Claude Code, OpenCode, Crush, Goose, Cline and Roo
(sorted by reactions, to surface what people care about rather than what is merely filed)
found that **complaints cluster around state management, not model quality or prompting.**
Four bugs recur in every harness regardless of language or vendor:

| # | Failure | Evidence | The design rule it forces |
|---|---|---|---|
| 1 | **Conversation state that doesn't round-trip.** Thinking blocks and tool-call IDs stored lossily, permanently bricking sessions on resume. | Claude Code #63147, #63192; OpenCode #44581 | Store provider content blocks **verbatim**, including thinking signatures, in a versioned payload. `Delta::Thinking` carries `signature` and it round-trips byte-exact. Never normalise on write. |
| 2 | **Pending approvals held in memory** — hang forever across a server restart; stop/interrupt become no-ops. | OpenCode #36347, #44747; Crush #3648 | **The most predictable bug in a client/server split.** Approvals are persisted `TaskSuspended` events, not in-memory futures (§6.4). Recovery re-arms them at boot. |
| 3 | **Silent failure recorded as success.** Aborted streams logged as clean stops with zero usage; a UI showing 50% context while the API receives 100%. | OpenCode #37852; Cline #7383 | A task may only reach `Completed` with a real `TaskOutput` + `Usage`. An interrupted stream is `TaskFailed`. Context accounting reads from the same `Usage` the provider returned, never a local estimate. |
| 4 | **Unbounded record stores with no retention plan.** OpenCode's 13GB event table; Roo's 370GB of checkpoint blobs; Codex's 90-of-91 orphaned rollout files. | — | Retention is a **Phase 0 contract, not a later feature**: large payloads are content-addressed blobs outside the event rows, with a documented GC and a per-workspace quota. |

All four are squarely in the path of an event-sourced, client/server, typed-record design
— which means they are things to *design against first*, not discover later.

**Two of the distinctive bets here are validated by open, unmet demand:**
per-sub-agent provider routing is an explicit feature request against Claude Code
(#38698, essentially this spec) that no harness implements correctly (#43869, OpenCode
#36250); and per-task cost attribution aggregated up the sub-agent tree is requested in
every tracker (Roo #5376, Codex #38335, OpenCode #39740) and shipped by nobody — it comes
nearly free when every typed task record carries its own usage.

> Sourcing note: issue numbers and URLs came from direct `gh api` tracker searches and are
> authoritative; some community-forum dates were summarised from Discourse JSON and may be
> off by a day or two. Reddit is under-represented (blocked to fetch).

---

## 2. Decisions taken (from clarification)

| Question | Decision |
|---|---|
| UI form factor | **Daemon + TUI + web UI.** The headless daemon (`round daemon`) owns all state; TUI and web are peer clients over one versioned API. |
| Agent engine | **Native loop + ACP client + ACP server.** Own the loop over raw provider APIs; also drive external ACP agents as sessions; also expose ourselves to editors. |
| v1 scope | **Full concept in one plan.** Design everything now; ship in phases against contracts frozen up front. |
| Isolation | **All four tiers** — shared FS, git worktree per session, OS sandbox, container/remote worker. |
| Inter-agent comms | **Yes** — a teaming layer with pub/sub messaging between sessions. |

---

## 3. Product shape

### 3.1 The nouns

```
Workspace ──┬── Session ──┬── Task ──┬── Task (child)
            │             │          └── Task (child)
            │             └── Task ─── spawns ──▶ Session (child / sub-agent)
            └── Session
```

- **Workspace** — a project root and the config/policy/memory scoped to it.
- **Session** — a supervised agent instance: a provider+model, a system prompt, a
  tool set, a working directory, an isolation tier, and an append-only task log.
  Sessions form a tree (a sub-agent is a *child session*, not a hidden call).
- **Task** — one interaction or one action. Typed input, typed output, status,
  parent, provenance, cost, and an isolation attestation.
- **Team** — a set of sessions that can address each other (see §7).
- **Trigger** — the thing that starts a session or workflow run (see §8).

### 3.2 The one-screen promise

The UI's job is to make N concurrent sessions triageable by one human. The
organising idea is an **attention queue**: at any moment the daemon knows exactly
which sessions are blocked on a human (permission ask, elicitation, a workflow
approval gate, a deadlocked peer wait). That set is the primary UI surface; the
transcript view is secondary.

---

