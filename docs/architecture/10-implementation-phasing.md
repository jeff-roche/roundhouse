# Roundhouse Architecture — Implementation Phasing

> Why the crate boundaries double as work-assignment boundaries for an AI agent team,
> what each of the seven phases freezes, and how to actually parallelize the build.
> The seven phase implementation plans in `docs/superpowers/plans/` are the direct,
> task-by-task realization of this document.

## 13. Implementation plan for an AI agent team

### 13.1 The organizing principle

Every design decision above was made with one constraint in mind: **implementation will
be done by a team of AI agents, not incrementally by one human.** That changes what "good
architecture" means. The crate boundaries in §5.2 are not just modularity — they are
**work-assignment boundaries** with minimal shared mutable state, so N agents can each own
a crate and touch almost nothing another agent is editing. The contracts frozen in Phase 0
exist specifically so that a provider-adapter agent, a TUI agent, and a policy-engine agent
can all start from the same `roundhouse-core` types without waiting on each other's design
decisions mid-flight. The conformance-suite pattern in §9.10 exists specifically so a
human reviewer can trust an agent-written provider adapter from a snapshot diff instead of
reading every line.

### 13.2 Phases and what they freeze

**Phase 0 — Contracts (must complete before any other phase starts).** One team, tight
coordination, no parallelism benefit here — the whole point is these types are shared
truth. Deliverables: `roundhouse-core` (`Event`, `Task`, `TaskKind`, `Session`, ids, `Address`,
error types — no I/O, `#![forbid(unsafe_code)]`), `roundhouse-proto` (client↔daemon wire types +
schema emission), the `Provider`/`Isolate`/`Bus` traits as *signatures only* (§9.4, §6.5,
§7.8), the SQLite schema and migration harness (§4.1, append-only trigger from S-LOG-2),
and the `TaskRunner` private-constructor pattern that makes S-LOG-1 structurally true. Exit
criterion: every downstream crate compiles against stub implementations of these traits.
**Nothing in Phase 1+ starts until Phase 0's types are tagged and reviewed** — retrofitting
a data-model change across ten crates written by ten agents is far more expensive than one
careful review pass up front.

**Phase 1 — Vertical slice.** Parallel tracks, one agent (or small team) per crate, against
the frozen Phase 0 contracts:
- `roundhouse-store`: event append/fold, WAL writer task, crash recovery (S-LOG-4/5).
- `roundhouse-provider`: the `openai-chat` and `anthropic-messages` codecs (§9.4), streaming +
  hermetic cassette tests (S-PROV-1/5/8) — the two codecs covering ~80% of providers.
- `roundhouse-agent` (agent loop core): `chat`→`infer` task tree, deterministic context assembly
  (S-LOOP-1/2).
- `roundhouse-tools`: `shell`/`read`/`write`/`edit`/`find` executors (S-TOOL-1..4).
- `roundhouse-tui`: attach-to-daemon, render loop, streaming without flicker (S-TUI-1/2).
Exit criterion: a human can run `round`, start a session against Anthropic or an
OpenAI-compatible provider, watch it edit a file, and see the task log. This is the
first point the whole team demos something real.

**Phase 2 — Robustness.** Crash recovery end-to-end, cancellation (S-SESS-4/5), retry and
fallback (S-PROV-3/4), compaction (S-LOOP-3), the permission engine and sealed deny floor
(§6.2–6.4), worktree + OS-sandbox isolation (§6.5, S-ISO-1/2/3), secrets and redaction
(§6.7), cost attribution as a derived view (§9.7, S-OBS-1), the blocked-anywhere query
(S-OBS-4). This phase is where the failure taxonomy in §1.1 gets closed off in tests, not
just design intent.

**Phase 3 — MCP host** (§10, `roundhouse-mcp`): server lifecycle, tool namespacing, MRTR-driven
elicitation. (Sampling is deprecated per §10.1 — the suggested migration is calling LLM
APIs directly, which `roundhouse-provider` already does, so there is no sampling adapter to
build.) Independent of Phase 4; can run in parallel with it.

**Phase 4 — Sub-agents and messaging**: `agent` task spawning child sessions (S-SESS-7,
S-TOOL-8), the inter-agent bus and teams (§7), deadlock detection. This is where the
product's core differentiator — cross-provider parallel sessions — becomes real.

**Phase 5 — Everything that needs the above stable**: ACP client and server (§10),
triggers and scheduling (§8.2–8.7), workflows (§8.8–8.13), unattended approval policy
(§6.4, S-PERM-5), the web UI (§11.3). These all depend on Phase 2's permission engine and
Phase 4's session-tree semantics, which is why they're sequenced last despite being large.

**Phase 6 — Provider breadth**: the remaining ~23 provider profiles (§9.5) fanned out one
agent per provider (or small cluster), each independently gated by the conformance suite
from §9.10. This is the phase with the highest parallelism ceiling — provider profiles
share no state with each other, only the frozen codec + trait contracts from Phase 0/1.

### 13.3 How to actually parallelize this with an agent team

- **Assign by crate, not by feature.** A crate boundary is a compile boundary; an agent
  that owns `roundhouse-policy` can be handed §6 verbatim as a spec and never needs to know how
  `roundhouse-tui` renders an approval prompt, only that it must produce a `Decision` the UI can
  render generically.
- **Use git worktrees per agent**, mirroring the isolation-tier design the product itself
  uses (§6.5, §11's dogfooding opportunity) — each agent's changes land in review as a
  branch, merged after the crate's own test suite and the cross-crate contract tests pass.
- **Freeze, don't negotiate, mid-phase.** If an agent discovers Phase 0's `Event` enum is
  missing a variant it needs, that is an escalation to a human, not a unilateral change —
  the whole value of frozen contracts is that nine other agents are relying on them not
  moving.
- **The conformance suite is the review artifact for provider adapters (§9.10).** For
  Phase 6 specifically, a human reviewer's job per adapter is: read the 16 golden
  snapshots, skim the cassette list, confirm `conformance().assert_green()`, done. This is
  what makes 23 provider adapters by 23 different agent runs actually reviewable in
  bounded human time.
- **Security-relevant crates (`roundhouse-policy`, `roundhouse-sandbox`, `roundhouse-config` secrets
  handling) get a mandatory second-agent adversarial review pass** — a fresh agent
  instructed to try to defeat the shell parser (§6.3), find a fail-open path in the
  isolation tiers (§6.5), or find a secret leak into the task log (§6.7) — before merge.
  This mirrors the shell-parser bake-off already flagged as an open question in §6.12.
- **Cross-cutting invariants (§1.1's three load-bearing stories, S-LOG-1/2, S-ISO-1/2) are
  enforced by tests that run in every crate's CI, not by convention** — a source-scanning
  test for raw `UPDATE events`/`DELETE FROM events`, a test that no executor is reachable
  outside `TaskRunner`, a test that every task row carries `isolation_tier_achieved`. These
  are cheap to write once and they are what makes ten independently-written crates still
  add up to one coherent invariant.

### 13.4 Sequencing summary

```
Phase 0  Contracts            (serial, all hands, blocks everything)
Phase 1  Vertical slice       (parallel: store / provider×2 / agent-loop / tools / TUI)
Phase 2  Robustness           (parallel: recovery / policy+sandbox / secrets / cost+search)
Phase 3  MCP host        ─┐   (parallel with Phase 4)
Phase 4  Sub-agents+bus   ┴─  (both depend on Phase 2)
Phase 5  ACP + triggers + workflows + web UI   (depends on Phase 2 & 4)
Phase 6  Provider breadth (23 profiles)         (max parallelism; depends only on Phase 0/1)
```

Phase 6 can start as soon as Phase 1's codec work lands — it does not need to wait for
Phase 5 — so in practice it should run concurrently with Phases 2–5 once the two
reference codecs and the conformance harness exist.

