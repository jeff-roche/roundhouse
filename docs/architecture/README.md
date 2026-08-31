# Roundhouse Architecture

Roundhouse is a local-first Rust daemon supervising many concurrent AI-agent sessions,
driven from a terminal UI and a web UI, speaking to any LLM provider, with every action
recorded as a first-class, typed, queryable Task in an append-only event log. See
[`00-overview.md`](00-overview.md) for the full motivation and product shape.

**Naming:** the project is `Roundhouse`. The CLI binary is `round`; the daemon is
`round daemon` (the same binary, not a second one). Crates are `roundhouse-*`. See
[`00-overview.md`](00-overview.md#0-naming) for the full naming rationale and the
vocabulary the metaphor supplies (stall, turntable, interlocking).

This directory is the frozen design, split by topic for reference. It was produced
through a brainstorming/clarification process with a team of parallel research and
design agents, then reviewed and approved section-by-section. It is not a living
spec — changes should be made deliberately and should stay consistent across
documents, the same way the original design tracked its own internal consistency
(see [`11-verification.md`](11-verification.md)).

## Reading order

| Doc | Covers |
|---|---|
| [00-overview.md](00-overview.md) | Naming, why Roundhouse exists, decisions taken, the core nouns (Workspace/Session/Task/Team/Trigger) |
| [01-data-model.md](01-data-model.md) | The Event/Task/Delta spine — the contract everything else is written against |
| [02-system-architecture.md](02-system-architecture.md) | Process topology, the Cargo workspace crate table, pinned dependency versions |
| [03-security-and-sandboxing.md](03-security-and-sandboxing.md) | Policy engine, shell handling, approvals, isolation tiers, network policy, secrets, taint |
| [04-messaging-and-teams.md](04-messaging-and-teams.md) | Addressing, delivery semantics, teams, deadlock detection ("the interlocking") |
| [05-scheduling-and-workflows.md](05-scheduling-and-workflows.md) | Triggers, the Job model, workflows, durability, human-in-the-loop |
| [06-provider-abstraction.md](06-provider-abstraction.md) | The narrow-waist IR, codecs, quirk profiles, credentials, testing strategy |
| [07-protocols-acp-mcp.md](07-protocols-acp-mcp.md) | ACP client/server roles, MCP host role |
| [08-ui-design.md](08-ui-design.md) | TUI and web UI, shared route table, the hard interaction moments |
| [09-user-stories.md](09-user-stories.md) | Personas, the three load-bearing stories, acceptance criteria, non-functional budgets |
| [10-implementation-phasing.md](10-implementation-phasing.md) | Why crate boundaries double as agent work-assignment boundaries, the seven phases |
| [11-verification.md](11-verification.md) | Internal consistency check, how the implementation gets verified |
| [12-memory-subsystem.md](12-memory-subsystem.md) | Memory scopes, storage, how memory enters context |

## Implementation plans

Each phase in [10-implementation-phasing.md](10-implementation-phasing.md) has a
task-by-task, TDD implementation plan in `docs/superpowers/plans/`:

| Phase | Plan | Scope |
|---|---|---|
| 0 | `2026-08-27-phase0-contracts.md` | `roundhouse-core`, `roundhouse-proto`, trait signatures, SQLite schema, TaskRunner pattern — blocks every other phase |
| 1 | `2026-08-27-phase1-vertical-slice.md` | Store, two provider codecs, agent loop, core tools, TUI attach — first end-to-end demo |
| 2 | `2026-08-27-phase2-robustness.md` | Crash recovery, retry/fallback, permission engine, isolation, secrets, cost, blocked-query |
| 3 | `2026-08-27-phase3-mcp-host.md` | `roundhouse-mcp` — server lifecycle, tool namespacing, MRTR |
| 4 | `2026-08-27-phase4-subagents-messaging.md` | `roundhouse-bus`, `agent` task spawning, deadlock detection |
| 5 | `2026-08-27-phase5-acp-triggers-workflows-web.md` | ACP client/server, scheduling, workflows, web UI |
| 6 | `2026-08-27-phase6-provider-breadth.md` | The remaining ~23 provider profiles |

Phases 0→1→2 are sequential (each depends on the last). Phase 3 and Phase 4 can run in
parallel once Phase 2 lands. Phase 5 depends on both Phase 2 (permission engine) and
Phase 4 (session-tree semantics). Phase 6 depends only on Phase 0/1 and has the highest
parallelism ceiling — it does not need to wait for Phase 5.

## Known gaps and follow-ups (found while writing the phase plans)

Each phase plan was written by an agent reading this design fresh and reporting back
what it found. Two spec inconsistencies and several open items surfaced this way,
independently confirmed by more than one agent in some cases. Resolved items are fixed
in these docs already; unresolved ones are listed here so they aren't lost before a
human implementer starts Phase 0.

**Resolved in these docs:**
- **Crate naming.** §5.2's workspace table (18 crates at the time this note was written,
  pre-Phase-0; 20 as of the Phase 2 whole-branch-review cleanup, which added
  `roundhouse-secrets` and `roundhouse-net`) is now stated as the single
  source of truth. `roundhouse-agent`/`roundhouse-session` (used loosely elsewhere in
  the original draft) both name `roundhouse-engine`. `roundhouse-config` was a genuine
  gap — the design referenced `S-CFG-1`/`S-CFG-5` (layered config, API versioning) as
  Phase 0 contracts but never gave "layered config" a crate — it's now a real row in
  §5.2's table. See [`02-system-architecture.md`](02-system-architecture.md)'s
  naming-reconciliation note.
- **Missing pinned dependencies.** `axum` (web UI server), `insta` (conformance
  snapshots), `hmac`/`sha2`/`hex` (SigV4 signing), `aws-smithy-eventstream`/
  `aws-smithy-types` (Bedrock's binary eventstream), `toml`, `walkdir` — all needed by
  Phase 5/6 but absent from the original §5.3 baseline. Added to
  [`02-system-architecture.md`](02-system-architecture.md) with the phase that needs
  each.
- **`roundhouse-config` had no implementation task.** Giving it a crate row fixed the
  naming inconsistency, but nothing built its actual layered-config-loading logic.
  Since `S-CFG-1`/`S-CFG-5` are named Phase 0 exit contracts (§12.7), Task 13 was added
  to `docs/superpowers/plans/2026-08-27-phase0-contracts.md` — a real (not stubbed)
  `ConfigScope`/`SecretRef`/`ConfigLoader` with narrower-scope-wins TOML merging,
  wired into `roundhouse-daemon` so the exit criterion exercises it. `toml` 0.8 was
  added to the plan's Global Constraints and to §5.3 for this.
- **Phase 1's demo-level exit criterion wasn't covered by its own task list.** "A human
  can run `round`, start a session, watch it edit a file, see the task log" needed
  wiring the five Phase 1 crates behind `roundhouse-daemon`/`roundhouse-cli`, neither of
  which was one of Phase 1's five deliverable crates. Fixed by adding a sixth track
  (Track F, Task 21) to `docs/superpowers/plans/2026-08-27-phase1-vertical-slice.md`,
  with its own automated, hermetic end-to-end test.
- **Phase 1 also independently rebuilt the `roundhouse-agent`/`roundhouse-engine` split
  as a real crate** (not just a naming note) before the reconciliation above existed —
  Task 21's work required fixing this properly: all 37 references were renamed to
  `roundhouse-engine`, and Tasks 11-12's `lib.rs` edits were rewritten to *add* modules
  to the crate Phase 0 already populated (with `EngineHandles`) rather than overwrite it.
- **No concrete `Provider` implementation existed anywhere in Phases 0-1.** Tracks B's
  Tasks 7-10 built only pure `encode`/`decode` codec functions; nothing bridged them to
  a live `HttpTransport` as a struct implementing `Provider` — `round daemon` could not
  talk to a real model even with Phase 1 fully executed. Fixed by adding a seventh track
  (Track G, Task 22) to the same Phase 1 plan: `ReqwestTransport` (the one sanctioned
  construction site for `reqwest::Client`, per §9.10's rule) and
  `AnthropicMessagesProvider` (bridging Tasks 9-10's codec to it), wired into
  `round daemon`'s `main.rs` to activate automatically when `ANTHROPIC_API_KEY` is set,
  falling back to Track F's fake otherwise. Task 22's own automated tests stay hermetic
  (a local TCP responder for the transport, `CassetteTransport` for the provider's
  shape); an actual live call is a documented manual smoke step, deliberately never
  CI-verified, matching §9.10's "live smoke" tier.
- **`SessionId`/`TaskId`/`WorkspaceId`/`TeamId` construction assumed a public inner
  field that doesn't exist.** Two different manifestations of the same root cause, both
  now fixed:
  - Phase 1 called a constructor method that was never defined —
    `SessionId::new_v4()`/`TaskId::new_v4()` — 10 places, fixed to `::new()`.
  - Phase 4, working from an assumed (and wrong) Phase 0 interface documented in its own
    "Assumed Phase 0 interfaces" section, used tuple-construction syntax —
    `SessionId(Uuid::new_v4())` and similarly for `WorkspaceId`/`TaskId`/`TeamId` — which
    doesn't compile against Phase 0's real types (their inner field is private; only
    `::new()`/`::from_uuid()` are public). 86 occurrences fixed to `::new()` across
    `docs/superpowers/plans/2026-08-27-phase4-subagents-messaging.md`, and that plan's
    "Assumed Phase 0 interfaces" section corrected to show the real (private-field)
    shape so it doesn't mislead a future reader. `MessageId` was untouched — it's a type
    Phase 4 defines itself with a genuinely `pub` field, so its tuple-construction was
    already correct.
- **Two missing dependency declarations in Phase 1's Task 12** — its own test uses
  `futures` and `tempfile`, neither declared anywhere in the task. Fixed by adding both
  to `roundhouse-engine`'s Cargo.toml edit in that task.

**Still open — needs a human decision or a follow-up task before/during execution:**
- **Two library APIs could not be verified against real documentation** — `rmcp`
  3.1.4's exact wire-level API (used in Phase 3's MCP host; the plan isolates the risk
  to a single hand-rolled transport file with a reconciliation note) and `sse-stream`
  0.2.5's exact constructor (used in Phase 1's SSE decoder tasks; flagged inline for the
  implementer to confirm before starting). Confirm both against real docs before
  executing those tasks.
- **`Quorum::All`'s resolution needs live roster size**, which the message-wait
  executor alone can't determine (Phase 4). Deliberately deferred to the tool-dispatch
  layer rather than mishandled — implement that resolution when building
  `agent_spawn`/`team_create`, not inside `roundhouse-bus` itself.

**Confirmed correctly load-bearing (no action needed, noted for visibility):**
- Phase 6's plan correctly wires both spec-mandated blocking gates: the dataset-licensing
  check (§9.7) gates dataset ingestion, and the Open Responses spec-verification gate
  (§9.4) is Task 5's literal Step 0, before any adapter code is written.
- Phase 2's plan resolved a latent contradiction between "any task left `Running` on
  crash is `Interrupted`" and §1.1's requirement that pending approvals survive a
  restart and re-arm: crash-recovery's `Interrupted` state applies only to
  `Created`/`Decided`/`Running` tasks; `Suspended*` tasks are re-armed through the
  attention-queue path instead, never wiped.

## 2026-08-28 audit remediation

An independent audit (`docs/audit-2026-08-27.md`, ~92 findings across all 14 architecture
docs and all 7 phase plans, verified by a second pass of dedicated review agents) found
real inconsistencies and gaps. All of them were fixed the same day:

- **Architecture docs (findings A1–A11, G9):** the `todo`/plan-tracking task kind,
  `report` added as a frozen `TaskKind`, the `job:<id>` memory-scope gap resolved by
  simplifying job continuity to report-seeding, the `Message` trigger redesigned to bind
  an `Address` instead of a topic string, the Phase 4/5 messaging traceability
  disagreement, the stale §14.4 open-items list, the context render-order duplication,
  the `roundhouse-daemon`/`roundhouse-cli` dependency-rule wording, the undefined
  Project-vs-Workspace config scope, the nonexistent `yolo` profile, and `insta`'s real
  Phase 1 start date — all fixed directly in the docs in this directory. A new §4.5 in
  `01-data-model.md` designs the retention/blob-store subsystem (content-addressed
  blobs, GC, per-workspace quota) that was previously only named, not specified.
  `roundhouse-secrets` and `roundhouse-conformance` were added to §5.2's crate table
  (same pattern as `roundhouse-config`'s original addition, above).
- **All 7 phase plans** were fixed against the corrected architecture and against each
  other's actual (not assumed) interfaces: every id-construction and id-field-access bug
  was swept (extending the tuple-construction fix below to Phase 3, which the original
  sweep missed, plus two new `.0`-field-access sites in Phase 4 found only during
  verification); every "built in isolation, never wired" mechanism (Phase 2's sealed
  floor, approval re-arm, and shell-pipeline check; Phase 3's policy gate; Phase 4's
  wait-graph interlocking, rate limiter, and message fan-out; Phase 5's report
  persistence and expression contexts) was wired into its real call path with an
  integration test; and every previously-unowned subsystem was designed and built into
  its owning phase: network policy and the shell-parser bake-off (Phase 2), `ApprovalPolicy`,
  OS-liveness units, and ACP v2 load-bearing details (Phase 5), team-memory wiring and
  human break-glass (Phase 4), and the remaining ~33 provider profiles (Phase 6, which
  went from 5 profiles to 38). Two further cross-phase type collisions surfaced only
  while doing this work (not in the original audit) and were fixed too: Phase 1's
  `RequestCtx`/`ChatStream` redefinitions were reconciled into single, real, in-place
  edits of Phase 0's placeholder types (Phase 0's own Task 7 explicitly hands this off to
  Phase 1), and a broader instance of the same bug in Phase 1's Task 12 (`Capabilities`/
  `Plan`/`TokenCount`/`ModelInfo`/`ProviderError`/the `Provider` trait itself, all
  redefined a second time with drifted shapes) was found and fixed the same way; Phase
  3's locally-invented 3-variant `MediaSource` enum was reconciled to Phase 0's real
  single-struct shape; and Phase 2's own richer `ProviderError` — needed for §9.8's
  retry/fallback classification but originally defined a second time at a different path
  (`roundhouse_provider::errors::ProviderError`) commented as "Phase 0/1's frozen type,"
  which it wasn't — was merged into Phase 0's real `ProviderError` (`ir.rs`) in place,
  the same pattern as `RequestCtx`/`ChatStream`, since it's the type every `Provider`
  adapter's methods actually return and classification has to produce that same type at
  the point an adapter calls it, not a parallel one downstream.
- **Recurring-pattern recommendation (extract a canonical Phase 0 surface reference):**
  rather than a separate document, each phase-plan fix was briefed directly against
  Phase 0's actual, current, corrected plan — read
  `docs/superpowers/plans/2026-08-27-phase0-contracts.md` itself as that reference; it
  is the single source of truth for every type Phase 0 delivers, the same role this
  README already assigns §5.2 for crate names.

## Provenance

This design was produced by a team of parallel research and design agents (protocol
research, Rust ecosystem survey, LLM provider survey, prior-art analysis, and dedicated
design passes on messaging, scheduling/workflows, security/sandboxing, the provider
abstraction layer, UI, and user stories), synthesized into one document, and reviewed
collaboratively with the project owner. Naming was resolved last, through a multi-round
collision search against crates.io and known projects, after the original `Sund-AI`
placeholder was found to collide with an existing MIT/Harvard-affiliated AI nonprofit
(Sundai). See [00-overview.md](00-overview.md#0-naming) for the full naming rationale.
