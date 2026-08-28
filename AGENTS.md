# AGENTS.md

Guidance for coding agents working in this repository.

## Project status

Phase 0 implementation in progress: Task 1 (Cargo workspace skeleton) is complete;
Tasks 2–14 remain. `docs/architecture/` is the frozen design (committed, reference
truth). `docs/superpowers/plans/`, `docs/audits/`, and `docs/scratch/` hold the
phase-by-phase implementation plans, audit findings, and scratch notes — they exist
locally but are gitignored, so don't expect them on a fresh clone. Phase 0
(`docs/superpowers/plans/2026-08-27-phase0-contracts.md`) creates the workspace
and the shared contracts every later phase depends on.

## Commands

The Cargo workspace exists and builds as of Task 1. Standard commands now apply:

- Build everything: `cargo build --workspace`
- Test everything: `cargo test --workspace`
- Test one crate: `cargo test -p <crate-name>`
- Run one test file in a crate: `cargo test -p <crate-name> --test <test_name>`

## Architecture

- **The core bet:** make the *task* — not the chat message — the unit of
  record. Every interaction and every action is a typed, addressable,
  persisted `Task`, so a session is a queryable log, sub-agents are child
  sessions you can open, and per-task provider selection is a field rather
  than a process boundary. Full rationale, including the specific bugs in
  other agent harnesses this is designed against:
  [`docs/architecture/00-overview.md`](docs/architecture/00-overview.md).
- **Core nouns**, forming a tree: `Workspace` → `Session` → `Task` (a `Task`
  can spawn a child `Session` as a sub-agent). `Team` is a set of sessions
  that can address each other; `Trigger` starts a session or workflow run.
  (`docs/architecture/00-overview.md` §3.1)
- **Everything is event-sourced.** Each session has one append-only `Event`
  log (`Event`/`EventPayload`/`Delta`, defined in `roundhouse-core`); `Task`
  and `Session` state are folds over it, never mutated in place. The
  `events` table physically rejects `UPDATE`/`DELETE`, and a source scan
  fails the build on any raw SQL string that tries. See
  [`docs/architecture/01-data-model.md`](docs/architecture/01-data-model.md).
- **18-crate Cargo workspace**, with crate boundaries doubling as
  agent work-assignment boundaries — one crate, one owner, minimal shared
  mutable state.
  [`docs/architecture/02-system-architecture.md`](docs/architecture/02-system-architecture.md)
  §5.2 is the single source of truth for crate names and the dependency
  table; treat any other doc's crate name as a typo if it disagrees.
  `roundhouse-core` is the zero-I/O, zero-async root everything else depends
  on transitively; `roundhouse-daemon` and `roundhouse-cli` are the only two
  crates allowed to depend on the rest — nothing else may depend on them.
  `#![forbid(unsafe_code)]` everywhere except one confined module in
  `roundhouse-sandbox`.
- **Seven build phases**
  ([`docs/architecture/10-implementation-phasing.md`](docs/architecture/10-implementation-phasing.md)):
  Phase 0 (contracts, blocks everything) → Phase 1 (vertical slice) →
  Phase 2 (robustness) → Phases 3/4 in parallel (MCP host; sub-agents +
  messaging bus) → Phase 5 (ACP, triggers/workflows, web UI) → Phase 6
  (provider breadth, highest parallelism ceiling). Each phase has its own
  task-by-task TDD plan in `docs/superpowers/plans/`.

## Working in this repo

- `docs/architecture/` is frozen design, not a living spec — edit it
  deliberately and keep documents consistent with each other.
- If a task's assumed interface conflicts with what a frozen contract
  actually looks like, that's an escalation, not something to silently
  paper over (`docs/architecture/10-implementation-phasing.md` §13.3).
