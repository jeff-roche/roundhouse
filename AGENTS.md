# AGENTS.md

Guidance for coding agents working in this repository.

## Project status

Phase 0 and Phase 1 are both complete. Phase 0 landed all 14 tasks of
`docs/superpowers/plans/2026-08-27-phase0-contracts.md`: the 18-crate Cargo workspace exists
with every downstream crate wired against Phase 0 stub traits, event-sourcing and S-LOG
properties are enforced at the type and schema levels, layered config loading with
`roundhouse-config` is real, and content-addressed blob storage (`BlobRef`, `blobs` table,
`write_blob`/`read_blob`, GC eligibility, quota rejection) is wired into
`roundhouse-core`/`roundhouse-store`. Phase 1 landed all 22 tasks of
`docs/superpowers/plans/2026-08-27-phase1-vertical-slice.md`: the full vertical slice now
runs end to end — `roundhouse-cli`'s `round` TUI attaches over a Unix socket to
`roundhouse-daemon`, whose `TaskRunner` (`roundhouse-core`) records every action as
event-sourced `chat`/`infer` tasks folded by `roundhouse-store`, driven by
`roundhouse-engine`'s `run_chat_turn`, dispatching to `roundhouse-tools`' executors
(`read`/`write`/`edit`/`find`/`shell`), and backed by a real `Provider` implementation
(`roundhouse-provider`'s `AnthropicMessagesProvider`) when `ANTHROPIC_API_KEY` is set.
Phase 2 (robustness) is next per `docs/superpowers/plans/2026-08-27-phase2-robustness.md`.
`docs/architecture/` is the frozen design (committed, reference truth).
`docs/superpowers/plans/`, `docs/audits/`, and `docs/scratch/` hold the phase-by-phase
implementation plans, audit findings, and scratch notes — they exist locally but are
gitignored, so don't expect them on a fresh clone.

### Running what Phase 1 built

`roundhouse-daemon`'s binary (`round-daemon-internal`) runs one scripted demo session on
startup — real event log, real `chat`→`infer` task tree, one scripted `edit_file` call —
then serves the results to exactly one attached client over a Unix socket
(`$ROUND_SOCKET`, default resolved by `roundhouse_tui::default_socket_path`). In one
terminal:

```
cargo run -p roundhouse-daemon --bin round-daemon-internal
```

With no `ANTHROPIC_API_KEY` set (the default, and what CI relies on), it runs fully
offline against `roundhouse_daemon::demo::FakeEditProvider` — zero outbound connections.
Export a real `ANTHROPIC_API_KEY` first to exercise the live `AnthropicMessagesProvider`
path instead. In a second terminal, attach with the TUI client to watch the session's
task log stream in over the socket:

```
cargo run -p roundhouse-cli --bin round
```

See `crates/roundhouse-daemon/src/demo.rs` and `crates/roundhouse-daemon/src/main.rs` for
the actual wiring, and `crates/roundhouse-daemon/tests/exit_criterion_demo.rs` for the
scripted end-to-end test this exit criterion is pinned against.

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
- **20-crate Cargo workspace** (18 at Phase 0 completion; Phase 2 added
  `roundhouse-secrets` and `roundhouse-net`), with crate boundaries doubling as
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
