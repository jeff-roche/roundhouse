# Roundhouse

Roundhouse is a local-first Rust daemon supervising many concurrent AI-agent
sessions, driven from a terminal UI and a web UI, speaking to any LLM
provider, with every action recorded as a first-class, typed, queryable
**Task** in an append-only event log.

The CLI binary is `round`. The daemon is `round daemon` — the same binary,
not a second one.

## Status: pre-Phase 0

This repository currently holds the frozen design only — there is no Cargo
workspace, no crates, and nothing to build yet. Phase 0
(`docs/superpowers/plans/2026-08-27-phase0-contracts.md`, present locally but
not checked in — see below) is what creates the workspace and the shared
contracts every later phase builds against.

## Why Roundhouse

Existing agent harnesses (Claude Code, OpenCode, Crush, Goose, Codex CLI) are
one conversation at a time, in one terminal, against one vendor's loop.
Roundhouse's bet is that making the *task* — not the *message* — the unit of
record fixes three things bolted on everywhere else: parallel sub-agents are
opaque black boxes, the transcript is a chat log instead of a queryable
record, and provider choice is a per-process decision instead of a per-task
field. See [`docs/architecture/00-overview.md`](docs/architecture/00-overview.md)
for the full rationale, including the specific harness bugs this design is
built to avoid.

## Documentation

The full design lives in [`docs/architecture/`](docs/architecture/), split
by topic; start at [`docs/architecture/README.md`](docs/architecture/README.md)
for the reading order and the crate-by-crate implementation phasing.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
