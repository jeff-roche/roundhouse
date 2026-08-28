# Contributing

## Where things stand

This project is pre-Phase 0: [`docs/architecture/`](docs/architecture/) is a
frozen design, reviewed section-by-section, and treated as reference truth —
changes to it should be deliberate and kept consistent across documents (the
same bar the design held itself to; see the audit-remediation log in
[`docs/architecture/README.md`](docs/architecture/README.md)). If you find a
gap or inconsistency while implementing against it, that's worth flagging
explicitly rather than silently working around.

## How implementation proceeds

Each of the seven build phases in
[`docs/architecture/10-implementation-phasing.md`](docs/architecture/10-implementation-phasing.md)
has a task-by-task, test-driven implementation plan. Phase 0 must land before
anything else starts — it produces the shared types every other crate
compiles against. Within a plan, each task follows the same cycle: write a
failing test, confirm it fails for the expected reason, write the minimal
implementation, confirm the test passes, commit.

If an assumed interface turns out to conflict with a frozen contract from an
earlier phase, treat that as something to resolve deliberately, not to patch
around unilaterally — the value of freezing Phase 0's types is that later
phases can rely on them not moving underneath them.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/) style
(`feat:`, `feat(core):`, `fix:`, etc.), matching the convention already used
in the phase implementation plans.

## License

By contributing, you agree that your contributions will be licensed under
the [MIT license](LICENSE).
