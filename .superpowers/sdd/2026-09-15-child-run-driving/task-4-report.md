# Task 4 Report: Parked Child Recovery and Parent Wake-up

## Delivered

- Added migration 0014's `workflow_child_call` association, keyed by child run
  id and containing only parent invocation identity, task identity, and join
  state. It has no resolved call input or secret provenance columns.
- Made child-run creation, the parent step checkpoint, child-session
  persistence, and the call association one transaction.
- Added flow APIs to insert, load, and idempotently mark an association joined.
- Added `DeliveryExecutor::continue_after_child_terminal`, which leaves parked
  children outstanding, joins terminal children exactly once, resumes the
  parent from its recorded call, and follows terminal ancestors.
- Kept `finish_run` as the owner of terminal run refund and spawn-tree release.

## Coverage

- `a_parked_child_keeps_its_parent_call_running_after_restart` verifies restart
  recovery retains the drawn grant, unfinished parent task, and live tree edge.
- `a_terminal_child_wakes_its_parent_once` verifies a completed child wakes the
  existing parent exactly once, produces one parent terminal, one refund, and
  no duplicate child run.
- `child_call_identity_round_trips_and_joins_once` verifies durable identity
  round-tripping and idempotent join-state transition.

## Verification

- `cargo fmt --all -- --check`
- `cargo test -p roundhouse-daemon scheduler_driver::delivery_tests::a_parked_child_keeps_its_parent_call_running_after_restart -- --exact`
- `cargo test -p roundhouse-daemon scheduler_driver::delivery_tests::a_terminal_child_wakes_its_parent_once -- --exact`
- `cargo test -p roundhouse-flow --test ledger`
- `cargo test --workspace`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`

## Fix Round 1 Ruling

`workflow_child_call` remains the sole durable identity for a `call:`. Migration
0015 adds an expiring compare-and-swap continuation lease to that association:
only `available`, or an expired `claimed`, row can elect a resumer; only that
resumer's opaque token can release or complete it. A failed resumer releases
the lease immediately. A process that dies after claim leaves a bounded lease,
which a later boot may reclaim after expiry. A completed continuation is never
claimed again.

The call's redacted `TaskCreated` is now appended by
`WorkflowSessionTree::persist_parent_call_task` in the same transaction as the
child session, child run, parent step checkpoint, and association. The normal
daemon buffered sink explicitly suppresses that already-persisted event;
in-memory sinks retain it for flow-level observability. Resumption begins at
`Resume::Work` but runs through `DeliveryExecutor::drive_run_to_completion`,
so later tool, agent, and nested-call pending segments use the ordinary driver.

Restart tests build new `DaemonResources`, a new `SpawnTree`, and new session
and admission registries, then call `boot::reconcile_spawn_tree_at_boot` before
the continuation. This is the production boot reconciliation helper, not a
reused live tree. No gate-answer routing was added.

## Fix Round 1 TDD Evidence

RED, before the implementation:

- `cargo test -p roundhouse-daemon scheduler_driver::delivery_tests::a_call_task_creation_rolls_back_with_its_child_association -- --exact`
  failed at the child-run assertion: `left: 1`, `right: 0`. The old separate
  buffered append left a durable child association after the task write trigger
  rejected `TaskCreated`.
- `cargo test -p roundhouse-daemon scheduler_driver::delivery_tests::concurrent_child_continuations_drive_the_following_effect_once -- --exact`
  failed with `the first continuation reaches its following effect`, `left: 0`,
  `right: 1`. The old one-segment resumer returned `AwaitingWork` instead of
  invoking the segmented dispatcher.
- `cargo test -p roundhouse-daemon scheduler_driver::delivery_tests::an_expired_continuation_claim_retries_after_a_crash_between_join_and_resume -- --exact`
  failed with `the child task was joined before parent resumption`, `left: 0`,
  `right: 1`. There was no durable continuation claim or post-join hand-off
  point to survive.

GREEN after the implementation:

- `cargo test -p roundhouse-daemon scheduler_driver::delivery_tests::a_call_task_creation_rolls_back_with_its_child_association -- --exact`
- `cargo test -p roundhouse-daemon scheduler_driver::delivery_tests::concurrent_child_continuations_drive_the_following_effect_once -- --exact`
- `cargo test -p roundhouse-daemon scheduler_driver::delivery_tests::an_expired_continuation_claim_retries_after_a_crash_between_join_and_resume -- --exact`
- `cargo test -p roundhouse-daemon scheduler_driver::delivery_tests::a_parked_child_keeps_its_parent_call_running_after_restart -- --exact`
- `cargo test -p roundhouse-daemon scheduler_driver::delivery_tests::a_terminal_child_wakes_its_parent_once -- --exact`
- `cargo test -p roundhouse-flow --test run_loop`
- `cargo test -p roundhouse-flow`

## Fix Round 1 Parent Session Correction

Parent continuation reconstructs its headless session from the parent run's
own durable `SessionCreated`, never from the child session. Scheduled root
runs now append that lifecycle event before their first drive, so the parent
session definition exists across a process restart just as a workflow child
session's does. This does not add a gate-answer path or change continuation
ownership.

The concurrent continuation regression uses different parent and child jobs,
and asserts their durable session definitions differ (`parent: None` versus
the child's link to that parent). It rebuilds resources and reconciles the
spawn tree, completes the child gate, races a second continuation against the
first, and proves the following parent `read` is dispatched exactly once.

TDD evidence:

- RED: after the regression asserted the parent lifecycle definition, it failed
  with `session must have a SessionCreated event`; scheduled root sessions had
  no durable lifecycle event to reconstruct after restart.
- GREEN: `cargo test -p roundhouse-daemon --lib
  scheduler_driver::delivery_tests::concurrent_child_continuations_drive_the_following_effect_once
  -- --exact` passes after persisting the root event and loading the parent
  session's event stream.

## Fix Round 2 Ruling And TDD Evidence

An active continuation claim is now non-expiring. `claimed` rows can become
`available` only when the claim holder returns an ordinary error, or during
`boot::reconcile_spawn_tree_at_boot`; boot is the only point at which an old
holder is known unable to execute parent effects. Migration 0016 removes the
lease-expiry column. Claim tokens still fence release and completion, and a
completed continuation remains permanently ineligible.

Root `workflow_run` insertion and its root `SessionCreated` event are now one
transaction in `DeliveryExecutor::run_claimed_delivery`. A rejected lifecycle
write therefore leaves no durable run that continuation could not reconstruct.

RED, before the Round 2 implementation:

- `a_long_held_continuation_claim_cannot_be_stolen` advanced its test clock by
  31 seconds while the first continuation was blocked. A second continuation
  reached the same parent-effect gate (`left: 2`, `right: 1`), proving the old
  lease could steal live execution.
- `root_run_creation_rolls_back_when_its_session_lifecycle_is_rejected` failed
  with `left: 1`, `right: 0`: the standalone root-run commit survived a trigger
  rejecting `SessionCreated`.
- `an_incomplete_continuation_claim_retries_only_after_boot_reconciliation`
  failed after it aborted the claimant, rebuilt resources, and invoked real
  boot reconciliation: the old claim remained unavailable because boot did not
  reclaim it.

GREEN after the Round 2 implementation:

- `cargo test -p roundhouse-daemon --lib
  scheduler_driver::delivery_tests::a_long_held_continuation_claim_cannot_be_stolen
  -- --exact`
- `cargo test -p roundhouse-daemon --lib
  scheduler_driver::delivery_tests::root_run_creation_rolls_back_when_its_session_lifecycle_is_rejected
  -- --exact`
- `cargo test -p roundhouse-daemon --lib
  scheduler_driver::delivery_tests::an_incomplete_continuation_claim_retries_only_after_boot_reconciliation
  -- --exact`
