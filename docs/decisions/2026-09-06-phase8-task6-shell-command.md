# Phase 8 L1 Task 6 — model-facing shell command decisions

Status: accepted 2026-09-06

- The model-facing surface is a new `shell_command` tool. The existing `shell`
  tool remains the explicit argv/direct-exec surface and is not reinterpreted.
- A parsed command is admitted one resolved node at a time. The second (or any
  later) node cannot inherit an earlier node's approval.
- Phase 8 refuses commands containing pipelines or redirections. Pipe file
  descriptors and synthetic write tasks are deferred until a later task;
  silently dropping either would change command meaning.
- Phase 8 also refuses shell control-flow operators and multiline compound
  commands. Flattening `&&`, `||`, command lists, or loops into independent
  execs would execute branches a shell would skip.
- Phase 8 refuses grouping, function, coprocess, negation, and timed-command
  syntax as well. These AST forms are not flattened into independent execs.
- Unquoted glob metacharacters are refused until bounded, workspace-rooted glob
  expansion exists. Quoted or escaped wildcard characters remain literal argv.
- The classifier receives an empty `SessionEnv`. The daemon environment is not
  model input and must not become an implicit expansion channel.
