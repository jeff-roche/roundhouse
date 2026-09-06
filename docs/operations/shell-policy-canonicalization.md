# Shell policy: what a `program` allow/deny rule actually matches

This is operator-facing, not architecture reference (`docs/architecture/` is
frozen design and out of scope for this note) — it documents a real,
operator-visible behavior of `Predicate::Shell` rules that is easy to get
wrong when hand-writing policy config, first identified as carry-forward
CF-16 and pinned precisely by ruling W1-R75.

## The rule

When the engine dispatches a shell task, the `program` it judges policy
against (`roundhouse-engine`'s `tool_dispatch.rs::resolve_shell_program`) is:

> **the canonicalized DIRECTORY containing the binary, joined with the
> LITERAL, model/PATH-supplied final path component — never a fully
> symlink-resolved path.**

This is *not* the same as running `readlink -f` (or any other full-resolution
tool) on the binary yourself. Two concrete consequences:

### 1. Relative allow rules stop matching once `cwd` is canonicalized

A rule written against a relative program string —
`Predicate::Shell { program: "./gradlew", .. }` or
`"./scripts/build.sh"` — no longer matches the value the engine actually
judges, because the directory half of that value is always canonicalized.
This is deliberate and fail-closed: a relative program allow-rule now denies
rather than silently matching a directory the model's own choice of `cwd`
could otherwise steer.

**If your policy config has an allow rule for a relative shell program,
rewrite it against the canonicalized directory + literal final component
shape described above, not the relative string you used to write.**

### 2. `readlink -f` does not produce a string that matches

An operator who canonicalizes a binary fully (following the *final*
component's own symlink too) gets a *different* string than the one policy
sees. Measured on a real dev environment:

| Command you might run  | What `readlink -f` reports | What policy actually judges |
|---|---|---|
| `readlink -f $(which sh)`     | `/usr/bin/bash`      | `/usr/bin/sh` (directory resolved, name preserved) |
| `readlink -f $(which python3)`| `/usr/bin/python3.14`| `/usr/bin/python3` |
| `readlink -f $(which awk)`    | `/usr/bin/gawk`       | `/usr/bin/awk` |

Do not rewrite a rule to the fully-resolved `readlink -f` output — that
string will not match either. Use the canonicalized-directory-plus-literal-
final-component value, exactly as `resolve_shell_program` builds it.

## Why this shape, briefly

Canonicalizing only the directory (not the final component) is what defeats
a model-controlled `cwd` from redirecting a relative program to a different
binary, while still preserving basename-based matching
(`is_interpreter`/`sealed_program`) — resolving the final component's own
symlink (e.g. `python3` → `python3.14`) would silently defeat that basename
matching the moment an operator "helpfully" rewrote a rule to the fully
resolved path. See `roundhouse-engine/src/tool_dispatch.rs`'s own doc
comment on `resolve_shell_program` for the complete rationale, including why
absolute program strings are handled differently from relative ones for
workspace containment purposes.
