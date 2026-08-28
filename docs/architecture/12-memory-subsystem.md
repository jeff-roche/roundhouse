# Roundhouse Architecture — Memory Subsystem

> Scopes, team-memory read/write asymmetry, storage as audited plain files, how
> memory enters context, why writing memory is an explicit tool call rather than
> passive extraction, and concurrency handling.

## 15. Memory subsystem

*(Added during design review — this was the thinnest section of the initial draft; it had
inherited a schema from other sections without a dedicated design pass. Resolved here.)*

### 15.1 Scopes — three, not four

```rust
pub enum MemoryScope {
    User,                                // ~/.config/roundhouse/memory/*.md
    Project { workspace: WorkspaceId },  // <repo>/.roundhouse/memory/*.md
    Team { team: TeamId },               // shared blackboard, see §7.5
}
```

**No session scope.** A session's own task log already *is* its memory — a fourth scope
for "things this session wants to remember about itself" would just be a worse-audited
duplicate of the log that already exists.

```rust
pub enum MemoryOp { Read { key: Option<String> }, Write { key: String, content: String },
                    Append { key: String, content: String }, Delete { key: String }, List }
```

### 15.2 Team memory: read is membership, write is a grant

**Every member of a team gets read access to the team's memory scope as a side effect of
joining the roster — no separate grant needed**, since the entire point of a shared
blackboard is that teammates can see it (§7.3, §7.5). **Write access is a distinct,
explicit grant**, evaluated by the same policy engine as everything else (§6.2): a
`memory` task with `op: Write|Append|Delete` against `Team` scope goes through
`Policy::decide` like any other mutating action, and the sealed-floor precedence rules
apply identically — a sub-agent's write grant can only ever be a subset of what its
parent holds, never broader. This mirrors the read/write asymmetry that already exists
for file paths (§6.7's read-denylist vs write policy) rather than inventing a new
asymmetry just for memory.

### 15.3 Storage: plain files, audited writes

Consistent with everything else here being task-log-derived, but not identical to it:
**memory *writes* are Tasks** (audited, diffable, subject to policy), but **memory
*content* lives as plain text files on disk**, not buried in the SQLite event log. This
is a deliberate exception, mirroring Claude Code's `CLAUDE.md` convention: plain files
are diffable by hand, greppable, editable outside the tool, and survive independent of
the daemon's database. The event log records *that* a write happened and *what changed*
(old-content-hash → new-content-hash, per S-MEM-2); the file is the source of truth for
*current* content.

### 15.4 How it enters context

Memory blocks sit in the **pinned region** of context assembly. **This section is the one
place the render order is defined** (§9.3 quotes it for cache-breakpoint placement rather
than redefining it): system prompt → tool definitions → memory → compaction summary →
retained window → current turn. Memory blocks **survive compaction verbatim** rather than
being summarized away — this
directly targets a prior-art complaint (§1.1): agents forgetting project instructions
specifically because compaction swept them up along with everything else. Precedence on
conflict is `User → Project → Team`, narrower wins — the same "more specific wins"
direction as the policy engine's scope ranking (§6.2), kept consistent rather than
inventing a second precedence rule just for memory.

**Truncation is explicit, never silent.** If memory exceeds ~20% of the context window
(S-MEM-1), it truncates at a block boundary and stamps a `memory_truncated` warning on
the enclosing `infer` task — the same "degradation is a recorded event, never a silent
shrink" rule used everywhere else in this design (§6.5's isolation attestation, §9.7's
unknown-pricing handling).

### 15.5 Writing is a tool call, not passive extraction

Deliberately rejected: auto-extracting "things worth remembering" from a conversation.
That pattern goes stale, can contradict itself, and can write memory the human never
saw happen. Instead, every write is an explicit `memory` task the model chooses to make,
which means it is: visible in the task log at the moment it happens; subject to the
permission engine like any other write (`Denied` with `memory_scope_denied` per S-MEM-2
if ungranted); and diffable, since the write records the content-hash transition.

### 15.6 Concurrency

Real scenario in this architecture (unlike most single-session harnesses): multiple
parallel sessions writing the same memory file. Per S-MEM-3: an advisory file lock per
memory file, 5s acquisition timeout, read-modify-write under the lock, atomic rename on
write-out. A failed lock acquisition fails the task closed with `memory_locked` rather
than partially writing — the same "fail closed, never partial" instinct as `edit`'s
atomicity guarantee (S-TOOL-3).

### 15.7 Resolved from earlier open questions

- ~~Do sub-agents inherit team memory automatically, or must it be granted?~~ **Resolved
  (§15.2): read is automatic via membership; write requires an explicit grant.**
- ~~Should session-scoped memory exist?~~ **Resolved (§15.1): no — the task log already
  serves that purpose.**

---

*End of design. This design was reviewed and approved by the user, and split into the
architecture documents in this directory. All seven implementation phases (§13.2) have
corresponding task-by-task plans in `docs/superpowers/plans/`.*
