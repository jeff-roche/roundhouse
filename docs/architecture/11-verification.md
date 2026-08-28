# Roundhouse Architecture — Verification

> What "done" means for the design itself, the consistency check performed across
> sections, and how the implementation gets verified once it exists.

## 14. Verification

### 14.1 What "done" means for this design

This document is a design, not code — there is nothing to run yet. Verification here
means two things: (a) internal consistency — do the sections agree with each other and
with `CONCEPT.md` — and (b) a concrete plan for how the *implementation* will be verified,
since §12's user stories were written as test-ready acceptance criteria specifically so
this section can point at them rather than re-deriving a test strategy.

### 14.2 Consistency check performed

- **Task kinds** (§4.2) cover every kind named in `CONCEPT.md`, either directly or via an
  explicit, documented mapping — `todo` maps onto `plan` (§4.2's note under the kind
  table), and "open agent plugin protocol"/per-agent process-vs-in-process spawning are
  recorded as deliberate v1 cuts rather than silently dropped — plus the kinds later
  sections required (`infer`, `compact`, `checkpoint`, `plan`, `elicit`, `flow`, `report`)
  — each addition is justified inline (§4.2's "why `infer` is a task kind" note, and
  `report`'s role as the mandatory workflow/job terminal task, §8.6) rather than silently
  expanding scope.
- **The `message` task kind** (§4.2) matches the schema in §7.6, and the `agent` task kind
  matches the spawn semantics in §7.2/§7.7 and S-TOOL-8/S-SESS-7.
- **Isolation tiers** are defined once (§6.5) and referenced consistently by §8.5
  (unattended jobs default to worktree-or-higher), §9.9 (sub-agent credential scoping,
  resolved via §6.1's spawn-boundary rule — never inherited, gated by the parent's own
  policy scope), and the TUI's tier glyph column (§11.2).
- **The permission `Decision` type** is defined once (§6.2) and both ACP directions
  (§10.2's table), the unattended-job escalation policy (§8.5), and the TUI approval
  prompt (§11.4) map onto it rather than defining their own.
- **Cost accounting** is asserted exactly once to be a derived view over
  `(usage, pricing_snapshot_id)`, never a stored column (§9.7), and §12's S-OBS-1 acceptance
  criteria were written to match that ("rollups are computed, never stored, so they cannot
  drift").
- **The four failure-taxonomy bugs from §1.1** each have a corresponding design rule
  cited inline, and each also has a corresponding P0 user story with acceptance criteria
  (§12.4) — so the lesson from prior art is traceable all the way to a test.

No contradictions were found between sections; the open-questions lists (end of §6, §7,
§8, §9, §10, §11) are where genuine unresolved decisions live, and are deliberately not
papered over.

### 14.3 How the implementation gets verified

1. **Structural invariants, enforced by tests that cannot be bypassed by convention**
   (§13.3): the `TaskRunner` private-constructor pattern for S-LOG-1, the append-only
   SQLite trigger plus source-scan for S-LOG-2, `isolation_tier_achieved` presence on every
   task row for S-ISO-1/2. These are Phase 0 deliverables, not late additions.
2. **The conformance suite** (§9.10) is the primary verification mechanism for the highest
   agent-parallelism surface (23 provider adapters) — golden snapshots a human can review
   in minutes, cassette replay at adversarial chunk boundaries, and a generic
   param-mask-enforcement property test that catches the Kimi-class correctness bug for
   every adapter for free.
3. **The user stories in §12 are the acceptance-test source of truth.** Every P0/P1 story
   has Given/When/Then criteria with concrete numbers (§12.5's non-functional budgets) —
   an implementing agent writes the test from the story directly, and a reviewing agent or
   human checks the test against the story, not against prose.
4. **Adversarial review for security-critical crates** (§13.3): a second agent explicitly
   tasked with defeating the shell parser (§6.3's bake-off), finding a fail-open isolation
   path (§6.5's four anti-fail-open rules), or finding a secret leak into the log (§6.7's
   redaction pass) before those crates merge.
5. **End-to-end demo gates per phase** (§13.2's exit criteria) — Phase 1 ends when a human
   can watch a real session edit a file through the TUI; later phases have equivalent
   concrete, observable exit criteria rather than "the code is written."
6. **Fixed reference hardware for non-functional numbers** (§12.5: 8-core/32GB/NVMe/
   Linux 6.x) so performance budgets are testable assertions in CI, not aspirational
   claims — this was a deliberate requirement placed on the user-stories work rather than
   left to be improvised later.

### 14.4 Open items carried forward (not resolved here, tracked for the next step)

*(Updated 2026-08-28 — this list was stale: every item below it previously carried
forward is now decided or gated in its home section, not open.)* The shell-parser
bake-off and Opaque-approval UX (§6.12), inbound-message interruption semantics (§7.9),
report-schema extensibility and cross-tree cost rollup (§8.14), the Open Responses
`2026-04-24` field-level verification (§9.11), and the ACP v1/v2 compatibility question
(§10.4) are all **decided or gated**, not open: §6.12 locks `brush-parser` with a
numeric fallback rule; §7.9 decides inbound messages never interrupt mid-turn; §8.14
decides report schema is core+extension and cost rollup is a real enforced transfer;
§9.11 gates Open Responses verification to just before that adapter is written, contained
to one codec; §10.4 explicitly decides **no static v1/v2 compatibility table will be
built** — the protocol's own `initialize` handshake answers it live. What remains
genuinely open is not a design question at all but **implementation-time verification**:
run the shell-parser bake-off against a real corpus (Phase 2), verify Open Responses
against its published spec before that adapter is written (Phase 6), and confirm the
Open Responses/`sse-stream` library APIs against real docs before their tasks start (see
`docs/architecture/README.md`'s "Still open" list). None of this blocks starting Phase 0.

**Resolved during review, via one unifying rule (§6.1):** sub-agent taint propagation
(§6.8), sub-agent credential scoping (§9.9), approval-grant scope across sub-agents
(§6.4), and team-memory read/write access (§15.2) looked like four independent
open questions but were the same question — "what does a child inherit from its
parent, and what flows back on return" — asked four times. The answer is now one
sentence, stated once in §6.1 and applied consistently at each site: capabilities
(spend, mutate, escalate) never flow automatically and never exceed the parent's own
grant; restrictions (taint, denial rules) flow automatically and only ever tighten.

---

