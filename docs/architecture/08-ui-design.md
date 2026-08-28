# Roundhouse Architecture — UI Design: TUI + Web

> One object model and one route table shared by both clients; the TUI's in-process
> multiplexing approach; the web UI's SolidJS/SSE stack embedded in the `round`
> binary; and the hard interaction moments (batch approval, interrupt/queue/steer,
> triaging overnight runs). See
> `docs/superpowers/plans/2026-08-27-phase1-vertical-slice.md` (TUI attach+render) and
> `docs/superpowers/plans/2026-08-27-phase5-acp-triggers-workflows-web.md` (web UI).

## 11. UI design: TUI + web

### 11.1 One object model, one route table, two renderers

Every view is addressable by a route shared by both clients, so a TUI keybinding and a
web URL resolve to the same thing and permalinks are trivial:
`/w/:ws`, `/w/:ws/inbox`, `/w/:ws/s/:session[/t/:task[/diff]]`, `/w/:ws/tree`,
`/w/:ws/messages`, `/w/:ws/runs`, `/w/:ws/search`, `/w/:ws/cost`, `/settings/...`.

| View | TUI | Web |
|---|---|---|
| Dashboard / attention inbox | ✅ primary | ✅ |
| Session detail / task log | ✅ | ✅ |
| Diff review | ✅ unified, hunk-staged | ✅ side-by-side, word-level |
| Session tree | ✅ indented outline | ✅ laid-out graph |
| Message timeline | ⚠️ list only | ✅ swimlanes (needs 2D) |
| Cost/usage | ⚠️ tables + sparklines | ✅ charts |
| Settings/providers | ⚠️ read + toggle | ✅ full editor (secrets belong in a form) |
| Compare sessions / share / permalink | ❌ | ✅ |

### 11.2 TUI: multiplex in-process, don't delegate to tmux

The daemon already holds every session's summary in one process — tmux panes would
duplicate connections and can't express the attention queue (tmux cannot tell you which
of 12 panes is blocked). tmux is a *window* manager; the hard problem here is *attention*
management. We ship a deliberately small pane system — **at most two side-by-side panes
plus a modal layer** — not a tiling WM; that complexity buys nothing and costs every
keybinding. `round attach <session>` gives a single-session, no-chrome mode for people who
want Roundhouse to compose inside their own tmux layout.

**Dashboard** (attention band always on top, session list below, sub-agents indented
`└`, cost/tier/tokens per row) → **session detail** (chat turns as the collapsible
grouping unit; running tasks show a phase spinner and live tail; long output caps at 3
tail lines with `O` to expand; sub-agents render inline as a nested collapsible child
session with a provider badge and `→ s-xxxx` link) → **task detail**.

**Glyph vocabulary**, degrading to ASCII under `--no-unicode` and to reverse-video under
`NO_COLOR` (status is glyph-first and never color-only): queued `▪`/`.`, running
`▶`+spinner, ok `✓`/`+`, failed `✗`/`x`, blocked-on-human `!` (bold+reverse), blocked-
on-peer `⇄`/`<>`, cancelled `⏸`/`#`, denied `⊘`/`-`.

**Keybindings: modal (vim-like) with `Space` as leader**, not chorded — chorded `Ctrl-*`
collides with tmux/terminal/flow-control bindings and caps out around 20 memorable
bindings; modal gives a `:` palette, a which-key overlay, and lets destructive verbs sit
behind mode+leader so a stray keystroke never approves a migration. `[`/`]` prev/next
session, `{`/`}` prev/next *blocked* session, `Space a/s/t/m/r//` for inbox/sessions/
tree/messages/runs/search, `Space y`/`Y` quick-approve once/always **(gated to risk
class ≤ MEDIUM — a HIGH-risk item always forces the full modal, no one-keystroke path
around it)**, `Esc` soft interrupt, `Esc Esc` hard cancel. The gate is the same
principle already applied to `Opaque` shell commands (§6.3): a fast keystroke is exactly
the review a human is worst at for anything genuinely risky, so the design removes the
shortcut rather than trusting care in the moment.

**Streaming without flicker.** Dirty-flag regions (`ATTENTION`, `SESSION_LIST`, `LOG`,
`COMPOSER`, `STATUS`) + a 16ms render tick that does nothing when nothing is dirty —
an idle 12-session dashboard costs zero syscalls. Token deltas append into a per-task
rope; the dashboard subscribes to coalesced 4Hz session summaries, and **full delta
streams are subscribed only for the focused session, any split pane, and any session
with a blocked task** — the daemon does the aggregation, not the TUI, so 200 sessions
stays cheap.

**Mouse policy: emit `CSI ?1000h ?1006h` ourselves, never call `EnableMouseCapture`.**
Crossterm's helper also sets `?1002h`/`?1003h` (motion reporting), which is what destroys
native drag-select and middle-click paste — the exact regression Claude Code had to ship
an escape hatch for. Our narrower policy keeps wheel and click while drag-select and
paste survive untouched. Explicit copy via **OSC 52** (`y`/`Y`/`c`) since the TUI lives in
the alt screen. **This is a working default gated on empirical verification, same
pattern as the shell-parser bake-off (§6.3):** confirm `?1000h`-only actually delivers
wheel+click without motion-reporting side effects across Alacritty, kitty, Windows
Terminal, GNOME Terminal, and tmux/screen before shipping it as the default. The
fallback is already documented, not something to invent later — in any terminal where
`?1000h` still intercepts button-1 drag, `Shift`+drag is the universal bypass, surfaced
in the status bar the first time a user drags.

**Approval prompt** shows the exact argv verbatim (never reflowed or re-quoted), daemon-
computed risk flags as a short bullet list (not prose), and precedent ("3× this exact
argv approved this session"). Five stable options in fixed key order: once / always-
this-pattern / always-this-exact-argv / reject / reject-always. `t` opens the argv in the
composer for edit-then-run — approving runs *your* edited version and tells the agent.

**Blocked/wait panel** renders deadlock cycles as a cycle diagram, not a list, with
one-keystroke resolutions: reply on behalf of one side, release, cancel, or broadcast one
fact to both (resolves most real cases in a single keystroke). The daemon runs cycle
detection (§7.7); the UI never infers it.

### 11.3 Web: SolidJS, SSE, embedded in the `round` binary

**SolidJS** over React: token streams are the dominant update pattern, and fine-grained
signals patch one text node per delta with no VDOM diff — the difference between 6
streaming sessions being free and being a fan event — plus a ~15KB runtime that matters
embedded in the single `round` binary via `rust-embed` — the daemon is a subcommand of
that same binary (§0), so "the web UI is available" is just "the daemon is running."
CodeMirror 6 for diffs, dagre+SVG for the
session-tree graph, uPlot for cost charts. No component framework or SSR.

**What the web UI does that the TUI structurally cannot:** side-by-side word-level diffs
with inline comments that feed back as tool results; a real laid-out session-tree graph
(size=spend, edges=messages, color=provider) where an outline can't show 40-node fan-out;
**cross-session message swimlanes** (time on x, sessions as lanes, blocked spans hatched,
deadlock cycles highlighted in red) — the single strongest argument for a web client;
cost charts; synchronized-scroll session comparison; shareable read-only permalinks.

**Transport: SSE server→client, POST client→server**, not WebSocket — SSE's `Last-Event-
ID` maps directly onto the `(session_id, seq)` cursor already required for crash
recovery, survives proxies that break WS upgrades, and client→server traffic is low-rate
request/response shaped. **Resync**: the daemon keeps a ring buffer of the last 4096
events per session; on reconnect it replays the gap, or if the cursor is older than the
ring's tail, emits `resync_required` and the client refetches a snapshot. The TUI uses
the identical `(session_id, seq)` semantics over the Unix socket — one resync contract,
two transports.

**Access scope for v1: lightweight LAN access, not loopback-only and not full remote
auth.** Binding beyond `127.0.0.1` is opt-in (a flag, off by default — loopback-only
remains what you get with no configuration), and when enabled it's gated by a **shared
token** entered once per device, generated into the state dir the same way the existing
loopback token already is (§6.4's approval-flow token pattern) — no login system,
no session management, no TLS by default. This deliberately assumes a trusted LAN, the
same trust boundary a home NAS or a local dev server already relies on, and answers the
actual want ("check overnight runs from my phone on my own network") without building
real remote-auth infrastructure a v1 doesn't need. Exposing the daemon beyond a trusted
LAN (over the internet, via a reverse proxy) is explicitly not this — that's the "full
remote auth" tier this decision deliberately defers, and it should be revisited only if
real demand for it shows up.

### 11.4 The hard interaction moments

- **Batch approval.** The daemon computes a **decision signature** (tool + normalized
  argv + risk class + target host/path class); identical signatures collapse into one
  inbox row (`×5`) with one decision applying to all. A HIGH-risk item forces sequential
  review even inside a multi-select.
- **Interrupt vs queue vs steer** are four distinct, unambiguous inputs: `Esc` (soft —
  finish in-flight, don't start next), `Esc Esc` (hard cancel), type+`Enter` (queue,
  delivered as the next turn), type+`Ctrl-Enter` (steer now — injected at the next tool
  boundary without killing in-flight work).
- **Triaging 50 overnight runs.** A dedicated Runs view bucketed by *what it needs from
  you* (`NEEDS YOU` / `FAILED` / collapsed `NO-OP` / `LANDED`), not chronology. **The
  rule: no-op runs must cost zero attention** — aggressive default collapsing plus a
  fixed rhythm (`d` diff → `m` merge → auto-advance) is what makes 34 no-op nightly runs
  readable in one line.
- **Cross-provider sub-agent.** The picker is provider-first; the child renders as a
  split pane with its own footer (provider, tokens, cost) so the cost asymmetry between
  a paid parent and a free local child is legible at a glance.

### 11.5 Open questions

~~Quick-approve safety.~~ **Decided (§11.2): yes, gate `Space y` to risk ≤ MEDIUM** —
same principle as the `Opaque` shell-command decision (§6.3): remove the one-keystroke
shortcut for anything genuinely risky rather than trust care in the moment.

~~Web auth for remote/mobile access.~~ **Decided (§11.3): lightweight LAN access for
v1** — opt-in binding beyond loopback, gated by a shared per-device token, no login
system or TLS by default. Deliberately assumes a trusted LAN, the same boundary a home
NAS already relies on. Full remote auth (real login/sessions, TLS, beyond-LAN exposure)
is explicitly deferred, revisited only on real demand.

~~Mouse policy verification.~~ **Gated (§11.2), same pattern as the shell-parser
bake-off:** verify `?1000h`-only across real terminals before shipping as default;
`Shift`+drag is the already-documented fallback where it doesn't hold.

~~Grant persistence scope across sub-agents.~~ **Resolved (§6.1, §6.4):** a `Session`
grant flows down to children spawned afterward only — never up to the parent or sideways
to siblings; anything broader is the existing explicit `GrantScope::Always` path.



