# Roundhouse Architecture — Protocol Surfaces: ACP and MCP

> How Roundhouse implements the ACP client role, the ACP server role, and the MCP
> host role, and how all three map onto the internal event model. See
> `docs/superpowers/plans/2026-08-27-phase3-mcp-host.md` (MCP) and
> `docs/superpowers/plans/2026-08-27-phase5-acp-triggers-workflows-web.md` (ACP).

## 10. Protocol surfaces: ACP client, ACP server, MCP host

Both protocols moved recently and the versions below were verified on 2026-08-27.

### 10.1 State of the protocols

**ACP** — JSON-RPC 2.0, newline-delimited, over stdio (agent stdout is protocol-only,
stderr free for logs). `protocolVersion` is a single **integer**, not a date. Governance is
now jointly Zed + JetBrains at `agentclientprotocol/rust-sdk` (moved from
`zed-industries`), with intent to move to an independent foundation.

A **draft v2** (2026-07-20) changes things that matter to us:

| v1 | v2 |
|---|---|
| `authenticate` / `logout` | `auth/login` / `auth/logout` |
| `session/load` | removed → `session/resume` with `replayFrom` |
| `session/set_mode` | removed → `session/set_config_option` |
| **`fs/*`, `terminal/*`** | **removed entirely** |
| `session/prompt` returns `stopReason` | returns `{}` on *acceptance*; completion arrives as `state_update: idle` + `stopReason` |
| capability booleans | capability *objects* (`{}` = supported, omitted = not) |
| `tool_call` + `tool_call_update` | `tool_call` gone; first `tool_call_update` creates |

Three v2 details are load-bearing for our design:

1. **Merge semantics are three-state**: *omitted = unchanged, `null` = clear, value =
   replace*; chunks append. A plain `Option<T>` silently erases a distinction the
   protocol depends on — use the SDK's `MaybeUndefined` tri-state.
2. **Every enum is open**; unknown values must round-trip. `_`-prefixed values are for
   implementation extensions.
3. **In v2, being an ACP client means being an MCP server.** With `fs/*` and `terminal/*`
   deleted, the only way to give an agent our file access or sandboxed execution is to
   hand it an MCP server config on `session/new`. Watch `unstable_mcp_over_acp` (RFD,
   already implemented behind a flag) — it serves those tools in-process over the existing
   ACP channel instead of spawning a shim, which is **the difference between a sandboxable
   harness and one with side channels.**

⚠️ **v2 is draft and the spec says not to ship it by default.** No editor or agent is
confirmed shipping v2 in production. Stable v1 is what real editors speak today.

**MCP revision `2026-07-28`** made the protocol **stateless** and **removed
server-initiated requests entirely**:

- The `initialize` handshake is gone; every request carries `_meta` protocol version and
  client capabilities. `server/discover` is the mandatory discovery RPC and the prescribed
  stdio backward-compat probe.
- `Mcp-Session-Id` and protocol-level sessions removed; cross-call state is server-minted
  handles passed as ordinary tool arguments.
- **MRTR** replaces server→client requests: sampling/elicitation/roots arrive *inside a
  result* as `resultType: "input_required"` with `inputRequests` and an opaque,
  AEAD-protected `requestState`. The client fulfils them and **retries the original
  request with a new JSON-RPC id**, echoing `requestState`. For us: **no inbound request
  router — a retry loop around `tools/call`/`prompts/get`/`resources/read`, with a round
  cap.**
- **Sampling, roots and logging are all deprecated** (≥12-month window). Suggested
  migration for sampling is to integrate LLM APIs directly — which we already do.
  **Elicitation is the survivor and is where human-in-the-loop belongs.**

### 10.2 How we implement all three roles

Crates: `agent-client-protocol 2.0.0` (workspace also ships `-http`, `-rmcp` bridge,
`-conductor` proxy-chain, `-test`) and `rmcp 3.1.4` (implements `2026-07-28` while staying
compatible with `2025-11-25` and earlier via `ClientLifecycleMode::Auto`).

**Three loops, one core.** As ACP *server* we emit `session/update`; as ACP *client* we
consume it; as MCP *host* we do neither and run tool loops. The shared internal event
model (§4) is the seam, and **it is built on v2's upsert semantics — ids everywhere,
tri-state patches — because v1 is losslessly representable as a degenerate v2 stream but
not vice versa.** `roundhouse-acp` keeps two thin protocol surfaces (`schema::v1`, `schema::v2`)
behind shared application logic, selected per connection after `initialize`; ACP v2 stays
behind a feature flag until it stabilises.

**The `agent-client-protocol` crate is pinned to an exact version, upgraded
deliberately, never tracked to latest.** No new policy — this is just applying the same
discipline every dependency in §5.3 already gets, to a crate with an unusually fast
breaking-change cadence (0.10→2.0 in ~4 months). The insulation itself is already the
thin-surface-behind-shared-logic architecture above; pinning is what keeps an upstream
breaking release from becoming an unplanned mid-sprint migration.

**No static per-agent v1/v2 compatibility table is built or maintained.** The protocol's
own `initialize` handshake already answers this live, at connection time — the agent
declares its supported version during negotiation (§10.1). A maintained table would
duplicate information the protocol already hands us for free and would go stale the
moment an agent updates. The only thing worth caching is the *observed* result per
`(agent binary, version)` as a local runtime hint to skip a redundant negotiation round
on reconnect — an optimization, not a source of truth anyone has to keep current.

**Mapping ACP onto our model:**

| ACP | Roundhouse |
|---|---|
| session | a Session (child session when driven as a sub-agent) |
| `agent_message_chunk` / `agent_thought_chunk` | `TaskDelta::{Text,Thinking}` on the `chat` task |
| `tool_call_update` | a child Task of the appropriate kind, created on first update |
| `plan_update` | a `plan` task |
| `state_update: idle` + `stopReason` | `TaskCompleted` on the `chat` task |
| `session/request_permission` | §6.4 approval flow, both directions |
| `terminal_update` / `terminal_output_chunk` | `shell` task with a live handle (§4.3) |
| `usage_update` | `Usage` on the enclosing `infer`/`chat` task |

**Permissions are the one true crossing point.** An MCP `tools/call` we want approved
becomes an ACP `session/request_permission` upward; an ACP permission request we receive
as a client becomes a policy decision plus possibly a UI prompt. One internal
`Decision` type, adapters at both edges (§6.4).

**Two elicitation shapes are unavoidable.** ACP forked MCP's elicitation and then kept
`elicitationId` + `elicitation/complete`, which MCP has since removed (correlation moved
into `requestState`). Our `elicit` task normalises both.

**We do not ship ACP's `Proxy`/`Conductor` role.** It's real extra surface on top of an
already-large scope, it isn't needed by any of the product's actual differentiators
(parallel sessions, the typed task log, provider abstraction), and it would mean building
against a protocol feature that's itself still unstable. Consistent with how this design
already treats several other genuinely-interesting-but-not-core capabilities (the
reserved-but-unbuilt `Control` message kind, §7.9; App Sandbox entitlements, §6.5): the
trait boundary (`roundhouse-acp` as a distinct crate) stays open to it, but nothing is built
until a concrete need shows up.

**The version matrix is the real cost:** ACP v1+v2 × MCP legacy-`initialize` +
modern-`discover`. Both SDKs handle both eras; keep the surfaces thin and select after
negotiation.

### 10.3 Consuming the ACP registry

`agentclientprotocol/registry` is a curated, versioned install index of ACP agents,
restricted to those supporting authentication. **Consume it rather than hardcoding agent
launch configs** — roughly 45 agents are listed (Claude via `claude-agent-acp`, Codex,
Gemini CLI, Goose, Cursor, Copilot CLI, Qwen Code, OpenCode, OpenHands, Cline, Amp, …).

### 10.4 Open questions

~~Ship ACP's Proxy/Conductor role?~~ **Decided (§10.2): no.** Extra surface, not core to
any differentiator, and the protocol feature itself is still unstable — the trait
boundary stays open, nothing built without a concrete need.

~~Insulate `roundhouse-core` from ACP's breaking-change cadence — pin or track?~~ **Decided
(§10.2): pin, same discipline as every other dependency in §5.3.** The insulation
mechanism is already the thin-surface architecture; pinning is what prevents an upstream
break from becoming an unplanned migration.

~~Who maintains the per-agent v1/v2 compatibility table?~~ **Decided (§10.2): nobody —
no static table needed.** The `initialize` handshake already answers this live; a
maintained table would duplicate what the protocol hands us for free and go stale
immediately. Observed results are cached opportunistically as a local hint, not a
source of truth.

*(All of §10's open questions are now resolved.)*

