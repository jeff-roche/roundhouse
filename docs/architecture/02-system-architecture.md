# Roundhouse Architecture — System Architecture

> Process topology, the Cargo workspace crate boundaries (doubling as work-assignment
> boundaries for an implementing agent team), and the verified dependency baseline
> pinned against crates.io on 2026-08-27.

## 5. System architecture

### 5.1 Process topology

```
┌────────────┐   ┌────────────┐   ┌───────────────┐
│ round TUI  │   │  web UI    │   │ editor (Zed)  │
└─────┬──────┘   └─────┬──────┘   └───────┬───────┘
      │ NDJSON/UDS     │ HTTP+SSE         │ ACP (server role)
      └────────────────┴──────────────────┘
                       ▼
              ┌──────────────────┐
              │  round daemon    │  supervisor · policy · bus · scheduler
              └────────┬─────────┘
        ┌──────────────┼──────────────┬───────────────┐
        ▼              ▼              ▼               ▼
  session actor   session actor   MCP hosts    ACP client conns
        │                                            │
   task executors ──▶ sandbox tiers            external agents
        │
   provider adapters ──▶ 20+ inference providers
```

### 5.2 Cargo workspace

Crate boundaries are chosen to double as **work boundaries for the implementing
agent team** — one crate, one owner, one test suite, minimal shared mutable surface.

| Crate | Responsibility | Depends on |
|---|---|---|
| `roundhouse-core` | Domain types: `Event`, `Task`, `Session`, ids, errors. **No I/O.** | — |
| `roundhouse-proto` | Client↔daemon wire types + JSON Schema emission; versioned | `roundhouse-core` |
| `roundhouse-store` | SQLite event log, materialised views, FTS5, migrations | `roundhouse-core` |
| `roundhouse-policy` | Permission rule language + evaluation engine | `roundhouse-core` |
| `roundhouse-sandbox` | Isolation tiers behind one trait | `roundhouse-core` |
| `roundhouse-provider` | Provider trait + adapters, capability registry | `roundhouse-core` |
| `roundhouse-conformance` | The reusable conformance-suite library §9.10 specifies (`roundhouse_conformance::run::<Adapter>()`) — golden-snapshot harness, cassette replay, the generic param-mask property test. Pulled out of `roundhouse-provider` into its own crate so provider-adapter crates (and any future out-of-tree adapter) can depend on the test harness without depending on the adapters it tests. | core, provider (dev-dependency of provider's own adapter tests) |
| `roundhouse-tools` | Task executors (shell/fs/http/web/git/memory) | core, sandbox, policy |
| `roundhouse-mcp` | MCP host (rmcp) | core, policy |
| `roundhouse-acp` | ACP client + ACP server (agent-client-protocol) | core, proto |
| `roundhouse-bus` | Inter-agent messaging + teams | core, store |
| `roundhouse-engine` | Agent loop, session actor, supervision, context mgmt | most of the above |
| `roundhouse-config` | Layered config loading (builtin/user/project/workspace scopes per §6.2's precedence ranking), `SecretRef` types | core |
| `roundhouse-secrets` | Secret *material* handling: `CredentialProvider` implementations (§9.9), keyring/file-fallback resolution, the `Secret<T>`/`expose_for_request` type-level guarantee (§6.7), outbound redaction. Split out from `roundhouse-config` (which only ever holds `SecretRef` pointers, never material) because material-handling has a materially different trust boundary and a much smaller expose-site surface to audit. | core, config |
| `roundhouse-flow` | Workflow definition + durable execution | core, engine, store |
| `roundhouse-sched` | Triggers and scheduling | core, engine, store |
| `roundhouse-daemon` | Daemon: wiring, API server, lifecycle — runs as `round daemon` | all |
| `roundhouse-tui` | ratatui client | proto |
| `roundhouse-cli` | The `round` binary: TUI attach, headless/one-shot runs, and `round daemon` | proto, daemon, tui |
| `roundhouse-web` | axum API + embedded web client assets | proto |

**Non-negotiable rules:** `roundhouse-core` has no async and no I/O; no *library* crate
(i.e. none of the rows above `roundhouse-daemon` in this table) depends on
`roundhouse-daemon` or `roundhouse-cli` — those two are consumers of everything else,
never a dependency of it; every crate is independently testable;
`#![forbid(unsafe_code)]` everywhere
except `roundhouse-sandbox` (which needs it, and confines it to one module).

> **Naming reconciliation (found during phase planning, resolved here):** earlier
> drafts of §9.3, §12.2, and §13.2 referred to `roundhouse-agent`, `roundhouse-session`,
> and `roundhouse-config` as if they were crates distinct from this table — they never
> were. `roundhouse-agent`/`roundhouse-session` both name what this table calls
> `roundhouse-engine` ("agent loop, session actor, supervision, context mgmt" is one
> crate, not three); `roundhouse-config` was a genuine gap and is now this table's own
> row. **This table is the single source of truth for crate names.** If you find a
> plan or doc elsewhere still using the old names, treat it as a typo for the name
> given here, not as a second crate.
>
> **Two more crates added during later phase planning (2026-08-28), same pattern:**
> Phase 2 needed a home for secret *material* handling distinct from `roundhouse-config`'s
> `SecretRef` pointers — `roundhouse-secrets` is now this table's own row. Phase 6 needed
> the conformance suite (§9.10) usable as a dependency of provider-adapter tests without
> depending on the adapters themselves — `roundhouse-conformance` is now this table's own
> row. Both were previously created ad hoc by their phase plans without a matching row
> here; this table is still the single source of truth, now including them.

### 5.3 Verified dependency baseline

Checked against crates.io on 2026-08-27 by research agent; pin these.

| Need | Choice | Version | Rationale |
|---|---|---|---|
| Runtime | `tokio` + `tokio-util` | 1.53 / 0.7.19 | Hand-rolled session actors; `CancellationToken` + `TaskTracker`. **No actor framework** — every one with real supervision is pre-1.0 with 6–8 week breaking cadence. |
| TUI | `ratatui` + `crossterm` | 0.30.2 / 0.29 | Enable `layout-cache`. Use `ratatui-textarea 0.9.2` — the old `tui-textarea` is dead at ratatui 0.29. |
| Storage | `rusqlite` (bundled) + `deadpool-sqlite` + `rusqlite_migration` | 0.40.2 / 0.14 / 2.6 | One writer task; WAL; FTS5 is compiled in by default. `sqlx-sqlite` **cannot coexist** — conflicting `libsqlite3-sys` `links` versions. |
| HTTP | `reqwest` | **0.13.4** | Note: `reqwest-eventsource` is stranded on 0.12 and abandoned. |
| SSE | `sse-stream` | 0.2.5 | What `rmcp` uses → no dependency conflict. |
| LLM clients | **hand-written per provider** | — | `rig` (42 minor versions, ~3-week breaking cadence) is still fixing dropped params and mis-ordered reasoning blocks. The provider abstraction *is* the product. |
| MCP | `rmcp` | 3.1.4 | Official SDK; handles MRTR automatically. |
| ACP | `agent-client-protocol` | 2.0.0 | Official SDK; `schema::v1` + `schema::v2` in one binary. |
| Sandbox | `landlock` + `seccompiler` + bubblewrap/Seatbelt | 0.4.7 / 0.5.0 | See §6. |
| Process | `process-wrap` | 10.0.0 | Kills process *groups*; `command-group` is stale. |
| PTY | `portable-pty` | 0.9.0 | Only mature cross-platform incl. ConPTY. |
| Git | `git2` (writes) + `gix` (fast reads) | 0.21 / 0.87 | `gix` push/rebase/merge still incomplete. |
| Diff | `similar` + `diffy` | 3.2 / 0.5.1 | Generate / apply. |
| Schemas | `schemars` | **1.2.2** | 1.0 shipped; 0.8 churn risk retired. |
| Secrets | `keyring` + `secrecy` + `zeroize` | 4.1.6 / 0.10.3 / 1.9 | Always offer a 0600 file fallback — Linux secret-service is unreliable. |
| Observability | `tracing` + `tracing-subscriber` + `console-subscriber` | 0.1.44 / 0.3.23 / 0.5 | tokio-console is the only way to debug hundreds of live tasks. |
| Errors | `thiserror` (libs) / `color-eyre` (bins) | 2.0.20 / 0.6.5 | |
| IPC | NDJSON over tokio Unix socket | — | Zero deps, debuggable with `nc`, log is already JSON. |

**Additions identified during phase planning (2026-08-27), not covered by the original
research pass — pin versions before the phase that needs them starts:**

| Need | Choice | Used by | Rationale |
|---|---|---|---|
| Web framework | `axum` | Phase 5 (`roundhouse-web`) | Inbound HTTP/SSE server for the web UI; explicitly requested by the design (§11.3) but never added to this table. |
| Snapshot testing | `insta` | Phase 1 (golden snapshots for the first two codecs), Phase 6 (`roundhouse-provider` conformance suite for the remaining ~23 profiles) | The golden-codec-snapshot mechanism §9.10 assumes; needed as soon as the first codec exists, not deferred to Phase 6. |
| AWS signing | `hmac` + `sha2` + `hex` | Phase 6 (`bedrock-converse` codec) | SigV4 request signing. |
| AWS eventstream | `aws-smithy-eventstream` + `aws-smithy-types` | Phase 6 (`bedrock-converse` codec) | Bedrock's legacy Converse API is a binary eventstream, not SSE. |
| Config parsing | `toml` | Phase 6 (quirk-profile deserializer), likely also `roundhouse-config` | Provider quirk profiles and layered config are both TOML. |
| Filesystem walking | `walkdir` | Phase 6 (provider-profile discovery) | |

**Two traps to encode in CI:** never set `panic = "abort"` (it destroys task-level
panic isolation and the whole supervisor design), and always use `BEGIN IMMEDIATE`
for write transactions (a deferred txn that later writes returns
`SQLITE_BUSY_SNAPSHOT`, for which the busy handler is *not* invoked).

---

