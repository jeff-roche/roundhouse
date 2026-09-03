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
| `roundhouse-store` | SQLite event log, materialised views, FTS5, migrations | core, provider (Task 20: the cost-attribution derived view needs `Cost`/`PricingLookup`/`ModelId`/`ProviderId` from `roundhouse-provider::{fallback, ir}` — a deliberate, tracked deviation from this table's original `core`-only row, landed here; see `crates/roundhouse-store/Cargo.toml`'s own comment on the edge) |
| `roundhouse-policy` | Permission rule language + evaluation engine | core, store (Task 15: the project-scope trust ledger persists through `roundhouse-store`) |
| `roundhouse-sandbox` | Isolation tiers behind one trait | `roundhouse-core` |
| `roundhouse-provider` | Provider trait + adapters, capability registry | `roundhouse-core` |
| `roundhouse-conformance` | Shared provider-adapter conformance test library (§9.10): `ConformanceSubject`/`ConformanceCase`/`SerializeOnlyMask`/`run()`/`ConformanceReport::assert_green()`. Per §13.3, this crate IS the review artifact for a provider adapter. (The `.cassette` on-disk fixture format and `CassetteTransport::from_file` it replays through live in `roundhouse-provider` itself, since that's where `CassetteTransport` is defined.) | core (for `Usage`, not re-exported from `roundhouse-provider`'s crate root), provider (real dependency, for the `Provider` trait and IR types every case exercises; `roundhouse-provider` only takes this crate back as a `[dev-dependencies]` entry, so Tasks 5-17's own `tests/*_conformance.rs` files can call into it, which keeps the edge one-way and acyclic) |
| `roundhouse-tools` | Task executors (shell/fs/http/web/git/memory) | core, sandbox, policy, net (Task 24: the `http` executor is constructible only from a `roundhouse-net::ProxyHandle`, so `http` traffic is structurally forced through `LoopbackProxy`'s egress allowlist/metadata-IP hard-deny rather than reaching the network directly) |
| `roundhouse-mcp` | MCP host (rmcp) | core, policy, provider (Task 1, Phase 3: `ContentBlock`/`MediaSource` live in `roundhouse-provider`, not `roundhouse-core`) |
| `roundhouse-acp` | ACP client + ACP server (agent-client-protocol) | core, proto |
| `roundhouse-bus` | Inter-agent messaging + teams | `roundhouse-core` |
| `roundhouse-engine` | Agent loop, session actor, supervision, context mgmt | most of the above, plus net (Task 25: session creation registers the session's egress allowlist with the real `LoopbackProxy` at the same call site it decides isolation tier, so `SessionActor`'s home module depends on `roundhouse-net` directly rather than only transitively) |
| `roundhouse-config` | Layered config loading (builtin/user/project/workspace scopes per §6.2's precedence ranking), `SecretRef` types | — (no internal `roundhouse-*` dependency) |
| `roundhouse-secrets` | Secret *material* handling: `CredentialProvider` implementations (§9.9), keyring/file-fallback resolution, the `Secret`/`expose_within_control_lane` closure-scoped type-level guarantee (§6.7; see `roundhouse-secrets/src/secret.rs`'s module doc comment for why this replaced an earlier, defeatable `ControlLaneToken` capability-type design), outbound redaction. Split out from `roundhouse-config` (which only ever holds `SecretRef` pointers, never material) because material-handling has a materially different trust boundary and a much smaller expose-site surface to audit. | core, config, store (Task 18: keyring/file-fallback resolution persists the fallback `Degradation` through `roundhouse-store`), provider (Phase 6 Task 2: the six concrete `CredentialProvider` implementations — bearer, header-key, OAuth refresh, Azure Entra, exec-command, SigV4 — live here and implement `roundhouse_provider::credential::CredentialProvider`/mutate `roundhouse_provider::HttpRequest` directly; acyclic because this crate already reaches `roundhouse-provider` transitively through `roundhouse-store`'s own edge above, so this is a shorter path to an already-reachable target, not a new cycle; `roundhouse-provider` takes this crate back only as a `[dev-dependencies]` entry, which is legal in Cargo — see `crates/roundhouse-secrets/Cargo.toml`'s own comment on the edge) |
| `roundhouse-flow` | Workflow definition + durable execution | core, engine, store |
| `roundhouse-sched` | Triggers and scheduling | core, engine, store |
| `roundhouse-daemon` | Daemon: wiring, API server, lifecycle — runs as `round daemon` | core, proto, store, policy, sandbox, provider, tools, mcp, acp, bus, engine, flow, sched, config, tui — no direct `roundhouse-net` edge of its own (reached transitively through `engine`/`tools`, both of which depend on it directly per their own rows above); no `roundhouse-secrets` edge either, direct or transitive: `roundhouse-secrets` now depends on `roundhouse-provider` normally (Phase 6 Task 2, see that row above), and `roundhouse-provider` depends back on `roundhouse-secrets` only as a `[dev-dependencies]` entry (excluded from the normal build graph) — neither direction gives `roundhouse-daemon` a path to `roundhouse-secrets`, so the daemon genuinely has none as of this writing |
| `roundhouse-tui` | ratatui client | proto |
| `roundhouse-cli` | The `round` binary: TUI attach, headless/one-shot runs, and `round daemon` | proto, tui (not `daemon` — `round daemon` is spawned as a separate process/binary, not linked in) |
| `roundhouse-web` | axum API + embedded web client assets | proto |
| `roundhouse-net` | The daemon-owned network egress boundary (§6.6, one of the design's "exactly two real boundaries," §6.1): the two-lane model (`Lane::Control`/`Lane::Agent`), the `HostPattern`/`EgressPolicy` allowlist matcher, `ConnectFilter`'s metadata-IP hard-deny, and the per-session `LoopbackProxy` (a loopback HTTP CONNECT proxy with bearer-token session disambiguation) that the agent lane exits through exclusively. | core, store |

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
> **One more crate added during later phase planning (2026-08-28), same pattern:**
> Phase 2 needed a home for secret *material* handling distinct from `roundhouse-config`'s
> `SecretRef` pointers — `roundhouse-secrets` is now this table's own row. It was
> previously created ad hoc by its phase plan without a matching row here; this table is
> still the single source of truth, now including it.
>
> **Correction (final Phase 2 whole-branch-review cleanup), superseded below:** an earlier
> version of this table carried a `roundhouse-conformance` row before the crate existed and
> had it removed pending Phase 6 Task 3 actually creating it. Task 3 has now landed
> `crates/roundhouse-conformance` and it is a real workspace member, so the row above is
> restored — this note is kept as a record of the same "row added before the crate existed"
> pattern flagged elsewhere in this section.
>
> **A third crate added the same way (Task 23, Phase 2):** §6.6's loopback-proxy network
> boundary had no implementing crate anywhere in the plan before Task 23 — a full-text
> search across every prior phase plan turned up no `loopback proxy`/`agent lane`/
> `control lane`/CONNECT vocabulary at all. `roundhouse-net` is now this table's own row,
> same pattern as the two above: built ad hoc by its phase task without a matching row
> here until now.
>
> **One new dependency edge added the same way (Task 24, Phase 2):** closing the audit
> finding that `Attestation.net_enforced` was attested but never honestly computed or
> enforced required one real, deliberate edge onto `roundhouse-net` that this table
> didn't declare before now: `roundhouse-tools` (so the new `http` task executor can
> only ever be constructed from a real `roundhouse-net::ProxyHandle`, forcing `http`
> traffic through `LoopbackProxy`). That row above is amended in place rather than
> duplicating the proxy-routing logic in the downstream crate. (An initial version of
> this task also added `roundhouse-sandbox -> roundhouse-net` so `attest()` could call
> the mechanism-honesty table — a security-review finding on that same round caught
> that this needlessly pulled `roundhouse-net`'s `roundhouse-store`/SQLite dependency
> into `roundhouse-sandbox`, the workspace's smallest and most tightly audited crate.
> Fix: `NetworkMechanism`/`net_enforced_for` now live in `roundhouse-core` instead,
> which both `roundhouse-sandbox` and `roundhouse-net` already depended on, so no
> `roundhouse-sandbox` row change was needed after all.)
>
> **A second new dependency edge added the same way (Task 25, Phase 2):** wiring the
> sealed floor, isolation-shortfall recording, and the network-policy proxy into the
> real task-admission path (the audit's "built in isolation, never wired" recurring
> finding) required `roundhouse-engine`'s `session_actor.rs` to call
> `roundhouse_net::proxy::LoopbackProxy::register_session` directly at session-creation
> time — the same call site that already decides a session's isolation tier and builds
> its `SealedContext`. That row above is amended in place (replacing the previous vague
> "most of the above" with an explicit call-out of `net`) rather than inventing a
> separate crate to host `create_session_with_egress`.

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

